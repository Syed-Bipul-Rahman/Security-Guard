//! Signed, fail-closed OTA self-update: the Rust port of updater.py.
//!
//! Same channel, same manifest, same key as the Python updater, so a fleet can
//! move between the two builds through the normal update path:
//!   * `$GUARD_UPDATE_URL/manifest.json` plus `manifest.json.sig` (base64 of a
//!     64-byte Ed25519 signature over the manifest's exact bytes), verified
//!     against the public key baked into the binary. No key, a bad signature or
//!     a malformed manifest means no update.
//!   * SHA-256 check of every download before it is used.
//!   * Downgrade protection: never apply a version <= the running one.
//!   * Atomic swap keeping the previous binary (`guard.bak`, or `guard.old.exe`
//!     on Windows, which can rename a running .exe but not overwrite it).
//!
//! Log lines and the printed result match updater.py word for word;
//! tests/test_rust_binary.py runs both against the same signed manifests.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::{net, pyrepr, util};

/// Release identity, baked at compile time (release.yml sets these for tagged
/// builds); the defaults match updater.py. As in updater.py, the environment
/// variables of the same name override them at run time.
pub const DEFAULT_PUBKEY: &str = match option_env!("GUARD_UPDATE_PUBKEY") {
    Some(k) => k,
    None => "b42962000f5fd0e3f3ab68eaee6ab946623f50313c8b6d3b644421daf9279bb0",
};
pub const DEFAULT_BASE_URL: &str = match option_env!("GUARD_UPDATE_URL") {
    Some(u) => u,
    None => "https://security.syedbipul.me/guard",
};

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn sha256_file(p: &Path) -> std::io::Result<String> {
    Ok(sha256_hex(&fs::read(p)?))
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    // bytes.fromhex: whitespace between bytes is allowed
    let s: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return Err("non-hexadecimal number found in fromhex() arg".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| "non-hexadecimal number found in fromhex() arg".to_string())
        })
        .collect()
}

/// updater._semver: the digits of each dot-separated part, padded to three.
pub fn semver(v: &str) -> (u128, u128, u128) {
    let mut parts: Vec<u128> = v
        .split('.')
        .map(|p| {
            let num: String = p.chars().filter(|c| c.is_ascii_digit()).collect();
            if num.is_empty() {
                0
            } else {
                num.parse().unwrap_or(u128::MAX)
            }
        })
        .collect();
    parts.resize(parts.len().max(3), 0);
    (parts[0], parts[1], parts[2])
}

/// str() of a manifest value, as updater.py sees it.
fn as_text(v: Option<&Value>, default: &str) -> String {
    match v {
        None => default.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) => "None".into(),
        Some(other) => pyrepr::repr(other),
    }
}

/// A truthy string field (Python's `if not (url and want)`).
fn text_field<'a>(m: &'a Value, key: &str) -> Option<&'a str> {
    m.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

pub fn platform_key() -> String {
    let arch = match env::consts::ARCH {
        "aarch64" | "arm64" => "arm64",
        "x86_64" | "amd64" => "x64",
        other => other,
    };
    let os = match env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    format!("{os}-{arch}")
}

fn fetch(url: &str) -> Result<Vec<u8>, String> {
    net::fetch(url, "guard-updater", Duration::from_secs(900), true)
}

fn verify(sig: &[u8], msg: &[u8], pk: &[u8]) -> bool {
    let (Ok(sig), Ok(pk)) = (<[u8; 64]>::try_from(sig), <[u8; 32]>::try_from(pk)) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    key.verify_strict(msg, &Signature::from_bytes(&sig)).is_ok()
}

/// What `check_and_apply` returns, printed like updater.py's dict.
pub struct Outcome(Value);

impl Outcome {
    pub fn repr(&self) -> String {
        pyrepr::repr(&self.0)
    }

    pub fn binary_updated(&self) -> bool {
        self.0["binary_updated"] == true
    }
}

pub struct Updater {
    base: String,
    pubkey: Vec<u8>,
    current: String,
    home: PathBuf,
    exe: PathBuf,
}

fn log(msg: &str) {
    util::emit(msg);
}

impl Updater {
    pub fn from_env(current: &str) -> Result<Self, String> {
        let base = env::var("GUARD_UPDATE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.into());
        let pubkey_hex = env::var("GUARD_UPDATE_PUBKEY").unwrap_or_else(|_| DEFAULT_PUBKEY.into());
        let exe =
            env::current_exe().map_err(|e| format!("cannot locate the running binary: {e}"))?;
        Ok(Updater {
            base: base.trim_end_matches('/').to_string(),
            pubkey: if pubkey_hex.is_empty() {
                Vec::new()
            } else {
                hex_decode(&pubkey_hex)?
            },
            current: current.to_string(),
            home: util::guard_home(),
            exe,
        })
    }

    // -- the signature gate --
    fn load_verified_manifest(&self) -> Option<Map<String, Value>> {
        if self.pubkey.is_empty() {
            log("updater: NO public key embedded -> refusing all updates (fail closed)");
            return None;
        }
        let fetched = fetch(&format!("{}/manifest.json", self.base)).and_then(|raw| {
            fetch(&format!("{}/manifest.json.sig", self.base)).map(|sig| (raw, sig))
        });
        let (raw, sig_b64) = match fetched {
            Ok(v) => v,
            Err(e) => {
                log(&format!(
                    "updater: manifest fetch failed ({e}); staying on current version"
                ));
                return None;
            }
        };
        // base64.b64decode: characters outside the alphabet are discarded
        let cleaned: Vec<u8> = sig_b64
            .iter()
            .copied()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'='))
            .collect();
        let Ok(sig) = base64::engine::general_purpose::STANDARD.decode(&cleaned) else {
            log("updater: malformed signature -> refusing");
            return None;
        };
        if !verify(&sig, &raw, &self.pubkey) {
            log("updater: SIGNATURE INVALID -> refusing update (possible tampering)");
            return None;
        }
        match serde_json::from_slice::<Value>(&raw) {
            Ok(Value::Object(m)) => Some(m),
            _ => {
                log("updater: manifest not valid JSON -> refusing");
                None
            }
        }
    }

    /// Download `url` to `dest` only if its SHA-256 is `want`.
    fn download_verified(&self, url: &str, want: &str, dest: &Path) -> Result<bool, String> {
        let data = match fetch(url) {
            Ok(d) => d,
            Err(e) => {
                log(&format!("updater: download failed {url} ({e})"));
                return Ok(false);
            }
        };
        if sha256_hex(&data) != want {
            log(&format!(
                "updater: SHA-256 MISMATCH for {url} -> discarding"
            ));
            return Ok(false);
        }
        fs::write(dest, &data).map_err(|e| format!("{}: {e}", dest.display()))?;
        Ok(true)
    }

    fn update_blocklist(&self, m: &Map<String, Value>) -> Result<bool, String> {
        let Some(bl) = m.get("blocklist").filter(|v| v.is_object()) else {
            return Ok(false);
        };
        let (Some(url), Some(want)) = (text_field(bl, "url"), text_field(bl, "sha256")) else {
            return Ok(false);
        };
        let feed = self.home.join("feed");
        fs::create_dir_all(&feed).map_err(|e| format!("{}: {e}", feed.display()))?;
        let local = feed.join("malware-blocklist.json");
        if local.exists() && sha256_file(&local).map_err(|e| e.to_string())? == want {
            return Ok(false); // already current
        }
        let tmp = feed.join("malware-blocklist.json.new");
        if self.download_verified(url, want, &tmp)? {
            fs::rename(&tmp, &local).map_err(|e| e.to_string())?; // atomic
            let short: String = want.chars().take(12).collect();
            log(&format!("updater: blocklist updated ({short}...)"));
            return Ok(true);
        }
        Ok(false)
    }

    fn update_binary(&self, m: &Map<String, Value>) -> Result<bool, String> {
        let newver = as_text(m.get("version"), "0");
        let minver = as_text(m.get("min_version"), "0");
        if semver(&newver) <= semver(&self.current) {
            return Ok(false); // downgrade protection / already current
        }
        if semver(&self.current) < semver(&minver) {
            log(&format!(
                "updater: current {} below min_version {minver}; forced upgrade",
                self.current
            ));
        }
        let plat = platform_key();
        let entry = m
            .get("binary")
            .and_then(|b| b.get(&plat))
            .filter(|e| match e {
                Value::Null | Value::Bool(false) => false,
                Value::Object(o) => !o.is_empty(),
                Value::String(s) => !s.is_empty(),
                _ => true,
            });
        let Some(entry) = entry else {
            log(&format!(
                "updater: no binary for platform {plat} in manifest"
            ));
            return Ok(false);
        };
        let target = &self.exe; // the running binary
        let tmp = target.with_extension("new");
        // Only the root service can replace a binary in a system dir. If this
        // process can't write there (a manual non-root `guard update`), skip
        // cleanly: the service applies it.
        if fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .is_err()
        {
            let dir = target
                .parent()
                .unwrap_or(Path::new("."))
                .display()
                .to_string();
            log(&format!(
                "updater: {newver} available; binary self-update skipped ({dir} not writable — the root service applies it). Blocklist is current."
            ));
            return Ok(false);
        }
        let field = |k: &str| {
            entry
                .get(k)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("'{k}'"))
        };
        let fetched =
            field("url").and_then(|url| self.download_verified(url, field("sha256")?, &tmp));
        match fetched {
            Ok(true) => {}
            other => {
                let _ = fs::remove_file(&tmp);
                return other;
            }
        }
        match swap(target, &tmp) {
            Ok(()) => {
                log(&format!(
                    "updater: binary updated {} -> {newver}; restart to run it",
                    self.current
                ));
                Ok(true)
            }
            Err(e) => {
                log(&format!(
                    "updater: swap failed ({e}); keeping current binary"
                ));
                let _ = fs::remove_file(&tmp);
                Ok(false)
            }
        }
    }

    pub fn check_and_apply(&self) -> Result<Outcome, String> {
        let m = match self.load_verified_manifest() {
            Some(m) if !m.is_empty() => m,
            _ => return Ok(Outcome(json!({"status": "no-op"}))),
        };
        let bl = self.update_blocklist(&m)?;
        let bin = self.update_binary(&m)?;
        Ok(Outcome(json!({
            "status": if bl || bin { "updated" } else { "current" },
            "blocklist_updated": bl,
            "binary_updated": bin,
            "offered_version": m.get("version").cloned().unwrap_or(Value::Null),
        })))
    }
}

/// Put the verified `tmp` in place of the running binary `target`.
fn swap(target: &Path, tmp: &Path) -> std::io::Result<()> {
    fs::set_permissions(tmp, fs::metadata(target)?.permissions())?;
    if cfg!(windows) {
        // Windows can't overwrite a running .exe, but it can rename one. The
        // running process keeps executing the renamed image; the next launch
        // runs the new guard.exe.
        let old = target.with_extension("old.exe");
        let _ = fs::remove_file(&old);
        fs::rename(target, &old)?;
        fs::rename(tmp, target)?;
        return Ok(());
    }
    fs::copy(target, target.with_extension("bak"))?; // rollback copy
    fs::rename(tmp, target) // atomic swap (Unix)
}

/// Remove a guard.old.exe left by a previous Windows rename-swap.
pub fn cleanup_stale() {
    if cfg!(windows) {
        if let Ok(exe) = env::current_exe() {
            let _ = fs::remove_file(exe.with_extension("old.exe"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_matches_python() {
        assert_eq!(semver("2.1.0"), (2, 1, 0));
        assert_eq!(semver("2"), (2, 0, 0));
        assert_eq!(semver(""), (0, 0, 0));
        assert_eq!(semver("v1.2"), (1, 2, 0));
        // updater._semver keeps every digit of a part: "3-pr5" -> 35
        assert_eq!(semver("0.0.3-pr5"), (0, 0, 35));
        assert!(semver("2.0.0") <= semver("2.0.0"));
        assert!(semver("10.0.0") > semver("9.9.9"));
    }

    #[test]
    fn hex_and_platform() {
        assert_eq!(hex_decode("0aff").unwrap(), vec![0x0a, 0xff]);
        assert!(hex_decode("0g").is_err());
        assert!(hex_decode("abc").is_err());
        assert!([
            "linux-x64",
            "linux-arm64",
            "darwin-arm64",
            "darwin-x64",
            "windows-x64",
            "windows-arm64"
        ]
        .contains(&platform_key().as_str()));
    }

    #[test]
    fn rejects_bad_signatures() {
        assert!(!verify(&[0u8; 63], b"m", &[0u8; 32]));
        assert!(!verify(&[0u8; 64], b"m", &[0u8; 31]));
        assert!(!verify(
            &[0u8; 64],
            b"m",
            &hex_decode(DEFAULT_PUBKEY).unwrap()
        ));
    }
}
