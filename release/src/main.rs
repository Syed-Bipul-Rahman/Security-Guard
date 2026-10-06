//! sign-manifest: release-side signing for Guard OTA updates (was release/sign_manifest.py).
//!
//! Run this in the release pipeline (offline / CI secret). It never ships in the
//! guard binary; only the PUBLIC key does (cli/src/update.rs DEFAULT_PUBKEY, or
//! GUARD_UPDATE_PUBKEY at build time).
//!
//!   keygen                 -> write a new secret seed to a file, print the public key
//!   sign MANIFEST.json     -> write MANIFEST.json.sig (base64 Ed25519 signature)
//!   build-and-sign ...     -> assemble a manifest from files and sign it
//!
//! Usage:
//!   cargo run --manifest-path release/Cargo.toml -- keygen --out guard-update.key
//!   cargo run --manifest-path release/Cargo.toml -- sign manifest.json --key guard-update.key
//!   cargo run --manifest-path release/Cargo.toml -- build-and-sign \
//!       --version 1.1.0 --key guard-update.key \
//!       --base-url https://security.syedbipul.me/guard \
//!       --blocklist malware-feed/malware-blocklist.json \
//!       --binary linux-x64=out/guard-linux-x64 \
//!       --binary darwin-arm64=out/guard-darwin-arm64 \
//!       --out manifest.json
//!
//! SECURITY: guard-update.key is the master key to the whole fleet's root agent.
//! Keep it in a CI secret / HSM / offline vault. Rotate = bake a new public key
//! into the binary and re-sign.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const USAGE: &str = "\
usage: sign-manifest keygen [--out FILE]
       sign-manifest sign MANIFEST --key FILE
       sign-manifest build-and-sign --version V [--min-version V] --key FILE --base-url URL
                     [--blocklist FILE] [--binary PLAT=PATH]... [--out FILE]
";

type Res<T> = Result<T, String>;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha256_file(p: &Path) -> Res<String> {
    let mut f = fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 65536];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("{}: {e}", p.display()))?;
        if n == 0 {
            return Ok(hex(&h.finalize()));
        }
        h.update(&buf[..n]);
    }
}

fn load_key(path: &str) -> Res<SigningKey> {
    let seed = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| "key file must be a 32-byte seed (from `keygen`)".to_string())?;
    Ok(SigningKey::from_bytes(&seed))
}

fn sign_b64(raw: &[u8], key: &SigningKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.sign(raw).to_bytes())
}

fn write(path: &str, data: &[u8]) -> Res<()> {
    fs::write(path, data).map_err(|e| format!("{path}: {e}"))
}

fn keygen(out: &str) -> Res<()> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("no secure randomness: {e}"))?;
    let key = SigningKey::from_bytes(&seed);
    write(out, &seed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(out, fs::Permissions::from_mode(0o600));
    }
    println!("secret seed  -> {out}  (KEEP OFFLINE / in a CI secret)");
    println!("PUBLIC key   -> bake this into cli/src/update.rs DEFAULT_PUBKEY (or GUARD_UPDATE_PUBKEY) and rebuild:");
    println!("  {}", hex(key.verifying_key().as_bytes()));
    Ok(())
}

fn sign(manifest: &str, key: &str) -> Res<()> {
    let key = load_key(key)?;
    let raw = fs::read(manifest).map_err(|e| format!("{manifest}: {e}"))?;
    let sig = sign_b64(&raw, &key);
    write(&format!("{manifest}.sig"), sig.as_bytes())?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&sig)
        .expect("own base64");
    let ok = ed25519_dalek::Signature::from_slice(&bytes)
        .map(|s| key.verifying_key().verify(&raw, &s).is_ok())
        .unwrap_or(false);
    println!("signed: {manifest} -> {manifest}.sig");
    println!("verify: {}", if ok { "True" } else { "False" });
    Ok(())
}

/// json.dumps(v, indent=2, sort_keys=True) with its default ASCII escaping.
fn dumps_sorted(v: &Value) -> String {
    let pretty = serde_json::to_string_pretty(v).expect("serializable");
    let mut out = String::with_capacity(pretty.len());
    for c in pretty.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            for u in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{u:04x}"));
            }
        }
    }
    out
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

struct Build<'a> {
    version: &'a str,
    min_version: &'a str,
    key: &'a str,
    base_url: &'a str,
    blocklist: Option<&'a str>,
    binaries: Vec<&'a str>,
    out: &'a str,
}

fn build_and_sign(b: &Build) -> Res<()> {
    let key = load_key(b.key)?;
    let base = b.base_url.trim_end_matches('/');
    // URLs are flat: {base}/{filename}, matching GitHub Release asset names.
    let mut manifest = json!({"version": b.version, "min_version": b.min_version});
    if let Some(bl) = b.blocklist {
        let p = Path::new(bl);
        manifest["blocklist"] =
            json!({"sha256": sha256_file(p)?, "url": format!("{base}/{}", file_name(p))});
    }
    let mut binaries = BTreeMap::new();
    for spec in &b.binaries {
        let (plat, path) = spec
            .split_once('=')
            .ok_or_else(|| format!("--binary wants PLAT=PATH, got {spec:?}"))?;
        let p = Path::new(path);
        binaries.insert(
            plat.to_string(),
            json!({"sha256": sha256_file(p)?, "url": format!("{base}/{}", file_name(p))}),
        );
    }
    if !binaries.is_empty() {
        manifest["binary"] = json!(binaries);
    }
    let raw = dumps_sorted(&manifest);
    write(b.out, raw.as_bytes())?;
    write(
        &format!("{}.sig", b.out),
        sign_b64(raw.as_bytes(), &key).as_bytes(),
    )?;
    println!("wrote {} (+ .sig) for version {}", b.out, b.version);
    println!("{raw}");
    Ok(())
}

/// Parsed options (repeatable ones collect) and positional arguments.
type Args<'a> = (BTreeMap<&'a str, Vec<&'a str>>, Vec<&'a str>);

/// `--name value` options (repeatable ones collect), plus positionals.
fn parse<'a>(args: &'a [String], known: &[&str]) -> Res<Args<'a>> {
    let mut opts: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut pos = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(name) = a.strip_prefix("--") {
            let (name, inline) = match name.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (name, None),
            };
            if !known.contains(&name) {
                return Err(format!("unrecognized argument: {a}"));
            }
            let v = match inline {
                Some(v) => v,
                None => it
                    .next()
                    .ok_or_else(|| format!("--{name}: expected one argument"))?,
            };
            opts.entry(name).or_default().push(v);
        } else {
            pos.push(a.as_str());
        }
    }
    Ok((opts, pos))
}

fn one<'a>(o: &BTreeMap<&str, Vec<&'a str>>, k: &str) -> Option<&'a str> {
    o.get(k).and_then(|v| v.last().copied())
}

fn run(args: &[String]) -> Res<()> {
    let Some(cmd) = args.first() else {
        return Err("a command is required".into());
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "keygen" => {
            let (o, pos) = parse(rest, &["out"])?;
            if !pos.is_empty() {
                return Err(format!("unrecognized arguments: {}", pos.join(" ")));
            }
            keygen(one(&o, "out").unwrap_or("guard-update.key"))
        }
        "sign" => {
            let (o, pos) = parse(rest, &["key"])?;
            let [manifest] = pos[..] else {
                return Err("sign needs exactly one MANIFEST".into());
            };
            sign(manifest, one(&o, "key").ok_or("--key is required")?)
        }
        "build-and-sign" => {
            let (o, pos) = parse(
                rest,
                &[
                    "version",
                    "min-version",
                    "key",
                    "base-url",
                    "blocklist",
                    "binary",
                    "out",
                ],
            )?;
            if !pos.is_empty() {
                return Err(format!("unrecognized arguments: {}", pos.join(" ")));
            }
            build_and_sign(&Build {
                version: one(&o, "version").ok_or("--version is required")?,
                min_version: one(&o, "min-version").unwrap_or("0.0.0"),
                key: one(&o, "key").ok_or("--key is required")?,
                base_url: one(&o, "base-url").ok_or("--base-url is required")?,
                blocklist: one(&o, "blocklist"),
                binaries: o.get("binary").cloned().unwrap_or_default(),
                out: one(&o, "out").unwrap_or("manifest.json"),
            })
        }
        "-h" | "--help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command: {other}")),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprint!("{USAGE}");
            eprintln!("sign-manifest: error: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8032_test_vector() {
        // RFC 8032 section 7.1, TEST 1 (empty message)
        let seed: [u8; 32] = (0..32)
            .map(|i| {
                u8::from_str_radix(
                    &"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
                        [i * 2..i * 2 + 2],
                    16,
                )
                .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let key = SigningKey::from_bytes(&seed);
        assert_eq!(
            hex(key.verifying_key().as_bytes()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(
            hex(&key.sign(b"").to_bytes()),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn manifest_json_like_python() {
        let v = json!({"version": "1.0", "binary": {"b": {"url": "u", "sha256": "s"}}, "min_version": "0.0.0", "n": "é"});
        assert_eq!(
            dumps_sorted(&v),
            "{\n  \"binary\": {\n    \"b\": {\n      \"sha256\": \"s\",\n      \"url\": \"u\"\n    }\n  },\n  \"min_version\": \"0.0.0\",\n  \"n\": \"\\u00e9\",\n  \"version\": \"1.0\"\n}"
        );
    }
}
