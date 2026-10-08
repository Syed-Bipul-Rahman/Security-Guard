//! The reversible, neutered quarantine vault (port of guard_av/quarantine.py).
//!
//! Items are XORed with a SHA-256 counter-mode keystream under a per-item
//! random key, so the vault never holds a runnable or re-detectable copy.
//! Layout and record format are the Python vault's: <id>.bin + <id>.json, so
//! either build can restore what the other quarantined.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::pystr;
use crate::{pyjson, pyrepr, util};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Symmetric: applying it twice gives the input back.
fn keystream_xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (block, chunk) in data.chunks(32).enumerate() {
        let mut h = Sha256::new();
        h.update(key);
        h.update((block as u64).to_be_bytes());
        let ks = h.finalize();
        out.extend(chunk.iter().zip(ks.iter()).map(|(b, k)| b ^ k));
    }
    out
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("system random source");
    b
}

/// Path.resolve(): absolute, symlinks resolved, without Windows' \\?\ prefix.
fn resolve(p: &Path) -> String {
    let abs = fs::canonicalize(p).unwrap_or_else(|_| {
        std::env::current_dir()
            .map(|d| d.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    });
    let s = abs.display().to_string();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s)
}

fn write_record(path: &Path, rec: &Map<String, Value>) -> std::io::Result<()> {
    util::write_text(
        path,
        &pyjson::dumps(&Value::Object(rec.clone()), Some(2), false),
    )
}

pub struct Vault {
    root: PathBuf,
}

impl Vault {
    pub fn new(root: PathBuf) -> Self {
        Vault { root }
    }

    fn paths(&self, id: &str) -> Result<(PathBuf, PathBuf), String> {
        let bare = id.strip_suffix('\n').unwrap_or(id);
        if bare.len() != 32
            || !bare
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(format!("invalid quarantine id: {}", pyrepr::str_repr(id)));
        }
        Ok((
            self.root.join(format!("{id}.bin")),
            self.root.join(format!("{id}.json")),
        ))
    }

    fn ensure(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }

    /// Move a file into the vault -> its record (without the key).
    pub fn quarantine(&self, path: &str, threat: &str) -> Result<Map<String, Value>, String> {
        let src = Path::new(path);
        let shown = crate::deps::py_path_str(path);
        if util::is_system_path(&shown) {
            return Err(format!(
                "not quarantining {shown}: operating-system directory"
            ));
        }
        let data = fs::read(src)
            .map_err(|e| format!("cannot read {shown}: {}", pystr::os_error(&e, &shown)))?;
        let io = |e: std::io::Error| e.to_string();
        self.ensure().map_err(io)?;
        let id = hex(&random_bytes::<16>());
        let key = random_bytes::<32>();
        let (bin_path, meta_path) = self.paths(&id)?;
        fs::write(&bin_path, keystream_xor(&data, &key)).map_err(io)?;
        let mut rec = Map::new();
        rec.insert("id".into(), json!(id));
        rec.insert("original_path".into(), json!(resolve(src)));
        rec.insert("sha256".into(), json!(hex(&Sha256::digest(&data))));
        rec.insert("size".into(), json!(data.len()));
        rec.insert("threat".into(), json!(threat));
        rec.insert("quarantined_at".into(), json!(util::now_iso()));
        rec.insert("key".into(), json!(hex(&key)));
        write_record(&meta_path, &rec).map_err(io)?;
        if let Err(e) = fs::remove_file(src) {
            rec.insert(
                "note".into(),
                json!(format!(
                    "original not removed: {}",
                    pystr::os_error(&e, &shown)
                )),
            );
            write_record(&meta_path, &rec).map_err(io)?;
        }
        rec.remove("key");
        Ok(rec)
    }

    pub fn list(&self) -> Vec<Value> {
        let Ok(rd) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut metas: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                let n = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if cfg!(windows) {
                    n.to_lowercase().ends_with(".json")
                } else {
                    n.ends_with(".json")
                }
            })
            .collect();
        metas.sort();
        let mut out: Vec<Value> = Vec::new();
        for m in metas {
            let Ok(text) = fs::read_to_string(&m) else {
                continue;
            };
            let Ok(Value::Object(mut rec)) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            rec.remove("key");
            out.push(Value::Object(rec));
        }
        let at = |v: &Value| {
            v.get("quarantined_at")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        out.sort_by_key(at);
        out
    }

    fn load(&self, id: &str) -> Result<(Map<String, Value>, PathBuf, PathBuf), String> {
        let (bin_path, meta_path) = self.paths(id)?;
        if !meta_path.exists() || !bin_path.exists() {
            return Err(format!("no quarantined item {id}"));
        }
        let text = fs::read_to_string(&meta_path).map_err(|e| e.to_string())?;
        match serde_json::from_str(&text) {
            Ok(Value::Object(rec)) => Ok((rec, bin_path, meta_path)),
            Ok(_) => Err(format!("bad quarantine record for {id}")),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Put an item back (verifying its SHA-256) -> where it went.
    pub fn restore(&self, id: &str, dest: Option<&str>, overwrite: bool) -> Result<String, String> {
        let (rec, bin_path, meta_path) = self.load(id)?;
        let s = |k: &str| rec.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let key = unhex(&s("key")).ok_or("non-hexadecimal number found in fromhex() arg")?;
        let stored = fs::read(&bin_path).map_err(|e| e.to_string())?;
        let data = keystream_xor(&stored, &key);
        if hex(&Sha256::digest(&data)) != s("sha256") {
            return Err(format!("integrity check failed for {id}; not restored"));
        }
        let target = crate::deps::py_path_str(
            &dest
                .map(str::to_string)
                .unwrap_or_else(|| s("original_path")),
        );
        let tp = Path::new(&target);
        if tp.exists() && !overwrite {
            return Err(format!(
                "{target} exists (pass overwrite=True to replace it)"
            ));
        }
        if let Some(parent) = tp.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(tp, &data).map_err(|e| pystr::os_error(&e, &target))?;
        fs::remove_file(&bin_path).map_err(|e| e.to_string())?;
        fs::remove_file(&meta_path).map_err(|e| e.to_string())?;
        Ok(target)
    }

    pub fn delete(&self, id: &str) -> Result<(), String> {
        let (_, bin_path, meta_path) = self.load(id)?;
        fs::remove_file(&bin_path).map_err(|e| e.to_string())?;
        fs::remove_file(&meta_path).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keystream_matches_python() {
        // _keystream_xor(b"A" * 40, b"\x01" * 32).hex()[:16] in quarantine.py
        let out = keystream_xor(&[b'A'; 40], &[1u8; 32]);
        assert_eq!(keystream_xor(&out, &[1u8; 32]), vec![b'A'; 40]);
        let mut h = Sha256::new();
        h.update([1u8; 32]);
        h.update(0u64.to_be_bytes());
        assert_eq!(out[0], b'A' ^ h.finalize()[0]);
    }

    /// test_av_engine.py TestQuarantine: what cannot be read is not
    /// quarantined; empty input has an empty keystream.
    #[test]
    fn unreadable_source_and_empty_data() {
        let root = std::env::temp_dir().join(format!("guard-vault-{}", std::process::id()));
        let v = Vault::new(root.join("v"));
        let err = v
            .quarantine(&root.join("missing").to_string_lossy(), "x")
            .unwrap_err();
        assert!(err.starts_with("cannot read"), "{err}");
        assert!(v.list().is_empty());
        assert!(keystream_xor(b"", &[7u8; 32]).is_empty());
        let _ = fs::remove_dir_all(&root);
    }
}
