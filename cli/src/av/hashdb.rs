//! Exact-match hash signatures (port of guard_av/hashdb.py).

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;

use super::hashing::Hashes;
use super::model::Verdict;
use super::pystr;

#[derive(Clone, Debug)]
pub struct HashEntry {
    pub name: String,
    pub verdict: Verdict,
}

pub fn algo_for(digest: &str) -> Option<&'static str> {
    if digest.is_empty() || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    match digest.len() {
        32 => Some("md5"),
        40 => Some("sha1"),
        64 => Some("sha256"),
        _ => None,
    }
}

#[derive(Default)]
pub struct HashDatabase {
    md5: HashMap<String, HashEntry>,
    sha1: HashMap<String, HashEntry>,
    sha256: HashMap<String, HashEntry>,
}

impl HashDatabase {
    pub fn len(&self) -> usize {
        self.md5.len() + self.sha1.len() + self.sha256.len()
    }

    fn table(&mut self, algo: &str) -> &mut HashMap<String, HashEntry> {
        match algo {
            "md5" => &mut self.md5,
            "sha1" => &mut self.sha1,
            _ => &mut self.sha256,
        }
    }

    pub fn add(&mut self, digest: &str, name: &str, verdict: &str) -> Result<(), String> {
        let algo = algo_for(digest).ok_or_else(|| {
            format!(
                "not a md5/sha1/sha256 hex digest: {}",
                crate::pyrepr::str_repr(digest)
            )
        })?;
        let verdict = Verdict::parse(verdict)
            .ok_or_else(|| format!("unknown verdict: {}", crate::pyrepr::str_repr(verdict)))?;
        self.table(algo).insert(
            digest.to_lowercase(),
            HashEntry {
                name: name.to_string(),
                verdict,
            },
        );
        Ok(())
    }

    /// (algo, entry) for the first algorithm that matches.
    pub fn lookup(&self, h: &Hashes) -> Option<(&'static str, &HashEntry)> {
        for (algo, table) in [
            ("sha256", &self.sha256),
            ("sha1", &self.sha1),
            ("md5", &self.md5),
        ] {
            let d = h.get(algo);
            if !d.is_empty() {
                if let Some(e) = table.get(&d.to_lowercase()) {
                    return Some((algo, e));
                }
            }
        }
        None
    }

    fn load_json(&mut self, text: &str) -> Result<(), String> {
        let data: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let entries = data.get("entries").and_then(Value::as_array);
        for e in entries.into_iter().flatten() {
            let name = match e.get("name") {
                Some(v) if crate::pyjson::truthy(Some(v)) => pystr::py_str(v),
                _ => "Unnamed".into(),
            };
            let verdict = e
                .get("verdict")
                .map(pystr::py_str)
                .unwrap_or_else(|| "malicious".into());
            for algo in ["md5", "sha1", "sha256"] {
                if let Some(v) = e.get(algo).filter(|v| crate::pyjson::truthy(Some(v))) {
                    self.add(&pystr::py_str(v), &name, &verdict)?;
                }
            }
        }
        Ok(())
    }

    fn load_text(&mut self, text: &str) -> Result<(), String> {
        for line in text.lines() {
            let line = pystr::strip(line.split('#').next().unwrap_or(""));
            if line.is_empty() {
                continue;
            }
            let parts = pystr::split_ws(line);
            if algo_for(parts[0]).is_none() {
                continue;
            }
            let rest = pystr::strip(&line[parts[0].len()..]);
            let name = if parts.len() > 1 {
                rest
            } else {
                "Hash.Blocklisted"
            };
            self.add(parts[0], name, "malicious")?;
        }
        Ok(())
    }

    pub fn load(&mut self, path: &Path, bytes: &[u8]) -> Result<(), String> {
        let json = pystr::suffix(&path.to_string_lossy()).to_lowercase() == ".json";
        if json {
            let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
            self.load_json(text)
        } else {
            self.load_text(&String::from_utf8_lossy(bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::av::hashing::hash_bytes;

    /// test_av_core.py TestHashDatabase.
    #[test]
    fn digests_and_lookup_order() {
        assert_eq!(algo_for(&"a".repeat(32)), Some("md5"));
        assert_eq!(algo_for(&"A".repeat(40)), Some("sha1"));
        assert_eq!(algo_for(&"0".repeat(64)), Some("sha256"));
        for bad in ["xyz", &"a".repeat(33), ""] {
            assert_eq!(algo_for(bad), None, "{bad}");
        }
        let mut db = HashDatabase::default();
        assert!(db.add("nothex", "x", "malicious").is_err());
        let h = hash_bytes(b"evil");
        db.add(&h.md5, "ByMd5", "malicious").unwrap();
        db.add(&h.sha256.to_uppercase(), "BySha", "suspicious")
            .unwrap();
        assert_eq!(db.len(), 2);
        let (algo, e) = db.lookup(&h).unwrap();
        assert_eq!(
            (algo, e.name.as_str(), e.verdict),
            ("sha256", "BySha", Verdict::Suspicious)
        );
        assert!(db.lookup(&hash_bytes(b"good")).is_none());
        let md5_only = Hashes {
            md5: h.md5.clone(),
            ..Default::default()
        };
        assert_eq!(db.lookup(&md5_only).unwrap().1.name, "ByMd5");
    }

    #[test]
    fn json_and_text_lists() {
        let mut db = HashDatabase::default();
        let json = format!(
            r#"{{"entries": [{{"sha1": "{}", "name": "B", "verdict": "suspicious"}}, {{"md5": "{}"}}]}}"#,
            "b".repeat(40),
            "c".repeat(32)
        );
        db.load(Path::new("h.json"), json.as_bytes()).unwrap();
        let sha1 = Hashes {
            sha1: "b".repeat(40),
            ..Default::default()
        };
        assert_eq!(db.lookup(&sha1).unwrap().1.verdict, Verdict::Suspicious);
        let md5 = Hashes {
            md5: "c".repeat(32),
            ..Default::default()
        };
        assert_eq!(db.lookup(&md5).unwrap().1.name, "Unnamed");
        let text = format!(
            "# comment\n\n{}  Trojan.X  # trailing\n{}\nnot-a-hash Foo\n",
            "d".repeat(64),
            "e".repeat(32)
        );
        let mut db = HashDatabase::default();
        db.load(Path::new("list.txt"), text.as_bytes()).unwrap();
        assert_eq!(db.len(), 2);
        let sha = Hashes {
            sha256: "d".repeat(64),
            ..Default::default()
        };
        assert_eq!(db.lookup(&sha).unwrap().1.name, "Trojan.X");
        let md5 = Hashes {
            md5: "e".repeat(32),
            ..Default::default()
        };
        assert_eq!(db.lookup(&md5).unwrap().1.name, "Hash.Blocklisted");
    }
}
