//! MD5 / SHA-1 / SHA-256 in one pass (port of guard_av/hashing.py).

use std::io::Read;
use std::path::Path;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Default)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

impl Hashes {
    pub fn get(&self, algo: &str) -> &str {
        match algo {
            "md5" => &self.md5,
            "sha1" => &self.sha1,
            _ => &self.sha256,
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Multi(Md5, Sha1, Sha256);

impl Multi {
    fn new() -> Self {
        Multi(Md5::new(), Sha1::new(), Sha256::new())
    }
    fn update(&mut self, b: &[u8]) {
        self.0.update(b);
        self.1.update(b);
        self.2.update(b);
    }
    fn finish(self) -> Hashes {
        Hashes {
            md5: hex(&self.0.finalize()),
            sha1: hex(&self.1.finalize()),
            sha256: hex(&self.2.finalize()),
        }
    }
}

pub fn hash_bytes(data: &[u8]) -> Hashes {
    let mut m = Multi::new();
    m.update(data);
    m.finish()
}

/// Streaming, constant memory.
pub fn hash_file(path: &Path) -> std::io::Result<Hashes> {
    let mut f = std::fs::File::open(path)?;
    let mut m = Multi::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        m.update(&buf[..n]);
    }
    Ok(m.finish())
}

#[cfg(test)]
mod tests {
    #[test]
    fn known_digests() {
        let h = super::hash_bytes(b"abc");
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert!(h.sha256.starts_with("ba7816bf"));
    }
}
