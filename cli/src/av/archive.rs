//! Bounded, in-memory extraction of zip / tar / gzip / bzip2 / xz members for
//! scanning (port of guard_av/archive.py). Nothing touches the disk; hard
//! limits cap what a hostile archive can cost.

use std::io::{Cursor, Read};

pub struct Limits {
    pub max_members: usize,
    pub max_member_size: u64,
    pub max_total_size: u64,
    pub max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_members: 1000,
            max_member_size: 32 * 1024 * 1024,
            max_total_size: 256 * 1024 * 1024,
            max_ratio: 200,
        }
    }
}

pub struct Member {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Default)]
pub struct Extraction {
    pub members: Vec<Member>,
    pub notes: Vec<String>,
    pub bomb: bool,
}

/// Read at most `cap` bytes -> (data, truncated).
fn read_capped(r: &mut dyn Read, cap: u64) -> std::io::Result<(Vec<u8>, bool)> {
    let mut data = Vec::new();
    r.take(cap + 1).read_to_end(&mut data)?;
    let truncated = data.len() as u64 > cap;
    data.truncate(cap as usize);
    Ok((data, truncated))
}

fn extract_zip(data: &[u8], lim: &Limits) -> Extraction {
    let mut ex = Extraction::default();
    let mut zf = match zip::ZipArchive::new(Cursor::new(data)) {
        Ok(z) => z,
        Err(e) => {
            ex.notes.push(format!("bad zip: {e}"));
            return ex;
        }
    };
    struct Info {
        index: usize,
        name: String,
        encrypted: bool,
        compress_size: u64,
        file_size: u64,
    }
    let mut infos = Vec::new();
    for index in 0..zf.len() {
        let Ok(f) = zf.by_index_raw(index) else {
            continue;
        };
        let mut name = f.name().to_string();
        if let Some(n) = name.find('\0') {
            name.truncate(n);
        }
        if cfg!(windows) {
            name = name.replace('\\', "/");
        }
        if name.ends_with('/') {
            continue;
        }
        infos.push(Info {
            index,
            name,
            encrypted: f.encrypted(),
            compress_size: f.compressed_size(),
            file_size: f.size(),
        });
    }
    if infos.len() > lim.max_members {
        ex.notes.push(format!(
            "{} members; scanned first {}",
            infos.len(),
            lim.max_members
        ));
        infos.truncate(lim.max_members);
    }
    let mut total = 0u64;
    for info in infos {
        if info.encrypted {
            ex.notes
                .push(format!("encrypted member skipped: {}", info.name));
            continue;
        }
        if info.compress_size > 0
            && info.file_size > info.compress_size.saturating_mul(lim.max_ratio)
            && info.file_size > 1024 * 1024
        {
            ex.bomb = true;
            ex.notes.push(format!(
                "compression ratio {}:1 on {}; not extracted",
                info.file_size / info.compress_size,
                info.name
            ));
            continue;
        }
        let budget = lim
            .max_member_size
            .min(lim.max_total_size.saturating_sub(total));
        if budget == 0 {
            ex.notes.push("total size budget exhausted".into());
            break;
        }
        let read = zf
            .by_index(info.index)
            .map_err(|e| e.to_string())
            .and_then(|mut f| read_capped(&mut f, budget).map_err(|e| e.to_string()));
        let (body, truncated) = match read {
            Ok(r) => r,
            Err(e) => {
                ex.notes.push(format!("cannot read {}: {e}", info.name));
                continue;
            }
        };
        if truncated {
            ex.notes
                .push(format!("{} truncated at {budget} bytes", info.name));
        }
        total += body.len() as u64;
        ex.members.push(Member {
            name: info.name,
            data: body,
        });
    }
    ex
}

/// A tar stream, read lazily through `r` (plain or decompressing).
fn extract_tar(r: &mut dyn Read, lim: &Limits) -> Extraction {
    let mut ex = Extraction::default();
    let mut ar = tar::Archive::new(r);
    let entries = match ar.entries() {
        Ok(e) => e,
        Err(e) => {
            ex.notes.push(format!("bad tar: {e}"));
            return ex;
        }
    };
    let (mut total, mut seen) = (0u64, 0usize);
    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                if ex.members.is_empty() && seen == 0 {
                    ex.notes.push(format!("bad tar: {e}"));
                } else {
                    ex.notes.push(format!("tar read error: {e}"));
                }
                break;
            }
        };
        use tar::EntryType::*;
        let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        let regular = matches!(
            entry.header().entry_type(),
            Regular | Continuous | GNUSparse
        );
        if !regular || name.ends_with('/') {
            continue;
        }
        seen += 1;
        if seen > lim.max_members {
            ex.notes.push(format!(
                "more than {} members; rest skipped",
                lim.max_members
            ));
            break;
        }
        let budget = lim
            .max_member_size
            .min(lim.max_total_size.saturating_sub(total));
        if budget == 0 {
            ex.notes.push("total size budget exhausted".into());
            break;
        }
        match read_capped(&mut entry, budget) {
            Ok((body, truncated)) => {
                if truncated {
                    ex.notes.push(format!("{name} truncated at {budget} bytes"));
                }
                total += body.len() as u64;
                ex.members.push(Member { name, data: body });
            }
            Err(e) => {
                ex.notes.push(format!("tar read error: {e}"));
                break;
            }
        }
    }
    ex
}

fn decoder<'a>(tag: &str, data: &'a [u8]) -> Box<dyn Read + 'a> {
    match tag {
        "gzip" => Box::new(flate2::read::MultiGzDecoder::new(data)),
        "bzip2" => Box::new(bzip2::read::MultiBzDecoder::new(data)),
        _ => Box::new(lzma_rust2::XzReader::new(data, true)),
    }
}

fn decompress_stream(tag: &str, data: &[u8], name: String, lim: &Limits) -> Extraction {
    let mut ex = Extraction::default();
    let (body, truncated) = match read_capped(&mut decoder(tag, data), lim.max_member_size) {
        Ok(r) => r,
        Err(e) => {
            ex.notes.push(format!("bad stream: {e}"));
            return ex;
        }
    };
    if truncated && !data.is_empty() && body.len() as u64 > lim.max_ratio * data.len() as u64 {
        ex.bomb = true;
        ex.notes.push(format!(
            "decompresses beyond {} bytes at >{}:1",
            lim.max_member_size, lim.max_ratio
        ));
    } else if truncated {
        ex.notes
            .push(format!("stream truncated at {} bytes", lim.max_member_size));
    }
    ex.members.push(Member { name, data: body });
    ex
}

/// The member name for a single compressed stream: the archive's name without
/// its compression suffix.
fn strip(name: &str) -> String {
    let low = name.to_lowercase();
    for e in [".gz", ".bz2", ".xz", ".tgz"] {
        if low.ends_with(e) {
            let cut = &name[..name.len() - e.len()];
            return if cut.is_empty() {
                "payload".into()
            } else {
                cut.into()
            };
        }
    }
    format!("{name}.out")
}

/// Dispatch on the content type tag from filetype::identify().
pub fn extract(data: &[u8], tag: &str, name: &str, lim: &Limits) -> Extraction {
    match tag {
        "zip" => extract_zip(data, lim),
        "tar" => extract_tar(&mut Cursor::new(data), lim),
        "gzip" | "bzip2" | "xz" => {
            // a compressed tarball is a tar; otherwise it's one compressed stream
            let tar = extract_tar(&mut decoder(tag, data), lim);
            if !tar.members.is_empty() {
                return tar;
            }
            decompress_stream(tag, data, strip(name), lim)
        }
        _ => Extraction {
            notes: vec![format!(
                "{tag} archives are not unpacked (no stdlib decoder)"
            )],
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn single_gzip_stream_and_names() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"hello").unwrap();
        let ex = extract(&gz.finish().unwrap(), "gzip", "d/x.GZ", &Limits::default());
        assert_eq!(ex.members.len(), 1);
        assert_eq!(ex.members[0].name, "d/x");
        assert_eq!(ex.members[0].data, b"hello");
        assert_eq!(strip(".gz"), "payload");
        assert_eq!(strip("a.bin"), "a.bin.out");
    }

    #[test]
    fn gzip_bomb_is_flagged() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        gz.write_all(&vec![0u8; 40 * 1024 * 1024]).unwrap();
        let ex = extract(&gz.finish().unwrap(), "gzip", "b.gz", &Limits::default());
        assert!(ex.bomb);
    }
}
