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

    // ---- test_av_heuristics.py, archive section
    const LIM: Limits = Limits {
        max_members: 3,
        max_member_size: 1000,
        max_total_size: 1500,
        max_ratio: 50,
    };

    fn zip_of(files: &[(&str, &[u8])], encrypt: &[&str]) -> Vec<u8> {
        let mut zw = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let o = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in files {
            if let Some(d) = name.strip_suffix('/') {
                zw.add_directory(d, o).unwrap();
            } else {
                zw.start_file(*name, o).unwrap();
                zw.write_all(data).unwrap();
            }
        }
        let mut raw = zw.finish().unwrap().into_inner();
        // the "encrypted" flag in both headers, as conftest.make_zip sets it
        for name in encrypt {
            for (sig, off, hdr) in [(b"PK\x03\x04", 6usize, 30usize), (b"PK\x01\x02", 8, 46)] {
                let hits: Vec<usize> = (0..raw.len().saturating_sub(3))
                    .filter(|&i| &raw[i..i + 4] == sig)
                    .collect();
                for p in hits {
                    if raw.get(p + hdr..p + hdr + name.len()) == Some(name.as_bytes()) {
                        raw[p + off] |= 1;
                    }
                }
            }
        }
        raw
    }

    fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, *data).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn bz2(data: &[u8]) -> Vec<u8> {
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn xz(data: &[u8]) -> Vec<u8> {
        let mut w =
            lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6)).unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap()
    }

    fn names(ex: &Extraction) -> Vec<&str> {
        ex.members.iter().map(|m| m.name.as_str()).collect()
    }

    fn noted(ex: &Extraction, what: &str) -> bool {
        ex.notes.iter().any(|n| n.contains(what))
    }

    fn noise(n: usize) -> Vec<u8> {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    #[test]
    fn zip_members_and_dirs() {
        let ex = extract(
            &zip_of(&[("d/", b""), ("d/a.txt", b"hello")], &[]),
            "zip",
            "x.zip",
            &Limits::default(),
        );
        assert_eq!(names(&ex), ["d/a.txt"]);
        assert_eq!(ex.members[0].data, b"hello");
        assert!(ex.notes.is_empty() && !ex.bomb);
    }

    #[test]
    fn zip_limits_and_budget() {
        let x = vec![b'x'; 600];
        let five: Vec<(String, &[u8])> = (0..5).map(|i| (format!("f{i}"), x.as_slice())).collect();
        let five: Vec<(&str, &[u8])> = five.iter().map(|(n, d)| (n.as_str(), *d)).collect();
        let ex = extract_zip(&zip_of(&five, &[]), &LIM);
        assert_eq!(ex.members.len(), 3);
        assert!(
            noted(&ex, "scanned first 3") && noted(&ex, "truncated"),
            "{:?}",
            ex.notes
        );
        assert_eq!(ex.members.iter().map(|m| m.data.len()).sum::<usize>(), 1500);
        let lim = Limits {
            max_members: 10,
            max_member_size: 1000,
            max_total_size: 1000,
            max_ratio: 200,
        };
        let ex = extract_zip(&zip_of(&[("a", &[b'x'; 1000]), ("b", b"y")], &[]), &lim);
        assert_eq!(names(&ex), ["a"]);
        assert!(ex
            .notes
            .contains(&"total size budget exhausted".to_string()));
    }

    #[test]
    fn zip_bomb_encrypted_bad_and_unreadable() {
        let data = zip_of(
            &[
                ("bomb.bin", &vec![0u8; 2 * 1024 * 1024]),
                ("secret.txt", b"s"),
                ("ok.txt", b"fine"),
            ],
            &["secret.txt"],
        );
        let ex = extract_zip(&data, &Limits::default());
        assert!(
            ex.bomb && noted(&ex, "encrypted member skipped: secret.txt"),
            "{:?}",
            ex.notes
        );
        assert_eq!(names(&ex), ["ok.txt"]);
        let ex = extract(b"PK\x03\x04garbage", "zip", "x", &Limits::default());
        assert!(ex.notes[0].starts_with("bad zip"));
        let mut data = zip_of(&[("a.txt", &b"hello world".repeat(50))], &[]);
        let i = data.windows(4).position(|w| w == b"PK\x03\x04").unwrap() + 30 + "a.txt".len();
        data[i..i + 8].copy_from_slice(&[0xff; 8]); // corrupt the deflate stream
        let ex = extract_zip(&data, &Limits::default());
        assert!(ex.members.is_empty());
        assert!(
            ex.notes[0].starts_with("cannot read a.txt"),
            "{:?}",
            ex.notes
        );
    }

    #[test]
    fn tar_variants_limits_and_errors() {
        let t = tar_of(&[("a.sh", b"echo hi"), ("b.txt", &[b'x'; 600])]);
        for (data, tag) in [
            (t.clone(), "tar"),
            (gz(&t), "gzip"),
            (bz2(&t), "bzip2"),
            (xz(&t), "xz"),
        ] {
            let ex = extract(&data, tag, "t", &Limits::default());
            assert_eq!(names(&ex), ["a.sh", "b.txt"], "{tag}");
        }
        let x = vec![b'x'; 600];
        let five: Vec<(String, &[u8])> = (0..5).map(|i| (format!("f{i}"), x.as_slice())).collect();
        let five: Vec<(&str, &[u8])> = five.iter().map(|(n, d)| (n.as_str(), *d)).collect();
        let ex = extract_tar(&mut Cursor::new(tar_of(&five)), &LIM);
        assert_eq!(ex.members.len(), 3);
        assert!(
            noted(&ex, "more than 3") && noted(&ex, "truncated"),
            "{:?}",
            ex.notes
        );
        let lim = Limits {
            max_members: 10,
            max_member_size: 1000,
            max_total_size: 1000,
            max_ratio: 200,
        };
        let ex = extract_tar(
            &mut Cursor::new(tar_of(&[("a", &[b'x'; 1000]), ("b", b"y")])),
            &lim,
        );
        assert_eq!(names(&ex), ["a"]);
        assert!(ex
            .notes
            .contains(&"total size budget exhausted".to_string()));
        let ex = extract(&[0u8; 10], "tar", "t", &Limits::default());
        assert!(
            ex.notes.first().is_some_and(|n| n.starts_with("bad tar")),
            "{:?}",
            ex.notes
        );
        // header fine, body cut short
        let good = tar_of(&[("a", &[b'x'; 2000])]);
        let ex = extract_tar(&mut Cursor::new(&good[..1024]), &Limits::default());
        assert!(noted(&ex, "tar read error"), "{:?}", ex.notes);
    }

    #[test]
    fn tar_symlinks_are_skipped() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "link", "/etc/passwd").unwrap();
        let ex = extract_tar(
            &mut Cursor::new(b.into_inner().unwrap()),
            &Limits::default(),
        );
        assert!(ex.members.is_empty());
    }

    #[test]
    fn compressed_single_streams() {
        let one = |data: Vec<u8>, tag: &str, name: &str| {
            let ex = extract(&data, tag, name, &Limits::default());
            (ex.members[0].name.clone(), ex.members[0].data.clone())
        };
        assert_eq!(
            one(gz(b"payload"), "gzip", "evil.js.gz"),
            ("evil.js".into(), b"payload".to_vec())
        );
        assert_eq!(one(bz2(b"p"), "bzip2", "a.bz2").0, "a");
        assert_eq!(one(xz(b"p"), "xz", "noext").0, "noext.out");
        assert_eq!(one(gz(b"p"), "gzip", ".gz").0, "payload");
        let lim = Limits {
            max_member_size: 1000,
            max_ratio: 5,
            ..Limits::default()
        };
        let ex = extract(&gz(&[0u8; 100_000]), "gzip", "b.gz", &lim);
        assert!(ex.bomb && ex.members[0].data.len() == 1000);
        let ex = extract(&gz(&noise(3000)), "gzip", "r.gz", &lim);
        assert!(!ex.bomb && noted(&ex, "truncated"), "{:?}", ex.notes);
        let ex = extract(b"\x1f\x8b\x08garbage", "gzip", "bad.gz", &Limits::default());
        assert!(ex.members.is_empty());
        assert!(
            ex.notes.iter().any(|n| n.starts_with("bad stream")),
            "{:?}",
            ex.notes
        );
        let ex = extract(b"Rar!\x1a\x07", "rar", "x.rar", &Limits::default());
        assert!(ex.members.is_empty() && ex.notes[0].contains("not unpacked"));
    }
}
