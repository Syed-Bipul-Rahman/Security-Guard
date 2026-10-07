//! Synthetic binaries and archives for the tests, ported from tests/conftest.py.

use std::io::Write;

pub const EXEC: u32 = 0x2000_0000;
pub const WRITE: u32 = 0x8000_0000;
pub const READ: u32 = 0x4000_0000;
pub const CODE: u32 = 0x0000_0020;

/// Deterministic noise (splitmix64).
pub fn random_bytes(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut out = Vec::with_capacity(n + 8);
    while out.len() < n {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        out.extend_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    }
    out.truncate(n);
    out
}

pub struct Section<'a> {
    pub name: &'a [u8],
    pub flags: u32,
    pub body: Vec<u8>,
}

pub fn section(name: &[u8], flags: u32, body: Vec<u8>) -> Section<'_> {
    Section { name, flags, body }
}

/// A minimal, structurally valid PE32 image; section virtual addresses are
/// 0x1000, 0x2000, ... in order.
pub fn build_pe_with(
    sections: &[Section],
    entry: u32,
    extra: &[u8],
    opt_magic: u16,
    dll: bool,
) -> Vec<u8> {
    let opt_size: usize = 0xE0;
    let headers = 0x40 + 4 + 20 + opt_size + 40 * sections.len();
    let raw = (headers + 0x1FF) & !0x1FF;
    let mut dos = vec![0u8; 0x40];
    dos[0..2].copy_from_slice(b"MZ");
    dos[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    let mut coff = Vec::new();
    coff.extend_from_slice(&0x14Cu16.to_le_bytes());
    coff.extend_from_slice(&(sections.len() as u16).to_le_bytes());
    coff.extend_from_slice(&[0u8; 12]);
    coff.extend_from_slice(&(opt_size as u16).to_le_bytes());
    coff.extend_from_slice(&(if dll { 0x2000u16 } else { 0x0102 }).to_le_bytes());
    let mut opt = vec![0u8; opt_size];
    opt[0..2].copy_from_slice(&opt_magic.to_le_bytes());
    opt[16..20].copy_from_slice(&entry.to_le_bytes());
    let (mut table, mut bodies) = (Vec::new(), Vec::new());
    let mut ptr = raw as u32;
    for (i, s) in sections.iter().enumerate() {
        let mut name = [0u8; 8];
        name[..s.name.len().min(8)].copy_from_slice(&s.name[..s.name.len().min(8)]);
        table.extend_from_slice(&name);
        let len = s.body.len() as u32;
        for v in [len, 0x1000 * (i as u32 + 1), len, ptr, 0, 0] {
            table.extend_from_slice(&v.to_le_bytes());
        }
        table.extend_from_slice(&[0u8; 4]);
        table.extend_from_slice(&s.flags.to_le_bytes());
        bodies.extend_from_slice(&s.body);
        ptr += len;
    }
    let mut out = [dos, b"PE\0\0".to_vec(), coff, opt, table].concat();
    out.resize(raw, 0);
    out.extend_from_slice(&bodies);
    out.extend_from_slice(extra);
    out
}

pub fn build_pe() -> Vec<u8> {
    build_pe_with(
        &[
            section(b".text", EXEC | READ | CODE, vec![0x90; 512]),
            section(b".data", READ | WRITE, vec![0; 512]),
        ],
        0x1000,
        b"",
        0x10B,
        false,
    )
}

pub fn build_elf(body: &[u8]) -> Vec<u8> {
    [b"\x7fELF\x02\x01\x01".as_slice(), &[0u8; 9], body].concat()
}

fn zip_options() -> zip::write::SimpleFileOptions {
    zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).unwrap())
}

/// A deflated zip; names ending in "/" are directories. Members in
/// `encrypt_flag` get the "encrypted" bit set in both headers (without being
/// encrypted).
pub fn make_zip(files: &[(&str, &[u8])], encrypt_flag: &[&str]) -> Vec<u8> {
    let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data) in files {
        if name.ends_with('/') {
            zw.add_directory(name.trim_end_matches('/'), zip_options())
                .unwrap();
        } else {
            zw.start_file(*name, zip_options()).unwrap();
            zw.write_all(data).unwrap();
        }
    }
    let mut raw = zw.finish().unwrap().into_inner();
    for name in encrypt_flag {
        let enc = name.as_bytes();
        for (sig, off, hdr) in [(b"PK\x03\x04", 6usize, 30usize), (b"PK\x01\x02", 8, 46)] {
            let mut i = 0;
            while let Some(p) = find(&raw, sig, i) {
                let n = p + hdr;
                if raw.get(n..n + enc.len()) == Some(enc) {
                    raw[p + off] |= 0x1;
                }
                i = p + 4;
            }
        }
    }
    raw
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    hay.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// A tar with these files and an empty directory "adir".
pub fn make_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, data) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_cksum();
        b.append_data(&mut h, name, *data).unwrap();
    }
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Directory);
    h.set_size(0);
    h.set_mode(0o755);
    h.set_mtime(0);
    h.set_cksum();
    b.append_data(&mut h, "adir", std::io::empty()).unwrap();
    b.into_inner().unwrap()
}

pub fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

pub fn bz2(data: &[u8]) -> Vec<u8> {
    let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

pub fn xz(data: &[u8]) -> Vec<u8> {
    let mut w =
        lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6)).unwrap();
    w.write_all(data).unwrap();
    w.finish().unwrap()
}
