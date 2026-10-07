//! Identify a file by content (magic bytes / shebang), not extension
//! (port of guard_av/filetype.py).

use super::pystr;

const MAGIC: &[(&[u8], usize, &str)] = &[
    (b"MZ", 0, "pe"),
    (b"\x7fELF", 0, "elf"),
    (b"\xfe\xed\xfa\xce", 0, "macho"),
    (b"\xfe\xed\xfa\xcf", 0, "macho"),
    (b"\xce\xfa\xed\xfe", 0, "macho"),
    (b"\xcf\xfa\xed\xfe", 0, "macho"),
    (b"\xca\xfe\xba\xbe", 0, "macho-fat"), // also Java .class; disambiguated below
    (b"PK\x03\x04", 0, "zip"),
    (b"PK\x05\x06", 0, "zip"),
    (b"\x1f\x8b", 0, "gzip"),
    (b"BZh", 0, "bzip2"),
    (b"\xfd7zXZ\x00", 0, "xz"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z"),
    (b"Rar!\x1a\x07", 0, "rar"),
    (b"ustar", 257, "tar"),
    (b"%PDF-", 0, "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole"),
    (b"{\\rtf", 0, "rtf"),
    (b"\x89PNG\r\n\x1a\n", 0, "png"),
    (b"\xff\xd8\xff", 0, "jpeg"),
    (b"GIF87a", 0, "gif"),
    (b"GIF89a", 0, "gif"),
    (b"wOF2", 0, "woff2"),
    (b"wOFF", 0, "woff"),
    (b"\x00asm", 0, "wasm"),
    (b"dex\n", 0, "dex"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", 0, "lnk"),
    (b"SQLite format 3\x00", 0, "sqlite"),
];

/// Longest key first, as filetype.py sorts them.
const SHEBANGS: &[(&str, &str)] = &[
    ("powershell", "powershell"),
    ("python2", "python"),
    ("python3", "python"),
    ("python", "python"),
    ("bash", "shell"),
    ("dash", "shell"),
    ("node", "javascript"),
    ("perl", "perl"),
    ("ruby", "ruby"),
    ("pwsh", "powershell"),
    ("zsh", "shell"),
    ("ksh", "shell"),
    ("php", "php"),
    ("sh", "shell"),
];

fn ext_script(ext: &str) -> Option<&'static str> {
    Some(match ext {
        ".js" | ".mjs" | ".cjs" | ".jsx" | ".ts" | ".tsx" => "javascript",
        ".py" | ".pyw" => "python",
        ".sh" | ".bash" | ".zsh" => "shell",
        ".ps1" | ".psm1" | ".psd1" => "powershell",
        ".bat" | ".cmd" => "batch",
        ".vbs" | ".vbe" | ".vba" | ".bas" => "vbscript",
        ".php" | ".phtml" => "php",
        ".pl" => "perl",
        ".rb" => "ruby",
        ".hta" | ".html" | ".htm" => "html",
        _ => return None,
    })
}

pub const DOCUMENT_EXTS: &[&str] = &[
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg", ".jpeg",
    ".png", ".gif", ".mp3", ".mp4", ".avi", ".mov", ".csv", ".odt",
];

pub fn is_executable(tag: &str) -> bool {
    matches!(tag, "pe" | "elf" | "macho" | "macho-fat" | "dex")
}

pub fn is_archive(tag: &str) -> bool {
    matches!(tag, "zip" | "gzip" | "tar" | "bzip2" | "xz" | "7z" | "rar")
}

pub fn is_script(tag: &str) -> bool {
    matches!(
        tag,
        "javascript"
            | "python"
            | "shell"
            | "powershell"
            | "batch"
            | "vbscript"
            | "php"
            | "perl"
            | "ruby"
            | "html"
    )
}

fn is_text(head: &[u8]) -> bool {
    if head.is_empty() {
        return true;
    }
    if head.contains(&0) {
        return head.starts_with(b"\xff\xfe") || head.starts_with(b"\xfe\xff");
    }
    match std::str::from_utf8(head) {
        Ok(_) => true,
        // a multi-byte char cut at the end of the sniff window is still text
        Err(e) => e.valid_up_to() + 3 >= head.len(),
    }
}

/// A type tag for a buffer (pass at least the first 512 bytes).
pub fn identify(head: &[u8], name: &str) -> &'static str {
    for &(magic, off, tag) in MAGIC {
        if head.len() >= off + magic.len() && &head[off..off + magic.len()] == magic {
            if tag == "macho-fat" && head.len() >= 8 {
                let v = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
                if v >= 45 {
                    return "java-class";
                }
            }
            return tag;
        }
    }
    if head.starts_with(b"#!") {
        let window = &head[2..head.len().min(120)];
        let line = window.split(|&b| b == b'\n').next().unwrap_or(b"");
        let line: String = line.iter().map(|&b| b as char).collect(); // latin-1
        let parts = pystr::split_ws(&line);
        let mut prog = "";
        if let Some(first) = parts.first() {
            prog = pystr::name(first);
            if prog == "env" && parts.len() > 1 {
                prog = parts[1];
            }
        }
        for &(key, tag) in SHEBANGS {
            if prog.starts_with(key) {
                return tag;
            }
        }
        return "script";
    }
    if is_text(head) {
        let ext = if name.is_empty() {
            String::new()
        } else {
            pystr::suffix(name).to_lowercase()
        };
        return ext_script(&ext).unwrap_or("text");
    }
    "binary"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies() {
        assert_eq!(identify(b"MZ\x90\x00", "x.txt"), "pe");
        assert_eq!(
            identify(b"\xca\xfe\xba\xbe\x00\x00\x00\x34", ""),
            "java-class"
        );
        assert_eq!(
            identify(b"\xca\xfe\xba\xbe\x00\x00\x00\x02", ""),
            "macho-fat"
        );
        assert_eq!(identify(b"#!/usr/bin/env python3\n", ""), "python");
        assert_eq!(identify(b"#!/bin/bash -e\n", ""), "shell");
        assert_eq!(identify(b"#!/opt/thing\n", ""), "script");
        assert_eq!(identify(b"console.log(1)", "a.JS"), "javascript");
        assert_eq!(identify(b"hello \xe2\x82", "a"), "text");
        assert_eq!(identify(b"\xff\x00\x01", "a"), "binary");
    }

    /// test_av_core.py test_identify / test_type_groups.
    #[test]
    fn identifies_like_filetype_py() {
        let pe = [b"MZ".as_slice(), &[0u8; 0x3A], &0x40u32.to_le_bytes()].concat();
        let ustar = [vec![0u8; 257], b"ustar\x0000".to_vec()].concat();
        let cases: &[(&[u8], &str, &str)] = &[
            (&pe, "", "pe"),
            (b"\x7fELF\x02\x01\x01\0\0", "", "elf"),
            (b"\xcf\xfa\xed\xfe\0\0\0\0\0\0\0\0", "", "macho"),
            (b"\xca\xfe\xba\xbe", "", "macho-fat"),
            (b"PK\x03\x04rest", "", "zip"),
            (b"\x1f\x8b\x08", "", "gzip"),
            (&ustar, "", "tar"),
            (b"%PDF-1.7", "", "pdf"),
            (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "", "ole"),
            (b"#!/usr/bin/env\n", "", "script"),
            (b"#!\n", "", "script"),
            (b"#!/usr/local/bin/node\n", "", "javascript"),
            (b"Write-Host hi", "a.PS1", "powershell"),
            (b"plain words", "notes", "text"),
            (b"", "", "text"),
            (b"\xff\xfeh\x00i\x00", "", "text"),
            (b"caf\xc3", "", "text"),
            (b"\x00\x01\x02\x03binary", "", "binary"),
            (b"\xc3\x28xxxxxxxxxxxxxxxxxxxx", "", "binary"),
        ];
        for (head, name, tag) in cases {
            assert_eq!(identify(head, name), *tag, "{head:?} {name}");
        }
        assert!(is_executable("pe") && !is_executable("zip"));
        assert!(is_archive("tar") && !is_archive("pe"));
        assert!(is_script("powershell") && !is_script("text"));
    }
}
