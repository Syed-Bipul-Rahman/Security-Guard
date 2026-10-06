//! Python text, path and regex semantics the scanner and remediator output
//! depends on: str.splitlines, universal newlines on read_text / write_text,
//! code-point slicing, and `re` patterns run on Rust's regex engine.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use regex::Regex;
use sha2::{Digest, Sha256};

pub use crate::av::pystr::strip;

/// str.splitlines(): every Python line boundary, no trailing empty part.
pub fn splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        let brk = matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !brk {
            continue;
        }
        out.push(&s[start..i]);
        let mut next = i + c.len_utf8();
        if c == '\r' {
            if let Some((_, '\n')) = it.peek() {
                it.next();
                next += 1;
            }
        }
        start = next;
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// Universal-newlines translation done by Python's text-mode reads.
pub fn universal(s: String) -> String {
    if !s.contains('\r') {
        return s;
    }
    s.replace("\r\n", "\n").replace('\r', "\n")
}

/// Path.read_text(encoding="utf-8", errors="replace").
pub fn read_text(p: &Path) -> io::Result<String> {
    let b = fs::read(p)?;
    Ok(universal(String::from_utf8_lossy(&b).into_owned()))
}

/// The text as Path.write_text() stores it ("\n" becomes os.linesep).
pub fn text_bytes(s: &str) -> Vec<u8> {
    if cfg!(windows) {
        s.replace('\n', "\r\n").into_bytes()
    } else {
        s.as_bytes().to_vec()
    }
}

pub fn write_text(p: &Path, s: &str) -> io::Result<()> {
    fs::write(p, text_bytes(s))
}

pub fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// s[:n] in code points.
pub fn head(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// str(Path(a) / b): b's "/" separators become the platform's.
pub fn join(a: &str, b: &str) -> String {
    crate::deps::py_path_str(&format!("{a}/{b}"))
}

/// str(Path(p).resolve()): absolute, symlinks resolved, missing tail kept.
pub fn resolve(p: &str) -> String {
    let path = Path::new(p);
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut done = PathBuf::new();
    let mut rest: Vec<_> = abs.components().collect();
    rest.reverse();
    while let Some(c) = rest.pop() {
        use std::path::Component::*;
        match c {
            CurDir => {}
            ParentDir => {
                done.pop();
            }
            other => {
                let next = done.join(other);
                match fs::canonicalize(&next) {
                    Ok(real) => done = real,
                    Err(_) => {
                        done = next;
                        for c in rest.into_iter().rev() {
                            match c {
                                CurDir => {}
                                ParentDir => {
                                    done.pop();
                                }
                                o => done.push(o),
                            }
                        }
                        break;
                    }
                }
            }
        }
    }
    let s = done.to_string_lossy().into_owned();
    if cfg!(windows) {
        if let Some(unc) = s.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{unc}");
        }
        if let Some(local) = s.strip_prefix(r"\\?\") {
            return local.to_string();
        }
    }
    s
}

/// re.sub(r"[^A-Za-z0-9._-]", "_", s)
pub fn safe_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// A Python `re` pattern for Rust's regex crate. Python's \s also matches
/// \x1c-\x1f and \Z is \z; a pattern using what Rust's engine lacks
/// (backreferences, lookaround) fails to compile instead.
pub fn translate(pat: &str) -> String {
    const WS: &str = r"\s\x1c-\x1f";
    let mut out = String::new();
    let mut in_class = false;
    let mut chars = pat.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('s') if in_class => out.push_str(WS),
                Some('s') => out.push_str(&format!("[{WS}]")),
                Some('S') => out.push_str(&format!("[^{WS}]")),
                Some('Z') if !in_class => out.push_str(r"\z"),
                Some(x) => {
                    out.push('\\');
                    out.push(x);
                }
                None => out.push('\\'),
            },
            '[' if !in_class => {
                in_class = true;
                out.push('[');
                if chars.peek() == Some(&'^') {
                    chars.next();
                    out.push('^');
                }
                if chars.peek() == Some(&']') {
                    chars.next();
                    out.push_str(r"\]");
                }
            }
            '[' => out.push_str(r"\["),
            ']' if in_class => {
                in_class = false;
                out.push(']');
            }
            '&' | '~' | '-' if in_class && chars.peek() == Some(&c) => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// re.compile(pattern, flags) for "DOTALL|IGNORECASE|MULTILINE" flag names.
pub fn compile(pattern: &str, flags: &str) -> Result<Regex, String> {
    let mut inline = String::new();
    for f in flags.split('|') {
        match strip(f).to_uppercase().as_str() {
            "DOTALL" => inline.push('s'),
            "IGNORECASE" => inline.push('i'),
            "MULTILINE" => inline.push('m'),
            _ => {}
        }
    }
    let prefix = if inline.is_empty() {
        String::new()
    } else {
        format!("(?{inline})")
    };
    Regex::new(&format!("{prefix}{}", translate(pattern)))
        .map_err(|e| format!("regex {pattern:?} is not supported: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_and_slices() {
        assert_eq!(
            splitlines("a\r\nb\rc\x0bd\u{2028}e\n"),
            vec!["a", "b", "c", "d", "e"]
        );
        assert_eq!(splitlines("\n\nx"), vec!["", "", "x"]);
        assert!(splitlines("").is_empty());
        assert_eq!(head("héllo", 2), "hé");
        assert_eq!(head("hi", 5), "hi");
        assert_eq!(universal("a\r\nb\rc".into()), "a\nb\nc");
        assert_eq!(safe_name("/a b/ç.js"), "_a_b__.js");
    }

    #[test]
    fn python_regex() {
        assert_eq!(
            translate(r"a\s[\s,]\S\Z"),
            r"a[\s\x1c-\x1f][\s\x1c-\x1f,][^\s\x1c-\x1f]\z"
        );
        assert_eq!(translate(r"[]a[]"), r"[\]a\[]");
        assert!(compile(r"x\s+y", "").unwrap().is_match("x\x1cy"));
        assert!(compile(r"a.b", "DOTALL").unwrap().is_match("a\nb"));
        assert!(compile(r"(?<=a)b", "").is_err());
    }
}
