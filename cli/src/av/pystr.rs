//! Python string and path semantics the av output depends on: str.strip /
//! str.split whitespace, PurePath name / suffix / suffixes, str() of JSON
//! values and how an OSError prints.

use serde_json::Value;

/// str.isspace for one character (Rust's is_whitespace misses \x1c-\x1f).
pub fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

pub fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// str.split() with no separator.
pub fn split_ws(s: &str) -> Vec<&str> {
    s.split(is_space).filter(|p| !p.is_empty()).collect()
}

/// str() of a JSON value.
pub fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => crate::pyrepr::repr(other),
    }
}

fn is_sep(c: char) -> bool {
    c == '/' || (cfg!(windows) && c == '\\')
}

/// PurePath(p).name
pub fn name(p: &str) -> &str {
    let mut p = p;
    if cfg!(windows) {
        let b = p.as_bytes();
        if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
            p = &p[2..];
        }
    }
    p.split(is_sep)
        .rfind(|part| !part.is_empty() && *part != ".")
        .unwrap_or("")
}

/// PurePath(p).suffix
pub fn suffix(p: &str) -> &str {
    let n = name(p);
    match n.rfind('.') {
        Some(i) if i > 0 && i < n.len() - 1 => &n[i..],
        _ => "",
    }
}

/// PurePath(p).suffixes
pub fn suffixes(p: &str) -> Vec<String> {
    let n = name(p);
    if n.ends_with('.') {
        return Vec::new();
    }
    n.trim_start_matches('.')
        .split('.')
        .skip(1)
        .map(|s| format!(".{s}"))
        .collect()
}

/// The exception class an OSError would have in Python.
pub fn os_error_class(e: &std::io::Error) -> &'static str {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotFound => "FileNotFoundError",
        PermissionDenied => "PermissionError",
        IsADirectory => "IsADirectoryError",
        NotADirectory => "NotADirectoryError",
        AlreadyExists => "FileExistsError",
        _ => "OSError",
    }
}

/// str(OSError) for a failed call on `path`: "[Errno N] text: 'path'".
pub fn os_error(e: &std::io::Error, path: &str) -> String {
    let (code, text) = errno_text(e);
    let base = match code {
        Some(n) => format!("[Errno {n}] {text}"),
        None => text,
    };
    if path.is_empty() {
        base
    } else {
        format!("{base}: {}", crate::pyrepr::str_repr(path))
    }
}

#[cfg(not(windows))]
fn errno_text(e: &std::io::Error) -> (Option<i32>, String) {
    let full = e.to_string();
    match e.raw_os_error() {
        Some(n) => {
            let tail = format!(" (os error {n})");
            (
                Some(n),
                full.strip_suffix(&tail).unwrap_or(&full).to_string(),
            )
        }
        None => (None, full),
    }
}

/// Python's open() on Windows reports C-runtime errno values, not Win32 codes.
#[cfg(windows)]
fn errno_text(e: &std::io::Error) -> (Option<i32>, String) {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotFound => (Some(2), "No such file or directory".into()),
        PermissionDenied => (Some(13), "Permission denied".into()),
        AlreadyExists => (Some(17), "File exists".into()),
        _ => (e.raw_os_error(), e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purepath_parts() {
        assert_eq!(name("a/b.tar.gz"), "b.tar.gz");
        assert_eq!(name("x.zip!dir/inner.exe"), "inner.exe");
        assert_eq!(name("a/b/"), "b");
        assert_eq!(name("."), "");
        assert_eq!(suffix("a/.bashrc"), "");
        assert_eq!(suffix("a/b.tar.gz"), ".gz");
        assert_eq!(suffix("x."), "");
        assert_eq!(suffixes("report.pdf.exe"), vec![".pdf", ".exe"]);
        assert_eq!(suffixes("..a.b"), vec![".b"]);
        assert!(suffixes("a.b.").is_empty());
        assert_eq!(strip("\x1c x \u{a0}"), "x");
    }
}
