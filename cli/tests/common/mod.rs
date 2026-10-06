//! Shared harness for the guard binary's integration tests.
//!
//! Every test builds its input, runs `guard`, normalises what can't repeat
//! (scratch paths, timings, random ids) and compares the result with a golden
//! file in tests/golden/. The goldens were recorded from guard.py, the Python
//! build this binary replaced, so these tests keep proving the binary behaves
//! the way the Python one did.
//!
//! Environment:
//!   GUARD_RS_BIN=path        test this binary instead of the one cargo built
//!   GUARD_REFERENCE=guard.py run a reference build instead (`python3 guard.py`)
//!   GUARD_GOLDEN=record      write the goldens instead of checking them
//!   GUARD_GOLDEN=record-os   write this OS's overrides (<name>.<os>.b64) where
//!                            its output differs from the shared golden
//!
//! Goldens are base64 text: several hold detection evidence from the malware
//! samples, and in plain text that would make Guard (and other scanners) flag
//! this repository. Read one with `base64 -d < tests/golden/av/<name>.b64`.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use base64::Engine;
use serde_json::Value;

pub mod fixtures;
pub mod samples;
pub mod server;

pub const WINDOWS: bool = cfg!(windows);

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

pub fn bin() -> PathBuf {
    match std::env::var_os("GUARD_RS_BIN") {
        // a relative path is from the repository root, as CI passes it
        Some(p) => repo_root().join(p),
        None => PathBuf::from(env!("CARGO_BIN_EXE_guard")),
    }
}

/// guard.py when recording or re-checking goldens against the Python build.
pub fn reference() -> Option<PathBuf> {
    std::env::var_os("GUARD_REFERENCE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// The interpreter, found on this process's PATH (a test may empty the child's).
fn python() -> PathBuf {
    let name = std::env::var("GUARD_PYTHON").unwrap_or_else(|_| {
        if WINDOWS {
            "python".into()
        } else {
            "python3".into()
        }
    });
    let exe = if WINDOWS && !name.ends_with(".exe") {
        format!("{name}.exe")
    } else {
        name.clone()
    };
    std::env::var_os("PATH")
        .and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join(&exe))
                .find(|c| c.is_file())
        })
        .unwrap_or_else(|| PathBuf::from(name))
}

#[derive(Debug, Clone)]
pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    pub raw_stdout: Vec<u8>,
}

impl Out {
    /// Exit code and stdout, the usual golden.
    pub fn shown(&self) -> String {
        format!("exit {}\n--- stdout\n{}", self.code, self.stdout)
    }
    /// Exit code, stdout and stderr.
    pub fn shown_all(&self) -> String {
        format!(
            "exit {}\n--- stdout\n{}--- stderr\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

pub fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).replace("\r\n", "\n")
}

/// A command for guard (or, with GUARD_REFERENCE, guard.py).
pub struct Guard {
    args: Vec<String>,
    env: Vec<(String, String)>,
    remove: Vec<String>,
    cwd: Option<PathBuf>,
    exe: Option<PathBuf>,
    stdin: Option<Vec<u8>>,
}

pub fn guard<S: AsRef<str>>(args: &[S]) -> Guard {
    Guard {
        args: args.iter().map(|a| a.as_ref().to_string()).collect(),
        env: Vec::new(),
        remove: Vec::new(),
        cwd: None,
        exe: None,
        stdin: None,
    }
}

impl Guard {
    pub fn env(mut self, k: &str, v: impl AsRef<std::ffi::OsStr>) -> Self {
        self.env
            .push((k.into(), v.as_ref().to_string_lossy().into_owned()));
        self
    }
    pub fn env_remove(mut self, k: &str) -> Self {
        self.remove.push(k.into());
        self
    }
    pub fn home(self, p: &Path) -> Self {
        self.env("GUARD_HOME", p)
    }
    pub fn cwd(mut self, p: &Path) -> Self {
        self.cwd = Some(p.to_path_buf());
        self
    }
    /// Always run this executable, even when recording from the reference.
    pub fn exe(mut self, p: &Path) -> Self {
        self.exe = Some(p.to_path_buf());
        self
    }
    pub fn stdin(mut self, data: &[u8]) -> Self {
        self.stdin = Some(data.to_vec());
        self
    }

    pub fn command(&self) -> Command {
        let mut cmd = match (&self.exe, reference()) {
            (Some(exe), _) => Command::new(exe),
            (None, Some(py)) => {
                let mut c = Command::new(python());
                c.arg(py);
                c
            }
            (None, None) => Command::new(bin()),
        };
        cmd.args(&self.args);
        // no proxies: the tests talk to local servers or nothing at all
        for (k, _) in std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?, v))) {
            if k.to_lowercase().contains("proxy") {
                cmd.env_remove(&k);
            }
        }
        for k in &self.remove {
            cmd.env_remove(k);
        }
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        if let Some(d) = &self.cwd {
            cmd.current_dir(d);
        }
        cmd
    }

    pub fn run(&self) -> Out {
        let mut cmd = self.command();
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        cmd.stdin(if self.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("cannot run {cmd:?}: {e}"));
        if let Some(data) = &self.stdin {
            use std::io::Write;
            let mut si = child.stdin.take().unwrap();
            si.write_all(data).unwrap();
        }
        let o = child.wait_with_output().unwrap();
        Out {
            code: o.status.code().unwrap_or(-1),
            stdout: text(&o.stdout),
            stderr: text(&o.stderr),
            raw_stdout: o.stdout,
        }
    }
}

// ---------------------------------------------------------------- scratch
static SEQ: AtomicU32 = AtomicU32::new(0);

/// A scratch directory, removed on drop.
pub struct Tmp {
    pub path: PathBuf,
}

impl Tmp {
    pub fn new(tag: &str) -> Tmp {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!("guard-it-{}-{n}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        // the canonical spelling (macOS: /private/var/...), as the tools print it
        let path = fs::canonicalize(&base).unwrap_or(base);
        Tmp {
            path: strip_verbatim(path),
        }
    }
    pub fn join(&self, p: impl AsRef<Path>) -> PathBuf {
        self.path.join(p)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        if std::env::var_os("GUARD_KEEP_TMP").is_none() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// canonicalize() on Windows returns \\?\C:\...; tools print C:\...
pub fn strip_verbatim(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => p,
    }
}

pub fn write(path: &Path, data: impl AsRef<[u8]>) -> PathBuf {
    if let Some(d) = path.parent() {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(path, data).unwrap();
    path.to_path_buf()
}

pub fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for e in fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let ft = e.file_type().unwrap();
        let to = dst.join(e.file_name());
        if ft.is_dir() {
            copy_tree(&e.path(), &to);
        } else if ft.is_file() {
            fs::copy(e.path(), to).unwrap();
        }
    }
}

pub fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

// ------------------------------------------------------------ normalising
/// Replaces scratch paths with placeholders (in plain and JSON-escaped form),
/// and writes the path separators after a placeholder as "/", so a golden
/// recorded on one OS reads the same on the others.
#[derive(Default, Clone)]
pub struct Norm {
    paths: Vec<(String, String)>,
    literal: Vec<(String, String)>,
    regex: Vec<(regex::Regex, String)>,
}

impl Norm {
    pub fn new() -> Norm {
        Norm::default()
    }
    pub fn path(mut self, p: &Path, name: &str) -> Norm {
        let tag = format!("<{name}>");
        let mut forms = vec![s(p)];
        if let Ok(c) = fs::canonicalize(p) {
            forms.push(s(&strip_verbatim(c)));
        }
        for f in forms {
            if !self.paths.iter().any(|(a, _)| *a == f) {
                self.paths.push((f, tag.clone()));
            }
        }
        // longest first, so nested roots win
        self.paths.sort_by_key(|a| std::cmp::Reverse(a.0.len()));
        self
    }
    pub fn lit(mut self, from: &str, to: &str) -> Norm {
        self.literal.push((from.into(), to.into()));
        self
    }
    pub fn re(mut self, pat: &str, to: &str) -> Norm {
        self.regex
            .push((regex::Regex::new(pat).unwrap(), to.into()));
        self
    }

    pub fn apply(&self, input: &str) -> String {
        let mut out = input.to_string();
        let mut tags = Vec::new();
        for (from, tag) in &self.paths {
            let escaped = from.replace('\\', "\\\\");
            if escaped != *from {
                out = out.replace(&escaped, tag);
            }
            out = out.replace(from, tag);
            tags.push(tag.clone());
        }
        if WINDOWS {
            out = slashes_after(&out, &tags);
        }
        for (a, b) in &self.literal {
            out = out.replace(a, b);
        }
        for (r, b) in &self.regex {
            out = r.replace_all(&out, b.as_str()).into_owned();
        }
        out
    }
}

/// `<T>\a\b` and `<T>\\a\\b` -> `<T>/a/b`, up to the end of the path.
fn slashes_after(s: &str, tags: &[String]) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    'outer: while !rest.is_empty() {
        for t in tags {
            if let Some(after) = rest.strip_prefix(t.as_str()) {
                out.push_str(t);
                let mut it = after.char_indices().peekable();
                let mut end = after.len();
                while let Some((i, c)) = it.next() {
                    match c {
                        '\\' => {
                            out.push('/');
                            if let Some((_, '\\')) = it.peek() {
                                it.next();
                            }
                        }
                        '"' | '\n' | '\'' | ')' | ',' | ']' => {
                            end = i;
                            break;
                        }
                        c => out.push(c),
                    }
                }
                rest = &after[end..];
                continue 'outer;
            }
        }
        let c = rest.chars().next().unwrap();
        out.push(c);
        rest = &rest[c.len_utf8()..];
    }
    out
}

/// JSON text with sorted keys, two-space indented: dict order doesn't matter
/// (Python compared dicts with ==), list order does.
pub fn canon_json(v: &Value) -> String {
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let sorted: BTreeMap<&String, Value> =
                    m.iter().map(|(k, v)| (k, sort(v))).collect();
                let mut out = serde_json::Map::new();
                for (k, v) in sorted {
                    out.insert(k.clone(), v);
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_string_pretty(&sort(v)).unwrap() + "\n"
}

pub fn parse_json(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or_else(|e| panic!("not JSON ({e}):\n{s}"))
}

// ----------------------------------------------------------------- goldens
fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
}

fn os_tag() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

fn b64_wrapped(s: &str) -> String {
    let enc = base64::engine::general_purpose::STANDARD.encode(s.as_bytes());
    let mut out = String::new();
    for chunk in enc.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out
}

fn b64_read(p: &Path) -> String {
    let raw: String = fs::read_to_string(p).unwrap().split_whitespace().collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .unwrap();
    String::from_utf8(bytes).unwrap()
}

/// Check `actual` against tests/golden/<suite>/<name>.b64 (or the per-OS
/// <name>.<os>.b64 when one exists), or record it with GUARD_GOLDEN=record.
pub fn golden(suite: &str, name: &str, actual: &str) {
    let dir = golden_dir().join(suite);
    let per_os = dir.join(format!("{name}.{}.b64", os_tag()));
    let shared = dir.join(format!("{name}.b64"));
    let mode = std::env::var("GUARD_GOLDEN").unwrap_or_default();
    if mode == "record" {
        fs::create_dir_all(&dir).unwrap();
        fs::write(&shared, b64_wrapped(actual)).unwrap();
        return;
    }
    // this OS's override, only where it differs from the shared golden
    if mode == "record-os" {
        if shared.exists() && b64_read(&shared) == actual {
            let _ = fs::remove_file(&per_os);
        } else {
            fs::create_dir_all(&dir).unwrap();
            fs::write(&per_os, b64_wrapped(actual)).unwrap();
        }
        return;
    }
    let file = if per_os.exists() { per_os } else { shared };
    if !file.exists() {
        panic!("no golden {} (record it with GUARD_GOLDEN=record GUARD_REFERENCE=guard.py); actual:\n{actual}", file.display());
    }
    let want = b64_read(&file);
    if want != actual {
        let (w, a): (Vec<&str>, Vec<&str>) = (want.lines().collect(), actual.lines().collect());
        let first = w
            .iter()
            .zip(&a)
            .position(|(x, y)| x != y)
            .unwrap_or(w.len().min(a.len()));
        let lo = first.saturating_sub(3);
        let mut msg = format!(
            "{} differs from the golden at line {}:\n",
            file.display(),
            first + 1
        );
        for i in lo..(first + 4).min(w.len().max(a.len())) {
            if let Some(x) = w.get(i) {
                msg.push_str(&format!("  want {:>4}| {x}\n", i + 1));
            }
            if let Some(y) = a.get(i) {
                msg.push_str(&format!("  got  {:>4}| {y}\n", i + 1));
            }
        }
        msg.push_str(&format!(
            "\nfull actual output (base64, for a per-OS golden):\n{}",
            b64_wrapped(actual)
        ));
        panic!("{msg}");
    }
}
