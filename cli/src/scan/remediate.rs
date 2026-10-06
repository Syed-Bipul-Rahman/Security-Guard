//! `guard clean` / `guard restore` (port of remediator.py): cut injected
//! malicious IIFEs out of real source files, quarantine whole-file droppers,
//! drop auto-run settings and tasks from .vscode. Every change is backed up to
//! <guard_home>/quarantine first and recorded in index.jsonl, so `guard
//! restore` can put it back. A source file is never deleted.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde_json::{json, Map, Value};

use super::py;
use super::scanner::Scanner;
use crate::av::pystr;
use crate::deps::py_path_str;
use crate::pyjson;

// ---------------------------------------------------------------------------
// string/comment-aware bracket matching. Byte offsets: every byte that matters
// is ASCII, so this cuts at the same characters as Python's str indexing.
// ---------------------------------------------------------------------------

fn skip_string(s: &[u8], mut i: usize, quote: u8) -> usize {
    i += 1;
    while i < s.len() {
        match s[i] {
            b'\\' => i += 2,
            c if c == quote => return i + 1,
            _ => i += 1,
        }
    }
    s.len()
}

fn skip_line_comment(s: &[u8], mut i: usize) -> usize {
    while i < s.len() && s[i] != b'\n' {
        i += 1;
    }
    i
}

fn skip_block_comment(s: &[u8], mut i: usize) -> usize {
    i += 2;
    while i < s.len() {
        if s[i] == b'*' && i + 1 < s.len() && s[i + 1] == b'/' {
            return i + 2;
        }
        i += 1;
    }
    s.len()
}

/// s[i] is '`': the index after the closing backtick, handling ${ ... }.
fn skip_template(s: &[u8], mut i: usize) -> usize {
    let n = s.len();
    i += 1;
    while i < n {
        match s[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'`' => return i + 1,
            b'$' if i + 1 < n && s[i + 1] == b'{' => {
                i += 2;
                let mut depth = 1;
                while i < n && depth > 0 {
                    let c = s[i];
                    if c == b'\\' {
                        i += 2;
                        continue;
                    }
                    if c == b'\'' || c == b'"' {
                        i = skip_string(s, i, c);
                        continue;
                    }
                    if c == b'`' {
                        i = skip_template(s, i);
                        continue;
                    }
                    if c == b'{' {
                        depth += 1;
                    } else if c == b'}' {
                        depth -= 1;
                    }
                    i += 1;
                }
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    n
}

/// Strings, templates and comments to skip at `i`: the index after them.
fn skip_any(s: &[u8], i: usize) -> Option<usize> {
    let c = s[i];
    if c == b'\'' || c == b'"' {
        return Some(skip_string(s, i, c));
    }
    if c == b'`' {
        return Some(skip_template(s, i));
    }
    if c == b'/' && i + 1 < s.len() {
        if s[i + 1] == b'/' {
            return Some(skip_line_comment(s, i));
        }
        if s[i + 1] == b'*' {
            return Some(skip_block_comment(s, i));
        }
    }
    None
}

/// The index of the bracket matching s[i], if balanced.
fn matching_bracket(s: &[u8], mut i: usize) -> Option<usize> {
    let open = s[i];
    let close = match open {
        b'(' => b')',
        b'{' => b'}',
        _ => b']',
    };
    let mut depth = 0i64;
    while i < s.len() {
        if let Some(j) = skip_any(s, i) {
            i = j;
            continue;
        }
        let c = s[i];
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn brackets_balanced(s: &[u8]) -> bool {
    let mut stack = vec![];
    let mut i = 0;
    while i < s.len() {
        if let Some(j) = skip_any(s, i) {
            i = j;
            continue;
        }
        match s[i] {
            c @ (b'(' | b'[' | b'{') => stack.push(c),
            c @ (b')' | b']' | b'}') => {
                let want = match c {
                    b')' => b'(',
                    b']' => b'[',
                    _ => b'{',
                };
                if stack.pop() != Some(want) {
                    return false;
                }
            }
            _ => {}
        }
        i += 1;
    }
    stack.is_empty()
}

// ---------------------------------------------------------------------------
// locate + excise malicious IIFEs
// ---------------------------------------------------------------------------

static IIFE_OPEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&py::translate(
        r"\(\s*(?:async\b\s*)?(?:function\b|\([^()]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)",
    ))
    .unwrap()
});

/// Markers of a malicious IIFE. Stored reversed: plain in the binary, they
/// would match Guard's own signatures.
const STRONG_MARKERS_REV: &[&str] = &[
    "vne.ssecorp(bota",
    "ofnIyxorp(lave",
    "bota(lave",
    "YEK_IPA_HTUA",
    "ppa.lecrev.net-mrifnoc-htua",
];

fn iife_is_malicious(body: &str) -> bool {
    let strong = STRONG_MARKERS_REV
        .iter()
        .map(|m| m.chars().rev().collect::<String>())
        .any(|m| body.contains(&m));
    strong
        || (body.contains("eval(")
            && (body.contains("node-fetch")
                || body.contains("process.env")
                || body.contains("atob(")))
}

/// (start, end) of the top-level malicious IIFEs, non-overlapping.
pub fn find_malicious_iifes(text: &str) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let mut spans: Vec<(usize, usize)> = vec![];
    for m in IIFE_OPEN.find_iter(text) {
        let i = m.start();
        if spans.iter().any(|&(a, e)| a <= i && i < e) {
            continue;
        }
        let Some(j) = matching_bracket(b, i) else {
            continue;
        };
        let mut k = j + 1;
        while k < b.len() && matches!(b[k], b' ' | b'\t' | b'\r' | b'\n') {
            k += 1;
        }
        if k >= b.len() || b[k] != b'(' {
            continue;
        }
        let Some(m2) = matching_bracket(b, k) else {
            continue;
        };
        let mut end = m2 + 1;
        if end < b.len() && b[end] == b';' {
            end += 1;
        }
        if iife_is_malicious(&text[i..end]) {
            spans.push((i, end));
        }
    }
    spans
}

/// The text without its malicious IIFEs (and the blank space they leave),
/// plus the removed blocks.
pub fn strip_malicious_iife(text: &str) -> (String, Vec<String>) {
    let mut spans = find_malicious_iifes(text);
    if spans.is_empty() {
        return (text.to_string(), vec![]);
    }
    spans.sort();
    let mut out = text.to_string();
    let mut removed = vec![];
    for &(i, end) in spans.iter().rev() {
        removed.push(out[i..end].to_string());
        let ls = out[..i].rfind('\n').map_or(0, |p| p + 1);
        let seg_start = if pystr::strip(&out[ls..i]).is_empty() {
            ls
        } else {
            i
        };
        let ob = out.as_bytes();
        let mut seg_end = end;
        while seg_end < ob.len() && (ob[seg_end] == b' ' || ob[seg_end] == b'\t') {
            seg_end += 1;
        }
        if seg_end < ob.len() && ob[seg_end] == b'\n' {
            seg_end += 1;
        }
        out.replace_range(seg_start..seg_end, "");
    }
    static BLANKS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\n{3,}").unwrap());
    (BLANKS.replace_all(&out, "\n\n").into_owned(), removed)
}

// ---------------------------------------------------------------------------
// tolerant JSONC (string-aware)
// ---------------------------------------------------------------------------

fn strip_jsonc(text: &str) -> String {
    let b = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'"' || c == b'\'' {
            let j = skip_string(b, i, c).min(b.len());
            out.extend_from_slice(&b[i..j]);
            i = j;
            continue;
        }
        if c == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            i = skip_line_comment(b, i);
            continue;
        }
        if c == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            i = skip_block_comment(b, i);
            continue;
        }
        out.push(c);
        i += 1;
    }
    // comments end on ASCII, so the bytes are still UTF-8
    let s = String::from_utf8_lossy(&out).into_owned();
    static TRAILING: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r",([\s\x1c-\x1f]*[}\]])").unwrap());
    TRAILING.replace_all(&s, "$1").into_owned()
}

fn load_jsonc(p: &Path) -> Option<Value> {
    let text = py::read_text(p).ok()?;
    serde_json::from_str(&strip_jsonc(&text)).ok()
}

// ---------------------------------------------------------------------------
// the remediator
// ---------------------------------------------------------------------------

const SCRIPT_EXTS: &[&str] = &[".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"];
const BINARY_EXTS: &[&str] = &[
    ".woff2", ".woff", ".ttf", ".otf", ".png", ".jpg", ".jpeg", ".ico", ".gif", ".webp",
];

fn now() -> (u64, u32) {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs(), d.subsec_micros())
}

/// "%Y%m%dT%H%M%SZ" in UTC.
fn compact_ts(secs: u64) -> String {
    let iso = crate::util::iso_utc(secs as i64, 0);
    let digits: String = iso[..19]
        .chars()
        .filter(|c| *c != '-' && *c != ':')
        .collect();
    format!("{digits}Z")
}

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => unreachable!(),
    }
}

pub struct Remediator {
    qdir: PathBuf,
    index: PathBuf,
}

impl Remediator {
    pub fn new(home: &Path) -> Remediator {
        let qdir = home.join("quarantine");
        let _ = fs::create_dir_all(&qdir);
        Remediator {
            index: qdir.join("index.jsonl"),
            qdir,
        }
    }

    fn log(&self, msg: &str) {
        crate::util::emit(msg);
    }

    fn backup(&self, path: &str) -> Result<(PathBuf, String), String> {
        let data = fs::read(path).map_err(|e| pystr::os_error(&e, path))?;
        let sha = py::sha256_hex(&data);
        let safe = py::safe_name(path);
        let safe = safe.trim_matches('_');
        let dest = self
            .qdir
            .join(format!("{}__{safe}.{}.bak", compact_ts(now().0), &sha[..8]));
        fs::write(&dest, &data).map_err(|e| pystr::os_error(&e, &dest.to_string_lossy()))?;
        Ok((dest, sha))
    }

    fn record(
        &self,
        action: &str,
        path: &str,
        backup: Option<&Path>,
        before: Value,
        after: Value,
        detail: &str,
    ) {
        let (secs, micros) = now();
        let rec = json!({
            "ts": crate::util::iso_utc(secs as i64, micros),
            "action": action,
            "path": path,
            "backup": backup.map(|b| b.to_string_lossy().into_owned()),
            "sha_before": before,
            "sha_after": after,
            "detail": detail,
        });
        let line = format!("{}\n", pyjson::dumps(&rec, None, false));
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.index)
        {
            let _ = f.write_all(&py::text_bytes(&line));
        }
    }

    fn name_of(p: &Path) -> String {
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    fn quarantine_file(&self, path: &str, reason: &str) -> Result<Value, String> {
        let (backup, sha) = self.backup(path)?;
        if let Err(e) = fs::remove_file(path) {
            return Ok(
                json!({"action": "error", "path": path, "error": pystr::os_error(&e, path)}),
            );
        }
        self.record(
            "quarantine",
            path,
            Some(&backup),
            json!(sha),
            Value::Null,
            reason,
        );
        self.log(&format!(
            "remediate: quarantined dropper {path} -> {}",
            Self::name_of(&backup)
        ));
        Ok(
            json!({"action": "quarantine", "path": path, "backup": backup.to_string_lossy(), "reason": reason}),
        )
    }

    fn neutralize_js(&self, path: &str) -> Result<Option<Value>, String> {
        let Ok(text) = py::read_text(Path::new(path)) else {
            return Ok(None);
        };
        let (new, removed) = strip_malicious_iife(&text);
        if removed.is_empty() {
            return Ok(None);
        }
        if !brackets_balanced(new.as_bytes()) {
            self.log(&format!(
                "remediate: refusing to edit {path} (removal would unbalance it) — left for manual review"
            ));
            return Ok(Some(json!({"action": "manual", "path": path,
                "note": "malicious block found but safe bounds unclear; manual review"})));
        }
        let (backup, before) = self.backup(path)?;
        py::write_text(Path::new(path), &new).map_err(|e| pystr::os_error(&e, path))?;
        let after = py::sha256_hex(new.as_bytes());
        let n = removed.len();
        self.record(
            "neutralize",
            path,
            Some(&backup),
            json!(before),
            json!(after),
            &format!("removed {n} injected block(s)"),
        );
        self.log(&format!(
            "remediate: excised {n} injected block(s) from {path} (kept the real code)"
        ));
        Ok(Some(
            json!({"action": "neutralize", "path": path, "blocks": n, "backup": backup.to_string_lossy()}),
        ))
    }

    fn write_json(&self, path: &str, data: &Value) -> Result<String, String> {
        let new = format!("{}\n", pyjson::dumps(data, Some(2), false));
        py::write_text(Path::new(path), &new).map_err(|e| pystr::os_error(&e, path))?;
        Ok(py::sha256_hex(new.as_bytes()))
    }

    fn clean_vscode_settings(&self, path: &str) -> Result<Option<Value>, String> {
        let Some(Value::Object(mut data)) = load_jsonc(Path::new(path)) else {
            return Ok(None);
        };
        if !data.contains_key("task.allowAutomaticTasks") {
            return Ok(None);
        }
        let (backup, before) = self.backup(path)?;
        data.shift_remove("task.allowAutomaticTasks");
        let after = self.write_json(path, &Value::Object(data))?;
        self.record(
            "clean-settings",
            path,
            Some(&backup),
            json!(before),
            json!(after),
            "removed task.allowAutomaticTasks",
        );
        self.log(&format!("remediate: removed auto-run flag from {path}"));
        Ok(Some(
            json!({"action": "clean-settings", "path": path, "backup": backup.to_string_lossy()}),
        ))
    }

    fn task_is_malicious(task: &Map<String, Value>) -> bool {
        let mut runon = String::new();
        if let Some(Value::Object(ro)) = task.get("runOptions") {
            runon = ro
                .get("runOn")
                .map(pystr::py_str)
                .unwrap_or_default()
                .to_lowercase();
        }
        let blob = pyjson::dumps(&Value::Object(task.clone()), None, false).to_lowercase();
        let auto = runon == "folderopen" || blob.contains("\"runon\": \"folderopen\"");
        let bad = [
            "public/fonts",
            ".woff2",
            "node ./",
            "atob(",
            "eval(",
            "invoke-expression",
            "iex ",
            "powershell -e",
        ]
        .iter()
        .any(|k| blob.contains(k));
        auto && bad
    }

    fn clean_vscode_tasks(&self, path: &str) -> Result<Option<Value>, String> {
        let Some(Value::Object(mut data)) = load_jsonc(Path::new(path)) else {
            return Ok(None);
        };
        let Some(Value::Array(tasks)) = data.get("tasks") else {
            return Ok(None);
        };
        let mut kept = vec![];
        let mut dropped = 0;
        for t in tasks {
            match t {
                Value::Object(o) if Self::task_is_malicious(o) => dropped += 1,
                _ => kept.push(t.clone()),
            }
        }
        if dropped == 0 {
            return Ok(None);
        }
        let (backup, before) = self.backup(path)?;
        data.insert("tasks".into(), Value::Array(kept));
        let after = self.write_json(path, &Value::Object(data))?;
        self.record(
            "clean-tasks",
            path,
            Some(&backup),
            json!(before),
            json!(after),
            &format!("removed {dropped} auto-run task(s)"),
        );
        self.log(&format!(
            "remediate: removed {dropped} malicious auto-run task(s) from {path}"
        ));
        Ok(Some(
            json!({"action": "clean-tasks", "path": path, "dropped": dropped, "backup": backup.to_string_lossy()}),
        ))
    }

    pub fn remediate_file(&self, path_arg: &str, is_dropper: bool) -> Result<Value, String> {
        let path = py_path_str(path_arg);
        let p = Path::new(&path);
        if !p.exists() {
            return Ok(json!({"action": "gone", "path": path}));
        }
        let parent = pystr::name(&path[..path.len() - pystr::name(&path).len()]).to_lowercase();
        let name = pystr::name(&path).to_lowercase();
        if parent == ".vscode" && name == "settings.json" {
            return Ok(self
                .clean_vscode_settings(&path)?
                .unwrap_or_else(|| json!({"action": "noop", "path": path})));
        }
        if parent == ".vscode" && (name == "tasks.json" || name == "launch.json") {
            return Ok(self
                .clean_vscode_tasks(&path)?
                .unwrap_or_else(|| json!({"action": "noop", "path": path})));
        }
        if is_dropper {
            return self.quarantine_file(&path, "whole-file dropper / masquerade payload");
        }
        if SCRIPT_EXTS.contains(&pystr::suffix(&path).to_lowercase().as_str()) {
            if let Some(r) = self.neutralize_js(&path)? {
                return Ok(r);
            }
        }
        // a real source file we couldn't surgically clean: NEVER delete it
        Ok(json!({"action": "manual", "path": path,
            "note": "malicious markers present but no safe automatic fix; manual review"}))
    }

    /// Detect with the scanner, then remediate every flagged file.
    pub fn clean_repo(&self, repo: &str) -> Result<Value, String> {
        let sig = super::sigs::load(None)?;
        let mut sc = Scanner::new(&sig, true)?;
        let mut summary = obj(json!({"repo": repo, "neutralized": [], "quarantined": [],
            "config_cleaned": [], "manual": [], "noop": []}));
        let mut seen: Vec<String> = vec![];
        let route = |summary: &mut Map<String, Value>, res: Value| {
            let act = res.get("action").and_then(Value::as_str).unwrap_or("");
            let bucket = match act {
                "neutralize" => "neutralized",
                "quarantine" => "quarantined",
                "clean-settings" | "clean-tasks" => "config_cleaned",
                "manual" => "manual",
                _ => "noop",
            };
            let path = res.get("path").cloned().unwrap_or(json!(""));
            if let Some(Value::Array(a)) = summary.get_mut(bucket) {
                a.push(path);
            }
        };
        let abs = |rel: Option<&Value>| -> Option<String> {
            let rel = rel.and_then(Value::as_str).filter(|s| !s.is_empty())?;
            Some(if Path::new(rel).is_absolute() {
                py_path_str(rel)
            } else {
                py::join(repo, rel)
            })
        };

        // 1. .vscode auto-run
        let (_, vf) = sc.vscode.is_safe_to_open(repo);
        for f in vf.iter().filter(|f| f.severity == "critical") {
            if let Some(fp) = abs(Some(&json!(f.path))) {
                if !seen.contains(&fp) {
                    seen.push(fp.clone());
                    route(&mut summary, self.remediate_file(&fp, false)?);
                }
            }
        }

        // 2. tree: masquerade droppers + injections / payloads; 3. av engine:
        // whole-file threats are quarantined, code inside a real source file
        // goes to the excise-or-manual path.
        let res = sc.scan_tree(repo);
        let bucket = |k: &str| {
            res.get(k)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        };
        for x in bucket("magic").iter().filter(|x| crit(x)) {
            if let Some(fp) = abs(x.get("path").or(x.get("where"))) {
                if !seen.contains(&fp) {
                    seen.push(fp.clone());
                    route(&mut summary, self.remediate_file(&fp, true)?);
                }
            }
        }
        for x in bucket("fingerprint").iter().filter(|x| crit(x)) {
            let Some(fp) = abs(x.get("where").or(x.get("path"))) else {
                continue;
            };
            if seen.contains(&fp) {
                continue;
            }
            seen.push(fp.clone());
            let dropper = BINARY_EXTS.contains(&pystr::suffix(&fp).to_lowercase().as_str());
            route(&mut summary, self.remediate_file(&fp, dropper)?);
        }
        for x in bucket("av").iter().filter(|x| crit(x)) {
            let Some(fp) = abs(x.get("path").or(x.get("where"))) else {
                continue;
            };
            if seen.contains(&fp) {
                continue;
            }
            seen.push(fp.clone());
            let whole = x.get("action").and_then(Value::as_str) == Some("quarantine");
            route(&mut summary, self.remediate_file(&fp, whole)?);
        }
        Ok(Value::Object(summary))
    }

    /// Put back the most recent backup of an original path (or a backup name).
    pub fn restore(&self, target: &str) -> Result<Value, String> {
        if !self.index.exists() {
            return Ok(json!({"restored": [], "error": "no quarantine index"}));
        }
        let text = py::read_text(&self.index)
            .map_err(|e| pystr::os_error(&e, &self.index.to_string_lossy()))?;
        let mut recs = vec![];
        for line in py::splitlines(&text) {
            if pystr::strip(line).is_empty() {
                continue;
            }
            let rec: Value =
                serde_json::from_str(line).map_err(|e| format!("{}: {e}", self.index.display()))?;
            recs.push(rec);
        }
        let matches = |r: &Value| {
            r.get("path").and_then(Value::as_str) == Some(target)
                || r.get("backup")
                    .and_then(Value::as_str)
                    .filter(|b| !b.is_empty())
                    .is_some_and(|b| pystr::name(b) == target)
        };
        let Some(r) = recs.iter().rev().find(|r| matches(r)) else {
            return Ok(json!({"restored": [], "error": format!("no record for {target}")}));
        };
        let backup = r.get("backup").and_then(Value::as_str).unwrap_or("");
        if backup.is_empty() || !Path::new(backup).exists() {
            return Ok(json!({"restored": [], "error": "backup file missing"}));
        }
        let dest = py_path_str(r.get("path").and_then(Value::as_str).unwrap_or(""));
        if let Some(parent) = Path::new(&dest)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .map_err(|e| pystr::os_error(&e, &parent.to_string_lossy()))?;
        }
        let data = fs::read(backup).map_err(|e| pystr::os_error(&e, backup))?;
        fs::write(&dest, data).map_err(|e| pystr::os_error(&e, &dest))?;
        let bpath = PathBuf::from(py_path_str(backup));
        let before = r.get("sha_before").cloned().unwrap_or(Value::Null);
        self.record(
            "restore",
            &dest,
            Some(&bpath),
            Value::Null,
            before,
            "restored from backup",
        );
        self.log(&format!(
            "remediate: restored {dest} from {}",
            pystr::name(backup)
        ));
        Ok(json!({"restored": [dest], "from": backup}))
    }
}

fn crit(v: &Value) -> bool {
    v.get("severity").and_then(Value::as_str) == Some("critical")
}

/// remediator.main: `guard clean [<path>]`, `guard restore <path|backup>`.
pub fn main(argv: &[String]) -> Result<u8, String> {
    let (sub, rest) = argv.split_first().ok_or("usage")?;
    let rem = Remediator::new(&crate::util::guard_home());
    if sub == "restore" {
        let Some(target) = rest.first() else {
            eprintln!("usage: guard restore <original-path|backup-name>");
            return Ok(2);
        };
        println!("{}", pyjson::dumps(&rem.restore(target)?, Some(2), false));
        return Ok(0);
    }
    let target = if sub != "clean" {
        sub.as_str()
    } else {
        rest.first().map_or(".", String::as_str)
    };
    let out = if Path::new(target).is_file() {
        rem.remediate_file(target, false)?
    } else {
        rem.clean_repo(target)?
    };
    println!("{}", pyjson::dumps(&out, Some(2), false));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFECTED: &str = "import x from 'y';\n\n(async () => {\n  const u = atob(process.env.AUTH_API_KEY);\n  const r = await fetch(u); eval(proxyInfo);\n})();\n\nexport default { a: \"(\" };\n";

    #[test]
    fn excises_the_iife_only() {
        let (new, removed) = strip_malicious_iife(INFECTED);
        assert_eq!(removed.len(), 1);
        assert_eq!(new, "import x from 'y';\n\nexport default { a: \"(\" };\n");
        assert!(brackets_balanced(new.as_bytes()));
        assert!(find_malicious_iifes("(() => { console.log(1) })();").is_empty());
    }

    #[test]
    fn brackets_skip_strings_and_comments() {
        assert!(brackets_balanced(
            b"f(\"(\", '[', `${a({})}`) // )\n/* ] */"
        ));
        assert!(!brackets_balanced(b"f(]"));
        assert_eq!(
            strip_jsonc("{\"a\": \"//x\", // c\n \"b\": [1,],}"),
            "{\"a\": \"//x\", \n \"b\": [1]}"
        );
        assert_eq!(compact_ts(0), "19700101T000000Z");
    }
}
