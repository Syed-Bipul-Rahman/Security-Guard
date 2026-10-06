//! JS/text droppers disguised with a binary extension (port of magic_bytes.py):
//! a "font" or "image" that does not start with its format's magic bytes and
//! reads as source code.

use std::fs::File;
use std::io::Read;

use serde_json::{json, Map, Value};

use super::sigs::{str_list, Res};
use crate::av::pystr;

const READ_BYTES: usize = 16;
const SNIFF_BYTES: usize = 4096;

const DEFAULT_MAGIC: &[(&str, &[&str])] = &[
    (".woff2", &["774f4632"]),
    (".woff", &["774f4646"]),
    (".ttf", &["00010000", "74727565"]),
    (".otf", &["4f54544f"]),
    (".eot", &[]),
    (".png", &["89504e470d0a1a0a"]),
    (".jpg", &["ffd8ff"]),
    (".jpeg", &["ffd8ff"]),
    (".gif", &["474946383761", "474946383961"]),
    (".ico", &["00000100"]),
];

const DEFAULT_TEXT_INDICATORS: &[&str] = &[
    "require(",
    "global[",
    "process.env",
    "eval(",
    "function",
    "=>",
    "var _$_",
    "module.exports",
    "import ",
];

pub struct Finding {
    pub path: String,
    pub severity: &'static str,
    pub reason: String,
    pub detail: String,
}

impl Finding {
    pub fn to_json(&self) -> Map<String, Value> {
        match json!({"path": self.path, "severity": self.severity, "reason": self.reason, "detail": self.detail})
        {
            Value::Object(m) => m,
            _ => unreachable!(),
        }
    }
}

pub struct Checker {
    magic: Vec<(String, Vec<String>)>,
    indicators: Vec<String>,
}

impl Checker {
    pub fn new(sig: &Value) -> Res<Checker> {
        let mb = sig.get("magic_bytes");
        let by_ext = mb
            .and_then(|m| m.get("by_ext"))
            .and_then(Value::as_object)
            .filter(|m| !m.is_empty());
        let magic = match by_ext {
            Some(m) => m
                .iter()
                .map(|(k, v)| {
                    let hexes = str_list(Some(v))?
                        .iter()
                        .map(|h| h.to_lowercase())
                        .collect();
                    Ok((k.to_lowercase(), hexes))
                })
                .collect::<Res<Vec<_>>>()?,
            None => DEFAULT_MAGIC
                .iter()
                .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
                .collect(),
        };
        let ind = str_list(mb.and_then(|m| m.get("text_body_indicators")))?;
        let indicators = if ind.is_empty() {
            DEFAULT_TEXT_INDICATORS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            ind
        };
        Ok(Checker { magic, indicators })
    }

    fn expected(&self, ext: &str) -> Option<&Vec<String>> {
        // later keys win, like a dict built from the JSON object
        self.magic
            .iter()
            .rev()
            .find(|(k, _)| k == ext)
            .map(|(_, v)| v)
    }

    /// (is source text, the first four indicators found)
    fn looks_like_text(&self, data: &[u8]) -> (bool, String) {
        let head = &data[..data.len().min(SNIFF_BYTES)];
        let Ok(text) = std::str::from_utf8(head) else {
            return (false, String::new());
        };
        let hits: Vec<&str> = self
            .indicators
            .iter()
            .filter(|i| text.contains(i.as_str()))
            .map(String::as_str)
            .collect();
        (
            !hits.is_empty(),
            hits.iter().take(4).copied().collect::<Vec<_>>().join(", "),
        )
    }

    pub fn check_bytes(&self, path: &str, data: &[u8]) -> Vec<Finding> {
        let ext = pystr::suffix(path).to_lowercase();
        let Some(expected) = self.expected(&ext) else {
            return vec![];
        };
        let header: String = data[..data.len().min(READ_BYTES)]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let magic_ok = expected.iter().any(|m| header.starts_with(m.as_str()));
        let (is_text, indicators) = self.looks_like_text(data);
        let h16 = &header[..header.len().min(16)];
        let finding = |severity, reason: String, detail: String| Finding {
            path: path.to_string(),
            severity,
            reason,
            detail,
        };
        if !expected.is_empty() && !magic_ok && is_text {
            vec![finding(
                "critical",
                format!(
                    "binary-disguised dropper: {ext} file contains source text, not {ext} data"
                ),
                format!(
                    "header={h16} expected~{} indicators=[{indicators}]",
                    expected[0]
                ),
            )]
        } else if expected.is_empty() && is_text {
            vec![finding(
                "high",
                format!("suspicious: {ext} asset contains source text"),
                format!("indicators=[{indicators}]"),
            )]
        } else if !expected.is_empty() && !magic_ok && !is_text {
            vec![finding(
                "low",
                format!(
                    "{ext} file has unexpected header (not disguised text, but not valid {ext})"
                ),
                format!("header={h16}"),
            )]
        } else {
            vec![]
        }
    }

    pub fn check_file(&self, path: &str) -> Vec<Finding> {
        let read = || -> std::io::Result<Vec<u8>> {
            let mut data = Vec::new();
            File::open(path)?
                .take(READ_BYTES.max(SNIFF_BYTES) as u64)
                .read_to_end(&mut data)?;
            Ok(data)
        };
        match read() {
            Ok(data) => self.check_bytes(path, &data),
            Err(e) => vec![Finding {
                path: path.to_string(),
                severity: "info",
                reason: "unreadable".into(),
                detail: pystr::os_error(&e, path),
            }],
        }
    }
}
