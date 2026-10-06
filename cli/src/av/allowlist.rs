//! False-positive suppression (port of guard_av/allowlist.py).

use std::collections::BTreeSet;

use regex::Regex;
use serde_json::Value;

use super::model::Detection;

#[derive(Default)]
pub struct Allowlist {
    sha256: BTreeSet<String>,
    paths: Vec<(String, Option<Regex>)>,
    rules: BTreeSet<String>,
}

/// fnmatch.translate: `*`, `?`, `[seq]`, `[!seq]`; matches the whole string.
fn translate(pat: &str) -> String {
    let c: Vec<char> = pat.chars().collect();
    let mut out = String::from("(?s)^");
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        i += 1;
        match ch {
            '*' => {
                while i < c.len() && c[i] == '*' {
                    i += 1;
                }
                out.push_str(".*");
            }
            '?' => out.push('.'),
            '[' => {
                let mut j = i;
                if j < c.len() && c[j] == '!' {
                    j += 1;
                }
                if j < c.len() && c[j] == ']' {
                    j += 1;
                }
                while j < c.len() && c[j] != ']' {
                    j += 1;
                }
                if j >= c.len() {
                    out.push_str("\\[");
                } else {
                    let body: String = c[i..j].iter().collect();
                    i = j + 1;
                    if body.is_empty() {
                        out.push_str("(?!)");
                    } else if body == "!" {
                        out.push('.');
                    } else {
                        let (neg, body) = match body.strip_prefix('!') {
                            Some(b) => (true, b.to_string()),
                            None => (false, body),
                        };
                        let mut cls = String::new();
                        for ch in body.chars() {
                            if matches!(ch, '\\' | '[' | ']' | '&' | '~' | '|' | '^') {
                                cls.push('\\');
                            }
                            cls.push(ch);
                        }
                        out.push('[');
                        if neg {
                            out.push('^');
                        }
                        out.push_str(&cls);
                        out.push(']');
                    }
                }
            }
            c => out.push_str(&regex::escape(&c.to_string())),
        }
    }
    out.push('$');
    out
}

/// os.path.normcase: Windows compares paths case-insensitively.
fn normcase(s: &str) -> String {
    if cfg!(windows) {
        s.to_lowercase()
    } else {
        s.to_string()
    }
}

fn strings(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().map(super::pystr::py_str).collect(),
        Some(Value::Object(o)) => o.keys().cloned().collect(),
        Some(Value::String(s)) => s.chars().map(String::from).collect(),
        _ => Vec::new(),
    }
}

impl Allowlist {
    pub fn load(text: &str) -> Result<Allowlist, String> {
        let data: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let mut a = Allowlist::default();
        for h in strings(data.get("sha256")) {
            a.add_hash(&h);
        }
        for p in strings(data.get("paths")) {
            a.add_path(&p.replace('\\', "/"));
        }
        a.rules.extend(strings(data.get("rules")));
        Ok(a)
    }

    fn add_path(&mut self, p: &str) {
        if !self.paths.iter().any(|(q, _)| q == p) {
            let re = Regex::new(&translate(&normcase(p))).ok();
            self.paths.push((p.to_string(), re));
        }
    }

    pub fn merge(&mut self, other: Allowlist) {
        self.sha256.extend(other.sha256);
        for (p, _) in other.paths {
            self.add_path(&p);
        }
        self.rules.extend(other.rules);
    }

    pub fn add_hash(&mut self, sha256: &str) {
        self.sha256.insert(sha256.to_lowercase());
    }

    /// Why this whole file is trusted ("" if it isn't).
    pub fn file_reason(&self, path: &str, sha256: &str) -> String {
        if !sha256.is_empty() && self.sha256.contains(&sha256.to_lowercase()) {
            let short: String = sha256.chars().take(16).collect();
            return format!("known-good hash {short}");
        }
        let norm = normcase(&path.replace('\\', "/"));
        for (pat, re) in &self.paths {
            if re.as_ref().is_some_and(|r| r.is_match(&norm)) {
                return format!("path matches {pat}");
            }
        }
        String::new()
    }

    pub fn suppresses(&self, d: &Detection) -> bool {
        (!d.rule_id.is_empty() && self.rules.contains(&d.rule_id)) || self.rules.contains(&d.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnmatch_like_python() {
        let m = |p: &str, s: &str| Regex::new(&translate(p)).unwrap().is_match(s);
        assert!(m("*/vendor/*", "/a/vendor/b/c"));
        assert!(m("*.min.js", "x/y.min.js"));
        assert!(!m("*.min.js", "x/y.min.jsx"));
        assert!(m("a?c", "abc"));
        assert!(m("[!x]b", "ab"));
        assert!(!m("[!x]b", "xb"));
        assert!(m("[a-c]1", "b1"));
        assert!(m("a[b", "a[b"));
        assert!(m("a.b", "a.b") && !m("a.b", "axb"));
    }

    /// test_av_core.py TestAllowlist.test_hash_path_and_rule.
    #[test]
    fn hash_path_and_rule() {
        let a = Allowlist::load(
            r#"{"sha256": ["ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"],
                "paths": ["*/vendor/*"], "rules": ["rule.x", "Threat.Y"]}"#,
        )
        .unwrap();
        assert!(a
            .file_reason("x", &"ab".repeat(32))
            .starts_with("known-good hash"));
        assert_eq!(
            a.file_reason("C:\\proj\\vendor\\lib.dll", ""),
            "path matches */vendor/*"
        );
        assert_eq!(a.file_reason("/proj/src/a.js", &"00".repeat(32)), "");
        let det = |name: &str, rule_id: &str| Detection {
            name: name.into(),
            rule_id: rule_id.into(),
            ..Default::default()
        };
        assert!(a.suppresses(&det("Other", "rule.x")));
        assert!(a.suppresses(&det("Threat.Y", "")));
        assert!(!a.suppresses(&det("Z", "rule.z")));
    }
}
