//! The JSON rule format (port of the loading half of guard_av/rules.py).
//!
//! Rule files are validated here with the same checks and messages as
//! rules.py; matching runs in guard_core's rules module, the same code the
//! Python engine uses when its Rust core is present.

use std::collections::BTreeSet;

use guard_core::rules as core_rules;
use serde_json::{Map, Value};

use super::filetype as ft;
use super::model::{Detection, Verdict};
use super::pystr::{self, py_str};
use crate::pyrepr::{repr, str_repr};

pub const MAX_MATCHES_PER_STRING: usize = 64;

type Res<T> = Result<T, String>;

fn is_hex(c: char) -> bool {
    c.is_ascii_hexdigit()
}

/// Mirrors compile_hex()'s validation (the core module does the translation).
fn check_hex(spec: &str) -> Res<()> {
    let s: Vec<char> = pystr::split_ws(spec).concat().chars().collect();
    let sub = |a: usize, b: usize| -> String { s[a.min(s.len())..b.min(s.len())].iter().collect() };
    let r = str_repr(spec);
    let (mut i, mut depth, mut tokens) = (0usize, 0i32, 0usize);
    while i < s.len() {
        let c = s[i];
        tokens += 1;
        if c == '(' {
            depth += 1;
            i += 1;
        } else if c == '|' {
            if depth == 0 {
                return Err(format!("'|' outside a group in hex string {r}"));
            }
            i += 1;
        } else if c == ')' {
            if depth == 0 {
                return Err(format!("unbalanced ')' in hex string {r}"));
            }
            depth -= 1;
            i += 1;
        } else if c == '[' {
            let Some(j) = s[i..].iter().position(|&x| x == ']').map(|p| p + i) else {
                return Err(format!("unterminated jump in hex string {r}"));
            };
            let body = sub(i + 1, j);
            let jump = str_repr(&sub(i, j + 1));
            let (lo, hi) = match body.split_once('-') {
                Some((a, b)) => (a.to_string(), b.to_string()),
                None => (body.clone(), body.clone()),
            };
            let digits = |t: &str| !t.is_empty() && t.chars().all(|c| c.is_ascii_digit());
            if !digits(&lo) || !digits(&hi) {
                return Err(format!("bad jump {jump} in hex string {r}"));
            }
            let (lo, hi): (u128, u128) = (lo.parse().unwrap_or(0), hi.parse().unwrap_or(0));
            if hi < lo {
                return Err(format!("inverted jump {jump} in hex string {r}"));
            }
            i = j + 1;
        } else if (c == '?' && s.get(i + 1) == Some(&'?'))
            || (is_hex(c) && s.get(i + 1).is_some_and(|&n| is_hex(n)))
        {
            i += 2;
        } else {
            return Err(format!(
                "invalid token at {} in hex string {r}",
                str_repr(&sub(i, i + 4))
            ));
        }
    }
    if depth != 0 {
        return Err(format!("unbalanced '(' in hex string {r}"));
    }
    if tokens == 0 {
        return Err("empty hex string".into());
    }
    Ok(())
}

fn check_string(name: &str, spec: &Value) -> Res<()> {
    let Some(spec) = spec.as_object() else {
        return Err(format!("string {name} must be an object"));
    };
    let truthy = |k: &str, default: bool| match spec.get(k) {
        Some(v) => crate::pyjson::truthy(Some(v)),
        None => default,
    };
    if let Some(h) = spec.get("hex") {
        check_hex(&py_str(h))
    } else if let Some(t) = spec.get("text") {
        if py_str(t).is_empty() {
            return Err(format!("string {name} is empty"));
        }
        if !truthy("ascii", true) && !truthy("wide", false) {
            return Err(format!("string {name} disables both ascii and wide"));
        }
        Ok(())
    } else if spec.contains_key("regex") {
        Ok(()) // compiled (and any error reported) by the core module
    } else {
        Err(format!("string {name} needs one of text / hex / regex"))
    }
}

/// _expand: the string names a name list refers to.
fn expand(names: &Value, defined: &[String]) -> Res<Vec<String>> {
    let items: Vec<Value> = match names {
        Value::String(s) if s == "them" => return Ok(defined.to_vec()),
        Value::String(_) => vec![names.clone()],
        Value::Array(a) => a.clone(),
        Value::Object(o) => o.keys().map(|k| Value::String(k.clone())).collect(),
        other => return Err(format!("bad condition: {}", repr(other))),
    };
    let mut out = Vec::new();
    for n in &items {
        match n {
            Value::String(s) if s.ends_with('*') => {
                let p = &s[..s.len() - 1];
                let hit: Vec<String> = defined
                    .iter()
                    .filter(|d| d.starts_with(p))
                    .cloned()
                    .collect();
                if hit.is_empty() {
                    return Err(format!("wildcard {s} matches no string"));
                }
                out.extend(hit);
            }
            Value::String(s) if defined.contains(s) => out.push(s.clone()),
            other => {
                return Err(format!(
                    "condition references undefined string {}",
                    repr(other)
                ))
            }
        }
    }
    Ok(out)
}

/// isinstance(v, int) (bool counts, as in Python).
fn py_int(v: Option<&Value>) -> Option<i128> {
    match v? {
        Value::Bool(b) => Some(i128::from(*b)),
        Value::Number(n) if n.is_i64() || n.is_u64() => n.to_string().parse().ok(),
        _ => None,
    }
}

fn defined_has(v: &Value, defined: &[String]) -> bool {
    v.as_str().is_some_and(|s| defined.iter().any(|d| d == s))
}

fn validate_condition(cond: &Value, defined: &[String]) -> Res<()> {
    if cond.is_string() {
        expand(&Value::Array(vec![cond.clone()]), defined)?;
        return Ok(());
    }
    let c = match cond.as_object() {
        Some(c) if !c.is_empty() => c,
        _ => return Err(format!("bad condition: {}", repr(cond))),
    };
    let them = Value::String("them".into());
    if let Some(v) = c.get("all") {
        expand(v, defined)?;
    } else if let Some(v) = c.get("any") {
        expand(v, defined)?;
    } else if c.contains_key("at_least") {
        match py_int(c.get("at_least")) {
            Some(n) if n >= 1 => {}
            _ => return Err("at_least must be a positive integer".into()),
        }
        expand(c.get("of").unwrap_or(&them), defined)?;
    } else if c.contains_key("and") || c.contains_key("or") {
        let parts = c.get("and").or_else(|| c.get("or"));
        match parts {
            Some(Value::Array(a)) if !a.is_empty() => {
                for p in a {
                    validate_condition(p, defined)?;
                }
            }
            _ => return Err("and/or need a non-empty list".into()),
        }
    } else if let Some(n) = c.get("not") {
        validate_condition(n, defined)?;
    } else if let Some(at) = c.get("at") {
        if !defined_has(at, defined) {
            return Err(format!("at references undefined string {}", repr(at)));
        }
        if py_int(c.get("offset")).is_none() {
            return Err("at needs an integer offset".into());
        }
    } else if let Some(n) = c.get("count") {
        if !defined_has(n, defined) {
            return Err(format!("count references undefined string {}", repr(n)));
        }
        if py_int(c.get("min")).is_none() {
            return Err("count needs an integer min".into());
        }
    } else if c.contains_key("filesize_max") || c.contains_key("filesize_min") {
        let v = c.get("filesize_max").or_else(|| c.get("filesize_min"));
        if py_int(v).is_none() {
            return Err("filesize bound must be an integer".into());
        }
    } else {
        return Err(format!("unknown condition operator in {}", repr(cond)));
    }
    Ok(())
}

/// list(x) of a JSON value.
fn py_list(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Object(o) => o.keys().map(|k| Value::String(k.clone())).collect(),
        Value::String(s) => s.chars().map(|c| Value::String(c.into())).collect(),
        _ => Vec::new(),
    }
}

/// int(x) of a JSON value.
fn py_to_int(v: &Value) -> Res<i128> {
    match v {
        Value::Bool(b) => Ok(i128::from(*b)),
        Value::Number(n) => match n.as_f64() {
            Some(_) if n.is_i64() || n.is_u64() => Ok(n.to_string().parse().unwrap_or(0)),
            Some(f) => Ok(f.trunc() as i128),
            None => Ok(0),
        },
        Value::String(s) => pystr::strip(s)
            .replace('_', "")
            .parse()
            .map_err(|_| format!("invalid literal for int() with base 10: {}", str_repr(s))),
        other => Err(format!(
            "int() argument must be a string, a bytes-like object or a real number, not '{}'",
            match other {
                Value::Null => "NoneType",
                Value::Array(_) => "list",
                _ => "dict",
            }
        )),
    }
}

pub struct Rule {
    pub id: String,
    pub name: String,
    pub verdict: Verdict,
    pub description: String,
    filetypes: Vec<Value>,
    exclude_extensions: BTreeSet<String>,
    max_filesize: i128,
    pub whole_file: bool,
    spec: Value,
}

impl Rule {
    pub fn from_value(d: &Value) -> Res<Rule> {
        let Some(m) = d.as_object() else {
            return Err("rule must be an object".into());
        };
        for key in ["id", "name", "condition"] {
            if !m.contains_key(key) {
                let id = m.get("id").map(py_str).unwrap_or_else(|| "?".into());
                return Err(format!("rule {id} missing '{key}'"));
            }
        }
        let id = py_str(&m["id"]);
        let raw = m
            .get("verdict")
            .cloned()
            .unwrap_or(Value::String("malicious".into()));
        let verdict = Verdict::parse(&py_str(&raw))
            .ok_or_else(|| format!("rule {id}: unknown verdict: {}", repr(&raw)))?;
        if verdict == Verdict::Clean {
            return Err(format!("rule {id}: verdict cannot be clean"));
        }
        let empty = Map::new();
        let strings = match m.get("strings") {
            Some(v) if crate::pyjson::truthy(Some(v)) => v
                .as_object()
                .ok_or_else(|| format!("rule {id}: strings must be an object"))?,
            _ => &empty,
        };
        for (n, s) in strings {
            check_string(n, s)?;
        }
        let names: Vec<String> = strings.keys().cloned().collect();
        validate_condition(&m["condition"], &names)?;
        // The pattern compiler itself: reports what the Rust regex engine rejects.
        if let Err(e) = core_rules::RuleSet::from_json(&Value::Array(vec![d.clone()]).to_string()) {
            let prefix = format!("rule {id}: ");
            return Err(e.strip_prefix(&prefix).unwrap_or(&e).to_string());
        }
        let filetypes = match m.get("filetypes") {
            Some(v) if crate::pyjson::truthy(Some(v)) => py_list(v),
            _ => vec![Value::String("any".into())],
        };
        let exclude_extensions = m
            .get("exclude_extensions")
            .map(py_list)
            .unwrap_or_default()
            .iter()
            .map(|e| py_str(e).to_lowercase())
            .collect();
        Ok(Rule {
            name: py_str(&m["name"]),
            verdict,
            description: m.get("description").map(py_str).unwrap_or_default(),
            filetypes,
            exclude_extensions,
            max_filesize: match m.get("max_filesize") {
                Some(v) => py_to_int(v)?,
                None => 0,
            },
            whole_file: crate::pyjson::truthy(m.get("whole_file")),
            spec: d.clone(),
            id,
        })
    }

    fn type_matches(&self, tag: &str) -> bool {
        self.filetypes.iter().any(|w| match w.as_str() {
            Some("any") => true,
            Some(w) if w == tag => true,
            Some("executable") => ft::is_executable(tag),
            Some("archive") => ft::is_archive(tag),
            Some("script") => ft::is_script(tag),
            Some("textual") => ft::is_script(tag) || tag == "text" || tag == "script",
            _ => false,
        })
    }

    pub fn applies(&self, name: &str, tag: &str, size: u64) -> bool {
        if self.max_filesize != 0 && i128::from(size) > self.max_filesize {
            return false;
        }
        if !self.exclude_extensions.is_empty()
            && self
                .exclude_extensions
                .contains(&pystr::suffix(name).to_lowercase())
        {
            return false;
        }
        self.type_matches(tag)
    }
}

#[derive(Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    compiled: Option<core_rules::RuleSet>,
}

impl RuleSet {
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn add(&mut self, rule: Rule) -> Res<()> {
        if self.rules.iter().any(|r| r.id == rule.id) {
            return Err(format!("duplicate rule id {}", rule.id));
        }
        self.rules.push(rule);
        self.compiled = None;
        Ok(())
    }

    /// Load a rules*.json file -> how many rule entries it held.
    pub fn load_text(&mut self, text: &str) -> Res<usize> {
        let data: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let items = match &data {
            Value::Object(o) => o.get("rules").cloned().unwrap_or(Value::Array(vec![])),
            other => other.clone(),
        };
        let items = match items {
            Value::Array(a) => a,
            Value::Object(o) => o.keys().map(|k| Value::String(k.clone())).collect(),
            Value::String(s) => s.chars().map(|c| Value::String(c.into())).collect(),
            other => return Err(format!("'{}' object is not iterable", py_type(&other))),
        };
        for d in &items {
            self.add(Rule::from_value(d)?)?;
        }
        Ok(items.len())
    }

    pub fn compile(&mut self) -> Res<()> {
        if self.compiled.is_none() {
            let specs = Value::Array(self.rules.iter().map(|r| r.spec.clone()).collect());
            self.compiled = Some(core_rules::RuleSet::from_json(&specs.to_string())?);
        }
        Ok(())
    }

    pub fn scan(&self, data: &[u8], name: &str, tag: &str, size: u64) -> Vec<Detection> {
        let applicable: Vec<usize> = (0..self.rules.len())
            .filter(|&i| self.rules[i].applies(name, tag, size))
            .collect();
        let Some(compiled) = self.compiled.as_ref().filter(|_| !applicable.is_empty()) else {
            return Vec::new();
        };
        let size = i64::try_from(size).unwrap_or(i64::MAX);
        compiled
            .scan(data, &applicable, size, MAX_MATCHES_PER_STRING)
            .into_iter()
            .map(|(i, evidence)| {
                let r = &self.rules[i];
                Detection {
                    engine: "rule",
                    name: r.name.clone(),
                    verdict: r.verdict,
                    rule_id: r.id.clone(),
                    description: r.description.clone(),
                    evidence,
                    whole_file: r.whole_file,
                    score: 0,
                }
            })
            .collect()
    }
}

fn py_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// _evidence for one (string, offset): "$name@offset: printable bytes".
pub fn evidence(data: &[u8], name: &str, off: usize) -> String {
    let end = (off + 48).min(data.len());
    let chunk = &data[off.min(end)..end];
    let printable: String = chunk
        .iter()
        .map(|&b| {
            if (32..127).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    format!("{name}@{off}: {printable}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn err(v: Value) -> String {
        Rule::from_value(&v).err().unwrap()
    }

    #[test]
    fn validation_messages_match_rules_py() {
        assert_eq!(
            err(json!({"id": "x", "name": "n"})),
            "rule x missing 'condition'"
        );
        assert_eq!(
            err(json!({"id": "x", "name": "n", "condition": "$a", "verdict": "bad"})),
            "rule x: unknown verdict: 'bad'"
        );
        assert_eq!(
            err(json!({"id": "x", "name": "n", "condition": "$a"})),
            "condition references undefined string '$a'"
        );
        assert_eq!(
            err(
                json!({"id": "x", "name": "n", "condition": "$a", "strings": {"$a": {"hex": "4D (5A"}}})
            ),
            "unbalanced '(' in hex string '4D (5A'"
        );
        assert_eq!(
            err(
                json!({"id": "x", "name": "n", "condition": "$a", "strings": {"$a": {"hex": "4D [3-1]"}}})
            ),
            "inverted jump '[3-1]' in hex string '4D [3-1]'"
        );
        assert_eq!(
            err(
                json!({"id": "x", "name": "n", "condition": {"at_least": 0}, "strings": {"$a": {"text": "a"}}})
            ),
            "at_least must be a positive integer"
        );
        assert_eq!(
            err(
                json!({"id": "x", "name": "n", "condition": {"zz": 1}, "strings": {"$a": {"text": "a"}}})
            ),
            "unknown condition operator in {'zz': 1}"
        );
    }
}
