//! YARA-style rule matching — port of the matching half of `guard_av/rules.py`.
//!
//! Python still parses and validates rule files (and decides which rules apply
//! to a file); this module compiles the same rule dicts to `regex::bytes`
//! patterns and evaluates conditions with the same lazy, short-circuit order,
//! so the strings it looks at — and therefore the evidence it reports — are
//! identical to the Python backend.

use regex::bytes::Regex;
use serde_json::Value;

#[derive(Debug)]
enum Cond {
    All(Vec<usize>),
    Any(Vec<usize>),
    AtLeast(u64, Vec<usize>),
    And(Vec<Cond>),
    Or(Vec<Cond>),
    Not(Box<Cond>),
    At(usize, i64),
    Count(usize, u64),
    FilesizeMax(i64),
    FilesizeMin(i64),
}

pub struct Rule {
    names: Vec<String>,
    patterns: Vec<Regex>,
    cond: Cond,
}

pub struct RuleSet {
    rules: Vec<Rule>,
}

type Res<T> = Result<T, String>;

// ------------------------------------------------------------------ strings
fn hex_digit(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

/// YARA hex string -> regex source (bytes, `\xHH` escaped). Mirrors compile_hex().
fn compile_hex(spec: &str) -> Res<String> {
    let s: Vec<u8> = spec.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut out = String::new();
    let (mut i, mut depth) = (0usize, 0i32);
    while i < s.len() {
        let c = s[i];
        match c {
            b'(' => {
                out.push_str("(?:");
                depth += 1;
                i += 1;
            }
            b'|' if depth > 0 => {
                out.push('|');
                i += 1;
            }
            b')' if depth > 0 => {
                out.push(')');
                depth -= 1;
                i += 1;
            }
            b'[' => {
                let j = s[i..].iter().position(|&x| x == b']').ok_or("unterminated jump")? + i;
                let body = std::str::from_utf8(&s[i + 1..j]).map_err(|e| e.to_string())?;
                let (lo, hi) = match body.split_once('-') {
                    Some((a, b)) => (a, b),
                    None => (body, body),
                };
                let lo: u64 = lo.parse().map_err(|_| format!("bad jump [{body}]"))?;
                let hi: u64 = hi.parse().map_err(|_| format!("bad jump [{body}]"))?;
                out.push_str(&format!(".{{{lo},{hi}}}"));
                i = j + 1;
            }
            b'?' if s.get(i + 1) == Some(&b'?') => {
                out.push('.');
                i += 2;
            }
            _ if hex_digit(c) && s.get(i + 1).is_some_and(|&d| hex_digit(d)) => {
                out.push_str(&format!("\\x{}", std::str::from_utf8(&s[i..i + 2]).unwrap()));
                i += 2;
            }
            _ => return Err(format!("invalid token in hex string {spec:?}")),
        }
    }
    if depth != 0 || out.is_empty() {
        return Err(format!("invalid hex string {spec:?}"));
    }
    Ok(out)
}

fn escape_bytes(b: &[u8]) -> String {
    b.iter().map(|c| format!("\\x{c:02x}")).collect()
}

fn flag(spec: &Value, key: &str) -> bool {
    spec.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// Mirrors compile_string(): same flag defaults (DOTALL on for text/hex, off
/// for regex unless asked), ASCII-only classes like Python bytes patterns.
fn compile_string(name: &str, spec: &Value) -> Res<Regex> {
    let mut flags = String::from("(?-u)");
    if flag(spec, "nocase") {
        flags.push_str("(?i)");
    }
    let src = if let Some(h) = spec.get("hex") {
        flags.push_str("(?s)");
        compile_hex(h.as_str().ok_or("hex must be a string")?)?
    } else if let Some(t) = spec.get("text") {
        flags.push_str("(?s)");
        let text = t.as_str().ok_or("text must be a string")?;
        let mut forms = Vec::new();
        if spec.get("ascii").and_then(Value::as_bool).unwrap_or(true) {
            forms.push(escape_bytes(text.as_bytes()));
        }
        if flag(spec, "wide") {
            let wide: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            forms.push(escape_bytes(&wide));
        }
        if forms.is_empty() || text.is_empty() {
            return Err(format!("string {name} is empty"));
        }
        format!("(?:{})", forms.join("|"))
    } else if let Some(r) = spec.get("regex") {
        if flag(spec, "multiline") {
            flags.push_str("(?m)");
        }
        if flag(spec, "dotall") {
            flags.push_str("(?s)");
        }
        format!("(?:{})", r.as_str().ok_or("regex must be a string")?)
    } else {
        return Err(format!("string {name} needs one of text / hex / regex"));
    };
    Regex::new(&format!("{flags}{src}")).map_err(|e| format!("string {name}: {e}"))
}

// --------------------------------------------------------------- conditions
fn expand(names_v: &Value, defined: &[String]) -> Res<Vec<usize>> {
    let list: Vec<&str> = match names_v {
        Value::String(s) if s == "them" => return Ok((0..defined.len()).collect()),
        Value::String(s) => vec![s.as_str()],
        Value::Array(a) => a.iter().map(|v| v.as_str().ok_or_else(|| "names must be strings".to_string())).collect::<Res<_>>()?,
        _ => return Err("bad name list".into()),
    };
    let mut out = Vec::new();
    for n in list {
        if let Some(prefix) = n.strip_suffix('*') {
            out.extend(defined.iter().enumerate().filter(|(_, d)| d.starts_with(prefix)).map(|(i, _)| i));
        } else {
            out.push(defined.iter().position(|d| d == n).ok_or(format!("undefined string {n}"))?);
        }
    }
    Ok(out)
}

fn index_of(v: &Value, defined: &[String]) -> Res<usize> {
    let n = v.as_str().ok_or("expected a string name")?;
    defined.iter().position(|d| d == n).ok_or(format!("undefined string {n}"))
}

fn int(v: Option<&Value>) -> Res<i64> {
    v.and_then(Value::as_i64).ok_or_else(|| "expected an integer".into())
}

/// Same key precedence as rules.evaluate(): all, any, at_least, and, or, not,
/// at, count, filesize_max, filesize_min.
fn parse_cond(v: &Value, defined: &[String]) -> Res<Cond> {
    if v.is_string() {
        return Ok(Cond::All(expand(v, defined)?));
    }
    let o = v.as_object().ok_or("bad condition")?;
    let them = Value::String("them".into());
    let list = |k: &str| -> Res<Vec<Cond>> {
        o[k].as_array().ok_or("and/or need a list")?.iter().map(|c| parse_cond(c, defined)).collect()
    };
    Ok(if let Some(x) = o.get("all") {
        Cond::All(expand(x, defined)?)
    } else if let Some(x) = o.get("any") {
        Cond::Any(expand(x, defined)?)
    } else if let Some(n) = o.get("at_least") {
        Cond::AtLeast(n.as_u64().ok_or("at_least must be a positive integer")?,
                      expand(o.get("of").unwrap_or(&them), defined)?)
    } else if o.contains_key("and") {
        Cond::And(list("and")?)
    } else if o.contains_key("or") {
        Cond::Or(list("or")?)
    } else if let Some(x) = o.get("not") {
        Cond::Not(Box::new(parse_cond(x, defined)?))
    } else if let Some(x) = o.get("at") {
        Cond::At(index_of(x, defined)?, int(o.get("offset"))?)
    } else if let Some(x) = o.get("count") {
        Cond::Count(index_of(x, defined)?, int(o.get("min"))?.max(0) as u64)
    } else if o.contains_key("filesize_max") {
        Cond::FilesizeMax(int(o.get("filesize_max"))?)
    } else if o.contains_key("filesize_min") {
        Cond::FilesizeMin(int(o.get("filesize_min"))?)
    } else {
        return Err("unknown condition operator".into());
    })
}

// ------------------------------------------------------------------ matching
/// Offsets per string, computed on first use; `order` remembers the order in
/// which strings were looked at (Python dict insertion order) for evidence.
struct Lazy<'a> {
    rule: &'a Rule,
    data: &'a [u8],
    max: usize,
    cache: Vec<Option<Vec<usize>>>,
    order: Vec<usize>,
}

impl Lazy<'_> {
    fn get(&mut self, i: usize) -> &[usize] {
        if self.cache[i].is_none() {
            let offs: Vec<usize> = self.rule.patterns[i].find_iter(self.data).take(self.max).map(|m| m.start()).collect();
            self.cache[i] = Some(offs);
            self.order.push(i);
        }
        self.cache[i].as_deref().unwrap()
    }

    fn hit(&mut self, i: usize) -> bool {
        !self.get(i).is_empty()
    }
}

fn eval(c: &Cond, m: &mut Lazy, size: i64) -> bool {
    match c {
        Cond::All(v) => v.iter().all(|&i| m.hit(i)),
        Cond::Any(v) => v.iter().any(|&i| m.hit(i)),
        Cond::AtLeast(need, pool) => {
            let need = *need as usize;
            let mut hits = 0usize;
            for (k, &i) in pool.iter().enumerate() {
                if m.hit(i) {
                    hits += 1;
                    if hits >= need {
                        return true;
                    }
                }
                if hits + (pool.len() - k - 1) < need {
                    return false;
                }
            }
            false
        }
        Cond::And(v) => v.iter().all(|x| eval(x, m, size)),
        Cond::Or(v) => v.iter().any(|x| eval(x, m, size)),
        Cond::Not(x) => !eval(x, m, size),
        Cond::At(i, off) => *off >= 0 && m.get(*i).contains(&(*off as usize)),
        Cond::Count(i, min) => m.get(*i).len() as u64 >= *min,
        Cond::FilesizeMax(n) => size <= *n,
        Cond::FilesizeMin(n) => size >= *n,
    }
}

/// Same text as rules._evidence(): first looked-at string with a match.
fn evidence(m: &Lazy) -> String {
    for &i in &m.order {
        let offs = m.cache[i].as_deref().unwrap();
        if let Some(&o) = offs.first() {
            let chunk = &m.data[o..(o + 48).min(m.data.len())];
            let printable: String = chunk.iter().map(|&b| if (32..127).contains(&b) { b as char } else { '.' }).collect();
            return format!("{}@{}: {}", m.rule.names[i], o, printable);
        }
    }
    String::new()
}

impl Rule {
    fn from_value(v: &Value) -> Res<Rule> {
        let id = v.get("id").and_then(Value::as_str).unwrap_or("?");
        let ctx = |e: String| format!("rule {id}: {e}");
        let (mut names, mut patterns) = (Vec::new(), Vec::new());
        if let Some(strings) = v.get("strings").and_then(Value::as_object) {
            for (n, spec) in strings {
                patterns.push(compile_string(n, spec).map_err(ctx)?);
                names.push(n.clone());
            }
        }
        let cond = parse_cond(v.get("condition").ok_or("missing condition")?, &names).map_err(ctx)?;
        Ok(Rule { names, patterns, cond })
    }
}

impl RuleSet {
    /// `rules_json`: a JSON array of rule dicts, in RuleSet order.
    pub fn from_json(rules_json: &str) -> Res<RuleSet> {
        let v: Value = serde_json::from_str(rules_json).map_err(|e| e.to_string())?;
        let arr = v.as_array().ok_or("expected a JSON array of rules")?;
        Ok(RuleSet { rules: arr.iter().map(Rule::from_value).collect::<Res<_>>()? })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Match the rules at `indices` (already filtered by Python's applies())
    /// and return (index, evidence) for each hit, in order.
    pub fn scan(&self, data: &[u8], indices: &[usize], filesize: i64, max_matches: usize) -> Vec<(usize, String)> {
        let mut out = Vec::new();
        for &ri in indices {
            let Some(rule) = self.rules.get(ri) else { continue };
            let mut m = Lazy { rule, data, max: max_matches, cache: vec![None; rule.patterns.len()], order: Vec::new() };
            if eval(&rule.cond, &mut m, filesize) {
                out.push((ri, evidence(&m)));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rs(json: &str) -> RuleSet {
        RuleSet::from_json(json).unwrap()
    }

    #[test]
    fn hex_wildcards_jumps_alternation() {
        let r = rs(r#"[{"id":"h","strings":{"$a":{"hex":"4D ?? [1-2] (41|42) 5A"}},"condition":"$a"}]"#);
        assert_eq!(r.scan(b"..M\x00xxBZ", &[0], 9, 64).len(), 1);
        assert!(r.scan(b"M\x00xxxCZ", &[0], 7, 64).is_empty());
    }

    #[test]
    fn evidence_and_lazy_order() {
        let r = rs(r#"[{"id":"e","strings":{"$miss":{"text":"zzz"},"$hit":{"text":"abc","nocase":true}},
                       "condition":{"any":"them"}}]"#);
        assert_eq!(r.scan(b"..ABC", &[0], 5, 64), vec![(0, "$hit@2: ABC".to_string())]);
    }

    #[test]
    fn conditions() {
        let r = rs(r#"[{"id":"c","strings":{"$a":{"text":"a"},"$b":{"regex":"b+"}},
            "condition":{"and":[{"count":"$a","min":2},{"at":"$b","offset":0},{"not":{"filesize_max":2}},
                                {"at_least":1,"of":["$*"]},{"or":[{"filesize_min":1}]}]}}]"#);
        assert_eq!(r.scan(b"bbaa", &[0], 4, 64).len(), 1);
        assert!(r.scan(b"xbaa", &[0], 4, 64).is_empty());
    }

    #[test]
    fn wide_strings() {
        let r = rs(r#"[{"id":"w","strings":{"$w":{"text":"hi","wide":true,"ascii":false}},"condition":"$w"}]"#);
        assert_eq!(r.scan(b"h\x00i\x00", &[0], 4, 64).len(), 1);
        assert!(r.scan(b"hi", &[0], 2, 64).is_empty());
    }

    #[test]
    fn errors() {
        assert!(RuleSet::from_json("{}").is_err());
        assert!(RuleSet::from_json(r#"[{"id":"x","strings":{"$a":{"regex":"(?<=a)b"}},"condition":"$a"}]"#).is_err());
        assert!(RuleSet::from_json(r#"[{"id":"x","strings":{"$a":{"hex":"4G"}},"condition":"$a"}]"#).is_err());
        assert!(RuleSet::from_json(r#"[{"id":"x","condition":"$nope"}]"#).is_err());
    }
}
