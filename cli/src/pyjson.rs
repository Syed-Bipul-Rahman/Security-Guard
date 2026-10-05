//! `json.dumps` as Python writes it (ASCII-escaped, Python float repr, its
//! separators and indentation), so files and output the Python build wrote keep
//! the exact same bytes after the switch to this binary.

use serde_json::Value;

/// Python's repr() of a float.
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        };
    }
    // `{:e}` gives the shortest round-trip digits, like Python's repr.
    let e = format!("{f:e}");
    let (mant, exp) = e.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    let (neg, mant) = mant.strip_prefix('-').map_or((false, mant), |m| (true, m));
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if (-4..16).contains(&exp) {
        if exp < 0 {
            out.push_str("0.");
            out.push_str(&"0".repeat((-exp - 1) as usize));
            out.push_str(&digits);
        } else {
            let point = exp as usize + 1;
            if digits.len() <= point {
                out.push_str(&digits);
                out.push_str(&"0".repeat(point - digits.len()));
                out.push_str(".0");
            } else {
                out.push_str(&digits[..point]);
                out.push('.');
                out.push_str(&digits[point..]);
            }
        }
    } else {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push_str(&format!(
            "e{}{:02}",
            if exp < 0 { '-' } else { '+' },
            exp.abs()
        ));
    }
    out
}

pub fn number(n: &serde_json::Number) -> String {
    if n.is_f64() {
        float_repr(n.as_f64().unwrap())
    } else {
        n.to_string()
    }
}

/// A JSON string literal with ensure_ascii=True.
pub fn string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
        }
    }
    out.push('"');
}

fn write(v: &Value, indent: Option<usize>, sort_keys: bool, level: usize, out: &mut String) {
    let (item_sep, open_pad, close_pad) = match indent {
        Some(n) => (
            format!(",\n{}", " ".repeat(n * (level + 1))),
            format!("\n{}", " ".repeat(n * (level + 1))),
            format!("\n{}", " ".repeat(n * level)),
        ),
        None => (", ".into(), String::new(), String::new()),
    };
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number(n)),
        Value::String(s) => string(s, out),
        Value::Array(a) if a.is_empty() => out.push_str("[]"),
        Value::Array(a) => {
            out.push('[');
            out.push_str(&open_pad);
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(&item_sep);
                }
                write(x, indent, sort_keys, level + 1, out);
            }
            out.push_str(&close_pad);
            out.push(']');
        }
        Value::Object(o) if o.is_empty() => out.push_str("{}"),
        Value::Object(o) => {
            let mut items: Vec<(&String, &Value)> = o.iter().collect();
            if sort_keys {
                items.sort_by(|a, b| a.0.cmp(b.0));
            }
            out.push('{');
            out.push_str(&open_pad);
            for (i, (k, x)) in items.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(&item_sep);
                }
                string(k, out);
                out.push_str(": ");
                write(x, indent, sort_keys, level + 1, out);
            }
            out.push_str(&close_pad);
            out.push('}');
        }
    }
}

/// `json.dumps(v, indent=indent, sort_keys=sort_keys)`
pub fn dumps(v: &Value, indent: Option<usize>, sort_keys: bool) -> String {
    let mut out = String::new();
    write(v, indent, sort_keys, 0, &mut out);
    out
}

/// Python truthiness of a JSON value.
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Bool(true)) => true,
    }
}

/// `a or b`: the first truthy value, else the last one.
pub fn or<'a>(a: Option<&'a Value>, b: Option<&'a Value>) -> Option<&'a Value> {
    if truthy(a) {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn floats_like_python() {
        for (f, s) in [
            (9.8, "9.8"),
            (1.0, "1.0"),
            (0.0, "0.0"),
            (-2.5, "-2.5"),
            (1e16, "1e+16"),
            (1.5e16, "1.5e+16"),
            (123456789012345.6, "123456789012345.6"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.25e-7, "1.25e-07"),
            (1e100, "1e+100"),
        ] {
            assert_eq!(float_repr(f), s, "{f}");
        }
    }

    #[test]
    fn dumps_like_python() {
        let v = json!({"b": [1, 2.0, {}], "a": "é😀\u{7f}\"\n", "c": [], "d": null, "e": true});
        assert_eq!(
            dumps(&v, None, false),
            "{\"b\": [1, 2.0, {}], \"a\": \"\\u00e9\\ud83d\\ude00\\u007f\\\"\\n\", \"c\": [], \"d\": null, \"e\": true}"
        );
        assert_eq!(
            dumps(&json!({"z": 1, "a": [1, {"k": []}]}), Some(2), true),
            "{\n  \"a\": [\n    1,\n    {\n      \"k\": []\n    }\n  ],\n  \"z\": 1\n}"
        );
    }

    #[test]
    fn truthiness() {
        assert!(!truthy(Some(&json!(""))));
        assert!(!truthy(Some(&json!(0))));
        assert!(!truthy(Some(&json!([]))));
        assert!(truthy(Some(&json!("x"))));
        assert_eq!(or(Some(&json!("")), Some(&json!("p"))), Some(&json!("p")));
    }
}
