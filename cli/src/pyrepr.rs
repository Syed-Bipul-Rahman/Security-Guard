//! Python `repr()` of JSON values, so commands that printed a Python dict keep
//! printing exactly the same text (scripts that parse `guard update` keep working).

use serde_json::Value;

pub fn str_repr(s: &str) -> String {
    // Python picks single quotes unless the text has a ' and no ".
    let q = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

pub fn repr(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => crate::pyjson::number(n),
        Value::String(s) => str_repr(s),
        Value::Array(a) => format!("[{}]", a.iter().map(repr).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter()
                .map(|(k, v)| format!("{}: {}", str_repr(k), repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_python_repr() {
        let v = json!({"status": "updated", "ok": true, "no": false, "v": null, "n": [1, 2.5]});
        assert_eq!(
            repr(&v),
            "{'status': 'updated', 'ok': True, 'no': False, 'v': None, 'n': [1, 2.5]}"
        );
        assert_eq!(str_repr("it's"), "\"it's\"");
        assert_eq!(str_repr("a'\"b"), "'a\\'\"b'");
        assert_eq!(str_repr("x\\y\n"), "'x\\\\y\\n'");
    }
}
