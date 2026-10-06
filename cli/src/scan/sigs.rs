//! signatures.json: the incident signature set the scanner and remediator use.
//! The bundled copy is gzipped by build.rs; plain IOC strings in the binary
//! would make Guard flag itself.

use std::io::Read;
use std::path::Path;

use serde_json::Value;

use crate::av::pystr;

pub type Res<T> = Result<T, String>;

static BUNDLED_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/signatures.json.gz"));

pub fn gunzip(gz: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_end(&mut out)
        .expect("bundled data decompresses");
    out
}

/// load_signatures(path): the bundled set, or a signatures.json given on the
/// command line.
pub fn load(path: Option<&str>) -> Res<Value> {
    let (text, name) = match path {
        None => (gunzip(BUNDLED_GZ), "<bundled>/signatures.json".to_string()),
        Some(p) => {
            let shown = crate::deps::py_path_str(p);
            let b = std::fs::read(Path::new(&shown)).map_err(|e| {
                format!(
                    "{}: {}",
                    pystr::os_error_class(&e),
                    pystr::os_error(&e, &shown)
                )
            })?;
            (b, shown)
        }
    };
    let text = String::from_utf8(text).map_err(|e| format!("{name}: {e}"))?;
    let text = super::py::universal(text);
    serde_json::from_str(&text).map_err(|e| format!("{name}: {e}"))
}

/// The list at `v`, or nothing.
pub fn list(v: Option<&Value>) -> impl Iterator<Item = &Value> {
    v.and_then(Value::as_array).into_iter().flatten()
}

pub fn opt_str(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

pub fn req_str(v: &Value, key: &str) -> Res<String> {
    opt_str(v, key).ok_or_else(|| format!("signature entry without a string {key:?}: {v}"))
}

pub fn str_list(v: Option<&Value>) -> Res<Vec<String>> {
    match v {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("expected a list of strings, got {x}"))
            })
            .collect(),
        Some(other) => Err(format!("expected a list of strings, got {other}")),
    }
}
