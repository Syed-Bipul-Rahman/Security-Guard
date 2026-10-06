//! Is this folder safe to open in VS Code? (port of vscode_guard.py): the
//! .vscode settings that allow automatic tasks, and tasks that run on
//! folderOpen.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use super::py;
use super::sigs::{req_str, str_list, Res};
use crate::av::pystr;

pub struct Finding {
    pub path: String,
    pub severity: &'static str,
    pub reason: String,
    pub detail: String,
}

impl Finding {
    fn new(path: &str, severity: &'static str, reason: String, detail: &str) -> Self {
        Finding {
            path: path.into(),
            severity,
            reason,
            detail: detail.into(),
        }
    }

    pub fn to_json(&self) -> Map<String, Value> {
        match json!({"path": self.path, "severity": self.severity, "reason": self.reason, "detail": self.detail})
        {
            Value::Object(m) => m,
            _ => unreachable!(),
        }
    }
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {}: {}",
            self.severity.to_uppercase(),
            self.path,
            self.reason
        )?;
        if !self.detail.is_empty() {
            write!(f, " ({})", self.detail)?;
        }
        Ok(())
    }
}

/// vscode_guard.strip_jsonc: comments and trailing commas out, best effort.
pub fn strip_jsonc(text: &str) -> String {
    static BLOCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());
    static LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(^|[^:])//[^\n]*").unwrap());
    static TRAILING: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r",([\s\x1c-\x1f]*[}\]])").unwrap());
    let t = BLOCK.replace_all(text, "");
    let t = LINE.replace_all(&t, "$1");
    TRAILING.replace_all(&t, "$1").into_owned()
}

pub struct Guard {
    settings_file: String,
    tasks_file: String,
    danger_keys: Vec<String>,
    danger_runon: Vec<String>,
    danger_cmds: Vec<String>,
    danger_args: Vec<String>,
}

fn lower(v: Vec<String>) -> Vec<String> {
    v.into_iter().map(|s| s.to_lowercase()).collect()
}

impl Guard {
    pub fn new(sig: &Value) -> Res<Guard> {
        let Some(c) = sig.get("vscode_guard") else {
            return Ok(Guard {
                settings_file: ".vscode/settings.json".into(),
                tasks_file: ".vscode/tasks.json".into(),
                danger_keys: vec!["task.allowAutomaticTasks".into()],
                danger_runon: vec!["folderopen".into()],
                danger_cmds: ["node", "npm", "npx", "sh", "bash", "powershell", "cmd"]
                    .map(String::from)
                    .to_vec(),
                danger_args: [
                    "public/fonts/",
                    ".woff2",
                    ".woff",
                    "curl",
                    "wget",
                    "iwr",
                    "invoke-",
                    "base64",
                    "eval",
                ]
                .map(String::from)
                .to_vec(),
            });
        };
        let field = |k: &str| str_list(Some(c.get(k).unwrap_or(&Value::Null)));
        Ok(Guard {
            settings_file: req_str(c, "settings_file")?,
            tasks_file: req_str(c, "tasks_file")?,
            danger_keys: field("settings_danger_keys")?,
            danger_runon: lower(field("tasks_danger_runon")?),
            danger_cmds: lower(field("tasks_danger_commands")?),
            danger_args: lower(field("tasks_danger_arg_substrings")?),
        })
    }

    /// (parsed JSON, raw text); the raw text lets callers fail closed.
    fn load_jsonc(path: &Path) -> (Option<Value>, String) {
        let raw = match py::read_text(path) {
            Ok(t) => t,
            Err(e) => {
                return (
                    None,
                    format!(
                        "unreadable: {}",
                        pystr::os_error(&e, &path.to_string_lossy())
                    ),
                )
            }
        };
        (serde_json::from_str(&strip_jsonc(&raw)).ok(), raw)
    }

    fn check_settings(&self, repo: &str) -> Vec<Finding> {
        let p = py::join(repo, &self.settings_file);
        let p = Path::new(&p);
        if !p.exists() {
            return vec![];
        }
        let (data, raw) = Self::load_jsonc(p);
        let rel = &self.settings_file;
        let mut out = vec![];
        match data {
            None => {
                for key in &self.danger_keys {
                    if raw.contains(key.as_str()) && raw.contains("true") {
                        out.push(Finding::new(
                            rel,
                            "critical",
                            format!(
                                "auto-task setting present in unparseable settings.json ({key})"
                            ),
                            "raw substring match; treat as enabled",
                        ));
                    }
                }
            }
            Some(Value::Object(data)) => {
                for key in &self.danger_keys {
                    if data.get(key) == Some(&Value::Bool(true)) {
                        out.push(Finding::new(
                            rel,
                            "critical",
                            format!("{key} = true enables silent task auto-run on folder open"),
                            "",
                        ));
                    }
                }
            }
            Some(_) => {}
        }
        out
    }

    fn check_tasks(&self, repo: &str) -> Vec<Finding> {
        let p = py::join(repo, &self.tasks_file);
        let p = Path::new(&p);
        if !p.exists() {
            return vec![];
        }
        let (data, raw) = Self::load_jsonc(p);
        let rel = &self.tasks_file;
        let mut out = vec![];
        let Some(data) = data else {
            let low = raw.to_lowercase();
            if self.danger_runon.iter().any(|r| low.contains(r.as_str()))
                && self.danger_cmds.iter().any(|c| low.contains(c.as_str()))
            {
                out.push(Finding::new(
                    rel,
                    "critical",
                    "unparseable tasks.json with folderOpen + command — treat as auto-run dropper"
                        .into(),
                    "raw substring match",
                ));
            }
            return out;
        };
        for (cmd, args, run_on) in task_commands(&data) {
            let cmd_l = cmd.to_lowercase();
            let args_l = args.join(" ").to_lowercase();
            let blob = format!("{cmd_l} {args_l}");
            let auto = self.danger_runon.contains(&run_on.to_lowercase());
            let cmd_words = pystr::split_ws(&cmd_l);
            let blob_words = pystr::split_ws(&blob);
            let is_cmd = self.danger_cmds.iter().any(|c| {
                *c == cmd_l || cmd_words.contains(&c.as_str()) || blob_words.contains(&c.as_str())
            });
            let bad_args: Vec<&str> = self
                .danger_args
                .iter()
                .filter(|a| blob.contains(a.as_str()))
                .map(String::as_str)
                .collect();
            if auto && (is_cmd || !bad_args.is_empty()) {
                let what = format!("{cmd} {}", args.join(" "));
                let ind = if bad_args.is_empty() {
                    cmd_l.clone()
                } else {
                    bad_args.join(", ")
                };
                out.push(Finding::new(
                    rel,
                    "critical",
                    format!("auto-run task ({run_on}) executes '{what}'"),
                    &format!("dropper indicators: {ind}"),
                ));
            } else if auto {
                out.push(Finding::new(
                    rel,
                    "high",
                    format!("task auto-runs on {run_on} — review command '{cmd}'"),
                    "",
                ));
            } else if !bad_args.is_empty() {
                out.push(Finding::new(
                    rel,
                    "high",
                    "task references dropper-like path/command".into(),
                    &format!("indicators: {}", bad_args.join(", ")),
                ));
            }
        }
        out
    }

    pub fn scan_repo(&self, repo: &str) -> Vec<Finding> {
        let mut f = self.check_settings(repo);
        f.extend(self.check_tasks(repo));
        f
    }

    pub fn is_safe_to_open(&self, repo: &str) -> (bool, Vec<Finding>) {
        let f = self.scan_repo(repo);
        (!f.iter().any(|x| x.severity == "critical"), f)
    }
}

/// Iterating a JSON value the way Python iterates the parsed object: a list's
/// items, a dict's keys, a string's characters.
fn py_iter(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Object(o) => o.keys().map(|k| Value::String(k.clone())).collect(),
        Value::String(s) => s.chars().map(|c| Value::String(c.to_string())).collect(),
        _ => vec![],
    }
}

fn get_or<'a>(o: &'a Map<String, Value>, k: &str, default: &'a Value) -> &'a Value {
    o.get(k).unwrap_or(default)
}

/// (str(command), [str(arg)], runOn) for each task in a tasks.json.
fn task_commands(data: &Value) -> Vec<(String, Vec<String>, String)> {
    let Value::Object(d) = data else {
        return vec![];
    };
    let empty = Value::String(String::new());
    let tasks = d.get("tasks").filter(|t| crate::pyjson::truthy(Some(t)));
    let mut out = vec![];
    for task in tasks.map(py_iter).unwrap_or_default() {
        let Value::Object(task) = task else { continue };
        let cmd = pystr::py_str(get_or(&task, "command", &empty));
        let args: Vec<String> = task
            .get("args")
            .filter(|a| crate::pyjson::truthy(Some(a)))
            .map(py_iter)
            .unwrap_or_default()
            .iter()
            .map(pystr::py_str)
            .collect();
        let mut run_on = Value::String(String::new());
        if let Some(Value::Object(rr)) = task.get("runOptions") {
            run_on = get_or(rr, "runOn", &empty).clone();
        }
        if !crate::pyjson::truthy(Some(&run_on)) {
            run_on = get_or(&task, "runOn", &empty).clone();
        }
        out.push((cmd, args, pystr::py_str(&run_on)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonc() {
        assert_eq!(
            strip_jsonc("{\"a\": 1, // c\n/* x\n */\"u\": \"http://x\",}"),
            "{\"a\": 1, \n\"u\": \"http://x\"}"
        );
    }
}
