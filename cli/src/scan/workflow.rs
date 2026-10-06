//! Workflow baselines (port of workflow_baseline.py): a workflow added or
//! changed since the approved baseline needs review, and is critical when its
//! content matches the incident signatures.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::fingerprint::Matcher;
use super::py;
use crate::av::pystr;

const WORKFLOW_DIR: &str = ".github/workflows";

pub struct Finding {
    pub path: String,
    pub state: &'static str,
    pub severity: &'static str,
    pub detail: String,
}

impl Finding {
    pub fn to_json(&self) -> Value {
        json!({"path": self.path, "state": self.state, "severity": self.severity, "detail": self.detail})
    }
}

/// Stable filesystem-safe key for a repo path.
pub fn repo_key(repo: &str) -> String {
    let p = py::resolve(repo);
    let h = &py::sha256_hex(p.as_bytes())[..12];
    format!("{}-{h}", py::safe_name(pystr::name(&p)))
}

/// Path.rglob("*") under `root`, not following directory links.
fn rglob(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(root) else { return };
    for e in rd.flatten() {
        let p = e.path();
        out.push(p.clone());
        let real_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if real_dir {
            rglob(&p, out);
        }
    }
}

/// The parts Python compares when sorting paths.
fn sort_key(p: &Path) -> Vec<String> {
    let s = p.to_string_lossy();
    let s = if cfg!(windows) {
        s.to_lowercase()
    } else {
        s.into_owned()
    };
    s.split(std::path::MAIN_SEPARATOR)
        .map(str::to_string)
        .collect()
}

pub struct Baseline<'a> {
    matcher: &'a Matcher,
    dir: PathBuf,
}

impl<'a> Baseline<'a> {
    pub fn new(matcher: &'a Matcher) -> Self {
        Baseline {
            matcher,
            dir: crate::util::guard_home().join("baselines"),
        }
    }

    /// {rel posix path: sha256} for the repo's workflow files, in path order.
    fn current(&self, repo: &str) -> Vec<(String, String)> {
        let root = PathBuf::from(py::join(repo, WORKFLOW_DIR));
        let mut out = vec![];
        if !root.is_dir() {
            return out;
        }
        let mut all = vec![];
        rglob(&root, &mut all);
        all.sort_by_key(|p| sort_key(p));
        let base = PathBuf::from(repo);
        for f in all {
            let suf = pystr::suffix(&f.to_string_lossy()).to_lowercase();
            if !f.is_file() || !(suf == ".yml" || suf == ".yaml") {
                continue;
            }
            let rel = f.strip_prefix(&base).unwrap_or(&f);
            let rel: Vec<String> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            let digest = fs::read(&f).map(|b| py::sha256_hex(&b)).unwrap_or_default();
            out.push((rel.join("/"), digest));
        }
        out
    }

    fn load(&self, repo: &str) -> Option<Map<String, Value>> {
        let p = self.dir.join(format!("{}.json", repo_key(repo)));
        let text = fs::read(&p).ok()?;
        match serde_json::from_slice(&text) {
            Ok(Value::Object(m)) => Some(m),
            _ => None,
        }
    }

    fn assess(&self, repo: &str, rel: &str) -> (&'static str, String) {
        let content = match py::read_text(Path::new(&py::join(repo, rel))) {
            Ok(c) => c,
            Err(_) => return ("high", "unreadable".into()),
        };
        let mut ids: Vec<String> = self
            .matcher
            .scan_content(rel, &content)
            .into_iter()
            .filter(|h| h.severity == "critical")
            .map(|h| h.sig_id)
            .collect();
        if ids.is_empty() {
            return ("high", String::new());
        }
        ids.sort();
        ids.dedup();
        (
            "critical",
            format!("content matches signatures: {}", ids.join(", ")),
        )
    }

    pub fn diff(&self, repo: &str) -> Vec<Finding> {
        let repo_abs = py::resolve(repo);
        let current = self.current(&repo_abs);
        let mut out = vec![];
        let Some(baseline) = self.load(&repo_abs) else {
            for (rel, _) in &current {
                let (sev, detail) = self.assess(&repo_abs, rel);
                let detail = if detail.is_empty() {
                    "no baseline recorded yet — needs review".into()
                } else {
                    detail
                };
                out.push(Finding {
                    path: rel.clone(),
                    state: "added",
                    severity: sev,
                    detail,
                });
            }
            return out;
        };
        let empty = Map::new();
        let base_wf = match baseline.get("workflows") {
            Some(Value::Object(m)) => m,
            _ => &empty,
        };
        for (rel, digest) in &current {
            match base_wf.get(rel) {
                None => {
                    let (sev, d) = self.assess(&repo_abs, rel);
                    let detail = if d.is_empty() {
                        "not in approved baseline".into()
                    } else {
                        d
                    };
                    out.push(Finding {
                        path: rel.clone(),
                        state: "added",
                        severity: sev,
                        detail,
                    });
                }
                Some(v) if v.as_str() != Some(digest.as_str()) => {
                    let (sev, d) = self.assess(&repo_abs, rel);
                    let detail = if d.is_empty() {
                        "content differs from approved baseline".into()
                    } else {
                        d
                    };
                    out.push(Finding {
                        path: rel.clone(),
                        state: "modified",
                        severity: sev,
                        detail,
                    });
                }
                Some(_) => out.push(Finding {
                    path: rel.clone(),
                    state: "unchanged",
                    severity: "ok",
                    detail: String::new(),
                }),
            }
        }
        for rel in base_wf.keys() {
            if !current.iter().any(|(r, _)| r == rel) {
                out.push(Finding {
                    path: rel.clone(),
                    state: "removed",
                    severity: "info",
                    detail: "was in baseline, now absent".into(),
                });
            }
        }
        out
    }
}
