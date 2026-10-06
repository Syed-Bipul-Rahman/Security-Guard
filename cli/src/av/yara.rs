//! Real YARA rules via yara-x in guard_core (port of guard_av/yara_rules.py).
//!
//! Each *.yar / *.yara file is its own namespace (the file stem). A hit is
//! SUSPICIOUS unless the rule's metadata says verdict = "malicious"; its rule
//! id is "yara:<namespace>.<rule>", which the allowlist can disable.

use std::time::Duration;

use guard_core::yara::YaraRules;
use serde_json::{Map, Value};

use super::model::{Detection, Verdict};
use super::pystr::{self, py_str};
use super::rules::{evidence, MAX_MATCHES_PER_STRING};

pub const SUFFIXES: [&str; 2] = [".yar", ".yara"];
const SCAN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
pub struct YaraRuleSet {
    sources: Vec<(String, String, String)>, // (namespace, origin, source)
    compiled: Option<YaraRules>,
}

impl YaraRuleSet {
    pub fn load(&mut self, origin: &str, bytes: &[u8]) {
        let name = pystr::name(origin);
        let suffix = pystr::suffix(origin);
        let stem = &name[..name.len() - suffix.len()];
        self.sources.push((
            stem.to_string(),
            origin.to_string(),
            String::from_utf8_lossy(bytes).into_owned(),
        ));
        self.compiled = None;
    }

    /// Compile now, so a bad rule file fails at load time with yara-x's message.
    pub fn compile(&mut self) -> Result<(), String> {
        if self.compiled.is_none() && !self.sources.is_empty() {
            self.compiled = Some(YaraRules::compile(&self.sources)?);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.compiled.as_ref().map_or(0, |c| c.len())
    }

    pub fn warnings(&self) -> Vec<String> {
        self.compiled
            .as_ref()
            .map(|c| c.warnings().to_vec())
            .unwrap_or_default()
    }

    pub fn scan(&self, data: &[u8]) -> Vec<Detection> {
        let Some(c) = &self.compiled else {
            return Vec::new();
        };
        let Ok(hits) = c.scan(data, SCAN_TIMEOUT, MAX_MATCHES_PER_STRING) else {
            return Vec::new(); // timed out: abandoned, like the Python engine
        };
        hits.into_iter()
            .map(|(namespace, rule, tags, meta_json, first)| {
                let meta: Map<String, Value> = serde_json::from_str(&meta_json).unwrap_or_default();
                let verdict = meta
                    .get("verdict")
                    .map(|v| Verdict::parse(&py_str(v)).unwrap_or(Verdict::Suspicious))
                    .unwrap_or(Verdict::Suspicious)
                    .max(Verdict::Suspicious);
                let description = meta.get("description").map(py_str).unwrap_or_default();
                Detection {
                    engine: "yara",
                    name: rule.clone(),
                    verdict,
                    rule_id: format!("yara:{namespace}.{rule}"),
                    description: if description.is_empty() {
                        tags.join(" ")
                    } else {
                        description
                    },
                    evidence: first
                        .map(|(p, o)| evidence(data, &p, o))
                        .unwrap_or_default(),
                    whole_file: meta.get("whole_file") == Some(&Value::Bool(true)),
                    score: 0,
                }
            })
            .collect()
    }
}
