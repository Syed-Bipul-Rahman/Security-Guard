//! Verdicts, detections and per-file results (port of guard_av/model.py).

use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Verdict {
    #[default]
    Clean,
    Suspicious,
    Malicious,
}

impl Verdict {
    /// Verdict.parse: str(value).strip().upper() names a member.
    pub fn parse(text: &str) -> Option<Verdict> {
        match crate::av::pystr::strip(text).to_uppercase().as_str() {
            "CLEAN" => Some(Verdict::Clean),
            "SUSPICIOUS" => Some(Verdict::Suspicious),
            "MALICIOUS" => Some(Verdict::Malicious),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Suspicious => "suspicious",
            Verdict::Malicious => "malicious",
        }
    }
}

/// One reason a file was flagged.
#[derive(Clone, Debug, Default)]
pub struct Detection {
    pub engine: &'static str,
    pub name: String,
    pub verdict: Verdict,
    pub description: String,
    pub rule_id: String,
    pub evidence: String,
    pub score: u32,
    pub whole_file: bool,
}

impl Detection {
    pub fn to_json(&self) -> Value {
        json!({
            "engine": self.engine,
            "name": self.name,
            "verdict": self.verdict.label(),
            "description": self.description,
            "rule_id": self.rule_id,
            "evidence": self.evidence,
            "score": self.score,
            "whole_file": self.whole_file,
        })
    }
}

/// Result for one scanned object (a file, or an archive member).
#[derive(Clone, Debug)]
pub struct ScanResult {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
    pub filetype: String,
    pub verdict: Verdict,
    pub detections: Vec<Detection>,
    pub children: Vec<ScanResult>,
    pub allowlisted: String,
    pub error: String,
    pub heuristic_score: u32,
}

impl ScanResult {
    pub fn new(path: String) -> Self {
        ScanResult {
            path,
            size: 0,
            sha256: String::new(),
            md5: String::new(),
            sha1: String::new(),
            filetype: "unknown".into(),
            verdict: Verdict::Clean,
            detections: Vec::new(),
            children: Vec::new(),
            allowlisted: String::new(),
            error: String::new(),
            heuristic_score: 0,
        }
    }

    /// Own detections, then each child's, depth first.
    pub fn all_detections(&self) -> Vec<&Detection> {
        let mut out: Vec<&Detection> = self.detections.iter().collect();
        for c in &self.children {
            out.extend(c.all_detections());
        }
        out
    }

    /// Name of the most severe detection (own or nested), "" when clean.
    pub fn threat_name(&self) -> String {
        let mut best: Option<&Detection> = None;
        for d in self.all_detections() {
            if best.is_none_or(|b| d.verdict > b.verdict) {
                best = Some(d);
            }
        }
        best.map(|d| d.name.clone()).unwrap_or_default()
    }

    pub fn finalize(&mut self) {
        let own = self.detections.iter().map(|d| d.verdict);
        let kids = self.children.iter().map(|c| c.verdict);
        self.verdict = own.chain(kids).max().unwrap_or(Verdict::Clean);
    }

    pub fn to_json(&self) -> Value {
        json!({
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "md5": self.md5,
            "sha1": self.sha1,
            "filetype": self.filetype,
            "verdict": self.verdict.label(),
            "threat": self.threat_name(),
            "heuristic_score": self.heuristic_score,
            "allowlisted": self.allowlisted,
            "error": self.error,
            "detections": self.detections.iter().map(Detection::to_json).collect::<Vec<_>>(),
            "children": self.children.iter().map(ScanResult::to_json).collect::<Vec<_>>(),
        })
    }
}
