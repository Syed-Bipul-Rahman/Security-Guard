//! YARA rules, compiled and matched by yara-x (VirusTotal's Rust rewrite of
//! YARA). Python reads the rule files and maps hits onto Guard detections;
//! this module only compiles sources and reports what matched.

use std::time::Duration;

/// One matching rule: (namespace, identifier, tags, metadata as a JSON
/// object, first matched pattern as (identifier, offset) when the rule has one).
pub type Hit = (String, String, Vec<String>, String, Option<(String, usize)>);

pub struct YaraRules {
    rules: yara_x::Rules,
    warnings: Vec<String>,
}

impl YaraRules {
    /// Compile `(namespace, origin, source)` triples. `origin` (usually the
    /// file path) appears in error messages.
    pub fn compile(sources: &[(String, String, String)]) -> Result<Self, String> {
        let mut compiler = yara_x::Compiler::new();
        for (namespace, origin, source) in sources {
            compiler.new_namespace(namespace);
            let code = yara_x::SourceCode::from(source.as_str()).with_origin(origin.as_str());
            compiler.add_source(code).map_err(|e| e.to_string())?;
        }
        let warnings = compiler.warnings().iter().map(|w| w.to_string()).collect();
        Ok(YaraRules { rules: compiler.build(), warnings })
    }

    pub fn len(&self) -> usize {
        self.rules.iter().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Matching non-private rules, in rule order. `Err` on timeout.
    pub fn scan(&self, data: &[u8], timeout: Duration, max_matches: usize) -> Result<Vec<Hit>, String> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        scanner.set_timeout(timeout).max_matches_per_pattern(max_matches);
        let results = scanner.scan(data).map_err(|e| e.to_string())?;
        Ok(results
            .matching_rules()
            .map(|r| {
                let meta: serde_json::Map<String, serde_json::Value> = r
                    .metadata()
                    .map(|(k, v)| (k.to_string(), meta_json(v)))
                    .collect();
                let first = r.patterns().find_map(|p| {
                    p.matches().next().map(|m| (p.identifier().to_string(), m.range().start))
                });
                (
                    r.namespace().to_string(),
                    r.identifier().to_string(),
                    r.tags().map(|t| t.identifier().to_string()).collect(),
                    serde_json::Value::Object(meta).to_string(),
                    first,
                )
            })
            .collect())
    }
}

fn meta_json(v: yara_x::MetaValue<'_>) -> serde_json::Value {
    use yara_x::MetaValue::*;
    match v {
        Integer(i) => i.into(),
        Float(f) => f.into(),
        Bool(b) => b.into(),
        String(s) => s.into(),
        Bytes(b) => b.iter().map(|&c| c as char).collect::<std::string::String>().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(ns: &str, text: &str) -> (String, String, String) {
        (ns.into(), format!("{ns}.yar"), text.into())
    }

    const RULE: &str = r#"
        rule Eicarish : test demo {
            meta: verdict = "malicious" score = 90 ratio = 0.5 strong = true raw = "\xff"
            strings: $a = "EVIL" $b = { 4D 5A }
            condition: any of them
        }
        private rule hidden { condition: true }
        rule nostrings { condition: filesize == 3 }
    "#;

    #[test]
    fn compiles_and_reports_matches() {
        let y = YaraRules::compile(&[src("demo", RULE)]).unwrap();
        assert_eq!(y.len(), 3);
        assert!(!y.is_empty());
        let hits = y.scan(b"xxEVILyy", Duration::from_secs(5), 64).unwrap();
        assert_eq!(hits.len(), 1);
        let (ns, id, tags, meta, first) = &hits[0];
        assert_eq!((ns.as_str(), id.as_str()), ("demo", "Eicarish"));
        assert_eq!(tags, &vec!["test".to_string(), "demo".to_string()]);
        let meta: serde_json::Value = serde_json::from_str(meta).unwrap();
        assert_eq!(meta["verdict"], "malicious");
        assert_eq!(meta["score"], 90);
        assert_eq!(meta["ratio"], 0.5);
        assert_eq!(meta["strong"], true);
        assert_eq!(meta["raw"], "\u{ff}");
        assert_eq!(first, &Some(("$a".to_string(), 2)));
        let hits = y.scan(b"abc", Duration::from_secs(5), 64).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, "nostrings");
        assert_eq!(hits[0].4, None);
    }

    #[test]
    fn compile_errors_name_the_origin() {
        let err = YaraRules::compile(&[src("bad", "rule x { condition: $nope }")]).err().unwrap();
        assert!(err.contains("bad.yar"), "{err}");
    }

    #[test]
    fn warnings_are_kept() {
        let y = YaraRules::compile(&[src("w", "rule w { strings: $a = { 00 [0-1] [0-1] 01 } condition: $a and 1 == 1 }")]).unwrap();
        assert!(!y.warnings().is_empty());
    }
}
