use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

use crate::timeline_parser::detectors::{warn_skipped, SkippedRule};

#[derive(Clone, Debug)]
pub struct ToolMatch {
    pub name: String,
    pub category: String,
    pub mitre: String,
}

pub struct TAToolDetector {
    /// A prefilter: one alternation over every *live* pattern, so the common case
    /// — text matching nothing — costs one scan rather than several hundred.
    ///
    /// `None` means "no prefilter", not "no detection". It used to mean the
    /// latter, and that was the more dangerous of this file's two silent
    /// failures: the alternation is built from every pattern at once, so a single
    /// uncompilable one made `Regex::new(..).ok()` return `None` and `scan`
    /// returned empty for every input — TA-tool detection off across the whole
    /// run — while `pattern_count()` still reported hundreds of loaded patterns.
    prefilter: Option<Regex>,
    pattern_to_tool: Vec<(Regex, ToolMatch)>,
    count: usize,
    skipped: Vec<SkippedRule>,
}

impl TAToolDetector {
    pub fn new(data_dir: &Path) -> Result<Self> {
        let yaml_path = data_dir.join("ta_tools.yaml");
        if !yaml_path.exists() {
            eprintln!(
                "[!] TA tool list not found at {} — TA-tool detection DISABLED \
                 (set --data-dir or WTP_DATA_DIR)",
                yaml_path.display()
            );
            return Ok(Self {
                prefilter: None,
                pattern_to_tool: Vec::new(),
                count: 0,
                skipped: Vec::new(),
            });
        }
        let content = std::fs::read_to_string(&yaml_path)?;
        let data: HashMap<String, HashMap<String, serde_yaml::Value>> = serde_yaml::from_str(&content)?;

        // Only patterns that compiled on their own go into the prefilter. A bad
        // one must cost its own rule, not the alternation every other rule is
        // gated behind.
        let mut live_patterns: Vec<String> = Vec::new();
        let mut pattern_to_tool: Vec<(Regex, ToolMatch)> = Vec::new();
        let mut skipped: Vec<SkippedRule> = Vec::new();

        for (category, tools) in &data {
            for (tool_name, info) in tools {
                let mitre = info.get("mitre")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let patterns = info.get("patterns")
                    .and_then(|v| v.as_sequence())
                    .map(|seq| seq.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>())
                    .unwrap_or_default();

                for p in &patterns {
                    match Regex::new(&format!("(?i){}", p)) {
                        Ok(re) => {
                            live_patterns.push(p.clone());
                            pattern_to_tool.push((re, ToolMatch {
                                name: tool_name.clone(),
                                category: category.clone(),
                                mitre: mitre.clone(),
                            }));
                        }
                        Err(e) => skipped.push(SkippedRule {
                            section: format!("ta_tools.yaml: {category}"),
                            reason: tool_name.clone(),
                            pattern: p.clone(),
                            error: e.to_string(),
                        }),
                    }
                }
            }
        }

        let count = pattern_to_tool.len();
        warn_skipped("TA-tool", &skipped, count);

        let prefilter = if live_patterns.is_empty() {
            None
        } else {
            let joined = live_patterns.iter()
                .map(|p| format!("({})", p))
                .collect::<Vec<_>>()
                .join("|");
            match Regex::new(&format!("(?i){}", joined)) {
                Ok(re) => Some(re),
                Err(e) => {
                    // Every part compiled alone, so the union is too large or too
                    // deep rather than wrong. Detection stays complete; it just
                    // loses its fast path.
                    eprintln!(
                        "[!] TA-tool prefilter could not be built ({e}) — scanning all \
                         {count} patterns per record instead. Detection is complete but slower."
                    );
                    None
                }
            }
        };

        Ok(Self { prefilter, pattern_to_tool, count, skipped })
    }

    pub fn pattern_count(&self) -> usize {
        self.count
    }

    /// Patterns present in `ta_tools.yaml` that are not active.
    pub fn skipped_rules(&self) -> &[SkippedRule] {
        &self.skipped
    }

    pub fn scan(&self, text: &str) -> Vec<ToolMatch> {
        if text.is_empty() {
            return Vec::new();
        }
        // No prefilter means scan everything, not skip everything.
        if let Some(ref prefilter) = self.prefilter {
            if !prefilter.is_match(text) {
                return Vec::new();
            }
        }

        let mut matches = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (re, tool) in &self.pattern_to_tool {
            if re.is_match(text) && seen.insert(&tool.name) {
                matches.push(tool.clone());
            }
        }
        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector_from(yaml: &str) -> TAToolDetector {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ta_tools.yaml"), yaml).unwrap();
        // The YAML is read in full at construction, so the temp dir can go.
        TAToolDetector::new(dir.path()).unwrap()
    }

    /// The regression this rewrite exists for. A lookaround is not supported by
    /// the `regex` crate, and one such pattern used to take the whole detector
    /// down with it: the prefilter is an alternation over every pattern, so it
    /// failed to compile, and `scan` then returned empty for every input.
    #[test]
    fn one_uncompilable_pattern_does_not_disable_the_others() {
        let d = detector_from(
            "lateral_movement:\n\
             \x20 psexec:\n\
             \x20   mitre: T1570\n\
             \x20   patterns:\n\
             \x20     - \"psexec\"\n\
             \x20 unsupported_syntax:\n\
             \x20   mitre: T1059\n\
             \x20   patterns:\n\
             \x20     - \"(?<!safe)mimikatz\"\n",
        );

        let hits = d.scan("C:\\Windows\\Temp\\psexec.exe");
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].name, "psexec");
        assert_eq!(hits[0].mitre, "T1570");
        assert_eq!(d.pattern_count(), 1, "only the compilable pattern is live");
    }

    /// ...and it is named, so the report can say the run was degraded.
    #[test]
    fn an_uncompilable_pattern_is_recorded_with_its_error() {
        let d = detector_from(
            "credential_access:\n\
             \x20 unsupported_syntax:\n\
             \x20   mitre: T1003\n\
             \x20   patterns:\n\
             \x20     - \"(?<!safe)dump\"\n",
        );
        let skipped = d.skipped_rules();
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert_eq!(skipped[0].reason, "unsupported_syntax");
        assert_eq!(skipped[0].section, "ta_tools.yaml: credential_access");
        assert!(!skipped[0].error.is_empty());
        assert_eq!(d.pattern_count(), 0);
        // Nothing loaded, so nothing matches — but that is now visible.
        assert!(d.scan("dump").is_empty());
    }

    /// A missing rule pack is loud, not fatal, and matches nothing.
    #[test]
    fn a_missing_rule_pack_yields_no_patterns_and_no_matches() {
        let dir = tempfile::tempdir().unwrap();
        let d = TAToolDetector::new(dir.path()).unwrap();
        assert_eq!(d.pattern_count(), 0);
        assert!(d.skipped_rules().is_empty(), "absent is not the same as uncompilable");
        assert!(d.scan("anything at all").is_empty());
    }

    /// Every pattern shipped in the repo's own rule pack must compile. Makes the
    /// lookaround class unreintroducible for this pack.
    #[test]
    fn every_shipped_ta_tool_pattern_compiles() {
        let d = TAToolDetector::new(Path::new("tools/threat_intel")).unwrap();
        let names: Vec<&str> = d.skipped_rules().iter().map(|s| s.reason.as_str()).collect();
        assert!(d.skipped_rules().is_empty(), "these shipped patterns are not active: {names:?}");
        assert!(d.pattern_count() > 0, "the shipped pack loaded no patterns at all");
    }
}
