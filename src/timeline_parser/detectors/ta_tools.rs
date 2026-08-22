use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct ToolMatch {
    pub name: String,
    pub category: String,
    pub mitre: String,
}

pub struct TAToolDetector {
    compiled: Option<Regex>,
    pattern_to_tool: Vec<(Regex, ToolMatch)>,
    count: usize,
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
            return Ok(Self { compiled: None, pattern_to_tool: Vec::new(), count: 0 });
        }
        let content = std::fs::read_to_string(&yaml_path)?;
        let data: HashMap<String, HashMap<String, serde_yaml::Value>> = serde_yaml::from_str(&content)?;

        let mut all_patterns: Vec<String> = Vec::new();
        let mut pattern_to_tool: Vec<(Regex, ToolMatch)> = Vec::new();

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
                    all_patterns.push(p.clone());
                    if let Ok(re) = Regex::new(&format!("(?i){}", p)) {
                        pattern_to_tool.push((re, ToolMatch {
                            name: tool_name.clone(),
                            category: category.clone(),
                            mitre: mitre.clone(),
                        }));
                    }
                }
            }
        }

        let count = pattern_to_tool.len();
        let combined = if all_patterns.is_empty() {
            None
        } else {
            let joined = all_patterns.iter()
                .map(|p| format!("({})", p))
                .collect::<Vec<_>>()
                .join("|");
            Regex::new(&format!("(?i){}", joined)).ok()
        };

        Ok(Self { compiled: combined, pattern_to_tool, count })
    }

    pub fn pattern_count(&self) -> usize {
        self.count
    }

    pub fn scan(&self, text: &str) -> Vec<ToolMatch> {
        if text.is_empty() {
            return Vec::new();
        }
        let Some(ref compiled) = self.compiled else { return Vec::new() };
        if !compiled.is_match(text) {
            return Vec::new();
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
