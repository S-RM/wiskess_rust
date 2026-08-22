use anyhow::Result;
use regex::Regex;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct PathMatch {
    pub reason: String,
    pub severity: String,
    pub mitre: String,
}

struct PathRule {
    pattern: Regex,
    reason: String,
    severity: String,
    mitre: String,
}

struct FilenameRule {
    pattern: Regex,
    reason: String,
    severity: String,
    mitre: String,
}

pub struct SuspiciousPathDetector {
    path_rules: Vec<PathRule>,
    filename_rules: Vec<FilenameRule>,
}

impl SuspiciousPathDetector {
    /// How many rules are live. Zero means path detection is off, which the
    /// report has to say — a run with no rules produces a thin timeline that
    /// looks exactly like a quiet host.
    pub fn rule_count(&self) -> usize {
        self.path_rules.len() + self.filename_rules.len()
    }

    pub fn new(data_dir: &Path) -> Result<Self> {
        let yaml_path = data_dir.join("suspicious_paths.yaml");
        if !yaml_path.exists() {
            eprintln!(
                "[!] Suspicious-path rules not found at {} — path detection DISABLED \
                 (set --data-dir or WTP_DATA_DIR)",
                yaml_path.display()
            );
            return Ok(Self { path_rules: Vec::new(), filename_rules: Vec::new() });
        }
        let content = std::fs::read_to_string(&yaml_path)?;
        let data: serde_yaml::Value = serde_yaml::from_str(&content)?;

        let mut path_rules = Vec::new();
        if let Some(rules) = data.get("suspicious_executable_paths").and_then(|v| v.as_sequence()) {
            for rule in rules {
                let pattern_str = rule.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                let reason = rule.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let severity = rule.get("severity").and_then(|v| v.as_str()).unwrap_or("med").to_string();
                let mitre = rule.get("mitre").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if let Ok(re) = Regex::new(&format!("(?i){}", pattern_str)) {
                    path_rules.push(PathRule { pattern: re, reason, severity, mitre });
                }
            }
        }

        let mut filename_rules = Vec::new();
        if let Some(rules) = data.get("suspicious_filenames").and_then(|v| v.as_sequence()) {
            for rule in rules {
                let pattern_str = rule.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                let reason = rule.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let severity = rule.get("severity").and_then(|v| v.as_str()).unwrap_or("med").to_string();
                let mitre = rule.get("mitre").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if let Ok(re) = Regex::new(&format!("(?i){}", pattern_str)) {
                    filename_rules.push(FilenameRule { pattern: re, reason, severity, mitre });
                }
            }
        }

        Ok(Self { path_rules, filename_rules })
    }

    pub fn check_path(&self, filepath: &str) -> Vec<PathMatch> {
        if filepath.is_empty() {
            return Vec::new();
        }
        let mut hits = Vec::new();

        for rule in &self.path_rules {
            if rule.pattern.is_match(filepath) {
                hits.push(PathMatch {
                    reason: rule.reason.clone(),
                    severity: rule.severity.clone(),
                    mitre: rule.mitre.clone(),
                });
            }
        }

        let filename = filepath.rsplit('\\').next()
            .or_else(|| filepath.rsplit('/').next())
            .unwrap_or(filepath);
        let parent = if filepath.contains('\\') {
            filepath.rsplit_once('\\').map(|(p, _)| p).unwrap_or("")
        } else {
            filepath.rsplit_once('/').map(|(p, _)| p).unwrap_or("")
        };

        for rule in &self.filename_rules {
            if rule.pattern.is_match(filename) {
                // Only flag if the entire filename matches (not a substring like "explorer.exe.dmp")
                let fname_lower = filename.to_lowercase();
                let is_exact_exe = fname_lower.ends_with(".exe") || fname_lower.ends_with(".dll")
                    || fname_lower.ends_with(".scr") || fname_lower.ends_with(".com");
                if is_exact_exe && !parent.contains("System32") && !parent.contains("SysWOW64")
                    && !parent.contains("WinSxS") && !parent.contains("winsxs")
                {
                    hits.push(PathMatch {
                        reason: rule.reason.clone(),
                        severity: rule.severity.clone(),
                        mitre: rule.mitre.clone(),
                    });
                }
            }
        }

        hits
    }
}
