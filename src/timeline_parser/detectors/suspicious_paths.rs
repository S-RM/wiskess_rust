use anyhow::Result;
use regex::Regex;
use std::path::Path;

use crate::timeline_parser::detectors::file_classes::normalise_path;
use crate::timeline_parser::detectors::{warn_skipped, SkippedRule};

#[derive(Clone, Debug)]
pub struct PathMatch {
    pub reason: String,
    pub severity: String,
    pub mitre: String,
}

struct Rule {
    pattern: Regex,
    /// A second pattern that vetoes the match.
    ///
    /// Needed because the webroot rule has to exclude the very directories that
    /// `user_temp_execution` and `windows_temp_execution` exist to match, and a
    /// global exclusion list would break those two.
    exclude: Option<Regex>,
    /// Extensions this rule applies to. Empty = any.
    require_ext: Vec<String>,
    /// Parent-directory fragments that veto the match, compared case-insensitively.
    exclude_parent: Vec<String>,
    reason: String,
    severity: String,
    mitre: String,
}

impl Rule {
    fn applies_to(&self, filename: &str, parent: &str) -> bool {
        if !self.require_ext.is_empty() {
            let f = filename.to_lowercase();
            if !self.require_ext.iter().any(|e| f.ends_with(e.as_str())) {
                return false;
            }
        }
        if !self.exclude_parent.is_empty() {
            let p = parent.to_lowercase();
            if self.exclude_parent.iter().any(|frag| p.contains(frag.as_str())) {
                return false;
            }
        }
        true
    }

    fn to_match(&self) -> PathMatch {
        PathMatch {
            reason: self.reason.clone(),
            severity: self.severity.clone(),
            mitre: self.mitre.clone(),
        }
    }
}

pub struct SuspiciousPathDetector {
    path_rules: Vec<Rule>,
    filename_rules: Vec<Rule>,
    skipped: Vec<SkippedRule>,
}

impl SuspiciousPathDetector {
    /// How many rules are live. Zero means path detection is off, which the
    /// report has to say — a run with no rules produces a thin timeline that
    /// looks exactly like a quiet host.
    pub fn rule_count(&self) -> usize {
        self.path_rules.len() + self.filename_rules.len()
    }

    /// Rules present in the YAML that could not be compiled. Non-empty means the
    /// run is degraded and the report says so.
    pub fn skipped_rules(&self) -> &[SkippedRule] {
        &self.skipped
    }

    pub fn new(data_dir: &Path) -> Result<Self> {
        let yaml_path = data_dir.join("suspicious_paths.yaml");
        if !yaml_path.exists() {
            eprintln!(
                "[!] Suspicious-path rules not found at {} — path detection DISABLED \
                 (set --data-dir or WTP_DATA_DIR)",
                yaml_path.display()
            );
            return Ok(Self {
                path_rules: Vec::new(),
                filename_rules: Vec::new(),
                skipped: Vec::new(),
            });
        }
        let content = std::fs::read_to_string(&yaml_path)?;
        let data: serde_yaml::Value = serde_yaml::from_str(&content)?;

        let mut skipped = Vec::new();
        let path_rules = load_section(&data, "suspicious_executable_paths", &mut skipped);
        let filename_rules = load_section(&data, "suspicious_filenames", &mut skipped);

        warn_skipped("suspicious-path", &skipped, path_rules.len() + filename_rules.len());

        Ok(Self { path_rules, filename_rules, skipped })
    }

    /// Check a full path against the path rules, and its filename against the
    /// filename rules.
    ///
    /// The path is normalised first, so a relative `.\...` from `MFTECmd.csv`, a
    /// `/`-separated `FullPath` from `mft_dump.csv` and a `[root]/...` from the
    /// rusty USN parse all meet the rules in the same shape.
    pub fn check_path(&self, filepath: &str) -> Vec<PathMatch> {
        if filepath.trim().is_empty() {
            return Vec::new();
        }
        let path = normalise_path(filepath);
        let mut hits = Vec::new();

        let (parent, filename) = match path.rsplit_once('\\') {
            Some((p, f)) => (p, f),
            None => ("", path.as_str()),
        };

        for rule in &self.path_rules {
            if !rule.applies_to(filename, parent) {
                continue;
            }
            if rule.pattern.is_match(&path) && !rule.excluded(&path) {
                hits.push(rule.to_match());
            }
        }

        // Filename rules match the leaf, but their exclusions are about where it
        // sits — a `cmd.exe` under System32 is Windows, the same name elsewhere is
        // not.
        //
        // This used to be gated on the filename ending in .exe/.dll/.scr/.com for
        // *every* rule, hard-coded. That silently disabled `double_extension`,
        // whose entire purpose is to catch `payload.exe.txt` — a name that by
        // definition does not end in `.exe`. The gate is now per-rule
        // (`require_ext`), and absent by default.
        for rule in &self.filename_rules {
            if !rule.applies_to(filename, parent) {
                continue;
            }
            if rule.pattern.is_match(filename) && !rule.excluded(&path) {
                hits.push(rule.to_match());
            }
        }

        hits
    }
}

impl Rule {
    fn excluded(&self, path: &str) -> bool {
        self.exclude.as_ref().is_some_and(|re| re.is_match(path))
    }
}

fn load_section(
    data: &serde_yaml::Value,
    section: &str,
    skipped: &mut Vec<SkippedRule>,
) -> Vec<Rule> {
    let mut out = Vec::new();
    let Some(rules) = data.get(section).and_then(|v| v.as_sequence()) else {
        return out;
    };

    for rule in rules {
        let pattern_str = rule.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
        let reason = rule.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let severity = rule.get("severity").and_then(|v| v.as_str()).unwrap_or("med").to_string();
        let mitre = rule.get("mitre").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let exclude_str = rule.get("exclude_pattern").and_then(|v| v.as_str());

        let require_ext: Vec<String> = rule
            .get("require_ext")
            .and_then(|v| v.as_sequence())
            .map(|s| {
                s.iter()
                    .filter_map(|v| v.as_str())
                    .map(|e| e.trim().to_lowercase())
                    .collect()
            })
            .unwrap_or_default();

        let exclude_parent: Vec<String> = rule
            .get("exclude_parent")
            .and_then(|v| v.as_sequence())
            .map(|s| {
                s.iter()
                    .filter_map(|v| v.as_str())
                    .map(|e| e.trim().to_lowercase())
                    .collect()
            })
            .unwrap_or_default();

        let pattern = match Regex::new(&format!("(?i){pattern_str}")) {
            Ok(re) => re,
            Err(e) => {
                skipped.push(SkippedRule {
                    section: section.to_string(),
                    reason: reason.clone(),
                    pattern: pattern_str.to_string(),
                    error: e.to_string(),
                });
                continue;
            }
        };

        let exclude = match exclude_str {
            Some(s) => match Regex::new(&format!("(?i){s}")) {
                Ok(re) => Some(re),
                Err(e) => {
                    // A rule whose exclusion does not compile must not load
                    // without it: the exclusion is what keeps it from firing on
                    // the whole of `\Windows\Temp`.
                    skipped.push(SkippedRule {
                        section: section.to_string(),
                        reason: format!("{reason} (exclude_pattern)"),
                        pattern: s.to_string(),
                        error: e.to_string(),
                    });
                    continue;
                }
            },
            None => None,
        };

        out.push(Rule {
            pattern,
            exclude,
            require_ext,
            exclude_parent,
            reason,
            severity,
            mitre,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> SuspiciousPathDetector {
        // The rules that ship, not a fixture: a test against a hand-written YAML
        // cannot catch a rule that does not compile in the real one.
        SuspiciousPathDetector::new(Path::new("tools/threat_intel")).unwrap()
    }

    fn reasons(d: &SuspiciousPathDetector, path: &str) -> Vec<String> {
        d.check_path(path).into_iter().map(|m| m.reason).collect()
    }

    /// The regression that started this work: a JSP written into a served tree,
    /// as MFTECmd spells it — relative, no drive letter.
    #[test]
    fn a_script_in_a_web_served_tree_is_flagged_from_a_relative_path() {
        let d = detector();
        let hits = d.check_path(r".\ColdFusion2018\cfusion\wwwroot\cf_scripts\scripts\ajax\shell.jsp");
        let reasons: Vec<&str> = hits.iter().map(|h| h.reason.as_str()).collect();
        assert!(
            reasons.contains(&"script_in_web_served_tree"),
            "expected a webroot hit, got {reasons:?}"
        );
        let hit = hits.iter().find(|h| h.reason == "script_in_web_served_tree").unwrap();
        assert_eq!(hit.severity, "high");
        assert_eq!(hit.mitre, "T1505.003");
    }

    /// The same file, spelled the other two ways the collection format uses.
    #[test]
    fn the_webroot_rule_does_not_care_which_separator_the_source_used() {
        let d = detector();
        for path in [
            r".\srv\tomcat\webapps\ROOT\shell.jsp",
            "[root]/srv/tomcat/webapps/ROOT/shell.jsp",
            "/srv/tomcat/webapps/ROOT/shell.jsp",
            r"D:\srv\tomcat\webapps\ROOT\shell.jsp",
        ] {
            assert!(
                reasons(&d, path).contains(&"script_in_web_served_tree".to_string()),
                "{path} should hit the webroot rule"
            );
        }
    }

    /// A servlet container writes these only when the JSP was *requested*. That
    /// is execution evidence, and it is the strongest of the three webshell rules.
    #[test]
    fn a_compiled_jsp_is_flagged_as_container_compilation() {
        let d = detector();
        for path in [
            r".\ColdFusion2018\cfusion\runtime\work\Catalina\localhost\tmp\org\apache\jsp\shell_jsp.java",
            r".\srv\tomcat\work\Catalina\localhost\ROOT\org\apache\jsp\shell_jsp.class",
        ] {
            assert!(
                reasons(&d, path).contains(&"jsp_compiled_by_servlet_container".to_string()),
                "{path} should hit the compiled-JSP rule"
            );
        }
    }

    /// The webroot rule must not fire on a shipped library that merely lives near
    /// one, or it stops being worth reading.
    #[test]
    fn a_vendor_jar_beside_a_webroot_is_not_a_webshell() {
        let d = detector();
        let r = reasons(&d, r".\Program Files\AppServer\lib\jsp-api.jar");
        assert!(
            !r.contains(&"script_in_web_served_tree".to_string()),
            "a .jar outside a served directory is not a webshell, got {r:?}"
        );
    }

    /// The exclusions exist so the webroot rule does not swallow the two Temp
    /// rules' territory — and so those two keep working.
    #[test]
    fn temp_directories_stay_with_the_rules_that_own_them() {
        let d = detector();

        let temp = reasons(&d, r"C:\Users\testuser\AppData\Local\Temp\dropper.exe");
        assert!(temp.contains(&"user_temp_execution".to_string()));
        assert!(!temp.contains(&"script_in_web_served_tree".to_string()));

        let wtemp = reasons(&d, r"C:\Windows\Temp\stage.ps1");
        assert!(wtemp.contains(&"windows_temp_execution".to_string()));
    }

    /// The gate that silently disabled this rule: a double extension by
    /// definition does not end in `.exe`, so a global "must end in .exe" check
    /// meant it could never fire.
    #[test]
    fn a_double_extension_is_flagged_even_though_it_does_not_end_in_exe() {
        let d = detector();
        let r = reasons(&d, r"C:\Users\testuser\Downloads\invoice.exe.txt");
        assert!(r.contains(&"double_extension".to_string()), "got {r:?}");
    }

    /// A masquerading system binary is only interesting away from System32, and
    /// the comparison has to be case-insensitive — the old one was not, so a path
    /// spelled `system32` (as MFT often does) defeated it.
    #[test]
    fn a_system_binary_is_flagged_outside_system32_in_any_casing() {
        let d = detector();
        assert!(reasons(&d, r"C:\Users\Public\svchost.exe")
            .contains(&"masquerading_system_binary".to_string()));

        for legit in [
            r"C:\Windows\System32\svchost.exe",
            r".\windows\system32\svchost.exe",
            r".\Windows\SysWOW64\cmd.exe",
        ] {
            let r = reasons(&d, legit);
            assert!(
                !r.contains(&"masquerading_system_binary".to_string())
                    && !r.contains(&"masquerading_shell".to_string()),
                "{legit} is Windows shipping its own binary, got {r:?}"
            );
        }
    }

    /// The rule that was silently absent. This test is the reason it cannot
    /// happen again — it asserts against the YAML that actually ships.
    #[test]
    fn every_shipped_rule_compiles() {
        let d = detector();
        let skipped: Vec<&str> = d.skipped_rules().iter().map(|s| s.reason.as_str()).collect();
        assert!(
            d.skipped_rules().is_empty(),
            "these shipped rules are not active: {skipped:?}"
        );
        assert!(d.rule_count() > 0, "no rules loaded at all");
    }

    #[test]
    fn an_empty_path_matches_nothing() {
        let d = detector();
        assert!(d.check_path("").is_empty());
        assert!(d.check_path("   ").is_empty());
    }
}
