pub mod classify;
pub mod compromised;
pub mod file_classes;
pub mod ioc_matcher;
pub mod restoration;
pub mod software;
pub mod suspicious_paths;
pub mod ta_tools;

/// The ATT&CK tactic and technique a firing rule carries, accumulated as rules
/// fire on one row.
///
/// The rule packs have carried this all along — `suspicious_paths.yaml` gives each
/// rule a `mitre:` technique ID and `ta_tools.yaml` files each tool under a tactic
/// section — and every parser threw it away: each one wrote
/// `mitre_tactic: String::new(), mitre_technique: String::new()` regardless of
/// what fired. So a `high` webshell rule reported no technique, and
/// `## Findings by ATT&CK Tactic`, which groups on `mitre_tactic`, could not see a
/// single path or TA-tool detection.
///
/// **First rule to fire wins each field.** Parsers that already derive a tactic
/// from the artifact itself (an event ID, a persistence registry key) seed it
/// before scanning, and a rule hit then fills only what is still blank.
#[derive(Clone, Debug, Default)]
pub struct Attack {
    pub tactic: String,
    pub technique: String,
}

impl Attack {
    /// Seed from what the artifact itself already established.
    pub fn from_artifact(tactic: &str, technique: &str) -> Self {
        Self { tactic: tactic.to_string(), technique: technique.to_string() }
    }

    fn fill(field: &mut String, value: &str) {
        if field.is_empty() && !value.is_empty() {
            *field = value.to_string();
        }
    }

    /// Take the technique from a suspicious-path hit.
    ///
    /// The tactic is deliberately **not** derived: `suspicious_paths.yaml` supplies
    /// a technique ID and nothing else, and mapping `T1505.003` back to
    /// "Persistence" would mean shipping a technique→tactic table this repo does
    /// not have. An empty tactic groups the finding under
    /// `Unknown/Uncategorized`, which is true; a guessed one would not be.
    pub fn from_path(&mut self, m: &suspicious_paths::PathMatch) {
        Self::fill(&mut self.technique, &m.mitre);
    }

    /// Take both from a TA-tool hit — the tool's YAML section *is* its tactic.
    pub fn from_tool(&mut self, m: &ta_tools::ToolMatch) {
        Self::fill(&mut self.tactic, &tactic_name(&m.category));
        Self::fill(&mut self.technique, &m.mitre);
    }
}

/// `credential_access` -> `Credential Access`, the spelling the rest of the
/// pipeline and the report already use.
///
/// Mechanical, because ATT&CK tactic names are the section names title-cased —
/// with the one irregular case that has a lowercase conjunction.
fn tactic_name(category: &str) -> String {
    if category == "command_control" || category == "command_and_control" {
        return "Command and Control".to_string();
    }
    category
        .split('_')
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut cs = w.chars();
            match cs.next() {
                Some(first) => first.to_uppercase().collect::<String>() + cs.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A detection rule that is present in a shipped rule pack but did not compile.
///
/// Every loader here used to discard these with `if let Ok(re) = Regex::new(..)`.
/// One rule in `suspicious_paths.yaml` used a negative lookahead, which the
/// `regex` crate does not support, so the file held 14 rules, the detector loaded
/// 13, and the report printed `13` as though that were the intended number. A
/// detection rule that silently does not exist is worse than one that is missing
/// loudly: the run still produces a clean-looking report.
///
/// Shared across the four loaders (`suspicious_paths`, `ta_tools`, the
/// `classify` vendor list, `software`) so the report can state all of them in one
/// place and `DetectionCoverage::degraded()` can key off the total.
#[derive(Clone, Debug)]
pub struct SkippedRule {
    /// Which pack and section the rule came from, e.g. `suspicious_filenames`
    /// or `ta_tools.yaml: lateral_movement`.
    pub section: String,
    /// The rule's own name — its `reason`, its `product`, or the tool it detects.
    pub reason: String,
    pub pattern: String,
    pub error: String,
}

/// Say on stderr which rules are inactive, and how many of the pack that is.
///
/// One function rather than one block per loader, so every pack reports the same
/// way and a new pack cannot quietly report differently.
pub fn warn_skipped(pack: &str, skipped: &[SkippedRule], live: usize) {
    for s in skipped {
        eprintln!(
            "[!] Detection rule `{}` in {} did not compile and is NOT active: {}",
            s.reason, s.section, s.error
        );
        eprintln!("[!]   pattern: {}", s.pattern);
    }
    if !skipped.is_empty() {
        eprintln!(
            "[!] {} of {} {} rules are inactive — detection is DEGRADED",
            skipped.len(),
            skipped.len() + live,
            pack
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path_hit(mitre: &str) -> suspicious_paths::PathMatch {
        suspicious_paths::PathMatch {
            reason: "script_in_web_served_tree".into(),
            severity: "high".into(),
            mitre: mitre.into(),
        }
    }

    fn tool_hit(category: &str, mitre: &str) -> ta_tools::ToolMatch {
        ta_tools::ToolMatch {
            name: "sometool".into(),
            category: category.into(),
            mitre: mitre.into(),
        }
    }

    #[test]
    fn a_ta_tool_section_becomes_its_attack_tactic() {
        assert_eq!(tactic_name("credential_access"), "Credential Access");
        assert_eq!(tactic_name("impact"), "Impact");
        assert_eq!(tactic_name("defense_evasion"), "Defense Evasion");
        // The one tactic whose name is not just the words title-cased.
        assert_eq!(tactic_name("command_control"), "Command and Control");
        assert_eq!(tactic_name("command_and_control"), "Command and Control");
        assert_eq!(tactic_name(""), "");
    }

    /// The defect this exists to fix: a path rule carries a technique and nothing
    /// was reading it.
    #[test]
    fn a_path_rule_supplies_the_technique_and_never_invents_the_tactic() {
        let mut a = Attack::default();
        a.from_path(&path_hit("T1505.003"));
        assert_eq!(a.technique, "T1505.003");
        assert_eq!(a.tactic, "", "there is no technique->tactic table here, so none is guessed");
    }

    #[test]
    fn a_ta_tool_supplies_both() {
        let mut a = Attack::default();
        a.from_tool(&tool_hit("lateral_movement", "T1021"));
        assert_eq!(a.tactic, "Lateral Movement");
        assert_eq!(a.technique, "T1021");
    }

    /// What the artifact itself established outranks a rule hit, and the first
    /// rule to fire outranks the second.
    #[test]
    fn what_is_already_known_is_never_overwritten() {
        let mut a = Attack::from_artifact("Execution", "");
        a.from_tool(&tool_hit("credential_access", "T1003"));
        assert_eq!(a.tactic, "Execution", "the artifact's own tactic stands");
        assert_eq!(a.technique, "T1003", "but a blank field is filled");

        a.from_path(&path_hit("T1505.003"));
        assert_eq!(a.technique, "T1003", "the first rule to fire keeps the field");
    }

    /// A rule with no `mitre:` must not blank a field another rule filled.
    #[test]
    fn a_rule_without_attack_data_changes_nothing() {
        let mut a = Attack::from_artifact("Execution", "T1059");
        a.from_path(&path_hit(""));
        a.from_tool(&tool_hit("", ""));
        assert_eq!((a.tactic.as_str(), a.technique.as_str()), ("Execution", "T1059"));
    }
}
