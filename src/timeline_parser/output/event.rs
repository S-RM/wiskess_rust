use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// One normalised event.
///
/// The last three fields exist so that a decidable question is decided **here**,
/// once, rather than re-litigated by every downstream consumer. The 28-host
/// review that prompted them found the same artefact classified three different
/// ways on three different hosts — `MpDlpCmd.exe` under Defender's platform tree
/// supporting an AMBER, a GREEN and a RED verdict — because nothing in the
/// output said what it was. A model asked to judge 1,256 identical rows will
/// sometimes call them servicing and sometimes call them attacker activity; the
/// fix is to not ask.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct UnifiedEvent {
    pub timestamp: String,
    pub source: String,
    pub event_type: String,
    pub severity: String,
    pub description: String,
    pub indicators: Vec<String>,
    pub mitre_tactic: String,
    pub mitre_technique: String,
    pub user: String,
    pub hostname: String,
    pub detection_rule: String,

    /// What this event *is*, when that is decidable from its own fields:
    /// `automation:group-membership-refresh`, `vendor:withsecure`,
    /// `os:component-store`, `os:servicing`, `responder:collection`.
    /// Empty means "not decided", never "not benign".
    #[serde(default)]
    pub classification: String,

    /// For a tool/binary finding: whether anything shows it *ran*, as opposed to
    /// merely being present on disk. See [`ExecutionEvidence`].
    #[serde(default)]
    pub execution_evidence: String,

    /// Where this event sits relative to the host's restoration date:
    /// `pre-restoration`, `restoration-process`, `responder`,
    /// `post-restoration`. Empty when no restoration date is known.
    #[serde(default)]
    pub phase: String,
}

/// Does the evidence show the file ran, or only that it exists?
///
/// `ntdsutil.exe` in `WinSxS` was read as attacker tooling until someone
/// observed there was "no process-creation event, no prefetch, and no Amcache or
/// UserAssist record, so nothing shows it ran". That is derivable from the
/// artefact the row came from, so it is derived once, here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionEvidence {
    /// The file exists (MFT, USN, component store) and nothing shows it ran.
    None,
    /// An Amcache/shimcache entry exists — the file was *seen* by the OS, which
    /// is not the same as executed.
    Registered,
    /// Prefetch, UserAssist run count, 4688/Sysmon 1, a service start, or a
    /// jump-list/LNK access record.
    Executed,
}

impl ExecutionEvidence {
    pub fn label(self) -> &'static str {
        match self {
            ExecutionEvidence::None => "none",
            ExecutionEvidence::Registered => "registered",
            ExecutionEvidence::Executed => "executed",
        }
    }

    /// The default reading for a parser's source artefact.
    ///
    /// AppCompatCache (shimcache) is deliberately `registered`, not `executed`:
    /// a shimcache entry means the file was examined by the application
    /// compatibility layer, which happens on enumeration as well as on launch.
    pub fn for_source(source: &str) -> Option<ExecutionEvidence> {
        Some(match source {
            "mft" | "usnjrnl" | "registry" | "regripper" => ExecutionEvidence::None,
            "amcache" | "appcompatcache" => ExecutionEvidence::Registered,
            "jump-lists" | "lnk-files" => ExecutionEvidence::Executed,
            _ => return None,
        })
    }
}

impl UnifiedEvent {
    /// The identity of this event, for adjacent-duplicate removal.
    ///
    /// This used to hash `timestamp`, `source` and the **first 100 characters** of
    /// the description. On this evidence that is a data-loss bug rather than a
    /// tuning choice: an MFT create reads
    /// `File created: .\<45 chars of product tree>\<…>\<name>.jsp (36984 bytes)`,
    /// so every file written into the same deep directory in the same second
    /// hashed identically and all but one was deleted — precisely the same-second
    /// batch a dropper produces.
    ///
    /// Everything that distinguishes two events is therefore hashed: the whole
    /// description, the verb (`event_type`), the rule that fired, and the
    /// indicator set, which is what separates a row a detection fired on from an
    /// otherwise identical one it did not.
    ///
    /// Cost is one pass over short strings per event, and `dedup_by_key` only
    /// compares neighbours, so this stays O(n).
    pub fn dedup_key(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.timestamp.hash(&mut hasher);
        self.source.hash(&mut hasher);
        self.event_type.hash(&mut hasher);
        self.detection_rule.hash(&mut hasher);
        self.description.hash(&mut hasher);
        self.indicators.hash(&mut hasher);
        hasher.finish()
    }

    /// Replace any control character in this event's text with a space.
    ///
    /// `columns::get` trims a terminator, which is the common shape, but not a
    /// control character in the *middle* of a cell — and Amcache's `ProductName`
    /// is arbitrary bytes written by whoever built the binary. One real row read
    /// `Product: 熀\r\u{1}\u{0}\u{1}o桓牯`, and that single `NUL` in a 131 MB
    /// supertimeline is enough for `grep` to declare the whole file binary and
    /// print nothing — including for every unrelated row in it. An embedded
    /// newline does the same to any line-oriented reader, quoted or not.
    ///
    /// So this is not cosmetic and it is not only about corruption: a field an
    /// attacker controls must not be able to decide whether the analyst's tools
    /// can read the output. Run once over the final vector, so the CSV, the
    /// JSONL, the OpenSearch NDJSON and the report all get it.
    pub fn sanitise(&mut self) {
        fn clean(s: &mut String) {
            if s.chars().any(char::is_control) {
                *s = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
            }
        }
        clean(&mut self.timestamp);
        clean(&mut self.source);
        clean(&mut self.event_type);
        clean(&mut self.severity);
        clean(&mut self.description);
        clean(&mut self.mitre_tactic);
        clean(&mut self.mitre_technique);
        clean(&mut self.user);
        clean(&mut self.hostname);
        clean(&mut self.detection_rule);
        clean(&mut self.classification);
        clean(&mut self.execution_evidence);
        clean(&mut self.phase);
        for i in &mut self.indicators {
            clean(i);
        }
    }

    /// Is this event explained by something that is not an actor?
    ///
    /// A classified event is still written to the supertimeline — suppressing it
    /// would hide the evidence the classification was drawn from — but it must
    /// not be presented as a finding, and must never reach a verdict table.
    pub fn is_explained(&self) -> bool {
        self.classification.starts_with("automation:")
            || self.classification.starts_with("vendor:")
            || self.classification.starts_with("os:")
            || self.classification.starts_with("responder:")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape observed in a live Amcache export: an interior `NUL` and a bare
    /// `CR` inside a `ProductName`, in a row that is otherwise ordinary. One of
    /// them anywhere in the file costs every other row its greppability.
    #[test]
    fn a_control_character_never_reaches_an_output_field() {
        let mut e = UnifiedEvent {
            description: "Amcache: c:\\dir\\app.exe | Product: a\r\u{0}\u{1}b".to_string(),
            user: "domain.local\\testuser\u{0}".to_string(),
            indicators: vec!["HASH:aa\u{0}bb".to_string()],
            ..Default::default()
        };
        e.sanitise();
        assert_eq!(e.description, "Amcache: c:\\dir\\app.exe | Product: a   b");
        assert_eq!(e.user, "domain.local\\testuser ");
        assert_eq!(e.indicators[0], "HASH:aa bb");
        for field in [&e.description, &e.user, &e.indicators[0]] {
            assert!(!field.chars().any(char::is_control), "{field:?}");
        }
    }

    /// It must not rewrite anything else — a path is full of characters that look
    /// like escapes and are not.
    #[test]
    fn ordinary_text_is_left_exactly_as_it_was() {
        let before = UnifiedEvent {
            description: "File created: \\inetpub\\wwwroot\\uploads\\shell.jsp (36984 bytes)"
                .to_string(),
            user: "domain.local\\svcweb".to_string(),
            indicators: vec!["PATH:script_in_web_served_tree".to_string()],
            ..Default::default()
        };
        let mut after = before.clone();
        after.sanitise();
        assert_eq!(after.description, before.description);
        assert_eq!(after.user, before.user);
        assert_eq!(after.indicators, before.indicators);
    }
}
