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
    pub fn dedup_key(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.timestamp.hash(&mut hasher);
        self.source.hash(&mut hasher);
        let desc_prefix: String = self.description.chars().take(100).collect();
        desc_prefix.hash(&mut hasher);
        hasher.finish()
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
