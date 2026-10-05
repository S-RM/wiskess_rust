//! Deterministic classification: decide, from fields the parser already has,
//! what an artefact *is* — before anything downstream is asked to judge it.
//!
//! The problem this solves was measured across a 28-host run: the same artefact
//! received opposite verdicts on different hosts. `MY-CTX01` was called RED
//! for "2268 local administrator group additions performed by the machine
//! account MY-CTX01$"; `MY-DHCP02` classed byte-identical machine-account
//! activity as background. `fls.exe` under
//! `ProgramData\F-Secure\...\response-package\...` was cited as "forensic
//! tooling in user-writable locations". `MpDlpCmd.exe` under Defender's platform
//! tree supported an AMBER, a GREEN and a RED.
//!
//! None of those are hard questions. Each is decidable from the row itself. A
//! model asked to judge a thousand identical events will sometimes call them
//! servicing and sometimes call them attacker activity — that is the nature of
//! the thing, and the fix is not a better prompt. It is to answer the question
//! here, once, so no two hosts can disagree.
//!
//! Everything classified here is still written to the supertimeline. A
//! classification suppresses a *finding*, never the evidence.

use anyhow::Result;
use chrono::NaiveDateTime;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::timeline_parser::detectors::file_classes::normalise_path;
use crate::timeline_parser::detectors::{warn_skipped, SkippedRule};
use crate::timeline_parser::output::event::UnifiedEvent;

// ── Principals ───────────────────────────────────────────────────────────────

/// A machine account: the computer object's own credential, spelled `HOST$`.
///
/// **A machine account is never a user account.** The run that prompted this
/// reported `TA-created User Account: MY-REM03$` and `Other: MY-PVS01$` as
/// attacker-created accounts. They are the hosts themselves.
pub fn is_machine_account(name: &str) -> bool {
    let n = strip_principal(name);
    !n.is_empty() && n.ends_with('$')
}

/// SYSTEM and the built-in service principals, by SID or by name.
pub fn is_system_principal(name: &str, sid: &str) -> bool {
    let s = sid.trim();
    if matches!(s, "S-1-5-18" | "S-1-5-19" | "S-1-5-20") {
        return true;
    }
    let n = strip_principal(name);
    matches!(
        n.as_str(),
        "system" | "localsystem" | "local system" | "local service" | "network service"
    ) || n.starts_with("nt authority")
}

/// True when the acting principal is the machine itself rather than a person:
/// the precondition for reading repeated activity as automation.
pub fn is_automation_principal(name: &str, sid: &str, logon_id: &str) -> bool {
    is_machine_account(name)
        || is_system_principal(name, sid)
        // 0x3e7 is the SYSTEM logon session.
        || logon_id.trim().eq_ignore_ascii_case("0x3e7")
}

/// Strip domain prefix, realm suffix and any parenthesised SID, and lowercase.
pub fn strip_principal(name: &str) -> String {
    let lower = name.to_lowercase();
    let s = lower.split('(').next().unwrap_or(&lower).trim();
    let s = s.split('@').next().unwrap_or(s);
    s.rsplit('\\').next().unwrap_or(s).trim().to_string()
}

// ── Paths: vendor trees, the component store, the responder's own kit ────────

/// One "anything under here belongs to this product" rule.
struct VendorRule {
    pattern: Regex,
    product: String,
}

/// Paths that are OS servicing rather than anything a person did. A file's
/// presence in the component store is not evidence that it ran, or that anyone
/// put it there.
const COMPONENT_STORE: &[(&str, &str)] = &[
    (r"\winsxs\", "component-store"),
    (r"\servicing\", "component-store"),
    (r"\driverstore\", "driver-store"),
    (r"\softwaredistribution\", "windows-update"),
    (r"\assembly\gac", "gac"),
    (r"\windows\installer\", "msi-cache"),
];

/// The responder's own footprint. Class 2 of the post-restoration partition:
/// the forensic collection is not attacker activity, and on the run that
/// prompted this it was landing in the same undifferentiated pile.
///
/// Each entry names a **directory or an executable**, and is matched at the start
/// of a path segment by [`path_segment_starts_with`] — never as a bare substring.
/// Unanchored, `collection-` explains away anything named `…datacollection-*` and
/// `hayabusa` anything under a directory containing the word, and an event this
/// classifies leaves the triage cut. That was tolerable while path classification
/// only ever saw drive-rooted paths; once `PATH_RE` also matches the relative
/// `.\…` form that `MFTECmd.csv` carries, it applies to every MFT row on the host.
const RESPONDER_MARKERS: &[(&str, &str)] = &[
    ("ir-collector", "collector"),
    ("velociraptor", "collector"),
    ("vql_", "collector-output"),
    ("kape.exe", "collector"),
    ("kape\\", "collector"),
    ("wiskess", "collector"),
    ("collection-", "collection-archive"),
    ("evtxecmd", "parser"),
    ("mftecmd", "parser"),
    ("hayabusa", "parser"),
];

/// Does `frag` appear in `lower` at the start of a path segment?
///
/// `lower` must already be lowercased and separator-normalised. A match at
/// position 0 counts: a path can reach here without a drive or a leading
/// separator (`Collection-HOST-…\Timeline\x.csv`), and the first segment is still
/// a segment.
///
/// This is a prefix test within the segment, not a whole-segment test, because
/// every marker is deliberately a stem — `collection-` is followed by a hostname,
/// `vql_` by a query name. The cost is that a directory merely *starting* with a
/// marker matches too; the alternative is missing the real thing on every host.
fn path_segment_starts_with(lower: &str, frag: &str) -> bool {
    lower
        .match_indices(frag)
        .any(|(at, _)| at == 0 || lower.as_bytes()[at - 1] == b'\\')
}

/// Built-in vendor trees, used when no `vendor_paths.yaml` is supplied and
/// merged with it when one is.
///
/// The path decides, never the filename. `fls.exe` is Sleuth Kit and is also
/// shipped inside F-Secure's response package; `7za.exe` ships with VMware
/// Tools. Judging either by name manufactures a finding on every host that runs
/// the product.
///
/// **A path allowlist is spoofable and an Authenticode signer is not**, so the
/// signer would be the better key — but the wiskess Timeline export carries no
/// signature field (`amcache.csv` is `FullPath, ProductName, SHA1,
/// FileExtension` and nothing else), so there is nothing here to prefer it
/// with. The report says which key was used. The escape hatch is
/// `overrides_explanation` in `output/supertimeline.rs`: a supplied-IOC match or
/// a malicious hash verdict outranks any path classification, because those are
/// statements about the content.
const BUILTIN_VENDOR_PATHS: &[(&str, &str)] = &[
    (r"\programdata\f-secure\", "withsecure"),
    (r"\program files\f-secure\", "withsecure"),
    (r"\program files (x86)\f-secure\", "withsecure"),
    (r"\programdata\microsoft\windows defender\", "microsoft-defender"),
    (r"\program files\windows defender\", "microsoft-defender"),
    (r"\programdata\microsoft\windows security health\", "microsoft-defender"),
    (r"\program files\sentinelone\", "sentinelone"),
    (r"\programdata\sentinel\", "sentinelone"),
    (r"\system32\drivers\sentinelone\", "sentinelone"),
    (r"\program files\vmware\vmware tools\", "vmware-tools"),
    (r"\program files\crowdstrike\", "crowdstrike"),
    (r"\programdata\crowdstrike\", "crowdstrike"),
    (r"\program files\sophos\", "sophos"),
    (r"\programdata\sophos\", "sophos"),
    (r"\program files\eset\", "eset"),
    (r"\program files\trend micro\", "trend-micro"),
    (r"\program files\symantec\", "symantec"),
    (r"\program files\carbon black\", "carbon-black"),
    (r"\program files\bitdefender\", "bitdefender"),
    (r"\program files\huntress\", "huntress"),
    (r"\program files\cisco\amp\", "cisco-amp"),
    (r"\program files\microsoft monitoring agent\", "azure-monitor"),
    (r"\windows\ccm\", "sccm"),
    (r"\windows\ccmsetup\", "sccm"),
];

/// Registry keys whose values are a product's own configuration — including
/// its blocklists. Anything read out of one of these is a statement about what
/// the software is *configured* to do, not about what this host did.
///
/// The case that proved this matters: an F-Secure Ultralight EDR key,
/// `...\Ultralight\Settings\nif.untrusted_urls`, enumerates dozens of domains in
/// a `REG_MULTI_SZ` value — the product's own sinkhole list, carrying
/// `anydesk.com` and `teamviewer.com` alongside genuinely malicious-looking
/// names. It appeared on 23 hosts and was first read as 23 compromises.
const CONFIG_KEY_MARKERS: &[&str] = &[
    r"\f-secure\",
    r"\withsecure\",
    r"\sentinelone\",
    r"\crowdstrike\",
    r"\sophos\",
    r"\eset\",
    r"\trend micro\",
    r"\symantec\",
    r"\bitdefender\",
    r"\microsoft\windows defender\",
    r"\policies\",
    r"\group policy\",
    r"untrusted_urls",
    r"\blocklist",
    r"\allowlist",
    r"\exclusions\",
];

pub struct Classifier {
    vendor: Vec<VendorRule>,
    /// Where the vendor rules came from, for the report's coverage table.
    pub vendor_rule_count: usize,
    pub vendor_source: String,
    skipped: Vec<SkippedRule>,
}

impl Classifier {
    /// Load `vendor_paths.yaml` from the data dir, merged over the built-ins.
    ///
    /// The built-ins are never dropped: a missing YAML must degrade to "fewer
    /// vendor trees known", not to "every EDR install tree is now suspicious".
    pub fn load(data_dir: &Path) -> Result<Self> {
        let mut vendor: Vec<VendorRule> = BUILTIN_VENDOR_PATHS
            .iter()
            .map(|(p, name)| VendorRule {
                pattern: Regex::new(&format!("(?i){}", regex::escape(p))).unwrap(),
                product: (*name).to_string(),
            })
            .collect();

        let mut source = "built-in".to_string();
        let mut skipped: Vec<SkippedRule> = Vec::new();
        let yaml_path = data_dir.join("vendor_paths.yaml");
        if yaml_path.exists() {
            let content = std::fs::read_to_string(&yaml_path)?;
            let data: serde_yaml::Value = serde_yaml::from_str(&content)?;
            let mut added = 0usize;
            if let Some(seq) = data.get("vendor_paths").and_then(|v| v.as_sequence()) {
                for rule in seq {
                    let product = rule.get("product").and_then(|v| v.as_str()).unwrap_or("");
                    if product.is_empty() {
                        continue;
                    }
                    // `path` is a literal path fragment, escaped here, so its
                    // compilation cannot fail. `pattern` is a regex and can.
                    if let Some(frag) = rule.get("path").and_then(|v| v.as_str()) {
                        if let Ok(re) = Regex::new(&format!("(?i){}", regex::escape(frag))) {
                            vendor.push(VendorRule { pattern: re, product: product.to_string() });
                            added += 1;
                        }
                    }
                    if let Some(pat) = rule.get("pattern").and_then(|v| v.as_str()) {
                        match Regex::new(&format!("(?i){}", pat)) {
                            Ok(re) => {
                                vendor
                                    .push(VendorRule { pattern: re, product: product.to_string() });
                                added += 1;
                            }
                            Err(e) => skipped.push(SkippedRule {
                                section: "vendor_paths.yaml".to_string(),
                                reason: product.to_string(),
                                pattern: pat.to_string(),
                                error: e.to_string(),
                            }),
                        }
                    }
                }
            }
            source = format!("built-in + {} from {}", added, yaml_path.display());
        }

        // A vendor rule that does not compile is the inverse of the other packs:
        // it does not lose a detection, it loses an *explanation*, so an install
        // tree stays unclassified and crowds the triage cut. Still degraded, still
        // has to be said.
        warn_skipped("vendor-path", &skipped, vendor.len());

        let n = vendor.len();
        Ok(Self { vendor, vendor_rule_count: n, vendor_source: source, skipped })
    }

    /// Vendor patterns present in `vendor_paths.yaml` that are not active.
    pub fn skipped_rules(&self) -> &[SkippedRule] {
        &self.skipped
    }

    /// The product whose install tree this path sits under, if any.
    pub fn vendor_for_path(&self, path: &str) -> Option<&str> {
        if path.is_empty() {
            return None;
        }
        self.vendor
            .iter()
            .find(|r| r.pattern.is_match(path))
            .map(|r| r.product.as_str())
    }

    /// Decide a classification for a path-bearing event, most specific first.
    ///
    /// Vendor beats component store: a vendor package unpacked under
    /// `ProgramData` is more informative than "somewhere on disk".
    ///
    /// The path is normalised first. Every fragment below is written in Windows
    /// form, and `mft_dump.csv`'s `/`-separated `FullPath` would otherwise match
    /// none of them.
    pub fn classify_path(&self, path: &str) -> Option<String> {
        if path.is_empty() {
            return None;
        }
        let normalised = normalise_path(path);
        if let Some(product) = self.vendor_for_path(&normalised) {
            return Some(format!("vendor:{product}"));
        }
        let lower = normalised.to_lowercase();
        if let Some((_, what)) = COMPONENT_STORE.iter().find(|(frag, _)| lower.contains(frag)) {
            return Some(format!("os:{what}"));
        }
        if let Some((_, what)) =
            RESPONDER_MARKERS.iter().find(|(frag, _)| path_segment_starts_with(&lower, frag))
        {
            return Some(format!("responder:{what}"));
        }
        None
    }
}

/// Is this registry path a product's own settings tree (including its
/// blocklists) rather than a record of something the host did?
pub fn is_configuration_key(key_path: &str) -> bool {
    let lower = key_path.to_lowercase();
    CONFIG_KEY_MARKERS.iter().any(|m| lower.contains(m))
}

// ── Persistence: establishment, not inventory ────────────────────────────────

/// Tasks under `\Microsoft\Windows\` are shipped by the OS. Modified by SYSTEM,
/// they are servicing.
///
/// `win_taskscheduler_susp_schtasks_delete_or_disable` fired 69 times in-window
/// on one host, every one of them
/// `\Microsoft\Windows\UpdateOrchestrator\Resume On Boot` under SYSTEM, and all
/// 69 were reported as persistence. **Deleting or disabling a scheduled task is
/// not persistence** — it is, if anything, the opposite.
pub fn is_os_task_servicing(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains(r"\microsoft\windows\")
        && (lower.contains("task") || lower.contains("schtasks"))
}

/// Sigma rule families that describe the *removal* of something, which a
/// persistence tag cannot honestly be drawn from.
const NOT_PERSISTENCE_RULES: &[&str] = &[
    "schtasks_delete",
    "delete_or_disable",
    "task_delete",
    "service_delete",
    "autorun_delete",
    "remove_scheduled_task",
];

/// Does this detection describe the **removal or disabling** of something?
///
/// Separate from [`persistence_is_established`] on purpose. That function asks
/// for positive evidence and is safe where the event type is structured (an
/// EID). Applied to a free-text sigma hit it would strip the tactic from every
/// rule whose message happens not to use one of the establishment verbs — a
/// second, opposite error. This asks only the question that is decidable from
/// the text: does this describe a deletion?
pub fn persistence_is_contradicted(rule: &str, description: &str) -> bool {
    let rule_lower = rule.to_lowercase();
    if NOT_PERSISTENCE_RULES.iter().any(|r| rule_lower.contains(r)) {
        return true;
    }
    let d = description.to_lowercase();
    ["deleted", "was deleted", "/delete", "disabled", "/disable", "removed", "unregister"]
        .iter()
        .any(|k| d.contains(k))
}

/// Does this detection describe establishment (a creation, an install) or
/// merely the existence — or removal — of an entry?
///
/// 25,952 Persistence findings across 27 of 28 hosts is an inventory of the
/// scheduled tasks, services and autoruns every Windows host has. A persistence
/// tag has to require evidence that something was *established*.
pub fn persistence_is_established(event_type: &str, rule: &str, description: &str) -> bool {
    // A deletion outranks the event type. A 4698 whose message says the task was
    // removed is a 4698 about a removal, whatever the EID nominally means.
    if persistence_is_contradicted(rule, description) {
        return false;
    }
    // Event types the parser only assigns on a genuine creation/install record.
    if matches!(
        event_type,
        "service_installed" | "scheduled_task_created" | "account_created" | "group_member_added"
    ) {
        return true;
    }
    let d = description.to_lowercase();
    ["created", "installed", "registered", "was added", "new service", "new task"]
        .iter()
        .any(|k| d.contains(k))
}

// ── Machine-account group-membership automation ──────────────────────────────

/// One observed group-membership change, kept for the cadence pass.
#[derive(Clone, Debug)]
pub struct GroupChange {
    /// Index of the emitted event this record came from, when one was emitted.
    ///
    /// Optional because the cadence has to be measured over **every** observed
    /// change, including the ones the include-gate dropped. A rate computed only
    /// from the events that survived filtering is not the host's rate.
    pub event_idx: Option<usize>,
    pub when: NaiveDateTime,
    /// The principal that performed the change.
    pub subject: String,
    /// The member SID/name that was added.
    pub member: String,
    /// The group it was added to.
    pub group: String,
    /// Was the subject a machine account / SYSTEM?
    pub by_machine: bool,
}

/// A recurring membership-refresh pattern, stated as a rate.
#[derive(Clone, Debug)]
pub struct Automation {
    pub subject: String,
    pub group: String,
    pub count: usize,
    /// Median interval between successive changes, in minutes.
    pub median_interval_mins: i64,
    pub span_hours: i64,
    pub members: Vec<String>,
    pub first: String,
    pub last: String,
}

impl Automation {
    /// "776 additions of the same 3 SIDs at ~1.5h intervals over 4 days" is a
    /// different statement from "776 admin group additions", and only the first
    /// is decidable by a reader.
    pub fn as_rate(&self) -> String {
        let interval = if self.median_interval_mins >= 60 {
            format!("~{:.1}h", self.median_interval_mins as f64 / 60.0)
        } else {
            format!("~{}m", self.median_interval_mins)
        };
        format!(
            "{} additions of the same {} member(s) to {} by {} at {} intervals over {:.1} days",
            self.count,
            self.members.len(),
            self.group,
            self.subject,
            interval,
            self.span_hours as f64 / 24.0
        )
    }
}

/// Below this a repeated change is not yet a cadence — it is just a few events.
pub const AUTOMATION_MIN_EVENTS: usize = 10;
/// Group Policy Restricted Groups re-applies a *small, fixed* member set. A
/// large or growing set is not a refresh.
pub const AUTOMATION_MAX_MEMBERS: usize = 8;
/// Share of consecutive intervals that must sit within ±50% of the median for
/// the series to count as regular.
const AUTOMATION_REGULARITY: f64 = 0.6;

/// Classify machine-account group-membership churn as automation, and return
/// one summary per (subject, group) series.
///
/// The events that *fit* the pattern are stamped
/// `automation:group-membership-refresh` and drop out of the triage set. The
/// events that break it — a member outside the recurring set — are left as
/// findings and marked, because that single event is the thing worth reading.
/// One such event was found on `MY-DHCP01`: a foreign-prefix SID ten minutes
/// before the collection archive, buried under 148 routine ones.
pub fn classify_group_membership(
    events: &mut [UnifiedEvent],
    changes: &[GroupChange],
) -> Vec<Automation> {
    let mut series: BTreeMap<(String, String), Vec<&GroupChange>> = BTreeMap::new();
    for c in changes {
        if !c.by_machine {
            continue;
        }
        series
            .entry((c.subject.clone(), c.group.clone()))
            .or_default()
            .push(c);
    }

    let mut out = Vec::new();
    for ((subject, group), mut rows) in series {
        if rows.len() < AUTOMATION_MIN_EVENTS {
            continue;
        }
        rows.sort_by_key(|c| c.when);

        let members: BTreeSet<String> = rows.iter().map(|c| c.member.clone()).collect();
        if members.len() > AUTOMATION_MAX_MEMBERS {
            continue;
        }

        // Which members recur? A one-off member in an otherwise regular series
        // is precisely the event that must survive.
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for c in &rows {
            *counts.entry(c.member.as_str()).or_default() += 1;
        }
        let recurring: BTreeSet<&str> = counts
            .iter()
            .filter(|(_, n)| **n >= 3)
            .map(|(m, _)| *m)
            .collect();
        if recurring.is_empty() {
            continue;
        }

        let mut intervals: Vec<i64> = rows
            .windows(2)
            .map(|w| (w[1].when - w[0].when).num_minutes())
            .collect();
        if intervals.is_empty() {
            continue;
        }
        let mut sorted = intervals.clone();
        sorted.sort_unstable();
        let median = sorted[sorted.len() / 2];
        if median <= 0 {
            // Everything at one instant is a bulk operation, not a cadence.
            continue;
        }
        let lo = (median as f64 * 0.5) as i64;
        let hi = (median as f64 * 1.5).ceil() as i64;
        let regular = intervals.iter().filter(|i| **i >= lo && **i <= hi).count();
        if (regular as f64) / (intervals.len() as f64) < AUTOMATION_REGULARITY {
            continue;
        }
        intervals.clear();

        let span_hours = (rows.last().unwrap().when - rows.first().unwrap().when).num_hours();
        let mut classified = 0usize;
        for c in &rows {
            let Some(idx) = c.event_idx else { continue };
            if !recurring.contains(c.member.as_str()) {
                // Off-pattern: the single event *is* the finding.
                if let Some(e) = events.get_mut(idx) {
                    e.indicators.push(format!("OFF_CADENCE_MEMBER:{}", c.member));
                }
                continue;
            }
            if let Some(e) = events.get_mut(idx) {
                e.classification = "automation:group-membership-refresh".to_string();
                e.severity = "low".to_string();
                e.mitre_tactic.clear();
                e.mitre_technique.clear();
                classified += 1;
            }
        }
        if classified == 0 {
            continue;
        }

        out.push(Automation {
            subject,
            group,
            count: rows.len(),
            median_interval_mins: median,
            span_hours,
            members: recurring.iter().map(|m| (*m).to_string()).collect(),
            first: rows.first().unwrap().when.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            last: rows.last().unwrap().when.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        });
    }
    out
}

/// One event per detected automation series, so the cadence is visible in the
/// timeline rather than only in the report.
pub fn automation_events(autos: &[Automation], hostname: &str) -> Vec<UnifiedEvent> {
    autos
        .iter()
        .map(|a| UnifiedEvent {
            timestamp: a.first.clone(),
            source: "classification".to_string(),
            event_type: "automation_series".to_string(),
            severity: "info".to_string(),
            description: format!(
                "Group membership refresh (automation, not actor activity): {}. \
                 Members: {}. Last change {}.",
                a.as_rate(),
                a.members.join(", "),
                a.last
            ),
            indicators: vec![
                format!("AUTOMATION:group-membership-refresh"),
                format!("RATE:{}m", a.median_interval_mins),
            ],
            hostname: hostname.to_string(),
            detection_rule: "machine_account_cadence".to_string(),
            classification: "automation:group-membership-refresh".to_string(),
            ..Default::default()
        })
        .collect()
}

// ── One pass over the file-artefact events ───────────────────────────────────

/// Windows paths as they appear inside a description line.
///
/// This used to require a drive-rooted path (`C:\`, `\\?\C:\`,
/// `\Device\HarddiskVolume2\`). Two of the three largest artifacts do not carry
/// one: `MFTECmd.csv` writes its parent path **relative** to the volume root
/// (`.\Windows\Temp\…`), and `usnjrnl_j_rusty.csv` writes `[root]/…`, which
/// `normalise_path` reduces to a leading `\`. So path classification matched
/// nothing at all on the MFT and USN rows — the bulk of the timeline — and
/// nothing said so: `classify_path` returning `None` is indistinguishable from
/// "this path is not in a vendor tree".
///
/// The alternatives, in preference order at a given start position:
///   1. `\\?\C:` — the extended-length form, first so `\\` is not read as UNC
///   2. `\Device\HarddiskVolume<n>` — the volume-device form
///   3. `\\host` — UNC
///   4. `C:` — a drive letter
///   5. `.` / `..` — MFTECmd's relative parent
///   6. failing all of those, `\segment\…` — rooted at the volume with no drive,
///      which is what a stripped `[root]` leaves. Two segments are required so a
///      lone `\x` in prose is not read as a path.
///
/// A spurious match is safe in the direction that matters: `classify_path` simply
/// finds no marker in it and the event keeps its place in the triage cut.
static PATH_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?i)(?:"#,
        r#"(?:\\\\\?\\[a-z]:|\\Device\\HarddiskVolume\d+|\\\\[a-z0-9._$-]+|[a-z]:|\.{1,2})"#,
        r#"\\[^"|,;]*"#,
        r#"|\\[^"|,;\\]+\\[^"|,;]*"#,
        r#")"#,
    ))
    .unwrap()
});

/// Sources whose rows are *about* a file or a registry key, and where the path
/// therefore decides what the row is.
///
/// Event-log and sigma rows are deliberately excluded: their text mentions paths
/// incidentally, and a service message naming Defender's tree must not excuse
/// the row it appears in. Those two sources classify themselves, in their own
/// parsers, from structured fields rather than from prose.
const PATH_SOURCES: &[&str] = &[
    "mft", "usnjrnl", "amcache", "amcache-regripper", "appcompatcache", "jump-lists", "lnk-files",
];

/// Apply path-derived classification and execution evidence across the timeline.
///
/// Returns `(classified, with_execution_evidence)`.
pub fn apply(events: &mut [UnifiedEvent], c: &Classifier) -> (usize, usize) {
    use crate::timeline_parser::output::event::ExecutionEvidence;

    let mut classified = 0usize;
    let mut evidenced = 0usize;

    for e in events.iter_mut() {
        let is_path_source = PATH_SOURCES.contains(&e.source.as_str());
        let is_registry = matches!(e.source.as_str(), "registry" | "regripper");

        if is_registry && e.classification.is_empty() && is_configuration_key(&e.description) {
            // The product's own settings, including its blocklists. Whatever
            // strings this row carries, the host did not go there.
            e.classification = "config:product-settings".to_string();
            classified += 1;
        }

        if !is_path_source {
            continue;
        }

        if e.classification.is_empty() {
            if let Some(m) = PATH_RE.find(&e.description) {
                if let Some(class) = c.classify_path(m.as_str().trim()) {
                    e.classification = class;
                    classified += 1;
                }
            }
        }

        if e.execution_evidence.is_empty() {
            // AppCompatCache carries the answer explicitly; take it over the
            // per-source default when it is present.
            let ev = if e.source == "appcompatcache" && e.description.contains("Executed: Yes") {
                Some(ExecutionEvidence::Executed)
            } else {
                ExecutionEvidence::for_source(&e.source)
            };
            if let Some(ev) = ev {
                e.execution_evidence = ev.label().to_string();
                evidenced += 1;
            }
        }
    }
    (classified, evidenced)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").unwrap()
    }

    fn ev(i: usize) -> UnifiedEvent {
        UnifiedEvent {
            timestamp: format!("2026-05-0{}T00:00:00Z", i % 9 + 1),
            source: "event-logs".into(),
            event_type: "group_member_added".into(),
            severity: "high".into(),
            mitre_tactic: "Persistence".into(),
            mitre_technique: "T1098".into(),
            ..Default::default()
        }
    }

    /// A machine account is never a user account. This alone removes
    /// `"TA-created User Account: MY-REM03$"` and its siblings.
    #[test]
    fn a_machine_account_is_recognised_through_its_domain_prefix_and_sid() {
        assert!(is_machine_account("MY-REM03$"));
        assert!(is_machine_account("DOMAIN\\MY-CTX01$"));
        assert!(is_machine_account("MY-PVS01$ (S-1-5-21-1-2-3-1105)"));
        assert!(!is_machine_account("super admin"));
        assert!(!is_machine_account(""));
    }

    #[test]
    fn system_is_recognised_by_sid_by_name_and_by_logon_session() {
        assert!(is_system_principal("SYSTEM", ""));
        assert!(is_system_principal("", "S-1-5-18"));
        assert!(is_system_principal("NT AUTHORITY\\SYSTEM", ""));
        assert!(!is_system_principal("super admin", "S-1-5-21-1-2-3-2659"));
        assert!(is_automation_principal("someone", "", "0x3e7"));
        assert!(!is_automation_principal("super admin", "S-1-5-21-1-2-3-2659", "0x1a2b3c"));
    }

    /// The 2268-additions case. A regular cadence of the same small member set
    /// by the host's own machine account is Restricted Groups, not an actor.
    #[test]
    fn a_regular_machine_account_cadence_is_classified_as_automation() {
        let mut events: Vec<UnifiedEvent> = (0..24).map(ev).collect();
        let changes: Vec<GroupChange> = (0..24)
            .map(|i| GroupChange {
                event_idx: Some(i),
                when: dt("2026-05-01T00:00:00") + chrono::Duration::minutes(90 * i as i64),
                subject: "MY-CTX01$".into(),
                member: format!("S-1-5-21-1-2-3-{}", 1000 + (i % 3)),
                group: "Administrators".into(),
                by_machine: true,
            })
            .collect();

        let autos = classify_group_membership(&mut events, &changes);
        assert_eq!(autos.len(), 1, "{autos:?}");
        let a = &autos[0];
        assert_eq!(a.count, 24);
        assert_eq!(a.members.len(), 3);
        assert_eq!(a.median_interval_mins, 90);
        // Stated as a rate, which is the only form a reader can decide.
        assert!(a.as_rate().contains("~1.5h"), "{}", a.as_rate());
        assert!(events.iter().all(|e| e.classification == "automation:group-membership-refresh"));
        assert!(events.iter().all(|e| e.mitre_tactic.is_empty()),
            "an automation series must not carry a Persistence tag");
    }

    /// The one event that breaks the pattern is the finding, and it must not be
    /// swept up with the 148 routine ones around it.
    #[test]
    fn an_off_cadence_member_survives_as_a_finding() {
        let mut events: Vec<UnifiedEvent> = (0..21).map(ev).collect();
        let mut changes: Vec<GroupChange> = (0..20)
            .map(|i| GroupChange {
                event_idx: Some(i),
                when: dt("2026-05-01T00:00:00") + chrono::Duration::minutes(90 * i as i64),
                subject: "MY-DHCP01$".into(),
                member: format!("S-1-5-21-1-2-3-{}", 1000 + (i % 2)),
                group: "Administrators".into(),
                by_machine: true,
            })
            .collect();
        changes.push(GroupChange {
            event_idx: Some(20),
            when: dt("2026-05-01T22:35:00"),
            subject: "MY-DHCP01$".into(),
            member: "S-1-5-21-9-9-9-1105".into(), // foreign prefix, seen once
            group: "Administrators".into(),
            by_machine: true,
        });

        classify_group_membership(&mut events, &changes);
        assert_eq!(events[20].classification, "", "the odd one out must stay a finding");
        assert_eq!(events[20].severity, "high");
        assert!(events[20].indicators.iter().any(|i| i.starts_with("OFF_CADENCE_MEMBER:")));
        assert_eq!(events[0].classification, "automation:group-membership-refresh");
    }

    /// A human adding an account to Administrators once is not automation, and
    /// no amount of pattern-matching may turn it into one.
    #[test]
    fn a_human_change_is_never_classified_as_automation() {
        let mut events: Vec<UnifiedEvent> = (0..15).map(ev).collect();
        let changes: Vec<GroupChange> = (0..15)
            .map(|i| GroupChange {
                event_idx: Some(i),
                when: dt("2026-05-01T00:00:00") + chrono::Duration::minutes(90 * i as i64),
                subject: "super admin".into(),
                member: "S-1-5-21-1-2-3-2659".into(),
                group: "Administrators".into(),
                by_machine: false,
            })
            .collect();
        assert!(classify_group_membership(&mut events, &changes).is_empty());
        assert!(events.iter().all(|e| e.classification.is_empty()));
    }

    /// Irregular timing is not a cadence. A burst of additions inside one minute
    /// is a bulk operation and stays a finding.
    #[test]
    fn an_irregular_burst_is_not_automation() {
        let mut events: Vec<UnifiedEvent> = (0..15).map(ev).collect();
        let changes: Vec<GroupChange> = (0..15)
            .map(|i| GroupChange {
                event_idx: Some(i),
                when: dt("2026-05-01T00:00:00") + chrono::Duration::seconds(i as i64),
                subject: "HOST$".into(),
                member: "S-1-5-21-1-2-3-1000".into(),
                group: "Administrators".into(),
                by_machine: true,
            })
            .collect();
        assert!(classify_group_membership(&mut events, &changes).is_empty());
    }

    /// Too few events to establish a rate: report them, do not explain them.
    #[test]
    fn a_handful_of_changes_is_not_yet_a_cadence() {
        let mut events: Vec<UnifiedEvent> = (0..4).map(ev).collect();
        let changes: Vec<GroupChange> = (0..4)
            .map(|i| GroupChange {
                event_idx: Some(i),
                when: dt("2026-05-01T00:00:00") + chrono::Duration::hours(i as i64),
                subject: "HOST$".into(),
                member: "S-1-5-21-1-2-3-1000".into(),
                group: "Administrators".into(),
                by_machine: true,
            })
            .collect();
        assert!(classify_group_membership(&mut events, &changes).is_empty());
    }

    /// The three named path false-positives from the cross-host review.
    #[test]
    fn the_named_vendor_paths_are_classified_as_vendor_trees() {
        let c = Classifier::load(Path::new("/nonexistent")).unwrap();
        assert_eq!(
            c.classify_path(r"C:\ProgramData\F-Secure\Ultralight\response-package\1774339991\fls.exe")
                .as_deref(),
            Some("vendor:withsecure")
        );
        assert_eq!(
            c.classify_path(r"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2\MpDlpCmd.exe")
                .as_deref(),
            Some("vendor:microsoft-defender")
        );
        assert_eq!(
            c.classify_path(r"C:\Program Files\VMware\VMware Tools\7za.exe").as_deref(),
            Some("vendor:vmware-tools")
        );
    }

    /// The path decides, not the filename. `fls.exe` outside a vendor tree is
    /// still unclassified — the tool does not get a pass, the location does.
    #[test]
    fn the_same_filename_outside_a_vendor_tree_is_not_classified() {
        let c = Classifier::load(Path::new("/nonexistent")).unwrap();
        assert_eq!(c.classify_path(r"C:\Users\super admin\Downloads\fls.exe"), None);
    }

    /// `ntdsutil.exe` in WinSxS is OS servicing, and its presence there is not
    /// evidence of anything.
    #[test]
    fn component_store_paths_are_os_servicing() {
        let c = Classifier::load(Path::new("/nonexistent")).unwrap();
        assert_eq!(
            c.classify_path(r"C:\Windows\WinSxS\amd64_ntdsutil\ntdsutil.exe").as_deref(),
            Some("os:component-store")
        );
        assert_eq!(
            c.classify_path(r"C:\Windows\SoftwareDistribution\Download\x.exe").as_deref(),
            Some("os:windows-update")
        );
    }

    /// The responder's own kit is class 2 of the post-restoration partition.
    #[test]
    fn the_collectors_own_artefacts_are_attributed_to_the_responder() {
        let c = Classifier::load(Path::new("/nonexistent")).unwrap();
        assert_eq!(
            c.classify_path(r"C:\Users\ir\AppData\Local\Temp\ir-Collector-Windows.exe")
                .as_deref(),
            Some("responder:collector")
        );
        assert!(c
            .classify_path(r"C:\Temp\VQL_processes.jsonl")
            .unwrap()
            .starts_with("responder:"));
    }

    /// A marker must name a directory or a binary, not appear anywhere in a
    /// string. Unanchored, these three were all read as the responder's own kit
    /// and dropped out of the triage cut — and after the `PATH_RE` widening the
    /// substring test ran against every MFT row on the host, not just the few
    /// that carried a drive letter.
    #[test]
    fn a_marker_inside_a_name_is_not_the_responders_kit() {
        let c = Classifier::load(Path::new("/nonexistent")).unwrap();
        for path in [
            r"C:\Windows\System32\datacollection-service.dll",
            r"C:\Program Files\Acme\telemetry-hayabusa-plugin.dll",
            r"C:\inetpub\wwwroot\upload-collection-2026.aspx",
        ] {
            assert_eq!(c.classify_path(path), None, "{path} is not the responder's own kit");
        }
    }

    /// ...while the real thing still is, at the start of any segment.
    #[test]
    fn a_marker_starting_a_segment_is_still_the_responders_kit() {
        let c = Classifier::load(Path::new("/nonexistent")).unwrap();
        for (path, expected) in [
            (r"C:\Tools\Collection-MY-WEB01-2026-09-10-Wiskess\Timeline\x.csv", "responder:collection-archive"),
            (r"Collection-MY-WEB01\Timeline\registry.csv", "responder:collection-archive"),
            (r"D:\kape\kape.exe", "responder:collector"),
            (r"\Users\testuser\Desktop\hayabusa\hayabusa.exe", "responder:parser"),
        ] {
            assert_eq!(c.classify_path(path).as_deref(), Some(expected), "{path}");
        }
    }

    fn path_event(source: &str, description: &str) -> UnifiedEvent {
        UnifiedEvent {
            timestamp: "2026-06-24T10:58:22.919Z".into(),
            source: source.into(),
            event_type: "file_created".into(),
            severity: "med".into(),
            description: description.into(),
            ..Default::default()
        }
    }

    /// The regression: `MFTECmd.csv` carries a path relative to the volume root,
    /// so after normalisation it has no drive letter — and `PATH_RE` used to
    /// require one. Path classification therefore matched nothing on the largest
    /// artifact in the collection, and nothing reported that.
    #[test]
    fn a_path_with_no_drive_letter_is_still_classified() {
        let c = Classifier::load(Path::new("/nonexistent")).unwrap();
        let mut events = vec![
            path_event("mft", r"File created: \Windows\WinSxS\amd64_ntdsutil\ntdsutil.exe (91 bytes)"),
            path_event("usnjrnl", r"FileCreate|Close: \Program Files\VMware\VMware Tools\7za.exe"),
            path_event("mft", r"File created: \Windows\SoftwareDistribution\Download\x.exe (0 bytes)"),
        ];
        let (classified, _) = apply(&mut events, &c);
        assert_eq!(classified, 3, "{:?}", events.iter().map(|e| &e.classification).collect::<Vec<_>>());
        assert_eq!(events[0].classification, "os:component-store");
        assert_eq!(events[1].classification, "vendor:vmware-tools");
        assert_eq!(events[2].classification, "os:windows-update");
    }

    /// `mft_dump.csv` writes `/` separators and the rusty USN parser prefixes
    /// `[root]`. Both have to reach the same rules as the Windows spelling.
    #[test]
    fn the_other_path_spellings_reach_the_same_rules() {
        let c = Classifier::load(Path::new("/nonexistent")).unwrap();
        assert_eq!(
            c.classify_path("[root]/Windows/WinSxS/amd64_x/y.exe").as_deref(),
            Some("os:component-store")
        );
        assert_eq!(
            c.classify_path(r".\Program Files\Sophos\Sophos Agent\x.exe").as_deref(),
            Some("vendor:sophos")
        );
    }

    /// A webshell under a webroot is in no vendor tree, no component store and no
    /// collection — so it stays unclassified and stays in the triage cut. That is
    /// the whole point of widening the regex without widening the markers.
    #[test]
    fn a_relative_webroot_path_is_not_explained_away() {
        let c = Classifier::load(Path::new("/nonexistent")).unwrap();
        let mut events = vec![path_event(
            "mft",
            r"File created: \ColdFusion2018\cfusion\wwwroot\cf_scripts\scripts\ajax\shell.jsp (36984 bytes)",
        )];
        let (classified, _) = apply(&mut events, &c);
        assert_eq!(classified, 0);
        assert!(events[0].classification.is_empty(), "{}", events[0].classification);
    }

    /// The EDR blocklist that read as 23 host compromises.
    #[test]
    fn a_product_settings_key_is_configuration_not_activity() {
        assert!(is_configuration_key(
            r"HKEY_LOCAL_MACHINE\Software\F-Secure\Ultralight\Settings\nif.untrusted_urls"
        ));
        assert!(is_configuration_key(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\x"));
        assert!(!is_configuration_key(
            r"HKLM\SYSTEM\CurrentControlSet\Services\Remotely_Agent\ImagePath"
        ));
    }

    /// Deleting or disabling a scheduled task is not persistence.
    #[test]
    fn task_deletion_is_never_persistence() {
        assert!(!persistence_is_established(
            "sigma_detection_med",
            "win_taskscheduler_susp_schtasks_delete_or_disable.yml",
            r"Task \Microsoft\Windows\UpdateOrchestrator\Resume On Boot disabled"
        ));
        assert!(is_os_task_servicing(
            r"schtasks /change /tn \Microsoft\Windows\UpdateOrchestrator\Resume On Boot /disable"
        ));
    }

    /// An inventory entry is not an establishment record.
    #[test]
    fn persistence_requires_an_establishment_record() {
        assert!(persistence_is_established("service_installed", "correlated_eid_7045", "A new service was installed"));
        assert!(!persistence_is_established(
            "registry_persistence",
            "registry_persistence_check",
            "Run: OneDriveSetup = C:\\Windows\\SysWOW64\\OneDriveSetup.exe"
        ));
    }

    /// A YAML file adds vendor trees; it never removes the built-ins, because a
    /// missing or truncated file must not make every EDR tree suspicious again.
    #[test]
    fn a_vendor_yaml_extends_the_builtins_rather_than_replacing_them() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("vendor_paths.yaml"),
            "vendor_paths:\n  - product: acme-edr\n    path: '\\Program Files\\Acme\\'\n",
        )
        .unwrap();
        let c = Classifier::load(dir.path()).unwrap();
        assert_eq!(
            c.classify_path(r"C:\Program Files\Acme\agent.exe").as_deref(),
            Some("vendor:acme-edr")
        );
        assert_eq!(
            c.classify_path(r"C:\Program Files\SentinelOne\x.exe").as_deref(),
            Some("vendor:sentinelone"),
            "the built-ins must survive"
        );
    }
}
