use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::io::BufReader;
use std::path::Path;
use std::sync::LazyLock;

use crate::timeline_parser::config::{severity_order, PipelineConfig};
use crate::timeline_parser::detectors::classify::{
    self, is_automation_principal, is_machine_account, strip_principal, Automation, GroupChange,
};
use crate::timeline_parser::detectors::compromised::CompromisedEntities;
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::detectors::Attack;
use crate::timeline_parser::output::event::UnifiedEvent;
use crate::timeline_parser::parsers::columns::{
    self, Columns, Field, DATETIME, EVENT_ID, MESSAGE, USER_NAME,
};

/// Matches the `(1.2.3.4)` source IP that EvtxECmd appends to the `RemoteHost`
/// column, e.g. `MY-DC02 (192.168.40.3)`.
static REMOTE_IP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)").unwrap());

/// A successful inbound logon session worth keeping for precursor correlation —
/// "what session was already established before the actor did X". RDP (type 10)
/// and externally-sourced network/SMB (type 3) logons.
#[derive(Clone, Debug)]
pub struct SessionLogon {
    pub timestamp: String,
    pub logon_type: u8,
    pub user: String,
    pub src_ip: String,
    pub src_host: String,
}

impl SessionLogon {
    /// Human label for the logon channel.
    pub fn kind(&self) -> &'static str {
        match self.logon_type {
            10 | 7 => "RDP",
            3 => "SMB/Network",
            2 => "Interactive",
            _ => "Logon",
        }
    }
}

/// Everything `parse_correlated` learned from `event-logs.csv`.
///
/// Grew from a 2-tuple because two of these — the machine-account cadence and
/// the rare-logon count — are properties of the **whole file** and cannot be
/// decided a row at a time.
pub struct EventLogOutput {
    pub events: Vec<UnifiedEvent>,
    /// Inbound RDP/SMB sessions, for precursor correlation.
    pub logons: Vec<SessionLogon>,
    /// Machine-account group-membership series recognised as automation.
    pub automations: Vec<Automation>,
    /// Successful logons by real accounts carried as baseline (verbose only).
    pub baseline_logons: usize,
    /// Of those, how many were out of hours.
    pub off_hours_logons: usize,
    /// Of those, how many were rare combinations.
    pub rare_logons: usize,
}

/// A logon combination, counted across the whole record so rarity is decidable.
type LogonKey = (String, u8, String);

/// Is this a real person's (or a real service account's) logon, as opposed to
/// the machine's own or a built-in principal?
///
/// The operator's line: "all the successful logons from legitimate users, not
/// machine accounts". `ANONYMOUS LOGON` is excluded for the same reason — it
/// names no account at all.
fn is_baseline_user(user: &str) -> bool {
    let u = strip_principal(user);
    !u.is_empty()
        && u != "-"
        && !u.ends_with('$')
        && u != "system"
        && u != "localsystem"
        && u != "anonymous logon"
        && !u.starts_with("nt authority")
        && !u.starts_with("local service")
        && !u.starts_with("network service")
        && !u.starts_with("dwm-")
        && !u.starts_with("umfd-")
        && !u.starts_with("s-1-")
        && u.len() > 1
}

/// Human label for a Windows logon type.
fn logon_type_name(t: u8) -> &'static str {
    match t {
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        7 => "Unlock",
        8 => "NetworkCleartext",
        9 => "NewCredentials",
        10 => "RemoteInteractive",
        11 => "CachedInteractive",
        _ => "Other",
    }
}

/// Pull a Windows `EventData` field out of the JSON payload by its `@Name`,
/// returning the associated `#text` value. Payloads are flat
/// `{"@Name":"LogonType","#text":"10"}` records, so a substring scan is both
/// correct and far cheaper than JSON-parsing every row.
fn payload_field<'a>(payload: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("\"@Name\":\"{}\",\"#text\":\"", name);
    let start = payload.find(&key)? + key.len();
    let rest = &payload[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Resolve the remote source IP + workstation name of a logon. The `RemoteHost`
/// column (`Workstation (IP)`) is preferred; payload `IpAddress`/`WorkstationName`
/// are the fallback.
fn remote_endpoint(remote_host: &str, payload: &str) -> (String, String) {
    let ip = REMOTE_IP_RE
        .captures(remote_host)
        .map(|c| c[1].to_string())
        .or_else(|| payload_field(payload, "IpAddress").map(str::to_string))
        .unwrap_or_default();
    let host = remote_host
        .split('(')
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "-")
        .map(str::to_string)
        .or_else(|| payload_field(payload, "WorkstationName").map(str::to_string))
        .unwrap_or_default();
    let host = if host == "-" { String::new() } else { host };
    (ip, host)
}

/// True when an IPv4 is a real remote peer (not loopback / broadcast / empty).
fn is_external_src(ip: &str) -> bool {
    !ip.is_empty()
        && ip != "-"
        && ip != "0.0.0.0"
        && !ip.starts_with("127.")
        && !ip.starts_with("::")
}

/// True when a 4648 `TargetServerName` points at a *different* host (outbound
/// lateral movement) rather than the collected host itself, a service GUID, or
/// localhost.
fn is_remote_target(server: &str, self_host: &str) -> bool {
    let s = server.trim();
    if s.is_empty() || s == "-" || s.eq_ignore_ascii_case("localhost") {
        return false;
    }
    // Service-ticket GUIDs (8-4-4-4-12 hex) are not real servers.
    let looks_guid = s.len() == 36
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
        && s.matches('-').count() == 4;
    if looks_guid {
        return false;
    }
    let short = |h: &str| h.split('.').next().unwrap_or(h).trim_end_matches('$').to_lowercase();
    short(s) != short(self_host)
}

/// Build the stored description for an event-log row.
///
/// The **full** message is preserved verbatim — the CSV/JSONL supertimeline and triage
/// timeline are forensic deep-dive artifacts and must not lose payload data. Truncation
/// for human readability happens only when rendering the Markdown report (`trunc_desc`
/// in `src/output/report.rs`), which splices in rule-hit context as needed.
fn build_description(event_id: u32, msg: &str, _indicators: &[String]) -> String {
    format!("EventID {}: {}", event_id, msg)
}

struct CriticalEID {
    severity: &'static str,
    mitre: &'static str,
    tactic: &'static str,
    event_type: &'static str,
    /// The channel that gives this EventID the meaning the rule assumes.
    ///
    /// **An EventID is only unique within its provider**, so matching on the
    /// number alone is a false-positive generator. EID 1102 is the worked
    /// example: on `Security` it is "the audit log was cleared" (T1070.001,
    /// critical), but DFSR emits 1102 on `DFS Replication` for routine volume
    /// replication and ShellCommon emits 1102 on
    /// `...StartLayoutPopulation/Operational` for Start-menu tile population.
    /// A DC produces both constantly. Unscoped, a healthy domain controller
    /// reports "log clearing by an unknown host" on every single run — observed
    /// on RESTO-DC01 (20 hits, 0 genuine) and ITSDCPW014.
    channel: &'static str,
}

fn critical_eids() -> HashMap<u32, CriticalEID> {
    let mut map = HashMap::new();
    map.insert(1102, CriticalEID { severity: "crit", mitre: "T1070.001", tactic: "Defense Evasion", event_type: "log_cleared", channel: "Security" });
    map.insert(4624, CriticalEID { severity: "med", mitre: "T1078", tactic: "Initial Access", event_type: "logon_success", channel: "Security" });
    map.insert(4625, CriticalEID { severity: "low", mitre: "T1110", tactic: "Credential Access", event_type: "logon_failure", channel: "Security" });
    map.insert(4648, CriticalEID { severity: "med", mitre: "T1078", tactic: "Credential Access", event_type: "explicit_credential", channel: "Security" });
    map.insert(4672, CriticalEID { severity: "med", mitre: "T1078.002", tactic: "Privilege Escalation", event_type: "privilege_assigned", channel: "Security" });
    map.insert(4697, CriticalEID { severity: "high", mitre: "T1543.003", tactic: "Persistence", event_type: "service_installed", channel: "Security" });
    map.insert(4698, CriticalEID { severity: "high", mitre: "T1053.005", tactic: "Persistence", event_type: "scheduled_task_created", channel: "Security" });
    map.insert(4720, CriticalEID { severity: "high", mitre: "T1136.001", tactic: "Persistence", event_type: "account_created", channel: "Security" });
    map.insert(4728, CriticalEID { severity: "high", mitre: "T1098", tactic: "Persistence", event_type: "group_member_added", channel: "Security" });
    map.insert(4732, CriticalEID { severity: "high", mitre: "T1098", tactic: "Persistence", event_type: "group_member_added", channel: "Security" });
    map.insert(4756, CriticalEID { severity: "high", mitre: "T1098", tactic: "Persistence", event_type: "group_member_added", channel: "Security" });
    map.insert(4768, CriticalEID { severity: "low", mitre: "T1558.003", tactic: "Credential Access", event_type: "kerberos_tgt", channel: "Security" });
    map.insert(4769, CriticalEID { severity: "low", mitre: "T1558.003", tactic: "Credential Access", event_type: "kerberos_tgs", channel: "Security" });
    map.insert(4776, CriticalEID { severity: "low", mitre: "T1110", tactic: "Credential Access", event_type: "ntlm_auth", channel: "Security" });
    map.insert(7045, CriticalEID { severity: "high", mitre: "T1543.003", tactic: "Persistence", event_type: "service_installed", channel: "System" });
    map
}

/// Does this row's channel match the one the rule is defined for?
///
/// EvtxECmd writes `Channel` as e.g. `Security`, `System`, `DFS Replication`,
/// `Microsoft-Windows-...-Operational`. Compared case-insensitively.
///
/// When the input has no `Channel` column at all we cannot scope, and the
/// caller falls back to EID-only matching rather than dropping every detection
/// on a legacy export — but it says so on stderr, because silently reverting to
/// the buggy behaviour is exactly how this went unnoticed the first time.
fn channel_matches(rule: &CriticalEID, channel: &str) -> bool {
    channel.trim().eq_ignore_ascii_case(rule.channel)
}

pub fn parse_correlated(
    filepath: &Path,
    cfg: &PipelineConfig,
    ta_detector: &TAToolDetector,
    ioc_matcher: &IOCMatcher,
    hostname: &str,
    compromised: &CompromisedEntities,
) -> Result<EventLogOutput> {
    let critical = critical_eids();
    let mut events = Vec::new();
    let mut logons: Vec<SessionLogon> = Vec::new();
    // Every observed group-membership change, emitted or not: a cadence measured
    // only over the rows that survived filtering is not the host's cadence.
    let mut group_changes: Vec<GroupChange> = Vec::new();
    // Every observed real-account logon, so "rare" is a fact about the record
    // rather than about what happened to be in the window.
    let mut logon_counts: HashMap<LogonKey, usize> = HashMap::new();
    let mut emitted_logons: Vec<(usize, LogonKey)> = Vec::new();
    let mut off_hours_logons = 0usize;

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    // This block used to be `col("EventId").unwrap_or(1)` and
    // `col("UserName").unwrap_or(3)`. The current export spells them `event_id`
    // and `user_name`, so the event ID was read out of `timestamp_desc` and the
    // username out of `event_id` — every EID parsed as 0, no critical EID ever
    // matched, no logon was correlated, and 840,821 rows produced 11 events. The
    // resolver has no positional fallback for exactly this reason, and says so on
    // stderr when a required column is missing.
    let cols = Columns::resolve(
        "event-logs",
        filepath,
        &headers,
        &[
            DATETIME,
            EVENT_ID,
            MESSAGE,
            USER_NAME,
            Field::optional("payload", &["Payload"]),
            Field::optional("remote_host", &["RemoteHost"]),
            Field::optional("channel", &["Channel"]),
        ],
    );
    let mut rows = 0usize;
    // Used to scope critical-EID rules to the channel that defines them; see
    // `CriticalEID::channel`. Absent on legacy exports, handled below.
    let has_channel = cols.has("channel");
    if !has_channel {
        eprintln!(
            "[WARN] {}: no 'Channel' column - critical-EID rules cannot be scoped to a \
             channel and will match on EventID alone. Expect false positives such as \
             DFSR/ShellCommon EID 1102 reported as 'Security log cleared'. Re-export \
             with a current EvtxECmd to remove them.",
            filepath.display()
        );
    }

    for result in rdr.records() {
        let Ok(record) = result else { continue };

        rows += 1;

        let ts = cols.get(&record, "datetime").to_string();
        let eid_str = cols.get(&record, "event_id");
        let event_id: u32 = eid_str.parse().unwrap_or(0);
        let msg = cols.get(&record, "message");
        let user = cols.get(&record, "user_name").to_string();
        let payload = cols.get(&record, "payload");
        let remote_host = cols.get(&record, "remote_host").to_string();

        // Resolve the logon channel + remote endpoint once (used for session
        // tracking, lateral detection, and compromised-IP correlation).
        let logon_type: u8 = payload_field(payload, "LogonType")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let (src_ip, src_host) = remote_endpoint(&remote_host, payload);
        // For logon/lateral records the meaningful principal lives in the payload
        // (the `UserName` column is often the machine/subject account).
        let logon_user = payload_field(payload, "TargetUserName")
            .filter(|s| !s.is_empty() && *s != "-")
            .map(str::to_string)
            .unwrap_or_else(|| user.clone());

        let payload_snippet = payload.char_indices().nth(500).map_or(payload, |(i, _)| &payload[..i]);
        let scan_text = format!("{} {} {} {}", msg, payload_snippet, remote_host, src_ip);

        let ta_hits = ta_detector.scan(&scan_text);
        let ioc_hits = ioc_matcher.check(&scan_text);

        let user_compromised = compromised.is_user_compromised(&user);
        // The raw RemoteHost is `Host (IP)`, so match on the extracted src_ip too.
        let ip_compromised = compromised.is_ip_compromised(&remote_host)
            || compromised.is_ip_compromised(&src_ip);
        let channel = cols.get(&record, "channel");
        // A critical EID only counts on the channel that gives it its meaning.
        // Without a Channel column we cannot check, and fall back to EID-only
        // (warned about once, above) rather than losing the detection entirely.
        let is_critical_eid = match critical.get(&event_id) {
            Some(rule) => !has_channel || channel_matches(rule, channel),
            None => false,
        };
        let is_in_window = cfg.in_timewindow(&ts);

        let mut include = false;
        let mut indicators: Vec<String> = Vec::new();
        let mut severity = "low".to_string();
        // The principal shown on the emitted event (overridden for logon/lateral).
        let mut display_user = user.clone();
        let mut classification = String::new();
        // Indices of the records this row produced, so an emitted event can be
        // linked back to them once we know it survived the include gate. Held
        // per row rather than inferred from the tail of the vector: a future
        // early-exit between here and the push would otherwise hand a stale
        // entry to the *next* event.
        let mut pending_group_change: Option<usize> = None;
        let mut pending_logon: Option<usize> = None;

        // The acting principal, needed to tell automation from a person.
        let subject_user = payload_field(payload, "SubjectUserName")
            .filter(|s| !s.is_empty() && *s != "-")
            .map(str::to_string)
            .unwrap_or_else(|| user.clone());
        let subject_sid = payload_field(payload, "SubjectUserSid").unwrap_or("");
        let subject_logon_id = payload_field(payload, "SubjectLogonId").unwrap_or("");
        let by_automation =
            is_automation_principal(&subject_user, subject_sid, subject_logon_id);

        if !ta_hits.is_empty() {
            include = true;
            severity = "high".to_string();
            for hit in &ta_hits {
                indicators.push(format!("TA_TOOL:{}", hit.name));
            }
        }

        if !ioc_hits.is_empty() {
            include = true;
            severity = "high".to_string();
            indicators.extend(ioc_hits);
        }

        if user_compromised && is_in_window {
            include = true;
            indicators.push(format!("COMPROMISED_USER:{}", user));
            if severity_order(&severity) < severity_order("med") {
                severity = "med".to_string();
            }
        }

        if ip_compromised {
            include = true;
            indicators.push(format!("COMPROMISED_IP:{}", remote_host));
            if severity_order(&severity) < severity_order("med") {
                severity = "med".to_string();
            }
        }

        if is_critical_eid && is_in_window {
            let rule_info = &critical[&event_id];
            if severity_order(rule_info.severity) >= severity_order("high") {
                include = true;
                if severity_order(rule_info.severity) > severity_order(&severity) {
                    severity = rule_info.severity.to_string();
                }
            }
        }

        // --- Session logon tracking + lateral movement (runs regardless of the
        // critical-EID gate, so we can correlate precursor logons later). ---

        // Baseline: every successful logon by a real account, counted whether or
        // not it is kept. The count is what makes rarity decidable below.
        if event_id == 4624 && is_baseline_user(&logon_user) {
            let key: LogonKey = (
                strip_principal(&logon_user),
                logon_type,
                if src_ip.is_empty() { src_host.to_lowercase() } else { src_ip.clone() },
            );
            *logon_counts.entry(key.clone()).or_default() += 1;

            if cfg.verbosity.baseline() {
                include = true;
                display_user = logon_user.clone();
                indicators.push("BASELINE_LOGON".to_string());
                indicators.push(format!("LOGON_TYPE:{}", logon_type_name(logon_type)));
                if !src_ip.is_empty() {
                    indicators.push(format!("LOGON_FROM:{}", src_ip));
                }
                if logon_type == 3 && is_external_src(&src_ip) {
                    indicators.push("NETWORK_LOGON".to_string());
                }
                if cfg.is_out_of_hours(&ts) {
                    indicators.push("OFF_HOURS_LOGON".to_string());
                    off_hours_logons += 1;
                    if severity_order(&severity) < severity_order("med") {
                        severity = "med".to_string();
                    }
                }
                // Index is resolved after the push, at the bottom of the loop.
                pending_logon = Some(emitted_logons.len());
                emitted_logons.push((usize::MAX, key));
            }
        }

        // Record meaningful inbound logons: RDP (type 10), and externally-sourced
        // network/SMB logons (type 3). These feed precursor correlation.
        if event_id == 4624 && (logon_type == 10 || (logon_type == 3 && is_external_src(&src_ip))) {
            logons.push(SessionLogon {
                timestamp: ts.clone(),
                logon_type,
                user: logon_user.clone(),
                src_ip: src_ip.clone(),
                src_host: src_host.clone(),
            });
            // Surface RDP logons whenever they're in-window OR tied to the actor
            // (compromised user/IP) — so sessions outside the narrow auto-window
            // still appear.
            let actor_logon = is_in_window
                || ip_compromised
                || compromised.is_user_compromised(&logon_user);
            if logon_type == 10 && actor_logon {
                include = true;
                severity = "high".to_string();
                display_user = logon_user.clone();
                indicators.push("RDP_LOGON".to_string());
                if !src_ip.is_empty() { indicators.push(format!("LOGON_FROM:{}", src_ip)); }
            }
        }

        // RDP session end (logoff) — pairs with the logon above to bound the
        // window the actor was interactively present.
        if (event_id == 4634 || event_id == 4647) && logon_type == 10
            && (is_in_window || compromised.is_user_compromised(&logon_user))
        {
            include = true;
            display_user = logon_user.clone();
            if severity_order(&severity) < severity_order("med") { severity = "med".to_string(); }
            indicators.push("RDP_LOGOFF".to_string());
            if !src_ip.is_empty() { indicators.push(format!("LOGON_FROM:{}", src_ip)); }
        }

        // Outbound lateral movement: explicit-credential logon (4648) aimed at a
        // *remote* server — runas / mapped-drive / outbound RDP from this host.
        // Fires within the window OR when the subject is the compromised actor.
        if event_id == 4648 {
            let subject_user = payload_field(payload, "SubjectUserName")
                .filter(|s| !s.is_empty() && *s != "-")
                .map(str::to_string)
                .unwrap_or_else(|| user.clone());
            if let Some(server) = payload_field(payload, "TargetServerName") {
                if is_remote_target(server, hostname)
                    && (is_in_window || ip_compromised
                        || compromised.is_user_compromised(&subject_user))
                {
                    include = true;
                    severity = "high".to_string();
                    display_user = subject_user;
                    indicators.push(format!("LATERAL_OUTBOUND:{}", server));
                    if logon_user != user && !logon_user.is_empty() {
                        indicators.push(format!("RUNAS_USER:{}", logon_user));
                    }
                }
            }
        }

        // Group-membership changes: recorded for every row, so the cadence pass
        // below sees the whole series and can state it as a rate.
        if matches!(event_id, 4728 | 4732 | 4756) {
            if let Some(when) = crate::timeline_parser::detectors::restoration::parse_ts(&ts) {
                let member = payload_field(payload, "MemberSid")
                    .filter(|s| !s.is_empty() && *s != "-")
                    .or_else(|| payload_field(payload, "MemberName"))
                    .unwrap_or("")
                    .to_string();
                let group = payload_field(payload, "TargetUserName")
                    .filter(|s| !s.is_empty() && *s != "-")
                    .unwrap_or("group")
                    .to_string();
                if !member.is_empty() {
                    pending_group_change = Some(group_changes.len());
                    group_changes.push(GroupChange {
                        event_idx: None,
                        when,
                        subject: subject_user.clone(),
                        member,
                        group,
                        by_machine: by_automation,
                    });
                }
            }
        }

        // A machine account is never a user account. `TA-created User Account:
        // MY-REM03$` was the host itself; a computer object being created or
        // added to a group is domain plumbing, not an attacker-created account.
        if event_id == 4720 && is_machine_account(&logon_user) {
            classification = "automation:machine-account".to_string();
            severity = "low".to_string();
        }

        // Persistence has to mean establishment. `4698` on a task under
        // `\Microsoft\Windows\` changed by SYSTEM is OS servicing, and a rule
        // family that describes a *deletion* cannot support a persistence tag.
        if is_critical_eid && critical[&event_id].tactic == "Persistence" {
            let rule = format!("correlated_eid_{}", event_id);
            let describes_removal =
                !classify::persistence_is_established(critical[&event_id].event_type, &rule, msg);
            let os_task_by_the_os = by_automation && classify::is_os_task_servicing(msg);
            if describes_removal || os_task_by_the_os {
                classification = "os:servicing".to_string();
            }
        }

        if !include {
            continue;
        }

        // Label from the rule only when the row actually satisfied it, channel
        // included. Keying on the bare EventID here would stamp "log_cleared" /
        // T1070.001 onto a DFSR 1102 that was included for some unrelated reason
        // (an IOC hit, say) - the same collision as the detection gate above,
        // showing up as a fabricated technique rather than a fabricated hit.
        let (mut event_type, mut mitre_tactic, mut mitre_technique) = match critical.get(&event_id) {
            Some(rule_info) if is_critical_eid => {
                (rule_info.event_type.to_string(), rule_info.tactic.to_string(), rule_info.mitre.to_string())
            }
            _ => ("event_log".to_string(), String::new(), String::new()),
        };
        // Re-classify the session/lateral events to their true tactic.
        if indicators.iter().any(|i| i.starts_with("LATERAL_OUTBOUND:")) {
            event_type = "lateral_movement_outbound".to_string();
            mitre_tactic = "Lateral Movement".to_string();
            mitre_technique = "T1021".to_string();
        } else if indicators.iter().any(|i| i == "RDP_LOGON") {
            event_type = "rdp_logon".to_string();
            mitre_tactic = "Lateral Movement".to_string();
            mitre_technique = "T1021.001".to_string();
        } else if indicators.iter().any(|i| i == "RDP_LOGOFF") {
            event_type = "rdp_logoff".to_string();
            mitre_tactic = "Lateral Movement".to_string();
            mitre_technique = "T1021.001".to_string();
        }
        // A TA tool named in the message is the only ATT&CK signal an ordinary EID
        // carries, and it was being thrown away. It fills in *behind* the critical-EID
        // table and the session re-classification above, never over them.
        if !ta_hits.is_empty() && (mitre_tactic.is_empty() || mitre_technique.is_empty()) {
            let mut attack = Attack::from_artifact(&mitre_tactic, &mitre_technique);
            for hit in &ta_hits {
                attack.from_tool(hit);
            }
            mitre_tactic = attack.tactic;
            mitre_technique = attack.technique;
        }

        let description = if msg.is_empty() {
            format!("EventID {}", event_id)
        } else {
            build_description(event_id, msg, &indicators)
        };

        if let Some(i) = pending_logon {
            emitted_logons[i].0 = events.len();
        }
        if let Some(i) = pending_group_change {
            group_changes[i].event_idx = Some(events.len());
        }

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "event-logs".to_string(),
            event_type,
            severity,
            description,
            indicators,
            mitre_tactic,
            mitre_technique,
            user: display_user,
            hostname: hostname.to_string(),
            detection_rule: format!("correlated_eid_{}", event_id),
            classification,
            ..Default::default()
        });
    }

    // Rarity is a property of the whole record, so it is decided here rather
    // than row by row. A service account with ten thousand logons is furniture;
    // one with two is the thing worth reading.
    let mut rare_logons = 0usize;
    for (idx, key) in &emitted_logons {
        if *idx == usize::MAX {
            continue;
        }
        let seen = logon_counts.get(key).copied().unwrap_or(0);
        if seen < cfg.rare_logon_max {
            if let Some(e) = events.get_mut(*idx) {
                e.indicators.push(format!("RARE_LOGON:{}", seen));
                if severity_order(&e.severity) < severity_order("med") {
                    e.severity = "med".to_string();
                }
                rare_logons += 1;
            }
        }
    }

    // Machine-account group-membership churn, classified as the automation it is.
    let automations = classify::classify_group_membership(&mut events, &group_changes);

    let baseline_logons = emitted_logons.iter().filter(|(i, _)| *i != usize::MAX).count();
    columns::note_rows("event-logs", rows);
    Ok(EventLogOutput { events, logons, automations, baseline_logons, off_hours_logons, rare_logons })
}

#[cfg(test)]
mod desc_tests {
    use super::*;

    /// The operator's line: "all the successful logons from legitimate users,
    /// not machine accounts". Everything rejected here is the machine talking to
    /// itself, and carrying it would drown the accounts that are people.
    #[test]
    fn only_real_accounts_count_as_baseline_users() {
        for real in [
            "super admin",
            "DOMAIN\\user.name",
            "svc_backup",
            "ldapadmin",
            "msol_b0ae60f928ee",
        ] {
            assert!(is_baseline_user(real), "{real} should count");
        }
        for machine in [
            "MY-DC02$",
            "DOMAIN\\MY-CTX01$",
            "SYSTEM",
            "NT AUTHORITY\\SYSTEM",
            "LOCAL SERVICE",
            "NETWORK SERVICE",
            "ANONYMOUS LOGON",
            "DWM-1",
            "UMFD-0",
            "S-1-5-21-1-2-3-500",
            "-",
            "",
        ] {
            assert!(!is_baseline_user(machine), "{machine} should not count");
        }
    }

    /// The type is stated by name, because "10" is not something a reader can
    /// act on and "RemoteInteractive" is.
    #[test]
    fn logon_types_are_named_not_numbered() {
        assert_eq!(logon_type_name(2), "Interactive");
        assert_eq!(logon_type_name(3), "Network");
        assert_eq!(logon_type_name(5), "Service");
        assert_eq!(logon_type_name(10), "RemoteInteractive");
        assert_eq!(logon_type_name(99), "Other");
    }

    #[test]
    fn short_message_preserved() {
        let d = build_description(7045, "A new service was installed", &[]);
        assert_eq!(d, "EventID 7045: A new service was installed");
    }

    #[test]
    fn long_message_is_not_truncated() {
        // The stored description must keep the entire message verbatim, including a
        // deeply-buried payload field — truncation for display is the report's job.
        let mut msg = "A new service was installed; ".to_string();
        msg.push_str(&"x".repeat(320));
        msg.push_str("ImagePath=ScreenConnect.ClientService.exe");
        let d = build_description(7045, &msg, &["TA_TOOL:screenconnect".to_string()]);
        assert_eq!(d, format!("EventID 7045: {}", msg), "full message must survive");
        assert!(d.to_lowercase().contains("screenconnect"));
        assert!(!d.contains(" … "), "parser must not splice/elide: {d}");
    }
}
