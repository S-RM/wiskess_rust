use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::io::BufReader;
use std::path::Path;
use std::sync::LazyLock;

use crate::timeline_parser::config::{severity_order, PipelineConfig};
use crate::timeline_parser::detectors::compromised::CompromisedEntities;
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::output::event::UnifiedEvent;

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
    map.insert(4732, CriticalEID { severity: "high", mitre: "T1098", tactic: "Persistence", event_type: "group_member_added", channel: "Security" });
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
) -> Result<(Vec<UnifiedEvent>, Vec<SessionLogon>)> {
    let critical = critical_eids();
    let mut events = Vec::new();
    let mut logons: Vec<SessionLogon> = Vec::new();

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    let col = |name: &str| headers.iter().position(|h| h == name);
    let ts_idx = col("datetime").unwrap_or(0);
    let eid_idx = col("EventId").or_else(|| col("EventID")).unwrap_or(1);
    let msg_idx = col("message").unwrap_or(2);
    let user_idx = col("UserName").unwrap_or(3);
    let payload_idx = col("Payload");
    let remote_idx = col("RemoteHost");
    // Used to scope critical-EID rules to the channel that defines them; see
    // `CriticalEID::channel`. Absent on legacy exports, handled below.
    let channel_idx = col("Channel");
    if channel_idx.is_none() {
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

        let ts = record.get(ts_idx).unwrap_or("").to_string();
        let eid_str = record.get(eid_idx).unwrap_or("");
        let event_id: u32 = eid_str.parse().unwrap_or(0);
        let msg = record.get(msg_idx).unwrap_or("");
        let user = record.get(user_idx).unwrap_or("").to_string();
        let payload = payload_idx.and_then(|i| record.get(i)).unwrap_or("");
        let remote_host = remote_idx.and_then(|i| record.get(i)).unwrap_or("").to_string();

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
        let channel = channel_idx.and_then(|i| record.get(i)).unwrap_or("");
        // A critical EID only counts on the channel that gives it its meaning.
        // Without a Channel column we cannot check, and fall back to EID-only
        // (warned about once, above) rather than losing the detection entirely.
        let is_critical_eid = match critical.get(&event_id) {
            Some(rule) => channel_idx.is_none() || channel_matches(rule, channel),
            None => false,
        };
        let is_in_window = cfg.in_timewindow(&ts);

        let mut include = false;
        let mut indicators: Vec<String> = Vec::new();
        let mut severity = "low".to_string();
        // The principal shown on the emitted event (overridden for logon/lateral).
        let mut display_user = user.clone();

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

        let description = if msg.is_empty() {
            format!("EventID {}", event_id)
        } else {
            build_description(event_id, msg, &indicators)
        };

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
        });
    }

    Ok((events, logons))
}

#[cfg(test)]
mod desc_tests {
    use super::*;

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
