//! Precursor-logon correlation.
//!
//! The triage findings tell you *what* the actor did (mimikatz.bat created, a
//! service installed, a tool executed). This pass answers *how they got there*:
//! for each finding it locates the most recent preceding RDP/SMB logon and, when
//! that session isn't already on the timeline, injects it. The result is a
//! timeline where every malicious action is immediately preceded by the remote
//! logon that established the session.

use std::collections::HashSet;

use crate::timeline_parser::config::severity_order;
use crate::timeline_parser::output::event::UnifiedEvent;
use crate::timeline_parser::parsers::event_logs::SessionLogon;

/// A finding is only linked to a logon that happened within this many hours
/// before it — beyond that the session almost certainly isn't the entry point.
const MAX_LOOKBACK_HOURS: i64 = 48;

/// True when `logon_ts` is at or before `finding_ts` and no more than
/// `MAX_LOOKBACK_HOURS` earlier. Falls back to plain ordering if either
/// timestamp can't be parsed as RFC3339.
fn within_lookback(logon_ts: &str, finding_ts: &str) -> bool {
    use chrono::DateTime;
    match (DateTime::parse_from_rfc3339(logon_ts), DateTime::parse_from_rfc3339(finding_ts)) {
        (Ok(l), Ok(f)) => {
            let delta = f.signed_duration_since(l);
            delta.num_milliseconds() >= 0 && delta.num_hours() <= MAX_LOOKBACK_HOURS
        }
        // Unparseable timestamps: keep the cheap ordering check only.
        _ => logon_ts <= finding_ts,
    }
}

/// Event types that are themselves session/auth records — not "actions" we need
/// to find an entry logon for.
const NON_FINDING_TYPES: &[&str] = &[
    "rdp_logon",
    "rdp_logoff",
    "lateral_movement_outbound",
    "logon_success",
    "logon_failure",
    "explicit_credential",
    "privilege_assigned",
    "network_connection",
    "precursor_logon",
    "kerberos_tgt",
    "kerberos_tgs",
    "ntlm_auth",
];

/// Normalise a username for matching: drop domain prefix, `@realm`, `(SID)` and
/// case. `domain\Super Admin (S-1-5-…)` → `super admin`.
fn clean_user(user: &str) -> String {
    let lower = user.to_lowercase();
    let u = lower.split('(').next().unwrap_or(&lower).trim();
    let u = u.split('@').next().unwrap_or(u);
    let u = u.rsplit('\\').next().unwrap_or(u).trim();
    u.to_string()
}

/// A finding is a medium+ event that represents an action (not an auth record).
fn is_finding(e: &UnifiedEvent) -> bool {
    severity_order(&e.severity) >= severity_order("med")
        && !NON_FINDING_TYPES.contains(&e.event_type.as_str())
}

fn make_precursor_event(l: &SessionLogon, hostname: &str, action_ts: &str) -> UnifiedEvent {
    let technique = match l.logon_type {
        3 => "T1021.002", // SMB / admin shares
        _ => "T1021.001", // RDP
    };
    let endpoint = match (l.src_host.is_empty(), l.src_ip.is_empty()) {
        (false, false) => format!("{} ({})", l.src_host, l.src_ip),
        (true, false) => l.src_ip.clone(),
        (false, true) => l.src_host.clone(),
        (true, true) => "unknown source".to_string(),
    };
    let mut indicators = vec![
        "PRECURSOR_LOGON".to_string(),
        format!("LOGON_TYPE:{}", l.logon_type),
    ];
    if !l.src_ip.is_empty() {
        indicators.push(format!("LOGON_FROM:{}", l.src_ip));
    }
    UnifiedEvent {
        timestamp: l.timestamp.clone(),
        source: "session-correlation".to_string(),
        event_type: "precursor_logon".to_string(),
        severity: "high".to_string(),
        description: format!(
            "Preceding {} logon: {} from {} — established the session used before activity at {}",
            l.kind(),
            if l.user.is_empty() { "(unknown user)" } else { &l.user },
            endpoint,
            action_ts,
        ),
        indicators,
        mitre_tactic: "Lateral Movement".to_string(),
        mitre_technique: technique.to_string(),
        user: l.user.clone(),
        hostname: hostname.to_string(),
        detection_rule: "precursor_logon_correlation".to_string(),
    }
}

/// Inject the precursor logon for each finding. Logons already on the timeline
/// (RDP logons the event-log parser emitted in-window) are not duplicated — this
/// only adds the sessions that would otherwise be missing (out-of-window RDP and
/// network/SMB logons), so each malicious action gains a visible entry point.
pub fn add_precursor_logons(
    events: &mut Vec<UnifiedEvent>,
    logons: &[SessionLogon],
    hostname: &str,
) -> usize {
    if logons.is_empty() {
        return 0;
    }

    let mut sorted: Vec<&SessionLogon> = logons.iter().collect();
    sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Timestamps of logons already represented on the timeline (avoid dupes).
    let existing_logon_ts: HashSet<&str> = events
        .iter()
        .filter(|e| e.event_type == "rdp_logon")
        .map(|e| e.timestamp.as_str())
        .collect();

    // Emit each distinct precursor session at most once.
    let mut emitted: HashSet<(String, String)> = HashSet::new();
    let mut new_events = Vec::new();

    for e in events.iter() {
        if !is_finding(e) {
            continue;
        }
        let target_user = clean_user(&e.user);

        // Pick the most recent meaningful logon before the finding, within the
        // lookback window. When the finding names a user (e.g. a service install
        // by `super admin`), match that user's RDP/SMB session. When it doesn't
        // (e.g. a USN file-create with no owner), only an interactive RDP logon
        // is a defensible entry point — never the constant type-3 background.
        let precursor = sorted.iter().rev().find(|l| {
            if !within_lookback(&l.timestamp, &e.timestamp) {
                return false;
            }
            if !target_user.is_empty() {
                clean_user(&l.user) == target_user
            } else {
                l.logon_type == 10
            }
        });

        if let Some(l) = precursor {
            if existing_logon_ts.contains(l.timestamp.as_str()) {
                continue; // already on the timeline
            }
            let key = (l.timestamp.clone(), l.src_ip.clone());
            if !emitted.insert(key) {
                continue; // this session was already injected for an earlier finding
            }
            new_events.push(make_precursor_event(l, hostname, &e.timestamp));
        }
    }

    let added = new_events.len();
    events.extend(new_events);
    added
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(ts: &str, etype: &str, sev: &str, user: &str) -> UnifiedEvent {
        UnifiedEvent {
            timestamp: ts.into(),
            source: "x".into(),
            event_type: etype.into(),
            severity: sev.into(),
            description: "d".into(),
            indicators: vec![],
            mitre_tactic: String::new(),
            mitre_technique: String::new(),
            user: user.into(),
            hostname: "H".into(),
            detection_rule: String::new(),
        }
    }

    #[test]
    fn injects_last_logon_before_finding() {
        let logons = vec![
            SessionLogon { timestamp: "2026-05-05T08:00:00Z".into(), logon_type: 10, user: "domain\\super admin".into(), src_ip: "192.168.40.3".into(), src_host: "DESKTOP-X".into() },
            SessionLogon { timestamp: "2026-05-05T07:00:00Z".into(), logon_type: 3, user: "someone".into(), src_ip: "10.0.0.9".into(), src_host: String::new() },
        ];
        let mut events = vec![ev("2026-05-05T09:00:00Z", "file_created", "high", "domain\\Super Admin")];
        let added = add_precursor_logons(&mut events, &logons, "H");
        assert_eq!(added, 1);
        let p = events.iter().find(|e| e.event_type == "precursor_logon").unwrap();
        assert_eq!(p.timestamp, "2026-05-05T08:00:00Z"); // the RDP logon, same user
        assert!(p.indicators.iter().any(|i| i == "LOGON_FROM:192.168.40.3"));
    }

    #[test]
    fn does_not_duplicate_existing_rdp_logon() {
        let logons = vec![SessionLogon { timestamp: "2026-05-05T08:00:00Z".into(), logon_type: 10, user: "u".into(), src_ip: "1.2.3.4".into(), src_host: String::new() }];
        let mut events = vec![
            ev("2026-05-05T08:00:00Z", "rdp_logon", "high", "u"),
            ev("2026-05-05T09:00:00Z", "service_installed", "high", "u"),
        ];
        let added = add_precursor_logons(&mut events, &logons, "H");
        assert_eq!(added, 0); // logon already on timeline
    }
}
