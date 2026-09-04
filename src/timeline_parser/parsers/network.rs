use anyhow::Result;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::{severity_order, PipelineConfig};
use crate::timeline_parser::detectors::compromised::CompromisedEntities;
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::output::event::UnifiedEvent;

/// Pull the common name out of an LDAP distinguished name.
///
/// `network.csv` is SumECmd's parse of the **User Access Logging** database, and
/// its `AuthenticatedUserName` arrives in three shapes: a plain account
/// (`super admin`), a machine account (`domain\wks-0002$`), and — for AD DS
/// role access — a full DN, `cn=jane doe,ou=users,ou=site,ou=domain,
/// dc=domain,dc=local`.
///
/// The DN form was being carried through verbatim, and the report's per-user
/// table rejects anything containing `=` as a raw DN. The effect was that every
/// UAL access by a named human vanished from Account Activity — the one table
/// where "who reached this DC" belongs. The name is right there in the first
/// RDN; this takes it.
fn normalise_ual_user(raw: &str) -> String {
    let t = raw.trim();
    if !t.contains('=') {
        return t.to_string();
    }
    for rdn in t.split(',') {
        let rdn = rdn.trim();
        if let Some((attr, value)) = rdn.split_once('=') {
            if attr.trim().eq_ignore_ascii_case("cn") && !value.trim().is_empty() {
                return value.trim().to_string();
            }
        }
    }
    t.to_string()
}

pub fn parse(
    filepath: &Path,
    cfg: &PipelineConfig,
    ioc_matcher: &IOCMatcher,
    hostname: &str,
    compromised: &CompromisedEntities,
) -> Result<Vec<UnifiedEvent>> {
    let mut events = Vec::new();

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    let col = |name: &str| headers.iter().position(|h| h == name);
    let ts_idx = col("datetime").unwrap_or(0);
    let ip_idx = col("IpAddress").unwrap_or(1);
    let user_idx = col("AuthenticatedUserName").unwrap_or(2);
    let access_idx = col("TotalAccesses");
    let role_idx = col("RoleDescription");

    for result in rdr.records() {
        let Ok(record) = result else { continue };

        let ts = record.get(ts_idx).unwrap_or("").to_string();
        let ip = record.get(ip_idx).unwrap_or("").to_string();
        let user = normalise_ual_user(record.get(user_idx).unwrap_or(""));
        let total_accesses: u32 = access_idx
            .and_then(|i| record.get(i))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let role = role_idx.and_then(|i| record.get(i)).unwrap_or("").to_string();

        let is_in_window = cfg.in_timewindow(&ts);
        let scan_text = format!("{} {}", ip, user);
        let ioc_hits = ioc_matcher.check(&scan_text);

        let user_compromised = compromised.is_user_compromised(&user);
        let ip_compromised = compromised.is_ip_compromised(&ip);

        let mut include = false;
        let mut indicators: Vec<String> = ioc_hits;
        let mut severity = "low".to_string();

        if !indicators.is_empty() {
            include = true;
            severity = "high".to_string();
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
            indicators.push(format!("COMPROMISED_IP:{}", ip));
            if severity_order(&severity) < severity_order("med") {
                severity = "med".to_string();
            }
        }

        // Low-volume User Access Logging rows: a peer that reached this server
        // twice is more interesting than one that reached it ten thousand times.
        //
        // The curated default keeps this narrow — `TotalAccesses <= 5`, in-window
        // only. A verbose run takes everything **below** `--rare-logon-max`
        // (the operator's "less than ten") and drops the window requirement,
        // because the point of a baseline is to show what the server's ordinary
        // access pattern looked like on either side of the incident.
        let low_access = if cfg.verbosity.baseline() {
            total_accesses < cfg.rare_logon_max as u32
        } else {
            is_in_window && total_accesses <= 5
        };
        if low_access {
            include = true;
            indicators.push(format!("NET:low_access_count_{}", total_accesses));
            if is_in_window && total_accesses <= 2
                && severity_order(&severity) < severity_order("med")
            {
                severity = "med".to_string();
            }
        }

        if !include {
            continue;
        }

        let description = format!("{} | User: {} | IP: {} | Accesses: {}", role, user, ip, total_accesses);

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "network".to_string(),
            event_type: "network_connection".to_string(),
            severity,
            description,
            indicators,
            mitre_tactic: String::new(),
            mitre_technique: String::new(),
            user,
            hostname: hostname.to_string(),
            detection_rule: "network_correlated".to_string(),
            ..Default::default()
        });
    }

    Ok(events)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline_parser::config::{TimeWindow, Verbosity};
    use std::io::Write;

    /// A slice of the SumECmd DETAIL_Clients shape, including the LDAP-DN and
    /// machine-account user forms the real file carries.
    fn csv(dir: &tempfile::TempDir, rows: &[(&str, &str, &str, &str)]) -> std::path::PathBuf {
        let p = dir.path().join("network.csv");
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "datetime,RoleDescription,TotalAccesses,AuthenticatedUserName,IpAddress").unwrap();
        for (ts, role, accesses, user) in rows {
            writeln!(f, "{ts},{role},{accesses},\"{user}\",172.16.0.254").unwrap();
        }
        p
    }

    fn parse_rows(rows: &[(&str, &str, &str, &str)], verbosity: Verbosity) -> Vec<UnifiedEvent> {
        let dir = tempfile::tempdir().unwrap();
        let path = csv(&dir, rows);
        let cfg = PipelineConfig {
            verbosity,
            window: Some(TimeWindow {
                start: "2026-05-05T00:00:00Z".into(),
                end: "2026-05-07T00:00:00Z".into(),
                event_count: 0,
                confidence: "user-specified".into(),
            }),
            ..Default::default()
        };
        parse(
            &path,
            &cfg,
            &IOCMatcher::new(None).unwrap(),
            "MY-DC02",
            &CompromisedEntities::new(),
        )
        .unwrap()
    }

    /// "Less than ten" is strict: nine is low-volume, ten is not.
    #[test]
    fn the_verbose_access_threshold_is_strictly_below_the_limit() {
        let rows = [
            ("2026-02-02T09:45:40.000Z", "Active Directory Domain Services", "9", "alice"),
            ("2026-02-02T09:45:41.000Z", "Active Directory Domain Services", "10", "bob"),
            ("2026-02-02T09:45:42.000Z", "File Server", "4883", "msol_b0ae60f928ee"),
        ];
        let events = parse_rows(&rows, Verbosity::Baseline);
        let users: Vec<&str> = events.iter().map(|e| e.user.as_str()).collect();
        assert_eq!(users, vec!["alice"], "only the sub-threshold row is low-volume");
        assert!(events[0].indicators.iter().any(|i| i == "NET:low_access_count_9"));
    }

    /// The baseline exists to show behaviour on either side of the incident, so
    /// verbose drops the window gate. The curated default keeps it.
    #[test]
    fn verbose_keeps_out_of_window_rows_and_the_default_does_not() {
        let rows = [("2026-02-02T09:45:40.000Z", "File Server", "3", "alice")];
        assert_eq!(parse_rows(&rows, Verbosity::Baseline).len(), 1);
        assert_eq!(parse_rows(&rows, Verbosity::Curated).len(), 0, "out of window, curated cut");

        let in_window = [("2026-05-05T10:00:00Z", "File Server", "3", "alice")];
        assert_eq!(parse_rows(&in_window, Verbosity::Curated).len(), 1);
    }

    /// An out-of-window baseline row is background, not a finding: it must not
    /// acquire the severity that would carry it into the triage timeline.
    #[test]
    fn an_out_of_window_baseline_row_stays_low_severity() {
        let rows = [("2026-02-02T09:45:40.000Z", "File Server", "1", "alice")];
        let events = parse_rows(&rows, Verbosity::Baseline);
        assert_eq!(events[0].severity, "low");

        let in_window = [("2026-05-05T10:00:00Z", "File Server", "1", "alice")];
        assert_eq!(parse_rows(&in_window, Verbosity::Baseline)[0].severity, "med",
            "a near-zero access count inside the window is worth a look");
    }

    /// The regression: every UAL access by a named human was vanishing from the
    /// report's Account Activity table, because a raw DN is rejected there.
    #[test]
    fn an_ldap_distinguished_name_resolves_to_the_person_it_names() {
        assert_eq!(
            normalise_ual_user("cn=jane doe,ou=users,ou=site,ou=domain,dc=domain,dc=local"),
            "jane doe"
        );
        assert_eq!(normalise_ual_user("CN=Jane Doe,OU=Staff,DC=corp"), "Jane Doe");
        // Everything that is not a DN is left exactly as it was.
        assert_eq!(normalise_ual_user("super admin"), "super admin");
        assert_eq!(normalise_ual_user(r"domain\wks-0002$"), r"domain\wks-0002$");
        assert_eq!(normalise_ual_user(""), "");
        // A DN with no CN is not invented into one.
        assert_eq!(normalise_ual_user("ou=users,dc=domain"), "ou=users,dc=domain");
    }

    #[test]
    fn the_resolved_name_reaches_the_event() {
        let rows = [(
            "2026-05-05T10:00:00Z",
            "Active Directory Domain Services",
            "4",
            "cn=jane doe,ou=users,dc=domain,dc=local",
        )];
        let events = parse_rows(&rows, Verbosity::Curated);
        assert_eq!(events[0].user, "jane doe");
        assert!(events[0].description.contains("jane doe"));
    }
}
