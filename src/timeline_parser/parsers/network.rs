use anyhow::Result;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::{severity_order, PipelineConfig};
use crate::timeline_parser::detectors::compromised::CompromisedEntities;
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::output::event::UnifiedEvent;

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
        let user = record.get(user_idx).unwrap_or("").to_string();
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

        if is_in_window && total_accesses <= 5 {
            include = true;
            indicators.push(format!("NET:low_access_count_{}", total_accesses));
            if total_accesses <= 2 && severity_order(&severity) < severity_order("med") {
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
        });
    }

    Ok(events)
}
