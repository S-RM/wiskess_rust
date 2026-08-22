use anyhow::Result;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::severity_order;
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::suspicious_paths::SuspiciousPathDetector;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::output::event::UnifiedEvent;

pub fn parse(
    filepath: &Path,
    ta_detector: &TAToolDetector,
    ioc_matcher: &IOCMatcher,
    path_detector: &SuspiciousPathDetector,
    hostname: &str,
) -> Result<Vec<UnifiedEvent>> {
    let mut events = Vec::new();

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    let col = |name: &str| headers.iter().position(|h| h == name);
    let ts_idx = col("datetime").unwrap_or(0);
    let path_idx = col("Path").unwrap_or(1);
    let exec_idx = col("Executed");

    for result in rdr.records() {
        let Ok(record) = result else { continue };

        let ts = record.get(ts_idx).unwrap_or("").to_string();
        let path = record.get(path_idx).unwrap_or("").to_string();
        let executed = exec_idx.and_then(|i| record.get(i)).unwrap_or("");

        let path_hits = path_detector.check_path(&path);
        let ta_hits = ta_detector.scan(&path);
        let ioc_hits = ioc_matcher.check(&path);

        if path_hits.is_empty() && ta_hits.is_empty() && ioc_hits.is_empty() {
            continue;
        }

        let mut indicators: Vec<String> = Vec::new();
        let mut severity = "med";

        for hit in &path_hits {
            indicators.push(format!("PATH:{}", hit.reason));
            if severity_order(&hit.severity) > severity_order(severity) {
                severity = if hit.severity == "high" { "high" } else { severity };
            }
        }
        for hit in &ta_hits {
            indicators.push(format!("TA_TOOL:{}", hit.name));
            severity = "high";
        }
        indicators.extend(ioc_hits.clone());
        if !ioc_hits.is_empty() {
            severity = "high";
        }

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "appcompatcache".to_string(),
            event_type: "process_execution".to_string(),
            severity: severity.to_string(),
            description: format!("AppCompatCache: {} | Executed: {}", path, executed),
            indicators,
            mitre_tactic: "Execution".to_string(),
            mitre_technique: String::new(),
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "appcompat_suspicious_path".to_string(),
        });
    }

    Ok(events)
}
