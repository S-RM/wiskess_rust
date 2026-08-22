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
    let desc_idx = col("description").unwrap_or(1);
    let source_idx = col("source");
    let user_idx = col("user");

    for result in rdr.records() {
        let Ok(record) = result else { continue };

        let ts = record.get(ts_idx).unwrap_or("").to_string();
        let description = record.get(desc_idx).unwrap_or("");
        let source = source_idx.and_then(|i| record.get(i)).unwrap_or("");
        let user = user_idx.and_then(|i| record.get(i)).unwrap_or("").to_string();

        let scan_text = format!("{} {}", description, source);
        let ta_hits = ta_detector.scan(&scan_text);
        let ioc_hits = ioc_matcher.check(&scan_text);
        let path_hits = path_detector.check_path(description);

        if ta_hits.is_empty() && ioc_hits.is_empty() && path_hits.is_empty() {
            continue;
        }

        let mut indicators: Vec<String> = Vec::new();
        let mut severity = "low";

        for hit in &ta_hits {
            indicators.push(format!("TA_TOOL:{}", hit.name));
            severity = "high";
        }
        for hit in &path_hits {
            indicators.push(format!("PATH:{}", hit.reason));
            if severity_order(&hit.severity) > severity_order(severity) {
                severity = if hit.severity == "high" { "high" } else { "med" };
            }
        }
        indicators.extend(ioc_hits.clone());
        if !ioc_hits.is_empty() {
            severity = "high";
        }

        let desc_trunc = description.char_indices().nth(200).map_or(description, |(i, _)| &description[..i]);

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "regripper".to_string(),
            event_type: "registry_artifact".to_string(),
            severity: severity.to_string(),
            description: format!("RegRipper: {}", desc_trunc),
            indicators,
            mitre_tactic: String::new(),
            mitre_technique: String::new(),
            user,
            hostname: hostname.to_string(),
            detection_rule: "regripper_finding".to_string(),
        });
    }

    Ok(events)
}
