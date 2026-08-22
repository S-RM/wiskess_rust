use anyhow::Result;
use std::collections::HashSet;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::{severity_order, PipelineConfig};
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::suspicious_paths::SuspiciousPathDetector;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::output::event::UnifiedEvent;

pub fn parse(
    filepath: &Path,
    cfg: &PipelineConfig,
    ta_detector: &TAToolDetector,
    ioc_matcher: &IOCMatcher,
    path_detector: &SuspiciousPathDetector,
    hostname: &str,
) -> Result<Vec<UnifiedEvent>> {
    let high_interest: HashSet<&str> = [".exe", ".bat", ".ps1", ".vbs", ".js", ".hta", ".scr", ".com", ".msi"]
        .into_iter().collect();
    let archive_ext: HashSet<&str> = [".zip", ".rar", ".7z", ".cab"]
        .into_iter().collect();

    let mut events = Vec::new();

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    let col = |name: &str| headers.iter().position(|h| h == name);
    let ts_idx = col("datetime").unwrap_or(0);
    let ts_desc_idx = col("timestamp_desc");
    let parent_idx = col("ParentPath");
    let filename_idx = col("FileName");
    let ext_idx = col("Extension");

    for result in rdr.records() {
        let Ok(record) = result else { continue };

        let ts = record.get(ts_idx).unwrap_or("").to_string();
        if !cfg.in_timewindow(&ts) {
            continue;
        }

        let ts_desc = ts_desc_idx.and_then(|i| record.get(i)).unwrap_or("");
        if !ts_desc.contains("Created0x10") {
            continue;
        }

        let parent_path = parent_idx.and_then(|i| record.get(i)).unwrap_or("");
        let filename = filename_idx.and_then(|i| record.get(i)).unwrap_or("");
        let extension = ext_idx.and_then(|i| record.get(i)).unwrap_or("").to_lowercase();

        let full_path = if parent_path.is_empty() {
            filename.to_string()
        } else {
            format!("{}\\{}", parent_path, filename)
        };

        let ta_hits = ta_detector.scan(&full_path);
        let ioc_hits = ioc_matcher.check(&full_path);
        let path_hits = path_detector.check_path(&full_path);

        let has_detection = !ta_hits.is_empty() || !ioc_hits.is_empty() || !path_hits.is_empty();

        if !has_detection {
            let ext_ref = extension.as_str();
            if !high_interest.contains(ext_ref) && !archive_ext.contains(ext_ref) {
                continue;
            }
        }

        let mut indicators: Vec<String> = Vec::new();
        let mut severity = if high_interest.contains(extension.as_str()) { "med" } else { "low" };

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

        if high_interest.contains(extension.as_str()) {
            indicators.push("MFT:executable_created".to_string());
        } else if archive_ext.contains(extension.as_str()) {
            indicators.push("MFT:archive_created".to_string());
        }

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "mft".to_string(),
            event_type: "file_created".to_string(),
            severity: severity.to_string(),
            description: format!("File created: {}", full_path),
            indicators,
            mitre_tactic: String::new(),
            mitre_technique: String::new(),
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "mft_suspicious_file".to_string(),
        });
    }

    Ok(events)
}
