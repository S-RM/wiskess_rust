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
    let high_interest: HashSet<&str> = [".exe", ".bat", ".ps1", ".vbs", ".js", ".hta", ".scr", ".com"]
        .into_iter().collect();
    let archive_ext: HashSet<&str> = [".zip", ".rar", ".7z", ".cab", ".tar", ".gz"]
        .into_iter().collect();
    let noise_ext: HashSet<&str> = [".dll", ".tmp", ".log", ".etl", ".mum", ".manifest", ".cat"]
        .into_iter().collect();

    let mut events = Vec::new();

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    let col = |name: &str| headers.iter().position(|h| h == name);
    let ts_idx = col("datetime").unwrap_or(0);
    let name_idx = col("Name").unwrap_or(1);
    let ext_idx = col("Extension");
    let reasons_idx = col("UpdateReasons");
    let parent_idx = col("ParentPath");

    for result in rdr.records() {
        let Ok(record) = result else { continue };

        let ts = record.get(ts_idx).unwrap_or("").to_string();
        if !cfg.in_timewindow(&ts) {
            continue;
        }

        let name = record.get(name_idx).unwrap_or("");
        let extension = ext_idx.and_then(|i| record.get(i)).unwrap_or("").to_lowercase();
        let update_reasons = reasons_idx.and_then(|i| record.get(i)).unwrap_or("");
        let parent_path = parent_idx.and_then(|i| record.get(i)).unwrap_or("");

        let is_create = update_reasons.contains("FileCreate");
        let is_delete = update_reasons.contains("FileDelete")
            || (update_reasons.contains("Close") && update_reasons.contains("Delete"));
        let is_rename = update_reasons.contains("RenameNewName");

        if !is_create && !is_delete && !is_rename {
            continue;
        }

        let full_path = if parent_path.is_empty() {
            name.to_string()
        } else {
            format!("{}\\{}", parent_path, name)
        };

        let ta_hits = ta_detector.scan(name);
        let ioc_hits = ioc_matcher.check(name);
        let path_hits = path_detector.check_path(&full_path);

        let has_detection = !ta_hits.is_empty() || !ioc_hits.is_empty() || !path_hits.is_empty();

        if !has_detection {
            let ext_ref = extension.as_str();
            if noise_ext.contains(ext_ref) {
                continue;
            }
            if high_interest.contains(ext_ref) && (is_create || is_delete) {
                // keep
            } else if archive_ext.contains(ext_ref) && is_create {
                // keep
            } else {
                continue;
            }
        }

        let mut indicators: Vec<String> = Vec::new();
        let mut severity = "low";

        if is_create && high_interest.contains(extension.as_str()) {
            severity = "med";
            indicators.push("USN:executable_created".to_string());
        }
        if is_create && archive_ext.contains(extension.as_str()) {
            indicators.push("USN:archive_created".to_string());
        }
        if is_delete && high_interest.contains(extension.as_str()) {
            severity = "med";
            indicators.push("USN:executable_deleted".to_string());
        }
        if is_rename && high_interest.contains(extension.as_str()) {
            severity = "med";
            indicators.push("USN:executable_renamed".to_string());
        }

        for hit in &path_hits {
            indicators.push(format!("PATH:{}", hit.reason));
            if severity_order(&hit.severity) > severity_order(severity) {
                severity = if &hit.severity == "high" { "high" } else { severity };
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

        if indicators.is_empty() {
            continue;
        }

        let event_type = if is_create { "file_created" }
            else if is_delete { "file_deleted" }
            else { "file_modified" };

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "usnjrnl".to_string(),
            event_type: event_type.to_string(),
            severity: severity.to_string(),
            description: format!("{}: {}", update_reasons, name),
            indicators,
            mitre_tactic: String::new(),
            mitre_technique: String::new(),
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "usnjrnl_suspicious".to_string(),
            ..Default::default()
        });
    }

    Ok(events)
}
