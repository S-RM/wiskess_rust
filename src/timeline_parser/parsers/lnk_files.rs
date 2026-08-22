use anyhow::Result;
use std::io::BufReader;
use std::path::Path;

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
    let path_idx = col("LocalPath").unwrap_or(1);
    let net_idx = col("NetworkPath");
    let args_idx = col("Arguments");
    let machine_idx = col("MachineID");

    for result in rdr.records() {
        let Ok(record) = result else { continue };

        let ts = record.get(ts_idx).unwrap_or("").to_string();
        let local_path = record.get(path_idx).unwrap_or("");
        let network_path = net_idx.and_then(|i| record.get(i)).unwrap_or("");
        let arguments = args_idx.and_then(|i| record.get(i)).unwrap_or("");
        let machine_id = machine_idx.and_then(|i| record.get(i)).unwrap_or("");

        let scan_text = format!("{} {} {} {}", local_path, network_path, arguments, machine_id);
        let ta_hits = ta_detector.scan(&scan_text);
        let ioc_hits = ioc_matcher.check(&scan_text);
        let path_hits = path_detector.check_path(local_path);

        if ta_hits.is_empty() && ioc_hits.is_empty() && path_hits.is_empty() {
            continue;
        }

        let mut indicators: Vec<String> = Vec::new();
        let mut severity = "med".to_string();

        for hit in &ta_hits {
            indicators.push(format!("TA_TOOL:{}", hit.name));
            severity = "high".to_string();
        }
        for hit in &path_hits {
            indicators.push(format!("PATH:{}", hit.reason));
        }
        indicators.extend(ioc_hits.clone());
        if !ioc_hits.is_empty() {
            severity = "high".to_string();
        }

        let desc_path = if local_path.is_empty() { network_path } else { local_path };
        let args_trunc = arguments.char_indices().nth(100).map_or(arguments, |(i, _)| &arguments[..i]);

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "lnk-files".to_string(),
            event_type: "user_activity".to_string(),
            severity,
            description: format!("LNK: {} | Args: {}", desc_path, args_trunc),
            indicators,
            mitre_tactic: String::new(),
            mitre_technique: String::new(),
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "lnk_suspicious".to_string(),
        });
    }

    Ok(events)
}
