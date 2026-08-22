use anyhow::Result;
use regex::Regex;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::PipelineConfig;
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::output::event::UnifiedEvent;

static PERSISTENCE_PATTERNS: &[&str] = &[
    r"\\CurrentVersion\\Run\b",
    r"\\CurrentVersion\\RunOnce\b",
    r"\\CurrentVersion\\RunServices",
    r"\\Winlogon\\(Shell|Userinit|Notify)",
    r"\\Image File Execution Options\\",
    r"\\Services\\.*\\(ImagePath|ServiceDll)",
    r"\\Explorer\\(ShellIconOverlayIdentifiers|ShellServiceObjects|Browser Helper)",
    r"\\Wow6432Node\\.*\\Run\b",
    r"\\AppInit_DLLs",
    r"\\BootExecute",
    r"\\Session Manager\\KnownDLLs",
];

pub fn parse(
    filepath: &Path,
    cfg: &PipelineConfig,
    ta_detector: &TAToolDetector,
    ioc_matcher: &IOCMatcher,
    hostname: &str,
) -> Result<Vec<UnifiedEvent>> {
    let persistence_re = Regex::new(
        &PERSISTENCE_PATTERNS.iter()
            .map(|p| format!("({})", p))
            .collect::<Vec<_>>()
            .join("|")
    )?;

    let mut events = Vec::new();

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    let col = |name: &str| headers.iter().position(|h| h == name);
    let ts_idx = col("datetime").unwrap_or(0);
    let desc_idx = col("Description").unwrap_or(1);
    let category_idx = col("Category");
    let vname_idx = col("ValueName");
    let vdata_idx = col("ValueData");
    let hive_idx = col("HivePath");

    for result in rdr.records() {
        let Ok(record) = result else { continue };

        let ts = record.get(ts_idx).unwrap_or("").to_string();
        let description_field = record.get(desc_idx).unwrap_or("");
        let category = category_idx.and_then(|i| record.get(i)).unwrap_or("");
        let value_name = vname_idx.and_then(|i| record.get(i)).unwrap_or("");
        let value_data = vdata_idx.and_then(|i| record.get(i)).unwrap_or("");
        let hive_path = hive_idx.and_then(|i| record.get(i)).unwrap_or("");

        let scan_text = format!("{} {} {} {}", description_field, value_name, value_data, hive_path);

        let is_persistence = persistence_re.is_match(&scan_text);
        let ta_hits = ta_detector.scan(&scan_text);
        let ioc_hits = ioc_matcher.check(&scan_text);

        if !is_persistence && ta_hits.is_empty() && ioc_hits.is_empty() {
            continue;
        }

        let mut indicators: Vec<String> = Vec::new();
        let mut severity = "med".to_string();

        if is_persistence {
            indicators.push("REG:persistence_key".to_string());
            if cfg.in_timewindow(&ts) {
                severity = "high".to_string();
            }
        }
        for hit in &ta_hits {
            indicators.push(format!("TA_TOOL:{}", hit.name));
            severity = "high".to_string();
        }
        indicators.extend(ioc_hits.clone());
        if !ioc_hits.is_empty() {
            severity = "high".to_string();
        }

        let vdata_trunc = value_data.char_indices().nth(100).map_or(value_data, |(i, _)| &value_data[..i]);
        let description = format!("{}: {} = {}", category, value_name, vdata_trunc);

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "registry".to_string(),
            event_type: if is_persistence { "registry_persistence" } else { "registry_suspicious" }.to_string(),
            severity,
            description,
            indicators,
            mitre_tactic: if is_persistence { "Persistence".to_string() } else { String::new() },
            mitre_technique: if is_persistence { "T1547.001".to_string() } else { String::new() },
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "registry_persistence_check".to_string(),
        });
    }

    Ok(events)
}
