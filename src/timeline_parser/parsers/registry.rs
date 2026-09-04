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
        let mut classification = String::new();

        // Establishment, not inventory.
        //
        // Every Windows host ships with Run keys, services and autoruns; a rule
        // that fires on their existence produces an inventory of the machine's
        // own furniture and calls it Persistence. Across one 28-host run that was
        // 25,952 "Persistence findings" on 27 of 28 hosts — a number that says
        // nothing about any of them.
        //
        // The key's LastWriteTime is the discriminator the artefact already
        // carries: written inside the window of interest, the entry was
        // *established* there and the tactic is earned. Outside it, the entry
        // predates the window and is inventory. It is still reported — a Run key
        // pointing at something odd is worth reading whenever it was written —
        // but it does not get a Persistence tag.
        let established = cfg.in_timewindow(&ts);
        if is_persistence {
            indicators.push("REG:persistence_key".to_string());
            if established {
                severity = "high".to_string();
            } else {
                classification = "inventory:autorun-entry".to_string();
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
            mitre_tactic: if is_persistence && established { "Persistence".to_string() } else { String::new() },
            mitre_technique: if is_persistence && established { "T1547.001".to_string() } else { String::new() },
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "registry_persistence_check".to_string(),
            classification,
            ..Default::default()
        });
    }

    Ok(events)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline_parser::config::TimeWindow;
    use std::io::Write;

    fn csv(dir: &tempfile::TempDir, rows: &[(&str, &str, &str)]) -> std::path::PathBuf {
        let p = dir.path().join("registry.csv");
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "datetime,Description,Category,ValueName,ValueData,HivePath").unwrap();
        for (ts, name, data) in rows {
            writeln!(
                f,
                r"{ts},Registry Key,Autorun,{name},{data},C:\Windows\System32\config\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            )
            .unwrap();
        }
        p
    }

    fn parse_rows(rows: &[(&str, &str, &str)], window: Option<TimeWindow>) -> Vec<UnifiedEvent> {
        let dir = tempfile::tempdir().unwrap();
        let path = csv(&dir, rows);
        let cfg = PipelineConfig { window, ..Default::default() };
        let data = std::path::Path::new("/nonexistent");
        parse(
            &path,
            &cfg,
            &TAToolDetector::new(data).unwrap(),
            &IOCMatcher::new(None).unwrap(),
            "H",
        )
        .unwrap()
    }

    /// The 25,952-findings case: a Run key that has been there since the OS was
    /// installed is the host's furniture, not an intrusion. It is still
    /// reported — but not as Persistence.
    #[test]
    fn a_pre_existing_autorun_entry_is_inventory_not_persistence() {
        let events = parse_rows(
            &[("2019-06-07T23:40:00Z", "OneDriveSetup", r"C:\Windows\SysWOW64\OneDriveSetup.exe")],
            Some(TimeWindow {
                start: "2026-05-05T00:00:00Z".into(),
                end: "2026-05-07T00:00:00Z".into(),
                event_count: 0,
                confidence: "user-specified".into(),
            }),
        );
        assert_eq!(events.len(), 1, "the entry must still be reported");
        assert_eq!(events[0].mitre_tactic, "", "no Persistence tag on an inventory entry");
        assert_eq!(events[0].classification, "inventory:autorun-entry");
        assert!(events[0].indicators.iter().any(|i| i == "REG:persistence_key"));
    }

    /// ...and a key written inside the window was established there, which is
    /// what a persistence tag is supposed to mean.
    #[test]
    fn an_autorun_entry_written_in_the_window_earns_the_persistence_tag() {
        let events = parse_rows(
            &[("2026-05-05T10:00:00Z", "Remotely_Agent", r"C:\ProgramData\Remotely\Remotely_Agent.exe")],
            Some(TimeWindow {
                start: "2026-05-05T00:00:00Z".into(),
                end: "2026-05-07T00:00:00Z".into(),
                event_count: 0,
                confidence: "user-specified".into(),
            }),
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].mitre_tactic, "Persistence");
        assert_eq!(events[0].severity, "high");
        assert_eq!(events[0].classification, "");
    }
}
