//! Registry (RECmd) — key writes, and the autorun entries among them.
//!
//! 15,087 rows in the collection that prompted this work, **10 events**: the
//! parser kept only rows a persistence pattern, a TA-tool name or an IOC matched.
//! A registry write is a statement about the host's configuration at a moment in
//! time, and the rest of them are exactly the context an investigation needs to
//! read the ten. Unflagged rows are now carried at an `info` floor
//! (`REG:record`), which the `config:product-settings` classifier then absorbs
//! most of, so the curated cut does not widen.
//!
//! The establishment-window logic below is deliberately unchanged — it is what
//! stops the parser reporting the machine's own furniture as Persistence.

use anyhow::Result;
use regex::Regex;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::{raise, PipelineConfig};
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::detectors::Attack;
use crate::timeline_parser::output::event::UnifiedEvent;
use crate::timeline_parser::parsers::columns::{self, Columns, Field, DATETIME, MESSAGE};

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

/// RECmd's own label for the batch item that produced the row. Required: it is the
/// row's subject, and without it neither the description nor the persistence match
/// has anything to work with.
const DESCRIPTION: Field = Field::required("description", &["Description"]);
const CATEGORY: Field = Field::optional("category", &["Category"]);
const VALUE_NAME: Field = Field::optional("value_name", &["ValueName"]);
const VALUE_DATA: Field = Field::optional("value_data", &["ValueData"]);
const HIVE_PATH: Field = Field::optional("hive_path", &["HivePath"]);
/// Some RECmd batches emit the key path separately from the hive file. When it is
/// there it is the best subject for the persistence patterns, so it is scanned too.
const KEY_PATH: Field = Field::optional("key_path", &["KeyPath"]);

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
    let mut rows = 0usize;

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    let cols = Columns::resolve(
        "registry",
        filepath,
        &headers,
        &[DATETIME, MESSAGE, DESCRIPTION, CATEGORY, VALUE_NAME, VALUE_DATA, HIVE_PATH, KEY_PATH],
    );

    for result in rdr.records() {
        let Ok(record) = result else { continue };
        rows += 1;

        let ts = cols.get(&record, "datetime").to_string();
        if ts.is_empty() {
            continue;
        }
        let description_field = cols.get(&record, "description");
        let category = cols.get(&record, "category");
        let value_name = cols.get(&record, "value_name");
        let value_data = cols.get(&record, "value_data");
        let hive_path = cols.get(&record, "hive_path");
        let key_path = cols.get(&record, "key_path");

        let scan_text = format!(
            "{} {} {} {} {}",
            description_field, value_name, value_data, key_path, hive_path
        );

        let is_persistence = persistence_re.is_match(&scan_text);
        let ta_hits = ta_detector.scan(&scan_text);
        let ioc_hits = ioc_matcher.check(&scan_text);
        let has_detection = is_persistence || !ta_hits.is_empty() || !ioc_hits.is_empty();

        if !has_detection && !cfg.emit_quiet_baseline {
            continue;
        }

        let mut indicators: Vec<String> = Vec::new();
        let mut severity = if has_detection { "med".to_string() } else { "info".to_string() };
        let mut classification = String::new();

        if !has_detection {
            indicators.push("REG:record".to_string());
        }

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
                raise(&mut severity, "high");
            } else {
                classification = "inventory:autorun-entry".to_string();
            }
        }
        // An established autorun key is Persistence on the strength of the key
        // alone; anything else takes its tactic from whichever tool fired.
        let mut attack = if is_persistence && established {
            Attack::from_artifact("Persistence", "T1547.001")
        } else {
            Attack::default()
        };
        for hit in &ta_hits {
            indicators.push(format!("TA_TOOL:{}", hit.name));
            raise(&mut severity, "high");
            attack.from_tool(hit);
        }
        indicators.extend(ioc_hits.clone());
        if !ioc_hits.is_empty() {
            raise(&mut severity, "high");
        }

        let vdata_trunc = value_data.char_indices().nth(100).map_or(value_data, |(i, _)| &value_data[..i]);
        let mut description = format!("{}: {} = {}", category, value_name, vdata_trunc);
        // A row that names neither a category nor a value has nothing in that
        // shape; the timeliner's own sentence is better than `: = `.
        if category.is_empty() && value_name.is_empty() && vdata_trunc.is_empty() {
            let message = cols.get(&record, "message");
            description = if message.is_empty() {
                format!("{}: {}", description_field, hive_path)
            } else {
                message.to_string()
            };
        }

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "registry".to_string(),
            event_type: if is_persistence {
                "registry_persistence"
            } else if has_detection {
                "registry_suspicious"
            } else {
                "registry_record"
            }
            .to_string(),
            severity,
            description,
            indicators,
            mitre_tactic: attack.tactic,
            mitre_technique: attack.technique,
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "registry_persistence_check".to_string(),
            classification,
            ..Default::default()
        });
    }

    columns::note_rows("registry", rows);
    Ok(events)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline_parser::config::TimeWindow;
    use crate::timeline_parser::output::supertimeline::is_triage_hit;
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

    fn window() -> Option<TimeWindow> {
        Some(TimeWindow::new(
            "2026-05-05T00:00:00Z",
            "2026-05-07T00:00:00Z",
            0,
            "user-specified",
        ))
    }

    /// The 25,952-findings case: a Run key that has been there since the OS was
    /// installed is the host's furniture, not an intrusion. It is still
    /// reported — but not as Persistence.
    #[test]
    fn a_pre_existing_autorun_entry_is_inventory_not_persistence() {
        let events = parse_rows(
            &[("2019-06-07T23:40:00Z", "OneDriveSetup", r"C:\Windows\SysWOW64\OneDriveSetup.exe")],
            window(),
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
            window(),
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].mitre_tactic, "Persistence");
        assert_eq!(events[0].severity, "high");
        assert_eq!(events[0].classification, "");
    }

    /// The 10-from-15,087 case: an ordinary settings write is background, not
    /// absence — and background must not reach the curated cut.
    #[test]
    fn an_ordinary_key_write_is_carried_as_background() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("registry.csv");
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "datetime,timestamp_desc,message,Description,Category,ValueName,ValueData,HivePath").unwrap();
        writeln!(
            f,
            r"2026-05-05T10:00:00Z,d,m,Registry Key,TimeZone,Bias,0,C:\Windows\System32\config\SYSTEM"
        )
        .unwrap();
        drop(f);
        let events = parse(
            &p,
            &PipelineConfig { window: window(), ..Default::default() },
            &TAToolDetector::new(std::path::Path::new("/nonexistent")).unwrap(),
            &IOCMatcher::new(None).unwrap(),
            "MY-WEB01",
        )
        .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, "info");
        assert_eq!(events[0].event_type, "registry_record");
        assert!(events[0].indicators.contains(&"REG:record".to_string()));
        assert!(!is_triage_hit(&events[0]));
    }

    #[test]
    fn a_renamed_description_column_is_a_coverage_failure() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("registry.csv");
        std::fs::write(&p, "datetime,Detail\n2026-05-05T10:00:00Z,x\n").unwrap();
        let events = parse(
            &p,
            &PipelineConfig::default(),
            &TAToolDetector::new(std::path::Path::new("/nonexistent")).unwrap(),
            &IOCMatcher::new(None).unwrap(),
            "MY-WEB01",
        )
        .unwrap();
        // The row is still carried — a quiet artifact must not vanish — but the run
        // has to say the column it needed was not there.
        assert_eq!(events.len(), 1);
        assert!(columns::failures()
            .iter()
            .any(|f| f.artifact == "registry" && f.logical == "description"));
    }
}
