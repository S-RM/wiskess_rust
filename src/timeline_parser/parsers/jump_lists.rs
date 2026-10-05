//! Jump lists — what a user opened, per application.
//!
//! 1,231 rows in the collection that prompted this work, **0 events**. Every row
//! was `continue`d unless a detector fired on it, so an artifact that records a
//! user opening a file — including one on another host over UNC, and including
//! files since deleted — contributed nothing at all. Unflagged rows are now
//! carried at an `info` floor (`JUMPLIST:record`).
//!
//! A second defect: `PATH:` hits pushed an indicator but **never raised the
//! severity**, so a path rule on a jump-list target could not lift the event to
//! the level `is_triage_hit()` needs. Severity goes through [`raise`] now, and the
//! baseline path starts at `info` rather than the `med` every row used to start at.

use anyhow::Result;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::{raise, PipelineConfig};
use crate::timeline_parser::detectors::file_classes::normalise_path;
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::suspicious_paths::SuspiciousPathDetector;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::detectors::Attack;
use crate::timeline_parser::output::event::UnifiedEvent;
use crate::timeline_parser::parsers::columns::{self, Columns, Field, DATETIME, MESSAGE};

/// Something that names the opened file. `LocalPath` is JLECmd's own field;
/// `TargetIDAbsolutePath` is the path rebuilt from the shell items and is present
/// on rows where `LocalPath` is not. One of them has to resolve or the artifact
/// carries no target — which is how 1,231 rows became nothing.
const PATH_OR_TARGET: Field =
    Field::required("path_or_target", &["LocalPath", "TargetIDAbsolutePath", "CommonPath"]);
const LOCAL_PATH: Field = Field::optional("local_path", &["LocalPath"]);
const TARGET_PATH: Field = Field::optional("target_path", &["TargetIDAbsolutePath"]);
const APP_ID: Field = Field::optional("app_id", &["AppIdDescription", "AppId"]);
const ARGUMENTS: Field = Field::optional("arguments", &["Arguments"]);
const MACHINE_ID: Field = Field::optional("machine_id", &["MachineID"]);

pub fn parse(
    filepath: &Path,
    cfg: &PipelineConfig,
    ta_detector: &TAToolDetector,
    ioc_matcher: &IOCMatcher,
    path_detector: &SuspiciousPathDetector,
    hostname: &str,
) -> Result<Vec<UnifiedEvent>> {
    let mut events = Vec::new();
    let mut rows = 0usize;

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    let cols = Columns::resolve(
        "jump-lists",
        filepath,
        &headers,
        &[DATETIME, MESSAGE, PATH_OR_TARGET, LOCAL_PATH, TARGET_PATH, APP_ID, ARGUMENTS, MACHINE_ID],
    );

    for result in rdr.records() {
        let Ok(record) = result else { continue };
        rows += 1;

        let ts = cols.get(&record, "datetime").to_string();
        if ts.is_empty() {
            continue;
        }

        let local = cols.get(&record, "local_path");
        let target = cols.get(&record, "target_path");
        let path = normalise_path(if local.is_empty() { target } else { local });
        let app_desc = cols.get(&record, "app_id");
        let arguments = cols.get(&record, "arguments");
        let machine_id = cols.get(&record, "machine_id");
        if path.is_empty() && app_desc.is_empty() {
            continue;
        }

        let scan_text = format!("{} {} {} {}", path, app_desc, arguments, machine_id);
        let ta_hits = ta_detector.scan(&scan_text);
        let ioc_hits = ioc_matcher.check(&scan_text);
        let path_hits = path_detector.check_path(&path);
        let has_detection = !ta_hits.is_empty() || !ioc_hits.is_empty() || !path_hits.is_empty();

        if !has_detection && !cfg.emit_quiet_baseline {
            continue;
        }

        let mut indicators: Vec<String> = Vec::new();
        let mut severity = if has_detection { "med".to_string() } else { "info".to_string() };

        if !has_detection {
            indicators.push("JUMPLIST:record".to_string());
        }
        let mut attack = Attack::default();
        for hit in &ta_hits {
            indicators.push(format!("TA_TOOL:{}", hit.name));
            raise(&mut severity, "high");
            attack.from_tool(hit);
        }
        // This is the raise that was missing: the indicator was recorded and the
        // rule's own severity thrown away.
        for hit in &path_hits {
            indicators.push(format!("PATH:{}", hit.reason));
            raise(&mut severity, &hit.severity);
            attack.from_path(hit);
        }
        indicators.extend(ioc_hits.clone());
        if !ioc_hits.is_empty() {
            raise(&mut severity, "high");
        }

        let mut description = format!("JumpList: {} | Path: {}", app_desc, path);
        if !arguments.is_empty() {
            let args_trunc =
                arguments.char_indices().nth(100).map_or(arguments, |(i, _)| &arguments[..i]);
            description.push_str(&format!(" | Args: {}", args_trunc));
        }

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "jump-lists".to_string(),
            event_type: "user_activity".to_string(),
            severity,
            description,
            indicators,
            mitre_tactic: attack.tactic,
            mitre_technique: attack.technique,
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "jumplist_suspicious".to_string(),
            ..Default::default()
        });
    }

    columns::note_rows("jump-lists", rows);
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline_parser::output::supertimeline::is_triage_hit;
    use std::io::Write;

    /// `jump-lists.csv`'s header, verbatim.
    const HEADER: &str = "datetime,timestamp_desc,message,LocalPath,CommonPath,\
        TargetIDAbsolutePath,FileSize,AppIdDescription,Arguments,MachineID,SourceFile,hostname,\
        doc_type,timestamp";

    fn run_with(cfg: &PipelineConfig, header: &str, body: &str) -> Vec<UnifiedEvent> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jump-lists.csv");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "{header}").unwrap();
        f.write_all(body.as_bytes()).unwrap();
        drop(f);
        parse(
            &path,
            cfg,
            &TAToolDetector::new(Path::new("tools/threat_intel")).unwrap(),
            &IOCMatcher::new(None).unwrap(),
            &SuspiciousPathDetector::new(Path::new("tools/threat_intel")).unwrap(),
            "MY-WEB01",
        )
        .unwrap()
    }

    fn run(body: &str) -> Vec<UnifiedEvent> {
        run_with(&PipelineConfig::default(), HEADER, body)
    }

    /// The 0-from-1,231 case.
    #[test]
    fn an_ordinary_opened_file_is_carried_as_background() {
        let events = run(
            "2026-01-02T03:04:05.000Z,jump-lists - x: SourceCreated,m,\
             C:\\Users\\testuser\\Documents\\notes.docx,,,4096,Word,,MY-WEB01,f.jl,MY-WEB01,jump-lists,1\n",
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, "info");
        assert!(events[0].indicators.contains(&"JUMPLIST:record".to_string()));
        assert!(!is_triage_hit(&events[0]));
        assert!(events[0].description.contains("notes.docx"), "{}", events[0].description);
    }

    /// The missing raise: the indicator was pushed and the rule's severity dropped.
    #[test]
    fn a_path_rule_raises_the_severity_it_carries() {
        let events = run(
            "2026-01-02T03:04:05.000Z,d,m,C:\\inetpub\\wwwroot\\uploads\\shell.aspx,,,10,Notepad,,\
             MY-WEB01,f.jl,MY-WEB01,jump-lists,1\n",
        );
        assert_eq!(events.len(), 1);
        assert!(events[0].indicators.iter().any(|i| i == "PATH:script_in_web_served_tree"));
        assert_eq!(events[0].severity, "high", "the rule is high: {:?}", events[0].indicators);
        assert!(is_triage_hit(&events[0]));
    }

    /// Rows where JLECmd has no `LocalPath` still name a target, via the shell
    /// items. Reading only `LocalPath` would lose them.
    #[test]
    fn the_shell_item_path_is_used_when_there_is_no_local_path() {
        let events = run(
            "2026-01-02T03:04:05.000Z,d,m,,,\\\\10.0.0.5\\c$\\stage\\tool.exe,10,Explorer,,\
             MY-WEB01,f.jl,MY-WEB01,jump-lists,1\n",
        );
        assert_eq!(events.len(), 1);
        assert!(events[0].description.contains("tool.exe"), "{}", events[0].description);
    }

    #[test]
    fn arguments_are_recorded_rather_than_only_scanned() {
        let events = run(
            "2026-01-02T03:04:05.000Z,d,m,C:\\Windows\\System32\\cmd.exe,,,10,cmd,/c whoami,\
             MY-WEB01,f.jl,MY-WEB01,jump-lists,1\n",
        );
        assert!(events[0].description.contains("Args: /c whoami"), "{}", events[0].description);
    }

    #[test]
    fn a_renamed_target_column_is_a_coverage_failure() {
        let events = run_with(
            &PipelineConfig::default(),
            "datetime,timestamp_desc,message,SomeOtherColumn,hostname,doc_type,timestamp",
            "2026-01-02T03:04:05.000Z,d,m,x,MY-WEB01,jump-lists,1\n",
        );
        assert!(events.is_empty());
        assert!(columns::failures()
            .iter()
            .any(|f| f.artifact == "jump-lists" && f.logical == "path_or_target"));
    }
}
