//! LNK files — shortcuts, and therefore what a user or a dropper pointed at.
//!
//! 478 rows in the collection that prompted this work, **0 events**, for the same
//! reason as the jump lists: a `continue` when no detector fired. A LNK carries the
//! target path, its arguments and the MAC address of the machine that created it —
//! all three worth having on a timeline unconditionally, and the `MachineID` in
//! particular is how a shortcut written on another host is spotted. Unflagged rows
//! are now carried at an `info` floor (`LNK:record`).
//!
//! `PATH:` hits also never raised the severity here. They do now, via [`raise`].

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

/// Something that names the shortcut's target. A LNK to a share has a
/// `NetworkPath` and no `LocalPath`; one written by an installer may carry only a
/// `RelativePath`. Requiring any one of them keeps both shapes readable and makes
/// a rename visible.
const PATH_OR_TARGET: Field =
    Field::required("path_or_target", &["LocalPath", "NetworkPath", "RelativePath", "CommonPath"]);
const LOCAL_PATH: Field = Field::optional("local_path", &["LocalPath"]);
const NETWORK_PATH: Field = Field::optional("network_path", &["NetworkPath"]);
const RELATIVE_PATH: Field = Field::optional("relative_path", &["RelativePath"]);
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
        "lnk-files",
        filepath,
        &headers,
        &[
            DATETIME,
            MESSAGE,
            PATH_OR_TARGET,
            LOCAL_PATH,
            NETWORK_PATH,
            RELATIVE_PATH,
            ARGUMENTS,
            MACHINE_ID,
        ],
    );

    for result in rdr.records() {
        let Ok(record) = result else { continue };
        rows += 1;

        let ts = cols.get(&record, "datetime").to_string();
        if ts.is_empty() {
            continue;
        }

        let local_path = cols.get(&record, "local_path");
        let network_path = cols.get(&record, "network_path");
        let relative_path = cols.get(&record, "relative_path");
        let arguments = cols.get(&record, "arguments");
        let machine_id = cols.get(&record, "machine_id");

        // Local first, then the share, then the relative form — most specific to
        // least, so the description names the best-known target.
        let target = [local_path, network_path, relative_path]
            .into_iter()
            .find(|p| !p.is_empty())
            .unwrap_or("");
        let target = normalise_path(target);
        if target.is_empty() && arguments.is_empty() {
            continue;
        }

        let scan_text = format!("{} {} {} {}", target, arguments, machine_id, relative_path);
        let ta_hits = ta_detector.scan(&scan_text);
        let ioc_hits = ioc_matcher.check(&scan_text);
        let path_hits = path_detector.check_path(&target);
        let has_detection = !ta_hits.is_empty() || !ioc_hits.is_empty() || !path_hits.is_empty();

        if !has_detection && !cfg.emit_quiet_baseline {
            continue;
        }

        let mut indicators: Vec<String> = Vec::new();
        let mut severity = if has_detection { "med".to_string() } else { "info".to_string() };

        if !has_detection {
            indicators.push("LNK:record".to_string());
        }
        let mut attack = Attack::default();
        for hit in &ta_hits {
            indicators.push(format!("TA_TOOL:{}", hit.name));
            raise(&mut severity, "high");
            attack.from_tool(hit);
        }
        for hit in &path_hits {
            indicators.push(format!("PATH:{}", hit.reason));
            raise(&mut severity, &hit.severity);
            attack.from_path(hit);
        }
        indicators.extend(ioc_hits.clone());
        if !ioc_hits.is_empty() {
            raise(&mut severity, "high");
        }

        let args_trunc = arguments.char_indices().nth(100).map_or(arguments, |(i, _)| &arguments[..i]);
        let mut description = format!("LNK: {} | Args: {}", target, args_trunc);
        if !machine_id.is_empty() {
            description.push_str(&format!(" | MachineID: {}", machine_id));
        }

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "lnk-files".to_string(),
            event_type: "user_activity".to_string(),
            severity,
            description,
            indicators,
            mitre_tactic: attack.tactic,
            mitre_technique: attack.technique,
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "lnk_suspicious".to_string(),
            ..Default::default()
        });
    }

    columns::note_rows("lnk-files", rows);
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline_parser::output::supertimeline::is_triage_hit;
    use std::io::Write;

    /// `lnk-files.csv`'s header, verbatim.
    const HEADER: &str = "datetime,timestamp_desc,message,RelativePath,WorkingDirectory,LocalPath,\
        NetworkPath,CommonPath,FileSize,Arguments,MachineID,SourceFile,hostname,doc_type,timestamp";

    fn run_with(cfg: &PipelineConfig, header: &str, body: &str) -> Vec<UnifiedEvent> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lnk-files.csv");
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

    /// The 0-from-478 case.
    #[test]
    fn an_ordinary_shortcut_is_carried_as_background() {
        let events = run(
            "2026-01-02T03:04:05.000Z,lnk-files - x: TargetCreated,m,..\\notes.docx,\
             C:\\Users\\testuser\\Documents,C:\\Users\\testuser\\Documents\\notes.docx,,,4096,,\
             00:11:22:33:44:55,notes.lnk,MY-WEB01,lnk-files,1\n",
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, "info");
        assert!(events[0].indicators.contains(&"LNK:record".to_string()));
        assert!(!is_triage_hit(&events[0]));
    }

    /// The MAC of the machine that wrote the shortcut is how a LNK created
    /// elsewhere is spotted, so it belongs on the event, not only in the scan text.
    #[test]
    fn the_machine_id_is_recorded_on_the_event() {
        let events = run(
            "2026-01-02T03:04:05.000Z,d,m,,,C:\\Users\\testuser\\a.docx,,,10,,\
             00:11:22:33:44:55,a.lnk,MY-WEB01,lnk-files,1\n",
        );
        assert!(events[0].description.contains("MachineID: 00:11:22:33:44:55"), "{}", events[0].description);
    }

    #[test]
    fn a_shortcut_to_a_share_is_described_by_its_network_path() {
        let events = run(
            "2026-01-02T03:04:05.000Z,d,m,,,,\\\\10.0.0.5\\c$\\stage,,10,,\
             00:11:22:33:44:55,s.lnk,MY-WEB01,lnk-files,1\n",
        );
        assert_eq!(events.len(), 1);
        assert!(events[0].description.contains(r"\\10.0.0.5\c$\stage"), "{}", events[0].description);
    }

    /// The missing raise.
    #[test]
    fn a_path_rule_raises_the_severity_it_carries() {
        let events = run(
            "2026-01-02T03:04:05.000Z,d,m,,,C:\\inetpub\\wwwroot\\uploads\\shell.aspx,,,10,,\
             00:11:22:33:44:55,s.lnk,MY-WEB01,lnk-files,1\n",
        );
        assert_eq!(events[0].severity, "high", "got {:?}", events[0].indicators);
        assert!(is_triage_hit(&events[0]));
    }

    #[test]
    fn a_renamed_target_column_is_a_coverage_failure() {
        let events = run_with(
            &PipelineConfig::default(),
            "datetime,timestamp_desc,message,SomeOtherColumn,hostname,doc_type,timestamp",
            "2026-01-02T03:04:05.000Z,d,m,x,MY-WEB01,lnk-files,1\n",
        );
        assert!(events.is_empty());
        assert!(columns::failures()
            .iter()
            .any(|f| f.artifact == "lnk-files" && f.logical == "path_or_target"));
    }
}
