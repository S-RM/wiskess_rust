//! Generic emitter for low-volume artifacts with no bespoke parser.
//!
//! Three artifacts in a current collection had no parser at all — `shellbags.csv`
//! (756 rows), `powershell_history.csv` and `recycle-bin.csv` — so they
//! contributed nothing, and nothing said they had been skipped. That is a poor
//! trade for artifacts this small: the recycle-bin row on the collection that
//! prompted this work records a deleted `.cfm` file from an application
//! directory, and a shellbag records an administrator browsing an admin share on
//! another host by IP. Both are the kind of thing an investigation is looking for,
//! and neither needs a detection rule to be worth having on the timeline.
//!
//! This is deliberately **only** for artifacts with no bespoke parser. The
//! bespoke quiet parsers do things a generic emitter cannot and must not lose:
//! shimcache's `Executed: Yes` becoming `ExecutionEvidence::Executed`, the
//! registry parser's persistence-key establishment window, Amcache's SHA1
//! extraction feeding the hash-reputation pass. Running both over one file would
//! also emit every row twice.

use anyhow::Result;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::{raise, PipelineConfig};
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::suspicious_paths::SuspiciousPathDetector;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::detectors::Attack;
use crate::timeline_parser::output::event::UnifiedEvent;
use crate::timeline_parser::parsers::artifacts::PassthroughSpec;
use crate::timeline_parser::parsers::columns::{self, Columns, Field, DATETIME, MESSAGE, TIMESTAMP_DESC, USER_NAME};

pub fn parse(
    filepath: &Path,
    key: &'static str,
    spec: &PassthroughSpec,
    cfg: &PipelineConfig,
    ta_detector: &TAToolDetector,
    ioc_matcher: &IOCMatcher,
    path_detector: &SuspiciousPathDetector,
    hostname: &str,
) -> Result<Vec<UnifiedEvent>> {
    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    // The extra columns are declared per artifact in the registry, so they are
    // resolved dynamically rather than through the shared `Field` constants.
    let extra: Vec<Field> = spec
        .extra_cols
        .iter()
        .map(|c| Field::optional(c, std::slice::from_ref(c)))
        .collect();
    let mut fields = vec![DATETIME, TIMESTAMP_DESC, MESSAGE, USER_NAME];
    fields.extend(extra);

    let cols = Columns::resolve(key, filepath, &headers, &fields);

    let mut events = Vec::new();
    let mut rows = 0usize;

    for result in rdr.records() {
        let Ok(record) = result else { continue };
        rows += 1;

        let ts = cols.get(&record, "datetime").to_string();
        if ts.is_empty() || !cfg.in_timewindow(&ts) {
            continue;
        }

        // The timeliner already builds a human-readable `message` for most
        // artifacts. Where it is empty, the declared columns are joined instead —
        // and either way both feed the detectors, so a UNC path sitting in
        // `AbsolutePath` is actually seen rather than silently unexamined.
        let message = cols.get(&record, "message");
        let joined: Vec<String> = spec
            .extra_cols
            .iter()
            .filter_map(|c| {
                let v = cols.get(&record, c);
                if v.is_empty() { None } else { Some(format!("{c}: {v}")) }
            })
            .collect();

        let description = if message.is_empty() {
            joined.join(" | ")
        } else if joined.is_empty() {
            message.to_string()
        } else {
            format!("{message} | {}", joined.join(" | "))
        };
        if description.is_empty() {
            continue;
        }

        let scan_text = format!("{message} {}", joined.join(" "));
        let ta_hits = ta_detector.scan(&scan_text);
        let ioc_hits = ioc_matcher.check(&scan_text);

        // Path rules want a path, not a sentence: pass the declared columns that
        // look like one, so `\\10.0.0.1\c$\stage` is checked as a path and the
        // surrounding prose is not.
        let path_hits: Vec<_> = spec
            .extra_cols
            .iter()
            .map(|c| cols.get(&record, c))
            .filter(|v| v.contains('\\') || v.contains('/'))
            .flat_map(|v| path_detector.check_path(v))
            .collect();

        let has_detection = !ta_hits.is_empty() || !ioc_hits.is_empty() || !path_hits.is_empty();

        // No `continue` when nothing fired — that is the whole point of this
        // module. An unflagged row is background at `info`, not absent.
        if !has_detection && !cfg.emit_quiet_baseline {
            continue;
        }

        let mut severity = if has_detection { "med".to_string() } else { "info".to_string() };
        let mut indicators: Vec<String> = Vec::new();

        if !has_detection {
            indicators.push(format!("{}:record", spec.source.to_uppercase().replace('-', "_")));
        }
        let mut attack = Attack::default();
        for hit in &path_hits {
            indicators.push(format!("PATH:{}", hit.reason));
            raise(&mut severity, &hit.severity);
            attack.from_path(hit);
        }
        for hit in &ta_hits {
            indicators.push(format!("TA_TOOL:{}", hit.name));
            raise(&mut severity, "high");
            attack.from_tool(hit);
        }
        if !ioc_hits.is_empty() {
            indicators.extend(ioc_hits.clone());
            raise(&mut severity, "high");
        }

        events.push(UnifiedEvent {
            timestamp: ts,
            source: spec.source.to_string(),
            event_type: spec.event_type.to_string(),
            severity,
            description,
            indicators,
            mitre_tactic: attack.tactic,
            mitre_technique: attack.technique,
            user: cols.get(&record, "user_name").to_string(),
            hostname: hostname.to_string(),
            detection_rule: spec.detection_rule.to_string(),
            ..Default::default()
        });
    }

    columns::note_rows(key, rows);
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline_parser::parsers::artifacts;
    use std::io::Write;

    fn write_csv(dir: &tempfile::TempDir, name: &str, content: &str) -> std::path::PathBuf {
        let p = dir.path().join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        p
    }

    fn run(name: &str, key: &'static str, content: &str) -> Vec<UnifiedEvent> {
        let dir = tempfile::tempdir().unwrap();
        let path = write_csv(&dir, name, content);
        let spec = artifacts::spec(key).unwrap().passthrough.unwrap();
        parse(
            &path,
            key,
            &spec,
            &PipelineConfig::default(),
            &TAToolDetector::new(Path::new("tools/threat_intel")).unwrap(),
            &IOCMatcher::new(None).unwrap(),
            &SuspiciousPathDetector::new(Path::new("tools/threat_intel")).unwrap(),
            "MY-WEB01",
        )
        .unwrap()
    }

    /// The regression: 756 shellbag rows produced no events.
    #[test]
    fn every_row_of_a_quiet_artifact_becomes_an_event() {
        let events = run(
            "shellbags.csv",
            "shellbags",
            "datetime,timestamp_desc,message,AbsolutePath,ShellType,Value,user_name\n\
             2026-01-02T03:04:05.000Z,shellbags - UsrClass: LastWriteTime,Folder opened,C:\\\\Users\\\\testuser\\\\Documents,Directory,Documents,testuser\n\
             2026-01-02T03:04:06.000Z,shellbags - UsrClass: LastWriteTime,Folder opened,\\\\\\\\10.0.0.5\\\\c$\\\\stage,Network,stage,testuser\n",
        );
        assert_eq!(events.len(), 2, "both rows must survive with no rule firing");
        assert_eq!(events[0].severity, "info", "background, not a finding");
        assert!(events[0].indicators.contains(&"SHELLBAGS:record".to_string()));
        assert_eq!(events[0].source, "shellbags");
        assert_eq!(events[0].user, "testuser");
    }

    /// An `info` row must not reach the curated cut — the operator's report and
    /// triage timeline stay exactly as narrow as they were.
    #[test]
    fn a_baseline_row_carries_no_severity_that_would_promote_it() {
        let events = run(
            "recycle-bin.csv",
            "recycle-bin",
            "datetime,timestamp_desc,message,FileName,FileSize,user_name\n\
             2026-01-02T03:04:05.000Z,recycle-bin - $I: DeletedOn,,C:\\\\AppData\\\\report.cfm,2048,testuser\n",
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, "info");
        assert!(!crate::timeline_parser::output::supertimeline::is_triage_hit(&events[0]));
    }

    /// The columns are handed to the detectors, so a path in one is actually
    /// examined rather than carried past as prose.
    #[test]
    fn a_declared_column_is_seen_by_the_path_detector() {
        let events = run(
            "shellbags.csv",
            "shellbags",
            "datetime,timestamp_desc,message,AbsolutePath,ShellType,Value,user_name\n\
             2026-01-02T03:04:05.000Z,d,Folder opened,C:\\\\inetpub\\\\wwwroot\\\\uploads\\\\shell.aspx,Directory,x,testuser\n",
        );
        assert_eq!(events.len(), 1);
        assert!(
            events[0].indicators.iter().any(|i| i == "PATH:script_in_web_served_tree"),
            "got {:?}",
            events[0].indicators
        );
        assert_eq!(events[0].severity, "high", "a high path rule must raise it");
    }

    /// When the description would be built from columns, it is — an empty
    /// `message` must not produce an empty event.
    #[test]
    fn a_row_with_no_message_is_described_from_its_columns() {
        let events = run(
            "powershell_history.csv",
            "powershell-history",
            "datetime,timestamp_desc,message,command,user_name\n\
             2026-01-02T03:04:05.000Z,d,,Get-ChildItem C:\\\\,testuser\n",
        );
        assert_eq!(events.len(), 1);
        assert!(events[0].description.contains("Get-ChildItem"), "{}", events[0].description);
    }

    #[test]
    fn the_baseline_can_be_switched_off_without_losing_detections() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_csv(
            &dir,
            "shellbags.csv",
            "datetime,timestamp_desc,message,AbsolutePath,ShellType,Value,user_name\n\
             2026-01-02T03:04:05.000Z,d,Folder opened,C:\\\\Users\\\\testuser\\\\Documents,Directory,x,testuser\n\
             2026-01-02T03:04:06.000Z,d,Folder opened,C:\\\\inetpub\\\\wwwroot\\\\shell.aspx,Directory,x,testuser\n",
        );
        let spec = artifacts::spec("shellbags").unwrap().passthrough.unwrap();
        let cfg = PipelineConfig { emit_quiet_baseline: false, ..Default::default() };
        let events = parse(
            &path,
            "shellbags",
            &spec,
            &cfg,
            &TAToolDetector::new(Path::new("tools/threat_intel")).unwrap(),
            &IOCMatcher::new(None).unwrap(),
            &SuspiciousPathDetector::new(Path::new("tools/threat_intel")).unwrap(),
            "MY-WEB01",
        )
        .unwrap();
        assert_eq!(events.len(), 1, "only the flagged row");
        assert_eq!(events[0].severity, "high");
    }
}
