//! AppCompatCache (shimcache) — binaries the OS recorded having seen.
//!
//! 622 rows in the collection that prompted this work, 25 events. The other 597
//! were dropped by a `continue` when no detector fired, which is the wrong trade
//! for an artifact this small: shimcache is one of the few places that says a
//! binary *existed* after it has been deleted, and the row is worth having on the
//! timeline whether or not a rule matched its path. Unflagged rows are now carried
//! at an `info` floor (`APPCOMPAT:record`), which reaches the supertimeline and
//! `_triage.json` without widening the curated cut.
//!
//! The severity site was also a no-op: `severity = if hit.severity == "high" {
//! "high" } else { severity }` cannot move a `med` start anywhere, so a `high`
//! path rule left the event one step below the threshold `is_triage_hit()` uses.
//! It goes through [`raise`] now.
//!
//! `Executed: Yes` must stay in the description verbatim —
//! `classify::apply` reads it to set `ExecutionEvidence::Executed`, and shimcache
//! is the only source that states execution outright.

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

/// The cached path. Required: with no path there is nothing to match, describe or
/// classify, and 622 rows would come out as 622 empty events.
const PATH: Field = Field::required("path", &["Path", "FullPath", "full_name", "file_path"]);

/// Whether the cache entry's execution flag was set. Only some Windows versions
/// record it, so optional — and an absent flag must read as unknown, not as "no".
const EXECUTED: Field = Field::optional("executed", &["Executed"]);

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

    let cols = Columns::resolve("appcompatcache", filepath, &headers, &[DATETIME, MESSAGE, PATH, EXECUTED]);

    for result in rdr.records() {
        let Ok(record) = result else { continue };
        rows += 1;

        let ts = cols.get(&record, "datetime").to_string();
        if ts.is_empty() {
            continue;
        }
        let path = normalise_path(cols.get(&record, "path"));
        let executed = cols.get(&record, "executed");
        if path.is_empty() {
            continue;
        }

        let path_hits = path_detector.check_path(&path);
        let ta_hits = ta_detector.scan(&path);
        let ioc_hits = ioc_matcher.check(&path);
        let has_detection = !path_hits.is_empty() || !ta_hits.is_empty() || !ioc_hits.is_empty();

        if !has_detection && !cfg.emit_quiet_baseline {
            continue;
        }

        let mut indicators: Vec<String> = Vec::new();
        // `med` only when something fired. The old code started every event at
        // `med`, so switching the gate off without this would have delivered all
        // 622 rows as medium-severity findings.
        let mut severity = if has_detection { "med".to_string() } else { "info".to_string() };

        if !has_detection {
            indicators.push("APPCOMPAT:record".to_string());
        }
        // Shimcache is execution evidence whatever fired, so the tactic is the
        // artifact's; a rule hit can still supply the technique.
        let mut attack = Attack::from_artifact("Execution", "");
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
        indicators.extend(ioc_hits.clone());
        if !ioc_hits.is_empty() {
            raise(&mut severity, "high");
        }

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "appcompatcache".to_string(),
            event_type: "process_execution".to_string(),
            severity,
            description: format!("AppCompatCache: {} | Executed: {}", path, executed),
            indicators,
            mitre_tactic: attack.tactic,
            mitre_technique: attack.technique,
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "appcompat_suspicious_path".to_string(),
            ..Default::default()
        });
    }

    columns::note_rows("appcompatcache", rows);
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline_parser::output::supertimeline::is_triage_hit;
    use std::io::Write;

    /// `appcompatcache.csv`'s header, verbatim.
    const HEADER: &str = "datetime,timestamp_desc,message,Path,Executed,Duplicate,SourceFile,\
        ControlSet,CacheEntryPosition,hostname,doc_type,timestamp";

    fn run_with(cfg: &PipelineConfig, header: &str, body: &str) -> Vec<UnifiedEvent> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("appcompatcache.csv");
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

    /// The 597 dropped rows: an ordinary cache entry is background, not absence.
    #[test]
    fn an_entry_no_rule_fired_on_is_carried_as_background() {
        let events = run(
            "2026-01-02T03:04:05.000Z,appcompat - x: LastModified,m,\
             C:\\Windows\\System32\\svchost.exe,Yes,false,SOFTWARE,1,0,MY-WEB01,appcompatcache,1\n",
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, "info");
        assert!(events[0].indicators.contains(&"APPCOMPAT:record".to_string()));
        assert!(!is_triage_hit(&events[0]), "background must not widen the curated cut");
    }

    /// `classify::apply` reads this string to set execution evidence, so it has to
    /// survive verbatim.
    #[test]
    fn the_execution_flag_stays_in_the_description() {
        let events = run(
            "2026-01-02T03:04:05.000Z,d,m,C:\\Windows\\Temp\\stage.exe,Yes,false,SOFTWARE,1,0,H,a,1\n",
        );
        assert!(events[0].description.contains("Executed: Yes"), "{}", events[0].description);
    }

    /// The no-op severity site: a `high` path rule could not lift a `med` event,
    /// which is exactly the threshold the curated cut uses.
    #[test]
    fn a_high_path_rule_raises_the_event_and_it_reaches_the_triage_cut() {
        let events = run(
            "2026-01-02T03:04:05.000Z,d,m,\
             C:\\inetpub\\wwwroot\\uploads\\shell.aspx,Yes,false,SOFTWARE,1,0,H,a,1\n",
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, "high", "got {:?}", events[0].indicators);
        assert!(events[0].indicators.iter().any(|i| i == "PATH:script_in_web_served_tree"));
        assert!(is_triage_hit(&events[0]));
    }

    #[test]
    fn the_baseline_can_be_switched_off_without_losing_the_detections() {
        let cfg = PipelineConfig { emit_quiet_baseline: false, ..Default::default() };
        let events = run_with(
            &cfg,
            HEADER,
            "2026-01-02T03:04:05.000Z,d,m,C:\\Windows\\System32\\svchost.exe,Yes,f,S,1,0,H,a,1\n\
             2026-01-02T03:04:06.000Z,d,m,C:\\inetpub\\wwwroot\\shell.aspx,Yes,f,S,1,0,H,a,2\n",
        );
        assert_eq!(events.len(), 1, "only the flagged row");
        assert_eq!(events[0].severity, "high");
    }

    /// A renamed path column must be reported, not read as whatever sits at index 1.
    #[test]
    fn a_missing_path_column_is_a_coverage_failure_not_an_empty_event() {
        let events = run_with(
            &PipelineConfig::default(),
            "datetime,timestamp_desc,message,CachedFilePath,hostname,doc_type,timestamp",
            "2026-01-02T03:04:05.000Z,d,m,C:\\Windows\\System32\\svchost.exe,H,a,1\n",
        );
        assert!(events.is_empty(), "no path, no event — and the run has to say so");
        assert!(
            columns::failures()
                .iter()
                .any(|f| f.artifact == "appcompatcache" && f.logical == "path"),
            "the coverage record must name the column it could not read"
        );
    }
}
