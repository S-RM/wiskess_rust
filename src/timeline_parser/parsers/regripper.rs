//! RegRipper TLN output — one line per registry artefact, per plugin.
//!
//! 14,313 rows in the collection that prompted this work, 559 events, and those
//! 559 were 38% of the entire curated triage cut — because the rows that did *not*
//! match a detector were dropped, the artifact looked like nothing but findings.
//! Unflagged rows are now carried at an `info` floor (`REGRIPPER:record`).
//!
//! The severity site here had the mirror-image of the MFT bug: `severity = if
//! hit.severity == "high" { "high" } else { "med" }` **lowered** a `crit` rule to
//! `med`. It goes through [`raise`] now, which never lowers.

use anyhow::Result;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::{raise, PipelineConfig};
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::suspicious_paths::SuspiciousPathDetector;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::detectors::Attack;
use crate::timeline_parser::output::event::UnifiedEvent;
use crate::timeline_parser::parsers::columns::{self, Columns, Field, DATETIME, MESSAGE, USER_NAME};

/// The plugin's finding text. Required: it is the whole content of the row.
const DESCRIPTION: Field = Field::required("description", &["description", "Description"]);
/// Which RegRipper plugin or hive produced it.
const SOURCE: Field = Field::optional("source", &["source", "Source"]);

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
        "regripper",
        filepath,
        &headers,
        &[DATETIME, MESSAGE, DESCRIPTION, SOURCE, USER_NAME],
    );

    for result in rdr.records() {
        let Ok(record) = result else { continue };
        rows += 1;

        let ts = cols.get(&record, "datetime").to_string();
        if ts.is_empty() {
            continue;
        }
        let source = cols.get(&record, "source");
        let user = cols.get(&record, "user_name").to_string();
        // The timeliner's `message` is the fallback: a row with no `description`
        // still says something, and an empty event is not an improvement on a
        // dropped one.
        let description = {
            let d = cols.get(&record, "description");
            if d.is_empty() { cols.get(&record, "message") } else { d }
        };
        if description.is_empty() {
            continue;
        }

        let scan_text = format!("{} {}", description, source);
        let ta_hits = ta_detector.scan(&scan_text);
        let ioc_hits = ioc_matcher.check(&scan_text);
        let path_hits = path_detector.check_path(description);
        let has_detection = !ta_hits.is_empty() || !ioc_hits.is_empty() || !path_hits.is_empty();

        if !has_detection && !cfg.emit_quiet_baseline {
            continue;
        }

        let mut indicators: Vec<String> = Vec::new();
        let mut severity = if has_detection { "low".to_string() } else { "info".to_string() };

        if !has_detection {
            indicators.push("REGRIPPER:record".to_string());
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

        let desc_trunc = description.char_indices().nth(200).map_or(description, |(i, _)| &description[..i]);

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "regripper".to_string(),
            event_type: "registry_artifact".to_string(),
            severity,
            description: format!("RegRipper: {}", desc_trunc),
            indicators,
            mitre_tactic: attack.tactic,
            mitre_technique: attack.technique,
            user,
            hostname: hostname.to_string(),
            detection_rule: "regripper_finding".to_string(),
            ..Default::default()
        });
    }

    columns::note_rows("regripper", rows);
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline_parser::output::supertimeline::is_triage_hit;
    use std::io::Write;

    /// `regripper.csv`'s header, verbatim.
    const HEADER: &str =
        "datetime,timestamp_desc,message,source,system,user,description,hostname,doc_type,timestamp";

    fn run_with(cfg: &PipelineConfig, header: &str, body: &str) -> Vec<UnifiedEvent> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("regripper.csv");
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

    /// The rows that made this artifact look like pure signal.
    #[test]
    fn a_plugin_line_no_rule_fired_on_is_carried_as_background() {
        let events = run(
            "2026-01-02T03:04:05.000Z,regripper - rr.txt: TLN,m,REG,MY-WEB01,testuser,\
             TimeZoneInformation - Bias 0,MY-WEB01,regripper,1\n",
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, "info");
        assert!(events[0].indicators.contains(&"REGRIPPER:record".to_string()));
        assert!(!is_triage_hit(&events[0]));
        assert_eq!(events[0].user, "testuser");
    }

    /// The clamp: the old code lowered any rule that was not exactly `high`, so a
    /// `crit` rule arrived as `med`. [`raise`] never lowers.
    #[test]
    fn a_path_rule_is_never_clamped_down() {
        let events = run(
            "2026-01-02T03:04:05.000Z,d,m,REG,MY-WEB01,testuser,\
             AppCompatCache - C:\\inetpub\\wwwroot\\uploads\\shell.aspx,MY-WEB01,regripper,1\n",
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, "high", "got {:?}", events[0].indicators);
        assert!(is_triage_hit(&events[0]));
    }

    #[test]
    fn the_baseline_can_be_switched_off_without_losing_the_detections() {
        let cfg = PipelineConfig { emit_quiet_baseline: false, ..Default::default() };
        let events = run_with(
            &cfg,
            HEADER,
            "2026-01-02T03:04:05.000Z,d,m,REG,H,testuser,TimeZoneInformation - Bias 0,H,regripper,1\n\
             2026-01-02T03:04:06.000Z,d,m,REG,H,testuser,x C:\\inetpub\\wwwroot\\shell.aspx,H,regripper,2\n",
        );
        assert_eq!(events.len(), 1, "only the flagged row");
        assert_eq!(events[0].severity, "high");
    }

    #[test]
    fn a_renamed_description_column_is_a_coverage_failure() {
        let events = run_with(
            &PipelineConfig::default(),
            "datetime,timestamp_desc,message,source,system,user,finding,hostname,doc_type,timestamp",
            "2026-01-02T03:04:05.000Z,d,,REG,H,testuser,x,H,regripper,1\n",
        );
        assert!(events.is_empty(), "no description and no message means no content");
        assert!(columns::failures()
            .iter()
            .any(|f| f.artifact == "regripper" && f.logical == "description"));
    }
}
