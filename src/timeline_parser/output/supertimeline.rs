use anyhow::Result;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use serde_json::json;

use crate::timeline_parser::config::severity_order;
use super::event::UnifiedEvent;

const CSV_HEADER: &str =
    "Timestamp_UTC,Source,EventType,Severity,Description,Indicators,MitreTactic,MitreTechnique,User,Hostname,DetectionRule";

/// Quote a CSV cell that may contain commas/quotes/newlines.
fn q(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\"").replace(['\n', '\r'], " "))
}

fn write_csv_row<W: Write>(w: &mut W, e: &UnifiedEvent) -> Result<()> {
    let indicators = e.indicators.join(" | ");
    writeln!(w, "{},{},{},{},{},{},{},{},{},{},{}",
        e.timestamp, e.source, e.event_type, e.severity,
        q(&e.description), q(&indicators),
        e.mitre_tactic, e.mitre_technique,
        q(&e.user), e.hostname, q(&e.detection_rule))?;
    Ok(())
}

fn write_csv(events: &[UnifiedEvent], path: &Path) -> Result<()> {
    let file = File::create(path)?;
    let mut w = BufWriter::new(file);
    writeln!(w, "{}", CSV_HEADER)?;
    for e in events {
        write_csv_row(&mut w, e)?;
    }
    Ok(())
}

pub fn write_supertimeline(events: &[UnifiedEvent], csv_path: &Path, jsonl_path: &Path) -> Result<()> {
    write_csv(events, csv_path)?;

    let file = File::create(jsonl_path)?;
    let mut w = BufWriter::new(file);
    for e in events {
        serde_json::to_writer(&mut w, e)?;
        writeln!(w)?;
    }
    Ok(())
}

/// Indicator prefixes that mark an event as a genuine triage "hit" (actor
/// activity or a positive detection) rather than medium-severity background.
const STRONG_PREFIXES: &[&str] = &[
    "TA_TOOL:", "IOC:", "IOC_HASH:", "LATERAL_OUTBOUND:", "RUNAS_USER:",
    "COMPROMISED_USER:", "COMPROMISED_IP:", "PATH:", "GEO:anonymizing",
];

/// Is this event part of the curated triage timeline? High/crit severity, an
/// actor session/lateral event, a positive detection indicator, or a malicious
/// hash verdict. This is the set the triage report is built from — minus the
/// medium-severity background (sigma med, and the bare executable create/delete
/// churn that carries no other signal; a genuinely suspicious binary still lands
/// here via its TA_TOOL / IOC / PATH indicator).
pub fn is_triage_hit(e: &UnifiedEvent) -> bool {
    if severity_order(&e.severity) >= severity_order("high") {
        return true;
    }
    if matches!(e.event_type.as_str(),
        "rdp_logon" | "rdp_logoff" | "precursor_logon" | "lateral_movement_outbound")
    {
        return true;
    }
    e.indicators.iter().any(|ind| {
        if let Some(rest) = ind.strip_prefix("HASH_INTEL:") {
            // Only malicious hash verdicts count (skip "known clean" annotations).
            return !rest.to_lowercase().contains("clean");
        }
        STRONG_PREFIXES.iter().any(|p| ind.starts_with(p))
    })
}

/// Write the curated triage timeline (CSV + JSONL): the chronological set of
/// hits the triage report is based on, for ingestion into timeline tools.
pub fn write_triage_timeline(
    events: &[UnifiedEvent],
    csv_path: &Path,
    jsonl_path: &Path,
) -> Result<usize> {
    let hits: Vec<&UnifiedEvent> = events.iter().filter(|e| is_triage_hit(e)).collect();

    let file = File::create(csv_path)?;
    let mut w = BufWriter::new(file);
    writeln!(w, "{}", CSV_HEADER)?;
    for e in &hits {
        write_csv_row(&mut w, e)?;
    }

    let file = File::create(jsonl_path)?;
    let mut w = BufWriter::new(file);
    for e in &hits {
        serde_json::to_writer(&mut w, *e)?;
        writeln!(w)?;
    }

    Ok(hits.len())
}

// ── OpenSearch NDJSON ─────────────────────────────────────────────────────────

/// Write the reduced timeline in the shape the wiskess worker ingests.
///
/// `worker.py:307` skips anything whose name does not end in `json`, so this is
/// written as `.json` rather than `.jsonl` — `"x.jsonl".endswith("json")` is
/// false, and the existing `_supertimeline.jsonl` is silently never ingested.
///
/// The field set is dictated by `polars_tln.py::df_time` and the index mapping
/// in `field_mapping.py`, which every other document in the index already
/// follows:
///
/// | field | shape |
/// |---|---|
/// | `datetime` | `%Y-%m-%dT%H:%M:%S%.3fZ` string |
/// | `timestamp` | epoch **milliseconds**, integer — not the ISO string this
///   crate uses internally, which is why this is a separate serialisation |
/// | `timestamp_desc` | `"{doc_type} - {filename}: {source}"` |
/// | `message` | the full event text |
/// | `hostname` | the host |
/// | `doc_type` | `triage` — one value for everything this tool emits, so a
///   consumer can ask the index for the boiled-down timeline directly |
///
/// The parser's own fields ride alongside, and `triage_hit` marks the curated
/// subset so both timelines live in one document set.
pub fn write_opensearch_ndjson(
    events: &[UnifiedEvent],
    out_dir: &Path,
    hostname: &str,
) -> Result<(usize, PathBuf)> {
    let filename = format!("{hostname}_triage.json");
    let path = out_dir.join(&filename);
    let mut w = BufWriter::new(File::create(&path)?);

    for e in events {
        let mut doc = serde_json::Map::new();
        let (datetime, millis) = normalise_time(&e.timestamp);
        doc.insert("datetime".into(), json!(datetime));
        if let Some(ms) = millis {
            doc.insert("timestamp".into(), json!(ms));
        }
        doc.insert(
            "timestamp_desc".into(),
            json!(format!("triage - {filename}: {}", e.source)),
        );
        doc.insert("message".into(), json!(e.description));
        doc.insert("hostname".into(), json!(hostname));
        doc.insert("doc_type".into(), json!("triage"));

        doc.insert("source".into(), json!(e.source));
        doc.insert("event_type".into(), json!(e.event_type));
        doc.insert("severity".into(), json!(e.severity));
        doc.insert("indicators".into(), json!(e.indicators));
        doc.insert("mitre_tactic".into(), json!(e.mitre_tactic));
        doc.insert("mitre_technique".into(), json!(e.mitre_technique));
        doc.insert("user".into(), json!(e.user));
        doc.insert("detection_rule".into(), json!(e.detection_rule));
        doc.insert("triage_hit".into(), json!(is_triage_hit(e)));

        serde_json::to_writer(&mut w, &doc)?;
        writeln!(w)?;
    }
    w.flush()?;
    Ok((events.len(), path))
}

/// Normalise a source timestamp to the index's `datetime` format and its epoch
/// millisecond twin.
///
/// Timestamps arrive exactly as the source artefact wrote them — no parser
/// normalises them — so an unparseable value is passed through unchanged and
/// simply carries no `timestamp`. That is deliberately not an error: dropping a
/// forensic event because its timestamp is malformed loses evidence, and a
/// missing numeric field is visible where a silently discarded row is not.
pub fn normalise_time(ts: &str) -> (String, Option<i64>) {
    let trimmed = ts.trim_end_matches('Z');
    let parsed = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S%.f")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S"));
    match parsed {
        Ok(dt) => (
            format!("{}Z", dt.format("%Y-%m-%dT%H:%M:%S%.3f")),
            Some(dt.and_utc().timestamp_millis()),
        ),
        Err(_) => (ts.to_string(), None),
    }
}

#[cfg(test)]
mod opensearch_tests {
    use super::*;

    fn ev(ts: &str, source: &str, severity: &str) -> UnifiedEvent {
        UnifiedEvent {
            timestamp: ts.to_string(),
            source: source.to_string(),
            event_type: "process_execution".to_string(),
            severity: severity.to_string(),
            description: "a thing happened".to_string(),
            indicators: vec!["TA_TOOL:psexec".to_string()],
            mitre_tactic: "Execution".to_string(),
            mitre_technique: "T1569".to_string(),
            user: "super admin".to_string(),
            hostname: "MY-DC02".to_string(),
            detection_rule: "r".to_string(),
        }
    }

    fn write_as(tag: &str, events: &[UnifiedEvent]) -> (serde_json::Value, std::path::PathBuf) {
        // Per-test directory: these run in parallel and a shared path meant one
        // test read another's file.
        let dir = std::env::temp_dir()
            .join(format!("os-ndjson-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (_, path) = write_opensearch_ndjson(events, &dir, "MY-DC02").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let first = text.lines().next().unwrap().to_string();
        (serde_json::from_str(&first).unwrap(), path)
    }

    /// `worker.py` skips any file not ending in `json`, and `.jsonl` does not.
    #[test]
    fn the_filename_is_one_the_worker_will_ingest() {
        let (_, path) = write_as("name", &[ev("2026-05-05T09:50:31.422Z", "hayabusa", "high")]);
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.ends_with("json"), "{name}");
        assert!(!name.ends_with("jsonl"), "worker.py:307 would skip {name}");
    }

    /// The six fields the index requires, per polars_tln.py::df_time.
    #[test]
    fn every_required_index_field_is_present() {
        let (d, _) = write_as("fields", &[ev("2026-05-05T09:50:31.422Z", "hayabusa", "high")]);
        for f in ["datetime", "timestamp_desc", "message", "hostname", "doc_type", "timestamp"] {
            assert!(d.get(f).is_some(), "missing {f}: {d}");
        }
        assert_eq!(d["hostname"], "MY-DC02");
        assert_eq!(d["doc_type"], "triage");
        assert_eq!(d["message"], "a thing happened");
    }

    /// `timestamp` is mapped as epoch_millis. Emitting the ISO string this crate
    /// uses internally would be rejected or mis-mapped at ingest.
    #[test]
    fn timestamp_is_epoch_milliseconds_not_a_string() {
        let (d, _) = write_as("millis", &[ev("2026-05-05T09:50:31.422Z", "hayabusa", "high")]);
        assert_eq!(d["timestamp"], serde_json::json!(1777974631422i64));
        assert_eq!(d["datetime"], "2026-05-05T09:50:31.422Z");
    }

    #[test]
    fn timestamp_desc_follows_the_artefact_convention() {
        let (d, _) = write_as("desc", &[ev("2026-05-05T09:50:31.422Z", "hayabusa", "high")]);
        let td = d["timestamp_desc"].as_str().unwrap();
        assert!(td.starts_with("triage - "), "{td}");
        assert!(td.ends_with(": hayabusa"), "{td}");
    }

    /// An event whose timestamp cannot be parsed still reaches the index — it
    /// simply carries no numeric twin. Dropping it would lose evidence.
    #[test]
    fn an_unparseable_timestamp_keeps_the_event_and_omits_the_numeric_field() {
        let (d, _) = write_as("unparsed", &[ev("not a timestamp", "mft", "low")]);
        assert_eq!(d["datetime"], "not a timestamp");
        assert!(d.get("timestamp").is_none());
    }

    /// Both timelines live in one document set, distinguished by a flag, so the
    /// curated subset is a query rather than a second file.
    #[test]
    fn curated_hits_are_flagged_in_place() {
        let (hit, _) = write_as("hit", &[ev("2026-05-05T09:50:31.422Z", "hayabusa", "high")]);
        assert_eq!(hit["triage_hit"], true, "high severity is a curated hit");
        let (miss, _) = write_as("miss", &[UnifiedEvent {
            indicators: vec![],
            ..ev("2026-05-05T09:50:31.422Z", "mft", "low")
        }]);
        assert_eq!(miss["triage_hit"], false);
    }

    #[test]
    fn sub_second_precision_is_preserved_to_milliseconds() {
        assert_eq!(normalise_time("2026-05-05T09:50:31.4Z").0, "2026-05-05T09:50:31.400Z");
        assert_eq!(normalise_time("2026-05-05T09:50:31Z").0, "2026-05-05T09:50:31.000Z");
    }
}
