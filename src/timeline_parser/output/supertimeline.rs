use anyhow::Result;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use serde_json::json;

use crate::timeline_parser::config::severity_order;
use super::event::UnifiedEvent;

const CSV_HEADER: &str =
    "Timestamp_UTC,Source,EventType,Severity,Description,Indicators,MitreTactic,MitreTechnique,User,Hostname,DetectionRule,Classification,ExecutionEvidence,Phase";

/// Quote a CSV cell that may contain commas/quotes/newlines.
fn q(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\"").replace(['\n', '\r'], " "))
}

fn write_csv_row<W: Write>(w: &mut W, e: &UnifiedEvent) -> Result<()> {
    let indicators = e.indicators.join(" | ");
    writeln!(w, "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        e.timestamp, e.source, e.event_type, e.severity,
        q(&e.description), q(&indicators),
        e.mitre_tactic, e.mitre_technique,
        q(&e.user), e.hostname, q(&e.detection_rule),
        q(&e.classification), e.execution_evidence, e.phase)?;
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
    "OFF_CADENCE_MEMBER:",
    // `--verbose-events` only. Rarity is the signal: a (user, logon type,
    // source) seen a handful of times across the whole record is worth an
    // analyst's eye, where the same account logging on five thousand times is
    // furniture. `OFF_HOURS_LOGON` deliberately does NOT appear here — a 24/7
    // service account logs on at night by definition, and promoting 1,900 such
    // rows would bury the 38 that matter. An out-of-hours logon that is *also*
    // rare arrives through this prefix anyway.
    "RARE_LOGON:",
];

/// Is this event part of the curated triage timeline? High/crit severity, an
/// actor session/lateral event, a positive detection indicator, or a malicious
/// hash verdict. This is the set the triage report is built from — minus the
/// medium-severity background (sigma med, and the bare executable create/delete
/// churn that carries no other signal; a genuinely suspicious binary still lands
/// here via its TA_TOOL / IOC / PATH indicator).
pub fn is_triage_hit(e: &UnifiedEvent) -> bool {
    // An event carrying a positive, decidable explanation — vendor tree, OS
    // servicing, scheduled automation, the responder's own collection — is not
    // a finding. It stays in the supertimeline, so the evidence behind the
    // classification is never suppressed, but it must not be handed to an
    // analyst or a model as something to adjudicate. A direct IOC or malicious
    // hash verdict overrides the explanation: an allowlisted path is exactly
    // where an actor would prefer to sit.
    if e.is_explained() && !overrides_explanation(e) {
        return false;
    }
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

/// Evidence strong enough to outrank a benign classification: a supplied-IOC
/// match or a malicious hash verdict. A path allowlist is spoofable; these are
/// statements about the content, not about where it sits.
fn overrides_explanation(e: &UnifiedEvent) -> bool {
    e.indicators.iter().any(|i| {
        i.starts_with("IOC:")
            || i.starts_with("IOC_HASH:")
            || i.strip_prefix("HASH_INTEL:")
                .is_some_and(|r| !r.to_lowercase().contains("clean"))
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
    let generated = format!("{}Z", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3f"));
    // Every line written, whatever its doc_type. The caller reports this, so it
    // has to be the truth about the file rather than the length of one input.
    let mut written = 0usize;

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
        // Decided once, here, so no downstream consumer has to re-derive it and
        // no two hosts can disagree about the same artefact.
        doc.insert("classification".into(), json!(e.classification));
        doc.insert("explained".into(), json!(e.is_explained()));
        if !e.execution_evidence.is_empty() {
            doc.insert("execution_evidence".into(), json!(e.execution_evidence));
        }
        if !e.phase.is_empty() {
            doc.insert("phase".into(), json!(e.phase));
        }

        serde_json::to_writer(&mut w, &doc)?;
        writeln!(w)?;
        written += 1;
    }

    // Per-tag counts, as a document.
    //
    // A per-host parser cannot know that Impact fired on 18 of 28 hosts — but
    // it can state its own numbers in a shape a consumer can aggregate, so the
    // estate-wide coverage is computed once rather than rediscovered by every
    // analyst reading one host at a time.
    {
        let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
        let mut findings = 0usize;
        for e in events {
            if e.is_explained() || e.mitre_tactic.is_empty() {
                continue;
            }
            *counts.entry(e.mitre_tactic.as_str()).or_default() += 1;
            findings += 1;
        }
        if findings > 0 {
            let mut doc = serde_json::Map::new();
            doc.insert("datetime".into(), json!(generated));
            doc.insert("timestamp_desc".into(), json!(format!("triage_tags - {filename}")));
            doc.insert("hostname".into(), json!(hostname));
            doc.insert("doc_type".into(), json!("triage_tags"));
            doc.insert("tagged_findings".into(), json!(findings));
            doc.insert("tactics".into(), json!(counts));
            doc.insert(
                "message".into(),
                json!(format!(
                    "{findings} tagged finding(s) on {hostname}: {}",
                    counts
                        .iter()
                        .map(|(t, n)| format!("{t} {n}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            );
            serde_json::to_writer(&mut w, &doc)?;
            writeln!(w)?;
            written += 1;
        }
    }

    w.flush()?;
    Ok((written, path))
}

/// Write the triage report as its own ingestible timeline file.
///
/// The narrative was unreachable. A consumer reading this tool's output from an
/// index saw `doc_type: triage` and nothing else — the markdown only ever
/// existed inside the collection archive, so the report's own findings never
/// arrived through the channel everything else arrives through.
///
/// Shape follows the same convention as every other wiskess timeline file, so
/// the worker needs no special case:
///
/// | field | value |
/// |---|---|
/// | `datetime` / `timestamp` | **when the parser ran**, not when the evidence was made — this document is the analysis, and it is dated accordingly |
/// | `timestamp_desc` | `triage_report - <host>_triage_report.md: <section>` |
/// | `message` | the section's full markdown, verbatim |
/// | `hostname` | the host |
/// | `doc_type` | `triage_report` |
/// | `section` / `section_index` | which part of the report this is, and where it sat |
///
/// One document per `## ` section rather than one per report: a section is the
/// unit a reader (or a model) needs whole, and a single 60 KB blob is not
/// something an index can return usefully. `###` subsections stay with their
/// parent for the same reason.
///
/// Written as `.json` because `worker.py:307` skips anything whose name does not
/// end in `json` — `"x.jsonl".endswith("json")` is false.
pub fn write_report_ndjson(
    report_md: &str,
    out_dir: &Path,
    hostname: &str,
) -> Result<(usize, PathBuf)> {
    let filename = format!("{hostname}_triage_report.json");
    let path = out_dir.join(&filename);
    let mut w = BufWriter::new(File::create(&path)?);

    let now = chrono::Utc::now();
    let datetime = format!("{}Z", now.format("%Y-%m-%dT%H:%M:%S%.3f"));
    let millis = now.timestamp_millis();
    let source = format!("{hostname}_triage_report.md");

    let mut written = 0usize;
    for (i, (heading, body)) in split_sections(report_md).into_iter().enumerate() {
        let doc = json!({
            "datetime": datetime,
            "timestamp": millis,
            "timestamp_desc": format!("triage_report - {source}: {heading}"),
            "message": body,
            "hostname": hostname,
            "doc_type": "triage_report",
            "section": heading,
            "section_index": i,
        });
        serde_json::to_writer(&mut w, &doc)?;
        writeln!(w)?;
        written += 1;
    }
    w.flush()?;
    Ok((written, path))
}

/// Split a markdown report into `(heading, section text)` pairs on `## `.
///
/// `### ` subsections stay with their parent: a section is the unit a reader
/// (or a model) needs whole.
fn split_sections(md: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut heading = String::from("Header");
    let mut body = String::new();
    for line in md.lines() {
        if let Some(h) = line.strip_prefix("## ") {
            if !body.trim().is_empty() {
                out.push((heading.clone(), body.trim().to_string()));
            }
            heading = h.trim().to_string();
            body = format!("## {h}\n");
            continue;
        }
        body.push_str(line);
        body.push('\n');
    }
    if !body.trim().is_empty() {
        out.push((heading, body.trim().to_string()));
    }
    out
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
            ..Default::default()
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

    /// The narrative was unreachable: a consumer reading this tool's output from
    /// an index saw `doc_type: triage` and nothing else, so the report's own
    /// sections never reached the model at all. Now they arrive as their own
    /// timeline file, in the shape every other wiskess timeline file uses.
    #[test]
    fn the_report_is_written_as_an_ingestible_timeline_file() {
        let dir = std::env::temp_dir().join(format!("os-ndjson-{}-report", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let md = "# Triage Report: MY-DC02\n\n\
                  Preamble line.\n\n\
                  ## Log Continuity and Restoration\n\n\
                  POSSIBLE RESTORATION at 2026-05-09.\n\n\
                  ### A subsection\n\nstays with its parent\n\n\
                  ## Account Activity\n\nsome table\n";
        let (n, path) = write_report_ndjson(md, &dir, "MY-DC02").unwrap();

        // worker.py:307 skips anything not ending in `json`.
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "MY-DC02_triage_report.json");

        let text = std::fs::read_to_string(&path).unwrap();
        let docs: Vec<serde_json::Value> =
            text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(n, docs.len());
        assert_eq!(docs.len(), 3, "header + two sections: {docs:#?}");

        // The six fields every wiskess timeline document carries, plus the two
        // that separate cleanly out of a markdown report and no more.
        for d in &docs {
            for f in ["datetime", "timestamp", "timestamp_desc", "message", "hostname", "doc_type"] {
                assert!(d.get(f).is_some(), "missing {f}: {d}");
            }
            assert_eq!(d["doc_type"], "triage_report");
            assert_eq!(d["hostname"], "MY-DC02");
            assert_eq!(d.as_object().unwrap().len(), 8, "field set must stay small: {d}");
        }

        let continuity = docs.iter().find(|d| d["section"] == "Log Continuity and Restoration").unwrap();
        assert!(continuity["message"].as_str().unwrap().contains("POSSIBLE RESTORATION"));
        assert!(
            continuity["message"].as_str().unwrap().contains("### A subsection"),
            "a subsection belongs to its parent section, not to a document of its own"
        );
        assert!(continuity["timestamp_desc"].as_str().unwrap()
            .starts_with("triage_report - MY-DC02_triage_report.md: "));

        // Order is recoverable, so a consumer can reassemble the report.
        let idx: Vec<i64> = docs.iter().map(|d| d["section_index"].as_i64().unwrap()).collect();
        assert_eq!(idx, vec![0, 1, 2]);
    }

    /// The report is the analysis, not the evidence, so it is dated when the
    /// parser ran — not with any timestamp taken out of the collection.
    #[test]
    fn the_report_documents_are_dated_at_run_time() {
        let dir = std::env::temp_dir().join(format!("os-ndjson-{}-reptime", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let before = chrono::Utc::now().timestamp_millis();
        let (_, path) = write_report_ndjson("## Only\n\nbody\n", &dir, "H").unwrap();
        let after = chrono::Utc::now().timestamp_millis();

        let text = std::fs::read_to_string(&path).unwrap();
        let d: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        let ms = d["timestamp"].as_i64().unwrap();
        assert!((before..=after).contains(&ms), "{ms} not in {before}..={after}");
        // `datetime` and `timestamp` must describe the same instant.
        assert_eq!(normalise_time(d["datetime"].as_str().unwrap()).1, Some(ms));
    }

    /// An empty report still produces a valid (empty) file rather than a panic
    /// or a stray blank line the worker would choke on.
    #[test]
    fn an_empty_report_produces_an_empty_file() {
        let dir = std::env::temp_dir().join(format!("os-ndjson-{}-empty", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (n, path) = write_report_ndjson("", &dir, "H").unwrap();
        assert_eq!(n, 0);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
    }

    /// The event NDJSON carries events. The narrative and the restoration
    /// estimate have their own files, and repeating them here would be the same
    /// text indexed twice — the worker ingests every `*json` in the folder.
    #[test]
    fn the_event_ndjson_does_not_repeat_the_narrative() {
        let dir = std::env::temp_dir().join(format!("os-ndjson-{}-norepeat", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (_, path) =
            write_opensearch_ndjson(&[ev("2026-05-05T09:50:31.422Z", "hayabusa", "high")], &dir, "H")
                .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        for d in text.lines().map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()) {
            assert_ne!(d["doc_type"], "triage_report");
            assert_ne!(d["doc_type"], "restoration");
        }
    }

    #[test]
    fn sub_second_precision_is_preserved_to_milliseconds() {
        assert_eq!(normalise_time("2026-05-05T09:50:31.4Z").0, "2026-05-05T09:50:31.400Z");
        assert_eq!(normalise_time("2026-05-05T09:50:31Z").0, "2026-05-05T09:50:31.000Z");
    }
}
