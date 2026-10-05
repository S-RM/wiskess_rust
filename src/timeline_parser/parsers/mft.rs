//! $MFT — file creation events.
//!
//! This is the largest artifact in a collection (6.8 M rows on the host that
//! prompted this work) and the one the missed webshells were in. Two things were
//! wrong, and only the second is about tuning.
//!
//! **The extension gate dropped the row before an event existed.** Anything whose
//! extension was not in a nine-entry literal list was `continue`d, so a `.jsp`
//! written into a ColdFusion webroot never became an event — the path rules, the
//! classifier and `is_triage_hit()` were never consulted, because there was
//! nothing left to consult them about. The list now comes from
//! [`crate::timeline_parser::detectors::file_classes`], which knows what a server-side script is.
//! Measured on that collection, widening it adds ~27 k rows to ~191 k: `.cfm`
//! 15,646, `.jar` 6,591, `.jsp` **14**.
//!
//! **A `high` path rule could not raise the severity.** `severity = if
//! hit.severity == "high" { "high" } else { severity }` is a self-assignment for
//! anything that is not exactly `high` and a no-op for anything that is, so a
//! webroot hit left the event at `med` — one step below the threshold
//! `is_triage_hit()` uses. Severity now goes through [`raise`].
//!
//! Both MFT parses are handled: `MFTECmd.csv` (`ParentPath` + `FileName` +
//! `Extension`, and a **relative** `.\…` parent) and `mft_dump.csv` (`FullPath`
//! only, `/`-separated, plus `IsDeleted` and `HasAlternateDataStreams`). Only one
//! is read per host — see [`crate::timeline_parser::parsers::artifacts`] — because they are the
//! same $MFT and parsing both would double every file event.

use anyhow::Result;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::{raise, PipelineConfig};
use crate::timeline_parser::detectors::file_classes::{base_of, ext_of, is_archive, is_script, join_path, normalise_path};
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::suspicious_paths::SuspiciousPathDetector;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::detectors::Attack;
use crate::timeline_parser::output::event::UnifiedEvent;
use crate::timeline_parser::parsers::columns::{
    self, Columns, Field, DATETIME, EXTENSION, FILE_NAME, FILE_SIZE, FULL_PATH, PARENT_PATH,
};

/// Something that names the file. Neither shape's column is required alone, but
/// one of them has to be there: with no name and no path there is nothing to
/// describe, match or classify, and 6.8 M rows would come out as zero events —
/// which is the failure this whole module is a fix for.
const NAME_OR_PATH: Field =
    Field::required("name_or_path", &["FileName", "FullPath", "file_name", "full_name"]);

/// Which timestamp column this melted row came from.
///
/// The timeliner emits one row per timestamp per file, so this decides what the
/// row *means*. Without it every row would be read as a creation and the artifact
/// would quadruple.
const TS_DESC: Field = Field::required("timestamp_desc", &["timestamp_desc"]);

/// Is this row the file's `$STANDARD_INFORMATION` creation timestamp?
///
/// `MFTECmd.csv` spells it `Created0x10` and `mft_dump.csv` `StandardInfoCreated`.
/// The `$FILE_NAME` copies (`Created0x30`, `FileNameCreated`) are deliberately
/// **not** accepted: they are a second record of the same creation, and taking
/// both would emit every file event twice.
fn is_si_creation(ts_desc: &str) -> bool {
    let d = ts_desc.to_ascii_lowercase();
    d.contains("created0x10") || d.contains("standardinfocreated")
}

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
        "mft",
        filepath,
        &headers,
        &[
            DATETIME,
            TS_DESC,
            NAME_OR_PATH,
            FILE_NAME.optional_form(),
            PARENT_PATH,
            FULL_PATH,
            EXTENSION,
            FILE_SIZE,
            // `mft_dump.csv` only. Both are annotations on a row that was kept for
            // another reason — deliberately not keep-reasons of their own, because
            // on some hosts either would be six figures.
            Field::optional("is_deleted", &["IsDeleted"]),
            Field::optional("has_ads", &["HasAlternateDataStreams"]),
        ],
    );

    for result in rdr.records() {
        let Ok(record) = result else { continue };
        rows += 1;

        let ts = cols.get(&record, "datetime").to_string();
        if ts.is_empty() || !cfg.in_timewindow(&ts) {
            continue;
        }
        if !is_si_creation(cols.get(&record, "timestamp_desc")) {
            continue;
        }

        // `FullPath` when the source has it, otherwise parent + name. Normalised
        // either way: MFTECmd's parent is relative (`.\ColdFusion2018\…`) and
        // mft_dump's is `/`-separated, and a rule written for one spelling misses
        // the other.
        let filename = cols.get(&record, "file_name");
        let derived = cols.get(&record, "full_path");
        let full_path = if derived.is_empty() {
            join_path(cols.get(&record, "parent_path"), filename)
        } else {
            normalise_path(derived)
        };
        // mft_dump has no FileName column; the name is the tail of the path.
        let filename = if filename.is_empty() { base_of(&full_path) } else { filename.to_string() };

        let extension = {
            let e = cols.get_lower(&record, "extension");
            if e.is_empty() { ext_of(&filename) } else { e }
        };

        let ta_hits = ta_detector.scan(&full_path);
        let ioc_hits = ioc_matcher.check(&full_path);
        let path_hits = path_detector.check_path(&full_path);
        let has_detection = !ta_hits.is_empty() || !ioc_hits.is_empty() || !path_hits.is_empty();

        // MFT is one of the artifacts the operator named as needing filtering, so
        // the gate stays. What changed is what counts as interesting: a webshell
        // is a text file the server executes, so the interpreter's extension is
        // the signal.
        let script = is_script(&extension);
        let archive = is_archive(&extension);
        if !has_detection && !script && !archive {
            continue;
        }

        let mut indicators: Vec<String> = Vec::new();
        let mut severity = if script { "med".to_string() } else { "low".to_string() };
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
        indicators.extend(ioc_hits.clone());
        if !ioc_hits.is_empty() {
            raise(&mut severity, "high");
        }

        // Kept for continuity with the tools already reading these indicators:
        // "executable" here means anything the host will execute or interpret,
        // which is what `is_script` decides.
        if script {
            indicators.push("MFT:executable_created".to_string());
        } else if archive {
            indicators.push("MFT:archive_created".to_string());
        }

        let flag = |v: &str| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "yes" | "1");
        if flag(cols.get(&record, "has_ads")) {
            indicators.push("MFT:alternate_data_stream".to_string());
            raise(&mut severity, "med");
        }
        let deleted = flag(cols.get(&record, "is_deleted"));
        if deleted {
            indicators.push("MFT:created_then_deleted".to_string());
        }

        let size = cols.get(&record, "file_size");
        let mut description = format!("File created: {}", full_path);
        if !size.is_empty() {
            description.push_str(&format!(" ({} bytes)", size));
        }
        if deleted {
            description.push_str(" [deleted]");
        }

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "mft".to_string(),
            event_type: "file_created".to_string(),
            severity,
            description,
            indicators,
            mitre_tactic: attack.tactic,
            mitre_technique: attack.technique,
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "mft_suspicious_file".to_string(),
            ..Default::default()
        });
    }

    columns::note_rows("mft", rows);
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline_parser::output::supertimeline::is_triage_hit;
    use std::io::Write;

    /// `MFTECmd.csv`'s header, verbatim.
    const MFTECMD_HEADER: &str =
        "datetime,timestamp_desc,message,ParentPath,FileName,Extension,FileSize,hostname,\
         doc_type,timestamp";

    /// `mft_dump.csv`'s header, verbatim — no FileName, no Extension, no ParentPath.
    const DUMP_HEADER: &str = "datetime,timestamp_desc,message,FullPath,TotalEntrySize,FileSize,\
        StandardInfoFlags,FileNameFlags,IsADirectory,IsDeleted,HasAlternateDataStreams,hostname,\
        doc_type,timestamp";

    fn run(name: &str, header: &str, body: &str) -> Vec<UnifiedEvent> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "{header}").unwrap();
        f.write_all(body.as_bytes()).unwrap();
        drop(f);
        parse(
            &path,
            &PipelineConfig::default(),
            &TAToolDetector::new(Path::new("tools/threat_intel")).unwrap(),
            &IOCMatcher::new(None).unwrap(),
            &SuspiciousPathDetector::new(Path::new("tools/threat_intel")).unwrap(),
            "MY-WEB01",
        )
        .unwrap()
    }

    /// The case that started this: a JSP dropped into a relative-path webroot has
    /// to reach the curated timeline, which is the file the operator reads.
    #[test]
    fn a_jsp_created_under_a_webroot_is_high_and_reaches_the_triage_cut() {
        let events = run(
            "MFTECmd.csv",
            MFTECMD_HEADER,
            "2026-06-24T10:58:22.919Z,mft - MFTECmd.csv: Created0x10,m,\
             .\\app\\cfusion\\wwwroot\\cf_scripts\\scripts\\ajax,shell.jsp,.jsp,36984,MY-WEB01,mft,1\n",
        );
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.severity, "high", "a webroot script write is a high path rule: {:?}", e.indicators);
        assert!(e.indicators.iter().any(|i| i == "PATH:script_in_web_served_tree"), "{:?}", e.indicators);
        assert!(e.indicators.iter().any(|i| i == "MFT:executable_created"));
        assert!(is_triage_hit(e), "the operator reads the curated timeline");
        assert!(e.description.contains("36984 bytes"), "{}", e.description);
        assert_eq!(
            e.mitre_technique, "T1505.003",
            "the rule pack's `mitre:` has to reach the event — every parser used to drop it"
        );
    }

    /// A `.jar` shipped by the product is not a finding, and the extension gate
    /// widening must not make it one.
    #[test]
    fn a_vendor_jar_is_carried_but_is_not_a_finding() {
        let events = run(
            "MFTECmd.csv",
            MFTECMD_HEADER,
            "2026-01-02T03:04:05.000Z,mft - MFTECmd.csv: Created0x10,m,\
             .\\Program Files\\AppServer\\lib,jsp-api.jar,.jar,84210,MY-WEB01,mft,1\n",
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, "med", "a script extension, but no rule fired");
        assert!(!events[0].indicators.iter().any(|i| i.starts_with("PATH:")), "{:?}", events[0].indicators);
        assert!(!is_triage_hit(&events[0]));
    }

    /// The $FILE_NAME timestamps are a second copy of the same creation. Reading
    /// both would double every file event on the host.
    #[test]
    fn only_the_standard_information_creation_row_is_an_event() {
        let events = run(
            "MFTECmd.csv",
            MFTECMD_HEADER,
            "2026-01-02T03:04:05.000Z,mft - MFTECmd.csv: Created0x10,m,.\\tmp,a.exe,.exe,10,H,mft,1\n\
             2026-01-02T03:04:05.000Z,mft - MFTECmd.csv: Created0x30,m,.\\tmp,a.exe,.exe,10,H,mft,2\n\
             2026-01-02T03:04:05.000Z,mft - MFTECmd.csv: LastModified0x10,m,.\\tmp,a.exe,.exe,10,H,mft,3\n",
        );
        assert_eq!(events.len(), 1, "got {:?}", events.iter().map(|e| &e.description).collect::<Vec<_>>());
    }

    /// The other parse of the same $MFT: one column instead of three, and the
    /// findings have to come out the same.
    #[test]
    fn the_dump_parse_derives_the_name_and_extension_from_the_path() {
        let events = run(
            "mft_dump.csv",
            DUMP_HEADER,
            "2026-06-24T10:58:22.919Z,mft_dump - mft.csv: StandardInfoCreated,m,\
             /app/cfusion/wwwroot/cf_scripts/scripts/ajax/shell.jsp,40960,36984,,,false,false,false,\
             MY-WEB01,mft_dump,1\n",
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, "high");
        assert!(events[0].indicators.iter().any(|i| i == "PATH:script_in_web_served_tree"));
        assert!(events[0].indicators.iter().any(|i| i == "MFT:executable_created"),
            "the extension has to be derived from the path: {:?}", events[0].indicators);
        assert!(events[0].description.contains(r"\app\cfusion\wwwroot"), "{}", events[0].description);
    }

    /// `IsDeleted` / `HasAlternateDataStreams` exist only in the dump parse, and
    /// only annotate a row that was kept for another reason.
    #[test]
    fn the_dump_only_columns_annotate_the_row() {
        let events = run(
            "mft_dump.csv",
            DUMP_HEADER,
            "2026-01-02T03:04:05.000Z,mft_dump - mft.csv: StandardInfoCreated,m,\
             /Users/testuser/AppData/Local/Temp/stage.exe,40960,1024,,,false,true,true,\
             MY-WEB01,mft_dump,1\n",
        );
        assert_eq!(events.len(), 1);
        assert!(events[0].indicators.iter().any(|i| i == "MFT:created_then_deleted"));
        assert!(events[0].indicators.iter().any(|i| i == "MFT:alternate_data_stream"));
        assert!(events[0].description.ends_with("[deleted]"), "{}", events[0].description);
    }

    /// Ordinary churn still stays out — MFT is a filtered artifact.
    #[test]
    fn ordinary_files_are_not_events() {
        let events = run(
            "MFTECmd.csv",
            MFTECMD_HEADER,
            "2026-01-02T03:04:05.000Z,mft - MFTECmd.csv: Created0x10,m,.\\docs,notes.txt,.txt,10,H,mft,1\n\
             2026-01-02T03:04:05.000Z,mft - MFTECmd.csv: Created0x10,m,.\\pics,a.png,.png,10,H,mft,2\n",
        );
        assert!(events.is_empty());
    }

    /// The header-drift failure mode, on the biggest artifact there is: a rename
    /// must be reported, not read as an empty column.
    #[test]
    fn a_file_that_names_neither_a_path_nor_a_filename_is_a_coverage_failure() {
        // No `reset()`: the record is append-only and these tests share a process,
        // so clearing it would race the other parsers' resolutions.
        let events = run(
            "MFTECmd.csv",
            "datetime,timestamp_desc,message,SomeOtherColumn,hostname,doc_type,timestamp",
            "2026-01-02T03:04:05.000Z,mft - MFTECmd.csv: Created0x10,m,x,H,mft,1\n",
        );
        assert!(events.is_empty());
        let f = columns::failures();
        assert!(
            f.iter().any(|f| f.artifact == "mft" && f.logical == "name_or_path"),
            "the run has to say it could not read the file names: {:?}",
            f.iter().map(|f| f.describe()).collect::<Vec<_>>()
        );
    }
}
