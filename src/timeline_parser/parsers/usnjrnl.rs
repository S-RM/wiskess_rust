//! $UsnJrnl — file create / delete / rename records.
//!
//! This parser emitted **zero** events from 439,051 rows, for two independent
//! reasons, neither of which produced a warning:
//!
//! 1. it asked for a column called `UpdateReasons`, which neither current parse
//!    provides (both call it `reason`), so every row read an empty reason string,
//!    matched no verb, and hit `continue`;
//! 2. it matched reason text with `.contains("FileCreate")`, which is one of two
//!    vocabularies in use — `usnjrnl_j_rusty.csv` spells the same flag
//!    `USN_REASON_FILE_CREATE`, so even a resolved column would have matched
//!    nothing.
//!
//! Reasons are therefore normalised to canonical tokens before anything looks at
//! them, and the canonical form is what reaches the description — so the two
//! parses of one volume produce comparable output instead of two dialects.

use anyhow::Result;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::{raise, PipelineConfig};
use crate::timeline_parser::detectors::file_classes::{
    ext_of, is_archive, is_noise, is_script, join_path, normalise_path,
};
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::suspicious_paths::SuspiciousPathDetector;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::detectors::Attack;
use crate::timeline_parser::output::event::UnifiedEvent;
use crate::timeline_parser::parsers::columns::{
    self, Columns, DATETIME, ENTRY_NUMBER, EXTENSION, FILE_NAME, FULL_PATH, PARENT_PATH, REASON,
};

/// The USN reason flags this parser reasons about, and their canonical spelling.
///
/// Keys are the reason token with `USN_REASON_` stripped, upper-cased, and `_`
/// removed — the shape [`canonical_reasons`] reduces both vocabularies to.
const REASON_NAMES: &[(&str, &str)] = &[
    ("FILECREATE", "FileCreate"),
    ("FILEDELETE", "FileDelete"),
    ("RENAMENEWNAME", "RenameNewName"),
    ("RENAMEOLDNAME", "RenameOldName"),
    ("CLOSE", "Close"),
    ("DATAEXTEND", "DataExtend"),
    ("DATAOVERWRITE", "DataOverwrite"),
    ("DATATRUNCATION", "DataTruncation"),
    ("NAMEDDATAEXTEND", "NamedDataExtend"),
    ("NAMEDDATAOVERWRITE", "NamedDataOverwrite"),
    ("NAMEDDATATRUNCATION", "NamedDataTruncation"),
    ("BASICINFOCHANGE", "BasicInfoChange"),
    ("SECURITYCHANGE", "SecurityChange"),
    ("EXTENDEDATTRIBUTECHANGE", "ExtendedAttributeChange"),
    ("OBJECTIDCHANGE", "ObjectIdChange"),
    ("HARDLINKCHANGE", "HardLinkChange"),
    ("INDEXABLECHANGE", "IndexableChange"),
    ("STREAMCHANGE", "StreamChange"),
    ("COMPRESSIONCHANGE", "CompressionChange"),
    ("ENCRYPTIONCHANGE", "EncryptionChange"),
    ("REPARSEPOINTCHANGE", "ReparsePointChange"),
    ("TRANSACTEDCHANGE", "TransactedChange"),
    ("INTEGRITYCHANGE", "IntegrityChange"),
    ("DESIREDSTORAGECLASSCHANGE", "DesiredStorageClassChange"),
];

/// Reduce a reason field to a sorted set of canonical flag names.
///
/// `"DataExtend|Close"` and `"USN_REASON_CLOSE | USN_REASON_DATA_EXTEND"` are the
/// same record written by two tools; both come out as `["Close", "DataExtend"]`.
/// A flag this table does not know is kept verbatim rather than dropped — an
/// unrecognised reason is still evidence.
pub fn canonical_reasons(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = raw
        .split(['|', ',', ';'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|token| {
            let folded: String = token
                .to_uppercase()
                .replace("USN_REASON_", "")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect();
            REASON_NAMES
                .iter()
                .find(|(k, _)| *k == folded)
                .map(|(_, name)| (*name).to_string())
                .unwrap_or_else(|| token.to_string())
        })
        .collect();
    out.sort();
    out.dedup();
    out
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
        "usnjrnl",
        filepath,
        &headers,
        &[DATETIME, FILE_NAME, REASON, EXTENSION, PARENT_PATH, FULL_PATH, ENTRY_NUMBER],
    );

    for result in rdr.records() {
        let Ok(record) = result else { continue };
        rows += 1;

        let ts = cols.get(&record, "datetime").to_string();
        if ts.is_empty() || !cfg.in_timewindow(&ts) {
            continue;
        }

        let name = cols.get(&record, "file_name");
        let reasons = canonical_reasons(cols.get(&record, "reason"));
        let has = |flag: &str| reasons.iter().any(|r| r == flag);

        let is_create = has("FileCreate");
        let is_delete = has("FileDelete");
        let is_rename = has("RenameNewName");
        if !is_create && !is_delete && !is_rename {
            continue;
        }

        // `full_name` when the source derived it (the rusty parse), otherwise
        // parent + name. `usnjrnl-j-file.csv`'s ParentPath is empty on every row,
        // so on that file this is the bare filename and no path rule can fire —
        // which is why the registry prefers the other parse.
        // `full_name` when the source derived it, normalised: the rusty parse
        // writes `[root]/Users/...` with forward slashes, and MFT writes
        // `\Users\...`. Left raw, the same file appears in two spellings in one
        // supertimeline, `classify.rs` matches no vendor tree on the USN rows
        // (so a Trend Micro or Defender path stays unclassified there while the
        // MFT row for it is classified), and anything downstream grepping for
        // `\Users\` silently misses this artefact. `join_path` already
        // normalises, so the two branches now agree.
        let derived = cols.get(&record, "full_path");
        let full_path = if !derived.is_empty() {
            normalise_path(derived)
        } else {
            join_path(cols.get(&record, "parent_path"), name)
        };

        // `Extension` is absent from the rusty parse, so derive it rather than
        // treating every row as extensionless — which would put every script
        // create below the volume gate.
        let extension = {
            let e = cols.get_lower(&record, "extension");
            if e.is_empty() { ext_of(name) } else { e }
        };

        let ta_hits = ta_detector.scan(&full_path);
        let ioc_hits = ioc_matcher.check(&full_path);
        let path_hits = path_detector.check_path(&full_path);
        let has_detection = !ta_hits.is_empty() || !ioc_hits.is_empty() || !path_hits.is_empty();

        // USN is one of the artifacts the operator named as needing filtering —
        // 439,051 rows on one host — so the volume gate stays. What changed is
        // what counts as interesting: `is_script` now includes server-side script
        // extensions, so a `.jsp` written into a webroot is no longer discarded
        // before any rule sees it.
        if !has_detection {
            if is_noise(&extension) {
                continue;
            }
            let keep = (is_script(&extension) && (is_create || is_delete || is_rename))
                || (is_archive(&extension) && is_create);
            if !keep {
                continue;
            }
        }

        let mut indicators: Vec<String> = Vec::new();
        let mut severity = "low".to_string();

        if is_script(&extension) {
            if is_create {
                indicators.push("USN:executable_created".to_string());
                raise(&mut severity, "med");
            }
            if is_delete {
                indicators.push("USN:executable_deleted".to_string());
                raise(&mut severity, "med");
            }
            if is_rename {
                indicators.push("USN:executable_renamed".to_string());
                raise(&mut severity, "med");
            }
        }
        if is_archive(&extension) && is_create {
            indicators.push("USN:archive_created".to_string());
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
        indicators.extend(ioc_hits.clone());
        if !ioc_hits.is_empty() {
            raise(&mut severity, "high");
        }

        // A row that got through the volume gate is being kept, so it gets an
        // indicator saying which verb kept it. Dropping it here instead — which
        // is what this did — discards a row the gate already decided was worth
        // having, and says nothing about it.
        if indicators.is_empty() {
            let verb = if is_create { "created" } else if is_delete { "deleted" } else { "renamed" };
            indicators.push(format!("USN:file_{verb}"));
        }

        let event_type = if is_create {
            "file_created"
        } else if is_delete {
            "file_deleted"
        } else {
            "file_modified"
        };

        // The MFT entry number leads the path because it is short and it is the
        // file's identity: two same-second records of two different files that
        // share a name are distinguishable here and nowhere else.
        let entry = cols.get(&record, "entry_number");
        let description = if entry.is_empty() {
            format!("{}: {}", reasons.join("|"), full_path)
        } else {
            format!("{} [entry {}]: {}", reasons.join("|"), entry, full_path)
        };

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "usnjrnl".to_string(),
            event_type: event_type.to_string(),
            severity,
            description,
            indicators,
            mitre_tactic: attack.tactic,
            mitre_technique: attack.technique,
            hostname: hostname.to_string(),
            detection_rule: "usnjrnl_suspicious".to_string(),
            ..Default::default()
        });
    }

    columns::note_rows("usnjrnl", rows);
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// The bug: neither file's spelling matched what the code looked for.
    #[test]
    fn both_reason_vocabularies_reduce_to_the_same_flags() {
        assert_eq!(canonical_reasons("DataExtend|Close"), vec!["Close", "DataExtend"]);
        assert_eq!(
            canonical_reasons("USN_REASON_CLOSE | USN_REASON_DATA_EXTEND"),
            vec!["Close", "DataExtend"]
        );
        assert_eq!(
            canonical_reasons("USN_REASON_FILE_CREATE | USN_REASON_CLOSE"),
            vec!["Close", "FileCreate"]
        );
        assert_eq!(canonical_reasons("FileCreate|Close"), vec!["Close", "FileCreate"]);
    }

    #[test]
    fn an_unknown_reason_flag_is_kept_rather_than_dropped() {
        let r = canonical_reasons("USN_REASON_SOMETHING_NEW|Close");
        assert!(r.contains(&"Close".to_string()));
        assert!(
            r.iter().any(|t| t.contains("SOMETHING_NEW")),
            "an unrecognised flag is still evidence: {r:?}"
        );
    }

    #[test]
    fn an_empty_reason_yields_no_flags_and_never_a_guess() {
        assert!(canonical_reasons("").is_empty());
        assert!(canonical_reasons("  |  ").is_empty());
    }

    fn run(name: &str, content: &str) -> Vec<UnifiedEvent> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        std::fs::File::create(&path).unwrap().write_all(content.as_bytes()).unwrap();
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

    /// End to end on the schema that produced zero events.
    #[test]
    fn the_rusty_parse_yields_events_and_carries_the_directory() {
        let events = run(
            "usnjrnl_j_rusty.csv",
            "datetime,timestamp_desc,message,file_name,full_name,file_name_length,reason,file_attributes,hostname,doc_type,timestamp\n\
             2026-01-02T03:04:05.000Z,d,m,shell.jsp,[root]/inetpub/wwwroot/uploads/shell.jsp,9,USN_REASON_FILE_CREATE | USN_REASON_CLOSE,FILE_ATTRIBUTE_ARCHIVE,MY-WEB01,usnjrnl,1\n\
             2026-01-02T03:04:06.000Z,d,m,notes.txt,[root]/Users/testuser/notes.txt,9,USN_REASON_FILE_CREATE | USN_REASON_CLOSE,FILE_ATTRIBUTE_ARCHIVE,MY-WEB01,usnjrnl,2\n",
        );
        assert_eq!(events.len(), 1, "the .txt is below the volume gate, the .jsp is not");
        let e = &events[0];
        assert_eq!(e.event_type, "file_created");
        assert_eq!(e.severity, "high", "a webroot script write is a high path rule");
        assert!(e.indicators.iter().any(|i| i == "PATH:script_in_web_served_tree"), "{:?}", e.indicators);
        assert!(
            e.description.contains("wwwroot"),
            "the derived path must reach the description: {}",
            e.description
        );
        assert!(e.description.starts_with("Close|FileCreate:"), "{}", e.description);
        // One spelling of a path per output file. The source writes
        // `[root]/inetpub/...`; MFT writes `\inetpub\...` for the same file, and a
        // consumer that has to know which artefact a row came from before it can
        // grep it is a consumer that will miss this one.
        assert!(
            e.description.contains("\\inetpub\\wwwroot\\uploads\\shell.jsp"),
            "the path must be normalised, not carried in the source's dialect: {}",
            e.description
        );
        assert!(!e.description.contains("[root]"), "{}", e.description);
        assert!(!e.description.contains('/'), "{}", e.description);
    }

    /// The same events in the other vocabulary. The path rule cannot fire here —
    /// that file's ParentPath is empty — which is exactly why the registry
    /// prefers the other one.
    #[test]
    fn the_j_file_parse_yields_the_same_verbs_from_bare_filenames() {
        let events = run(
            "usnjrnl-j-file.csv",
            "datetime,timestamp_desc,message,file_name,Extension,EntryNumber,ParentEntryNumber,ParentPath,reason,file_attributes\n\
             2026-01-02T03:04:05.000Z,d,m,shell.jsp,.jsp,4211,10,,FileCreate|Close,Archive\n",
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "file_created");
        assert!(events[0].indicators.iter().any(|i| i == "USN:executable_created"));
        assert!(
            events[0].description.contains("[entry 4211]"),
            "the entry number is the file identity: {}",
            events[0].description
        );
    }

    /// Two records of two different files that share a name in the same second
    /// must not collapse into one.
    #[test]
    fn two_same_second_records_are_distinguished_by_their_entry_number() {
        let events = run(
            "usnjrnl-j-file.csv",
            "datetime,file_name,Extension,EntryNumber,ParentPath,reason\n\
             2026-01-02T03:04:05.000Z,setup.exe,.exe,101,,FileCreate|Close\n\
             2026-01-02T03:04:05.000Z,setup.exe,.exe,202,,FileCreate|Close\n",
        );
        assert_eq!(events.len(), 2);
        assert_ne!(events[0].description, events[1].description);
    }

    /// The gate is still a gate: USN is one of the artifacts the operator named
    /// as needing filtering.
    #[test]
    fn ordinary_churn_stays_out() {
        let events = run(
            "usnjrnl-j-file.csv",
            "datetime,file_name,Extension,EntryNumber,ParentPath,reason\n\
             2026-01-02T03:04:05.000Z,app.log,.log,1,,FileCreate|Close\n\
             2026-01-02T03:04:05.000Z,x.tmp,.tmp,2,,FileCreate|Close\n\
             2026-01-02T03:04:05.000Z,report.docx,.docx,3,,FileCreate|Close\n",
        );
        assert!(events.is_empty(), "got {:?}", events.iter().map(|e| &e.description).collect::<Vec<_>>());
    }

    /// A record with none of the three verbs is not a file event.
    #[test]
    fn a_metadata_only_record_is_not_an_event() {
        let events = run(
            "usnjrnl_j_rusty.csv",
            "datetime,file_name,full_name,reason\n\
             2026-01-02T03:04:05.000Z,tool.exe,[root]/Windows/System32/tool.exe,USN_REASON_BASIC_INFO_CHANGE | USN_REASON_CLOSE\n",
        );
        assert!(events.is_empty());
    }
}
