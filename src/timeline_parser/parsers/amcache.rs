//! Amcache — the OS's own inventory of binaries it has seen, with SHA1s.
//!
//! Two changes here, both about not discarding evidence.
//!
//! **`ProductName` no longer drops the row.** Six product names were matched
//! against a `ProductName` field and the row `continue`d — *before any detector
//! ran*. That field is metadata a binary reports about itself: an attacker who
//! wants their tool ignored only has to call it "Microsoft Windows". Using it to
//! discard evidence inverts the trust model. The rows are now kept and classified
//! `vendor:self-reported`, which keeps them out of the curated triage cut (the
//! effect the drop was reaching for) while leaving them in the supertimeline and
//! `_triage.json`, and — importantly — lets their SHA1s reach the hash-reputation
//! pass, which is precisely where a mislabelled binary is caught.
//!
//! **The severity clamp is gone.** `severity = if hit.severity == "high" { "high" }
//! else { "med" }` lowered a `crit` rule to `med`. It goes through [`raise`], which
//! never lowers.

use anyhow::Result;
use regex::Regex;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::{raise, PipelineConfig};
use crate::timeline_parser::detectors::file_classes::normalise_path;
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::suspicious_paths::SuspiciousPathDetector;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::detectors::Attack;
use crate::timeline_parser::output::event::UnifiedEvent;
use crate::timeline_parser::parsers::columns::{self, Columns, Field, DATETIME, EXTENSION, MESSAGE, USER_NAME};

/// Products whose own claim about themselves is taken as a *classification*, not
/// as grounds for deletion. See the module doc.
static KNOWN_GOOD_PRODUCTS: &[&str] = &[
    "microsoft malware protection",
    "microsoft windows",
    "windows update",
    "microsoft .net framework",
    "microsoft visual c++",
    "windows defender",
];

/// The binary's path. Required: it is the row's subject.
const PATH: Field = Field::required("path", &["FullPath", "full_name", "Path", "FullName"]);
const PRODUCT: Field = Field::optional("product", &["ProductName"]);
const SHA1: Field = Field::optional("sha1", &["SHA1", "SHA1Hash"]);

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
        "amcache",
        filepath,
        &headers,
        &[DATETIME, MESSAGE, PATH, PRODUCT, SHA1, EXTENSION],
    );

    for result in rdr.records() {
        let Ok(record) = result else { continue };
        rows += 1;

        let ts = cols.get(&record, "datetime").to_string();
        if ts.is_empty() {
            continue;
        }
        let full_path = normalise_path(cols.get(&record, "path"));
        let product = cols.get(&record, "product");
        let sha1 = cols.get(&record, "sha1");
        if full_path.is_empty() {
            continue;
        }

        let self_reported_vendor =
            KNOWN_GOOD_PRODUCTS.iter().any(|p| product.to_lowercase().contains(p));

        let path_hits = path_detector.check_path(&full_path);
        let ta_hits = ta_detector.scan(&full_path);
        let ioc_hits = ioc_matcher.check(&full_path);
        let hash_hits = ioc_matcher.check_hash(sha1);
        let has_detection = !path_hits.is_empty()
            || !ta_hits.is_empty()
            || !ioc_hits.is_empty()
            || !hash_hits.is_empty();

        if !has_detection && !cfg.emit_quiet_baseline {
            continue;
        }

        let mut indicators: Vec<String> = Vec::new();
        let mut severity = if has_detection { "low".to_string() } else { "info".to_string() };

        // Always record the SHA1 so the post-parse hash-lookup pass can enrich every
        // Amcache entry, not just the ones that already matched an IOC.
        if !sha1.is_empty() {
            indicators.push(format!("HASH:{}", sha1.to_lowercase()));
        }

        // Amcache is an execution-evidence artifact, so the tactic holds whatever
        // fired; a rule hit supplies the technique.
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
        indicators.extend(hash_hits.clone());
        if !hash_hits.is_empty() {
            raise(&mut severity, "high");
        }

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "amcache".to_string(),
            event_type: "process_execution".to_string(),
            severity,
            description: format!("Amcache: {} | Product: {} | SHA1: {}", full_path, product, sha1),
            indicators,
            mitre_tactic: attack.tactic,
            mitre_technique: attack.technique,
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "amcache_analysis".to_string(),
            classification: if self_reported_vendor {
                "vendor:self-reported".to_string()
            } else {
                String::new()
            },
            ..Default::default()
        });
    }

    columns::note_rows("amcache", rows);
    Ok(events)
}

/// Parse `regripper_amcache.csv` — a TLN-style export with no dedicated SHA1 column.
/// Schema: datetime,timestamp_desc,message,source,system,user,description,hostname,timestamp
/// The SHA1 is embedded in the message as `... <path> (<40-hex>)`, e.g.
///   `AmCache; ; ; Key LastWrite - c:\...\dismhost.exe (7fe71bf5...20f9)`
/// We extract both the path text and the SHA1 so the entry flows through the same
/// detectors and the downstream hash-lookup pass.
pub fn parse_regripper(
    filepath: &Path,
    cfg: &PipelineConfig,
    ta_detector: &TAToolDetector,
    ioc_matcher: &IOCMatcher,
    path_detector: &SuspiciousPathDetector,
    hostname: &str,
) -> Result<Vec<UnifiedEvent>> {
    let sha1_re = Regex::new(r"\b([0-9a-fA-F]{40})\b").unwrap();
    let mut events = Vec::new();
    let mut rows = 0usize;

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    let cols = Columns::resolve(
        "amcache-regripper",
        filepath,
        &headers,
        &[
            DATETIME,
            MESSAGE,
            Field::optional("description", &["description", "Description"]),
            USER_NAME,
        ],
    );

    for result in rdr.records() {
        let Ok(record) = result else { continue };
        rows += 1;

        let ts = cols.get(&record, "datetime").to_string();
        if ts.is_empty() {
            continue;
        }
        let message = cols.get(&record, "message");
        let desc_field = cols.get(&record, "description");
        // Prefer whichever field carries the path+hash detail.
        let detail = if message.len() >= desc_field.len() { message } else { desc_field };
        if detail.is_empty() {
            continue;
        }

        let sha1 = sha1_re.captures(detail)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_lowercase())
            .unwrap_or_default();

        let path_hits = path_detector.check_path(detail);
        let ta_hits = ta_detector.scan(detail);
        let ioc_hits = ioc_matcher.check(detail);
        let hash_hits = ioc_matcher.check_hash(&sha1);
        let has_detection = !path_hits.is_empty()
            || !ta_hits.is_empty()
            || !ioc_hits.is_empty()
            || !hash_hits.is_empty();

        if !has_detection && !cfg.emit_quiet_baseline {
            continue;
        }

        let mut indicators: Vec<String> = Vec::new();
        if !sha1.is_empty() {
            indicators.push(format!("HASH:{}", sha1));
        }

        let mut severity = if has_detection { "low".to_string() } else { "info".to_string() };
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
        indicators.extend(hash_hits.clone());
        if !hash_hits.is_empty() {
            raise(&mut severity, "high");
        }

        let desc_trunc = detail.char_indices().nth(220).map_or(detail, |(i, _)| &detail[..i]);
        events.push(UnifiedEvent {
            timestamp: ts,
            source: "amcache-regripper".to_string(),
            event_type: "process_execution".to_string(),
            severity,
            description: format!("Amcache(RegRipper): {}", desc_trunc),
            indicators,
            mitre_tactic: attack.tactic,
            mitre_technique: attack.technique,
            user: cols.get(&record, "user_name").to_string(),
            hostname: hostname.to_string(),
            detection_rule: "amcache_regripper_analysis".to_string(),
            ..Default::default()
        });
    }

    columns::note_rows("amcache-regripper", rows);
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline_parser::output::supertimeline::is_triage_hit;
    use std::io::Write;

    /// `amcache.csv`'s header, verbatim.
    const HEADER: &str = "datetime,timestamp_desc,message,FullPath,ProductName,SHA1,FileExtension,\
        hostname,doc_type,timestamp";

    fn run(body: &str) -> Vec<UnifiedEvent> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("amcache.csv");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "{HEADER}").unwrap();
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

    /// The trust inversion: a binary's own claim about itself must not delete the
    /// record of it. The row is kept, explained, and its hash still reaches the
    /// reputation pass.
    #[test]
    fn a_self_reported_vendor_binary_is_classified_not_discarded() {
        let events = run(
            "2026-01-02T03:04:05.000Z,amcache - a.csv: FileKeyLastWrite,m,\
             C:\\Users\\testuser\\AppData\\Local\\Temp\\tool.exe,Microsoft Windows,\
             0000000000000000000000000000000000000001,.exe,MY-WEB01,amcache,1\n",
        );
        assert_eq!(events.len(), 1, "the row must survive its own ProductName");
        assert_eq!(events[0].classification, "vendor:self-reported");
        assert!(
            events[0].indicators.iter().any(|i| i.starts_with("HASH:")),
            "the hash has to reach the reputation pass: {:?}",
            events[0].indicators
        );
        assert!(!is_triage_hit(&events[0]), "explained rows stay out of the curated cut");
    }

    /// The filename is deliberately longer than three characters: `short_exe_name`
    /// fires at `med` on `\xyz.exe`, which is a real detection and would make this
    /// test assert the wrong thing about the baseline.
    #[test]
    fn an_ordinary_entry_is_carried_as_background() {
        let events = run(
            "2026-01-02T03:04:05.000Z,d,m,C:\\Program Files\\Acme\\helper.exe,Acme App,,.exe,H,amcache,1\n",
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, "info");
        assert_eq!(events[0].classification, "");
    }

    /// The clamp: a `high` path rule must reach `high`, not `med`.
    #[test]
    fn a_path_rule_is_never_clamped_down() {
        let events = run(
            "2026-01-02T03:04:05.000Z,d,m,C:\\inetpub\\wwwroot\\uploads\\shell.aspx,,,.aspx,H,amcache,1\n",
        );
        assert_eq!(events[0].severity, "high", "got {:?}", events[0].indicators);
        assert!(is_triage_hit(&events[0]));
    }

    #[test]
    fn a_renamed_path_column_is_a_coverage_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("amcache.csv");
        std::fs::write(
            &path,
            "datetime,timestamp_desc,message,BinaryLocation,hostname,doc_type,timestamp\n\
             2026-01-02T03:04:05.000Z,d,m,C:\\a\\b.exe,H,amcache,1\n",
        )
        .unwrap();
        let events = parse(
            &path,
            &PipelineConfig::default(),
            &TAToolDetector::new(Path::new("tools/threat_intel")).unwrap(),
            &IOCMatcher::new(None).unwrap(),
            &SuspiciousPathDetector::new(Path::new("tools/threat_intel")).unwrap(),
            "MY-WEB01",
        )
        .unwrap();
        assert!(events.is_empty());
        assert!(columns::failures()
            .iter()
            .any(|f| f.artifact == "amcache" && f.logical == "path"));
    }
}
