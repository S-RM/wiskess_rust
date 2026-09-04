use anyhow::Result;
use regex::Regex;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::severity_order;
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::suspicious_paths::SuspiciousPathDetector;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::output::event::UnifiedEvent;

static KNOWN_GOOD_PRODUCTS: &[&str] = &[
    "microsoft malware protection",
    "microsoft windows",
    "windows update",
    "microsoft .net framework",
    "microsoft visual c++",
    "windows defender",
];

pub fn parse(
    filepath: &Path,
    ta_detector: &TAToolDetector,
    ioc_matcher: &IOCMatcher,
    path_detector: &SuspiciousPathDetector,
    hostname: &str,
) -> Result<Vec<UnifiedEvent>> {
    let mut events = Vec::new();

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    let col = |name: &str| headers.iter().position(|h| h == name);
    let ts_idx = col("datetime").unwrap_or(0);
    let path_idx = col("FullPath").or_else(|| col("Path")).unwrap_or(1);
    let product_idx = col("ProductName");
    let sha1_idx = col("SHA1");

    for result in rdr.records() {
        let Ok(record) = result else { continue };

        let ts = record.get(ts_idx).unwrap_or("").to_string();
        let full_path = record.get(path_idx).unwrap_or("").to_string();
        let product = product_idx.and_then(|i| record.get(i)).unwrap_or("");
        let sha1 = sha1_idx.and_then(|i| record.get(i)).unwrap_or("");

        if KNOWN_GOOD_PRODUCTS.iter().any(|p| product.to_lowercase().contains(p)) {
            continue;
        }

        let path_hits = path_detector.check_path(&full_path);
        let ta_hits = ta_detector.scan(&full_path);
        let ioc_hits = ioc_matcher.check(&full_path);
        let hash_hits = ioc_matcher.check_hash(sha1);

        let mut indicators: Vec<String> = Vec::new();
        let mut severity = "low";

        // Always record the SHA1 so the post-parse hash-lookup pass can enrich every
        // Amcache entry, not just the ones that already matched an IOC.
        if !sha1.is_empty() {
            indicators.push(format!("HASH:{}", sha1.to_lowercase()));
        }

        if path_hits.is_empty() && ta_hits.is_empty() && ioc_hits.is_empty() && hash_hits.is_empty() {
            severity = "info";
        } else {
            for hit in &path_hits {
                indicators.push(format!("PATH:{}", hit.reason));
                if severity_order(&hit.severity) > severity_order(severity) {
                    severity = if hit.severity == "high" { "high" } else { "med" };
                }
            }
            for hit in &ta_hits {
                indicators.push(format!("TA_TOOL:{}", hit.name));
                severity = "high";
            }
            indicators.extend(ioc_hits);
            indicators.extend(hash_hits.clone());
            if !hash_hits.is_empty() {
                severity = "high";
            }
        }

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "amcache".to_string(),
            event_type: "process_execution".to_string(),
            severity: severity.to_string(),
            description: format!("Amcache: {} | Product: {} | SHA1: {}", full_path, product, sha1),
            indicators,
            mitre_tactic: "Execution".to_string(),
            mitre_technique: String::new(),
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "amcache_analysis".to_string(),
            ..Default::default()
        });
    }

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
    ta_detector: &TAToolDetector,
    ioc_matcher: &IOCMatcher,
    path_detector: &SuspiciousPathDetector,
    hostname: &str,
) -> Result<Vec<UnifiedEvent>> {
    let sha1_re = Regex::new(r"\b([0-9a-fA-F]{40})\b").unwrap();
    let mut events = Vec::new();

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    let col = |name: &str| headers.iter().position(|h| h == name);
    let ts_idx = col("datetime").unwrap_or(0);
    let msg_idx = col("message").unwrap_or(2);
    let desc_idx = col("description");

    for result in rdr.records() {
        let Ok(record) = result else { continue };

        let ts = record.get(ts_idx).unwrap_or("").to_string();
        let message = record.get(msg_idx).unwrap_or("");
        let desc_field = desc_idx.and_then(|i| record.get(i)).unwrap_or("");
        // Prefer whichever field carries the path+hash detail.
        let detail = if message.len() >= desc_field.len() { message } else { desc_field };

        let sha1 = sha1_re.captures(detail)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_lowercase())
            .unwrap_or_default();

        let path_hits = path_detector.check_path(detail);
        let ta_hits = ta_detector.scan(detail);
        let ioc_hits = ioc_matcher.check(detail);
        let hash_hits = ioc_matcher.check_hash(&sha1);

        let mut indicators: Vec<String> = Vec::new();
        if !sha1.is_empty() {
            indicators.push(format!("HASH:{}", sha1));
        }

        let mut severity = "info";
        if !(path_hits.is_empty() && ta_hits.is_empty() && ioc_hits.is_empty() && hash_hits.is_empty()) {
            severity = "low";
            for hit in &path_hits {
                indicators.push(format!("PATH:{}", hit.reason));
                if severity_order(&hit.severity) > severity_order(severity) {
                    severity = if hit.severity == "high" { "high" } else { "med" };
                }
            }
            for hit in &ta_hits {
                indicators.push(format!("TA_TOOL:{}", hit.name));
                severity = "high";
            }
            indicators.extend(ioc_hits);
            indicators.extend(hash_hits.clone());
            if !hash_hits.is_empty() {
                severity = "high";
            }
        }

        let desc_trunc = detail.char_indices().nth(220).map_or(detail, |(i, _)| &detail[..i]);
        events.push(UnifiedEvent {
            timestamp: ts,
            source: "amcache-regripper".to_string(),
            event_type: "process_execution".to_string(),
            severity: severity.to_string(),
            description: format!("Amcache(RegRipper): {}", desc_trunc),
            indicators,
            mitre_tactic: "Execution".to_string(),
            mitre_technique: String::new(),
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "amcache_regripper_analysis".to_string(),
            ..Default::default()
        });
    }

    Ok(events)
}
