use anyhow::Result;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::timeline_parser::config::{severity_order, PipelineConfig, TimeWindow};
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::output::event::UnifiedEvent;

static MITRE_TACTIC_MAP: &[(&str, &str)] = &[
    ("Recon", "Reconnaissance"),
    ("InitAccess", "Initial Access"),
    ("Exec", "Execution"),
    ("Persis", "Persistence"),
    ("PrivEsc", "Privilege Escalation"),
    ("Evas", "Defense Evasion"),
    ("CredAccess", "Credential Access"),
    ("Discovery", "Discovery"),
    ("LatMov", "Lateral Movement"),
    ("Collection", "Collection"),
    ("C2", "Command and Control"),
    ("Exfil", "Exfiltration"),
    ("Impact", "Impact"),
];

fn normalize_level(level: &str) -> &'static str {
    match level.to_lowercase().trim() {
        "critical" | "crit" => "crit",
        "high" => "high",
        "medium" | "med" => "med",
        "low" => "low",
        _ => "info",
    }
}

fn normalize_tactic(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let lower = raw.to_lowercase();
    for (abbr, full) in MITRE_TACTIC_MAP {
        if lower.contains(&abbr.to_lowercase()) {
            return full.to_string();
        }
    }
    raw.to_string()
}

fn extract_user_from_details(details: &str) -> String {
    for prefix in &["TgtUser: ", "User: ", "Acct: "] {
        if let Some(start) = details.find(prefix) {
            let after = &details[start + prefix.len()..];
            let user: String = after.chars()
                .take_while(|c| *c != ' ' && *c != '¦' && *c != '|' && *c != '\t' && *c != ',')
                .collect();
            let user = user.trim().to_string();
            if !user.is_empty() && user != "-" {
                return user;
            }
        }
    }
    String::new()
}

/// Detect the attack window from hayabusa detections.
///
/// Unchanged behaviour: unbounded, and the largest cluster wins.
pub fn detect_timeframe(filepath: &Path, min_level: &str) -> Result<Option<TimeWindow>> {
    detect_timeframe_opts(filepath, min_level, None, false)
}

/// Detect the window, optionally restricted to `bounds` and preferring the most
/// recent cluster over the largest.
///
/// Both options exist for the same reason. The worker drives this tool with a
/// two-year range, which disables detection entirely and more than doubles what
/// reaches the report (13,725 events against 6,192 on the test corpus). Treating
/// that range as a *bound* rather than an override keeps the safety net for a
/// genuinely old incident while still narrowing to the activity.
///
/// `prefer_recent` changes which cluster wins. The default rule — largest —
/// optimises for density, so six stale detections outvote two from yesterday and
/// the window lands months before the incident. In incident response the recent
/// cluster is almost always the one that matters, and the bound is what covers
/// the exception.
///
/// A singleton is weak evidence, so a cluster of two or more is preferred even
/// if a later lone detection exists; only when every cluster is a singleton does
/// the most recent one win.
pub fn detect_timeframe_opts(
    filepath: &Path,
    min_level: &str,
    bounds: Option<(&str, &str)>,
    prefer_recent: bool,
) -> Result<Option<TimeWindow>> {
    let min_sev = severity_order(min_level);
    let mut timestamps: Vec<String> = Vec::new();

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::Reader::from_reader(reader);

    for result in rdr.records() {
        let record = result?;
        let headers = rdr.headers()?.clone();
        let level_idx = headers.iter().position(|h| h == "Level");
        let ts_idx = headers.iter().position(|h| h == "datetime");

        let level = level_idx.and_then(|i| record.get(i)).unwrap_or("");
        let normalized = normalize_level(level);
        if severity_order(normalized) >= min_sev {
            if let Some(ts) = ts_idx.and_then(|i| record.get(i)) {
                if !ts.is_empty() {
                    timestamps.push(ts.to_string());
                }
            }
        }
        break;
    }

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();
    let level_idx = headers.iter().position(|h| h == "Level").unwrap_or(0);
    let ts_idx = headers.iter().position(|h| h == "datetime").unwrap_or(0);

    timestamps.clear();
    for result in rdr.records() {
        let Ok(record) = result else { continue };
        let level = record.get(level_idx).unwrap_or("");
        let normalized = normalize_level(level);
        if severity_order(normalized) >= min_sev {
            let ts = record.get(ts_idx).unwrap_or("");
            if !ts.is_empty() {
                timestamps.push(ts.to_string());
            }
        }
    }

    // Outside the bound is outside the investigation.
    if let Some((lo, hi)) = bounds {
        timestamps.retain(|t| t.as_str() >= lo && t.as_str() <= hi);
    }

    if timestamps.is_empty() {
        if min_level == "high" {
            return detect_timeframe_opts(filepath, "med", bounds, prefer_recent);
        }
        return Ok(None);
    }

    Ok(window_from_timestamps(timestamps, prefer_recent))
}

/// Cluster detection timestamps into a window. Split out so the selection rule
/// is testable without a CSV on disk.
pub fn window_from_timestamps(mut timestamps: Vec<String>, prefer_recent: bool) -> Option<TimeWindow> {
    if timestamps.is_empty() {
        return None;
    }
    timestamps.sort();

    if timestamps.len() == 1 {
        let ts = &timestamps[0];
        return Some(TimeWindow {
            start: pad_time(ts, -2),
            end: pad_time(ts, 2),
            event_count: 1,
            confidence: "low".to_string(),
        });
    }

    let mut clusters: Vec<Vec<&str>> = Vec::new();
    let mut current: Vec<&str> = vec![&timestamps[0]];

    for i in 1..timestamps.len() {
        let gap_ok = is_within_gap(&timestamps[i-1], &timestamps[i], 4);
        if gap_ok {
            current.push(&timestamps[i]);
        } else {
            clusters.push(current);
            current = vec![&timestamps[i]];
        }
    }
    clusters.push(current);

    // Clusters are built in ascending order, so `last` is the most recent.
    let best = if prefer_recent {
        clusters
            .iter()
            .filter(|c| c.len() >= 2)
            .next_back()
            .or_else(|| clusters.last())
            .unwrap()
    } else {
        clusters.iter().max_by_key(|c| c.len()).unwrap()
    };
    let start = best.first().unwrap().to_string();
    let end = best.last().unwrap().to_string();

    let padded_start = pad_time(&start, -2);
    let padded_end = pad_time(&end, 2);

    let confidence = if best.len() >= 5 { "high" }
        else if best.len() >= 2 { "medium" }
        else { "low" };

    Some(TimeWindow {
        start: padded_start,
        end: padded_end,
        event_count: best.len(),
        confidence: confidence.to_string(),
    })
}

fn is_within_gap(ts1: &str, ts2: &str, hours: i64) -> bool {
    let parse = |s: &str| -> Option<chrono::NaiveDateTime> {
        let s = s.trim_end_matches('Z');
        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f").ok()
            .or_else(|| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").ok())
    };
    match (parse(ts1), parse(ts2)) {
        (Some(dt1), Some(dt2)) => (dt2 - dt1) <= chrono::Duration::hours(hours),
        _ => true,
    }
}

fn pad_time(ts: &str, hours: i64) -> String {
    let s = ts.trim_end_matches('Z');
    let dt = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S"));
    match dt {
        Ok(dt) => {
            let padded = dt + chrono::Duration::hours(hours);
            format!("{}Z", padded.format("%Y-%m-%dT%H:%M:%S"))
        }
        Err(_) => ts.to_string(),
    }
}

pub fn parse(
    filepath: &Path,
    cfg: &PipelineConfig,
    ta_detector: &TAToolDetector,
    ioc_matcher: &IOCMatcher,
    hostname: &str,
) -> Result<Vec<UnifiedEvent>> {
    let min_sev = severity_order(&cfg.hayabusa_level);
    let mut events = Vec::new();

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    let col = |name: &str| headers.iter().position(|h| h == name);
    let ts_idx = col("datetime").unwrap_or(0);
    let level_idx = col("Level").unwrap_or(3);
    let msg_idx = col("message").unwrap_or(2);
    let details_idx = col("Details");
    let extra_idx = col("ExtraFieldInfo");
    let _channel_idx = col("Channel");
    let _eid_idx = col("EventID");
    let tactics_idx = col("MitreTactics");
    let tags_idx = col("MitreTags");
    let rule_idx = col("RuleFile");

    for result in rdr.records() {
        let Ok(record) = result else { continue };

        let level_raw = record.get(level_idx).unwrap_or("");
        let level = normalize_level(level_raw);
        if severity_order(level) < min_sev {
            continue;
        }

        let ts = record.get(ts_idx).unwrap_or("").to_string();
        let msg = record.get(msg_idx).unwrap_or("");
        let details = details_idx.and_then(|i| record.get(i)).unwrap_or("");
        let extra = extra_idx.and_then(|i| record.get(i)).unwrap_or("");
        let tactics = tactics_idx.and_then(|i| record.get(i)).unwrap_or("");
        let tags = tags_idx.and_then(|i| record.get(i)).unwrap_or("");
        let rule_file = rule_idx.and_then(|i| record.get(i)).unwrap_or("");

        let tactic = normalize_tactic(tactics);
        let mut description = msg.to_string();
        if !details.is_empty() {
            description.push_str(" | ");
            description.push_str(details.char_indices().nth(200).map_or(details, |(i, _)| &details[..i]));
        }

        let scan_text = format!("{} {} {}", msg, details, extra);
        let ta_hits = ta_detector.scan(&scan_text);
        let ioc_hits = ioc_matcher.check(&scan_text);

        let mut indicators: Vec<String> = Vec::new();
        for hit in &ta_hits {
            indicators.push(format!("TA_TOOL:{}", hit.name));
        }
        indicators.extend(ioc_hits);

        let user = extract_user_from_details(details);

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "hayabusa".to_string(),
            event_type: format!("sigma_detection_{}", level),
            severity: level.to_string(),
            description,
            indicators,
            mitre_tactic: tactic,
            mitre_technique: tags.to_string(),
            user,
            hostname: hostname.to_string(),
            detection_rule: rule_file.to_string(),
        });
    }

    Ok(events)
}

#[cfg(test)]
mod recency_tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    /// The case this option exists for: a noisy old cluster outvotes a real
    /// recent one, and the window lands months before the incident. Everything
    /// that matters is then hard-dropped from MFT and USN.
    #[test]
    fn a_stale_dense_cluster_no_longer_beats_a_recent_one() {
        let ts = v(&[
            "2026-03-01T01:00:00Z", "2026-03-01T02:00:00Z", "2026-03-01T03:00:00Z",
            "2026-03-01T04:00:00Z", "2026-03-01T05:00:00Z", "2026-03-01T06:00:00Z",
            "2026-08-20T09:00:00Z", "2026-08-20T10:00:00Z",
        ]);
        let largest = window_from_timestamps(ts.clone(), false).unwrap();
        assert!(largest.start.starts_with("2026-02"), "default rule picks the dense old cluster");

        let recent = window_from_timestamps(ts, true).unwrap();
        assert!(recent.start.starts_with("2026-08-20"), "{recent:?}");
        assert_eq!(recent.event_count, 2);
    }

    /// A lone late detection is weak evidence and must not displace a real
    /// cluster — otherwise one stray alert defines the investigation.
    #[test]
    fn a_single_late_detection_does_not_displace_a_real_cluster() {
        let w = window_from_timestamps(
            v(&[
                "2026-08-18T09:00:00Z", "2026-08-18T09:30:00Z", "2026-08-18T10:00:00Z",
                "2026-08-25T04:00:00Z", // lone, later
            ]),
            true,
        )
        .unwrap();
        assert!(w.start.starts_with("2026-08-18"), "{w:?}");
        assert_eq!(w.event_count, 3);
    }

    /// ...but when every cluster is a singleton, the most recent one wins.
    #[test]
    fn among_singletons_the_most_recent_wins() {
        let w = window_from_timestamps(
            v(&["2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z", "2026-08-20T00:00:00Z"]),
            true,
        )
        .unwrap();
        assert!(w.start.starts_with("2026-08-19"), "{w:?}"); // padded -2h
        assert_eq!(w.event_count, 1);
        assert_eq!(w.confidence, "low");
    }

    #[test]
    fn the_default_rule_is_unchanged() {
        let ts = v(&[
            "2026-03-01T01:00:00Z", "2026-03-01T02:00:00Z", "2026-03-01T03:00:00Z",
            "2026-08-20T09:00:00Z",
        ]);
        let w = window_from_timestamps(ts, false).unwrap();
        assert_eq!(w.event_count, 3, "largest cluster still wins without the option");
    }

    #[test]
    fn no_timestamps_yields_no_window() {
        assert!(window_from_timestamps(Vec::new(), true).is_none());
    }
}
