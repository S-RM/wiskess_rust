//! Flood control for the **report**, and only for the report.
//!
//! This used to be `cap_floods(&mut Vec<UnifiedEvent>)`, called on the single
//! vector that the supertimeline, the triage timeline and the report all read. It
//! deleted every occurrence of a tool past the tenth and every event-log rule hit
//! past the twentieth, from all of them.
//!
//! Two things make that a loss of evidence rather than a presentation choice.
//! Events are timestamp-sorted before the cap runs, so it keeps the **earliest**
//! and deletes the rest: a tool that ran a hundred times over three days is
//! reported as having stopped after the tenth, and nothing says otherwise. And
//! the supertimeline is the file an analyst pivots in — the one place that is
//! supposed to hold everything.
//!
//! So the cap is now a *view*, built for the report only. The suppressed events
//! stay in the supertimeline, and the report gets a `CAPPED:` marker in their
//! place that says how many there were and the span they cover, which is the
//! answer to "did it stop?" that deleting them destroyed.

use std::collections::HashMap;

use super::event::UnifiedEvent;
use crate::timeline_parser::config::severity_order;

/// How many events of one kind the report tables carry before summarising.
///
/// Was 10 per tool/source and 20 per event-log rule, chosen when the cap applied
/// to the whole output and had to be tight. It only bounds a markdown table now,
/// so it can be generous, and `--report-cap` moves it.
pub const DEFAULT_REPORT_CAP: usize = 100;

/// What one over-cap group cost the report.
#[derive(Clone, Debug)]
pub struct CapSummary {
    /// The group: `<tool>:<source>` or `<detection rule>:<indicators>`.
    pub key: String,
    pub kept: usize,
    pub suppressed: usize,
    /// First and last timestamp **among the suppressed events** — the span the
    /// report is not showing.
    pub first: String,
    pub last: String,
}

/// The keys an event counts against.
///
/// Same two groupings as before: one per TA tool per source, and one per
/// event-log rule + indicator set. Baseline logons are exempt — `--verbose-events`
/// exists to carry the whole ordinary record, and a cap would silently answer a
/// different question.
fn keys_of(e: &UnifiedEvent) -> Vec<String> {
    let mut keys = Vec::new();
    for indicator in &e.indicators {
        if let Some(tool) = indicator.strip_prefix("TA_TOOL:") {
            keys.push(format!("{}:{}", tool, e.source));
        }
    }
    if e.source == "event-logs" && !e.indicators.iter().any(|i| i == "BASELINE_LOGON") {
        keys.push(format!("{}:{}", e.detection_rule, e.indicators.join(",")));
    }
    keys
}

/// Build the report's view of `events`: at most `cap` per group, plus one marker
/// event per group that went over.
///
/// `events` is expected sorted by timestamp (the caller sorts before dedup), and
/// the returned vector is sorted the same way — markers included, at the start of
/// the span they describe, so the report reads chronologically.
pub fn summarise_floods(events: &[UnifiedEvent], cap: usize) -> (Vec<UnifiedEvent>, Vec<CapSummary>) {
    // Which events each group holds, in the order they appear.
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, e) in events.iter().enumerate() {
        for key in keys_of(e) {
            groups.entry(key).or_default().push(i);
        }
    }

    let mut suppressed: Vec<bool> = vec![false; events.len()];
    let mut summaries: Vec<CapSummary> = Vec::new();
    let mut markers: Vec<UnifiedEvent> = Vec::new();

    // Sorted so the summary list, and therefore the report, does not reorder
    // itself between runs on the same input.
    let mut over: Vec<(&String, &Vec<usize>)> =
        groups.iter().filter(|(_, idx)| idx.len() > cap).collect();
    over.sort_by(|a, b| a.0.cmp(b.0));

    for (key, idx) in over {
        let cut = &idx[cap..];
        for i in cut {
            suppressed[*i] = true;
        }
        let first = events[cut[0]].timestamp.clone();
        let last = events[*cut.last().unwrap()].timestamp.clone();
        let severity = cut
            .iter()
            .map(|i| events[*i].severity.as_str())
            .max_by_key(|s| severity_order(s))
            .unwrap_or("info")
            .to_string();

        summaries.push(CapSummary {
            key: key.clone(),
            kept: cap,
            suppressed: cut.len(),
            first: first.clone(),
            last: last.clone(),
        });

        // The marker carries the group's own source and rule so it lands in the
        // report table it is standing in for, and `CAPPED:` is in
        // `STRONG_PREFIXES` so it reaches the triage cut: a suppression the
        // analyst cannot see is the bug this replaces.
        let exemplar = &events[cut[0]];
        markers.push(UnifiedEvent {
            timestamp: first.clone(),
            source: exemplar.source.clone(),
            event_type: "capped_summary".to_string(),
            severity,
            description: format!(
                "CAPPED: {} further {} events between {} and {} — see the supertimeline",
                cut.len(),
                key,
                first,
                last
            ),
            indicators: vec![format!("CAPPED:{key}"), format!("CAPPED_COUNT:{}", cut.len())],
            hostname: exemplar.hostname.clone(),
            detection_rule: exemplar.detection_rule.clone(),
            // The ATT&CK section of the report groups by tactic, so a marker with
            // no tactic lands in no table — which is how a run that summarised 65
            // events said so on stderr and nowhere in the report. It inherits the
            // tactic of the events it stands in for.
            mitre_tactic: exemplar.mitre_tactic.clone(),
            mitre_technique: exemplar.mitre_technique.clone(),
            ..Default::default()
        });
    }

    let mut out: Vec<UnifiedEvent> = events
        .iter()
        .enumerate()
        .filter(|(i, _)| !suppressed[*i])
        .map(|(_, e)| e.clone())
        .collect();
    out.extend(markers);
    // Stable, so events that share a timestamp keep the order the caller chose.
    out.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    (out, summaries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logon(ts: &str, baseline: bool) -> UnifiedEvent {
        UnifiedEvent {
            timestamp: ts.to_string(),
            source: "event-logs".to_string(),
            severity: "med".to_string(),
            detection_rule: "correlated_eid_4624".to_string(),
            indicators: if baseline {
                vec!["BASELINE_LOGON".to_string(), "LOGON_TYPE:Network".to_string()]
            } else {
                vec!["COMPROMISED_USER:testuser".to_string()]
            },
            ..Default::default()
        }
    }

    fn many(n: usize, baseline: bool) -> Vec<UnifiedEvent> {
        (0..n).map(|i| logon(&format!("2026-05-05T00:{:02}:{:02}Z", i / 60, i % 60), baseline)).collect()
    }

    /// The cap still bounds the table — but what it drops is now stated.
    #[test]
    fn an_over_cap_group_is_summarised_rather_than_deleted() {
        let events = many(100, false);
        let (view, caps) = summarise_floods(&events, 10);
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].suppressed, 90);
        assert_eq!(caps[0].first, "2026-05-05T00:00:10Z", "the span starts at the first one dropped");
        assert_eq!(caps[0].last, "2026-05-05T00:01:39Z");
        assert_eq!(view.len(), 11, "10 events plus the marker standing in for the other 90");

        let marker = view.iter().find(|e| e.event_type == "capped_summary").unwrap();
        assert!(marker.description.contains("90 further"), "{}", marker.description);
        assert!(marker.description.contains("2026-05-05T00:01:39Z"), "{}", marker.description);
        assert!(marker.indicators.iter().any(|i| i == "CAPPED_COUNT:90"));
    }

    /// The supertimeline is what this fixes: the input is left whole.
    #[test]
    fn the_input_is_never_modified() {
        let events = many(100, false);
        let (view, _) = summarise_floods(&events, 10);
        assert_eq!(events.len(), 100, "the caller's vector is the supertimeline");
        assert!(view.len() < events.len());
    }

    #[test]
    fn a_group_at_or_below_the_cap_is_untouched_and_gets_no_marker() {
        let events = many(10, false);
        let (view, caps) = summarise_floods(&events, 10);
        assert!(caps.is_empty());
        assert_eq!(view.len(), 10);
        assert!(!view.iter().any(|e| e.event_type == "capped_summary"));
    }

    /// ...and the baseline the operator explicitly asked for is not capped, or the
    /// flag would answer a different question than the one it was given.
    #[test]
    fn baseline_logons_are_not_capped() {
        let events = many(100, true);
        let (view, caps) = summarise_floods(&events, 10);
        assert!(caps.is_empty());
        assert_eq!(view.len(), 100, "the whole baseline must survive");
    }

    /// A tool is capped per source, so the same tool seen in two artifacts is two
    /// groups — the second is not silenced by the first.
    #[test]
    fn a_tool_is_counted_per_source() {
        let mut events = Vec::new();
        for source in ["amcache", "mft"] {
            for i in 0..6 {
                events.push(UnifiedEvent {
                    timestamp: format!("2026-05-05T00:00:{i:02}Z"),
                    source: source.to_string(),
                    severity: "high".to_string(),
                    indicators: vec!["TA_TOOL:sometool".to_string()],
                    ..Default::default()
                });
            }
        }
        let (view, caps) = summarise_floods(&events, 5);
        assert_eq!(caps.len(), 2, "one group per source: {:?}", caps);
        assert_eq!(view.len(), 12, "5 kept + 1 marker, twice");
    }

    /// The marker's severity is the group's, or a capped run of `high` events
    /// would be summarised as background.
    #[test]
    fn the_marker_carries_the_worst_severity_it_stands_for() {
        let mut events = many(12, false);
        events[11].severity = "crit".to_string();
        let (view, _) = summarise_floods(&events, 10);
        let marker = view.iter().find(|e| e.event_type == "capped_summary").unwrap();
        assert_eq!(marker.severity, "crit");
    }
}
