use std::collections::HashMap;

use super::event::UnifiedEvent;

const TOOL_SOURCE_CAP: usize = 10;
const EID_CAP: usize = 20;

pub fn cap_floods(events: &mut Vec<UnifiedEvent>) {
    let mut tool_source_counts: HashMap<String, usize> = HashMap::new();
    let mut eid_rule_counts: HashMap<String, usize> = HashMap::new();

    events.retain(|e| {
        for indicator in &e.indicators {
            if let Some(tool_name) = indicator.strip_prefix("TA_TOOL:") {
                let key = format!("{}:{}", tool_name, e.source);
                let count = tool_source_counts.entry(key).or_insert(0);
                *count += 1;
                if *count > TOOL_SOURCE_CAP {
                    return false;
                }
            }
        }

        // Baseline logons are exempt. `--verbose-events` exists to carry the
        // whole ordinary record — "all the successful logons from legitimate
        // users" — and a cap of 20 per indicator set would silently answer a
        // different question. They are only ever present when the operator asked
        // for them.
        if e.source == "event-logs" && !e.indicators.iter().any(|i| i == "BASELINE_LOGON") {
            let key = format!("{}:{}", e.detection_rule, e.indicators.join(","));
            let count = eid_rule_counts.entry(key).or_insert(0);
            *count += 1;
            if *count > EID_CAP {
                return false;
            }
        }

        true
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logon(ts: &str, baseline: bool) -> UnifiedEvent {
        UnifiedEvent {
            timestamp: ts.to_string(),
            source: "event-logs".to_string(),
            detection_rule: "correlated_eid_4624".to_string(),
            indicators: if baseline {
                vec!["BASELINE_LOGON".to_string(), "LOGON_TYPE:Network".to_string()]
            } else {
                vec!["COMPROMISED_USER:x".to_string()]
            },
            ..Default::default()
        }
    }

    /// The cap is what keeps one noisy EID from filling the timeline.
    #[test]
    fn a_repeated_event_log_rule_is_still_capped() {
        let mut events: Vec<UnifiedEvent> =
            (0..100).map(|i| logon(&format!("2026-05-05T00:00:{i:02}Z"), false)).collect();
        cap_floods(&mut events);
        assert_eq!(events.len(), EID_CAP);
    }

    /// ...but the baseline the operator explicitly asked for is not capped, or
    /// the flag would answer a different question than the one it was given.
    #[test]
    fn baseline_logons_are_not_capped() {
        let mut events: Vec<UnifiedEvent> =
            (0..100).map(|i| logon(&format!("2026-05-05T00:00:{i:02}Z"), true)).collect();
        cap_floods(&mut events);
        assert_eq!(events.len(), 100, "the whole baseline must survive");
    }
}
