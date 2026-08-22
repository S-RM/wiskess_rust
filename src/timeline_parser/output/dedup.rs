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

        if e.source == "event-logs" {
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
