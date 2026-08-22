use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnifiedEvent {
    pub timestamp: String,
    pub source: String,
    pub event_type: String,
    pub severity: String,
    pub description: String,
    pub indicators: Vec<String>,
    pub mitre_tactic: String,
    pub mitre_technique: String,
    pub user: String,
    pub hostname: String,
    pub detection_rule: String,
}

impl UnifiedEvent {
    pub fn dedup_key(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.timestamp.hash(&mut hasher);
        self.source.hash(&mut hasher);
        let desc_prefix: String = self.description.chars().take(100).collect();
        desc_prefix.hash(&mut hasher);
        hasher.finish()
    }
}
