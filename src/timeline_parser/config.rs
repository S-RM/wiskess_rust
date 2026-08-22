use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Resolve the `threat_intel` data directory holding the YAML/TXT detection lists.
///
/// Resolution order (first hit wins):
/// 1. explicit `--data-dir` CLI flag,
/// 2. `WTP_DATA_DIR` environment variable,
/// 3. next to the executable: `<exe_dir>/tools/threat_intel` (self-contained install),
/// 4. CWD-relative `tools/threat_intel` fallback (running from the repo root).
pub fn resolve_data_dir(cli_override: Option<&Path>) -> PathBuf {
    if let Some(p) = cli_override {
        return p.to_path_buf();
    }
    if let Ok(env_dir) = std::env::var("WTP_DATA_DIR") {
        if !env_dir.is_empty() {
            return PathBuf::from(env_dir);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let candidate = exe_dir.join("tools").join("threat_intel");
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from("tools").join("threat_intel")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeWindow {
    pub start: String,
    pub end: String,
    pub event_count: usize,
    pub confidence: String,
}

#[derive(Clone, Debug)]
pub struct PipelineConfig {
    pub hayabusa_level: String,
    pub window: Option<TimeWindow>,
    pub no_sigma: bool,
    pub offline: bool,
    pub verbose: bool,
}

impl PipelineConfig {
    pub fn in_timewindow(&self, ts: &str) -> bool {
        match &self.window {
            Some(w) => ts >= w.start.as_str() && ts <= w.end.as_str(),
            None => true,
        }
    }
}

pub fn severity_order(level: &str) -> u8 {
    match level {
        "crit" | "critical" => 4,
        "high" => 3,
        "med" | "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}
