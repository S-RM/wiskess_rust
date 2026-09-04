use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Resolve the `threat_intel` data directory holding the YAML/TXT detection lists.
///
/// Resolution order (first hit wins):
/// 1. explicit `--data-dir` CLI flag,
/// 2. `WTP_DATA_DIR` environment variable,
/// 3. next to the executable: `<exe_dir>/tools/threat_intel` (self-contained install),
/// 4. CWD-relative `tools/threat_intel` fallback (running from the repo root).
///
/// The exe-relative step is what lets a shipped Windows `.exe` find its data files
/// regardless of the working directory.
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

/// Working hours, in UTC, outside which a successful interactive logon is worth
/// looking at. Inclusive start, exclusive end.
///
/// ASSUMPTION: 07:00–19:00 UTC, and Saturday/Sunday counted as out-of-hours.
/// Timestamps in wiskess output are UTC, so a site whose staff work a different
/// timezone should pass `--business-hours` rather than read these as local.
pub const DEFAULT_BUSINESS_HOURS: (u32, u32) = (7, 19);

/// A (user, logon type, source) combination seen fewer than this many times
/// across the whole record is rare, and rarity is the signal — a service account
/// that logs on ten thousand times is furniture, one that logs on twice is not.
///
/// ASSUMPTION: the operator asked for "less than ten".
pub const DEFAULT_RARE_LOGON_MAX: usize = 10;

/// How much of the ordinary, un-suspicious record to carry into the output.
///
/// The default is the curated cut this tool was built for. `--verbose-events`
/// widens it to the baseline an analyst needs to say what *normal* looked like:
/// every successful logon by a real (non-machine) account, the network and
/// out-of-hours logons among them, rare logon combinations, and the low-volume
/// SRUM/network rows. Nothing here changes a detection — it changes what is
/// carried alongside one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Verbosity {
    #[default]
    Curated,
    Baseline,
}

impl Verbosity {
    pub fn baseline(self) -> bool {
        self == Verbosity::Baseline
    }
}

#[derive(Clone, Debug)]
pub struct PipelineConfig {
    pub hayabusa_level: String,
    pub window: Option<TimeWindow>,
    pub no_sigma: bool,
    pub offline: bool,
    pub verbose: bool,
    /// How much of the ordinary record to keep. See [`Verbosity`].
    pub verbosity: Verbosity,
    /// Inclusive start / exclusive end hour (UTC) of the working day.
    pub business_hours: (u32, u32),
    /// Logon combinations seen fewer than this many times are flagged rare.
    pub rare_logon_max: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            hayabusa_level: "med".to_string(),
            window: None,
            no_sigma: false,
            offline: false,
            verbose: false,
            verbosity: Verbosity::Curated,
            business_hours: DEFAULT_BUSINESS_HOURS,
            rare_logon_max: DEFAULT_RARE_LOGON_MAX,
        }
    }
}

impl PipelineConfig {
    pub fn in_timewindow(&self, ts: &str) -> bool {
        match &self.window {
            Some(w) => ts >= w.start.as_str() && ts <= w.end.as_str(),
            None => true,
        }
    }

    /// Is this timestamp outside the working day, or on a weekend?
    ///
    /// An unparseable timestamp is **not** out of hours: guessing on a value we
    /// could not read would invent a finding.
    pub fn is_out_of_hours(&self, ts: &str) -> bool {
        use chrono::{Datelike, Timelike, Weekday};
        let Some(dt) = crate::timeline_parser::detectors::restoration::parse_ts(ts) else { return false };
        if matches!(dt.weekday(), Weekday::Sat | Weekday::Sun) {
            return true;
        }
        let h = dt.hour();
        let (start, end) = self.business_hours;
        h < start || h >= end
    }
}

/// Parse a `--business-hours` value of the form `7-19`.
pub fn parse_business_hours(s: &str) -> Result<(u32, u32), String> {
    let (a, b) = s
        .split_once('-')
        .ok_or_else(|| format!("expected START-END (e.g. 7-19), got {s:?}"))?;
    let start: u32 = a.trim().parse().map_err(|_| format!("bad start hour in {s:?}"))?;
    let end: u32 = b.trim().parse().map_err(|_| format!("bad end hour in {s:?}"))?;
    if start > 23 || end > 24 || start >= end {
        return Err(format!("business hours must be 0<=START<END<=24, got {s:?}"));
    }
    Ok((start, end))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn business_hours_parse_and_reject_nonsense() {
        assert_eq!(parse_business_hours("7-19").unwrap(), (7, 19));
        assert_eq!(parse_business_hours(" 0 - 24 ").unwrap(), (0, 24));
        assert!(parse_business_hours("19-7").is_err());
        assert!(parse_business_hours("7").is_err());
        assert!(parse_business_hours("x-y").is_err());
    }

    #[test]
    fn out_of_hours_covers_nights_and_weekends_but_never_guesses() {
        let cfg = PipelineConfig::default();
        // 2026-05-05 is a Tuesday.
        assert!(!cfg.is_out_of_hours("2026-05-05T09:00:00Z"));
        assert!(cfg.is_out_of_hours("2026-05-05T03:14:00Z"));
        assert!(cfg.is_out_of_hours("2026-05-05T19:00:00Z"), "end hour is exclusive");
        // 2026-05-09 is a Saturday.
        assert!(cfg.is_out_of_hours("2026-05-09T11:00:00Z"));
        // Unreadable: no finding invented.
        assert!(!cfg.is_out_of_hours("20200922"));
    }
}
