use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

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

/// The detection data files a complete `--data-dir` holds.
///
/// Named here rather than at each loader because the loaders are individually
/// forgiving on purpose — `Classifier::load` falls back to `BUILTIN_VENDOR_PATHS`,
/// the hash lists are optional, and a `vulnerable_software.yaml` that is not there
/// simply flags nothing. Each fallback is right on its own and wrong together: a
/// run against a data dir that lost three of its six files reports fewer findings
/// and says nothing about why. So the presence of each is stated once, at startup,
/// and carried into the report's coverage table.
pub const EXPECTED_DATA_FILES: &[&str] = &[
    "ta_tools.yaml",
    "suspicious_paths.yaml",
    "vendor_paths.yaml",
    "vulnerable_software.yaml",
    "known_bad_hashes.txt",
    "known_good_hashes.txt",
];

/// Which of [`EXPECTED_DATA_FILES`] are not in `dir`, in declared order.
pub fn missing_data_files(dir: &Path) -> Vec<String> {
    EXPECTED_DATA_FILES
        .iter()
        .filter(|f| !dir.join(f).exists())
        .map(|f| (*f).to_string())
        .collect()
}

/// Which end of a time window a bound is, for [`normalise_bound`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    Start,
    End,
}

/// Widen a date-only bound to cover the whole of that day.
///
/// A bare `2026-08-21` is not a point in time, and treating it as one silently
/// excludes evidence: as an **upper** bound it cuts everything after midnight on
/// its last day, and the wiskess worker passes `end_date = today`, so that is the
/// collection day itself — the most recent evidence, dropped without a word. As a
/// **lower** bound it does not parse at all, which now costs the window its
/// parsed comparison (see [`TimeWindow::contains`]).
///
/// Anything that is not a bare `YYYY-MM-DD` is returned untouched, including
/// values that are not dates: this normalises, it does not validate.
pub fn normalise_bound(bound: &str, which: Bound) -> String {
    let is_date_only = bound.len() == 10
        && bound.as_bytes()[4] == b'-'
        && bound.as_bytes()[7] == b'-'
        && bound.bytes().enumerate().all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit());
    if !is_date_only {
        return bound.to_string();
    }
    match which {
        Bound::Start => format!("{bound}T00:00:00.000Z"),
        Bound::End => format!("{bound}T23:59:59.999Z"),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeWindow {
    pub start: String,
    pub end: String,
    pub event_count: usize,
    pub confidence: String,
    /// The bounds, parsed, computed on first use.
    ///
    /// Derived from `start`/`end` and therefore not part of the serialised form —
    /// a deserialised window recomputes it. Cached because [`contains`] is called
    /// once per row of a multi-million-row `$MFT`.
    ///
    /// [`contains`]: TimeWindow::contains
    #[serde(skip)]
    bounds: OnceLock<Option<(NaiveDateTime, NaiveDateTime)>>,
}

impl TimeWindow {
    /// Build a window, normalising both bounds ([`normalise_bound`]).
    ///
    /// Normalising here rather than at the CLI is deliberate: there are two entry
    /// points into this pipeline (the standalone binary and the copy vendored into
    /// wiskess), and only one of them was widening its end date. A constructor
    /// cannot be bypassed by either.
    pub fn new(
        start: impl AsRef<str>,
        end: impl AsRef<str>,
        event_count: usize,
        confidence: impl Into<String>,
    ) -> Self {
        Self {
            start: normalise_bound(start.as_ref(), Bound::Start),
            end: normalise_bound(end.as_ref(), Bound::End),
            event_count,
            confidence: confidence.into(),
            bounds: OnceLock::new(),
        }
    }

    fn parsed(&self) -> &Option<(NaiveDateTime, NaiveDateTime)> {
        self.bounds.get_or_init(|| {
            let parse = crate::timeline_parser::detectors::restoration::parse_ts;
            match (parse(&self.start), parse(&self.end)) {
                (Some(s), Some(e)) => Some((s, e)),
                _ => {
                    eprintln!(
                        "[!] Time window {}..{} does not parse as a pair of timestamps — \
                         falling back to comparing them as text, which is only correct while \
                         every event timestamp has the identical shape",
                        self.start, self.end
                    );
                    None
                }
            }
        })
    }

    /// Is `ts` inside the window?
    ///
    /// Compares parsed instants. This used to compare the raw strings, which is
    /// only right while every value has the same shape to the character:
    /// `"2026-08-21 10:00:00"` (space, no `Z`) sorts *above* every
    /// `"2026-08-21T…"`, and `"2026-08-21"` sorts below all of them, so a bound
    /// or a row in a different spelling silently landed outside the window.
    ///
    /// A timestamp that will not parse falls back to the text comparison rather
    /// than being declared out of window: unreadable timestamps are flagged
    /// elsewhere (`restoration::validate_timestamps`), and this is not the place
    /// to drop a row over one.
    pub fn contains(&self, ts: &str) -> bool {
        if let Some((start, end)) = self.parsed() {
            if let Some(t) = crate::timeline_parser::detectors::restoration::parse_ts(ts) {
                return t >= *start && t <= *end;
            }
        }
        ts >= self.start.as_str() && ts <= self.end.as_str()
    }
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
    pub offline: bool,
    pub verbose: bool,
    /// How much of the ordinary record to keep. See [`Verbosity`].
    pub verbosity: Verbosity,
    /// Inclusive start / exclusive end hour (UTC) of the working day.
    pub business_hours: (u32, u32),
    /// Logon combinations seen fewer than this many times are flagged rare.
    pub rare_logon_max: usize,
    /// Carry every row of a low-volume artifact, whether or not a rule fired.
    ///
    /// The artifacts classed [`Volume::Quiet`](crate::timeline_parser::parsers::artifacts::Volume)
    /// are small — a few hundred to a few thousand rows each — and every row of
    /// them is context an investigation wants: which folders a user browsed, what
    /// was in the recycle bin, which LNK and jump-list entries exist. All of them
    /// were being dropped unless a detection rule happened to fire, which meant
    /// eight artifact families contributed **nothing at all** to a 248,765-event
    /// timeline.
    ///
    /// Baseline rows are emitted at an `info` floor, so they reach the
    /// supertimeline and `_triage.json` without widening the curated triage cut or
    /// the markdown report — `is_triage_hit()` needs no change for this.
    pub emit_quiet_baseline: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            hayabusa_level: "med".to_string(),
            window: None,
            offline: false,
            verbose: false,
            verbosity: Verbosity::Curated,
            business_hours: DEFAULT_BUSINESS_HOURS,
            rare_logon_max: DEFAULT_RARE_LOGON_MAX,
            emit_quiet_baseline: true,
        }
    }
}

impl PipelineConfig {
    pub fn in_timewindow(&self, ts: &str) -> bool {
        match &self.window {
            Some(w) => w.contains(ts),
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

/// Raise `current` to `candidate` if `candidate` is more severe. Never lowers.
///
/// This existed six times, written wrong in two different ways. Three sites read
///
/// ```ignore
/// if severity_order(&hit.severity) > severity_order(severity) {
///     severity = if hit.severity == "high" { "high" } else { severity };
/// }
/// ```
///
/// — a self-assignment for anything that is not exactly `high`, so a `crit` rule
/// left the severity untouched. The other three read
/// `if high { "high" } else { "med" }`, which *lowers* a `crit` rule to `med`.
///
/// Both mattered: `is_triage_hit()` keys on `>= high`, so a rule that could not
/// raise an event to `high` could not put it in front of an analyst either. The
/// webshell path rule is `high` and the MFT event it fired on was `med`.
pub fn raise(current: &mut String, candidate: &str) {
    if severity_order(candidate) > severity_order(current) {
        *current = candidate.to_string();
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

    /// The bug this replaces: a `crit` rule could not raise a `med` event, and a
    /// separate site actively lowered `crit` to `med`.
    #[test]
    fn severity_is_raised_by_a_stronger_rule_and_never_lowered() {
        let mut s = "med".to_string();
        raise(&mut s, "high");
        assert_eq!(s, "high");
        raise(&mut s, "crit");
        assert_eq!(s, "crit", "a crit rule must not be clamped to high");
        raise(&mut s, "low");
        assert_eq!(s, "crit", "and nothing lowers it again");

        // The exact case the old code got wrong: not-quite-`high` did nothing.
        let mut s = "low".to_string();
        raise(&mut s, "med");
        assert_eq!(s, "med");
    }

    /// The bug: today's events were being dropped. The worker passes
    /// `end_date = today` as a bare date, so this was the collection day.
    #[test]
    fn a_date_only_bound_is_widened_to_cover_the_whole_day() {
        assert_eq!(normalise_bound("2026-08-21", Bound::End), "2026-08-21T23:59:59.999Z");
        assert_eq!(normalise_bound("2026-08-21", Bound::Start), "2026-08-21T00:00:00.000Z");
        let w = TimeWindow::new("2026-08-01", "2026-08-21", 0, "user-specified");
        assert!(w.contains("2026-08-21T10:00:00.000Z"), "an event on the last day is in scope");
        assert!(w.contains("2026-08-01T00:00:00.000Z"), "and so is one on the first");
        assert!(!w.contains("2026-08-22T00:00:00.000Z"));
    }

    #[test]
    fn a_full_timestamp_bound_is_left_alone() {
        assert_eq!(normalise_bound("2026-08-21T12:00:00Z", Bound::End), "2026-08-21T12:00:00Z");
        assert_eq!(normalise_bound("not-a-date", Bound::End), "not-a-date");
        // Ten characters, but not a date — normalising, not validating.
        assert_eq!(normalise_bound("2026-08-2x", Bound::End), "2026-08-2x");
    }

    /// The window compares instants, not text. Both of these are inside it and
    /// neither of them was, when the comparison was `ts >= start && ts <= end` on
    /// the raw strings.
    #[test]
    fn a_timestamp_in_another_spelling_is_still_inside_the_window() {
        let w = TimeWindow::new("2026-08-01T00:00:00Z", "2026-08-21T23:59:59.999Z", 0, "test");
        assert!(w.contains("2026-08-10 14:22:01"), "space separator, no Z");
        assert!(w.contains("2026-08-21T23:00:00"), "no Z");
        assert!(!w.contains("2026-09-01T00:00:00Z"));
    }

    /// An unreadable timestamp is not dropped here — it is flagged by
    /// `validate_timestamps`, and this is a window test, not a hygiene one.
    #[test]
    fn an_unparseable_timestamp_falls_back_to_the_text_comparison() {
        let w = TimeWindow::new("2026-08-01T00:00:00Z", "2026-08-21T23:59:59.999Z", 0, "test");
        assert!(!w.contains("20200922"), "sorts below the lower bound as text, as before");
        assert!(w.contains("2026-08-10T09:00:00Z"));
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
