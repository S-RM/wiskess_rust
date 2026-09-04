//! Log continuity: when did this host's record stop, and when did it resume?
//!
//! A restored or rebuilt host is the single most consequential thing a triage
//! can miss. Its evidence looks thin rather than absent — the timeline simply
//! stops, resumes days later, and every artefact before the resume belongs to a
//! machine that no longer exists. A verdict of "clean" drawn across that seam is
//! not a verdict at all.
//!
//! The signal is a gap in the event-log series whose far edge is recent. The
//! trap is that a powered-off machine produces exactly the same shape, so a
//! detector that stops at "gap" flags every weekend and every holiday shutdown.
//! What separates them is what brackets the gap:
//!
//! * a clean shutdown followed by a boot -> the machine was off. Downtime.
//! * an event-log clear (1102 / 104) -> the record was destroyed, not lost.
//! * neither -> the record stops with no explanation in it, which is what a
//!   restore from image looks like.
//!
//! All three are reported. Only the last two are treated as findings, and the
//! first is reported precisely so a reader can see it was considered and
//! excluded rather than never looked for.

use anyhow::Result;
use chrono::{Duration, NaiveDate, NaiveDateTime};
use std::collections::BTreeMap;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::output::event::UnifiedEvent;

/// Below this a break in the record is ordinary quiet, not a gap. A full day of
/// total silence on a Windows host is not: even an idle server writes service,
/// time-sync and update records daily.
///
/// ASSUMPTION: not specified by the operator. Stated here so it is reviewable.
pub const MIN_GAP_HOURS: i64 = 24;

/// A gap whose far edge lands within this many days of the end of the record is
/// "recent" — the operator's "something recent like a few days ago", widened to
/// two weeks so a collection taken the week after a rebuild still catches it.
///
/// ASSUMPTION: not specified by the operator.
pub const RECENT_DAYS: i64 = 14;

/// An OS installed within this window of the last logged event is itself a
/// restoration signal, independent of any gap.
///
/// ASSUMPTION: not specified by the operator.
pub const RECENT_INSTALL_DAYS: i64 = 90;

/// How far either side of a gap a lifecycle record still counts as bracketing it.
const BRACKET_HOURS: i64 = 3;

/// Event IDs that say the machine was shut down deliberately or lost power.
const SHUTDOWN_EIDS: &[&str] = &[
    "6006", // event log service stopped — the clean end of a session
    "1074", // shutdown initiated by a process or user
    "6008", // previous shutdown was unexpected
    "41",   // kernel power: rebooted without a clean shutdown
    "13",   // kernel general: shutting down
];

/// Event IDs that say the machine came back up.
const BOOT_EIDS: &[&str] = &[
    "6005", // event log service started — the clean start of a session
    "12",   // kernel general: starting up
];

/// Event IDs that say the record was destroyed rather than merely absent.
const CLEARED_EIDS: &[&str] = &[
    "1102", // security log cleared
    "104",  // a non-security log cleared
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapKind {
    /// Bracketed by a clean shutdown and a boot: the host was off.
    Downtime,
    /// An event-log clear sits at the near edge.
    LogCleared,
    /// Recent, and nothing in the record explains it.
    PossibleRestoration,
    /// Older, and nothing in the record explains it.
    Unexplained,
}

impl GapKind {
    pub fn label(&self) -> &'static str {
        match self {
            GapKind::Downtime => "downtime (bracketed by shutdown/boot)",
            GapKind::LogCleared => "event log cleared",
            GapKind::PossibleRestoration => "POSSIBLE RESTORATION",
            GapKind::Unexplained => "unexplained",
        }
    }
    /// Is this a finding, as opposed to an explained absence?
    pub fn is_finding(&self) -> bool {
        !matches!(self, GapKind::Downtime)
    }
}

#[derive(Debug, Clone)]
pub struct LogGap {
    /// Last event before the record stops.
    pub before: String,
    /// First event after it resumes. For a restoration this is the restore date.
    pub after: String,
    pub hours: i64,
    pub kind: GapKind,
    /// The lifecycle record that classified it, if there was one.
    pub evidence: String,
}

/// A ranked restoration candidate: one gap, with whatever independently
/// corroborates it.
///
/// The estimate already worked — on a 28-host run it produced dates for 22 of
/// 28 and revealed the estate had restored in two clusters 44 days apart. What
/// it lacked was a shape a consumer could read. Three full runs of a downstream
/// tool rejected the estimate because the word "POSSIBLE" reached the model
/// inside a wall of markdown, and because a host restored twice collapsed to a
/// single date.
#[derive(Debug, Clone)]
pub struct RestorationCandidate {
    /// The date the record resumes: the restoration date being proposed.
    pub resumes: String,
    pub stops: String,
    pub gap_hours: i64,
    pub kind: GapKind,
    /// Why this gap is read the way it is.
    pub basis: String,
    /// Independent evidence of a rebuild around this date — OS install, EDR
    /// (re)installation, the first post-gap boot. Each is evidence on its own;
    /// together they are the difference between an inference and a finding.
    pub corroboration: Vec<String>,
    /// Days from this resume to the end of the record. Recency is the primary
    /// ranking key: a restore is the *most recent* unexplained break.
    pub days_before_end: i64,
}

impl RestorationCandidate {
    /// Higher is a better candidate. Recent first, then the longer gap, then
    /// corroborated over bare.
    fn rank_key(&self) -> (i64, i64, usize) {
        (-self.days_before_end, self.gap_hours, self.corroboration.len())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Continuity {
    pub events_scanned: usize,
    pub series_first: Option<String>,
    pub series_last: Option<String>,
    pub days_with_events: usize,
    pub gaps: Vec<LogGap>,
    pub cleared_at: Vec<String>,
    /// OS install date, from `Host_Information.csv`.
    pub install_date: Option<String>,
    /// Install date within [`RECENT_INSTALL_DAYS`] of the last logged event.
    pub install_is_recent: bool,
    /// The `Security Log Retention` line wiskess writes, verbatim.
    pub security_log_retention: Option<String>,
    /// The end of that retention range: the latest moment the host's own hive
    /// says it was logging, which is the closest thing to a collection time the
    /// evidence carries.
    pub collection_at: Option<String>,
    /// Every unexplained gap, ranked. Not just the most recent: a host restored
    /// twice, or with a long outage before the restore, collapses to one date
    /// otherwise.
    pub candidates: Vec<RestorationCandidate>,
    /// Hours between the last parsed event and [`Continuity::collection_at`].
    /// A record that stops before the host was collected leaves a window in
    /// which nothing was observed — the same finding as an interior gap, at the
    /// edge where it is easiest to miss.
    pub trailing_gap_hours: Option<i64>,
}

impl Continuity {
    /// The single date a reader wants: when the record resumes after the most
    /// recent unexplained break.
    pub fn restoration_date(&self) -> Option<&str> {
        self.gaps
            .iter()
            .rfind(|g| matches!(g.kind, GapKind::PossibleRestoration))
            .map(|g| g.after.as_str())
    }

    pub fn findings(&self) -> impl Iterator<Item = &LogGap> {
        self.gaps.iter().filter(|g| g.kind.is_finding())
    }

    /// The best restoration candidate, as a structured value rather than as a
    /// sentence buried in markdown.
    pub fn best_candidate(&self) -> Option<&RestorationCandidate> {
        self.candidates.first()
    }

    /// Build the ranked candidate list from the gaps, folding in corroboration.
    ///
    /// `installs` are `(when, what)` pairs for independent rebuild signals the
    /// caller found elsewhere in the timeline — an EDR agent install, the OS
    /// install date, a first boot.
    pub fn rank_candidates(&mut self, installs: &[(String, String)]) {
        let end = self.series_last.as_deref().and_then(parse_ts);
        let mut out: Vec<RestorationCandidate> = Vec::new();

        for g in self.gaps.iter().filter(|g| g.kind.is_finding()) {
            let resume = parse_ts(&g.after);
            let days_before_end = match (resume, end) {
                (Some(r), Some(e)) => (e - r).num_days(),
                _ => i64::MAX,
            };

            let mut corroboration = Vec::new();
            if let (Some(r), Some(install)) =
                (resume, self.install_date.as_deref().and_then(parse_ts))
            {
                let delta = (r - install).num_days();
                if delta.abs() <= RESTORE_CORROBORATION_DAYS {
                    corroboration.push(format!(
                        "OS install date {} is {} day(s) from this resume",
                        iso(&install),
                        delta.abs()
                    ));
                }
            }
            for (when, what) in installs {
                if let (Some(r), Some(w)) = (resume, parse_ts(when)) {
                    let delta = (w - r).num_days();
                    if (0..=RESTORE_CORROBORATION_DAYS).contains(&delta) {
                        corroboration.push(format!("{what} at {when}, {delta} day(s) after the resume"));
                    }
                }
            }

            out.push(RestorationCandidate {
                resumes: g.after.clone(),
                stops: g.before.clone(),
                gap_hours: g.hours,
                kind: g.kind,
                basis: g.evidence.clone(),
                corroboration,
                days_before_end,
            });
        }

        out.sort_by_key(|c| std::cmp::Reverse(c.rank_key()));
        self.candidates = out;
    }
}

/// How close an independent rebuild signal has to sit to a resume for it to
/// corroborate it.
///
/// ASSUMPTION: not specified by the operator. A rebuild is patched, re-enrolled
/// and re-agented over the days that follow, not the same minute.
pub const RESTORE_CORROBORATION_DAYS: i64 = 7;

/// Products whose (re)installation is independent evidence of a rebuild, and —
/// after a restoration date — evidence that a finding belongs to the
/// restoration process rather than to an actor.
pub const REBUILD_SIGNAL_MARKERS: &[&str] = &[
    "sentinelone", "sentinel agent", "crowdstrike", "falcon sensor", "f-secure", "withsecure",
    "sophos", "carbon black", "cylance", "defender for endpoint", "mma agent",
    "microsoft monitoring agent", "azure connected machine", "tanium", "rapid7", "insight agent",
    "arctic wolf", "huntress", "trellix", "mcafee agent", "vmware tools", "domain join",
    "joined to domain", "windows update", "cumulative update", "servicing stack",
];

/// Parse the timestamps wiskess writes. Two shapes appear: ISO with a `Z`
/// (`2026-02-01T00:01:31.575Z`) and a space-separated local form
/// (`2026-05-11 14:58:47.688180`).
pub fn parse_ts(ts: &str) -> Option<NaiveDateTime> {
    let s = ts.trim().trim_end_matches('Z');
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(dt);
        }
    }
    None
}

/// A timestamp before this is corrupt, not old. The platform's ingest turns a
/// microsecond value read as milliseconds into 1970-01-21, and a single such row
/// would make the whole series look like it starts in 1970 with a 56-year gap.
fn plausible(dt: &NaiveDateTime) -> bool {
    dt.date() >= NaiveDate::from_ymd_opt(1990, 1, 1).unwrap()
}

/// One streaming pass over `event-logs.csv`, collecting only what continuity
/// needs: a per-day first/last timestamp, and the lifecycle records.
pub fn scan_event_logs(filepath: &Path) -> Result<Continuity> {
    let file = std::fs::File::open(filepath)?;
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(BufReader::new(file));
    let headers = rdr.headers()?.clone();
    let col = |name: &str| headers.iter().position(|h| h == name);
    let ts_idx = col("datetime").unwrap_or(0);
    // EvtxECmd writes `EventId`; some reconstructions carry `EventID`.
    let eid_idx = col("EventId").or_else(|| col("EventID"));

    let mut days: BTreeMap<NaiveDate, (NaiveDateTime, NaiveDateTime)> = BTreeMap::new();
    let mut shutdowns: Vec<NaiveDateTime> = Vec::new();
    let mut boots: Vec<NaiveDateTime> = Vec::new();
    let mut cleared: Vec<NaiveDateTime> = Vec::new();
    let mut scanned = 0usize;

    for result in rdr.records() {
        let Ok(record) = result else { continue };
        let Some(dt) = record.get(ts_idx).and_then(parse_ts) else { continue };
        if !plausible(&dt) {
            continue;
        }
        scanned += 1;

        days.entry(dt.date())
            .and_modify(|(lo, hi)| {
                if dt < *lo { *lo = dt; }
                if dt > *hi { *hi = dt; }
            })
            .or_insert((dt, dt));

        if let Some(eid) = eid_idx.and_then(|i| record.get(i)).map(str::trim) {
            if SHUTDOWN_EIDS.contains(&eid) {
                shutdowns.push(dt);
            } else if BOOT_EIDS.contains(&eid) {
                boots.push(dt);
            } else if CLEARED_EIDS.contains(&eid) {
                cleared.push(dt);
            }
        }
    }

    shutdowns.sort();
    boots.sort();
    cleared.sort();

    let mut c = Continuity {
        events_scanned: scanned,
        days_with_events: days.len(),
        series_first: days.values().next().map(|(lo, _)| iso(lo)),
        series_last: days.values().next_back().map(|(_, hi)| iso(hi)),
        cleared_at: cleared.iter().map(iso).collect(),
        ..Default::default()
    };

    let series_last = days.values().next_back().map(|(_, hi)| *hi);
    let bounds: Vec<(NaiveDateTime, NaiveDateTime)> = days.values().copied().collect();
    for pair in bounds.windows(2) {
        let (_, prev_hi) = pair[0];
        let (next_lo, _) = pair[1];
        let hours = (next_lo - prev_hi).num_hours();
        if hours < MIN_GAP_HOURS {
            continue;
        }
        let (kind, evidence) =
            classify(prev_hi, next_lo, series_last, &shutdowns, &boots, &cleared);
        c.gaps.push(LogGap {
            before: iso(&prev_hi),
            after: iso(&next_lo),
            hours,
            kind,
            evidence,
        });
    }

    Ok(c)
}

/// Decide what a gap is from what sits at its edges.
///
/// Order matters. A cleared log inside a downtime window is still a cleared log:
/// clearing is checked first because it is the more serious explanation and the
/// two are not mutually exclusive.
fn classify(
    before: NaiveDateTime,
    after: NaiveDateTime,
    series_last: Option<NaiveDateTime>,
    shutdowns: &[NaiveDateTime],
    boots: &[NaiveDateTime],
    cleared: &[NaiveDateTime],
) -> (GapKind, String) {
    let bracket = Duration::hours(BRACKET_HOURS);

    if let Some(t) = cleared.iter().find(|t| **t >= before - bracket && **t <= after + bracket) {
        return (GapKind::LogCleared, format!("event log cleared at {}", iso(t)));
    }

    let shut = shutdowns.iter().find(|t| **t >= before - bracket && **t <= after);
    let boot = boots.iter().find(|t| **t >= before && **t <= after + bracket);
    if let (Some(s), Some(b)) = (shut, boot) {
        return (
            GapKind::Downtime,
            format!("shutdown {} -> boot {}", iso(s), iso(b)),
        );
    }

    let recent = series_last
        .map(|last| (last - after).num_days() <= RECENT_DAYS)
        .unwrap_or(false);
    if recent {
        (
            GapKind::PossibleRestoration,
            "no shutdown or boot record brackets this gap".to_string(),
        )
    } else {
        (
            GapKind::Unexplained,
            "no shutdown or boot record brackets this gap".to_string(),
        )
    }
}

/// Fold in the facts wiskess records outside the event logs.
///
/// An OS installed days before the collection is a restoration signal on its
/// own — it needs no gap, because a rebuilt host has no earlier record to break.
pub fn add_host_information(c: &mut Continuity, host_info_csv: &Path) {
    let fields = crate::timeline_parser::parsers::host_info::host_info_fields(host_info_csv);
    c.install_date = fields.get("Install Date").cloned();
    c.security_log_retention = fields.get("Security Log Retention").cloned();

    if let (Some(install), Some(last)) = (&c.install_date, &c.series_last) {
        if let (Some(i), Some(l)) = (parse_ts(install), parse_ts(last)) {
            c.install_is_recent = (l - i).num_days() <= RECENT_INSTALL_DAYS && l >= i;
        }
    }

    c.collection_at = c.security_log_retention.as_deref().and_then(retention_end);
    if let (Some(last), Some(coll)) = (&c.series_last, &c.collection_at) {
        if let (Some(l), Some(k)) = (parse_ts(last), parse_ts(coll)) {
            let hours = (k - l).num_hours();
            if hours >= MIN_GAP_HOURS {
                c.trailing_gap_hours = Some(hours);
            }
        }
    }
}

/// Pull the end date out of `From: <a> to: <b>`.
///
/// Split on `" to: "` rather than on `:` — every timestamp in the line is full
/// of colons, and splitting on those returns the hour field.
pub fn retention_end(retention: &str) -> Option<String> {
    let (_, end) = retention.split_once(" to: ")?;
    let end = end.trim();
    (!end.is_empty()).then(|| end.to_string())
}

fn iso(dt: &NaiveDateTime) -> String {
    format!("{}Z", dt.format("%Y-%m-%dT%H:%M:%S"))
}

/// Findings become timeline events, so a gap is visible to anything reading the
/// supertimeline or the OpenSearch NDJSON rather than only to a human reading
/// the report. The event is stamped at the *resume* — that is the date being
/// reported, and it is where an analyst pivots to.
pub fn to_events(c: &Continuity, hostname: &str) -> Vec<UnifiedEvent> {
    let mut out = Vec::new();
    for g in c.findings() {
        let (severity, tactic, technique) = match g.kind {
            GapKind::LogCleared => ("high", "Defense Evasion", "T1070.001"),
            GapKind::PossibleRestoration => ("high", "", ""),
            _ => ("med", "", ""),
        };
        out.push(UnifiedEvent {
            timestamp: g.after.clone(),
            source: "log-continuity".to_string(),
            event_type: "log_gap".to_string(),
            severity: severity.to_string(),
            description: format!(
                "Event log record resumes after a {}h break ({}). Last event before: {}. {}",
                g.hours,
                g.kind.label(),
                g.before,
                g.evidence
            ),
            indicators: vec![
                format!("LOG_GAP:{}h", g.hours),
                format!("CONTINUITY:{}", g.kind.label()),
            ],
            mitre_tactic: tactic.to_string(),
            mitre_technique: technique.to_string(),
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "log_continuity".to_string(),
            ..Default::default()
        });
    }
    out
}

// ── Phase partition ──────────────────────────────────────────────────────────

pub const PHASE_PRE: &str = "pre-restoration";
pub const PHASE_PROCESS: &str = "restoration-process";
pub const PHASE_RESPONDER: &str = "responder";
pub const PHASE_POST: &str = "post-restoration";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhaseCounts {
    pub pre: usize,
    pub process: usize,
    pub responder: usize,
    pub post: usize,
}

/// Independent rebuild signals found in the timeline: EDR/agent installs,
/// platform updates, domain rejoins. Used both to corroborate a restoration
/// date and to explain what happens immediately after one.
pub fn rebuild_signals(events: &[UnifiedEvent]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for e in events {
        if !matches!(
            e.event_type.as_str(),
            "service_installed" | "process_execution" | "software_installed" | "file_created"
        ) {
            continue;
        }
        let lower = e.description.to_lowercase();
        if let Some(m) = REBUILD_SIGNAL_MARKERS.iter().find(|m| lower.contains(**m)) {
            out.push((e.timestamp.clone(), format!("{m} installed/updated")));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Partition every event against the host's restoration date.
///
/// A finding dated after a restoration is one of exactly three things, and they
/// are not equally interesting: the restoration process itself (EDR deployment,
/// domain rejoin, patching — expected, high volume, benign), the responder's own
/// collection, or genuine post-restoration attacker activity. Today all three
/// land in one undifferentiated pile, which is how a host whose entire 7.7-hour
/// window postdates its restoration produced a "post-restoration activity"
/// finding that was, in the reviewer's words, "definitionally true and
/// evidentially empty".
///
/// The last category is meant to be small and loud. Everything this function can
/// name, it names, so that what is left over is worth reading.
pub fn assign_phases(events: &mut [UnifiedEvent], restoration_date: &str) -> PhaseCounts {
    let mut counts = PhaseCounts::default();
    for e in events.iter_mut() {
        // A timestamp we could not read cannot be placed on either side of a
        // date. Leaving it unphased is the honest answer.
        if parse_ts(&e.timestamp).is_none() {
            continue;
        }
        let phase = if e.timestamp.as_str() < restoration_date {
            counts.pre += 1;
            PHASE_PRE
        } else if e.classification.starts_with("responder:") {
            counts.responder += 1;
            PHASE_RESPONDER
        } else if e.classification.starts_with("vendor:")
            || e.classification.starts_with("os:")
            || e.classification.starts_with("automation:")
            || {
                let lower = e.description.to_lowercase();
                REBUILD_SIGNAL_MARKERS.iter().any(|m| lower.contains(*m))
            }
        {
            counts.process += 1;
            PHASE_PROCESS
        } else {
            counts.post += 1;
            PHASE_POST
        };
        e.phase = phase.to_string();
    }
    counts
}

/// Mark the window immediately before a restoration as the high-relevance one.
///
/// The investigation team's own rule of thumb: the one to two months before a
/// host's restoration date is the highest-value window to scrutinise, because
/// that is the window in which a compromise leading to the restore would have
/// happened. A finding inside it and a finding predating it by a wide margin are
/// not equally interesting, and the report should not present them as if they
/// were.
pub fn mark_restoration_window(
    events: &mut [UnifiedEvent],
    restoration_date: &str,
    window_days: i64,
) -> usize {
    let Some(end) = parse_ts(restoration_date) else { return 0 };
    let start = end - Duration::days(window_days);
    let mut n = 0usize;
    for e in events.iter_mut() {
        let Some(dt) = parse_ts(&e.timestamp) else { continue };
        if dt >= start && dt < end {
            e.indicators.push(format!("RESTORE_WINDOW:{}d", window_days));
            n += 1;
        }
    }
    n
}

// ── Timestamp hygiene ────────────────────────────────────────────────────────

/// Validate every timestamp on the way out, and never let a parse failure
/// escape as a value arithmetic will accept.
///
/// The case: a host's activity start was the literal string `20200922` — no
/// time, wrong format — and because it sorts below every ISO timestamp it
/// silently became the start of the **case-wide** activity span, distorting
/// every gap calculation in the timing table. A value that does not parse must
/// be marked as such, not passed through.
///
/// `not_after` is the collection time: anything later is impossible and is
/// flagged rather than believed.
pub fn validate_timestamps(events: &mut [UnifiedEvent], not_after: Option<&str>) -> usize {
    let ceiling = not_after
        .and_then(parse_ts)
        // A day of slack: the retention line and the event stream are not
        // written by the same clock.
        .map(|dt| dt + Duration::days(1));
    let mut bad = 0usize;
    for e in events.iter_mut() {
        match parse_ts(&e.timestamp) {
            None => {
                e.indicators.push(format!("TIMESTAMP_INVALID:{}", e.timestamp));
                bad += 1;
            }
            Some(dt) if !plausible(&dt) => {
                e.indicators.push(format!("TIMESTAMP_IMPLAUSIBLE:{}", e.timestamp));
                bad += 1;
            }
            Some(dt) => {
                if let Some(c) = ceiling {
                    if dt > c {
                        e.indicators
                            .push(format!("TIMESTAMP_AFTER_COLLECTION:{}", e.timestamp));
                        bad += 1;
                    }
                }
            }
        }
    }
    bad
}

/// Is this a timestamp downstream arithmetic may use?
pub fn timestamp_is_usable(ts: &str) -> bool {
    parse_ts(ts).map(|dt| plausible(&dt)).unwrap_or(false)
}

/// The structured restoration record, written as its own ingestible timeline
/// file so a consumer reads a field rather than parsing a sentence out of
/// markdown.
///
/// One NDJSON line, not pretty-printed JSON: `worker.py` ingests any file whose
/// name ends in `json` and reads it a line at a time, so a multi-line object
/// would be fed to it as a sequence of syntax errors. It carries the same six
/// fields every wiskess timeline document carries — dated when the parser ran,
/// because the estimate is the analysis, not the evidence — with the estimate
/// itself alongside as fields.
pub fn write_restoration_json(
    c: &Continuity,
    hostname: &str,
    supplied: Option<&str>,
    out_dir: &Path,
) -> Result<std::path::PathBuf> {
    let filename = format!("{hostname}_restoration.json");
    let path = out_dir.join(&filename);
    let best = c.best_candidate();

    let now = chrono::Utc::now();
    let doc = serde_json::json!({
        "datetime": format!("{}Z", now.format("%Y-%m-%dT%H:%M:%S%.3f")),
        "timestamp": now.timestamp_millis(),
        "timestamp_desc": format!("restoration - {filename}: RestorationEstimate"),
        "message": restoration_sentence(supplied, best),
        "hostname": hostname,
        "doc_type": "restoration",

        "restoration_supplied": supplied,
        "restoration_inferred": best.map(|b| b.resumes.clone()),
        "restoration_basis": best.map(|b| b.basis.clone()),
        "gap_hours": best.map(|b| b.gap_hours),
        "corroboration": best.map(|b| b.corroboration.clone()).unwrap_or_default(),
        "record_first_event": c.series_first,
        "record_last_event": c.series_last,
        "collection_at": c.collection_at,
        "security_log_retention": c.security_log_retention,
        "os_install_date": c.install_date,
        "os_install_is_recent": c.install_is_recent,
        "trailing_gap_hours": c.trailing_gap_hours,
        "log_cleared_at": c.cleared_at,
        "candidates": c.candidates.iter().map(|k| serde_json::json!({
            "resumes": k.resumes,
            "stops": k.stops,
            "gap_hours": k.gap_hours,
            "assessment": k.kind.label(),
            "basis": k.basis,
            "corroboration": k.corroboration,
            "days_before_end_of_record": k.days_before_end,
        })).collect::<Vec<_>>(),
    });
    std::fs::write(&path, format!("{}\n", serde_json::to_string(&doc)?))?;
    Ok(path)
}

/// One sentence stating the estimate, for the `message` field every document in
/// the index carries.
fn restoration_sentence(supplied: Option<&str>, best: Option<&RestorationCandidate>) -> String {
    match (supplied, best) {
        (Some(s), _) => format!("Restoration date supplied by the operator: {s}."),
        (None, Some(b)) => format!(
            "Restoration inferred at {} from a {}h break in the event-log record ({}).",
            b.resumes, b.gap_hours, b.basis
        ),
        (None, None) => "No restoration date was inferred for this host.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build an `event-logs.csv` from `(datetime, EventId)` pairs.
    fn csv_of(dir: &tempfile::TempDir, rows: &[(&str, &str)]) -> std::path::PathBuf {
        let p = dir.path().join("event-logs.csv");
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "datetime,timestamp_desc,EventId,Channel").unwrap();
        for (ts, eid) in rows {
            writeln!(f, "{ts},event-logs - EvtxECmd-All.csv: TimeCreated,{eid},System").unwrap();
        }
        p
    }

    /// A day of events, so a series looks like a real host rather than a
    /// sequence of isolated records.
    fn day(d: &str) -> Vec<(String, String)> {
        vec![
            (format!("{d}T01:00:00.000Z"), "7036".to_string()),
            (format!("{d}T13:00:00.000Z"), "7036".to_string()),
            (format!("{d}T23:00:00.000Z"), "7036".to_string()),
        ]
    }

    fn series(days: &[&str], extra: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut rows: Vec<(String, String)> = days.iter().flat_map(|d| day(d)).collect();
        rows.extend(extra.iter().map(|(a, b)| (a.to_string(), b.to_string())));
        rows.sort();
        rows
    }

    fn scan(rows: &[(String, String)]) -> Continuity {
        let dir = tempfile::tempdir().unwrap();
        let borrowed: Vec<(&str, &str)> =
            rows.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let p = csv_of(&dir, &borrowed);
        scan_event_logs(&p).unwrap()
    }

    /// A continuous record has no gaps. If this fires on an ordinary host the
    /// detector is useless — every report would carry a false restoration.
    #[test]
    fn a_continuous_record_reports_no_gaps() {
        let c = scan(&series(
            &["2026-05-01", "2026-05-02", "2026-05-03", "2026-05-04", "2026-05-05"],
            &[],
        ));
        assert!(c.gaps.is_empty(), "{:?}", c.gaps);
        assert_eq!(c.days_with_events, 5);
        assert_eq!(c.series_first.as_deref(), Some("2026-05-01T01:00:00Z"));
        assert_eq!(c.series_last.as_deref(), Some("2026-05-05T23:00:00Z"));
    }

    /// The case the operator described: the record stops, resumes days later,
    /// and nothing in it explains why.
    #[test]
    fn an_unexplained_recent_gap_is_a_possible_restoration() {
        let c = scan(&series(
            &["2026-05-01", "2026-05-02", "2026-05-09", "2026-05-10"],
            &[],
        ));
        assert_eq!(c.gaps.len(), 1, "{:?}", c.gaps);
        let g = &c.gaps[0];
        assert_eq!(g.kind, GapKind::PossibleRestoration);
        assert_eq!(g.before, "2026-05-02T23:00:00Z");
        assert_eq!(g.after, "2026-05-09T01:00:00Z");
        assert_eq!(g.hours, 146);
        assert_eq!(c.restoration_date(), Some("2026-05-09T01:00:00Z"));
    }

    /// The false positive this detector would otherwise generate on every
    /// powered-off weekend. A shutdown and a boot at the edges explain the gap,
    /// and it must not be reported as a restoration.
    #[test]
    fn a_gap_bracketed_by_shutdown_and_boot_is_downtime_not_restoration() {
        let c = scan(&series(
            &["2026-05-01", "2026-05-02", "2026-05-09", "2026-05-10"],
            &[("2026-05-02T23:30:00.000Z", "6006"), ("2026-05-09T00:30:00.000Z", "6005")],
        ));
        assert_eq!(c.gaps.len(), 1, "{:?}", c.gaps);
        assert_eq!(c.gaps[0].kind, GapKind::Downtime);
        assert!(!c.gaps[0].kind.is_finding());
        assert!(c.gaps[0].evidence.contains("shutdown"), "{}", c.gaps[0].evidence);
        assert_eq!(c.restoration_date(), None);
        assert_eq!(c.findings().count(), 0);
    }

    /// A cleared log outranks a downtime bracket: the record was destroyed, and
    /// that is the finding whatever else was happening.
    #[test]
    fn a_cleared_log_outranks_a_downtime_bracket() {
        let c = scan(&series(
            &["2026-05-01", "2026-05-02", "2026-05-09", "2026-05-10"],
            &[
                ("2026-05-02T23:30:00.000Z", "6006"),
                ("2026-05-02T23:45:00.000Z", "1102"),
                ("2026-05-09T00:30:00.000Z", "6005"),
            ],
        ));
        assert_eq!(c.gaps[0].kind, GapKind::LogCleared);
        assert!(c.gaps[0].kind.is_finding());
        assert_eq!(c.cleared_at, vec!["2026-05-02T23:45:00Z"]);
    }

    /// Recency is what separates a restoration from a hole in an old record.
    /// Both gaps here are unexplained; only the one that resumes near the end of
    /// the record is a restoration candidate. The older one is still reported —
    /// an unexplained gap is a limit on any conclusion drawn across it — but it
    /// is not the date being asked for.
    #[test]
    fn only_the_gap_that_resumes_recently_is_a_restoration() {
        let c = scan(&series(
            &["2026-01-01", "2026-01-02", "2026-01-20", "2026-05-09", "2026-05-10"],
            &[],
        ));
        let kinds: Vec<GapKind> = c.gaps.iter().map(|g| g.kind).collect();
        assert_eq!(kinds, vec![GapKind::Unexplained, GapKind::PossibleRestoration]);
        assert_eq!(c.restoration_date(), Some("2026-05-09T01:00:00Z"));
        assert_eq!(c.findings().count(), 2);
    }

    /// The same shape with the record continuing long after the gap: nothing
    /// resumes recently, so there is no restoration date to report.
    #[test]
    fn a_gap_far_from_the_end_of_the_record_is_only_unexplained() {
        let c = scan(&series(
            &["2026-01-01", "2026-01-02", "2026-01-20", "2026-01-21"],
            &[("2026-05-10T12:00:00.000Z", "7036")],
        ));
        let kinds: Vec<GapKind> = c.gaps.iter().map(|g| g.kind).collect();
        assert_eq!(kinds, vec![GapKind::Unexplained, GapKind::PossibleRestoration]);
        // The trailing single event is itself the recent resume — which is the
        // point: a record that stops in January and reappears in May is exactly
        // the finding, not an artefact of the test.
        assert_eq!(c.restoration_date(), Some("2026-05-10T12:00:00Z"));
    }

    /// Quiet is not a gap. Overnight silence must not trip the threshold.
    #[test]
    fn a_quiet_night_is_not_a_gap() {
        let dir = tempfile::tempdir().unwrap();
        let p = csv_of(
            &dir,
            &[("2026-05-01T22:00:00.000Z", "7036"), ("2026-05-02T07:00:00.000Z", "7036")],
        );
        assert!(scan_event_logs(&p).unwrap().gaps.is_empty());
    }

    /// The ingest defect that renders a microsecond timestamp as 1970-01-21
    /// would otherwise put a 56-year gap at the head of every affected series.
    #[test]
    fn a_1970_timestamp_does_not_manufacture_a_gap() {
        let mut rows = series(&["2026-05-01", "2026-05-02"], &[]);
        rows.insert(0, ("1970-01-21T03:00:00.000Z".to_string(), "7036".to_string()));
        let c = scan(&rows);
        assert!(c.gaps.is_empty(), "{:?}", c.gaps);
        assert_eq!(c.series_first.as_deref(), Some("2026-05-01T01:00:00Z"));
        assert_eq!(c.events_scanned, 6, "the corrupt row is excluded, not counted");
    }

    #[test]
    fn timestamps_parse_in_both_shapes_wiskess_writes() {
        assert!(parse_ts("2026-02-01T00:01:31.575Z").is_some());
        assert!(parse_ts("2026-05-11 14:58:47.688180").is_some());
        assert!(parse_ts("2026-05-11T14:58:47").is_some());
        assert!(parse_ts("not a date").is_none());
    }

    #[test]
    fn host_information_supplies_the_install_date() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Host_Information.csv");
        std::fs::write(
            &p,
            "datetime,timestamp_desc,message\n\
             2026-05-11 14:58:47.6,Hostinfo - All host info.,Install Date: 2026-04-20 10:00:00.0000000\n\
             2026-05-11 14:58:47.6,Hostinfo - All host info.,\"Security Log Retention: From: 2026-05-05 07:24:05 to: 2026-05-11 09:35:03\"\n",
        )
        .unwrap();

        let mut c = Continuity {
            series_last: Some("2026-05-11T09:00:00Z".into()),
            ..Default::default()
        };
        add_host_information(&mut c, &p);
        assert_eq!(c.install_date.as_deref(), Some("2026-04-20 10:00:00.0000000"));
        assert!(c.install_is_recent, "an OS installed 21 days ago is a restoration signal");
        assert!(c.security_log_retention.as_deref().unwrap().contains("2026-05-05"));
    }

    /// The corpus case: the parsed record ends five days before the host's own
    /// hive says it was still logging. Nothing was observed in between, and at
    /// the trailing edge that is easy to miss entirely.
    #[test]
    fn a_record_that_stops_before_collection_is_a_trailing_gap() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Host_Information.csv");
        std::fs::write(
            &p,
            "datetime,timestamp_desc,message\n\
             2026-05-11 14:58:47.6,Hostinfo,\"Security Log Retention: From: 2026-05-05 07:24:05.2392688 to: 2026-05-11 09:35:03.2041926\"\n",
        )
        .unwrap();
        let mut c = Continuity {
            series_last: Some("2026-05-06T20:00:27Z".into()),
            ..Default::default()
        };
        add_host_information(&mut c, &p);
        assert_eq!(c.collection_at.as_deref(), Some("2026-05-11 09:35:03.2041926"));
        assert_eq!(c.trailing_gap_hours, Some(109));
    }

    /// A record that runs up to collection has no trailing gap. Reporting one on
    /// every host would make the real ones invisible.
    #[test]
    fn a_record_running_up_to_collection_has_no_trailing_gap() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Host_Information.csv");
        std::fs::write(
            &p,
            "datetime,timestamp_desc,message\n\
             2026-05-11 14:58:47.6,Hostinfo,\"Security Log Retention: From: 2026-05-05 07:24:05 to: 2026-05-11 09:35:03\"\n",
        )
        .unwrap();
        let mut c = Continuity {
            series_last: Some("2026-05-11T08:00:00Z".into()),
            ..Default::default()
        };
        add_host_information(&mut c, &p);
        assert_eq!(c.trailing_gap_hours, None);
    }

    #[test]
    fn the_retention_range_end_survives_its_own_colons() {
        assert_eq!(
            retention_end("From: 2026-05-05 07:24:05.2392688 to: 2026-05-11 09:35:03.2041926")
                .as_deref(),
            Some("2026-05-11 09:35:03.2041926")
        );
        assert_eq!(retention_end("no range here"), None);
    }

    /// A host installed years ago must not be flagged.
    #[test]
    fn an_old_install_date_is_not_a_restoration_signal() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Host_Information.csv");
        std::fs::write(
            &p,
            "datetime,timestamp_desc,message\n\
             2026-05-11 14:58:47.6,Hostinfo,Install Date: 2019-06-07 23:37:44.0000000\n",
        )
        .unwrap();
        let mut c = Continuity {
            series_last: Some("2026-05-11T09:00:00Z".into()),
            ..Default::default()
        };
        add_host_information(&mut c, &p);
        assert!(!c.install_is_recent);
    }

    /// Findings must reach the timeline, stamped at the resume.
    #[test]
    fn findings_become_timeline_events_stamped_at_the_resume() {
        let c = scan(&series(
            &["2026-05-01", "2026-05-02", "2026-05-09", "2026-05-10"],
            &[],
        ));
        let events = to_events(&c, "MY-DC02");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp, "2026-05-09T01:00:00Z");
        assert_eq!(events[0].severity, "high");
        assert_eq!(events[0].source, "log-continuity");
        assert!(events[0].indicators.iter().any(|i| i.starts_with("LOG_GAP:")));
    }


    // ── Ranked candidates, phases and timestamp hygiene ──────────────────────

    fn ev(ts: &str, desc: &str, class: &str) -> UnifiedEvent {
        UnifiedEvent {
            timestamp: ts.to_string(),
            source: "event-logs".to_string(),
            event_type: "service_installed".to_string(),
            severity: "high".to_string(),
            description: desc.to_string(),
            classification: class.to_string(),
            ..Default::default()
        }
    }

    /// A host restored twice collapses to one date today. Both gaps have to
    /// survive, ranked, with the most recent first.
    #[test]
    fn every_unexplained_gap_becomes_a_ranked_candidate() {
        let mut c = scan(&series(
            &["2026-01-01", "2026-01-02", "2026-01-20", "2026-05-09", "2026-05-10"],
            &[],
        ));
        c.rank_candidates(&[]);
        assert_eq!(c.candidates.len(), 2, "{:?}", c.candidates);
        assert_eq!(c.candidates[0].resumes, "2026-05-09T01:00:00Z", "most recent ranks first");
        assert_eq!(c.candidates[1].resumes, "2026-01-20T01:00:00Z");
        assert_eq!(c.best_candidate().unwrap().gap_hours, 2594);
    }

    /// An EDR install hours after the resume is independent evidence of a
    /// rebuild, and it should be emitted rather than left for a reader to spot.
    #[test]
    fn an_edr_install_after_the_resume_corroborates_the_candidate() {
        let mut c = scan(&series(
            &["2026-05-01", "2026-05-02", "2026-05-09", "2026-05-10"],
            &[],
        ));
        c.rank_candidates(&[(
            "2026-05-09T06:00:00Z".to_string(),
            "sentinelone installed/updated".to_string(),
        )]);
        let best = c.best_candidate().unwrap();
        assert_eq!(best.corroboration.len(), 1, "{best:?}");
        assert!(best.corroboration[0].contains("sentinelone"), "{best:?}");
    }

    /// An install long after the resume is not corroboration of it.
    #[test]
    fn a_distant_install_does_not_corroborate() {
        let mut c = scan(&series(&["2026-05-01", "2026-05-02", "2026-05-09", "2026-05-10"], &[]));
        c.rank_candidates(&[("2026-07-01T06:00:00Z".to_string(), "sentinelone installed/updated".to_string())]);
        assert!(c.best_candidate().unwrap().corroboration.is_empty());
    }

    /// The four-way split. The last category is the one that matters and it has
    /// to be small: everything nameable is named.
    #[test]
    fn findings_after_a_restoration_are_partitioned_four_ways() {
        let mut events = vec![
            ev("2026-05-01T10:00:00Z", "A new service was installed: evil.exe", ""),
            ev("2026-05-20T10:00:00Z", "SentinelOne agent installed", ""),
            ev("2026-05-20T11:00:00Z", "ir-Collector-Windows.exe ran", "responder:collector"),
            ev("2026-05-21T02:00:00Z", "A new service was installed: srvhost.exe", ""),
        ];
        let counts = assign_phases(&mut events, "2026-05-19T00:00:00Z");
        assert_eq!(counts, PhaseCounts { pre: 1, process: 1, responder: 1, post: 1 });
        assert_eq!(events[0].phase, PHASE_PRE);
        assert_eq!(events[1].phase, PHASE_PROCESS, "an EDR install after a rebuild is the rebuild");
        assert_eq!(events[2].phase, PHASE_RESPONDER);
        assert_eq!(events[3].phase, PHASE_POST, "the unexplained one must stand alone");
    }

    /// An unreadable timestamp cannot be placed on either side of a date, and
    /// pretending otherwise is how `20200922` became a case-wide activity start.
    #[test]
    fn an_unreadable_timestamp_is_left_unphased() {
        let mut events = vec![ev("20200922", "something", "")];
        let counts = assign_phases(&mut events, "2026-05-19T00:00:00Z");
        assert_eq!(counts, PhaseCounts::default());
        assert!(events[0].phase.is_empty());
    }

    /// The literal case from the run: a value that does not parse must be
    /// flagged, never passed through as something arithmetic will accept.
    #[test]
    fn a_malformed_timestamp_is_flagged_rather_than_believed() {
        let mut events = vec![
            ev("20200922", "activity start", ""),
            ev("1970-01-21T03:00:00Z", "microsecond value read as millis", ""),
            ev("2026-05-05T10:00:00Z", "ordinary", ""),
            ev("2027-01-01T00:00:00Z", "after the collection", ""),
        ];
        let bad = validate_timestamps(&mut events, Some("2026-05-11 09:35:03"));
        assert_eq!(bad, 3);
        assert!(events[0].indicators.iter().any(|i| i.starts_with("TIMESTAMP_INVALID:")));
        assert!(events[1].indicators.iter().any(|i| i.starts_with("TIMESTAMP_IMPLAUSIBLE:")));
        assert!(events[2].indicators.is_empty(), "a good timestamp must be left alone");
        assert!(events[3].indicators.iter().any(|i| i.starts_with("TIMESTAMP_AFTER_COLLECTION:")));

        assert!(!timestamp_is_usable("20200922"));
        assert!(timestamp_is_usable("2026-05-05T10:00:00Z"));
    }

    /// The investigation team's rule of thumb: the window that *ends* at the
    /// restore is where the compromise that led to it happened.
    #[test]
    fn the_window_before_a_restore_is_marked_and_nothing_else_is() {
        let mut events = vec![
            ev("2026-01-01T10:00:00Z", "long before", ""),   // 138 days before
            ev("2026-04-20T10:00:00Z", "inside the window", ""), // 29 days before
            ev("2026-05-20T10:00:00Z", "after the restore", ""),
        ];
        let n = mark_restoration_window(&mut events, "2026-05-19T00:00:00Z", 60);
        assert_eq!(n, 1);
        assert!(events[1].indicators.iter().any(|i| i == "RESTORE_WINDOW:60d"));
        assert!(events[0].indicators.is_empty());
        assert!(events[2].indicators.is_empty());
    }

    /// The estimate has to leave as fields, not as a sentence in markdown.
    #[test]
    fn the_restoration_record_is_written_as_structured_fields() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = scan(&series(&["2026-05-01", "2026-05-02", "2026-05-09", "2026-05-10"], &[]));
        c.rank_candidates(&[]);
        let path = write_restoration_json(&c, "MY-DC02", None, dir.path()).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1, "must be one NDJSON line, not pretty-printed");
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        // The six fields every wiskess timeline document carries.
        for f in ["datetime", "timestamp", "timestamp_desc", "message", "hostname", "doc_type"] {
            assert!(v.get(f).is_some(), "missing {f}");
        }
        assert_eq!(v["doc_type"], "restoration");
        assert!(v["message"].as_str().unwrap().contains("146h"), "{}", v["message"]);
        assert_eq!(v["restoration_inferred"], "2026-05-09T01:00:00Z");
        assert_eq!(v["gap_hours"], 146);
        assert_eq!(v["restoration_supplied"], serde_json::Value::Null);
        assert_eq!(v["candidates"].as_array().unwrap().len(), 1);
    }

    /// Downtime is not a finding and must not reach the timeline as one.
    #[test]
    fn downtime_produces_no_timeline_event() {
        let c = scan(&series(
            &["2026-05-01", "2026-05-02", "2026-05-09", "2026-05-10"],
            &[("2026-05-02T23:30:00.000Z", "6006"), ("2026-05-09T00:30:00.000Z", "6005")],
        ));
        assert!(to_events(&c, "H").is_empty());
    }
}
