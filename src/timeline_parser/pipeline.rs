use anyhow::Result;
use std::path::PathBuf;
use std::time::Instant;

use crate::timeline_parser::{config, intel, output, parsers};
use crate::timeline_parser::config::{PipelineConfig, Verbosity, DEFAULT_BUSINESS_HOURS, DEFAULT_RARE_LOGON_MAX};
use crate::timeline_parser::detectors::classify::{self, Automation};
use crate::timeline_parser::detectors::compromised::CompromisedEntities;
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::restoration;
use crate::timeline_parser::detectors::software;
use crate::timeline_parser::detectors::suspicious_paths::SuspiciousPathDetector;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::output::dedup;
use crate::timeline_parser::output::event::UnifiedEvent;
use crate::timeline_parser::output::report::{generate_report, DetectionCoverage, ReportContext};
use crate::timeline_parser::parsers::wiskess_log;
use crate::timeline_parser::parsers::wiskess_log::CollectionGap;
use crate::timeline_parser::output::supertimeline::{write_supertimeline, write_triage_timeline};
use crate::timeline_parser::parsers::discovery::discover_artifacts;

/// Days before the restoration date treated as the highest-relevance window.
/// Upstream exposes this as `--restoration-window-days`; wiskess does not, so
/// the vendored pipeline pins upstream's default.
const RESTORATION_WINDOW_DAYS: i64 = 60;

/// Plain (non-clap) arguments for a single Timeline/ folder pipeline run.
/// Field-for-field equivalent of upstream's `Cli`, minus CLI-parsing concerns.
pub struct TimelineParserArgs {
    pub timeline_dir: PathBuf,
    pub iocs: Option<PathBuf>,
    pub time_start: Option<String>,
    pub time_end: Option<String>,
    pub auto_narrow: bool,
    pub output_dir: PathBuf,
    pub hayabusa_level: String,
    pub no_sigma: bool,
    pub offline: bool,
    pub hash_lookup: bool,
    pub vt: bool,
    pub vt_key: Option<String>,
    pub vt_rate: u32,
    pub data_dir: Option<PathBuf>,
    pub verbose: bool,
    /// Upstream's `--restoration-date`: a rebuild date the operator knows,
    /// which overrides the one the parser infers from log continuity.
    pub restoration_date: Option<String>,
}

/// What the caller needs to log/report after a run.
#[derive(Debug, Clone)]
pub struct TimelineParserSummary {
    pub hostname: String,
    pub event_count: usize,
    pub triage_hits: usize,
    pub elapsed_secs: f64,
    pub output_dir: PathBuf,
    pub supertimeline_csv: PathBuf,
    pub supertimeline_jsonl: PathBuf,
    pub triage_csv: PathBuf,
    pub triage_jsonl: PathBuf,
    pub report_path: PathBuf,
    pub opensearch_path: PathBuf,
    pub opensearch_count: usize,
}

pub fn run(args: TimelineParserArgs) -> Result<TimelineParserSummary> {
    let start = Instant::now();

    eprintln!("[*] Wiskess Timeline Parser (vendored, upstream v0.2.0)");

    std::fs::create_dir_all(&args.output_dir).map_err(|e| {
        anyhow::anyhow!("Cannot create output directory {:?}: {}", args.output_dir, e)
    })?;
    eprintln!("[*] Output directory: {}", args.output_dir.display());

    // Phase 1: Discovery
    eprintln!("[*] Discovering artifacts in {:?}...", args.timeline_dir);
    let artifacts = discover_artifacts(&args.timeline_dir)?;

    // Find and parse the wiskess validation log (sits in collection root, parent of Timeline/)
    let collection_root = args.timeline_dir.parent().unwrap_or(&args.timeline_dir);
    let gaps: Vec<CollectionGap> = wiskess_log::find_wiskess_log(collection_root)
        .and_then(|log_path| {
            eprintln!("[*] Wiskess log: {}", log_path.display());
            wiskess_log::parse_gaps(&log_path).ok()
        })
        .unwrap_or_default();
    eprintln!("[*] Found {} artifact files", artifacts.len());

    // Load detection engines
    let data_dir = config::resolve_data_dir(args.data_dir.as_deref());
    eprintln!("[*] Detection data dir: {}", data_dir.display());
    let ta_detector = TAToolDetector::new(&data_dir)?;
    eprintln!("[*] TA tool detector: {} patterns", ta_detector.pattern_count());
    let path_detector = SuspiciousPathDetector::new(&data_dir)?;
    let ioc_matcher = IOCMatcher::new(args.iocs.as_deref())?;

    // GeoIP/ASN/anon enrichment for IP-literal hosts (optional — no-op if no DBs).
    let geo = intel::geo::GeoReaders::open(&intel::geo::find_geo_dbs());
    if geo.available() {
        eprintln!("[*] GeoIP databases loaded for IP enrichment");
    } else {
        eprintln!("[*] No GeoIP databases found (set MAXMIND_DB_DIR; IP geo enrichment disabled)");
    }

    // Upstream moved from a bare hostname to a HostIdentity: the report needs
    // to state a divergence (`X, also resolves to Y`) rather than file the host
    // under the comma-joined pair. `name` is still what every output path uses.
    let identity = parsers::host_info::resolve_identity(&artifacts, &args.timeline_dir);
    let hostname = identity.name.clone();
    if identity.diverges() {
        let others: Vec<&str> = identity.aliases().iter().map(|(_, n)| n.as_str()).collect();
        eprintln!("[*] Hostname: {} (also resolves to {})", hostname, others.join(", "));
    } else {
        eprintln!("[*] Hostname: {}", hostname);
    }

    // Phase 2: Timeframe detection
    let window = if let (Some(ref ts), Some(ref te)) = (&args.time_start, &args.time_end) {
        let te = end_of_day(te);

        if args.auto_narrow {
            let detected = artifacts
                .get("hayabusa")
                .map(|p| parsers::hayabusa::detect_timeframe_opts(
                    p, "high", Some((ts.as_str(), te.as_str())), true))
                .transpose()?
                .flatten();
            match detected {
                Some(w) => {
                    eprintln!("[*] Narrowed within {} to {}: {} to {} ({} events, {})",
                              ts, te, w.start, w.end, w.event_count, w.confidence);
                    Some(w)
                }
                None => {
                    eprintln!("[*] No detections inside {} to {} — analysing the whole bound", ts, te);
                    Some(config::TimeWindow {
                        start: ts.clone(), end: te, event_count: 0,
                        confidence: "user-specified".to_string(),
                    })
                }
            }
        } else {
            eprintln!("[*] User timeframe: {} to {}", ts, te);
            Some(config::TimeWindow {
                start: ts.clone(), end: te, event_count: 0,
                confidence: "user-specified".to_string(),
            })
        }
    } else if let Some(hayabusa_path) = artifacts.get("hayabusa") {
        eprintln!("[*] Auto-detecting timeframe...");
        let w = parsers::hayabusa::detect_timeframe(hayabusa_path, "high")?;
        if let Some(ref win) = w {
            eprintln!("[*] Timeframe: {} to {} ({} events, {})",
                     win.start, win.end, win.event_count, win.confidence);
        }
        w
    } else {
        None
    };

    let cfg = PipelineConfig {
        hayabusa_level: args.hayabusa_level.clone(),
        window: window.clone(),
        no_sigma: args.no_sigma,
        offline: args.offline,
        verbose: args.verbose,
        // Upstream gates these three behind --verbose-events / --business-hours
        // / --rare-logon-max. wiskess does not expose those flags, so the
        // vendored pipeline runs at upstream's defaults: curated output, no
        // baseline-logon carrying. Listed explicitly rather than filled from
        // `..Default::default()` so that the next field upstream adds breaks
        // the build here instead of silently taking a default.
        verbosity: Verbosity::Curated,
        business_hours: DEFAULT_BUSINESS_HOURS,
        rare_logon_max: DEFAULT_RARE_LOGON_MAX,
    };

    // Phase 3a: Hayabusa → build compromised entities
    let mut all_events: Vec<UnifiedEvent> = Vec::new();
    let mut compromised = CompromisedEntities::new();
    compromised.add_ips(&ioc_matcher.ips);
    compromised.add_users(&ioc_matcher.usernames);

    if let Some(path) = artifacts.get("hayabusa") {
        eprintln!("[*] Parsing hayabusa...");
        let events = parsers::hayabusa::parse(path, &cfg, &ta_detector, &ioc_matcher, &hostname)?;
        for e in &events { compromised.learn_from_event(e); }
        eprintln!("[*]   {} events", events.len());
        all_events.extend(events);
    }
    eprintln!("[*]   Compromised: {} users, {} IPs, {} hostnames",
             compromised.users.len(), compromised.ips.len(), compromised.hostnames.len());

    // Phase 3b: Event-logs correlated (also returns inbound RDP/SMB session logons)
    let mut session_logons: Vec<parsers::event_logs::SessionLogon> = Vec::new();
    let mut automations: Vec<Automation> = Vec::new();
    if let Some(path) = artifacts.get("event-logs") {
        eprintln!("[*] Parsing event-logs (correlated)...");
        let out = parsers::event_logs::parse_correlated(
            path, &cfg, &ta_detector, &ioc_matcher, &hostname, &compromised,
        )?;
        eprintln!("[*]   {} events, {} session logons", out.events.len(), out.logons.len());
        if cfg.verbosity.baseline() {
            eprintln!("[*]   baseline logons: {} ({} out-of-hours, {} rare)",
                      out.baseline_logons, out.off_hours_logons, out.rare_logons);
        }
        for a in &out.automations {
            eprintln!("[*]   Automation (not a finding): {}", a.as_rate());
        }
        automations = out.automations;
        all_events.extend(classify::automation_events(&automations, &hostname));
        all_events.extend(out.events);
        session_logons = out.logons;
    }

    // Phase 3c: Network
    if let Some(path) = artifacts.get("network") {
        eprintln!("[*] Parsing network...");
        let events = parsers::network::parse(path, &cfg, &ioc_matcher, &hostname, &compromised)?;
        eprintln!("[*]   {} events", events.len());
        all_events.extend(events);
    }

    // Phase 3d: Registry
    if let Some(path) = artifacts.get("registry") {
        eprintln!("[*] Parsing registry...");
        let events = parsers::registry::parse(path, &cfg, &ta_detector, &ioc_matcher, &hostname)?;
        eprintln!("[*]   {} events", events.len());
        all_events.extend(events);
    }

    // Phase 4: MFT + USN (parallel)
    eprintln!("[*] Parsing MFT + USN Journal (parallel)...");
    let (mft_events, usn_events) = rayon::join(
        || artifacts.get("MFTECmd").map_or_else(|| Ok(vec![]), |p|
            parsers::mft::parse(p, &cfg, &ta_detector, &ioc_matcher, &path_detector, &hostname)),
        || artifacts.get("usnjrnl-j-file").map_or_else(|| Ok(vec![]), |p|
            parsers::usnjrnl::parse(p, &cfg, &ta_detector, &ioc_matcher, &path_detector, &hostname)),
    );
    let mft_events = mft_events?;
    let usn_events = usn_events?;
    eprintln!("[*]   MFT: {}, USN: {}", mft_events.len(), usn_events.len());
    all_events.extend(mft_events);
    all_events.extend(usn_events);

    // Phase 5: Low-volume
    eprintln!("[*] Parsing low-volume artifacts...");
    if let Some(p) = artifacts.get("amcache") {
        let e = parsers::amcache::parse(p, &ta_detector, &ioc_matcher, &path_detector, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   Amcache: {}", e.len()); }
        all_events.extend(e);
    }
    if let Some(p) = artifacts.get("amcache-regripper") {
        let e = parsers::amcache::parse_regripper(p, &ta_detector, &ioc_matcher, &path_detector, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   Amcache(RegRipper): {}", e.len()); }
        all_events.extend(e);
    }
    if let Some(p) = artifacts.get("appcompatcache") {
        let e = parsers::appcompatcache::parse(p, &ta_detector, &ioc_matcher, &path_detector, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   AppCompat: {}", e.len()); }
        all_events.extend(e);
    }
    if let Some(p) = artifacts.get("browser-hist") {
        let e = parsers::browser_hist::parse(p, &cfg, &ioc_matcher, &geo, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   Browser: {}", e.len()); }
        all_events.extend(e);
    }
    if let Some(p) = artifacts.get("jump-lists") {
        let e = parsers::jump_lists::parse(p, &ta_detector, &ioc_matcher, &path_detector, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   Jump-lists: {}", e.len()); }
        all_events.extend(e);
    }
    if let Some(p) = artifacts.get("lnk-files") {
        let e = parsers::lnk_files::parse(p, &ta_detector, &ioc_matcher, &path_detector, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   LNK: {}", e.len()); }
        all_events.extend(e);
    }
    if let Some(p) = artifacts.get("regripper") {
        let e = parsers::regripper::parse(p, &ta_detector, &ioc_matcher, &path_detector, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   Regripper: {}", e.len()); }
        all_events.extend(e);
    }
    if let Some(p) = artifacts.get("hindsight") {
        let e = parsers::hindsight::parse(p, &cfg, &ioc_matcher, &ta_detector, &geo, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   Hindsight: {}", e.len()); }
        all_events.extend(e);
    }

    // Phase 5b: Amcache SHA1 hash reputation lookup + annotation
    std::fs::create_dir_all(&args.output_dir)?;
    let unique_hashes: Vec<String> = {
        let mut set = std::collections::HashSet::new();
        for e in &all_events {
            for ind in &e.indicators {
                if let Some(h) = ind.strip_prefix("HASH:") {
                    if h.len() == 40 { set.insert(h.to_lowercase()); }
                }
            }
        }
        set.into_iter().collect()
    };
    if !unique_hashes.is_empty() {
        use crate::timeline_parser::intel::hash_lookup::{self, Classification, HashLookupOpts, OfflineLists};
        let offline = OfflineLists::load(&data_dir);
        let online = (args.hash_lookup || args.vt) && !args.offline;
        eprintln!("[*] Hash lookup: {} unique Amcache SHA1s (offline lists: {}, online OSINT: {})",
                  unique_hashes.len(), offline.count(), online);
        let opts = HashLookupOpts {
            online,
            use_vt: args.vt,
            vt_key: hash_lookup::resolve_vt_key(args.vt_key.as_deref()),
            vt_rate_limit: args.vt_rate,
            verbose: args.verbose,
        };
        let results = hash_lookup::run(&unique_hashes, &offline, &opts);

        let mut bad = 0usize;
        for e in &mut all_events {
            let hash = e.indicators.iter()
                .find_map(|i| i.strip_prefix("HASH:").map(|s| s.to_lowercase()));
            if let Some(h) = hash {
                if let Some(r) = results.get(&h) {
                    if r.classification.is_bad() {
                        e.severity = "high".to_string();
                        e.indicators.push(format!("HASH_INTEL:{}", r.detail));
                        bad += 1;
                    } else if matches!(r.classification, Classification::KnownClean | Classification::VtClean) {
                        e.indicators.push(format!("HASH_INTEL:{}", r.classification.label()));
                    }
                }
            }
        }
        eprintln!("[*]   Hash lookup: {} malicious hits flagged", bad);
        hash_lookup::write_reports(&results, &hostname, &args.output_dir)?;
    }

    // Phase 5c: Correlate precursor RDP/SMB logons to findings
    let precursors = output::correlate::add_precursor_logons(&mut all_events, &session_logons, &hostname);
    if precursors > 0 {
        eprintln!("[*] Precursor logons injected: {}", precursors);
    }

    // Phase 5d: Log continuity — did this host's record stop and restart?
    let host_info_csv = args.timeline_dir.join("Host_Information.csv");
    let mut continuity = match artifacts.get("event-logs") {
        Some(path) => {
            eprintln!("[*] Log continuity: scanning event-logs...");
            restoration::scan_event_logs(path).unwrap_or_else(|e| {
                eprintln!("[!] Log continuity scan failed: {e}");
                restoration::Continuity::default()
            })
        }
        None => {
            eprintln!("[*] Log continuity: no event-logs.csv — restoration cannot be assessed");
            restoration::Continuity::default()
        }
    };
    if host_info_csv.exists() {
        restoration::add_host_information(&mut continuity, &host_info_csv);
    }
    eprintln!("[*]   {} days with events, {} gap(s), {} finding(s)",
              continuity.days_with_events, continuity.gaps.len(), continuity.findings().count());
    if let Some(d) = continuity.restoration_date() {
        eprintln!("[!]   POSSIBLE RESTORATION — record resumes {d}");
    }
    all_events.extend(restoration::to_events(&continuity, &hostname));

    // Phase 5e: Installed software exposure.
    let software_rules = software::SoftwareRules::load(&data_dir)?;
    let as_of = continuity
        .series_last
        .as_deref()
        .and_then(restoration::parse_ts)
        .map(|dt| dt.date());
    let mut inventory = software::build(
        artifacts.get("registry").map(|p| p.as_path()),
        artifacts.get("regripper").map(|p| p.as_path()),
        &software_rules,
        as_of,
    )?;
    if host_info_csv.exists() {
        let f = parsers::host_info::host_info_fields(&host_info_csv);
        software::evaluate_os(
            &mut inventory,
            f.get("Windows Version (Product Name)").map(String::as_str).unwrap_or(""),
            f.get("Build Lab").map(String::as_str).unwrap_or(""),
            &software_rules,
            as_of,
        );
    }
    eprintln!("[*] Installed software: {} products, {} flagged",
              inventory.installed.len(), inventory.flags.len());
    all_events.extend(software::to_events(&inventory, &hostname));

    // Phase 5h: Restoration — ranked candidates, corroboration, and the phase
    // each finding belongs to. Ported alongside --restoration-date: the report's
    // Restoration Phases section reads `event.phase` and `continuity.candidates`,
    // so without this block a supplied date would name itself in the prose and
    // then partition nothing.
    let signals = restoration::rebuild_signals(&all_events);
    continuity.rank_candidates(&signals);
    // A date-only `--restoration-date` means midnight that day. Left as
    // `2026-05-19` it would still partition correctly (string order works out)
    // but would not parse, so the relevance window before it could never be
    // marked.
    let supplied_restoration = args.restoration_date.as_deref().map(|d| {
        if d.len() == 10 && d.as_bytes()[4] == b'-' { format!("{d}T00:00:00Z") } else { d.to_string() }
    });
    let restoration_date: Option<String> = supplied_restoration
        .clone()
        .or_else(|| continuity.best_candidate().map(|c| c.resumes.clone()));
    if let Some(ref d) = restoration_date {
        let source = if supplied_restoration.is_some() { "supplied" } else { "inferred" };
        let counts = restoration::assign_phases(&mut all_events, d);
        let in_window = restoration::mark_restoration_window(
            &mut all_events, d, RESTORATION_WINDOW_DAYS);
        eprintln!("[*]   {} event(s) sit in the {}-day window before the restore (highest relevance)",
                  in_window, RESTORATION_WINDOW_DAYS);
        eprintln!(
            "[*] Restoration ({source}) {d}: {} pre / {} restoration-process / {} responder / {} post-restoration unexplained",
            counts.pre, counts.process, counts.responder, counts.post
        );
        for c in continuity.candidates.iter().take(3) {
            eprintln!("[*]   candidate {} ({}h, {}){}", c.resumes, c.gap_hours, c.kind.label(),
                      if c.corroboration.is_empty() { String::new() }
                      else { format!(" — corroborated: {}", c.corroboration.join("; ")) });
        }
    }
    let restoration_json = restoration::write_restoration_json(
        &continuity, &hostname, supplied_restoration.as_deref(), &args.output_dir)?;
    eprintln!("[*] Restoration record: {}", restoration_json.display());

    // Phase 6: Merge, dedup, output
    eprintln!("[*] Sorting {} events...", all_events.len());
    all_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    all_events.dedup_by(|a, b| a.dedup_key() == b.dedup_key());
    dedup::cap_floods(&mut all_events);
    eprintln!("[*] Final: {} events", all_events.len());

    std::fs::create_dir_all(&args.output_dir)?;
    let csv_path = args.output_dir.join(format!("{}_supertimeline.csv", hostname));
    let jsonl_path = args.output_dir.join(format!("{}_supertimeline.jsonl", hostname));
    let triage_csv_path = args.output_dir.join(format!("{}_triage_timeline.csv", hostname));
    let triage_jsonl_path = args.output_dir.join(format!("{}_triage_timeline.jsonl", hostname));
    let report_path = args.output_dir.join(format!("{}_triage_report.md", hostname));

    write_supertimeline(&all_events, &csv_path, &jsonl_path)?;
    let triage_hits = write_triage_timeline(&all_events, &triage_csv_path, &triage_jsonl_path)?;
    eprintln!("[*] Triage timeline: {} curated hits", triage_hits);

    // OpenSearch-shaped NDJSON, for the wiskess worker to ingest. Written as
    // `.json` because `worker.py` skips anything not ending in `json`, and
    // `.jsonl` does not — the two files above are never picked up.
    let (os_count, os_path) =
        crate::timeline_parser::output::supertimeline::write_opensearch_ndjson(&all_events, &args.timeline_dir, &hostname)?;
    eprintln!("[*] OpenSearch NDJSON: {} events -> {}", os_count, os_path.display());
    let elapsed = start.elapsed().as_secs_f64();
    let detection = DetectionCoverage {
        data_dir: data_dir.display().to_string(),
        ta_patterns: ta_detector.pattern_count(),
        path_rules: path_detector.rule_count(),
        software_rules: {
            let (e, p, _) = software_rules.counts();
            e + p
        },
    };
    let report_ctx = ReportContext {
        window: &window,
        identity: &identity,
        elapsed,
        gaps: &gaps,
        geo: &geo,
        ioc_coverage: &ioc_matcher.coverage(),
        detection: &detection,
        continuity: &continuity,
        software: &inventory,
        cfg: &cfg,
        automations: &automations,
        restoration_supplied: supplied_restoration.as_deref(),
    };
    generate_report(&all_events, &report_ctx, &report_path)?;

    eprintln!("[*] === COMPLETE ({:.1}s) ===", elapsed);
    eprintln!("[*] Supertimeline: {} | {}", csv_path.display(), jsonl_path.display());
    eprintln!("[*] Triage:        {} | {}", triage_csv_path.display(), report_path.display());

    Ok(TimelineParserSummary {
        hostname,
        event_count: all_events.len(),
        triage_hits,
        elapsed_secs: elapsed,
        output_dir: args.output_dir.clone(),
        supertimeline_csv: csv_path,
        supertimeline_jsonl: jsonl_path,
        triage_csv: triage_csv_path,
        triage_jsonl: triage_jsonl_path,
        report_path,
        opensearch_path: os_path,
        opensearch_count: os_count,
    })
}

/// Widen a date-only upper bound to the end of that day.
///
/// `in_timewindow` compares raw strings, so `"2026-08-21T10:00:00Z" <= "2026-08-21"`
/// is false — a date-only bound silently excludes everything after midnight on
/// its last day.
fn end_of_day(bound: &str) -> String {
    if bound.len() == 10 && bound.as_bytes()[4] == b'-' {
        format!("{bound}T23:59:59.999Z")
    } else {
        bound.to_string()
    }
}

#[cfg(test)]
mod bound_tests {
    use super::end_of_day;

    /// The bug: today's events were being dropped.
    #[test]
    fn a_date_only_bound_is_widened_to_cover_the_whole_day() {
        let b = end_of_day("2026-08-21");
        assert_eq!(b, "2026-08-21T23:59:59.999Z");
        assert!("2026-08-21T10:00:00.000Z" <= b.as_str(), "an event today must be in scope");
        assert!(!("2026-08-21T10:00:00.000Z" <= "2026-08-21"), "which it is not without this");
    }

    #[test]
    fn a_full_timestamp_bound_is_left_alone() {
        assert_eq!(end_of_day("2026-08-21T12:00:00Z"), "2026-08-21T12:00:00Z");
    }

    #[test]
    fn something_that_is_not_a_date_is_left_alone() {
        assert_eq!(end_of_day("not-a-date"), "not-a-date");
    }
}
