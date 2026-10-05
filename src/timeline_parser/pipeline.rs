//! One run of the parser over one `Timeline/` folder.
//!
//! This exists as a module rather than as the body of `main` because there are
//! two callers: this crate's CLI, and the copy of this crate vendored into
//! `wiskess_rust/src/timeline_parser/`. That second caller used to be a
//! hand-maintained transcription of `main.rs` — `sync_timeline_parser.sh` only
//! snapshotted `main.rs` so a human could port the changes across — and it drifted,
//! as a 470-line second copy will. It never called `write_report_ndjson`, so
//! `<host>_triage_report.json` was simply not produced on the wiskess path, and the
//! date-bound widening added upstream never reached it either.
//!
//! Everything here is synced mechanically like every other module, so there is one
//! pipeline and the difference between the two entry points is argument parsing.
//!
//! Two rules for editing this file, both because of that sync:
//!
//! * Write module paths as `crate::<module>::…` with the trailing `::` — including
//!   `use crate::timeline_parser::config::{self, …}` rather than `use crate::config;`. The sync
//!   rewrites `crate::timeline_parser::config::` to `crate::timeline_parser::config::` by pattern,
//!   and a bare `use crate::config;` is not rewritten and does not compile there.
//! * Keep exit policy out of here. `run` reports what happened; the caller decides
//!   whether a degraded run is fatal (see `TimelineParserSummary::degraded`).

use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use crate::timeline_parser::config::{self, PipelineConfig, Verbosity};
use crate::timeline_parser::detectors::classify::{self, Classifier};
use crate::timeline_parser::detectors::compromised::CompromisedEntities;
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::suspicious_paths::SuspiciousPathDetector;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::detectors::{restoration, software};
use crate::timeline_parser::intel::geo::{find_geo_dbs, GeoReaders};
use crate::timeline_parser::output::event::UnifiedEvent;
use crate::timeline_parser::output::report::{generate_report, ArtifactCoverage, DetectionCoverage, ReportContext};
use crate::timeline_parser::output::supertimeline::{
    write_opensearch_ndjson, write_report_ndjson, write_supertimeline, write_triage_timeline,
};
use crate::timeline_parser::output::{correlate, dedup};
use crate::timeline_parser::parsers::wiskess_log::CollectionGap;
use crate::timeline_parser::parsers::{self, artifacts as registry, columns, wiskess_log};

/// Everything one run needs, with no CLI-parsing concerns.
///
/// Plain fields and a [`Default`] impl on purpose: the wiskess caller builds this
/// with struct-update syntax, so a field added here does not break it — it
/// inherits the default the CLI would have given it. The previous shape, a bare
/// struct literal listing every field, is why `--no-sigma` had to be spelled out
/// in `ops/timeline.rs` long after nothing read it.
pub struct TimelineParserArgs {
    /// The Wiskess `Timeline/` folder to read.
    pub timeline_dir: PathBuf,
    /// Where the timelines, the report and the reports' JSON go.
    pub output_dir: PathBuf,
    /// Where the files `worker.py` ingests go, when that is not `output_dir`.
    ///
    /// The worker walks one directory — the collection's `Timeline/` — and reads
    /// every filename ending in `json` in it. On the wiskess path `output_dir` is
    /// the sibling `Triage/`, so without this the four ingestible documents are
    /// written somewhere nothing ever looks. Defaults to `output_dir`, which is
    /// what a standalone run wants.
    pub triage_json_dir: Option<PathBuf>,
    pub iocs: Option<PathBuf>,
    pub time_start: Option<String>,
    pub time_end: Option<String>,
    pub auto_narrow: bool,
    /// `None` means "med, or low with `verbose_events`".
    pub hayabusa_level: Option<String>,
    pub verbose_events: bool,
    pub business_hours: (u32, u32),
    pub rare_logon_max: usize,
    pub no_quiet_baseline: bool,
    pub report_cap: usize,
    pub restoration_date: Option<String>,
    pub restoration_window_days: i64,
    pub offline: bool,
    pub hash_lookup: bool,
    pub vt: bool,
    pub vt_key: Option<String>,
    pub vt_rate: u32,
    pub data_dir: Option<PathBuf>,
    pub verbose: bool,
}

impl Default for TimelineParserArgs {
    fn default() -> Self {
        Self {
            timeline_dir: PathBuf::new(),
            output_dir: PathBuf::from("./output"),
            triage_json_dir: None,
            iocs: None,
            time_start: None,
            time_end: None,
            auto_narrow: false,
            hayabusa_level: None,
            verbose_events: false,
            business_hours: config::DEFAULT_BUSINESS_HOURS,
            rare_logon_max: config::DEFAULT_RARE_LOGON_MAX,
            no_quiet_baseline: false,
            report_cap: dedup::DEFAULT_REPORT_CAP,
            restoration_date: None,
            restoration_window_days: 60,
            offline: false,
            hash_lookup: false,
            vt: false,
            vt_key: None,
            vt_rate: 4,
            data_dir: None,
            verbose: false,
        }
    }
}

/// What the caller needs to log, report, or refuse to accept.
///
/// Most of it is dead code in *this* binary — `main` uses `degraded`,
/// `coverage_problems` and `report_path` and prints the rest itself as it goes.
/// The paths are here for the wiskess caller, which logs them into the run log so
/// an operator can find the output of a host that has already scrolled past.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TimelineParserSummary {
    pub hostname: String,
    pub event_count: usize,
    pub triage_hits: usize,
    pub elapsed_secs: f64,
    pub output_dir: PathBuf,
    pub triage_json_dir: PathBuf,
    pub supertimeline_csv: PathBuf,
    pub supertimeline_jsonl: PathBuf,
    pub triage_csv: PathBuf,
    pub triage_jsonl: PathBuf,
    pub report_path: PathBuf,
    pub report_json: PathBuf,
    pub restoration_json: PathBuf,
    pub opensearch_path: PathBuf,
    pub opensearch_count: usize,
    /// This run could not read all of its evidence, or could not load all of its
    /// rules. The output is still written and is still the best available account
    /// of the host — but it is not a clean result, and a caller that logs
    /// "complete" over the top of this is the failure that made the flag exist.
    pub degraded: bool,
    /// Every reason for `degraded`, one line each, the same lines the report and
    /// stderr carry.
    pub coverage_problems: Vec<String>,
}

pub fn run(args: TimelineParserArgs) -> Result<TimelineParserSummary> {
    let start = Instant::now();

    // Validate/create the output directory up front so an invalid -o path fails
    // fast (before any parsing) with a clear message instead of after the full run.
    std::fs::create_dir_all(&args.output_dir).map_err(|e| {
        anyhow::anyhow!("Cannot create output directory {:?}: {}", args.output_dir, e)
    })?;
    eprintln!("[*] Output directory: {}", args.output_dir.display());

    // The four `.json` files the wiskess worker ingests. Same directory as
    // everything else unless the caller separates them.
    let triage_json_dir = args.triage_json_dir.clone().unwrap_or_else(|| args.output_dir.clone());
    if triage_json_dir != args.output_dir {
        std::fs::create_dir_all(&triage_json_dir).map_err(|e| {
            anyhow::anyhow!("Cannot create triage JSON directory {:?}: {}", triage_json_dir, e)
        })?;
        eprintln!("[*] Ingestible JSON directory: {}", triage_json_dir.display());
    }

    // Phase 1: Discovery
    eprintln!("[*] Discovering artifacts in {:?}...", args.timeline_dir);
    let discovery = registry::discover(&args.timeline_dir)?;
    let artifacts = &discovery.artifacts;

    // Find and parse the wiskess validation log (sits in collection root, parent of Timeline/)
    let collection_root = args.timeline_dir.parent().unwrap_or(&args.timeline_dir);
    let gaps: Vec<CollectionGap> = wiskess_log::find_wiskess_log(collection_root)
        .and_then(|log_path| {
            eprintln!("[*] Wiskess log: {}", log_path.display());
            wiskess_log::parse_gaps(&log_path).ok()
        })
        .unwrap_or_default();
    eprintln!("[*] Found {} artifact files", artifacts.len());
    // Two things the old discovery could not say. A superseded file is a
    // deliberate choice between two parses of the same artefact; an unrecognised
    // one is a Wiskess output this build does not know about, which used to be
    // read into a map that nothing ever asked, and so vanished silently.
    for s in &discovery.superseded {
        if s.note.is_empty() {
            eprintln!("[*]   {}: reading {}, not {}", s.key, s.chosen, s.skipped);
        } else {
            eprintln!("[*]   {}: reading {}, not {} ({})", s.key, s.chosen, s.skipped, s.note);
        }
    }
    if !discovery.unrecognised.is_empty() {
        eprintln!(
            "[!] {} CSV(s) in {} are not recognised by this build and were NOT parsed: {}",
            discovery.unrecognised.len(),
            args.timeline_dir.display(),
            discovery.unrecognised.join(", ")
        );
    }

    // Load detection engines
    let data_dir = config::resolve_data_dir(args.data_dir.as_deref());
    eprintln!("[*] Detection data dir: {}", data_dir.display());
    // Checked before the loaders run, because each loader is forgiving on its own
    // and their silence is only wrong in aggregate: a data dir missing three of six
    // files produces a quieter report and no statement that it did.
    let missing_data_files = config::missing_data_files(&data_dir);
    for f in &missing_data_files {
        eprintln!("[!] Detection data file missing: {}", data_dir.join(f).display());
    }
    let ta_detector = TAToolDetector::new(&data_dir)?;
    eprintln!("[*] TA tool detector: {} patterns", ta_detector.pattern_count());
    let path_detector = SuspiciousPathDetector::new(&data_dir)?;
    let classifier = Classifier::load(&data_dir)?;
    eprintln!("[*] Vendor/OS path classification: {} rules ({})",
              classifier.vendor_rule_count, classifier.vendor_source);
    let ioc_matcher = IOCMatcher::new(args.iocs.as_deref())?;

    // GeoIP/ASN/anon enrichment for IP-literal browser hosts (optional — no-op if no DBs).
    let geo = GeoReaders::open(&find_geo_dbs());
    if geo.available() {
        eprintln!("[*] GeoIP databases loaded for IP enrichment");
    } else {
        eprintln!("[*] No GeoIP databases found (set MAXMIND_DB_DIR; IP geo enrichment disabled)");
    }

    let identity = parsers::host_info::resolve_identity(artifacts, &args.timeline_dir);
    let hostname = identity.name.clone();
    if identity.diverges() {
        let others: Vec<&str> = identity.aliases().iter().map(|(_, n)| n.as_str()).collect();
        eprintln!("[*] Hostname: {} (also resolves to {})", hostname, others.join(", "));
    } else {
        eprintln!("[*] Hostname: {}", hostname);
    }

    // Phase 2: Timeframe detection
    let window = if let (Some(ref ts), Some(ref te)) = (&args.time_start, &args.time_end) {
        // Widened here as well as inside `TimeWindow::new`, because
        // `detect_timeframe_opts` filters on the bounds directly and never sees
        // the window.
        let ts = config::normalise_bound(ts, config::Bound::Start);
        let te = config::normalise_bound(te, config::Bound::End);

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
                    Some(config::TimeWindow::new(&ts, &te, 0, "user-specified"))
                }
            }
        } else {
            eprintln!("[*] User timeframe: {} to {}", ts, te);
            Some(config::TimeWindow::new(&ts, &te, 0, "user-specified"))
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

    // A verbose run lowers the sigma floor as well as widening the logon set —
    // but only when the operator did not state a level, so an explicit
    // `--hayabusa-level` always wins.
    let hayabusa_level = args
        .hayabusa_level
        .clone()
        .unwrap_or_else(|| if args.verbose_events { "low" } else { "med" }.to_string());

    let cfg = PipelineConfig {
        hayabusa_level: hayabusa_level.clone(),
        window: window.clone(),
        offline: args.offline,
        verbose: args.verbose,
        verbosity: if args.verbose_events { Verbosity::Baseline } else { Verbosity::Curated },
        business_hours: args.business_hours,
        rare_logon_max: args.rare_logon_max,
        emit_quiet_baseline: !args.no_quiet_baseline,
    };
    if !cfg.emit_quiet_baseline {
        eprintln!(
            "[*] Quiet-artifact baseline OFF: low-volume artifacts contribute only rows a \
             detection rule fired on"
        );
    }
    if cfg.verbosity.baseline() {
        eprintln!(
            "[*] Verbose events ON: baseline logons kept (business hours {:02}:00-{:02}:00 UTC, \
             rare below {} occurrences), sigma floor {}",
            cfg.business_hours.0, cfg.business_hours.1, cfg.rare_logon_max, hayabusa_level
        );
    }

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
    let mut automations: Vec<classify::Automation> = Vec::new();
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
        || artifacts.get("mft").map_or_else(|| Ok(vec![]), |p|
            parsers::mft::parse(p, &cfg, &ta_detector, &ioc_matcher, &path_detector, &hostname)),
        || artifacts.get("usnjrnl").map_or_else(|| Ok(vec![]), |p|
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
        let e = parsers::amcache::parse(p, &cfg, &ta_detector, &ioc_matcher, &path_detector, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   Amcache: {}", e.len()); }
        all_events.extend(e);
    }
    if let Some(p) = artifacts.get("amcache-regripper") {
        let e = parsers::amcache::parse_regripper(p, &cfg, &ta_detector, &ioc_matcher, &path_detector, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   Amcache(RegRipper): {}", e.len()); }
        all_events.extend(e);
    }
    if let Some(p) = artifacts.get("appcompatcache") {
        let e = parsers::appcompatcache::parse(p, &cfg, &ta_detector, &ioc_matcher, &path_detector, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   AppCompat: {}", e.len()); }
        all_events.extend(e);
    }
    if let Some(p) = artifacts.get("browser-hist") {
        let e = parsers::browser_hist::parse(p, &cfg, &ioc_matcher, &geo, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   Browser: {}", e.len()); }
        all_events.extend(e);
    }
    if let Some(p) = artifacts.get("jump-lists") {
        let e = parsers::jump_lists::parse(p, &cfg, &ta_detector, &ioc_matcher, &path_detector, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   Jump-lists: {}", e.len()); }
        all_events.extend(e);
    }
    if let Some(p) = artifacts.get("lnk-files") {
        let e = parsers::lnk_files::parse(p, &cfg, &ta_detector, &ioc_matcher, &path_detector, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   LNK: {}", e.len()); }
        all_events.extend(e);
    }
    if let Some(p) = artifacts.get("regripper") {
        let e = parsers::regripper::parse(p, &cfg, &ta_detector, &ioc_matcher, &path_detector, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   Regripper: {}", e.len()); }
        all_events.extend(e);
    }
    if let Some(p) = artifacts.get("hindsight") {
        let e = parsers::hindsight::parse(p, &cfg, &ioc_matcher, &ta_detector, &geo, &hostname)?;
        if !e.is_empty() { eprintln!("[*]   Hindsight: {}", e.len()); }
        all_events.extend(e);
    }

    // Phase 5a: the quiet artifacts with no bespoke parser — shellbags,
    // powershell-history, recycle-bin, prefetch, services. Driven from the
    // registry rather than hand-listed here, so adding a spec with a
    // `passthrough` is all it takes to have the artifact reach the timeline.
    // Only specs that declare one are dispatched, so nothing double-emits with a
    // bespoke parser.
    for spec in registry::ARTIFACTS {
        let Some(ref pt) = spec.passthrough else { continue };
        let Some(p) = artifacts.get(spec.key) else { continue };
        let e = parsers::passthrough::parse(
            p, spec.key, pt, &cfg, &ta_detector, &ioc_matcher, &path_detector, &hostname,
        )?;
        if !e.is_empty() { eprintln!("[*]   {}: {}", spec.key, e.len()); }
        all_events.extend(e);
    }

    // Phase 5b: Amcache SHA1 hash reputation lookup + annotation
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
        hash_lookup::write_reports(&results, &hostname, &args.output_dir, &triage_json_dir)?;
    }

    // Phase 5c: Correlate precursor RDP/SMB logons to findings
    let precursors = correlate::add_precursor_logons(&mut all_events, &session_logons, &hostname);
    if precursors > 0 {
        eprintln!("[*] Precursor logons injected: {}", precursors);
    }

    // Phase 5d: Log continuity — did this host's record stop and restart?
    //
    // Runs over event-logs.csv in its own streaming pass rather than inside
    // `event_logs::parse`: that parser drops every row failing its `include`
    // gate, and continuity is a property of the rows it discards as much as the
    // ones it keeps. A gap measured only over interesting events is not a gap.
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
    //
    // `as_of` is the last logged event, not today. An end-of-life date is judged
    // against when the host was collected — a collection analysed two years
    // later must not acquire findings its analyst could not have had.
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

    // Phase 5f: Deterministic classification.
    //
    // Runs after every parser and before dedup/output, so a vendor tree, the
    // component store or the responder's own kit is named once, here, rather
    // than re-derived (differently) by each consumer.
    let (classified, evidenced) = classify::apply(&mut all_events, &classifier);
    eprintln!("[*] Classified {} events (vendor/OS/responder/config), {} carry execution evidence",
              classified, evidenced);

    // Phase 5g: Timestamp hygiene.
    //
    // A value that does not parse must never reach downstream arithmetic as a
    // string it will happily compare. One host's activity start was the literal
    // `20200922`, and because it sorts below every ISO timestamp it became the
    // start of the case-wide span.
    let bad_ts = restoration::validate_timestamps(&mut all_events, continuity.collection_at.as_deref());
    if bad_ts > 0 {
        eprintln!("[!] {} event(s) carry an unusable timestamp — flagged, not silently accepted", bad_ts);
    }

    // Phase 5h: Restoration — ranked candidates, corroboration, and the phase
    // each finding belongs to.
    let signals = restoration::rebuild_signals(&all_events);
    continuity.rank_candidates(&signals);
    // A date-only `--restoration-date` means midnight that day. Left as `2026-05-19`
    // it would still partition correctly (string order works out) but would not
    // parse, so the relevance window before it could never be marked.
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
            &mut all_events, d, args.restoration_window_days);
        eprintln!("[*]   {} event(s) sit in the {}-day window before the restore (highest relevance)",
                  in_window, args.restoration_window_days);
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
        &continuity, &hostname, supplied_restoration.as_deref(), &triage_json_dir)?;
    eprintln!("[*] Restoration record: {}", restoration_json.display());

    // Phase 6: Merge, dedup, output
    //
    // The sort is by more than the timestamp because `dedup_by` only compares
    // *adjacent* elements: two identical events a third event apart both survive,
    // and which order they arrive in depends on the order the parsers finished.
    // Sorting on the same fields the dedup key hashes makes duplicates neighbours
    // and the output deterministic.
    // Before the sort and the dedup, so neither is decided by a byte no reader can
    // see: a control character in a field an attacker or a corrupt vendor string
    // controls otherwise reaches the CSV, and one `NUL` makes `grep` treat the
    // whole file as binary. See `UnifiedEvent::sanitise`.
    for event in &mut all_events {
        event.sanitise();
    }

    eprintln!("[*] Sorting {} events...", all_events.len());
    all_events.sort_by(|a, b| {
        a.timestamp
            .cmp(&b.timestamp)
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.event_type.cmp(&b.event_type))
            .then_with(|| a.description.cmp(&b.description))
    });
    all_events.dedup_by(|a, b| a.dedup_key() == b.dedup_key());
    eprintln!("[*] Final: {} events", all_events.len());

    let csv_path = args.output_dir.join(format!("{}_supertimeline.csv", hostname));
    let jsonl_path = args.output_dir.join(format!("{}_supertimeline.jsonl", hostname));
    let triage_csv_path = args.output_dir.join(format!("{}_triage_timeline.csv", hostname));
    let triage_jsonl_path = args.output_dir.join(format!("{}_triage_timeline.jsonl", hostname));
    let report_path = args.output_dir.join(format!("{}_triage_report.md", hostname));

    write_supertimeline(&all_events, &csv_path, &jsonl_path)?;
    let triage_hits = write_triage_timeline(&all_events, &triage_csv_path, &triage_jsonl_path)?;
    eprintln!("[*] Triage timeline: {} curated hits", triage_hits);

    // Phase 6a: what each artefact contributed.
    //
    // Rows come from the parsers (`columns::note_rows`), events from the finished
    // timeline, so every line of the table can be checked against the file it
    // names and the output it produced. Counted here rather than at parse time
    // because "events kept" has to mean what reached the output, after dedup.
    let rows_read = columns::rows_read();
    let column_failures = columns::failures();
    let mut emitted: HashMap<&str, usize> = HashMap::new();
    for e in &all_events {
        *emitted.entry(e.source.as_str()).or_insert(0) += 1;
    }
    // Registry order, so noisy artefacts are listed together and the quiet ones
    // (where a zero is a defect) read as a block.
    let mut artifact_coverage: Vec<ArtifactCoverage> = registry::ARTIFACTS
        .iter()
        .map(|spec| {
            let file = artifacts
                .get(spec.key)
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned());
            let mismatched = column_failures.iter().any(|f| f.artifact == spec.key);
            ArtifactCoverage {
                key: spec.key,
                volume: spec.volume.label(),
                rows_read: rows_read.get(spec.key).copied().unwrap_or(0),
                events_emitted: emitted.get(spec.key).copied().unwrap_or(0),
                status: match (&file, mismatched) {
                    (None, _) => "absent",
                    (Some(_), true) => "column-mismatch",
                    (Some(_), false) => "parsed",
                },
                file,
            }
        })
        .collect();
    // A second parse of an artefact the run already read. Listed so the choice is
    // visible: it is a decision about which file is better, not an omission.
    for s in &discovery.superseded {
        artifact_coverage.push(ArtifactCoverage {
            key: registry::spec(&s.key).map(|sp| sp.key).unwrap_or("unrecognised"),
            file: Some(s.skipped.clone()),
            volume: registry::spec(&s.key).map(|sp| sp.volume.label()).unwrap_or(""),
            rows_read: 0,
            events_emitted: 0,
            status: "superseded",
        });
    }

    let elapsed = start.elapsed().as_secs_f64();
    let detection = DetectionCoverage {
        data_dir: data_dir.display().to_string(),
        ta_patterns: ta_detector.pattern_count(),
        path_rules: path_detector.rule_count(),
        software_rules: {
            let (e, p, _) = software_rules.counts();
            e + p
        },
        // Every pack's uncompilable rules in one list: a run is degraded if any
        // pack is short, and the analyst should not have to know which pack a
        // rule lives in to find out.
        skipped_rules: [
            path_detector.skipped_rules(),
            ta_detector.skipped_rules(),
            classifier.skipped_rules(),
            software_rules.skipped_rules(),
        ]
        .concat(),
        artifacts: artifact_coverage,
        column_failures,
        unrecognised_files: discovery.unrecognised.clone(),
        missing_data_files,
    };
    // Said on stderr as well as in the report: a container run is read from its
    // log, and "complete" on a run that could not read its evidence is the thing
    // this whole pass exists to stop.
    let coverage_problems = detection.failure_lines();
    for line in &coverage_problems {
        eprintln!("[!] COVERAGE: {line}");
    }
    // The report gets a capped *view*; every writer above got the whole thing.
    // A `CAPPED:` marker event stands in for each group that was summarised, and
    // the summaries go into the report's coverage section as well — the marker is
    // chronological, so on its own it is only visible to a reader who happens to
    // look at the right table.
    let (report_events, capped) = dedup::summarise_floods(&all_events, args.report_cap);
    for c in &capped {
        eprintln!(
            "[*] Report cap: {} — showing {} of {}, {} summarised ({} .. {})",
            c.key, c.kept, c.kept + c.suppressed, c.suppressed, c.first, c.last
        );
    }
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
        capped: &capped,
    };
    let report_md = generate_report(&report_events, &report_ctx, &report_path)?;

    // The narrative, as its own ingestible timeline file. Written after the
    // report because it is the report — one document per section, dated now.
    let (report_docs, report_json) = write_report_ndjson(&report_md, &triage_json_dir, &hostname)?;
    eprintln!("[*] Report timeline: {} section(s) -> {}", report_docs, report_json.display());

    // OpenSearch-shaped NDJSON of the events themselves.
    //
    // Written as `.json` because `worker.py` skips anything not ending in
    // `json`, and `.jsonl` does not — the two files above are never picked up.
    // The report sections and the restoration estimate live in their own `.json`
    // files rather than being repeated here: the worker ingests every one of
    // them, so a copy in both places is the same text indexed twice.
    let (os_count, os_path) =
        write_opensearch_ndjson(&all_events, &triage_json_dir, &hostname, &detection)?;
    eprintln!("[*] OpenSearch NDJSON: {} documents -> {}", os_count, os_path.display());

    eprintln!("[*] === COMPLETE ({:.1}s) ===", elapsed);
    eprintln!("[*] Supertimeline: {} | {}", csv_path.display(), jsonl_path.display());
    eprintln!("[*] Triage:        {} | {}", triage_csv_path.display(), report_path.display());

    Ok(TimelineParserSummary {
        hostname,
        event_count: all_events.len(),
        triage_hits,
        elapsed_secs: elapsed,
        output_dir: args.output_dir.clone(),
        triage_json_dir,
        supertimeline_csv: csv_path,
        supertimeline_jsonl: jsonl_path,
        triage_csv: triage_csv_path,
        triage_jsonl: triage_jsonl_path,
        report_path,
        report_json,
        restoration_json,
        opensearch_path: os_path,
        opensearch_count: os_count,
        degraded: detection.degraded(),
        coverage_problems,
    })
}
