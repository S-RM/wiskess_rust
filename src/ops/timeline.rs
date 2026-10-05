use std::path::{Path, PathBuf};

use crate::configs::config;
use crate::timeline_parser::pipeline::{self, TimelineParserArgs};

use super::file_ops;

/// run_timeline_parser run Wiskess Timeline Parser over `{out_path}/Timeline`
pub fn run_timeline_parser(main_args: &config::MainArgs) {
    let timeline_dir = Path::new(&main_args.out_path).join("Timeline");
    let triage_dir = Path::new(&main_args.out_path).join("Triage");

    let txt = timeline_dir.join("Host_Information.txt");
    let csv = timeline_dir.join("Host_Information.csv");
    if txt.exists() && !csv.exists() {
        let _ = std::fs::copy(&txt, &csv);
    }

    let iocs = if main_args.ioc_file.is_empty() {
        None
    } else {
        Some(PathBuf::from(&main_args.ioc_file))
    };

    // Struct-update syntax, not an exhaustive literal. Every field this does not
    // name takes the same default the standalone CLI gives it, so a new upstream
    // argument arrives here already set to whatever `--help` documents instead of
    // failing the build and being filled in with a guess. The previous exhaustive
    // literal is how `no_sigma: false` outlived the flag itself.
    let args = TimelineParserArgs {
        timeline_dir: timeline_dir.clone(),
        // The report, the timelines and hash_lookup.txt: a human opens these.
        output_dir: triage_dir.clone(),
        // The four `.json` documents the worker ingests. It reads one directory —
        // this one — and picks up every filename in it ending in `json`. Written
        // into Triage/ they were indexed by nothing.
        triage_json_dir: Some(timeline_dir.clone()),
        iocs,
        time_start: Some(main_args.start_date.clone()),
        time_end: Some(main_args.end_date.clone()),
        hayabusa_level: Some("med".to_string()),
        data_dir: Some(main_args.tool_path.join("threat_intel")),
        restoration_date: main_args.restoration_date.clone(),
        ..Default::default()
    };

    match pipeline::run(args) {
        Ok(summary) => {
            // Said before the completion line, and one line per problem. A run
            // that could not read a required column still produces output and
            // still reports a plausible event count — this is the only place the
            // operator finds out that count was measured against half the
            // evidence.
            if summary.degraded {
                file_ops::log_msg(&main_args.out_log, format!(
                    "[!] Timeline parser DID NOT READ ALL OF ITS EVIDENCE for host {} — {} problem(s). \
                     The output below is not a clean result; see {}",
                    summary.hostname,
                    summary.coverage_problems.len(),
                    summary.report_path.display()
                ));
                for problem in &summary.coverage_problems {
                    file_ops::log_msg(&main_args.out_log, format!("[!]     {problem}"));
                }
            }
            file_ops::log_msg(&main_args.out_log, format!(
                "[+] Timeline parser complete for host {}: {} events ({} triage hits) -> {} \
                 (ingestible JSON -> {})",
                summary.hostname, summary.event_count, summary.triage_hits,
                summary.output_dir.display(), summary.triage_json_dir.display()
            ));
        }
        Err(e) => file_ops::log_msg(&main_args.out_log, format!(
            "[!] Timeline parser failed (non-fatal, wiskess run continues): {e}"
        )),
    }
}
