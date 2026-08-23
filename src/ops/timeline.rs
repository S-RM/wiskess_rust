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

    let args = TimelineParserArgs {
        timeline_dir: timeline_dir.clone(),
        iocs,
        time_start: Some(main_args.start_date.clone()),
        time_end: Some(main_args.end_date.clone()),
        auto_narrow: false,
        output_dir: triage_dir.clone(),
        hayabusa_level: "med".to_string(),
        no_sigma: false,
        offline: false,
        hash_lookup: false,
        vt: false,
        vt_key: None,
        vt_rate: 4,
        data_dir: Some(main_args.tool_path.join("threat_intel")),
        verbose: false,
    };

    match pipeline::run(args) {
        Ok(summary) => file_ops::log_msg(&main_args.out_log, format!(
            "[+] Timeline parser complete for host {}: {} events ({} triage hits) -> {}",
            summary.hostname, summary.event_count, summary.triage_hits, summary.output_dir.display()
        )),
        Err(e) => file_ops::log_msg(&main_args.out_log, format!(
            "[!] Timeline parser failed (non-fatal, wiskess run continues): {e}"
        )),
    }
}
