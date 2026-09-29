//! Native (in-process) parsers, run by `exe_ops::run_commands` for wiskers whose
//! binary is `wiskess_native`. Used where the external tool doesn't work on Linux,
//! i.e. PECmd can't decompress Win10+ (MAM) prefetch without Windows libraries.
//!
//! The wisker's `args` names the parser:
//! * `prefetch` - `{input}` is the Prefetch folder, parsed with frnsc-prefetch
//!
//! Timestamps are written as UTC `%Y-%m-%d %H:%M:%S.fffffff` (FILETIME precision).
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use chrono::{DateTime, Utc};
use csv::Writer;
use forensic_rs::prelude::{StdVirtualFS, VirtualFileSystem};
use frnsc_prefetch::prelude::read_prefetch_file;

pub const NATIVE_BINARY: &str = "wiskess_native";

pub fn is_native(binary: &str) -> bool {
    binary == NATIVE_BINARY
}

/// Run the named native parser, returning the (stdout, stderr) messages for the wiskess log
pub fn run_native(parser: &str, input: &Path, out_folder: &Path, outfile: &str) -> (Vec<u8>, Vec<u8>) {
    let mut log = Log::default();
    let out_path = out_folder.join(outfile);
    let result = catch_unwind(AssertUnwindSafe(|| match parser.trim() {
        "prefetch" => prefetch(input, &out_path, &mut log),
        other => Err(format!("unknown native parser `{other}`")),
    }));
    match result {
        Ok(Ok(())) => (),
        Ok(Err(e)) => log.err(format!("[!] native {parser} failed on {}: {e}", input.display())),
        Err(_) => log.err(format!("[!] native {parser} panicked on {}", input.display())),
    }
    (log.out.into_bytes(), log.err.into_bytes())
}

#[derive(Default)]
struct Log {
    out: String,
    err: String,
}

impl Log {
    fn out(&mut self, msg: String) {
        self.out.push_str(&msg);
        self.out.push('\n');
    }
    fn err(&mut self, msg: String) {
        self.err.push_str(&msg);
        self.err.push('\n');
    }
}

/// FILETIME (100ns ticks since 1601) to UTC string, blank for the unset value 0
fn fmt_filetime(ft: u64) -> String {
    if ft == 0 {
        return String::new();
    }
    const TICKS_TO_UNIX: i128 = 116_444_736_000_000_000;
    let ticks = ft as i128 - TICKS_TO_UNIX;
    let secs = ticks.div_euclid(10_000_000) as i64;
    let rem = ticks.rem_euclid(10_000_000) as u32;
    match DateTime::<Utc>::from_timestamp(secs, rem * 100) {
        Some(dt) => format!("{}.{:07}", dt.format("%Y-%m-%d %H:%M:%S"), rem),
        None => String::new(),
    }
}

/// One row per recorded run time, so the file is timeline-ready like PECmd's _Timeline.csv
fn prefetch(input: &Path, out_path: &Path, log: &mut Log) -> Result<(), String> {
    let mut files: Vec<_> = std::fs::read_dir(input)
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("pf")))
        .collect();
    files.sort();

    let mut wtr = Writer::from_path(out_path)
        .map_err(|e| format!("unable to create {}: {e}", out_path.display()))?;
    wtr.write_record([
        "RunTime", "RunTimeSlot", "ExecutableName", "RunCount", "Version",
        "SourceFilename", "Volumes", "FilesLoadedCount", "FilesLoaded",
    ]).map_err(|e| e.to_string())?;

    let mut fs = StdVirtualFS::new();
    let (mut parsed, mut rows) = (0, 0);
    for path in &files {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        // the parser slices the file without length checks, so isolate each file
        let pf = catch_unwind(AssertUnwindSafe(|| {
            let file = fs.open(path).map_err(|e| format!("{e:?}"))?;
            read_prefetch_file(&name, file).map_err(|e| format!("{e:?}"))
        }));
        let pf = match pf {
            Ok(Ok(pf)) => pf,
            Ok(Err(e)) => { log.err(format!("[!] prefetch {}: {e}", path.display())); continue; }
            Err(_) => { log.err(format!("[!] prefetch {}: parser panicked", path.display())); continue; }
        };
        parsed += 1;
        let volumes = pf.volume.iter()
            .map(|v| format!("{} (serial {:08X})", v.device_path, v.serial_number))
            .collect::<Vec<_>>()
            .join("; ");
        let files_loaded = pf.metrics.iter().map(|m| m.file.as_str()).collect::<Vec<_>>().join("; ");
        // slot 0 is the first run time in the file, which Windows keeps as the most recent
        for (slot, ft) in pf.last_run_times.iter().enumerate() {
            if ft.filetime() == 0 {
                continue;
            }
            wtr.write_record([
                fmt_filetime(ft.filetime()),
                slot.to_string(),
                pf.name.clone(),
                pf.run_count.to_string(),
                pf.version.to_string(),
                path.display().to_string(),
                volumes.clone(),
                pf.metrics.len().to_string(),
                files_loaded.clone(),
            ]).map_err(|e| e.to_string())?;
            rows += 1;
        }
    }
    wtr.flush().map_err(|e| e.to_string())?;
    log.out(format!("[+] prefetch: parsed {parsed}/{} files, {rows} run times -> {}", files.len(), out_path.display()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_formats_utc_with_100ns_precision() {
        // run time read by libscca from a real .pf: 2026-09-17 18:44:09.8766193 UTC
        assert_eq!(fmt_filetime(134_341_442_498_766_193), "2026-09-17 18:44:09.8766193");
        assert_eq!(fmt_filetime(0), "");
    }

    #[test]
    fn unknown_parser_is_reported() {
        let (out, err) = run_native("nope", Path::new("."), Path::new("."), "x.csv");
        assert!(out.is_empty());
        assert!(String::from_utf8_lossy(&err).contains("unknown native parser `nope`"));
    }

    #[test]
    fn truncated_prefetch_is_skipped_not_fatal() {
        let dir = tempfile::TempDir::new().unwrap();
        let pf_dir = dir.path().join("Prefetch");
        std::fs::create_dir(&pf_dir).unwrap();
        std::fs::write(pf_dir.join("BAD.EXE-00000000.pf"), b"MAM\x04").unwrap();
        let (out, err) = run_native("prefetch", &pf_dir, dir.path(), "prefetch_native.csv");
        assert!(String::from_utf8_lossy(&out).contains("parsed 0/1 files"));
        assert!(String::from_utf8_lossy(&err).contains("BAD.EXE-00000000.pf"));
        let csv = std::fs::read_to_string(dir.path().join("prefetch_native.csv")).unwrap();
        assert_eq!(csv.lines().count(), 1, "header only");
    }
}
