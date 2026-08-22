use anyhow::Result;
use std::path::{Path, PathBuf};

pub struct CollectionGap {
    pub name: String,
    pub data_source: String,
    pub analysis_file: String,
    pub lines: u32,
}

// These tools routinely produce empty output even on healthy collections.
const KNOWN_FP_TOOLS: &[&str] = &["SCCM_RecentlyUsedApplication", "WMIPersistenceFinder"];

pub fn find_wiskess_log(collection_root: &Path) -> Option<PathBuf> {
    std::fs::read_dir(collection_root).ok()?.flatten().find_map(|e| {
        let p = e.path();
        let name = p.file_name()?.to_str()?;
        if name.starts_with("wiskess_") && name.ends_with(".log") {
            Some(p)
        } else {
            None
        }
    })
}

pub fn parse_gaps(log_path: &Path) -> Result<Vec<CollectionGap>> {
    let content = std::fs::read_to_string(log_path)?;
    let mut gaps = Vec::new();
    let mut in_table = false;

    for line in content.lines() {
        // The table header line contains "name" and "data_source" and "lines" as column headings.
        // It may be prefixed with a [TIMESTAMP] token.
        let stripped = strip_timestamp(line);
        if !in_table {
            if stripped.contains("| data_source") && stripped.contains("| lines") {
                in_table = true;
            }
            continue;
        }

        // Separator line: all dashes and pluses
        if stripped.chars().all(|c| c == '-' || c == '+' || c == ' ') {
            continue;
        }

        // End of table: blank line or non-pipe line
        if !stripped.contains('|') {
            break;
        }

        // Parse: " name | data_source | analysis_file | lines "
        let cols: Vec<&str> = stripped.split('|').map(str::trim).collect();
        if cols.len() < 4 {
            continue;
        }
        let name = cols[0].to_string();
        let data_source = cols[1].to_string();
        let analysis_file = cols[2].to_string();
        let lines: u32 = cols[3].trim().parse().unwrap_or(0);

        if name.is_empty() {
            continue;
        }
        if KNOWN_FP_TOOLS.contains(&name.as_str()) {
            continue;
        }
        gaps.push(CollectionGap { name, data_source, analysis_file, lines });
    }

    Ok(gaps)
}

fn strip_timestamp(line: &str) -> &str {
    // Strip leading "[20260513T155539] " prefix if present
    let line = line.trim();
    if line.starts_with('[') {
        if let Some(end) = line.find("] ") {
            return line[end + 2..].trim();
        }
    }
    line
}
