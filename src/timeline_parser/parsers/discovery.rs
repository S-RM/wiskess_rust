use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub fn discover_artifacts(timeline_dir: &Path) -> Result<HashMap<String, PathBuf>> {
    let mut artifacts: HashMap<String, PathBuf> = HashMap::new();

    if !timeline_dir.exists() {
        anyhow::bail!("Timeline directory does not exist: {:?}", timeline_dir);
    }

    let known_artifacts = [
        ("hayabusa", &["hayabusa.csv"][..]),
        ("event-logs", &["event-logs.csv", "event_logs.csv"]),
        ("network", &["network.csv"]),
        ("registry", &["registry.csv"]),
        ("MFTECmd", &["MFTECmd.csv"]),
        ("usnjrnl-j-file", &["usnjrnl-j-file.csv", "usnjrnl.csv"]),
        ("amcache", &["amcache.csv"]),
        ("appcompatcache", &["appcompatcache.csv"]),
        ("browser-hist", &["browser-hist.csv", "browser_history.csv"]),
        ("hindsight", &["hindsight.csv"]),
        ("jump-lists", &["jump-lists.csv", "jump_lists.csv"]),
        ("lnk-files", &["lnk-files.csv", "lnk_files.csv"]),
        ("regripper", &["regripper.csv"]),
        ("amcache-regripper", &["regripper_amcache.csv"]),
    ];

    for (name, filenames) in &known_artifacts {
        for filename in *filenames {
            let path = timeline_dir.join(filename);
            if path.exists() {
                artifacts.insert(name.to_string(), path);
                break;
            }
        }
    }

    if artifacts.is_empty() {
        for entry in std::fs::read_dir(timeline_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("csv") {
                let stem = path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();
                if !stem.is_empty() {
                    artifacts.insert(stem, path);
                }
            }
        }
    }

    Ok(artifacts)
}
