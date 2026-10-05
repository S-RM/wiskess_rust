//! What the parser knows how to read, what it expects each file to be called,
//! and how much of each one to keep.
//!
//! Discovery used to be fourteen hard-coded exact filenames, matched
//! case-sensitively, with a `*.csv` fallback that only ran when *none* of the
//! fourteen matched. Since the dispatch side only ever asked for a fixed key, a
//! file the table did not name could never be parsed even when the fallback found
//! it. Three artifacts in a current collection were invisible for that reason —
//! `network-kstrike.csv` (the Linux-Wiskess equivalent of `network.csv`),
//! `usnjrnl_j_rusty.csv` and `mft_dump.csv` — and nothing in the run said a file
//! had been skipped.
//!
//! The registry also records the thing the dispatch code could not: **volume
//! class**. A handful of artifacts are genuinely too noisy to carry whole and are
//! filtered down to detections. Everything else is small and every row of it is
//! worth having in the supertimeline, whether or not a rule fired. Those two
//! groups had been treated identically — detection-gated — which is why eight
//! artifact families contributed nothing at all.

use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// How much of an artifact to carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Volume {
    /// Small enough to keep whole. Every row becomes an event, at an `info` floor
    /// when no rule fired, so the supertimeline holds the record and the curated
    /// triage cut stays as narrow as it was.
    Quiet,
    /// Hundreds of thousands to millions of rows. Detection-gated: only rows a
    /// rule fired on, or whose extension is inherently interesting, survive.
    Noisy,
}

impl Volume {
    pub fn label(self) -> &'static str {
        match self {
            Volume::Quiet => "quiet",
            Volume::Noisy => "noisy",
        }
    }
}

/// A quiet artifact with no bespoke parser, emitted generically.
#[derive(Clone, Copy, Debug)]
pub struct PassthroughSpec {
    pub source: &'static str,
    pub event_type: &'static str,
    pub detection_rule: &'static str,
    /// Columns to build a description from when `message` is empty, and to feed
    /// to the path/TA/IOC detectors.
    pub extra_cols: &'static [&'static str],
}

pub struct ArtifactSpec {
    /// Dispatch key. Also the name used in the coverage table.
    pub key: &'static str,
    /// Accepted filenames, **in preference order** — the first one present wins
    /// and the rest are reported as superseded.
    pub files: &'static [&'static str],
    pub volume: Volume,
    pub passthrough: Option<PassthroughSpec>,
    /// Why the preferred file is preferred, for the coverage table. Empty when
    /// the alternatives are just spelling variants.
    pub preference_note: &'static str,
}

pub const ARTIFACTS: &[ArtifactSpec] = &[
    // ---- Noisy: filtered to detections -------------------------------------
    ArtifactSpec {
        key: "hayabusa",
        files: &["hayabusa.csv"],
        volume: Volume::Noisy,
        passthrough: None,
        preference_note: "",
    },
    ArtifactSpec {
        key: "event-logs",
        files: &["event-logs.csv", "event_logs.csv", "EvtxECmd-All.csv"],
        volume: Volume::Noisy,
        passthrough: None,
        preference_note: "",
    },
    ArtifactSpec {
        key: "mft",
        // MFTECmd.csv first: it splits the $STANDARD_INFORMATION timestamps into
        // the `Created0x10` rows this parser keys on. `mft_dump.csv` is the
        // Linux-Wiskess parse of the same $MFT — usable as a fallback, and it
        // uniquely carries IsDeleted / HasAlternateDataStreams, but parsing both
        // would double every file event on the host.
        files: &["MFTECmd.csv", "mft_dump.csv"],
        volume: Volume::Noisy,
        passthrough: None,
        preference_note: "MFTECmd.csv splits the $SI timestamps this parser reads",
    },
    ArtifactSpec {
        key: "usnjrnl",
        // `usnjrnl_j_rusty.csv` first, and this ordering is the whole point:
        // `usnjrnl-j-file.csv` ships with an **empty** ParentPath on every row, so
        // it can only ever supply bare filenames — no directory, therefore no
        // webroot detection and no usable file identity. The rusty parse derives
        // the full path into `full_name`. Same events, one of them usable.
        files: &["usnjrnl_j_rusty.csv", "usnjrnl-j-file.csv", "usnjrnl.csv"],
        volume: Volume::Noisy,
        passthrough: None,
        preference_note: "usnjrnl_j_rusty.csv derives full paths; usnjrnl-j-file.csv's ParentPath is empty",
    },
    ArtifactSpec {
        key: "hindsight",
        files: &["hindsight.csv"],
        volume: Volume::Noisy,
        passthrough: None,
        preference_note: "",
    },

    // ---- Quiet: carried whole ----------------------------------------------
    ArtifactSpec {
        key: "network",
        // network-kstrike.csv is the Linux-Wiskess parse of the same User Access
        // Logging database that network.csv (SumECmd) holds on Windows. It was
        // never registered, so UAL evidence was missing from every Linux-collected
        // host without a word.
        files: &["network.csv", "network-kstrike.csv", "network_kstrike.csv", "sum.csv", "srum.csv"],
        volume: Volume::Quiet,
        passthrough: None,
        preference_note: "network-kstrike.csv is the same UAL data from a Linux collection",
    },
    ArtifactSpec {
        key: "registry",
        files: &["registry.csv"],
        volume: Volume::Quiet,
        passthrough: None,
        preference_note: "",
    },
    ArtifactSpec {
        key: "regripper",
        files: &["regripper.csv"],
        volume: Volume::Quiet,
        passthrough: None,
        preference_note: "",
    },
    ArtifactSpec {
        key: "amcache",
        files: &["amcache.csv"],
        volume: Volume::Quiet,
        passthrough: None,
        preference_note: "",
    },
    ArtifactSpec {
        key: "amcache-regripper",
        files: &["regripper_amcache.csv", "amcache_regripper.csv"],
        volume: Volume::Quiet,
        passthrough: None,
        preference_note: "",
    },
    ArtifactSpec {
        key: "appcompatcache",
        files: &["appcompatcache.csv"],
        volume: Volume::Quiet,
        passthrough: None,
        preference_note: "",
    },
    ArtifactSpec {
        key: "browser-hist",
        files: &["browser-hist.csv", "browser_history.csv"],
        volume: Volume::Quiet,
        passthrough: None,
        preference_note: "",
    },
    ArtifactSpec {
        key: "jump-lists",
        files: &["jump-lists.csv", "jump_lists.csv"],
        volume: Volume::Quiet,
        passthrough: None,
        preference_note: "",
    },
    ArtifactSpec {
        key: "lnk-files",
        files: &["lnk-files.csv", "lnk_files.csv"],
        volume: Volume::Quiet,
        passthrough: None,
        preference_note: "",
    },

    // ---- Quiet, no bespoke parser: emitted generically ---------------------
    ArtifactSpec {
        key: "shellbags",
        files: &["shellbags.csv", "shellbags_user.csv"],
        volume: Volume::Quiet,
        passthrough: Some(PassthroughSpec {
            source: "shellbags",
            event_type: "folder_access",
            detection_rule: "shellbag_record",
            // AbsolutePath is the reason this artifact matters: it records a
            // folder a user browsed to, including a UNC share on another host,
            // and survives the folder being deleted.
            extra_cols: &["AbsolutePath", "ShellType", "Value", "user_name"],
        }),
        preference_note: "",
    },
    ArtifactSpec {
        key: "powershell-history",
        files: &["powershell_history.csv", "powershell-history.csv", "ps_history.csv"],
        volume: Volume::Quiet,
        passthrough: Some(PassthroughSpec {
            source: "powershell-history",
            event_type: "command_executed",
            detection_rule: "powershell_console_history",
            extra_cols: &["command", "user_name"],
        }),
        preference_note: "",
    },
    ArtifactSpec {
        key: "recycle-bin",
        files: &["recycle-bin.csv", "recycle_bin.csv", "recyclebin.csv"],
        volume: Volume::Quiet,
        passthrough: Some(PassthroughSpec {
            source: "recycle-bin",
            event_type: "file_deleted",
            detection_rule: "recycle_bin_record",
            extra_cols: &["FileName", "FileSize", "user_name"],
        }),
        preference_note: "",
    },
    ArtifactSpec {
        key: "prefetch",
        files: &["prefetch.csv", "pecmd.csv"],
        volume: Volume::Quiet,
        passthrough: Some(PassthroughSpec {
            source: "prefetch",
            event_type: "process_executed",
            detection_rule: "prefetch_record",
            extra_cols: &["ExecutableName", "RunCount", "SourceFilename"],
        }),
        preference_note: "",
    },
    ArtifactSpec {
        key: "services",
        files: &["services.csv"],
        volume: Volume::Quiet,
        passthrough: Some(PassthroughSpec {
            source: "services",
            event_type: "service_config",
            detection_rule: "service_record",
            extra_cols: &["ServiceName", "ImagePath", "StartMode", "user_name"],
        }),
        preference_note: "",
    },
];

/// Files in `Timeline/` that are not artifacts, so an unrecognised-file warning
/// does not fire on the parser's own output or on the host summary.
const NOT_ARTIFACTS: &[&str] = &["host_information.csv", "hosts.csv", "iocs.csv"];

/// One file the run chose not to read, and why.
#[derive(Clone, Debug)]
pub struct Superseded {
    pub key: String,
    pub skipped: String,
    pub chosen: String,
    pub note: String,
}

pub struct Discovery {
    /// Dispatch key -> the file chosen for it.
    pub artifacts: HashMap<String, PathBuf>,
    pub superseded: Vec<Superseded>,
    /// CSVs in the directory that no spec claims.
    pub unrecognised: Vec<String>,
}

pub fn spec(key: &str) -> Option<&'static ArtifactSpec> {
    ARTIFACTS.iter().find(|s| s.key == key)
}

/// Index the directory once, then resolve each spec against it.
///
/// Matching is case-insensitive: a collection produced on a case-sensitive
/// filesystem spells `MFTECmd.csv` differently from one produced on Windows, and
/// the old exact comparison meant whichever way round the operator's collection
/// came, one of them silently found nothing.
pub fn discover(timeline_dir: &Path) -> Result<Discovery> {
    if !timeline_dir.exists() {
        anyhow::bail!("Timeline directory does not exist: {:?}", timeline_dir);
    }

    // lowercased filename -> real path
    let mut index: HashMap<String, PathBuf> = HashMap::new();
    for entry in std::fs::read_dir(timeline_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            index.insert(name.to_lowercase(), path.clone());
        }
    }

    let mut artifacts = HashMap::new();
    let mut superseded = Vec::new();
    let mut claimed: HashSet<String> = HashSet::new();

    for s in ARTIFACTS {
        let mut chosen: Option<&str> = None;
        for candidate in s.files {
            let lower = candidate.to_lowercase();
            let Some(path) = index.get(&lower) else { continue };
            claimed.insert(lower);
            match chosen {
                None => {
                    artifacts.insert(s.key.to_string(), path.clone());
                    chosen = Some(candidate);
                }
                Some(first) => superseded.push(Superseded {
                    key: s.key.to_string(),
                    skipped: (*candidate).to_string(),
                    chosen: first.to_string(),
                    note: s.preference_note.to_string(),
                }),
            }
        }
    }

    // Anything left is a CSV this build does not know about. Reported rather than
    // guessed at: the old `*.csv` fallback inferred a dispatch key from the file
    // stem, which no dispatch site ever asked for, so the file was read into a map
    // and then dropped. Saying so is more use than pretending to handle it.
    let mut unrecognised: Vec<String> = index
        .iter()
        .filter(|(lower, _)| {
            lower.ends_with(".csv")
                && !claimed.contains(*lower)
                && !NOT_ARTIFACTS.contains(&lower.as_str())
        })
        .map(|(_, p)| {
            p.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string()
        })
        .collect();
    unrecognised.sort();

    Ok(Discovery { artifacts, superseded, unrecognised })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_with(files: &[&str]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for f in files {
            std::fs::write(d.path().join(f), "datetime,timestamp_desc,message\n").unwrap();
        }
        d
    }

    #[test]
    fn every_key_is_unique_and_every_spec_names_at_least_one_file() {
        let mut seen = HashSet::new();
        for s in ARTIFACTS {
            assert!(seen.insert(s.key), "duplicate artifact key {}", s.key);
            assert!(!s.files.is_empty(), "{} names no files", s.key);
        }
    }

    /// The three that were invisible.
    #[test]
    fn the_previously_undiscovered_files_are_now_registered() {
        let d = dir_with(&["network-kstrike.csv", "usnjrnl_j_rusty.csv", "mft_dump.csv"]);
        let found = discover(d.path()).unwrap();
        assert!(found.artifacts.contains_key("network"), "network-kstrike.csv must satisfy `network`");
        assert!(found.artifacts.contains_key("usnjrnl"));
        assert!(found.artifacts.contains_key("mft"), "mft_dump.csv must satisfy `mft` as a fallback");
        assert!(found.unrecognised.is_empty(), "got {:?}", found.unrecognised);
    }

    /// The operator's correction: when both USN parses are present, the one with
    /// derived full paths wins and the other is reported, not silently ignored.
    #[test]
    fn the_usn_parse_with_full_paths_is_preferred_and_the_other_is_reported() {
        let d = dir_with(&["usnjrnl_j_rusty.csv", "usnjrnl-j-file.csv"]);
        let found = discover(d.path()).unwrap();
        let chosen = found.artifacts.get("usnjrnl").unwrap();
        assert_eq!(chosen.file_name().unwrap(), "usnjrnl_j_rusty.csv");

        let s = found.superseded.iter().find(|s| s.key == "usnjrnl").unwrap();
        assert_eq!(s.skipped, "usnjrnl-j-file.csv");
        assert!(s.note.contains("ParentPath"), "the reason has to be legible: {}", s.note);
    }

    /// Parsing both MFT parses would double every file event on the host.
    #[test]
    fn only_one_mft_parse_is_read_when_both_are_present() {
        let d = dir_with(&["MFTECmd.csv", "mft_dump.csv"]);
        let found = discover(d.path()).unwrap();
        assert_eq!(found.artifacts.get("mft").unwrap().file_name().unwrap(), "MFTECmd.csv");
        assert_eq!(found.superseded.iter().filter(|s| s.key == "mft").count(), 1);
    }

    #[test]
    fn filenames_match_regardless_of_case() {
        let d = dir_with(&["mftecmd.csv", "HAYABUSA.CSV"]);
        let found = discover(d.path()).unwrap();
        assert!(found.artifacts.contains_key("mft"));
        assert!(found.artifacts.contains_key("hayabusa"));
    }

    /// A new timeliner artifact must announce itself rather than vanish.
    #[test]
    fn an_unknown_csv_is_reported_and_the_host_summary_is_not() {
        let d = dir_with(&["something_new.csv", "Host_Information.csv", "hayabusa.csv"]);
        let found = discover(d.path()).unwrap();
        assert_eq!(found.unrecognised, vec!["something_new.csv"]);
    }

    #[test]
    fn a_missing_directory_is_an_error_not_an_empty_result() {
        assert!(discover(Path::new("/nonexistent/timeline/dir")).is_err());
    }

    /// The classes the operator named as needing filtering, and the ones that
    /// must not be.
    #[test]
    fn volume_classes_match_what_the_artifacts_actually_are() {
        for key in ["mft", "usnjrnl", "event-logs", "hayabusa"] {
            assert_eq!(spec(key).unwrap().volume, Volume::Noisy, "{key}");
        }
        for key in ["network", "shellbags", "lnk-files", "jump-lists", "recycle-bin", "registry"] {
            assert_eq!(spec(key).unwrap().volume, Volume::Quiet, "{key}");
        }
    }

    #[test]
    fn passthrough_artifacts_are_all_quiet() {
        for s in ARTIFACTS {
            if s.passthrough.is_some() {
                assert_eq!(s.volume, Volume::Quiet, "{} has no parser and must be quiet", s.key);
            }
        }
    }
}
