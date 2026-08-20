use crate::ops::exe_ops::installed_binary_check;
use crate::ops::file_ops::make_folders;

use super::whip_main::{print_log, run_cmd};

use anyhow::{bail, Result};
use fs_extra::dir::remove;
use glob::glob;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// The sub folder velociraptor collection is extracted to. Crate scope needed for tests
pub const VELO_FOLDER: &str = "velo";

/// Crate scope markers for identifying velociraptor collections
const VELO_MARKERS: [&str; 2] = ["uploads.json", "All File Metadata.json"];

/// find_velo_bin checks if the velocirpator.exe binary is available in the expected locations
/// # Arguments
/// * `tool_path` - the path to the wiskess tools folder
pub fn find_velo_bin(tool_path: &Path) -> Option<PathBuf> {
    let linked_bin = tool_path.join("velociraptor").join("velociraptor.exe");
    if linked_bin.is_file() {
        return Some(linked_bin);
    }

    let versioned_bin = glob(tool_path.join("velociraptor*").to_str()?)
        .ok()?
        .filter_map(|path| path.ok())
        .find(|path| path.is_file());
    if versioned_bin.is_some() {
        return versioned_bin;
    }

    let on_path = "velociraptor".to_string();
    match installed_binary_check(true, &on_path) == "" {
        true => Some(PathBuf::from(on_path)),
        false => None
    }
}

/// has_velo_markers says if an archive is a velociraptor collection
/// # Arguments
/// * `listing` - the contents of an archive, as listed by 7zip
pub fn has_velo_markers(listing: &str) -> bool {
    VELO_MARKERS.iter().all(|marker| listing.contains(marker))
}

/// is_velo_container checks if an archive is a velociraptor collection container, lists contents with 7zip
/// # Arguments
/// * `data_file` - the archive file path
/// * `log_name` - the name of the log file
fn is_velo_container(data_file: &Path, log_name: &Path) -> bool {
    // the artefact reads the container with the zip accessor, so only a zip can be extracted by it
    if data_file.extension().unwrap_or_default() != "zip" {
        return false;
    }

    let data_str = format!("'{}'", data_file.display());
    let list_cmd = ["l", "-ba", data_str.as_str()].to_vec();
    let bin_path = Path::new("7z.exe").to_path_buf();
    match run_cmd(bin_path, list_cmd, log_name, false) {
        Ok(output) => has_velo_markers(&String::from_utf8_lossy(&output.stdout)),
        Err(_error) => false
    }
}

/// any_file_extracted tests if a file was extracted to the output folder
fn any_file_extracted(out_folder: &Path) -> bool {
    WalkDir::new(out_folder)
        .min_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .any(|entry| entry.file_type().is_file())
}

/// extract_velo_container extracts a velociraptor collection using the `Windows.KapeFiles.Extract` artefact. It
/// restores the collected files' timestamps
/// Ref: <https://github.com/Velocidex/velociraptor/issues/2273>
/// # Arguments
/// * `velo_bin` - the path to the velociraptor binary
/// * `data_file` - the container (zip) file path
/// * `data_folder` - the folder where the container is extracted to
/// * `log_name` - the name of the log file
fn extract_velo_container(velo_bin: &Path, data_file: &Path, data_folder: &Path, log_name: &Path) -> Result<PathBuf> {
    let out_folder = data_folder.join("uploads").join(VELO_FOLDER);
    make_folders(&out_folder);

    let container_arg = format!("ContainerPath='{}'", data_file.display());
    let output_arg = format!("OutputDirectory='{}'", out_folder.display());
    let velo_cmd = [
        "artifacts", "collect", "Windows.KapeFiles.Extract",
        "--args", container_arg.as_str(),
        "--args", output_arg.as_str()
    ].to_vec();

    print_log(
        format!("Extracting the velociraptor collection '{}', preserving the timestamps...", data_file.display()).as_str(),
        log_name,
        true
    );
    let output = run_cmd(velo_bin.to_path_buf(), velo_cmd, log_name, true)?;
    if !output.status.success() {
        bail!("velociraptor exited with an error: {}", String::from_utf8_lossy(&output.stderr));
    }
    
    if !any_file_extracted(&out_folder) {
        bail!("no files were extracted from the container: {}", data_file.display());
    }
    Ok(out_folder)
}

/// extract_7z extracts an archive with 7zip
/// # Arguments
/// * `data_file` - the archive file path
/// * `data_folder` - the folder where the archive is extracted to
/// * `log_name` - the name of the log file
fn extract_7z(data_file: &Path, data_folder: &Path, log_name: &Path) {
    let data_str = format!("'{}'", data_file.display());
    let extract_flag = format!("-o'{}'", data_folder.display());
    let unzip_cmd = ["x", "-aos", data_str.as_str(), extract_flag.as_str()].to_vec();

    let bin_path = Path::new("7z.exe").to_path_buf();
    print_log(format!("Extracting the archive {data_str}...").as_str(), log_name, true);
    let _json_data = run_cmd(bin_path, unzip_cmd, log_name, true).unwrap();
}

/// extract_archive extracts an archive to the data folder using the velociraptor binary 
/// if available, otherwise it falls back to 7zip. It preserves the timestamps of the collected
/// files if velociraptor is used.
/// # Arguments
/// * `data_file` - the archive file path
/// * `data_folder` - the folder where the archive is extracted to
/// * `tool_path` - the path to the wiskess tools folder, where the velociraptor binary is
/// * `log_name` - the name of the log file
pub fn extract_archive(data_file: &Path, data_folder: &Path, tool_path: &Path, log_name: &Path) {
    if let Some(velo_bin) = find_velo_bin(tool_path) {
        if is_velo_container(data_file, log_name) {
            match extract_velo_container(&velo_bin, data_file, data_folder, log_name) {
                Ok(out_folder) => {
                    print_log(
                        format!("[ ] Extracted the velociraptor collection to: {}", out_folder.display()).as_str(),
                        log_name,
                        true
                    );
                    return;
                },
                Err(error) => {
                    // remove any part extracted files, so 7zip extracts the container from scratch
                    let _ = remove(data_folder.join("uploads").join(VELO_FOLDER));
                    print_log(
                        format!("[!] Unable to extract with velociraptor, so using 7zip - the timestamps won't be restored. Error: {error}").as_str(),
                        log_name,
                        true
                    );
                }
            }
        }
    } else {
        print_log(
            "[ ] No velociraptor binary found in the tools folder or on the path, so using 7zip - the timestamps of a velociraptor collection won't be restored.",
            log_name,
            true
        );
    }
    extract_7z(data_file, data_folder, log_name);
}
