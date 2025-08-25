use super::whip_main;

use anyhow::Ok;
use anyhow::Result;
use std::path::{Path, PathBuf};
// use inquire::{Confirm, Text};

/// Download a file from an Azure Storage, returning the path to the downloaded file
/// # Arguments
/// * `azure_url` - the url to the azure store hosting the file
/// * `output` - the path to where the file will be downloaded
/// * `file` - the name of the file on the azure store
/// * `tool_path` - the path to the tools, such as where azcopy.exe would be
pub async fn get_azure_file(azure_url: &str, output: &PathBuf, file: &String, recurse: bool, tool_path: &PathBuf, log_name: &Path) -> Result<PathBuf> {
    let output_file = output.join(file);
    let output_str = format!("'{}'", output_file.display());
    let wr_azure_url = format!("'{azure_url}'");
    let az_cmd = match recurse {
        true => ["sync", wr_azure_url.as_str(), output_str.as_str(), "--recursive"].to_vec(),
        false => ["sync", wr_azure_url.as_str(), output_str.as_str()].to_vec(),
    };
    
    let bin_path = tool_path.join("azcopy").join("azcopy.exe");
    let _json_data = whip_main::run_cmd(bin_path, az_cmd, log_name, true)?;

    Ok(output.join(file))
}

/// Upload  a file from an Azure Storage
/// # Arguments
/// * `input` - the path to the file to be uploaded
/// * `azure_url` - the url to where the file will be uploaded
/// * `tool_path` - the path to the tools, such as where azcopy.exe would be
pub async fn put_azure_file(input: &PathBuf, azure_url: &str, tool_path: &Path, log_name: &Path) {
    let wr_azure_url = format!("'{azure_url}'");
    let input_str = &input.clone().into_os_string();
    let az_cmd = ["copy", input_str.to_str().unwrap(), wr_azure_url.as_str(), "--recursive"].to_vec();
    
    let bin_path = tool_path.join("azcopy").join("azcopy.exe");
    let _json_data = whip_main::run_cmd(bin_path, az_cmd, log_name, true).unwrap();
}

/// List files in an Azure container.
/// # Arguments
/// * `azure_url` - The Azure URL to list files from.
/// * `show_err` - used for showing if the command was run OK. Set to false for not showing error and listing all files.
pub async fn list_azure_files(azure_url: &str, tool_path: &PathBuf, log_name: &Path, show_err: bool) -> Result<Vec<String>> {
    let wr_azure_url = format!("'{azure_url}'");
    let az_cmd = ["list", wr_azure_url.as_str()].to_vec();
    
    let bin_path = tool_path.join("azcopy").join("azcopy.exe");
    let json_data = whip_main::run_cmd(bin_path, az_cmd, log_name, show_err)?;

    let mut paths = Vec::new();
    let data = String::from_utf8(json_data.stdout)?;

    // Iterate over each line.
    for line in data.lines() {
        // Split each line at the first semicolon and collect the first part.
        if let Some((path, _)) = line.split_once(";") {
            // exclude paths with unsupported extensions
            match show_err {
                true => {
                    match Path::new(path).extension().unwrap_or_default().to_str().unwrap_or("") {
                        "zip"|"rar"|"7z"|"vmdk"|"vhdx"|"vhd"|"e01"|"vdi"|"ex01"|"raw" => paths.push(path.trim().to_string()),
                        &_ => continue,
                        }
                    },
                false => paths.push(path.trim().to_string())
            }
        }
    }

    Ok(paths)

}