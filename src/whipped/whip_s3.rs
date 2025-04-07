use crate::ops::file_ops;

use super::super::ops::exe_ops;

use anyhow::bail;
use anyhow::Ok;
use anyhow::Result;
use serde::{Serialize, Deserialize};
use serde_json::Number;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Payload {
    contents: Vec<Contents>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Contents {
    key: String,
    last_modified: String,
    size: Number
}

/// Download a file from an S3 bucket.
/// # Arguments
/// * `s3_url` - The S3 URL of the file
/// * `folder` - The path to download to
pub async fn get_s3_file(s3_url: &str, output: &PathBuf, file: &String, recurse: bool, log_name: &Path) -> Result<PathBuf> {
    // let region = "eu-central-1";
    let output_path = output.join(file);
    let out_folder = output_path.parent().unwrap();

    if !out_folder.exists() {
        // make the output folder
        file_ops::make_folders(&out_folder);
    }
    
    let args = match recurse {
        true => format!("s3 cp {s3_url} {} --output=json --recursive", out_folder.display()),
        false => format!("s3 cp {s3_url} {} --output=json", out_folder.display())
    };
    exe_ops::run_wisker(&"aws".to_string(), &args, log_name);

    let out_file = if output_path.exists() {
        output_path
    } else {
        PathBuf::new()
    };

    Ok(out_file)
}

/// Download a file from an S3 bucket.
/// # Arguments
/// * `input` - the path to where the file will be uploaded
/// * `s3_url` - The S3 URL of the file
pub async fn put_s3_file(input: &PathBuf, s3_url: &str, log_name: &Path) {
    // let region = "eu-central-1";

    if !input.exists() {
        // make the output folder
        println!("[!] Folder or file to upload does not exist, cannot be found at {}", input.display());
        return;
    }
    
    let args = format!("s3 cp {} {s3_url} --output=json", input.display());
    exe_ops::run_wisker(&"aws".to_string(), &args, log_name);
}

/// List files in an S3 bucket.
/// # Arguments
/// * `s3_url` - The S3 URL to list files from.
pub async fn list_s3_files(s3_url: &str, log_name: &Path, show_err: bool) -> Result<Vec<String>> {
    if !show_err {
        return Ok(vec!["".to_string()])
    }
    let bucket = s3_url.trim_start_matches("s3://");
    // let region = "eu-central-1";
    
    // aws s3api list-objects-v2 --bucket ir-evidence-falcon --region eu-central-1 --output=json
    // let args = format!("s3api list-objects-v2 --bucket {bucket} --region {region} --output=json");
    let args = format!("s3api list-objects-v2 --bucket {bucket} --output=json");
    let json_data = exe_ops::run_wisker(&"aws".to_string(), &args, log_name);

    // Deserialize the JSON string to the Contents struct
    let json_data_str = &String::from_utf8(json_data.stdout)?;
    if json_data_str == "" {
        bail!("[!] No data was returned when attempting to list files from AWS S3 URL: {s3_url}")
    }
    let payload: Payload = serde_json::from_str(json_data_str)?;
    file_ops::log_msg(log_name, format!("[ ] Contents from AWS S3 list: {:?}", payload));
    
    // Collect all Key values into a vector
    let files = payload.contents.into_iter()
        .map(|item| item.key)
        .filter_map(|path| {
            match Path::new(&path).extension().unwrap_or_default().to_str().unwrap_or("") {
                "zip"|"rar"|"7z"|"vmdk"|"vhdx"|"vhd"|"e01"|"vdi"|"ex01"|"raw" => Some(path.trim().to_string()),
                &_ => None,
            }
        })
        .collect();
    Ok(files)
}