use crate::ops::file_ops;

use super::super::ops::exe_ops;

use anyhow::Ok;
use anyhow::Result;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct Item {
    key: String,
}

#[derive(Debug, Deserialize)]
struct Contents {
    contents: Vec<Item>,
}

/// Download a file from an S3 bucket.
/// # Arguments
/// * `s3_url` - The S3 URL of the file
/// * `folder` - The path to download to
pub async fn get_s3_file(s3_url: &str, output: &PathBuf, file: &String, recurse: bool) -> Result<PathBuf> {
    // let region = "eu-central-1";
    let log_name = Path::new("whipped.log");

    if !output.exists() {
        // make the output folder
        file_ops::make_folders(&output);
    }
    
    let args = match recurse {
        true => format!("s3 cp {s3_url} {} --output=json --recursive", output.display()),
        false => format!("s3 cp {s3_url} {} --output=json", output.display())
    };
    exe_ops::run_wisker(&"aws".to_string(), &args, log_name);

    let out_file = if output.join(file).exists() {
        output.join(file)
    } else {
        PathBuf::new()
    };

    Ok(out_file)
}

/// Download a file from an S3 bucket.
/// # Arguments
/// * `input` - the path to where the file will be uploaded
/// * `s3_url` - The S3 URL of the file
pub async fn put_s3_file(input: &PathBuf, s3_url: &str) {
    // let region = "eu-central-1";
    let log_name = Path::new("whipped.log");

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
pub async fn list_s3_files(s3_url: &str) -> Result<Vec<String>> {
    let bucket = s3_url.trim_start_matches("s3://");
    // let region = "eu-central-1";
    let log_name = Path::new("whipped.log");
    
    // aws s3api list-objects-v2 --bucket ir-evidence-falcon --region eu-central-1 --output=json
    // let args = format!("s3api list-objects-v2 --bucket {bucket} --region {region} --output=json");
    let args = format!("s3api list-objects-v2 --bucket {bucket} --output=json");
    let json_data = exe_ops::run_wisker(&"aws".to_string(), &args, log_name);

    // Deserialize the JSON string to the Contents struct
    println!("[ ] JSON from AWS S3 list: {:?}", json_data.stdout);
    let contents: Contents = serde_json::from_str(&String::from_utf8(json_data.stdout)?)?;
    println!("[ ] Contents from AWS S3 list: {:?}", contents);
    
    // Collect all Key values into a vector
    let files = contents.contents.into_iter().map(|item| item.key).collect();
    
    println!("[ ] Files from AWS S3 list: {:?}", files);
    Ok(files)
}