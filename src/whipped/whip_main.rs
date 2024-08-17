use super::super::ops::exe_ops;

use rusoto_core::Region;
use rusoto_s3::{
    S3Client, S3, ListObjectsV2Request, 
    // GetObjectRequest
};
use serde::Deserialize;
// use tokio::fs::{self, File};
// use tokio::io::AsyncWriteExt;
// use tokio_stream::StreamExt;
// use futures::stream::TryStreamExt;
// use mime_guess::MimeGuess;
use std::error::Error;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
// use std::fs::metadata;
// use std::ptr::replace;
use reqwest::blocking::Client;
// use azure_storage_blobs::prelude::{BlobClient, BlobServiceClient};
use azure_storage::prelude::*;
use azure_storage_blobs::prelude::*;
use azure_core::prelude::*;
use futures::stream::StreamExt;
use serde_json::Value;
use struct_iterable::Iterable;

#[derive(Debug, Deserialize)]
struct Item {
    Key: String,
    LastModified: String,
    ETag: String,
    Size: u64,
    StorageClass: String,
}

#[derive(Debug, Deserialize)]
struct Contents {
    Contents: Vec<Item>,
}

#[derive(Debug, Deserialize, Iterable)]
struct Message {
    TimeStamp: String,
    MessageType: String,
    MessageContent: String,
    PromptDetails: Value,
}

#[derive(Debug, Deserialize)]
struct MessageContent {
    Path: String,
    ContentLength: String,
}

/// set_link determines whether the link is an AWS S3 or Azure Blob Storage URL using 
/// regex patterns. It then appends the provided component to the base URL accordingly.
///
/// # Arguments
/// * `link` - A string slice of the initial link that may point to an AWS S3 bucket or Azure Blob Storage.
/// * `component` - A string slice representing the specific component (data source or folder) to be appended to the URL.
/// * `aws_pattern` - A reference to a compiled regex pattern used to match AWS S3 URLs.
/// * `azure_pattern` - A reference to a compiled regex pattern used to match Azure Blob Storage URLs.
fn set_link(link: &str, folder: &str) -> String {
    let url = if link.starts_with("s3") {
        // If the cloud storage is AWS
        format!("{}/{}", link.trim_end_matches("/*"), folder)
    } else if let Some(azure_match) = regex::Regex::new(r"^https://[^/]+.core.windows.net").unwrap().captures(link) {
        // If the cloud storage is Azure
        let parts: Vec<&str> = link.split('?').collect();
        format!("{}/{}?{}", parts[0], folder, parts[1])
    } else {
        String::new()
    };
    url
}

/// Splits a given string by either a comma or a newline and trims each resulting substring.
///
/// # Arguments
/// * `data_source_list` - A string containing the source data to be split and trimmed.
fn split_and_trim(data_source_list: &str) -> Vec<String> {
    // Determine the split character
    let split_char = if data_source_list.contains(",") {
        ','
    } else {
        '\n'
    };

    // Split, trim, and collect the elements into a vector
    data_source_list
        .split(split_char)
        .map(|s| s.trim().to_string())
        .collect()
}

/// List files in an S3 bucket.
///
/// # Arguments
/// * `s3_url` - The S3 URL to list files from.
async fn list_s3_files(s3_url: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let bucket = s3_url.trim_start_matches("s3://");
    let region = "eu-central-1";
    let log_name = Path::new("whipped.log");
    
    // aws s3api list-objects-v2 --bucket ir-evidence-falcon --region eu-central-1 --output=json
    let args = format!("s3api list-objects-v2 --bucket {bucket} --region {region} --output=json");
    let json_data = exe_ops::run_wisker(&"aws".to_string(), &args, log_name);

    // Deserialize the JSON string to the Contents struct
    let contents: Contents = serde_json::from_str(&String::from_utf8(json_data.stdout)?)?;
    
    // Collect all Key values into a vector
    let files = contents.Contents.into_iter().map(|item| item.Key).collect();

    Ok(files)
}

/// List files in an Azure container.
///
/// # Arguments
/// * `azure_url` - The Azure URL to list files from.
async fn list_azure_files(azure_url: &str, tool_path: &PathBuf) -> Result<Vec<String>, Box<dyn Error>> {
    let log_name = Path::new("whipped.log");
    
    let binary = tool_path.join("azcopy").join("azcopy.exe")
        .into_os_string()
        .into_string()
        .unwrap();
    let args = format!("-c \"{binary} list '{azure_url}'\"");
    let json_data = exe_ops::run_wisker(
        &"pwsh".to_string(), 
        &args, 
        Path::new(log_name)
    );

    let mut paths = Vec::new();
    let data = String::from_utf8(json_data.stdout)?;

    println!("{data}");

    // Iterate over each line.
    for line in data.lines() {
        // Split each line at the first semicolon and collect the first part.
        if let Some((path, _)) = line.split_once(";") {
            paths.push(path.trim().to_string());
        }
    }

    // Print the collected paths.
    println!("{:?}", paths);

    Ok(paths)

}

/// List files from either an S3 or Azure link.
///
/// # Arguments
/// * `in_link` - A string slice of the initial input link that may point to an AWS S3 bucket or Azure Blob Storage.
async fn list_files(in_link: &String, tool_path: &PathBuf) -> Result<Vec<String>, Box<dyn Error>> {
    if in_link.starts_with("s3") {
        list_s3_files(&in_link).await
    } else if in_link.starts_with("https://") {
        list_azure_files(&in_link, &tool_path).await
    } else {
        panic!("Unknown URL format.");
    }
}


#[tokio::main]
pub async fn whip_main(data_source_list: &String, local_storage: &String, in_link: &String, tool_path: &PathBuf) {
    let mut data_list = Vec::new();
    if data_source_list == "" {
        // if no data source list provided, list the files/blobs/objects in the in_link
        data_list = match list_files(&in_link, &tool_path).await {
            Ok(files) => files,
            Err(e) => {
                eprintln!("Error listing the files: {}", e);
                panic!("User provided no data source list and there was an error listing files in the in_link");
            },
        };
    } else {
        // split the data source list by either commas, new lines, if needed
        data_list = split_and_trim(&data_source_list);
    }
    // loop through the data_list
    for data_item in data_list {
        // set vars for `data_folder`, `process_folder`
        let data_name = Path::new(&data_item).file_stem().unwrap().to_os_string().into_string().unwrap();
        let data_folder = Path::new(local_storage).join(format!("{data_name}-Wiskess"));
        println!("Downloading: {data_item} to {}", data_folder.display());
    }
    // set the in_link based on the item of the data_list
    // set the out_link based on the provided out_link and the process folder
    // check if the process folder exists in the out_link
    // if the process folder doens't exist in the out_link or the update flag is set
        // download the data
            // log the data downloaded and its size
            // get the type of data downloaded, i.e. image, folder or archive
            // if folder, loop through the folder at one level down, adding archives and images to process_vector
            // if extracted folder exists, log a message 
            // else if data is an archive, extract it to the extracted folder and check for archives at one level deep, adding paths to the process_vector
            // else if data is an image, move it to the extracted folder, add path to process_vector
            // else data is a file, move it to the extracted folder, add path to process_vector
        // update the data
            // if update flag is set download the process folder
                // if artefacts/collection.zip exists, expand it
                // remove any process result files that are zero size
                // remove timeline folder, ioc summary and ioc in analysis
        // process the data with a loop through the process_vector
            // if extension or file type is image, send to process_image
            // else if extension or file type is archive, send to process_archive
            // else if folder and has child folder named files, send to process_surge
            // else if folder and has child folder named uploads, send to process_velo
            // else log message that downloaded file is unknown, reporting on the downloaded data and contents at three levels deep
        // upload the data
            // compress the artefacts folder to a file collection.zip
            // upload the process folder
            // remove the data source files and extracted folder
    // else log a message saying use update flag or delete the process folder from the out_link
    // log a message to state the data source has been processed


    // let object_list_result = s3_client.list_objects_v2(list_request).await.unwrap();
    // if let Some(contents) = object_list_result.contents {
    //     for object in contents {
    //         if let Some(key) = object.key {
    //             let extensions = vec!["zip", "7z", "vmdk", "vhdx", "vhd", "eo1", "vdi", "ex01", "raw"];
    //             if extensions.iter().any(|&ext| key.ends_with(ext)) {
    //                 // Download the file
    //                 println!("Downloading: {}", key);
    //                 download_file(&s3_client, &bucket_name, &key).await;

    //                 let local_path = format!("x:/{}", key);
    //                 let file_metadata = metadata(&local_path).unwrap();
    //                 let file_type = MimeGuess::from_path(&local_path);

    //                 println!("File size: {} bytes", file_metadata.len());
    //                 println!("File type: {:?}", file_type);

    //                 // Delete the file
    //                 let _ = fs::remove_file(local_path).await;
    //                 println!("File deleted: {}", key);
    //             }
    //         }
    //     }
    // }
}

// Function to download a file from S3
// async fn download_file(s3_client: &S3Client, bucket: &str, key: &str) {
//     let get_request = GetObjectRequest {
//         bucket: bucket.to_owned(),
//         key: key.to_owned(),
//         ..Default::default()
//     };

//     if let Ok(result) = s3_client.get_object(get_request).await {
//         if let Some(body) = result.body {
//             let path = format!("x:/{}", key);

//             if let Ok(mut file) = File::create(&path).await {
//                 let mut stream = body.into_async_read();

//                 while let Ok(Some(chunk)) = stream.try_next().await {
//                     let _ = file.write_all(&chunk).await;
//                 }
//             }
//         }
//     }
// }