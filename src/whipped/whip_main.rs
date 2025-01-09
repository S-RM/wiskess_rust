use crate::configs::config::{self, MainArgs, WhippedArgs};
use crate::ops::exe_ops::{installed_binary_check, run_wisker};
use crate::ops::{file_ops, wiskess};

use super::super::ops::exe_ops;

use anyhow::{bail, Ok};
use indicatif::MultiProgress;
use serde::Deserialize;
use anyhow::Result;
use std::collections::HashMap;
use std::fs::metadata;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use std::process::Command;
use fs_extra::dir::{create, move_dir, CopyOptions};
use fs_extra::file::{move_file, CopyOptions as FileCopyOptions};
use inquire::Text;

#[derive(Debug, Deserialize)]
struct Item {
    key: String,
    // last_modified: String,
    // etag: String,
    // size: u64,
    // storage_class: String,
}

#[derive(Debug, Deserialize)]
struct Contents {
    contents: Vec<Item>,
}

/// set_link determines whether the link is an AWS S3 or Azure Blob Storage URL using 
/// regex patterns. It then appends the provided component to the base URL accordingly.
/// # Arguments
/// * `link` - A string slice of the initial link that may point to an AWS S3 bucket or Azure Blob Storage.
/// * `component` - A string slice representing the specific component (data source or folder) to be appended to the URL.
/// * `aws_pattern` - A reference to a compiled regex pattern used to match AWS S3 URLs.
/// * `azure_pattern` - A reference to a compiled regex pattern used to match Azure Blob Storage URLs.
fn set_link(link: &str, folder: &str) -> String {
    let url = if link.starts_with("s3") {
        // If the cloud storage is AWS
        format!("{}/{}", link.trim_end_matches("/*"), folder)
    } else if let Some(_azure_match) = regex::Regex::new(r"^https://[^/]+.core.windows.net").unwrap().captures(link) {
        // If the cloud storage is Azure
        let parts: Vec<&str> = link.split('?').collect();
        format!("{}/{}?{}", parts[0], folder, parts[1])
    } else {
        String::new()
    };
    url
}

/// Splits a given string by either a comma or a newline and trims each resulting substring.
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

/// Pre-process some data, get its type and put it into an extracted folder
/// return the process_vector - a list of paths needing processing
/// # Arguments
/// * `file_path` - The file to pre-process, could be a file or folder
/// * `log_name` - The file where logs are stored
/// * `data_folder` - the path to where the data extracted/copied to, i.e. collection.zip is extracted to collection-extracted
fn pre_process_data(file_path: &Path, log_name: &Path, data_folder: &PathBuf) -> Result<Vec<PathBuf>> {
    
    // log the data downloaded and its size
    let data_meta = metadata(&file_path)?;
    
    #[cfg (target_os = "windows")] {
        use std::os::windows::fs::MetadataExt;
        
        file_ops::log_msg(log_name, format!(
            "Downloaded file: {} with size: {} and type: {:?}.", 
            file_path.display(),
            data_meta.file_size(),
            data_meta.file_type(),
        ));
    }

    
    // get the type of data downloaded, i.e. image, folder or archive
    let mut process_vector: Vec<PathBuf> = Vec::new();
    if file_path.is_dir() {
        // if folder, loop through the folder at one level down, adding archives and images to process_vector
        let entries: Vec<PathBuf> = WalkDir::new(file_path)
            .min_depth(1)
            .max_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .collect();
    
        entries.iter().for_each(|entry| {
            if let Some(ext) = entry.extension() {
                match ext.to_str().unwrap_or("") {
                    "vmdk"|"vhdx"|"vhd"|"e01"|"vdi"|"ex01"|"raw" => {
                        process_vector.push(entry.to_path_buf())
                    },
                    "zip"|"7z" => {
                        pre_process_zip(entry, data_folder, log_name, &mut process_vector);
                    }
                    _ => println!("[ ] File in folder is not a valid artefact type")
                }
            }
        });
    } else if file_path.extension().unwrap() == "zip" || file_path.extension().unwrap() == "7z" {
        pre_process_zip(&file_path.to_path_buf(), data_folder, log_name, &mut process_vector);
    } else {
        process_vector.push(file_path.to_path_buf());
    }
    Ok(process_vector)
}


/// pre-process an achive of type zip or 7z, extract using 7zip then add artefacts to a vector. If the contents
/// has a folder in the root called uploads we treat it as a velociraptor collection and move the data into one folder.
/// # Arguments
/// `data_file` - the archive file path
/// `data_folder` - the folder where the archive is stored
/// `log_name` - the name of the log file
/// `process_vector` - the vector of files that need processing, is updated in this function
fn pre_process_zip(data_file: &PathBuf, data_folder: &PathBuf, log_name: &Path, process_vector: &mut Vec<PathBuf>) {
    // if data is an archive, extract it to the extracted folder 
    let data_str = data_file.clone().into_os_string();
    let extract_flag = format!("-o{}", data_folder.display());
    let unzip_cmd = ["x", "-aos", data_str.to_str().unwrap(), extract_flag.as_str()].to_vec();
                        
    let bin_path = Path::new("7z.exe").to_path_buf();
    let _json_data = run_cmd(bin_path, unzip_cmd, log_name).unwrap();
    // TODO: check for archives at one level deep, adding paths to the process_vector
    // loop through the extracted archive at one level down, adding relevant data to process_vector
    let entries: Vec<PathBuf> = WalkDir::new(data_folder)
        .min_depth(1)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .map(|e| e.into_path())
        .collect();

    entries.iter().for_each(|data_file| {
        if let Some(ext) = data_file.extension() {
            match ext.to_str().unwrap_or("") {
                "vmdk"|"vhdx"|"vhd"|"e01"|"vdi"|"ex01"|"raw" => {
                    process_vector.push(data_file.to_path_buf())
                },
                _ => ()
            }
        }
        if let Some(file_path) = data_file.file_name() {
            match file_path.to_str().unwrap_or("") {
                "uploads" => {
                    // this is a velociraptor collection, find data in folders `auto` and `ntfs`
                    let files_dir = data_file.join("files");
                    if files_dir.is_dir() {
                    println!("[ ] files folder already created, so not moving over files");
                    // add `files` folder to process_vector
                    return process_vector.push(files_dir)
                    }
                    let files_entries: Vec<PathBuf> = WalkDir::new(data_file)
                        .min_depth(3)
                        .max_depth(3)
                        .into_iter()
                        .filter_map(|e| e.ok())
                        .map(|e| e.into_path())
                        .collect();
                    // create folder `files`
                    _ = create(&files_dir, false);
                    // move the data into `files`
                    files_entries.iter().for_each(|files_entry| {
                        match files_entry.is_dir() {
                            true => {
                                let options = CopyOptions::new();
                                move_dir(files_entry, &files_dir, &options).unwrap()
                            },
                            false => {
                                let options = FileCopyOptions::new();
                                move_file(files_entry, &files_dir.join(files_entry.file_name().unwrap()), &options).unwrap()
                            },
                        };
                    });
                    // add `files` folder to process_vector
                    process_vector.push(files_dir)
                },
                _ => ()
            }
        }
    });
}

/// Download a file from an S3 bucket.
/// # Arguments
/// * `s3_url` - The S3 URL of the file
/// * `folder` - The path to download to
async fn get_s3_file(s3_url: &str, output: &PathBuf, file: &String) -> Result<PathBuf> {
    let region = "eu-central-1";
    let log_name = Path::new("whipped.log");

    if !output.exists() {
        // make the output folder
        file_ops::make_folders(&output);
    }
    
    let args = format!("s3 cp {s3_url} {} --region {region} --output=json", output.display());
    exe_ops::run_wisker(&"aws".to_string(), &args, log_name);

    let out_file = if output.join(file).exists() {
        output.join(file)
    } else {
        PathBuf::new()
    };

    Ok(out_file)
}

/// Download a file from an Azure Storage, returning the path to the downloaded file
/// # Arguments
/// * `azure_url` - the url to the azure store hosting the file
/// * `output` - the path to where the file will be downloaded
/// * `file` - the name of the file on the azure store
/// * `tool_path` - the path to the tools, such as where azcopy.exe would be
async fn get_azure_file(azure_url: &str, output: &PathBuf, file: &String, tool_path: &PathBuf) -> Result<PathBuf> {
    let log_name = Path::new("whipped.log");
    let output_file = output.join(file);
    let output_str = output_file.into_os_string();
    let wr_azure_url = format!("'{azure_url}'");
    let az_cmd = ["copy", wr_azure_url.as_str(), output_str.to_str().unwrap()].to_vec();
    
    let bin_path = tool_path.join("azcopy").join("azcopy.exe");
    let _json_data = run_cmd(bin_path, az_cmd, log_name)?;

    Ok(output.join(file))
}

/// Get files from either an S3 or Azure link.
/// # Arguments
/// * `in_link` - A string slice of the initial input link that may point to an AWS S3 bucket or Azure Blob Storage.
async fn get_file(in_link: &String, output: &PathBuf, file: &String, tool_path: &PathBuf) -> Result<PathBuf> {
    let out_file = output.join(&file);
    println!("[?] checking {}", out_file.display());
    if out_file.exists() && metadata(&out_file).unwrap().len() > 0 {
        println!("[ ] Already downloaded {}, delete it if wanting to download again", out_file.display());
        return Ok(out_file);
    }
    if in_link.starts_with("s3") {
        get_s3_file(&in_link, &output, &file).await
    } else if in_link.starts_with("https://") {
        get_azure_file(&in_link, &output, &file, &tool_path).await
    } else {
        panic!("Unknown URL format.");
    }
}


/// List files in an S3 bucket.
/// # Arguments
/// * `s3_url` - The S3 URL to list files from.
async fn list_s3_files(s3_url: &str) -> Result<Vec<String>> {
    let bucket = s3_url.trim_start_matches("s3://");
    let region = "eu-central-1";
    let log_name = Path::new("whipped.log");
    
    // aws s3api list-objects-v2 --bucket ir-evidence-falcon --region eu-central-1 --output=json
    let args = format!("s3api list-objects-v2 --bucket {bucket} --region {region} --output=json");
    let json_data = exe_ops::run_wisker(&"aws".to_string(), &args, log_name);

    // Deserialize the JSON string to the Contents struct
    let contents: Contents = serde_json::from_str(&String::from_utf8(json_data.stdout)?)?;
    
    // Collect all Key values into a vector
    let files = contents.contents.into_iter().map(|item| item.key).collect();

    Ok(files)
}

/// List files in an Azure container.
/// # Arguments
/// * `azure_url` - The Azure URL to list files from.
async fn list_azure_files(azure_url: &str, tool_path: &PathBuf) -> Result<Vec<String>> {
    let log_name = Path::new("whipped.log");
    let wr_azure_url = format!("'{azure_url}'");
    let az_cmd = ["list", wr_azure_url.as_str()].to_vec();
    
    let bin_path = tool_path.join("azcopy").join("azcopy.exe");
    let json_data = run_cmd(bin_path, az_cmd, log_name)?;

    let mut paths = Vec::new();
    let data = String::from_utf8(json_data.stdout)?;

    // Iterate over each line.
    for line in data.lines() {
        // Split each line at the first semicolon and collect the first part.
        if let Some((path, _)) = line.split_once(";") {
            paths.push(path.trim().to_string());
        }
    }

    // Print the collected paths.
    println!("Path: {:?}", paths);

    Ok(paths)

}

fn run_cmd(bin_path: PathBuf, cmd: Vec<&str>, log_name: &Path) -> Result<std::process::Output, anyhow::Error> {
    let binary = bin_path
        .into_os_string()
        .into_string()
        .unwrap();
    let output = run_wisker(&binary, &cmd.join(" "), log_name);
    Ok(output)
    // let mut command = Command::new(binary);
    // command.args(cmd);
    // file_ops::log_msg(log_name,format!("[ ] Running {:?}", command));
    // let json_data = command.output()?;
    // if let Some(exit_code) = json_data.status.code() {
    //     if exit_code != 0 {
    //         eprintln!("Failed. Exit code: {exit_code}");
    //     }
    // } else {
    //     eprintln!("Interrupted!");
    // }
    // Ok(json_data)
}

/// List files from either an S3 or Azure link.
///
/// # Arguments
/// * `in_link` - A string slice of the initial input link that may point to an AWS S3 bucket or Azure Blob Storage.
async fn list_files(in_link: &String, tool_path: &PathBuf) -> Result<Vec<String>> {
    let files = if in_link.starts_with("s3") {
        list_s3_files(&in_link).await?
    } else if in_link.starts_with("https://") {
        list_azure_files(&in_link, &tool_path).await?
    } else {
        panic!("Unknown URL format.");
    };

    Ok(files)
}

/// Process an image, where the type could be vmdk, vhdx, vhd, e01, vdi, ex01, raw
/// First checks which drives are taken and free, then mounts the image using 
/// either osf_mount, arsenal image mounter or imount. The mounted drives are then provided
/// to start_wiskess function with a loop (TODO: to find the one with the Windows drive). If
/// no Windows folder is found, all the drives are processed.
/// # Arguments
/// * `args` - the arguments needed to pass to the start_wiskess function
fn process_image(data_source: &PathBuf, log_name: &Path, args: MainArgs, config: PathBuf, artefacts_config: PathBuf) {
    // TODO: set free_drives as the drive letters that are available and have no disk mounted
    // Loop through three mounting tools: arsenal image mounter, osf_mount, and qemu-nbd
    let aim_ds_path = format!("--filename=\"{}\"", data_source.display());
    let osf_ds_path = format!("'{}'", data_source.display());
    let tool_map = HashMap::from([
        // ("{tool_path}/aim_cli.exe", vec!["--mount", "--readonly", &aim_ds_path, "--fakesig", "--background"]),
        ("C:/Program Files/OSFMount/OSFMount.com", vec!["-a", "-t", "file", "-f", &osf_ds_path, "-v", "all"]), 
        // ("qemu-nbd", vec!["-c", "/dev/ndb1", &osf_ds_path])
    ]);
    let mut any_tool = false;
    for (tool, cmd) in tool_map {
        let bin_path_str = &tool.replace(
                "{tool_path}",
                args.tool_path.clone().into_os_string().to_str().unwrap());
        let bin_path = Path::new(bin_path_str).to_path_buf();
        // if tool exists, attempt to mount it
        if installed_binary_check(true, bin_path_str) != "" 
        || bin_path.exists() {
            any_tool = true;
            println!("[+] Running {} {}", bin_path.display(), cmd.join(" "));
            let output = run_cmd(bin_path, cmd, &log_name);
            println!("{}", String::from_utf8(output.unwrap().stdout).unwrap());
            let status = Text::new("Has it been mounted?").prompt();
        }
        // get the drive letter and loop through mounted drives
        // if drive letter not found, loop through free_drives to find any that have mounted drives
        // if successfully mounted break the loop
        break;
    }
    if !any_tool {
        println!("[-] No tool found to mount images, if on Windows please install osfmount at
            file path `C:/Program Files/OSFMount/OSFMount.com`, if on Linux install `qemu-nbd`")
    }
}


/// Process the data that has been extracted as a logical or physical acquisition (files or image). 
/// If it is an image, the process_image function will mount the image and provide the drive to wiskess.
/// If it is a collection, provide the path to the base or root for start_wiskess
/// of where the collected files are.
/// # Arguments
/// * `data_source` - the path to data that needs processing
/// * `args` - the arguments needed to pass to the start_wiskess function
/// * `config` - the path to the wiskess config, of the processes to run
/// * `artefacts_config` - the path to the artefacts config, of the paths to process
fn process_data(data_source: &PathBuf, log_name: &Path, args: MainArgs, config: PathBuf, artefacts_config: PathBuf) {
    // check if config paths exist
    let config = file_ops::check_path(config);
    let artefacts_config = file_ops::check_path(artefacts_config);

    match data_source.extension().unwrap_or_default().to_str().unwrap_or("") {
        "vmdk"|"vhdx"|"vhd"|"e01"|"vdi"|"ex01"|"raw" => {
            // if extension or file type is image, send to process_image
            process_image(data_source, &log_name, args, config, artefacts_config);
        },
        "" => {
            // if there's no extension, it is likely a collection of files, send to process_collection
            let data_source_str = data_source.clone().into_os_string().into_string().unwrap();
            wiskess::start_wiskess(args, &config, &artefacts_config, &data_source_str);
        },
        _ => {
            // else log message that downloaded file is unknown, reporting on the downloaded data and contents at three levels deep
        }
    }
}


#[tokio::main]
pub async fn whip_main(args: WhippedArgs, tool_path: &PathBuf) -> Result<()> {
    let mut data_list = Vec::new();
    
    let log_name = Path::new("whipped.log");

    if args.data_source_list == "" {
        // if no data source list provided, list the files/blobs/objects in the in_link
        data_list = list_files(&args.in_link, &tool_path).await?;
        if data_list.is_empty() {
            bail!("Error: user provided no data list and we were unable to list any files from link: {}", &args.in_link)
        }
    } else {
        // split the data source list by either commas, new lines, if needed
        data_list = split_and_trim(&args.data_source_list);
    }
    // loop through the data_list
    for data_item in data_list {
        println!("[ ] processing {data_item}");
        // set vars for `data_folder`, `process_folder`
        let out_folder = format!("{}-extracted", 
            Path::new(&data_item).file_stem().unwrap().to_os_string().into_string().unwrap()
        );
        let wiskess_folder = Path::new(&args.local_storage)
            .join(&out_folder.replace("-extracted", "-Wiskess"));
        let out_folder_path = Path::new(&args.local_storage).join(&out_folder);
        let out_folder_path_str = out_folder_path.clone().into_os_string().into_string().unwrap();
        // set the in_link based on the item of the data_list
        let in_link_url = set_link(&args.in_link, &data_item);
        // set the out_link based on the provided out_link and the process folder
        let out_link_url = set_link(&args.out_link, &out_folder);
        // check if the process folder exists in the out_link
        let is_processed = !list_files(&out_link_url, &tool_path).await?.is_empty();
        // if the process folder doens't exist in the out_link or the update flag is set
        if !is_processed || args.update {
            // download the data
            let data_file = get_file(&in_link_url, &out_folder_path, &data_item, &tool_path).await?;
            match data_file.exists() {
                true => file_ops::log_msg(log_name, "Download complete".to_string()),
                false => bail!("Unable to get file. Something wrong with downloading the file.")
            };
            // pre-process data into process_vector
            let process_vector = pre_process_data(&data_file, &log_name, &out_folder_path)?;
            println!("Pre-processed data: {:?}", process_vector);
            // process the data with a loop through the process_vector, set the process folder path
            let mut wiskess_args = config::MainArgs {
                out_path: wiskess_folder.clone().into_os_string().into_string().unwrap(),
                start_date: args.start_date.clone(),
                end_date: args.end_date.clone(),
                tool_path: tool_path.clone(),
                ioc_file: args.ioc_file.clone(),
                silent: true,
                collect: false,
                out_log: PathBuf::new(),
                multi_pb: MultiProgress::new()
            };
            for (i, data_source) in process_vector.iter().enumerate() {
                if i > 0 {
                    wiskess_args.out_path = format!("{}_{i}", wiskess_folder.display());
                }
                process_data(data_source, &log_name, wiskess_args.clone(), args.config.clone(), args.artefacts_config.clone());
            }
        }
        // debug below
        println!("Using in link: {in_link_url} to download: {data_item} to {out_folder_path_str}. Will upload to {out_link_url}");
        assert_eq!(is_processed, false);
    }

    Ok(())
        // update the data
            // if update flag is set download the process folder
                // if artefacts/collection.zip exists, expand it
                // remove any process result files that are zero size
                // remove timeline folder, ioc summary and ioc in analysis
        // upload the data
            // compress the artefacts folder to a file collection.zip
            // upload the process folder
            // remove the data source files and extracted folder
    // else log a message saying use update flag or delete the process folder from the out_link
    // log a message to state the data source has been processed
}