use crate::configs::config::{self, MainArgs, WhippedArgs};
use crate::init::scripts;
use crate::ops::exe_ops::{run_wisker, run_posh};
use crate::ops::file_ops::make_folders;
use crate::ops::{file_ops, wiskess};

use super::whip_s3;
use super::whip_az;

use anyhow::{bail, Ok};
use indicatif::MultiProgress;
use anyhow::Result;
use std::fs::metadata;
use std::path::{Path, PathBuf};
use std::env;
use walkdir::WalkDir;
use fs_extra::dir::{create, move_dir, remove, CopyOptions};
use fs_extra::file::{move_file, CopyOptions as FileCopyOptions};
// use inquire::{Confirm, Text};

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
    file_ops::log_msg(log_name, format!(
        "Downloaded file: {} with size: {} and type: {:?}.", 
        file_path.display(),
        data_meta.len(),
        data_meta.file_type(),
    ));

    
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
    let data_str = format!("'{}'", data_file.clone().display());
    let extract_flag = format!("-o'{}'", data_folder.display());
    let unzip_cmd = ["x", "-aos", data_str.as_str(), extract_flag.as_str()].to_vec();
                        
    let bin_path = Path::new("7z.exe").to_path_buf();
    let _json_data = run_cmd(bin_path, unzip_cmd, log_name, true).unwrap();
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
        if data_file.is_file() {
            if let Some(ext) = data_file.extension() {
                match ext.to_str().unwrap_or("") {
                    "vmdk"|"vhdx"|"vhd"|"e01"|"vdi"|"ex01"|"raw" => {
                        process_vector.push(data_file.to_path_buf())
                    },
                    _ => ()
                }
            }
        } else if data_file.is_dir() {
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
                            .filter(|entry| {
                                entry.path().components().any(|component|{
                                    component.as_os_str().to_str().map_or(false, |comp_str| {
                                        match comp_str.to_uppercase().as_str() {
                                            "C%3A"|"%5C%5C.%5CC%3A" => true,
                                            &_ => false
                                        }
                                    })
                                })
                            })
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
        }
    });
}

/// run_cmd runs a binary with a command, in windows it uses powershell, 
/// in linux it uses the default shell of the operating system.
/// # Arguments
/// * `bin_path` - the path to the binary to run
/// * `cmd` - a vector of commands to run, these are joined with spaces before running
pub fn run_cmd(bin_path: PathBuf, cmd: Vec<&str>, log_name: &Path, show_err: bool) -> Result<std::process::Output, anyhow::Error> {
    let binary = bin_path
        .into_os_string()
        .into_string()
        .unwrap();

    let cmd = cmd.join(" ");
    
    let output = match env::consts::OS {
        "windows" => run_posh("-c", &format!("& {binary} {cmd}"), log_name, &String::new(), show_err),
        "linux" => run_wisker(&binary, &cmd, log_name),
        &_ => todo!()
    };
    Ok(output)
}

/// Get files from either an S3 or Azure link. First checks if the file name exists in the path
/// of the output destination or its parent. Then passes the vars to a function that downloads 
/// from either s3 or azure, based off the start of the in_link, i.e. `s3` or `https://`
/// # Arguments
/// * `in_link` - A string slice of the initial input link that may point to an AWS S3 bucket or Azure Blob Storage.
/// * `output` - The path to where the data will be downloaded to
/// * `file` - the name of the file to download
async fn get_file(in_link: &String, output: &PathBuf, file: &String, recurse: bool, tool_path: &PathBuf, log_name: &Path) -> Result<PathBuf> {
    let out_file = output.join(&file);
    let out_file_parent = output.parent().unwrap().join(&file);
    for data_path in [out_file.clone(), out_file_parent] {
        if data_path.exists() && metadata(&data_path).unwrap().len() > 0 {
            file_ops::log_msg(
                log_name, 
                format!("[ ] Already downloaded {}, delete it if wanting to download again", data_path.display())
            );
            return Ok(data_path);
        }
    }

    // if file is an item in a folder, make the folder
    if file.contains("/") || file.contains("\\") {
        let folder_path = out_file.parent().unwrap();
        make_folders(folder_path);
        println!("[ ] File has folder in path, making folder: {}", folder_path.display());
    }
    
    println!("[ ] Downloading: {}", file);
    if in_link.starts_with("s3") {
        whip_s3::get_s3_file(&in_link, &output, &file, recurse, log_name).await
    } else if in_link.starts_with("https://") {
        whip_az::get_azure_file(&in_link, &output, &file, recurse, &tool_path, log_name).await
    } else {
        println!("[!] Unknown URL format. {in_link}");
        Ok(PathBuf::new())
    }
}

/// Upload files to either S3 or Azure storage
/// # Arguments
/// * `in_folder` - the folder where the processed is stored locally
/// * `out_link` the URL to the S3 bucket or Azure Blob container
async fn upload_file(in_folder: &PathBuf, out_link: &String, tool_path: &Path, log_name: &Path) {
    let art_folder = in_folder.join("Artefacts");
    if art_folder.exists() && metadata(&art_folder).unwrap().len() > 0 {
        // compress the artefacts folder to a file collection.zip
        let zip_path = art_folder.join("collection.zip");
        let zip_cmd = ["a", zip_path.to_str().unwrap(), art_folder.to_str().unwrap()].to_vec();
                            
        let bin_path = Path::new("7z.exe").to_path_buf();
        let _json_data = run_cmd(bin_path, zip_cmd, log_name, true).unwrap();
    }
    // upload the process folder
    println!("[ ] Uploading: {}", in_folder.display());
    if out_link.starts_with("s3") {
        whip_s3::put_s3_file(&in_folder, &out_link, log_name).await
    } else if out_link.starts_with("https://") {
        whip_az::put_azure_file(&in_folder, &out_link, &tool_path, log_name).await
    } else {
        println!("[!] Unknown URL format. {out_link}");
        panic!("Unknown URL format.");
    }
}

/// List files from either an S3 or Azure link.
///
/// # Arguments
/// * `in_link` - A string slice of the initial input link that may point to an AWS S3 bucket or Azure Blob Storage.
async fn list_files(in_link: &String, tool_path: &PathBuf, log_name: &Path, show_err: bool) -> Result<Vec<String>> {
    let files = if in_link.starts_with("s3") {
        whip_s3::list_s3_files(&in_link, log_name, show_err).await?
    } else if in_link.starts_with("https://") {
        whip_az::list_azure_files(&in_link, &tool_path, log_name, show_err).await?
    } else {
        println!("[!] Unknown URL format.");
        vec!["".to_string()]
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
fn process_image(data_source: &PathBuf, _log_name: &Path, args: MainArgs, config: PathBuf, _artefacts_config: PathBuf) {
    // // ensure the paths has the slashes in the right way
    let data_source_ok = data_source.canonicalize().unwrap();

    // TEMP: This is  temporary workaround until the code commented below is operational
    // put the args into a whipped structure
    let whip_args = config::WhippedImageArgs {
        tool_path: args.tool_path,
        config,
        start_date: args.start_date,
        end_date: args.end_date,
        ioc_file: args.ioc_file,
        update: false,
        keep_evidence: true,
        image_path: data_source_ok.to_owned(),
        wiskess_folder: args.out_path
    };

    println!("[ ] Running whipped with args: image path: {}, wiskess folder: {}", whip_args.image_path.display(), &whip_args.wiskess_folder);
    scripts::run_whipped_image(whip_args);

    return;

    // TEMP: end

    // // TODO: set free_drives as the drive letters that are available and have no disk mounted
    // // Loop through three mounting tools: arsenal image mounter, osf_mount, and qemu-nbd
    // let aim_ds_path = format!("--filename=\"{}\"", data_source_ok.display());
    // let osf_ds_path = format!("'{}'", data_source_ok.display());
    // // TODO: in setup create a symlink for osfmount: New-Item -ItemType SymbolicLink -Path .\tools\ -name osfmount.lnk -Target 'C:\Program Files\OSFMount\OSFMount.com'
    // let tool_map = HashMap::from([
    //     ("{tool_path}\\aim_cli.exe", vec!["--mount", "--readonly", &aim_ds_path, "--fakesig", "--background"]),
    //     ("{tool_path}\\osfmount.lnk", vec!["-a", "-t", "file", "-f", &osf_ds_path, "-v", "all"]), 
    //     // ("qemu-nbd", vec!["-c", "/dev/ndb1", &osf_ds_path])
    // ]);
    // let mut any_tool = false;
    // for (tool, cmd) in tool_map {
    //     let bin_path_str = tool.replace(
    //             "{tool_path}",
    //             args.tool_path.clone().into_os_string().to_str().unwrap());
    //     let bin_path = PathBuf::from(&bin_path_str);
    //     // if tool exists, attempt to mount it
    //     println!("[?] Trying to run  {} {}", bin_path.display(), cmd.join(" "));
    //     if installed_binary_check(true, &bin_path_str) == "" {
    //         // && bin_path.exists() {
    //         any_tool = true;
    //         println!("[+] Running {} {}", bin_path.display(), cmd.join(" "));
    //         let output = run_wisker(&bin_path.into_os_string().into_string().unwrap(), &cmd.join(" "), &log_name);
    //         // let stdout = output.as_ref().unwrap().clone().stdout;
    //         // let stderr = output.unwrap().stderr;
    //         println!("{}", String::from_utf8(output.stdout).unwrap());
    //         println!("{}", String::from_utf8(output.stderr).unwrap());
    //         // let status = Confirm::new("Has it been mounted?").with_default(false).prompt();
    //         // if successfully mounted break the loop
    //         // if status. {
    //         //     Ok(true) => break,
    //         //     &_ => continue,
    //         // }
    //         break;
    //     }
    //     // get the drive letter and loop through mounted drives
    //     // if drive letter not found, loop through free_drives to find any that have mounted drives
    // }
    // if !any_tool {
    //     println!("[-] No tool found to mount images, if on Windows please install osfmount at
    //         file path `C:/Program Files/OSFMount/OSFMount.com`, if on Linux install `qemu-nbd`")
    // }
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

/// update_processed_data downloads the process folder, expands any collected files, 
/// then removes any empty or files that need reprocessing after any change to the results
async fn update_processed_data(out_link: &String, process_folder: &Path, tool_path: &PathBuf, log_name: &Path) {
    // download wiskess folder
    let process_folder_name = process_folder.file_name().unwrap().to_str().unwrap().to_string();
    let output_path =  process_folder.parent().unwrap().to_path_buf();
    file_ops::log_msg(log_name, format!("[ ] Updating data... link: {} at path: {}",out_link, output_path.display()));
    _ = get_file(out_link, &output_path, &process_folder_name, true, tool_path, log_name).await;
    // if artefacts/collection.zip exists, expand it
    let zip_path = output_path.join("Artefacts").join("collection.zip");
    if zip_path.exists() {
        let zip_out_cmd = format!("-o{}", process_folder.display());
        let zip_cmd = ["x", zip_path.to_str().unwrap(), &zip_out_cmd].to_vec();
        let bin_path = Path::new("7z.exe").to_path_buf();
        _ = run_cmd(bin_path, zip_cmd, log_name, true);
    }
    // remove any process result files that are zero size
    // remove timeline folder, ioc summary and ioc in analysis
}


#[tokio::main]
pub async fn whip_main(args: WhippedArgs, tool_path: &PathBuf) -> Result<()> {    
    let log_name = Path::new("whipped_main.log");

    let data_list = if args.data_source_list == "" {
        // if no data source list provided, list the files/blobs/objects in the in_link
        let data_list = list_files(&args.in_link, &tool_path, log_name, true).await?;
        if data_list.is_empty() {
            bail!("Error: user provided no data list and we were unable to list any files from link: {}", &args.in_link)
        }
        data_list
    } else {
        // split the data source list by either commas, new lines, if needed
        split_and_trim(&args.data_source_list)
    };
    // loop through the data_list
    for data_item in data_list {
        println!("[ ] processing {data_item}");
        file_ops::log_msg(log_name, format!("[ ] processing {data_item}"));
        // set vars for `data_folder`, `process_folder`
        let out_folder = format!("{}-extracted", 
            Path::new(&data_item).file_stem().unwrap().to_os_string().into_string().unwrap()
        );
        let wiskess_folder = Path::new(&args.local_storage)
            .join(&out_folder.replace("-extracted", "-Wiskess"));
        let wiskess_folder_name = wiskess_folder.file_name().unwrap().to_str().unwrap();
        let out_folder_path = Path::new(&args.local_storage).join(&out_folder);
        // set the in_link based on the item of the data_list
        let in_link_url = set_link(&args.in_link, &data_item);
        // set the out_link based on the provided out_link and the process folder
        let out_link_url = set_link(&args.out_link, &wiskess_folder_name);
        // check if the process folder exists in the out_link
        let is_processed = !list_files(&out_link_url, &tool_path, log_name, false).await?.is_empty();
        // if the process folder doens't exist in the out_link or the update flag is set
        if !is_processed || args.update {
            // download the data
            let data_file = get_file(&in_link_url, &out_folder_path, &data_item, false, &tool_path, log_name).await?;
            match data_file.exists() {
                true => file_ops::log_msg(log_name, "Download complete".to_string()),
                false => {
                    let msg = format!("[!] Unable to get file. Something wrong with downloading the file: {data_item}.");
                    println!("{msg}");
                    file_ops::log_msg(log_name, msg);
                }
            };
            // pre-process data into process_vector
            let process_vector = pre_process_data(&data_file, &log_name, &out_folder_path)?;
            file_ops::log_msg(log_name, format!("Pre-processed data: {:?}", process_vector));
            // update the data
            if args.update {
                println!("[ ] Updating the processed data...");
                update_processed_data(
                    &out_link_url,
                    &wiskess_folder,
                    tool_path,
                    log_name
                ).await;
            }
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
                // upload the data
                upload_file(&wiskess_folder, &args.out_link, &tool_path, log_name).await;
            }
        } else {
            file_ops::log_msg(
                log_name, 
                format!("Already processed {data_item}. If wanting to process again either delete the folder here and online or use the `--update` flag"));
        }
        // remove the data source files and extracted folder
        if !args.keep_evidence {
            println!("[ ] Removing {}", out_folder_path.display());
            let _ = remove(out_folder_path);
        }

        // debug below
        // println!("Using in link: {in_link_url} to download: {data_item} to {out_folder_path_str}. Will upload to {out_link_url}");
        // assert_eq!(is_processed, false);
    }

    Ok(())
}
