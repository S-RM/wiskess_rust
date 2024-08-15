/*
Get Files - Rust program to get files from a mounted drive
Requirements: Run as administrator
This takes two arguments: a drive mount and the config file that contains the paths to get
Example:
get-files.exe \\.\e: ./get-files.yaml
*/

use super::sector_reader;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, Write};
use std::path::{Path};
use anyhow::{bail, Context, Result};
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::structured_values::{NtfsFileName, NtfsFileNamespace};
use ntfs::{Ntfs, NtfsFile, NtfsReadSeek};
use regex::{RegexBuilder};
use sector_reader::SectorReader;

struct CommandInfo<'n, T>
where
    T: Read + Seek,
{
    current_directory: Vec<NtfsFile<'n>>,
    current_directory_string: String,
    fs: T,
    ntfs: &'n Ntfs,
}

/// get_file - opens a handle to the filesystem in read-only mode, then passes the filepath to copy to get()
/// 
/// Args:
/// * `filesystem` - the drive t copy from; in the format \\\\.\\d:
/// * `filepath` - the file path to copy from, i.e. Windows\System32\config\SYSTEM
/// * `dest_path` - the folder path to where to copy to, i.e. c:\wiskess\artefacts
pub fn get_file(filesystem: &String, filepath: &String, dest_path: &str, is_file: bool) -> Result<()> {
    let f = File::open(&filesystem)?;
    let sr = SectorReader::new(f, 4096)?;
    let mut fs = BufReader::new(sr);
    let mut ntfs = Ntfs::new(&mut fs)?;
    ntfs.read_upcase_table(&mut fs)?;
    let current_directory = vec![ntfs.root_directory(&mut fs)?];

    let mut info = CommandInfo {
        current_directory,
        current_directory_string: String::new(),
        fs,
        ntfs: &ntfs,
    };

    // println!("Opened \"{}\" read-only.", filesystem);

    // get the parent paths of filepath into directories
    let file_ancestors = Path::new(filepath).ancestors();
    // in a loop, use cd to move to the directory
    let mut dirs = vec![];
    for dir in file_ancestors {
        dirs.push(dir);
    }
    for dir in dirs.iter().rev() {
        if dir.parent() == None {
            continue;
        }
        let parent_path = dir.file_name().unwrap().to_str().unwrap().to_string();
        let result = cd(&parent_path, &mut info);
        
        if let Err(e) = result {
            eprintln!("Error: {e:?}");
        }
    }

    // get the file
    let filepath_path = Path::new(filepath); 
    let filename = filepath_path.file_name();
    let dest_parent = Path::new(dest_path).join(filepath);
    // if path to copy is a file, dest_p is the parent of the path, otherwise is the same
    // if copying a file, use get() once, else if a dir, get vector of file and loop using get()
    if is_file {
        let dest_p = dest_parent.parent().unwrap().as_os_str().to_str().unwrap();
        get(
            filename.unwrap().to_os_string().to_str().unwrap(), 
            &mut info, 
            dest_p
        )?
    } else {
        let dest_p = dest_parent.as_os_str().to_str().unwrap();
        let file_list = get_file_list(&mut info, dest_p);
        let re = RegexBuilder::new(r"\.(?:evtx|LOG1|LOG2|regtrans-ms|blf|LOG|mdb|log)$")
            .case_insensitive(true)
            .build()
            .unwrap();
        let mut num_matches: u32 = 0;
        for file in file_list {
            if re.is_match(&file) {
                num_matches += 1;
                get(
                    &file, 
                    &mut info, 
                    dest_p
                )?
            }
        };
        if num_matches <= 0 {
            bail!("[!] no match")
        }
    };

    Ok(())
}

fn get_file_list<T>(info: &mut CommandInfo<T>, _dest_p: &str) -> Vec<String>
where
    T: Read + Seek,
{
    let index = info
        .current_directory
        .last()
        .unwrap()
        .directory_index(&mut info.fs).unwrap();
    let mut iter = index.entries();
    let mut file_list = vec![];
    while let Some(entry) = iter.next(&mut info.fs) {
        let entry = entry.unwrap();
        let file_name = entry
            .key()
            .expect("key must exist for a found Index Entry").unwrap();
        file_list.push(file_name.name().to_string().unwrap().to_string());
    };
    file_list
}

/// get - get the file from the filesystem specified in info
fn get<T>(arg: &str, info: &mut CommandInfo<T>, dest_path: &str) -> Result<()>
where
    T: Read + Seek,
{
    // Extract any specific $DATA stream name from the file.
    let (file_name, data_stream_name) = match arg.find(':') {
        Some(mid) => (&arg[..mid], &arg[mid + 1..]),
        None => (arg, ""),
    };

    // Compose the output file name and try to create it.
    // It must not yet exist, as we don't want to accidentally overwrite things.
    let output_file_name = if data_stream_name.is_empty() {
        Path::new(dest_path).join(file_name).into_os_string().into_string().unwrap()
    } else {
        let new_name = format!("{file_name}_{data_stream_name}");
        Path::new(dest_path).join(new_name).into_os_string().into_string().unwrap()
    };
    let mut output_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_file_name)
        .with_context(|| format!("Tried to open \"{output_file_name}\" for writing"))?;

    // Open the desired file and find the $DATA attribute we are looking for.
    let file = parse_file_arg(file_name, info)?;
    let data_item = match file.data(&mut info.fs, data_stream_name) {
        Some(data_item) => data_item,
        None => {
            println!("The file does not have a \"{data_stream_name}\" $DATA attribute.");
            return Ok(());
        }
    };
    let data_item = data_item?;
    let data_attribute = data_item.to_attribute()?;
    let mut data_value = data_attribute.value(&mut info.fs)?;

    println!(
        "Saving {} bytes of data in \"{}\"...",
        data_value.len(),
        output_file_name
    );
    let mut buf = [0u8; 4096];

    loop {
        let bytes_read = data_value.read(&mut info.fs, &mut buf)?;
        if bytes_read == 0 {
            break;
        }

        output_file.write_all(&buf[..bytes_read])?;
    }

    Ok(())
}

/// parse_file_arg - parse the file arg into an NTFS entry number for getting
#[allow(clippy::from_str_radix_10)]
fn parse_file_arg<'n, T>(arg: &str, info: &mut CommandInfo<'n, T>) -> Result<NtfsFile<'n>>
where
    T: Read + Seek,
{
    if arg.is_empty() {
        bail!("Missing argument!");
    }

    if let Some(record_number_arg) = arg.strip_prefix('/') {
        let record_number = match record_number_arg.strip_prefix("0x") {
            Some(hex_record_number_arg) => u64::from_str_radix(hex_record_number_arg, 16),
            None => u64::from_str_radix(record_number_arg, 10),
        };

        if let Ok(record_number) = record_number {
            let file = info.ntfs.file(&mut info.fs, record_number)?;
            Ok(file)
        } else {
            bail!(
                "Cannot parse record number argument \"{}\"",
                record_number_arg
            )
        }
    } else {
        let index = info
            .current_directory
            .last()
            .unwrap()
            .directory_index(&mut info.fs)?;
        let mut finder = index.finder();

        if let Some(entry) = NtfsFileNameIndex::find(&mut finder, info.ntfs, &mut info.fs, arg) {
            let entry = entry?;
            let file = entry.to_file(info.ntfs, &mut info.fs)?;
            Ok(file)
        } else {
            bail!("No such file or directory \"{}\".", arg)
        }
    }
}

fn best_file_name<T>(
    info: &mut CommandInfo<T>,
    file: &NtfsFile,
    parent_record_number: u64,
) -> Result<NtfsFileName>
where
    T: Read + Seek,
{
    // Try to find a long filename (Win32) first.
    // If we don't find one, the file may only have a single short name (Win32AndDos).
    // If we don't find one either, go with any namespace. It may still be a Dos or Posix name then.
    let priority = [
        Some(NtfsFileNamespace::Win32),
        Some(NtfsFileNamespace::Win32AndDos),
        None,
    ];

    for match_namespace in priority {
        if let Some(file_name) =
            file.name(&mut info.fs, match_namespace, Some(parent_record_number))
        {
            let file_name = file_name?;
            return Ok(file_name);
        }
    }

    bail!(
        "Found no FileName attribute for File Record {:#x}",
        file.file_record_number()
    )
}

fn cd<T>(arg: &String, info: &mut CommandInfo<T>) -> Result<()>
where
    T: Read + Seek,
{
    if arg.is_empty() {
        return Ok(());
    }

    if arg == ".." {
        if info.current_directory_string.is_empty() {
            return Ok(());
        }

        info.current_directory.pop();

        let new_len = info.current_directory_string.rfind('\\').unwrap_or(0);
        info.current_directory_string.truncate(new_len);
    } else {
        let index = info
            .current_directory
            .last()
            .unwrap()
            .directory_index(&mut info.fs)?;
        let mut finder = index.finder();
        let maybe_entry = NtfsFileNameIndex::find(&mut finder, info.ntfs, &mut info.fs, arg);

        if maybe_entry.is_none() {
            // println!("Cannot find subdirectory \"{arg}\".");
            return Ok(());
        }

        let entry = maybe_entry.unwrap()?;
        let file_name = entry
            .key()
            .expect("key must exist for a found Index Entry")?;

        if !file_name.is_directory() {
            // println!("\"{arg}\" is not a directory.");
            return Ok(());
        }

        let file = entry.to_file(info.ntfs, &mut info.fs)?;
        let file_name = best_file_name(
            info,
            &file,
            info.current_directory.last().unwrap().file_record_number(),
        )?;
        if !info.current_directory_string.is_empty() {
            info.current_directory_string += "\\";
        }
        info.current_directory_string += &file_name.name().to_string_lossy();

        info.current_directory.push(file);
    }

    Ok(())
}