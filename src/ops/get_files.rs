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
use anyhow::{bail, Context, Result};
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::{Ntfs, NtfsFile, NtfsReadSeek};
use sector_reader::SectorReader;

struct CommandInfo<'n, T>
where
    T: Read + Seek,
{
    current_directory: Vec<NtfsFile<'n>>,
    fs: T,
    ntfs: &'n Ntfs,
}

/// get_file - opens a handle to the filesystem in read-only mode, then passes the filepath to copy to get()
pub fn get_file(filesystem: &String, filepath: &String, dest_path: &str) -> Result<()> {
    let f = File::open(&filesystem)?;
    let sr = SectorReader::new(f, 4096)?;
    let mut fs = BufReader::new(sr);
    let mut ntfs = Ntfs::new(&mut fs)?;
    ntfs.read_upcase_table(&mut fs)?;
    let current_directory = vec![ntfs.root_directory(&mut fs)?];

    let mut info = CommandInfo {
        current_directory,
        fs,
        ntfs: &ntfs,
    };

    println!("Opened \"{}\" read-only.", filesystem);

    let result = get(filepath, &mut info, dest_path);
    
    if let Err(e) = result {
        eprintln!("Error: {e:?}");
    }

    Ok(())
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
        format!("{}/{}", dest_path, file_name.to_string())
    } else {
        format!("{file_name}_{data_stream_name}")
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
