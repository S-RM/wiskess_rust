use std::{fs, io};
use std::fs::OpenOptions;
use std::io::{BufReader, BufRead};
use std::io::Write;
use core::result::Result::Ok;
use inquire::Confirm;
use inquire::CustomType;
use inquire::InquireError;

use walkdir::WalkDir;
use std::path::{Path, PathBuf};
use chrono::NaiveDate;
use glob::glob;

pub fn make_folders(out_path: &Path) {
    fs::create_dir_all(out_path).expect("Failed to create folder");
}

pub(crate) fn line_count(file_path: &Path) -> usize {
    let path = Path::new(&file_path);
    if path.exists() && path.is_file() {
        let file = fs::File::open(file_path).unwrap();
        let reader = BufReader::new(file);
        let lines_count: usize = reader.lines().count();
        return lines_count;
    } else {
        let file_path_glob = find_file_glob(&file_path.to_str().unwrap().to_string());
        if file_path_glob.len() > 0 {
            let file = fs::File::open(file_path_glob).unwrap();
            let reader = BufReader::new(file);
            let lines_count: usize = reader.lines().count();
            return lines_count;
        }
    }
    return 0;
}

///  file_exists_overwrite - will check if a file exists and ask the user if they want to
/// overwrite the file. This function returns false if it exists.
pub(crate) fn file_exists_overwrite(file_path: &Path, silent: bool) -> bool {
    let mut ret = true;
    let path_str = file_path.to_str().unwrap().to_string();
    if file_path.exists() && file_path.is_file() {
        ret = user_file_overwrite(silent, &path_str);
    } else {
        let file_path_glob = find_file_glob(&path_str);
        if file_path_glob.len() > 0 {
            ret = user_file_overwrite(silent, &file_path_glob);
        }
    }
        
    return ret;
}

fn find_file_glob(path_str: &String) -> String {
    // Get path from glob based path  
    for entry in glob(path_str).expect("Unable to read glob pattern") {
        match entry {
            Ok(path) => {
                return path.display().to_string();
            }
            Err(e) => println!("{:?}", e),
        }
    }
    return "".to_string();
}

fn user_file_overwrite(silent: bool, file_path: &String) -> bool {
    let mut ans: Result<bool, InquireError> = Ok(false);
    if !silent {
        let msg = format!("File exists: {}\nDo you want to overwrite the file?", file_path);
        ans = Confirm::new(&msg)
            .with_default(false)
            .with_help_message("Overwrite the file if you want to rerun the command.")
            .prompt();
    }

    match ans {
        Ok(true) => {
            let _ = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&file_path)
                .expect("Failed to overwrite file");
            return true;
        } 
        Ok(false) => {
            // println!("[ ] The file already exists: {}", file_path);
        }
        Err(_) => {
            println!("No valid response to question.");
        }
    }
    return false;
}

pub fn check_date(date: String, date_type: &String) -> String {
    let mut ret_date = date;
    let invalid_date = NaiveDate::parse_from_str(&ret_date, "%Y-%m-%d").is_err();
    if invalid_date {
        // TODO: Get time frame - use inquire confirm
        let msg = format!("Invalid date: {} What is the {} date?", ret_date, date_type);
        let new_date = CustomType::<NaiveDate>::new(&msg)
            .with_placeholder("yyyy-mm-dd")
            .with_parser(&|i| NaiveDate::parse_from_str(i, "%Y-%m-%d").map_err(|_e| ()))
            // .with_formatter(DEFAULT_DATE_FORMATTER)
            .with_error_message("Please type a valid date.")
            .with_help_message("Set the date with the right format.")
            .prompt()
            .expect("Unable to set date from user input");

        ret_date = format!("{}", new_date).to_string();
    }
    ret_date
}

pub fn log_msg(out_log: &Path, msg: String) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(&out_log)
        .expect("Failed to open log file");
    
    writeln!(file, "[{}] {}", chrono::Local::now().format("%Y%m%dT%H%M%S"), msg).unwrap();
}

/// check_access - get attr, try read, regex root to see if match \w:\\Windows\\
/// checks the access to the file by getting the attributes, attempting a read
/// and seeing if the path matches a regex of it being mounted. As mounted drives
/// in Windows are locked.
pub fn check_access(filepath: &String) -> Result<String, io::Error> {
    // Check access to file
    if Path::new(filepath).is_file() {
        let readable = match readable_file(filepath) {
            Ok(message) => Ok(message),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        };
        return readable;
    } else {
        let mut entries = WalkDir::new(filepath)
            .min_depth(1)
            .max_depth(1)
            .into_iter();
    
        while let Some(Ok(entry)) = entries.next() {
            let path = entry.path();
            if let true = path.is_file() {
                let readable = match readable_file(&path.display().to_string()) {
                    Ok(message) => Ok(message),
                    Err(e) => Err(io::Error::new(io::ErrorKind::Other, e))
                };
                return readable;
            }
        }
        let msg = format!("Checked access for folder: {filepath}");
        Ok(msg)
    }
}

fn readable_file(filepath: &String) -> Result<String, io::Error> {
    let metadata = fs::metadata(filepath)?;
    let permissions = metadata.permissions();
    if permissions.readonly() {
        Err(io::Error::new(io::ErrorKind::Other, format!("[!] Read-only permissions for file: {filepath}")))
    } else {
        match has_any_lines(filepath) {
            Ok(message) => Ok(message),
            Err(e) => match e.kind() {
                io::ErrorKind::InvalidData => Ok("File has invalid data, but is readable. So might be binary.".to_string()),
                io::ErrorKind::PermissionDenied => Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("[!] Permission denied to file: {filepath}. Error: {e}"))),
                _ => Err(io::Error::new(io::ErrorKind::Other, format!("[!] Empty file: {filepath}. Error: {e}")))
            }
        }
    }
}

fn has_any_lines(filepath: &String) -> Result<String, io::Error> {
    let file = OpenOptions::new()
        .read(true)
        .open(&filepath)?;
    let mut reader = BufReader::new(file);
    let mut first_line = String::new();
    match reader.read_line(&mut first_line) {
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, format!("[!] Empty file: {filepath}. Error: {e}"))),
        Ok(_) => Ok("this is a file".to_string()),
    }
}

pub fn check_path(file_path: PathBuf) -> PathBuf {
    let file_path = if !file_path.exists() && !file_path.is_file() {
        let path_str = inquire::Text::new(
            format!("Unable to find file: {}. Please check the path and enter again.", file_path.display()).as_str()
        ).prompt().unwrap();
        Path::new(&path_str).to_path_buf()
    } else {
        file_path
    };
    file_path
}
