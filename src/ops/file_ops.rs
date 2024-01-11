use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use inquire::Confirm;
use inquire::CustomType;
use inquire::InquireError;
use std::path::Path;
use chrono::NaiveDate;
use glob::glob;

pub fn make_folders(out_path: &String) {
    fs::create_dir_all(out_path).expect("Failed to create folder");
}

///  file_exists - will check if a file exists and ask the user if they want to
/// overwrite the file. This function returns false if it exists.
pub(crate) fn file_exists(file_path: &String, silent: bool) -> bool {
    let mut ret = true;
    let path = Path::new(&file_path);
    if path.exists() && path.is_file() {
        ret = user_file_overwrite(silent, file_path);
    } else {
        let file_path_glob = find_file_glob(&file_path);
        if file_path_glob.len() > 0 {
            ret = user_file_overwrite(silent, &file_path_glob);
        } else {
            println!("[-] File does not exist: {}", file_path);
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

pub fn log_msg(out_log: &String, msg: String) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(&out_log)
        .expect("Failed to open log file");
    
    writeln!(file, "[{}] {}", chrono::Local::now().format("%Y%m%dT%H%M%S"), msg).unwrap();
}