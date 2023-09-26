use std::fs;
use std::fs::OpenOptions;
use inquire::Confirm;
use inquire::CustomType;
use inquire::InquireError;
use std::path::Path;
use chrono::NaiveDate;

pub fn make_folders(out_path: &String) {
    fs::create_dir_all(out_path).expect("Failed to create folder");
}

pub(crate) fn file_exists(file_path: &String, silent: bool) {
    println!("[+] Opening file: {file_path}");

    let path = Path::new(&file_path);
    if path.exists() && path.is_file() {
        let mut ans: Result<bool, InquireError> = Ok(true);
        if !silent {
            ans = Confirm::new("File exists. Do you want to overwrite the file?")
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
            } 
            Ok(false) => println!("Keeping original file."),
            Err(_) => println!("No valid response to question."),
        }
    } else {
        println!("File does not exist!");
    }    
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
