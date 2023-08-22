pub mod file_ops {
    use std::fs;
    use std::fs::OpenOptions;
    use inquire::Confirm;
    use std::path::Path;

    pub fn make_folders(out_path: &String) {
        fs::create_dir_all(out_path).expect("Failed to create folder");
    }

    pub(crate) fn file_exists(file_path: &String) {
        println!("[+] Opening file: {file_path}");

        let path = Path::new(&file_path);
        if path.exists() {
            let ans = Confirm::new("File exists. Do you want to overwrite the file?")
                .with_default(false)
                .with_help_message("Overwrite the file if you want to rerun the command.")
                .prompt();

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
}