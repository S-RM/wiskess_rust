mod configs;

use crate::configs::config;
use serde_yaml::{self};
use std::process::{Command, Output};
use std::time::Duration;
use std::fs::OpenOptions;
use std::io::Write;
use std::thread;
use inquire::Confirm;
use std::fs;
use clap::Parser;
use std::path::Path;

/// Structure of the command line args
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Config file
    #[arg(short, long)]
    config: String,

    /// Output file
    #[arg(short, long)]
    logfile: String,
}

fn file_exists(file_path: &String) {
    println!("[+] Opening file: {file_path}");
    // match fs::metadata(file_path) {
    //     Ok(_) => exists = true,
    //     Err(_) => exists = false,
    // }

    let path = Path::new(&file_path);
    if path.exists() {
        let ans = Confirm::new("File exists. Do you want to overwrite the file?")
            .with_default(false)
            .with_help_message("Overwrite the file if you want to rerun the command.")
            .prompt();

        match ans {
            Ok(true) => {
                println!("That's awesome!");
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

fn main() {
    // Get the args
    let args = Args::parse();

    // Read the config
    let f = std::fs::File::open(args.config).expect("Could not open file.");
    let scrape_config: config::Config = serde_yaml::from_reader(f).expect("Could not read values.");
    println!("{:?}", scrape_config);

    // Set log
    let log_file = args.logfile;
    file_exists(&log_file);

    // let mut commands = Vec::new();
    let mut children = vec![];

    for wisker in scrape_config.wiskers {
        // Create thread per binary in config        
        let child = thread::spawn(move || {
            let output = Command::new(&wisker.binary)
                .arg(&wisker.args)
                .output()
                .expect("Failed to execute command");
            
            println!("[+] Ran {}", &wisker.name);
            output.stdout
        });

        
        children.push(child);
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(&log_file)
        .expect("Failed to open log file");
        
    for child in children {
        let output = child.join().unwrap();
        file.write_all(&output).expect("Failed to write to 'output.txt'");
    }
}