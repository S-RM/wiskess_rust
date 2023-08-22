mod configs;
mod ops;

use crate::configs::config;
use crate::ops::file_ops;
use serde_yaml::{self};
use std::process::{Command, Output};
use std::time::Duration;
use std::fs::OpenOptions;
use std::io::Write;
use std::thread;
use inquire::Confirm;
use clap::Parser;
use std::path::Path;
use chrono::Utc;

/// Structure of the command line args
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Config file
    #[arg(short, long)]
    config: String,

    /// Output folder
    #[arg(short, long)]
    out_path: String,
}

fn main() {
    // Get the args
    let args = Args::parse();

    // Set the start time
    let start_time = Utc::now().format("%Y%m%dT%H%M%S").to_string();
    // TODO: Make a logger for stdout and log file messages
    println!("Starting wiskess at: {}", start_time);

    // Set output directories
    let out_path = args.out_path;
    file_ops::make_folders(&out_path);
    // Set main log
    let out_log = format!("{}/wiskess_{}.log", &out_path, start_time);
    file_ops::file_exists(&out_log);

    // TODO: Get time frame
    // TODO: Get iocs from file

    // Read the config
    let f = OpenOptions::new()
        .read(true)
        .open(args.config)
        .expect("Unable to open config file.");
    let scrape_config: config::Config = serde_yaml::from_reader(f).expect("Could not read values.");

    // Run each binary in parallel
    let mut children = vec![];

    // TODO: Check if the wisker can be run in parallel, i.e. is set share_cpu: true in config
    // TODO: limit the number of threads to the max available on device
    for wisker in scrape_config.wiskers {
        // TODO: Check the binary path exist, if not warn about installing
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
        .open(&out_log)
        .expect("Failed to open log file");
        
    for child in children {
        let output = child.join().unwrap();
        file.write_all(&output).expect("Failed to write to log file");
    }
}