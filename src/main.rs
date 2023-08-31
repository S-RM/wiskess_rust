mod configs;
mod ops;
mod art;

use crate::configs::config;
use crate::ops::file_ops;
use crate::art::paths;
use serde_yaml::{self};
use std::process::{Command, Stdio};
use std::fs::OpenOptions;
use std::io::Write;
use std::thread;
use std::env;
use clap::{Parser, ArgAction};
use chrono::Utc;
use execute::{Execute, command, shell};



/// Structure of the command line args
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Config file
    #[arg(short, long)]
    config: String,

    /// Data source
    #[arg(short, long)]
    data_source: String,

    /// Output folder
    #[arg(short, long)]
    out_path: String,

    /// Start date
    #[arg(long)]
    start_date: String,
    
    /// End date
    #[arg(long)]
    end_date: String,

    /// IOC list file
    #[arg(short, long)]
    ioc_file: String,

    /// tool path, where binaries are stored. default gets from env var set internaly
    #[arg(short, long, default_value = "")]
    tool_path: String,

    /// Silent mode, no user input
    #[arg(short, long, action = ArgAction::SetTrue)]
    silent: bool,
}

fn main() {
    // Get the args
    let args = Args::parse();

    // Set the start time
    let wiskess_start = Utc::now().format("%Y%m%dT%H%M%S").to_string();
    // TODO: Make a logger for stdout and log file messages
    println!("Starting wiskess at: {}", wiskess_start);

    // Set output directories
    let out_path = args.out_path;
    file_ops::make_folders(&out_path);
    // Set main log
    let out_log = format!("{}/wiskess_{}.log", &out_path, wiskess_start);
    file_ops::file_exists(&out_log);

    // Set tool path
    let mut tool_path = args.tool_path;
    if tool_path == "" {
        tool_path = format!("{}\\tools", env::current_dir().unwrap().display());
        println!("[ ] tool path: {}", tool_path);
    }

    // Confirm date is valid
    let start_date = file_ops::check_date(args.start_date, &"start date".to_string());
    let end_date = file_ops::check_date(args.end_date, &"end date".to_string());
    // TODO: Get iocs from file

    // Read the config
    let f = OpenOptions::new()
        .read(true)
        .open(args.config)
        .expect("Unable to open config file.");
    let scrape_config: config::Config = serde_yaml::from_reader(f).expect("Could not read values.");

    // check the file paths in the config exist and return a hash of the art paths
    let data_paths = paths::check_art(
        scrape_config.artefacts, 
        &args.data_source,
        args.silent
    );

    // Run each binary in parallel
    let mut children = vec![];

    // TODO: Check if the wisker can be run in parallel, i.e. is set share_cpu: true in config
    // TODO: limit the number of threads to the max available on device
    for wisker in scrape_config.wiskers {
        // TODO: Check the binary path exist, if not warn about installing
        // Make the output folders from the yaml config
        let folder_path = format!("{}/{}", &out_path, &wisker.outfolder);
        file_ops::make_folders(&folder_path);
        // replace the placeholders, i.e. {input}, in wisker.args with those from local variables, the yaml config, etc.
        let wisker_arg = wisker.args
            .replace("{input}", data_paths[&wisker.input].as_str())
            .replace("{outfile}", &wisker.outfile.as_str())
            .replace("{outfolder}", &folder_path)
            .replace("{start_date}", &start_date)
            .replace("{end_date}", &end_date)
            .replace("{tool_path}", &tool_path);

        let wisker_binary = wisker.binary
            .replace("{tool_path}", &tool_path);

        
        // TODO: Check if wisker_arg contains any other placeholder
        // Create thread per binary in config        
        let child = thread::spawn(move || {
            let wisker_cmd = format!("{} {}", 
                &wisker_binary, 
                &wisker_arg);
            println!("[ ] Running: {}", wisker_cmd);
            let mut command = shell(wisker_cmd);
            command.stdout(Stdio::piped());
            let output = command.execute_output().unwrap();
            // println!("{}", String::from_utf8(&output.stdout).unwrap());

        //     let output = Command::new(&wisker.binary)
        //         .arg(&wisker_arg)
        //         .output()
        //         .expect("Failed to execute command");
            
            println!("[+] Ran {} with command: {} {}", 
                &wisker.name, 
                &wisker.binary,
                &wisker_arg);
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