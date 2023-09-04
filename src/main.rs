mod configs;
mod ops;
mod art;

use crate::configs::config;
use crate::ops::{file_ops, exe_ops};
use crate::art::paths;
use serde_yaml::{self};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::fs::OpenOptions;
use std::io::Write;
use std::thread;
use std::env;
use clap::{Parser, ArgAction};
use chrono::Utc;
use execute::{Execute, command, shell};
use rayon::prelude::*; 


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
    file_ops::file_exists(&out_log, args.silent);

    // Set tool path
    let mut tool_path = args.tool_path;
    if tool_path == "" {
        tool_path = format!("{}\\tools", env::current_dir().unwrap().display());
        println!("[ ] tool path: {}", tool_path);
    }

    // Confirm date is valid
    let start_date = file_ops::check_date(args.start_date, &"start date".to_string());
    let end_date = file_ops::check_date(args.end_date, &"end date".to_string());

    // let mut main_args = HashMap::new();
    let main_args = config::MainArgs {
        out_path: out_path,
        start_date: start_date,
        end_date: end_date,
        tool_path: tool_path,
        ioc_file: args.ioc_file,
        silent: args.silent
    };

    // Read the config
    let f = OpenOptions::new()
        .read(true)
        .open(args.config)
        .expect("Unable to open config file.");
    let scrape_config: config::Config = serde_yaml::from_reader(f).expect("Could not read values.");

    // TODO: check or gracefully error when the yaml config misses keys
    // TODO: Check the binary path exist, if not warn about installing

    // check the file paths in the config exist and return a hash of the art paths
    let data_paths = paths::check_art(
        scrape_config.artefacts, 
        &args.data_source,
        args.silent
    );
    
    // Run each binary in parallel
    let multi_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(0)
        .build()
        .unwrap();
    
    let single_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();

    // let wiskers = scrape_config.wiskers;
    // let multi_wiskers = &wiskers.clone();
    // let single_wiskers = wiskers.clone();
    

    // let multi_wiskers: Vec<config::Wiskers> = wiskers
    //     .into_iter()
    //     .filter(|w| w.para == true)
    //     .collect();

    // let single_wiskers: Vec<config::Wiskers> = scrape_config.clone().wiskers
    //     .into_iter()
    //     .filter(|w| w.para == false)
    //     .collect();

    for wisker in scrape_config.wiskers {
        
        let tx = tx.clone();
        let main_args_c = main_args.clone();
        let data_paths_c = data_paths.clone();

        // Create thread per binary in config        
        // let child = thread::spawn(move || {
        let mut pool = &multi_pool;            
        if !wisker.para {
            // wisker config set to non-parallel, may need those ran in parallel to finish
            // TODO: collect all the wiskers that are single and run in a separate loop
            pool = &single_pool;
        }
        pool.spawn(move || {
        
            let (wisker_arg, wisker_binary) = exe_ops::load_wisker(
                main_args_c, 
                &wisker, 
                data_paths_c);
            
            let output = exe_ops::run_wisker(&wisker_binary, &wisker_arg);
            
            println!("[+] Ran {} with command: {} {}", 
                &wisker.name, 
                &wisker_binary,
                &wisker_arg);
            // output.stdout
            tx.send(output.stdout).unwrap();
        });

        // children.push(child);
    }
    drop(tx);
    let children: Vec<_> = rx.into_iter().collect();

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(&out_log)
        .expect("Failed to open log file");
        
    // for child in children {
    //     let output = child.join().unwrap();
        // file.write_all(&output).expect("Failed to write to log file");
    // }
}