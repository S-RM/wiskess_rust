mod configs;
mod ops;
mod art;
mod setup;

use crate::configs::config;
use crate::ops::{file_ops, exe_ops};
use crate::art::paths;
use crate::setup::init;
use serde_yaml::{self};
use std::fs::OpenOptions;
use std::env;
use clap::{Parser, ArgAction};
use chrono::Utc;
use ctrlc;

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
    // Set exit handler
    ctrlc::set_handler(move || {
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");

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
    let f: std::fs::File = OpenOptions::new()
        .read(true)
        .open(args.config)
        .expect("Unable to open config file.");
    let scrape_config: config::Config = serde_yaml::from_reader(f).expect("Could not read values.");

    // TODO: check or gracefully error when the yaml config misses keys

    // TODO: check if setup has been run, or if any binaries are missing
    init::run_setup(&main_args.tool_path);

    // check the file paths in the config exist and return a hash of the art paths
    let data_paths = paths::check_art(
        scrape_config.artefacts, 
        &args.data_source,
        args.silent
    );
    
    // Run each binary in parallel    
    exe_ops::run_commands(&scrape_config.wiskers, &main_args, &data_paths, 0, &out_log);
    // Run each binary one after the other
    exe_ops::run_commands(&scrape_config.wiskers, &main_args, &data_paths, 1, &out_log);
}