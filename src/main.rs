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
use clap::{Parser, ArgAction, Subcommand, Command};
use chrono::Utc;
use ctrlc;

/// Structure of the command line args
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// tool path, where binaries are stored. default gets from env var set internaly
    #[arg(short, long, default_value = "")]
    tool_path: String,
    /// Silent mode, no user input
    #[arg(short, long, action = ArgAction::SetTrue)]
    silent: bool,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// setup the wiskess dependencies
    Setup { },
    /// whipped pipeline process commands
    Whipped {
        /// config file of the artefact file paths and binaries to run as processors
        #[arg(short, long)]
        config: String,
        /// file path to the data source; either mounted or the root folder
        #[arg(short, long)]
        data_source: String,
        /// output folder that will be the destination of the processed results
        #[arg(short, long)]
        out_path: String,
        /// Start date - typically the earliest time of the incident, or a few days before
        #[arg(long)]
        start_date: String,
        /// End date - the current date or end of the incident timeframe
        #[arg(long)]
        end_date: String,
        /// IOC list file
        #[arg(short, long)]
        ioc_file: String,
    },
    /// report generation of the processed results
    Report {
    }
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
    
    // Set tool path
    let mut tool_path = args.tool_path;
    if tool_path == "" {
        tool_path = format!("{}\\tools", env::current_dir().unwrap().display());
        println!("[ ] tool path: {}", tool_path);
    }

    match args.command {
        Commands::Setup {  } => {
            // TODO: check if setup has been run, or if any binaries are missing
            init::run_setup(&tool_path);
        },
        Commands::Whipped { 
            config, 
            data_source, 
            out_path, 
            start_date, 
            end_date, 
            ioc_file 
        } => {
            // Set output directories
            let out_path = out_path;
            file_ops::make_folders(&out_path);
            // Set main log
            let out_log = format!("{}/wiskess_{}.log", &out_path, wiskess_start);
            file_ops::file_exists(&out_log, args.silent);
            
            // Confirm date is valid
            let start_date = file_ops::check_date(start_date, &"start date".to_string());
            let end_date = file_ops::check_date(end_date, &"end date".to_string());
            
            let main_args = config::MainArgs {
                out_path: out_path,
                start_date: start_date,
                end_date: end_date,
                tool_path: tool_path,
                ioc_file: ioc_file,
                silent: args.silent
            };
        
            // Read the config
            let f: std::fs::File = OpenOptions::new()
                .read(true)
                .open(config)
                .expect("Unable to open config file.");
            let scrape_config: config::Config = serde_yaml::from_reader(f).expect("Could not read values.");
        
            // TODO: check or gracefully error when the yaml config misses keys
        
            // check the file paths in the config exist and return a hash of the art paths
            let data_paths = paths::check_art(
                scrape_config.artefacts, 
                &data_source,
                args.silent
            );
            
            // Run each binary in parallel    
            exe_ops::run_commands(&scrape_config.wiskers, &main_args, &data_paths, 0, &out_log);
            // Run each binary one after the other
            exe_ops::run_commands(&scrape_config.wiskers, &main_args, &data_paths, 1, &out_log);
        },
        Commands::Report {  } => todo!(),
    }

}