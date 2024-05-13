mod configs;
mod ops;
mod art;
mod init;

use crate::configs::config;
use crate::ops::{file_ops, exe_ops};
use crate::art::paths;
use crate::init::{scripts, setup};
use ops::valid_ops;
use serde_yaml::{self};

use std::fs::OpenOptions;
use std::{path::Path,env};
use clap::{Parser, ArgAction, Subcommand};
use chrono::Utc;
use ctrlc;
use indicatif::MultiProgress;
use figrs::{Figlet, FigletOptions};
use console::style;
use rand::seq::SliceRandom;

/// Wiskess Help - Command line arguments
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
    Setup {
        /// Personal github token to access public repos, if unsure how to setup see https://github.blog/2022-10-18-introducing-fine-grained-personal-access-tokens-for-github/
        #[arg(short, long)]
        github_token: String,
        /// Print additional info to the stdout
        #[arg(short, long)]
        verbose: bool
    },
    /// whipped pipeline process commands
    Whipped {
        /// config file of the binaries to run as processors
        #[arg(short, long, default_value = "config/main_win.yaml")]
        config: String,
        /// config file of the artefact file paths
        #[arg(short, long, default_value = "config/artefacts.yaml")]
        artefacts_config: String,
        /// file path to the data source; either mounted or the root folder
        #[arg(short, long)]
        data_source_list: String,
        /// file path where the data is temporarily downloaded to and Wiskess output is stored locally
        #[arg(short, long)]
        local_storage: String,
        /// Start date - typically the earliest time of the incident, or a few days before
        #[arg(long)]
        start_date: String,
        /// End date - the current date or end of the incident timeframe
        #[arg(long)]
        end_date: String,
        /// IOC list file
        #[arg(short, long)]
        ioc_file: String,
        /// The link that the data is stored on, i.e https://myaccount.file.core.windows.net/myclient/?sp=rl&st=...VWjgWTY8uc%3D&sr=s
        #[arg(long)]
        in_link: String,
        /// The link where you need the wiskess output uploaded to, 
        /// i.e. https://myaccount.file.core.windows.net/results/myclient/?sp=rcwl&st=2023-04-21T20...2FZWEA%3D&sr=s
        #[arg(long)]
        out_link: String,
        /// Set this flag to update the Wiskess results, such as changing the timeframe or after adding new IOCs to the list.
        #[arg(short, long)]
        update: bool,
        /// Set this flag to keep the downloaded data on your local storage. Useful if wanting to process the data after Wiskess. 
        /// Caution: make sure you have enough disk space for all the data source list.
        #[arg(short, long)]
        keep_evidence: bool,
    },
    /// process the data with wiskess
    Wiskess {
        /// config file of the binaries to run as processors
        #[arg(short, long, default_value = "config/main_win.yaml")]
        config: String,
        /// config file of the artefact file paths
        #[arg(short, long, default_value = "config/artefacts.yaml")]
        artefacts_config: String,
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
    }
}

fn show_banner() {
    let font = vec!["3-D", "3D Diagonal", "3D-ASCII", "ANSI Shadow", "Alligator", "Alpha", "Banner3-D", "Big Money-ne", "Caligraphy2", "Doh", "Henry 3D", "Larry 3D", "Train"];
    let font_str = font.choose(&mut rand::thread_rng()).unwrap();
    let opt = FigletOptions {
        font: font_str.to_string(), // Default font is "Standard"
        ..FigletOptions::default()
    };
    let figlet = Figlet::text("WISKESS".to_string(), opt).unwrap();
    println!("{}", style(figlet.text).magenta());
    println!("{}", style("Gavin Hull").yellow());
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    let msg_version = format!("version: {}", VERSION);
    println!("{}", style(msg_version).yellow());
}

fn main() {
    // Set exit handler
    ctrlc::set_handler(move || {
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");
 
    
    // Get the args
    let args = Args::parse();

    // Display banner
    show_banner();

    // Set tool path
    let tool_path = Path::new(&args.tool_path);
    let tool_path = match tool_path.to_str() {
        Some("") | None => {
            let path_to_exe = env::current_exe().unwrap();
            tool_path.join(&path_to_exe.parent().unwrap()).join("tools")
        }
        Some(&_) => tool_path.to_path_buf(),
    };

    // TODO: check the config file exists

    match args.command {
        Commands::Setup {
            github_token,
            verbose
        } => {
            // TODO: check if setup has been run, or if any binaries are missing
            scripts::run_setup(&tool_path, github_token, verbose);
        },
        Commands::Whipped { 
            config,
            artefacts_config,
            data_source_list,
            local_storage,
            start_date,
            end_date,
            ioc_file,
            in_link,
            out_link,
            update,
            keep_evidence,
        } => {            
            // Confirm date is valid
            let start_date = file_ops::check_date(start_date, &"start date".to_string());
            let end_date = file_ops::check_date(end_date, &"end date".to_string());

            // put the args into a whipped structure
            let args = config::WhippedArgs {
                config,
                artefacts_config,
                data_source_list,
                local_storage,
                start_date,
                end_date,
                ioc_file,      
                in_link,
                out_link,
                update,
                keep_evidence,
            };
            scripts::run_whipped(&tool_path, args)
        },
        Commands::Wiskess { 
            config, 
            artefacts_config,
            data_source, 
            out_path, 
            start_date, 
            end_date, 
            ioc_file 
        } => {
            // Set output directories
            file_ops::make_folders(Path::new(&out_path));
            
            // Set the start time
            let date_time_fmt = "%Y-%m-%dT%H%M%S";
            let wiskess_start = Utc::now();
            let wiskess_start_str = wiskess_start.format(date_time_fmt).to_string();
            
            // Set main log
            let out_log = format!("{}/wiskess_{}.log", &out_path, wiskess_start_str);
            file_ops::file_exists(&out_log, args.silent);
    	    
            // Write start time to log
            file_ops::log_msg(&out_log, format!("Starting wiskess at: {}", wiskess_start_str));

            // Confirm date is valid
            let start_date = file_ops::check_date(start_date, &"start date".to_string());
            let end_date = file_ops::check_date(end_date, &"end date".to_string());
            
            let main_args = config::MainArgs {
                out_path,
                start_date,
                end_date,
                tool_path: tool_path.to_str().unwrap().to_string(),
                ioc_file,
                silent: args.silent,
                out_log,
                multi_pb: MultiProgress::new()
            };
        
            // Read the config
            let f: std::fs::File = OpenOptions::new()
                .read(true)
                .open(config)
                .expect("Unable to open config file.");
            let config: config::Config = serde_yaml::from_reader(f).expect("Could not read values.");

            // Read the artefacts config
            let f: std::fs::File = OpenOptions::new()
                .read(true)
                .open(artefacts_config)
                .expect("Unable to open artefacts config file.");
            let config_artefacts: config::ConfigArt = serde_yaml::from_reader(f).expect("Could not read values of artefacts config.");
                    
            // TODO: check or gracefully error when the yaml config misses keys
        
            // check the file paths in the config exist and return a hash of the art paths
            let data_paths = paths::check_art(
                config_artefacts.artefacts, 
                &data_source,
                args.silent,
                &main_args
            );

            // if not a collection, run velo, extract zip and move files
            match paths::check_collection(&data_paths) {
                Ok(_) => {
                    // TODO: run velo
                    // TODO: extract velo collection 
                    // TODO: move extracted files to out_path/Artefacts
                },
                Err(_) => (),
            };

            // check access and copy unreadable artefacts
            let data_paths = paths::check_copy_art(data_paths, &main_args);
            // println!("{:#?}", data_paths);


            // Setup progress bars
            let pb = setup::prog_spin_init(960, &main_args.multi_pb, "magenta");
           
            // Run in parallel then in series (if applicable) each binary of   
            // wiskers, enrichers and reporters
            for func in [
                &config.wiskers,
                &config.enrichers,
                &config.reporters] {
	            setup::prog_spin_msg(&pb, "Wiskess - Running Wiskers / Enrichers / Reporters".to_string());            
                    for num_threads in [0, 1] {
                        exe_ops::run_commands(func, &main_args, &data_paths, num_threads);
                    }
            }

            setup::prog_spin_stop(&pb, "Wiskess complete".to_string());
            
            // Validate wiskess has processed all input files into output files
            valid_ops::valid_process(&config.wiskers, &data_paths, &data_source, &main_args.out_log);

            // Set end time
            let wiskess_stop = Utc::now();
            let wiskess_duration = wiskess_stop - wiskess_start;
            let seconds = wiskess_duration.num_seconds() % 60;
            let minutes = (wiskess_duration.num_seconds() / 60) % 60;
            let hours = (wiskess_duration.num_seconds() / 60) / 60;
            let duration = format!("{:0>2}:{:0>2}:{:0>2}", hours, minutes, seconds);
            file_ops::log_msg(
                &main_args.out_log, 
                format!(
                    "Wiskess finished at: {}, which took: {} [H:M:S]", 
                    wiskess_stop.format(date_time_fmt).to_string(), 
                    duration
                )
            );
        },
    }
}
