mod configs;
mod ops;
mod art;
mod init;
mod webs;
mod whipped;

use crate::configs::config;
use crate::ops::{file_ops, wiskess};
use crate::init::scripts;
use crate::webs::web;
use crate::whipped::whip_main;

use std::path::PathBuf;
use std::process::exit;
use std::{path::Path,env};
use clap::{ArgAction, Parser, Subcommand};
use ctrlc;
use indicatif::MultiProgress;
use figrs::{Figlet, FigletOptions};
use console::style;
use rand::seq::SliceRandom;
use anyhow::bail;

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
    /// Optoin to prevent making a collection from a mounted image
    #[arg(short, long, action = ArgAction::SetFalse)]
    no_collection: bool
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// setup the wiskess dependencies
    Setup {
        /// Personal github token to access public repos, if unsure how to setup see https://github.blog/2022-10-18-introducing-fine-grained-personal-access-tokens-for-github/
        #[arg(short, long)]
        github_token: String,
        /// Print additional info to the stdout, default is true
        #[arg(short, long, action = ArgAction::SetTrue)]
        verbose: bool,
    },
    /// launch the webui
    Gui {},
    /// whipped pipeline process commands
    Whipped {
        /// config file of the binaries to run as processors
        #[arg(short, long, default_value = "config/main_win.yaml")]
        config: PathBuf,
        /// config file of the artefact file paths
        #[arg(short, long, default_value = "config/artefacts.yaml")]
        artefacts_config: PathBuf,
        /// file path to the data source; either mounted or the root folder
        #[arg(short, long, default_value = "")]
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
        #[arg(short, long, default_value = "iocs.txt")]
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
        config: PathBuf,
        /// config file of the artefact file paths
        #[arg(short, long, default_value = "config/artefacts.yaml")]
        artefacts_config: PathBuf,
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
    OldWhip {
        /// config file of the binaries to run as processors
        #[arg(short, long, default_value = "config/main_win.yaml")]
        config: PathBuf,
        /// config file of the artefact file paths
        #[arg(short, long, default_value = "config/artefacts.yaml")]
        artefacts_config: PathBuf,
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
        #[arg(short, long, default_value = "iocs.txt")]
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

fn check_elevation() -> Result<(), anyhow::Error>{
    #[cfg (target_os = "windows")] {
        use windows_elevate::check_elevated;
        let is_elevated = check_elevated().expect("Failed to call check_elevated");
        if !is_elevated {
            bail!("[!] Not running as Administrator. Please use a terminal with local Administrator rights")
        }
    }
    #[cfg (target_os = "linux")] {
        use sudo;
        if sudo::check() == sudo::RunningAs::User {
            bail!("[!] Not running as Administrator. Please use a terminal with local Administrator rights")
        }
    }
    Ok(())
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

    // check we are running as administrator or as root
    match check_elevation() {
        Ok(()) => println!("[+] Running with elated permissions"),
        Err(e) => {
            println!("[!] Please use an elevated terminal. Error: {}", e);
            exit(0)
        }
    }

    // Set tool path
    let tool_path = Path::new(&args.tool_path);
    let tool_path = match tool_path.to_str() {
        Some("") | None => {
            let path_to_exe = env::current_exe().unwrap();
            tool_path.join(&path_to_exe.parent().unwrap()).join("tools")
        }
        Some(&_) => tool_path.to_path_buf(),
    };

    // Set no_collection to true - only valid for images
    let collect = args.no_collection;

    // TODO: check the config file exists

    match args.command {
        Commands::Setup {
            github_token,
            verbose
        } => {
            // TODO: check if setup has been run, or if any binaries are missing
            scripts::run_setup(&tool_path, github_token, verbose);
        },
        Commands::Gui {  } => {
            match web::main(tool_path) {
                Ok(_) => println!("GUI closed"),
                Err(e) => println!("[!] Something went wrong. Error: {e}"),
            };
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

            // check if config paths exist
            let config = file_ops::check_path(config);
            let artefacts_config = file_ops::check_path(artefacts_config);

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

            let _ = whip_main::whip_main(args, &tool_path);
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
            let args = config::MainArgs {
                out_path,
                start_date,
                end_date,
                tool_path,
                ioc_file,
                silent: args.silent,
                collect,
                out_log: PathBuf::new(),
                multi_pb: MultiProgress::new()
            };

            // check if config paths exist
            let config = file_ops::check_path(config);
            let artefacts_config = file_ops::check_path(artefacts_config);

            wiskess::start_wiskess(args, &config, &artefacts_config, &data_source);
        },
        Commands::OldWhip {
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

            // check if config paths exist
            let config = file_ops::check_path(config);
            let artefacts_config = file_ops::check_path(artefacts_config);

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
        }
    }
}
