use indicatif::MultiProgress;

use std::path::{Path, PathBuf};

use chrono::Utc;

use std::fs::OpenOptions;

use crate::{art::paths, configs::config, init::setup};

use super::{exe_ops, valid_ops, file_ops};

pub fn start_wiskess(args: config::MainArgs, config: &PathBuf, artefacts_config: &PathBuf, data_source: &String) {
    let (date_time_fmt, wiskess_start, main_args) = init_wiskess(args);
    
    let (config, data_paths) = config_wiskess(
        config, artefacts_config, &data_source, main_args.silent, &main_args
    );

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
    valid_ops::valid_process(&config.wiskers, &main_args, &data_paths, &data_source, &main_args.out_log);

    // Set end time
    end_wiskess(wiskess_start, main_args, &date_time_fmt);
}

pub(crate) fn config_wiskess(config: &PathBuf, artefacts_config: &PathBuf, data_source: &String, silent: bool, main_args: &config::MainArgs) -> (config::Config, std::collections::HashMap<String, String>) {
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
        data_source,
        silent,
        main_args
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
    let data_paths = paths::check_copy_art(data_paths, main_args);
    (config, data_paths)
}

pub(crate) fn init_wiskess(args: config::MainArgs) -> (String, chrono::prelude::DateTime<Utc>, config::MainArgs) {
    // Set output directories
    file_ops::make_folders(Path::new(&args.out_path));
        
    // Set the start time
    let date_time_fmt = "%Y-%m-%dT%H%M%S".to_string();
    let wiskess_start = Utc::now();
    let wiskess_start_str = wiskess_start.format(&date_time_fmt).to_string();
        
    // Set main log
    let wiskess_log_name = format!("wiskess_{}.log", wiskess_start_str);
    let out_log = Path::new(&args.out_path).join(wiskess_log_name);
    file_ops::file_exists_overwrite(&out_log, args.silent);
        
    // Write start time to log
    file_ops::log_msg(&out_log, format!("Starting wiskess at: {}", wiskess_start_str));

    // Confirm date is valid
    let start_date = file_ops::check_date(args.start_date, &"start date".to_string());
    let end_date = file_ops::check_date(args.end_date, &"end date".to_string());
        
    let main_args = config::MainArgs {
        out_path: args.out_path,
        start_date,
        end_date,
        tool_path: args.tool_path,
        ioc_file: args.ioc_file,
        silent: args.silent,
        collect: args.collect,
        out_log,
        multi_pb: MultiProgress::new()
    };
    (date_time_fmt, wiskess_start, main_args)
}

pub(crate) fn end_wiskess(wiskess_start: chrono::prelude::DateTime<Utc>, main_args: config::MainArgs, date_time_fmt: &String) {
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
}
