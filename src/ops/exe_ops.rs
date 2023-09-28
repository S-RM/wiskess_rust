use std::{collections::HashMap, process::{Stdio, Command}, io::Write};
use execute::{shell, Execute};
use rayon::ThreadPoolBuilder;
use std::fs::OpenOptions;
use powershell_script;
use crate::configs::config::{self, Wiskers};
use super::file_ops;

fn run_wisker(wisker_binary: &String, wisker_arg: &String) -> std::process::Output {
    let wisker_cmd = format!("{} {}", 
        &wisker_binary, 
        &wisker_arg);
    println!("[ ] Running: {}", wisker_cmd);
    let mut command = shell(wisker_cmd);
    command.stdout(Stdio::piped());
    let output = command.execute_output().unwrap();
    output
}

fn set_wisker(wisker: &config::Wiskers, data_paths: &HashMap<String, String>, folder_path: &String, main_args: &config::MainArgs) -> (String, String) {
    // TODO: remove quotes from wisker.args, as it causes issues and isn't needed
    
    // replace the placeholders, i.e. {input}, in wisker.args with those from local variables, the yaml config, etc.
    if data_paths.contains_key(&wisker.input) {
        let wisker_arg = wisker.args
            .replace("{input}", data_paths[&wisker.input].as_str())
            .replace("{outfile}", &wisker.outfile.as_str())
            .replace("{outfolder}", folder_path)
            .replace("{start_date}", &main_args.start_date)
            .replace("{end_date}", &main_args.end_date)
            .replace("{ioc_file}", &main_args.ioc_file)
            .replace("{out_path}", &main_args.out_path)
            .replace("{tool_path}", &main_args.tool_path);
        let wisker_binary = wisker.binary
        .replace("{tool_path}", &main_args.tool_path);
        
        // TODO: Check if wisker_arg contains any other placeholder
        (wisker_arg, wisker_binary)
    } else {
        panic!("Unable to find the input data path. Check the config.")
    }
}

pub fn load_wisker(main_args_c: config::MainArgs, wisker: &config::Wiskers, data_paths_c: HashMap<String, String>) -> (String, String, bool) {
    // Make the output folders from the yaml config
    let folder_path = format!("{}/{}", &main_args_c.out_path, &wisker.outfolder);
    file_ops::make_folders(&folder_path);
    
    let (wisker_arg, wisker_binary) = set_wisker(wisker, &data_paths_c, &folder_path, &main_args_c);

    // check binary is installed
    check_binary(&wisker_binary);
            
    // Check if the outfile already exists, ask user to overwrite
    let check_outfile = format!("{}/{}", &folder_path, &wisker.outfile);
    let overwrite_file = file_ops::file_exists(
        &check_outfile,
        main_args_c.silent
    );
    (wisker_arg, wisker_binary, overwrite_file)
}

pub fn run_commands(scrape_config_wiskers: &Vec<Wiskers>, main_args: &config::MainArgs, data_paths: &HashMap<String, String>, threads: usize, out_log: &String) {
    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();

    let mut run_para = true;
    if threads == 1 {
        run_para = false;
    }

    let sc = scrape_config_wiskers.clone();
    let wiskers: Vec<config::Wiskers> = sc
        .into_iter()
        .filter(|w| w.para == run_para)
        .collect();

    let (tx, rx) = std::sync::mpsc::channel();

    for wisker in wiskers {
    
        let tx = tx.clone();
        let main_args_c = main_args.clone();
        let data_paths_c = data_paths.clone();
        
        pool.spawn(move || {
    
            let (wisker_arg, wisker_binary, overwrite_file) = load_wisker(
                main_args_c, 
                &wisker, 
                data_paths_c);
        
            if overwrite_file {
                let output = run_wisker(&wisker_binary, &wisker_arg);
            
                println!("[+] Ran {} with command: {} {}", 
                    &wisker.name, 
                    &wisker_binary,
                    &wisker_arg);
                    
                tx.send(output.stdout).unwrap();
            }
        });
    }
    drop(tx);

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(&out_log)
        .expect("Failed to open log file");
        
    for msg in rx {
        file.write_all(&msg).expect("Failed to write to log file");
    }
}

pub fn run_posh(script: &String) {
    let mut pwsh = "pwsh".to_string();
    if !check_binary(&pwsh) {
        pwsh = "powershell".to_string();
    }
    let mut command = Command::new(pwsh);

    // command.arg(cmdline);
    command.arg("-f");
    command.arg(script);
    let output = command.execute_output().unwrap();

    if let Some(exit_code) = output.status.code() {
        if exit_code == 0 {
            println!("Ok.");
        } else {
            eprintln!("Failed.");
        }
    } else {
        eprintln!("Interrupted!");
    }
}

fn check_binary(binary: &String) -> bool {
    let mut binary_cmd = Command::new(binary);

    binary_cmd.arg("-h");

    if binary_cmd.execute_check_exit_status_code(0).is_err() {
        eprintln!("[!] The path `{}` is not a correct executable binary file.", binary);
        return false;
    }
    return true;
}
