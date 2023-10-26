use std::{collections::HashMap, process::{Stdio, Command}, io::Write};
use execute::{shell, Execute};
use rayon::ThreadPoolBuilder;
use std::fs::OpenOptions;
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

fn set_wisker(wisker: &config::Wiskers, data_paths: &HashMap<String, String>, folder_path: &String, main_args: &config::MainArgs) -> (String, String, String) {
    // TODO: remove quotes from wisker.args, as it causes issues and isn't needed
    
    // replace the placeholders, i.e. {input}, in wisker.args with those from local variables, the yaml config, etc.
    if data_paths.contains_key(&wisker.input) {
        let wisker_arg = set_placeholder(&wisker.args, wisker, data_paths, folder_path, main_args);
        let wisker_binary = wisker.binary
            .replace("{tool_path}", &main_args.tool_path);
        let mut wisker_script = String::new();
        if wisker.script {
            wisker_script = set_placeholder(&wisker.script_posh, wisker, data_paths, folder_path, main_args);
        }
        
        // TODO: Check if wisker_arg contains any other placeholder
        (wisker_arg, wisker_binary, wisker_script)
    } else {
        panic!("Unable to find the input data path. Check the config for {}", &wisker.input)
    }
}

fn set_placeholder(wisker_field: &String, wisker: &Wiskers, data_paths: &HashMap<String, String>, folder_path: &String, main_args: &config::MainArgs) -> String {
    let wisker_arg = wisker_field
        .replace("{input}", data_paths[&wisker.input].as_str())
        .replace("{outfile}", &wisker.outfile.as_str())
        .replace("{outfolder}", folder_path)
        .replace("{start_date}", &main_args.start_date)
        .replace("{end_date}", &main_args.end_date)
        .replace("{ioc_file}", &main_args.ioc_file)
        .replace("{out_path}", &main_args.out_path)
        .replace("{tool_path}", &main_args.tool_path);
    wisker_arg
}

pub fn load_wisker(main_args_c: config::MainArgs, wisker: &config::Wiskers, data_paths_c: HashMap<String, String>) -> (String, String, String, bool) {
    // Make the output folders from the yaml config
    let folder_path = format!("{}/{}", &main_args_c.out_path, &wisker.outfolder);
    file_ops::make_folders(&folder_path);
    
    let (wisker_arg, wisker_binary, wisker_script) = set_wisker(
        wisker, 
        &data_paths_c, 
        &folder_path, 
        &main_args_c
    );

    // check binary is installed
    let mut installed = false;
    if wisker.chk_exists {
        for test_arg in ["-h", "help", "--version", "-v", "-V"] {
            if check_binary(&wisker_binary, test_arg) {
                installed = true;
                break;
            }
        }
    } else {
        installed = true;
    }
    if !installed {
        eprintln!("[!] The path `{}` is not a correct executable binary file.", wisker_binary); 
    }
            
    // Check if the outfile already exists, ask user to overwrite
    let check_outfile = format!("{}/{}", &folder_path, &wisker.outfile);
    let overwrite_file = file_ops::file_exists(
        &check_outfile,
        main_args_c.silent
    );
    (wisker_arg, wisker_binary, wisker_script, overwrite_file)
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
    
            let (wisker_arg, wisker_binary, wisker_script, overwrite_file) = load_wisker(
                main_args_c, 
                &wisker, 
                data_paths_c);

            if overwrite_file {
                if wisker.script {
                    run_posh("-c", &wisker_script);
                }
                
                let output = run_wisker(&wisker_binary, &wisker_arg);
            
                println!("[+] Done {} with command: {} {}", 
                    &wisker.name, 
                    &wisker_binary,
                    &wisker_arg);
                    
                tx.send(output.stdout).unwrap();
            } else {    
                println!("If wanting to run the module again, {}",
                    "please delete the output file or run wiskess without --silent mode");
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

pub fn run_whipped_script(script: &String, args: config::WhippedArgs) {
    let mut pwsh = "pwsh".to_string();
    if !check_binary(&pwsh, "-h") {
        pwsh = "powershell".to_string();
    }
    let mut command = Command::new(pwsh);

    command.args(["-f", script]);
    command.args(["-config", &args.config]);
    command.args(["-data_source_list", &args.data_source_list]);
    command.args(["-local_storage", &args.local_storage]);
    command.args(["-start_date", &args.start_date]);
    command.args(["-end_date", &args.end_date]);
    command.args(["-ioc_file", &args.ioc_file]);
    command.args(["-storage_type", &args.storage_type]);
    command.args(["-in_link", &args.in_link]);
    command.args(["-out_link", &args.out_link]);
    if args.update {
        command.arg("-update");
    }
    if args.keep_evidence {
        command.arg("-keep_evidence");
    }
    // command.args(["-tool_path",tool_path]);

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

/// run powershell, checking filepaths for powershell or pwsh
/// arg payload is either script or command
/// arg func sets whether the payload is executed as file or command
pub fn run_posh(func: &str, payload: &String) {
    println!("[ ] Powershell function running: {} with payload: {}", func, payload);
    let mut pwsh = "pwsh".to_string();
    if !check_binary(&pwsh, "-h") {
        pwsh = "powershell".to_string();
    }
    let mut command = Command::new(pwsh);

    command.arg(func);
    command.arg(payload);

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

fn check_binary(binary: &String, arg: &str) -> bool {
    let mut binary_cmd = Command::new(binary);

    binary_cmd.arg(arg);

    if binary_cmd.execute_check_exit_status_code(0).is_err() {
        return false;
    }
    return true;
}
