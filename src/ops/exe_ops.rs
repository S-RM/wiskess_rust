use std::{collections::HashMap, io::Write, path::Path, process::{Command, Stdio}};
use execute::{shell, Execute};
use rayon::ThreadPoolBuilder;
use std::fs::{canonicalize, OpenOptions};

use crate::configs::config::{self, Wiskers};
use crate::init::setup;
use super::file_ops;

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
/// 
/// Args:
/// * func: set whether the payload is executed as file or command
/// * payload: either script or command
/// * out_log: the file path to the wiskess log
/// * git_token: the user's token for use in the setup, can be a blank string if not in use, i.e. ""
pub fn run_posh(func: &str, payload: &String, out_log: &String, git_token: &String) {
    if out_log != "" {
        file_ops::log_msg(&out_log, format!("[ ] Powershell function running: {} with payload: {}", func, payload));
    }
    let mut pwsh = "pwsh".to_string();
    if !check_binary(&pwsh, "-h") {
        pwsh = "powershell".to_string();
    }
    let mut command = Command::new(pwsh);

    command.arg(func);
    command.arg(payload);
    command.arg(git_token);

    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

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

    log_exe_output(out_log, output);
}

fn log_exe_output(out_log: &String, output: std::process::Output) {
    if out_log != "" {
        for o in output.stdout {
            file_ops::log_msg(&out_log, o.to_string());
        }
        for e in output.stderr {
            file_ops::log_msg(&out_log, e.to_string());
        }
    }
}


/// check if the binary works
/// 
/// Args:
/// * binary: the file path to the tool to run
/// * arg: the argument to test the execution, i.e. -h or --help
fn check_binary(binary: &String, arg: &str) -> bool {
    let mut binary_cmd = Command::new(binary);

    binary_cmd.arg(arg);

    if binary_cmd.execute_check_exit_status_code(0).is_err() {
        return false;
    }
    return true;
}

/// run the binary with the given argument, which is a string
/// returns the output of what was ran, including the stdout and stderr
fn run_wisker(wisker_binary: &String, wisker_arg: &String, out_log: &String) -> std::process::Output {
    let wisker_cmd = format!("{} {}", 
        &wisker_binary, 
        &wisker_arg);
    file_ops::log_msg(&out_log, format!("[ ] Running: {}", wisker_cmd));
    let mut command = shell(wisker_cmd);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let output = command.execute_output().unwrap();
    output
}

/// set the command to be run with the replacement of placeholders, as specified in the config yaml
/// 
/// Args:
/// * wisker: the command to be run as specified in the config, i.e. main_win.yaml
/// * data_paths: a hash map of the file paths that the data is sourced, i.e. mft:'C:\$MFT'
/// * folder_path: the path to the output folder
/// * main_args: the arguments specified from the main.rs, i.e. tool_path
/// returns the string of the constructed command for the binary, argument and/or script
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
    let input_path = get_wisker_art(data_paths, &wisker.input, main_args);
    let mut input_other_path = String::new();
    if wisker.input_other != "" {
        input_other_path = get_wisker_art(data_paths, &wisker.input_other, main_args);
    }
    
    let wisker_arg = wisker_field
        .replace("{input}", &input_path)
        .replace("{input_other}", &input_other_path)
        .replace("{outfile}", &wisker.outfile.as_str())
        .replace("{outfolder}", folder_path)
        .replace("{start_date}", &main_args.start_date)
        .replace("{end_date}", &main_args.end_date)
        .replace("{ioc_file}", &main_args.ioc_file)
        .replace("{out_path}", &main_args.out_path)
        .replace("{tool_path}", &main_args.tool_path);
    wisker_arg
}

fn get_wisker_art(data_paths: &HashMap<String, String>, input: &String, _main_args: &config::MainArgs) -> String {
    let input_path = data_paths[input].clone();
    
    if input_path != "" {
        match canonicalize(&input_path) {
            Ok(p) => p.into_os_string().into_string().unwrap(),
            Err(_e) => {
                // println!("[!] Unable to get path: {input_path}. Error: {}\n", e);
                input_path
            }
        }
    } else {    
        input_path
    }
}

pub fn load_wisker(main_args_c: &config::MainArgs, wisker: &config::Wiskers, data_paths_c: HashMap<String, String>) -> (String, String, String, bool) {
    // Make the output folders from the yaml config
    let folder_path = Path::new(&main_args_c.out_path).join(&wisker.outfolder);
    file_ops::make_folders(&folder_path);
    let folder_path_str = &folder_path.into_os_string().into_string().unwrap();
    
    let (wisker_arg, wisker_binary, wisker_script) = set_wisker(
        wisker, 
        &data_paths_c, 
        folder_path_str, 
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
    let check_outfile = format!("{}/{}", &folder_path_str, &wisker.outfile);
    let overwrite_file = file_ops::file_exists(
        &check_outfile,
        true
    );
    (wisker_arg, wisker_binary, wisker_script, overwrite_file)
}

pub fn run_commands(func: &Vec<Wiskers>, main_args: &config::MainArgs, data_paths: &HashMap<String, String>, threads: usize) {
    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();

    let mut run_para = true;
    if threads == 1 {
        run_para = false;
    }

    let func_c = func.clone();
    let wiskers: Vec<config::Wiskers> = func_c
        .into_iter()
        .filter(|w| w.para == run_para)
        .collect();

    let (tx, rx) = std::sync::mpsc::channel();
    
    // Setup progress bar second level
    let pb = setup::prog_spin_init(960, &main_args.multi_pb, "yellow");
    let num_wiskers = wiskers.len();
    setup::prog_spin_msg(&pb, format!("Running {} processes", num_wiskers));

    for wisker in wiskers {
        
        let tx = tx.clone();
        let main_args_c = main_args.clone();
        let data_paths_c = data_paths.clone();
        let pb_clone = pb.clone();
        
        pool.spawn(move || {
            let input_file = data_paths_c[&wisker.input].as_str();
            if input_file != "wiskess_none" {
                let (wisker_arg, wisker_binary, wisker_script, overwrite_file) = load_wisker(
                    &main_args_c, 
                    &wisker, 
                    data_paths_c);
        
                let pb2_clone = setup::prog_spin_after(&pb_clone, 480, &main_args_c.multi_pb, "white");
                setup::prog_spin_msg(&pb2_clone, format!("Running: {}", &wisker.name));
                pb2_clone.inc(1);

                if overwrite_file {
                    if wisker.script {
                        run_posh("-c", &wisker_script, &main_args_c.out_log, &"".to_string());
                    }
                    
                    let output = run_wisker(&wisker_binary, &wisker_arg, &main_args_c.out_log);
                
                    file_ops::log_msg(&main_args_c.out_log, format!("[+] Done {} with command: {} {}", 
                        &wisker.name, 
                        &wisker_binary,
                        &wisker_arg));
                        
                    tx.send(output.stdout).unwrap();
                    tx.send(output.stderr).unwrap();
                } else {    
                    let folder_path = format!("{}/{}", &main_args_c.out_path, &wisker.outfolder);
                    let file_path = format!("{}/{}", &folder_path, &wisker.outfile);
                    let msg = format!(
                        "[ ] The file already exists: {}\n{} {}\n{}",
                        file_path,
                        "If wanting to run the module again,",
                        &wisker.name,
                        "please delete the output file or run wiskess without --silent mode"
                    );
                    file_ops::log_msg(&main_args_c.out_log, msg);
                }
                setup::prog_spin_stop(&pb2_clone, format!("Done: {}", &wisker.name));
            }
        });
    }
    drop(tx);
    //setup::prog_spin_stop(&pb, format!("Ran {} wiskers",  num_wiskers));

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(&main_args.out_log)
        .expect("Failed to open log file");
        
    for msg in rx {
        file.write_all(&msg).expect("Failed to write to log file");
    }
}