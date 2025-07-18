use core::str;
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

    command.args(["-ExecutionPolicy", "Bypass"]);
    command.args(["-f", script]);
    command.args(["-config", &args.config.into_os_string().into_string().unwrap()]);
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
        if exit_code != 0 {
            eprintln!("Failed to run whipped script at path {}.", script);
        }
    } else {
        eprintln!("Interrupted!");
    }
}

pub fn run_whipped_image_script(script: &String, args: config::WhippedImageArgs) {
    let mut pwsh = "pwsh".to_string();
    if !check_binary(&pwsh, "-h") {
        pwsh = "powershell".to_string();
    }
    let mut command = Command::new(pwsh);
    
    command.args(["-ExecutionPolicy", "Bypass"]);
    command.args(["-f", script]);
    command.args(["-config", &args.config.into_os_string().into_string().unwrap()]);
    command.args(["-image_path", &args.image_path.into_os_string().into_string().unwrap()]);
    command.args(["-wiskess_folder", &args.wiskess_folder]);
    command.args(["-start_date", &args.start_date]);
    command.args(["-end_date", &args.end_date]);
    command.args(["-ioc_file", &args.ioc_file]);
    command.args(["-tool_path", &args.tool_path.parent().unwrap().to_str().unwrap()]);

    let output = command.execute_output().unwrap();

    if let Some(exit_code) = output.status.code() {
        if exit_code != 0 {
            eprintln!("Failed to run whipped script at path {}.", script);
        }
    } else {
        eprintln!("Interrupted!");
    }
}

/// run powershell, checking filepaths for powershell or pwsh
/// 
/// Args:
/// * `func`: set whether the payload is executed as file `-f` or command `-c`
/// * `payload`: either script or command
/// * `out_log`: the file path to the wiskess log
/// * `git_token`: the user's token for use in the setup, can be a blank string if not in use, i.e. ""
/// * `show_err`: don't show an error if the command doesn't work. 
pub fn run_posh(func: &str, payload: &String, out_log: &Path, git_token: &String, show_err: bool) -> std::process::Output {
    if out_log.exists() {
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
        if exit_code != 0  && show_err {
            eprintln!("Failed to run PowerShell payload: {}.", payload);
        }
    } else {
        eprintln!("Interrupted!");
    }

    log_exe_output(out_log, &output);
    output
}

fn log_exe_output(out_log: &Path, output: &std::process::Output) {
    if out_log.exists() {
        match str::from_utf8(&output.stdout) {
            Ok(v) => file_ops::log_msg(out_log, v.to_string()),
            Err(e) => file_ops::log_msg(out_log, format!("Invalid UTF-8 sequence: {}", e)),
        }
        // for o in output.stdout.clone() {
        //     file_ops::log_msg(&out_log, o.to_string());
        // }
        // for e in output.stderr.clone() {
        //     file_ops::log_msg(&out_log, e.to_string());
        // }
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
pub fn run_wisker(wisker_binary: &String, wisker_arg: &String, out_log: &Path) -> std::process::Output {
    let wisker_cmd = format!("{} {}", 
        &wisker_binary, 
        &wisker_arg);
    file_ops::log_msg(&out_log, format!("[ ] Running: {}", wisker_cmd));
    let mut command = shell(wisker_cmd);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let output = command.execute_output().unwrap();
    // let (pid, cpu_usage) = get_pid_process(&wisker_binary);
    // file_ops::log_msg(&out_log, format!("[ ] Process: {wisker_binary} running with PID: {pid} at  CPU: {cpu_usage}"));
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
            .replace("{tool_path}", &main_args.tool_path.to_str().unwrap().to_string());
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
        .replace("{tool_path}", &main_args.tool_path.to_str().unwrap().to_string());
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

pub fn load_wisker(main_args_c: &config::MainArgs, wisker: &config::Wiskers, data_paths_c: HashMap<String, String>) -> (String, String, String, bool, String) {
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
    let err_msg = installed_binary_check(wisker.chk_exists, &wisker_binary);
            
    // Check if the outfile already exists, ask user to overwrite
    let check_outfile = Path::new(&folder_path_str).join(&wisker.outfile);
    // let check_outfile = format!("{}/{}", &folder_path_str, &wisker.outfile);
    let overwrite_file = file_ops::file_exists_overwrite(
        &check_outfile,
        true
    );
    (wisker_arg, wisker_binary, wisker_script, overwrite_file, err_msg)
}

pub fn installed_binary_check(chk_exists: bool, binary: &String) -> String {
    let mut installed = false;
    if chk_exists {
        for test_arg in ["-h", "help", "--version", "-v", "-V", "-c print('wiskess')"] {
            if check_binary(binary, test_arg) {
                installed = true;
                break;
            }
        }
    } else {
        installed = true;
    }
    let mut err_msg = "".to_string();
    if !installed {
        err_msg = format!("[!] The path `{}` is not a correct executable binary file.", binary); 
    }
    err_msg
}

/// run_commands executes a list of "wiskers" (commands or tasks) in parallel using the specified number of threads.
/// 
/// This function sets up a thread pool and filters the commands to be run based on whether they should 
/// execute in parallel. It then spawns a new thread for each command, managing synchronization through 
/// channels for capturing output and handling existing output files.
/// 
/// # Arguments
/// * `func` - A vector of `Wiskers` that defines the commands or tasks to be executed. 
///   Each `Wisker` contains various attributes such as `para`, `name`, `input`, among others.
/// * `main_args` - A reference to `MainArgs` from the `config` module, which stores main configuration 
///   options like output log paths or other parameters required to execute a command.
/// * `data_paths` - A hash map holding data path mappings. These are used to locate input files required 
///   by the wiskers for execution.
/// * `threads` - The number of threads to utilize in the thread pool for parallel execution. If set to 1, 
///   commands are forced to execute sequentially.
/// 
/// # Behavior
/// - The function initializes a progress indicator and calculates the total number of tasks to be run.
/// - It checks whether an existing output file prevents the execution of a command unless overwriting is permitted.
/// - Each command's output (stdout and stderr) is sent through a channel and logged accordingly.
/// - Commands are spawned using a thread pool, which facilitates running them in parallel if allowed.
/// 
/// This function does not explicitly return a value but will perform file write operations for logging 
/// the standard output and errors for each command executed.
pub fn run_commands(func: &Vec<Wiskers>, main_args: &config::MainArgs, data_paths: &HashMap<String, String>, threads: usize) {
    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();

    let run_para = threads != 1;

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
                // Build the variables needed to run the binary
                let (wisker_arg, wisker_binary, wisker_script, overwrite_file, err_msg) = load_wisker(
                    &main_args_c, 
                    &wisker, 
                    data_paths_c);
        
                // Create the sub progress bar
                let pb2_clone = setup::prog_spin_after(&pb_clone, 480, &main_args_c.multi_pb, "white");
                setup::prog_spin_msg(&pb2_clone, format!("Running: {}", &wisker.name));
                pb2_clone.inc(1);

                if overwrite_file {
                    if wisker.script {
                        // it has a powershell script, which gets run before the binary
                        _ = run_posh("-c", &wisker_script, &main_args_c.out_log, &"".to_string(), true);
                    }

                    let output = run_wisker(&wisker_binary, &wisker_arg, &main_args_c.out_log);
                    
                    // run the binary with the args
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
                if err_msg != "" {
                    setup::prog_spin_stop(&pb2_clone, format!("Done: {}. Error: {}", &wisker.name, err_msg));
                } else {
                    setup::prog_spin_stop(&pb2_clone, format!("Done: {}", &wisker.name));
                }
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