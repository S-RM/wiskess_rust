use std::{env,path::Path};
use crate::{configs::config, ops::{exe_ops, file_ops}};
use super::setup;

pub fn run_setup(tool_path: &Path, github_token: String, verbose: bool) {
    println!("[+] Running setup...");
    match env::consts::OS {
        "windows" => {
            // Run the setup for windows
            match setup::setup_win(verbose, github_token, tool_path) {
                Ok(_) => {},
                Err(e) => println!("[!] Some error occured: {e}")
            };
	},
        "linux" => {
            let _ = setup::setup_linux(verbose, github_token, tool_path);
        },
        &_ => todo!()
    }
}
    
pub fn run_whipped(tool_path: &Path, args: config::WhippedArgs) {
    println!("[+] Running whipped...");
    
    // check local_storage exists, if drive exists make the folder
    println!("[-] Making dir: {}", args.local_storage);
    file_ops::make_folders(Path::new(&args.local_storage));
    
    match env::consts::OS {
       "windows" => {
           let script = tool_path.join("whipped.ps1").to_str().unwrap().to_string();
           exe_ops::run_whipped_script(&script, args);
        }
        "linux" => {
	    // TODO: setup linux
            todo!();
        },
        &_ => todo!()
    }
}
