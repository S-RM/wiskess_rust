use std::{env,path::Path};
use crate::{ops::exe_ops, configs::config};
use super::setup;

pub fn run_setup(tool_path: &Path, github_token: String, verbose: bool) {
    println!("[+] Running setup...");
    match env::consts::OS {
        "windows" => {
            let script = tool_path.join("setup.ps1").to_str().unwrap().to_string();
            // Run the script without any arguments
            // exe_ops::run_posh("-f", &script, &"".to_string(), &github_token);
            match setup::setup_win(verbose, github_token, tool_path) {
                Ok(_) => println!("Setup ran OK"),
                Err(e) => println!("[!] Some error occured: {e}")
            };
	},
        "linux" => {
            setup::setup_linux(verbose, github_token);
        },
        &_ => todo!()
    }
}
    
pub fn run_whipped(tool_path: &Path, args: config::WhippedArgs) {
    println!("[+] Running whipped...");
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
