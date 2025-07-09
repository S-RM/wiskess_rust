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
                Err(e) => print!(r#"[!] Some error occured: {e}. Some reasons might be:
    * Not running as admin or equivalent - please run in an elevated terminal
    * GitHub token is incorrect or lacks basic permissions - please generated one to access public repos, if unsure how to setup see https://github.blog/2022-10-18-introducing-fine-grained-personal-access-tokens-for-github/
    * Missing file under the tools directory - please re-download the release version"#)
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
    
pub fn run_whipped_image(args: config::WhippedImageArgs) {
    println!("[+] Running whipped image process...");
    
    // check local_storage exists, if drive exists make the folder
    println!("[-] Making dir: {}", args.wiskess_folder);
    file_ops::make_folders(Path::new(&args.wiskess_folder));
    
    match env::consts::OS {
       "windows" => {
           let script = args.tool_path.join("whipped_imageprocess.ps1").to_str().unwrap().to_string();
           exe_ops::run_whipped_image_script(&script, args);
        }
        "linux" => {
	    // TODO: setup linux
            todo!();
        },
        &_ => todo!()
    }
}
