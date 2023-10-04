pub mod init {
    use crate::{ops::exe_ops, configs::config};

    pub fn run_setup(tool_path: &String) {
        println!("[+] Running setup...");
        let script = format!("{}/{}", tool_path, "setup.ps1");
        // Run the script without any arguments
        exe_ops::run_posh("-f", &script);
    }
    
    pub fn run_whipped(tool_path: &String, args: config::WhippedArgs) {
        println!("[+] Running whipped...");
        let script = format!("{}/{}", &tool_path, "whipped.ps1");
        exe_ops::run_whipped_script(&tool_path, &script, args);
    }
}