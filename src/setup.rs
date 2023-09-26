pub mod init {
    use crate::ops::exe_ops;

    pub fn run_setup(tool_path: &String) {
        println!("[+] Running setup...");
        let script = format!("{}/{}", tool_path, "setup.ps1");
        exe_ops::run_posh(&script);
    }
}