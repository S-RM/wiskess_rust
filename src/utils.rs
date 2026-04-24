use std::path::{Path, PathBuf};
use std::env;
use anyhow::{bail, Ok};
use crate::ops::file_ops;

/// check if running with elevated permissions
pub fn check_elevation() -> Result<(), anyhow::Error>{
    #[cfg (target_os = "windows")] {
        use windows_elevate::check_elevated;
        let is_elevated = check_elevated().expect("Failed to call check_elevated");
        if !is_elevated {
            bail!("[!] Not running as Administrator. Please use a terminal with local Administrator rights")
        }
    }
    // #[cfg (target_os = "linux")] {
    //     use sudo;
    //     if sudo::check() == sudo::RunningAs::User {
    //         bail!("[!] Not running as root. Please either use sudo or the root account")
    //     }
    // }
    Ok(())
}

/// get the OS-specific config path if the provided config doesn't exist
pub fn get_config_type(config: PathBuf, tool_path: &Path) -> Result<PathBuf, anyhow::Error> {
    if !config.exists() || !config.is_file() {
        let config_os = match env::consts::OS {
            "windows" => {
                Path::new(tool_path).parent().unwrap().join("config").join("windows").join(config.file_name().unwrap())
            },
            "linux" => {
                Path::new(tool_path).parent().unwrap().join("config").join("linux").join(config.file_name().unwrap())
            },
            &_ => bail!(format!("[!] Unknown OS type. Not yet supporting OS: {}.", env::consts::OS))
        };
        Ok(config_os)
    } else {
        Ok(config)
    }
}

/// check both config files exist and return their paths
pub fn check_configs(config: PathBuf, tool_path: &PathBuf, artefacts_config: PathBuf) -> (PathBuf, PathBuf) {
    let config = get_config_type(config, tool_path).unwrap();
    let artefacts_config = get_config_type(artefacts_config, tool_path).unwrap();
    // check if config paths exist
    let config = file_ops::check_path(config);
    let artefacts_config = file_ops::check_path(artefacts_config);
    (config, artefacts_config)
}
