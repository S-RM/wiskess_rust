#[cfg(test)]
mod tests {
    use crate::configs::config::{Config, ConfigArt};
    use crate::utils;
    use std::path::{Path, PathBuf};

    /// Test loading Windows main.yaml config
    #[test]
    fn test_load_windows_main_config() {
        let config_path = Path::new("config/windows/main.yaml");

        if !config_path.exists() {
            // skip if file doesn't exist in test environment
            return;
        }

        let f = std::fs::File::open(config_path).unwrap();
        let config: Result<Config, _> = serde_yaml::from_reader(f);

        assert!(config.is_ok(), "Windows main.yaml should parse correctly");
        let config = config.unwrap();

        // verify structure
        assert!(config.wiskers.len() > 0, "Should have wiskers defined");
        assert!(config.enrichers.len() > 0, "Should have enrichers section");
        assert!(config.reporters.len() > 0, "Should have reporters section");

        // verify Windows-specific binaries use .exe extension or Windows paths
        for wisker in &config.wiskers {
            if wisker.binary.contains("{tool_path}") {
                // Windows binaries should use .exe or be in Get-ZimmermanTools
                let has_exe = wisker.binary.contains(".exe");
                let has_dll = wisker.binary.contains(".dll");
                let is_ez_tools = wisker.binary.contains("Get-ZimmermanTools");

                assert!(
                    has_exe || has_dll || is_ez_tools,
                    "Windows binary should use .exe, .dll, or be EZ Tools: {}",
                    wisker.binary
                );
            }
        }
    }

    /// Test loading Linux main.yaml config
    #[test]
    fn test_load_linux_main_config() {
        let config_path = Path::new("config/linux/main.yaml");

        if !config_path.exists() {
            // skip if file doesn't exist in test environment
            return;
        }

        let f = std::fs::File::open(config_path).unwrap();
        let config: Result<Config, _> = serde_yaml::from_reader(f);

        assert!(config.is_ok(), "Linux main.yaml should parse correctly");
        let config = config.unwrap();

        // verify structure
        assert!(config.wiskers.len() > 0, "Should have wiskers defined");
        assert!(config.enrichers.len() > 0, "Should have enrichers section");
        assert!(config.reporters.len() > 0, "Should have reporters section");

        // verify Linux-specific binaries use dotnet for DLLs
        for wisker in &config.wiskers {
            if wisker.binary.contains(".dll") {
                // Linux should use dotnet to run DLLs
                assert!(
                    wisker.binary.contains("dotnet"),
                    "Linux should use dotnet for .dll files: {}",
                    wisker.binary
                );
            }
        }
    }

    /// Test loading Windows artefacts.yaml config
    #[test]
    fn test_load_windows_artefacts_config() {
        let config_path = Path::new("config/windows/artefacts.yaml");

        if !config_path.exists() {
            return;
        }

        let f = std::fs::File::open(config_path).unwrap();
        let config: Result<ConfigArt, _> = serde_yaml::from_reader(f);

        assert!(config.is_ok(), "Windows artefacts.yaml should parse correctly");
        let config = config.unwrap();

        assert!(config.artefacts.len() > 0, "Should have artefacts defined");

        // verify Windows paths use backslash, C: drive, or placeholder
        for artefact in &config.artefacts {
            if !artefact.path.is_empty() {
                let has_windows_path = artefact.path.contains("C:") ||
                                       artefact.path.contains("\\") ||
                                       artefact.path.contains("Windows") ||
                                       artefact.path.contains("{root}");

                assert!(
                    has_windows_path,
                    "Windows artefact should have Windows-style path: {}",
                    artefact.path
                );
            }
        }
    }

    /// Test loading Linux artefacts.yaml config
    #[test]
    fn test_load_linux_artefacts_config() {
        let config_path = Path::new("config/linux/artefacts.yaml");

        if !config_path.exists() {
            return;
        }

        let f = std::fs::File::open(config_path).unwrap();
        let config: Result<ConfigArt, _> = serde_yaml::from_reader(f);

        assert!(config.is_ok(), "Linux artefacts.yaml should parse correctly");
        let config = config.unwrap();

        assert!(config.artefacts.len() > 0, "Should have artefacts defined");
    }

    /// Test OS-specific config resolution on Windows
    #[test]
    #[cfg(target_os = "windows")]
    fn test_config_resolution_windows() {
        let tool_path = PathBuf::from("C:\\tools");
        let config_name = PathBuf::from("main.yaml");

        let result = utils::get_config_type(config_name, &tool_path);

        assert!(result.is_ok());
        let resolved = result.unwrap();

        // should resolve to windows config folder
        assert!(resolved.to_str().unwrap().contains("windows"));
    }

    /// Test OS-specific config resolution on Linux
    #[test]
    #[cfg(target_os = "linux")]
    fn test_config_resolution_linux() {
        let tool_path = PathBuf::from("/opt/wiskess/tools");
        let config_name = PathBuf::from("main.yaml");

        let result = utils::get_config_type(config_name, &tool_path);

        assert!(result.is_ok());
        let resolved = result.unwrap();

        // should resolve to linux config folder
        assert!(resolved.to_str().unwrap().contains("linux"));
    }

    /// Test Windows has additional config files
    #[test]
    fn test_windows_additional_configs() {
        let collect_config = Path::new("config/windows/collect.yaml");
        let intense_config = Path::new("config/windows/intense.yaml");

        // Windows should have collect.yaml and intense.yaml
        if collect_config.exists() {
            let f = std::fs::File::open(collect_config).unwrap();
            let config: Result<Config, _> = serde_yaml::from_reader(f);
            assert!(config.is_ok(), "collect.yaml should parse correctly");
        }

        if intense_config.exists() {
            let f = std::fs::File::open(intense_config).unwrap();
            let config: Result<Config, _> = serde_yaml::from_reader(f);
            assert!(config.is_ok(), "intense.yaml should parse correctly");
        }
    }

    /// Test config paths are consistent between OS
    #[test]
    fn test_config_structure_consistency() {
        let windows_main = Path::new("config/windows/main.yaml");
        let linux_main = Path::new("config/linux/main.yaml");

        if !windows_main.exists() || !linux_main.exists() {
            return;
        }

        // both should exist
        assert!(windows_main.exists());
        assert!(linux_main.exists());

        // both should parse
        let win_f = std::fs::File::open(windows_main).unwrap();
        let win_config: Config = serde_yaml::from_reader(win_f).unwrap();

        let linux_f = std::fs::File::open(linux_main).unwrap();
        let linux_config: Config = serde_yaml::from_reader(linux_f).unwrap();

        // both should have wiskers
        assert!(win_config.wiskers.len() > 0);
        assert!(linux_config.wiskers.len() > 0);
    }

    /// Test tool_path placeholder exists in configs
    #[test]
    fn test_tool_path_placeholder() {
        let config_path = Path::new("config/windows/main.yaml");

        if !config_path.exists() {
            return;
        }

        let f = std::fs::File::open(config_path).unwrap();
        let config: Config = serde_yaml::from_reader(f).unwrap();

        // at least one wisker should use {tool_path} placeholder
        let has_placeholder = config.wiskers.iter().any(|w| w.binary.contains("{tool_path}"));
        assert!(has_placeholder, "Configs should use {{tool_path}} placeholder");
    }

    /// Test input placeholders exist in configs
    #[test]
    fn test_input_placeholder() {
        let config_path = Path::new("config/windows/main.yaml");

        if !config_path.exists() {
            return;
        }

        let f = std::fs::File::open(config_path).unwrap();
        let config: Config = serde_yaml::from_reader(f).unwrap();

        // at least one wisker should use {input} placeholder
        let has_input = config.wiskers.iter().any(|w| w.args.contains("{input}"));
        assert!(has_input, "Configs should use {{input}} placeholder");

        // at least one should use {outfolder} placeholder
        let has_outfolder = config.wiskers.iter().any(|w| w.args.contains("{outfolder}"));
        assert!(has_outfolder, "Configs should use {{outfolder}} placeholder");

        // at least one should use {outfile} placeholder
        let has_outfile = config.wiskers.iter().any(|w| w.args.contains("{outfile}"));
        assert!(has_outfile, "Configs should use {{outfile}} placeholder");
    }
}
