#[cfg(test)]
mod tests {
    use crate::configs::config::{Config, ConfigArt};
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    /// Test parsing a valid main config YAML file
    #[test]
    fn test_parse_valid_main_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("main.yaml");

        let yaml_content = r#"
wiskers:
  - name: test_wisker
    binary: test.exe
    args: --test
    outfolder: output
    input: input
    outfile: result.txt
    para: true
    script: false
    chk_exists: true

enrichers:
  - name: enricher_test
    binary: enrich.exe
    args: --enrich
    outfolder: enriched
    input: raw
    outfile: enriched.csv

reporters:
  - name: reporter_test
    binary: report.exe
    args: --report
    outfolder: reports
    input: data
    outfile: report.html
"#;

        let mut file = File::create(&config_file).unwrap();
        file.write_all(yaml_content.as_bytes()).unwrap();

        let f = File::open(&config_file).unwrap();
        let config: Result<Config, _> = serde_yaml::from_reader(f);

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.wiskers.len(), 1);
        assert_eq!(config.enrichers.len(), 1);
        assert_eq!(config.reporters.len(), 1);
        assert_eq!(config.wiskers[0].name, "test_wisker");
    }

    /// Test parsing a valid artefacts config YAML file
    #[test]
    fn test_parse_valid_artefacts_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("artefacts.yaml");

        let yaml_content = r#"
artefacts:
  - name: prefetch
    path: C:\Windows\Prefetch\*.pf
    legacy: ""
  - name: event_logs
    path: C:\Windows\System32\winevt\Logs\*.evtx
    legacy: ""
  - name: registry
    path: C:\Windows\System32\config\SYSTEM
    legacy: C:\WINDOWS\system32\config\system
"#;

        let mut file = File::create(&config_file).unwrap();
        file.write_all(yaml_content.as_bytes()).unwrap();

        let f = File::open(&config_file).unwrap();
        let config: Result<ConfigArt, _> = serde_yaml::from_reader(f);

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.artefacts.len(), 3);
        assert_eq!(config.artefacts[0].name, "prefetch");
        assert_eq!(config.artefacts[2].legacy, "C:\\WINDOWS\\system32\\config\\system");
    }

    /// Test config with default values
    #[test]
    fn test_config_default_values() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("defaults.yaml");

        let yaml_content = r#"
wiskers:
  - name: minimal_wisker
    binary: test.exe
    args: --test
    outfolder: out
    input: in
    outfile: result.txt
enrichers: []
reporters: []
"#;

        let mut file = File::create(&config_file).unwrap();
        file.write_all(yaml_content.as_bytes()).unwrap();

        let f = File::open(&config_file).unwrap();
        let config: Config = serde_yaml::from_reader(f).unwrap();

        // check default values are set correctly
        assert_eq!(config.wiskers[0].para, true); // default is true
        assert_eq!(config.wiskers[0].script, false); // default is false
        assert_eq!(config.wiskers[0].chk_exists, true); // default is true
        assert_eq!(config.wiskers[0].choco, ""); // default is empty string
    }

    /// Test config parsing with all optional fields
    #[test]
    fn test_config_with_optional_fields() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("full.yaml");

        let yaml_content = r#"
wiskers:
  - name: full_wisker
    binary: full.exe
    args: --full
    outfolder: output
    input: input
    input_other: other_input
    outfile: full_result.txt
    choco: choco_package
    github: user/repo
    web_download: https://example.com/tool.zip
    deps_choco: dependency_package
    deps_github: dep_user/dep_repo
    para: false
    script: true
    script_posh: script.ps1
    chk_exists: false
    valid_path: validation_path
enrichers: []
reporters: []
"#;

        let mut file = File::create(&config_file).unwrap();
        file.write_all(yaml_content.as_bytes()).unwrap();

        let f = File::open(&config_file).unwrap();
        let config: Config = serde_yaml::from_reader(f).unwrap();

        assert_eq!(config.wiskers[0].input_other, "other_input");
        assert_eq!(config.wiskers[0].choco, "choco_package");
        assert_eq!(config.wiskers[0].github, "user/repo");
        assert_eq!(config.wiskers[0].para, false);
        assert_eq!(config.wiskers[0].script, true);
        assert_eq!(config.wiskers[0].script_posh, "script.ps1");
    }

    /// Test parsing invalid YAML returns error
    #[test]
    fn test_parse_invalid_yaml() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("invalid.yaml");

        let yaml_content = r#"
wiskers:
  - name: broken
    binary: test.exe
    this is not valid yaml syntax [[[
"#;

        let mut file = File::create(&config_file).unwrap();
        file.write_all(yaml_content.as_bytes()).unwrap();

        let f = File::open(&config_file).unwrap();
        let config: Result<Config, _> = serde_yaml::from_reader(f);

        assert!(config.is_err());
    }

    /// Test parsing YAML with missing required fields
    #[test]
    fn test_parse_missing_required_fields() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("missing.yaml");

        let yaml_content = r#"
wiskers:
  - name: incomplete
    binary: test.exe
"#;

        let mut file = File::create(&config_file).unwrap();
        file.write_all(yaml_content.as_bytes()).unwrap();

        let f = File::open(&config_file).unwrap();
        let config: Result<Config, _> = serde_yaml::from_reader(f);

        // should error because required fields are missing
        assert!(config.is_err());
    }

    /// Test empty config sections
    #[test]
    fn test_empty_config_sections() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("empty.yaml");

        let yaml_content = r#"
wiskers: []
enrichers: []
reporters: []
"#;

        let mut file = File::create(&config_file).unwrap();
        file.write_all(yaml_content.as_bytes()).unwrap();

        let f = File::open(&config_file).unwrap();
        let config: Config = serde_yaml::from_reader(f).unwrap();

        assert_eq!(config.wiskers.len(), 0);
        assert_eq!(config.enrichers.len(), 0);
        assert_eq!(config.reporters.len(), 0);
    }
}
