pub mod config {
  use serde::{Deserialize, Serialize};

  /// Top level structure of config file
  #[derive(Debug, Serialize, Deserialize, Clone)]
  pub struct Config {
      pub wiskers: Vec<Wiskers>,
      pub enrichers: Vec<Wiskers>,
      pub reporters: Vec<Wiskers>,
  }

  /// Top level structure of artefacts config file
  #[derive(Debug, Serialize, Deserialize, Clone)]
  pub struct ConfigArt {
      pub artefacts: Vec<Artefacts>,
  }

  fn serde_true() -> bool {
    true
  }
  fn serde_false() -> bool {
    false
  }

  /// Configuration of the commands to run
  #[derive(Debug, Serialize, Deserialize, Clone)]
  pub struct Wiskers {
    pub name: String,
    pub binary: String,
    pub args: String,
    pub outfolder: String,
    pub input: String,
    pub outfile: String,
    #[serde(default)]
    pub choco: String,
    #[serde(default)]
    pub github: String,    
    #[serde(default)]
    pub web_download: String,
    #[serde(default)]
    pub deps_choco: String,
    #[serde(default)]
    pub deps_github: String,
    #[serde(default = "serde_true")]
    pub para: bool,
    #[serde(default = "serde_false")]
    pub script: bool,
    #[serde(default)]
    pub script_posh: String,
    #[serde(default = "serde_true")]
    pub chk_exists: bool,
    #[serde(default)]
    pub valid_path: String,
  }

  /// Artefact paths and type
  #[derive(Debug, Serialize, Deserialize, Clone)]
  pub struct Artefacts {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub legacy: String,
  }

  // Set struct for interal args
  #[derive(Debug, Clone)]
  pub struct MainArgs {
      pub out_path: String,
      pub start_date: String,
      pub end_date: String,
      pub tool_path: String,
      pub ioc_file: String,
      pub silent: bool,
      pub out_log: String
  }

  // Set struct for whipped args
  #[derive(Debug, Serialize, Deserialize, Clone)]
  pub struct WhippedArgs {
    pub config: String,
    pub artefacts_config: String,
    pub data_source_list: String,
    pub local_storage: String,
    pub start_date: String,
    pub end_date: String,
    pub ioc_file: String,
    pub in_link: String,
    pub out_link: String,
    pub update: bool,
    pub keep_evidence: bool
  }
}