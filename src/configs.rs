pub mod config {
  use serde::{Deserialize, Serialize};

  /// Top level structure of config file
  #[derive(Debug, Serialize, Deserialize, Clone)]
  pub struct Config {
      pub artefacts: Vec<Artefacts>,
      pub wiskers: Vec<Wiskers>,
      pub enrichers: Vec<Wiskers>,
      pub reporters: Vec<Wiskers>,
      pub collectors: Vec<Wiskers>,
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
  }

  /// Artefact paths and type
  #[derive(Debug, Serialize, Deserialize, Clone)]
  pub struct Artefacts {
    pub name: String,
    pub path: String,
    pub path_type: String,
  }

  // Set struct for interal args
  #[derive(Debug, Clone)]
  pub struct MainArgs {
      pub out_path: String,
      pub start_date: String,
      pub end_date: String,
      pub tool_path: String,
      pub ioc_file: String,
      pub silent: bool
  }

  // Set struct for whipped args
  #[derive(Debug, Clone)]
  pub struct WhippedArgs {
    pub config: String,
    pub data_source_list: String,
    pub local_storage: String,
    pub start_date: String,
    pub end_date: String,
    pub ioc_file: String,
    pub storage_type: String,
    pub in_link: String,
    pub out_link: String,
    pub update: bool,
    pub keep_evidence: bool
  }
}