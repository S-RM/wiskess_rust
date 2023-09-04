pub mod config {
  use serde::{Deserialize, Serialize};

  /// Top level structure of config file
  #[derive(Debug, Serialize, Deserialize)]
  pub struct Config {
      pub artefacts: Vec<Artefacts>,
      pub wiskers: Vec<Wiskers>,
  }

  fn serde_true() -> bool {
    true
  }

  /// Configuration of the commands to run
  #[derive(Debug, Serialize, Deserialize, Clone)]
  pub struct Wiskers {
    pub name: String,
    pub binary: String,
    pub args: String,
    pub outfolder: String,
    pub input: String,
    #[serde(default)]
    pub outfile: String,
    #[serde(default)]
    pub choco: String,
    #[serde(default)]
    pub github: String,
    #[serde(default)]
    pub deps_choco: String,
    #[serde(default)]
    pub deps_github: String,
    #[serde(default = "serde_true")]
    pub para: bool
  }

  /// Artefact paths and type
  #[derive(Debug, Serialize, Deserialize)]
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
}