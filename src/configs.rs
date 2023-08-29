pub mod config {
  use serde::{Deserialize, Serialize};

  /// Top level structure of config file
  #[derive(Debug, Serialize, Deserialize)]
  pub struct Config {
      pub artefacts: Vec<Artefacts>,
      pub wiskers: Vec<Wiskers>,
  }

  /// Configuration of the commands to run
  #[derive(Debug, Serialize, Deserialize)]
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
  }

  /// Artefact paths and type
  #[derive(Debug, Serialize, Deserialize)]
  pub struct Artefacts {
    pub name: String,
    pub path: String,
    pub path_type: String,
  }
}