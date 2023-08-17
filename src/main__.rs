use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_yaml::{self};

use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    wiskers: Vec<Wiskers>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Wiskers {
  name: String,
  binary: String,
  args: String,
  outfolder: String,
  outfile: String,
  choco: String,
  github: String,
  deps_choco: String,
  deps_github: String,
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    name: String,

    /// Number of times to greet
    #[arg(long, default_value_t = 1)]
    count: u8,

    /// Config file
    #[arg(short, long)]
    config: String,
}

fn run_cmds() {
    let binaries = vec!["calc.exe", "notepad.exe"];
    let mut outputs = Vec::new();

    for binary in binaries {
        let child = thread::spawn(move || {
            let output = Command::new(binary).output().unwrap();
            outputs.push(output);
        });
        child.join().unwrap();
    }

    for (i, output) in outputs.iter().enumerate() {
        let stdout = String::from_utf8(output.stdout).unwrap();
        println!("The stdout of binary {} is: {}", i + 1, stdout);
    }
}

fn main() {
    let args = Args::parse();

    /// Read the config
    let f = std::fs::File::open(args.config).expect("Could not open file.");
    let mut scrape_config: Config = serde_yaml::from_reader(f).expect("Could not read values.");
    println!("{:?}", scrape_config);

    for wisker in scrape_config.wiskers.iter() {
        println!(
            "name: {}, binary: {}, args {}",
            wisker.name, wisker.binary, wisker.args
        );
    }

}