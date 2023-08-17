use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_yaml::{self};
use std::process::{Command, Output};
use std::time::Duration;
use std::fs::OpenOptions;
use std::io::Write;
use std::thread;


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
  #[serde(default)]
  outfile: String,
  #[serde(default)]
  choco: String,
  #[serde(default)]
  github: String,
  #[serde(default)]
  deps_choco: String,
  #[serde(default)]
  deps_github: String,
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Config file
    #[arg(short, long)]
    config: String,
}

fn main() {
    // Get the args
    let args = Args::parse();

    // Read the config
    let f = std::fs::File::open(args.config).expect("Could not open file.");
    let scrape_config: Config = serde_yaml::from_reader(f).expect("Could not read values.");
    println!("{:?}", scrape_config);

    // let mut commands = Vec::new();
    let mut children = vec![];

    for wisker in scrape_config.wiskers {
        // Create thread per binary in config        
        let child = thread::spawn(move || {
            let output = Command::new(&wisker.binary)
                .arg(&wisker.args)
                .output()
                .expect("Failed to execute command");
            
            println!("[+] Ran {}", &wisker.name);
            output.stdout
        });

        
        children.push(child);
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open("output.txt")
        .expect("Failed to open 'output.txt'");

    for child in children {
        let output = child.join().unwrap();
        file.write_all(&output).expect("Failed to write to 'output.txt'");
    }
}