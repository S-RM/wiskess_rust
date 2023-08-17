use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_yaml::{self};
use std::process::{Command, Output};
use std::time::Duration;
use std::fs::OpenOptions;
use std::io::Write;
use std::thread;
use std::env;

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

    /// Read the config
    let f = std::fs::File::open(args.config).expect("Could not open file.");
    let mut scrape_config: Config = serde_yaml::from_reader(f).expect("Could not read values.");
    println!("{:?}", scrape_config);

    // let mut commands = Vec::new();

    for wisker in scrape_config.wiskers {
        // let command = format!(
        //     "{} {}",
        //     wisker.binary, wisker.args
        // );
        // let _ = &commands.push(command.to_string());
        // println!(
        //     "name: {}, binary: {}, args {}",
        //     wisker.name, wisker.binary, wisker.args
        // );

        let mut children = vec![];
        
        let child = thread::spawn(move || {
            let output = Command::new(&wisker.binary)
                .arg(&wisker.args)
                .output()
                .expect("Failed to execute command");
            
            output.stdout
        });

        children.push(child);
    }
//
    // let mut children = vec![];

    // for (program, args) in &commands {
    //     let args: Vec<&str> = args.split_whitespace().collect();
        
    //     let child = thread::spawn(move || {
    //         let output = Command::new(program)
    //             .args(args)
    //             .output()
    //             .expect("Failed to execute command");
            
    //         output.stdout
    //     });

    //     children.push(child);
    // }

    // let mut file = OpenOptions::new()
    //     .write(true)
    //     .append(true)
    //     .open("output.txt")
    //     .expect("Failed to open 'output.txt'");

    // for child in children {
    //     let output = child.join().unwrap();
    //     file.write_all(&output).expect("Failed to write to 'output.txt'");
    // }
}