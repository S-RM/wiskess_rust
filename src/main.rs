use std::process::Command;
use std::fs::OpenOptions;
use std::io::Write;
use std::thread;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let commands: Vec<(&str, &str)> = args[1..]
        .iter()
        .map(|arg| {
            let parts: Vec<&str> = arg.splitn(2, ' ').collect();
            (parts[0], *parts.get(1).unwrap_or(&""))
        })
        .collect();

    let mut children = vec![];

    for (program, args) in &commands {
        let args: Vec<&str> = args.split_whitespace().collect();
        
        let child = thread::spawn(move || {
            let output = Command::new(program)
                .args(args)
                .output()
                .expect("Failed to execute command");
            
            output.stdout
        });

        children.push(child);
    }

    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open("output.txt")
        .expect("Failed to open 'output.txt'");

    for child in children {
        let output = child.join().unwrap();
        file.write_all(&output).expect("Failed to write to 'output.txt'");
    }
}