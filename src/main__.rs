


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