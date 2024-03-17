use std::time::Duration;
use indicatif::{ProgressBar, ProgressStyle};
use run_script::ScriptOptions;

fn prog_spin_init(tick: u64) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(tick));
    pb.set_style(
        ProgressStyle::with_template("{spinner:.blue} {msg}")
            .unwrap()
            // For more spinners check out the cli-spinners project:
            // https://github.com/sindresorhus/cli-spinners/blob/master/spinners.json
            .tick_strings(&[
                "▹▹▹▹▹",
                "▸▹▹▹▹",
                "▹▸▹▹▹",
                "▹▹▸▹▹",
                "▹▹▹▸▹",
                "▹▹▹▹▸",
                "▪▪▪▪▪",
            ]),
    );
    pb
}

fn prog_spin_msg(pb: &ProgressBar, msg: String) {
    pb.set_message(msg);
}

fn prog_spin_stop(pb: &ProgressBar,msg: String) {
    pb.finish_with_message(msg);
}

pub fn setup_linux(github_token: String) {
    let pb = prog_spin_init(120);
    prog_spin_msg(&pb, "Wiskess - Setup Linux".to_string());
    prog_spin_msg(&pb, "Installing packages...".to_string());
    let options = ScriptOptions::new();
    let (mut code, mut output, mut error) = run_script::run_script!(
        r#"
         tool_dir="$PWD/tools/"
         cd $tool_dir
         sudo apt-get -y install p7zip-full awscli fd-find git ripgrep python2.7
         python3 -m pip install polars chardet datetime filetype requests --no-warn-script-location
         python3 -m pip install colorama yara-python psutil rfc5424-logging-handler netaddr --no-warn-script-location
         "#
    ).unwrap();
    println!("Exit Code: {}", code);
    println!("Output: {}", output);
    println!("Error: {}", error);

    prog_spin_msg(&pb, "Installing tools from github...".to_string());
    let (mut code, mut output, mut error) = run_script::run_script!(
        r#"
         tool_dir="$PWD/tools/"
         github_token="$1"
         for url in 'https://github.com/countercept/chainsaw' 'https://github.com/Yamato-Security/hayabusa' 'https://github.com/omerbenamram/evtx.git' 'https://github.com/omerbenamram/mft' 'https://github.com/forensicmatt/RustyUsn'
         do
           python3 $tool_dir/setup_get_git.py $github_token $url linux
         done
         "#,
         &vec![github_token],
         &options
    ).unwrap();
    println!("Exit Code: {}", code);
    println!("Output: {}", output);
    println!("Error: {}", error);

    prog_spin_msg(&pb, "Installing Loki and dependencies...".to_string());
    let (mut code, mut output, mut error) = run_script::run_script!(
        r#"
         tool_dir="$PWD/tools/"
         git clone https://github.com/Neo23x0/Loki.git "$tool_dir/loki"
         cd "$tool_dir/loki"
         python3 loki-upgrader.py
         cd $tool_dir
         "#
    ).unwrap();
    println!("Exit Code: {}", code);
    println!("Output: {}", output);
    println!("Error: {}", error);

    prog_spin_msg(&pb, "Getting Chainsaw shimcache patterns...".to_string());
    let (mut code, mut output, mut error) = run_script::run_script!(
        r#"
         tool_dir="$PWD/tools/"
         wget "https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/analysis/shimcache_patterns.txt" -O "$tool_dir/shimcache_patterns.txt"
         "#
    ).unwrap();
    println!("Exit Code: {}", code);
    println!("Output: {}", output);
    println!("Error: {}", error);

    prog_spin_msg(&pb, "Installing Vector...".to_string());
    let (mut code, mut output, mut error) = run_script::run_script!(
        r#"
         tool_dir="$PWD/tools/"
         echo "[ ] Installing Vector"
         curl --proto '=https' --tlsv1.2 -sSfL https://sh.vector.dev | bash -s -- -y
         # TODO: azcopy
         exit 0
         "#
    ).unwrap();
    println!("Exit Code: {}", code);
    println!("Output: {}", output);
    println!("Error: {}", error);

    prog_spin_stop(&pb, "[ ] Setup complete".to_string());
}
