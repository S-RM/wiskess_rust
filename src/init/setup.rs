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
                "▰▱▱▱▱▱▱",
		"▰▰▱▱▱▱▱",
		"▰▰▰▱▱▱▱",
		"▰▰▰▰▱▱▱",
		"▰▰▰▰▰▱▱",
		"▰▰▰▰▰▰▱",
		"▰▰▰▰▰▰▰",
		"▰▰▰▰▰▰▰",
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

fn output_script(verbose: bool, code: i32, output: String, error: String) {
    if verbose == true {
      println!("{}", output);
    }
    if error != "" {
      println!("Error: {}", error);
    }
    if code != 0 {
      println!("Exit code: {}", code);
    }
}

pub fn setup_linux(v: bool, github_token: String) {
    let pb = prog_spin_init(240);
    prog_spin_msg(&pb, "Wiskess - Setup Linux".to_string());
    prog_spin_msg(&pb, "Installing packages...".to_string());
    let options = ScriptOptions::new();
    let (code, output, error) = run_script::run_script!(
        r#"
         tool_dir="$PWD/tools/"
         cd $tool_dir
         sudo apt-get -y install p7zip-full awscli fd-find git ripgrep python2.7 python-pip regripper
         python3 -m pip install polars chardet datetime filetype requests libesedb-python --no-warn-script-location
         python3 -m pip install colorama yara-python psutil rfc5424-logging-handler netaddr --no-warn-script-location
         pip2 install python-registry
         "#
    ).unwrap();
    output_script(v, code, output, error);

    prog_spin_msg(&pb, "Getting latest releases of tools from github...".to_string());
    let urls = vec![
        "https://github.com/countercept/chainsaw",
	"https://github.com/Yamato-Security/hayabusa",
	"https://github.com/omerbenamram/evtx.git",
        "https://github.com/omerbenamram/mft",
	"https://github.com/forensicmatt/RustyUsn",
        "https://github.com/williballenthin/shellbags"
    ];
    for url in urls.iter() {
        let msg = format!("Getting: {}", url);
        prog_spin_msg(&pb, msg.to_string());    
    	let (code, output, error) = run_script::run_script!(
            r#"
             tool_dir="$PWD/tools/"
             cd $tool_dir
	     github_token="$1"
             url="$2"
             python3 $tool_dir/setup_get_git.py $github_token $url linux
             "#,
             &vec![github_token.clone(), url.to_string()],
             &options
        ).unwrap();
        output_script(v, code, output, error);
    }

    prog_spin_msg(&pb, "Installing Loki and dependencies...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
         tool_dir="$PWD/tools/"
         git clone https://github.com/Neo23x0/Loki.git "$tool_dir/loki"
         cd "$tool_dir/loki"
         python3 loki-upgrader.py
         cd $tool_dir
         git clone https://github.com/brimorlabs/KStrike "$tool_dir/KStrike"
         "#
    ).unwrap();
    output_script(v, code, output, error);

    prog_spin_msg(&pb, "Getting Chainsaw shimcache patterns...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
         tool_dir="$PWD/tools/"
         wget "https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/analysis/shimcache_patterns.txt" -O "$tool_dir/shimcache_patterns.txt"
         "#
    ).unwrap();
    output_script(v, code, output, error);

    prog_spin_msg(&pb, "Installing Vector...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
         tool_dir="$PWD/tools/"
         cd $tool_dir
         curl --proto '=https' --tlsv1.2 -sSfL https://sh.vector.dev | bash -s -- -y
         wget -q https://aka.ms/downloadazcopy-v10-linux
         tar -xvf downloadazcopy-v10-linux
         cp ./azcopy_linux_amd64_*/azcopy $tool_dir
         rm -rf downloadazcopy-v10-linux ./azcopy_linux_amd64_*
         exit 0
         "#
    ).unwrap();
    output_script(v, code, output, error);

    prog_spin_stop(&pb, "[ ] Setup complete".to_string());
}
