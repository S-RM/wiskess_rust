use std::{env, io, path::Path, time::Duration};
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use run_script::ScriptOptions;

pub fn prog_spin_init(tick: u64, m: &MultiProgress, colour: &str) -> ProgressBar {
    let pb = m.add(ProgressBar::new_spinner());
    prog_set_stlye(&pb, tick, colour); 
    pb
}

pub fn prog_spin_after(pb_before: &ProgressBar, tick: u64, m: &MultiProgress, colour: &str) -> ProgressBar {
    let pb = m.insert_after(pb_before, ProgressBar::new_spinner());
    prog_set_stlye(&pb, tick, colour); 
    pb
}

fn prog_set_stlye(pb: &ProgressBar, tick: u64, colour: &str) {
    pb.enable_steady_tick(Duration::from_millis(tick / 4));
    let sty2 = format!("[{{elapsed_precise}}] {{spinner:.{colour}}} {{msg}}");
    let sty_bar = ProgressStyle::with_template(sty2.as_str())
            .unwrap()
            // For more spinners check out the cli-spinners project:
            // https://github.com/sindresorhus/cli-spinners/blob/master/spinners.json
            .tick_strings(&[
                "▐    ▌",
                "▐=   ▌",
                "▐==  ▌",
                "▐=== ▌",
                "▐====▌",
                "▐ ===▌",
                "▐  ==▌",
                "▐   =▌",
                "▐    ▌",
                "▐   =▌",
                "▐  ==▌",
                "▐ ===▌",
                "▐====▌",
                "▐=== ▌",
                "▐==  ▌",
                "▐=   ▌",
                "▐====▌",
            ]);
    pb.set_style(sty_bar);
}

pub fn prog_spin_msg(pb: &ProgressBar, msg: String) {
    pb.set_message(msg);
}

pub fn prog_spin_stop(pb: &ProgressBar,msg: String) {
    pb.finish_with_message(msg);
}

/// format the outputs of a script command to a string 
/// Args:
/// * `versbose` - show the stdout of the script
/// * `code` - the code of the execution, 0 is success
/// * `output` - the stdout string of the script
/// * `error` - the stderr string of the script
/// 
/// returns a string in the form output: ..., error: ..., exit code: ...
fn output_script(verbose: bool, code: i32, output: String, error: String) -> String {
    let mut outmsg = String::new();
    if verbose == true {
      outmsg = format!("Output: {}\n", output);
    }
    if error != "" {
      outmsg = format!("{}\nError: {}", outmsg, error);
    }
    if code != 0 {
      outmsg = format!("{}\nExit code: {}", outmsg, code);
    }
    outmsg
}

pub fn setup_linux(v: bool, github_token: String) {
    // Setup progress bars    
    let m = MultiProgress::new();
    let pb = prog_spin_init(960, &m, "magenta");
    let pb2 = prog_spin_init(480, &m, "yellow");
    prog_spin_msg(&pb, "Wiskess - Setup Linux".to_string());
    prog_spin_msg(&pb2, "Installing packages...".to_string());

    let mut outmsg = String::new();
    let options = ScriptOptions::new();
    let (code, output, error) = run_script::run_script!(
        r#"
         tool_dir="$PWD/tools/"
         cd $tool_dir
         sudo apt-get update
         sudo apt-get -y install p7zip-full awscli fd-find git ripgrep python2.7 python-pip regripper python3-pip
         python3 -m ensurepip --default-pip
         python3 -m pip install polars chardet datetime filetype requests libesedb-python python-magic --no-warn-script-location
         python3 -m pip install colorama yara-python psutil rfc5424-logging-handler netaddr --no-warn-script-location
         pip2 install python-registry
         "#
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));

    let pb3 = prog_spin_init(240, &m, "white");

    prog_spin_msg(&pb2, "Getting latest releases of tools from github...".to_string());
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
        prog_spin_msg(&pb3, msg.to_string());    
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
        outmsg.push_str(&output_script(v, code, output, error));
    }

    prog_spin_msg(&pb2, "Git cloning github repositories...".to_string());
    let repos = vec![
         "https://github.com/brimorlabs/KStrike",
         "https://github.com/ANSSI-FR/bmc-tools.git",
         "https://github.com/Neo23x0/loki.git",
         "https://github.com/williballenthin/shellbags"
    ];
    for repo in repos.iter() {
        let msg = format!("Cloning: {}", repo);
        prog_spin_msg(&pb3, msg.to_string());    
    	let (code, output, error) = run_script::run_script!(
            r#"
             tool_dir="$PWD/tools/"
             cd $tool_dir
             repo="$1"
             git clone $repo
             "#,
             &vec![repo.to_string()],
             &options
        ).unwrap();
        outmsg.push_str(&output_script(v, code, output, error));
    }

    prog_spin_stop(&pb3, "".to_string());

    prog_spin_msg(&pb2, "Installing Loki and dependencies...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
         tool_dir="$PWD/tools/"
         cd "$tool_dir/loki"
         python3 loki-upgrader.py
         "#
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));

    prog_spin_msg(&pb2, "Getting Chainsaw shimcache patterns...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
         tool_dir="$PWD/tools/"
         wget "https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/analysis/shimcache_patterns.txt" -O "$tool_dir/shimcache_patterns.txt"
         "#
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));

    prog_spin_msg(&pb2, "Installing Vector...".to_string());
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
    outmsg.push_str(&output_script(v, code, output, error));

    prog_spin_stop(&pb2, "".to_string());

    prog_spin_stop(&pb, "[ ] Setup complete".to_string());
    print!("{}", outmsg);
}

pub fn setup_win(v: bool, github_token: String, tool_path: &Path) -> io::Result<()> {
    // Setup progress bars    
    let m = MultiProgress::new();
    let pb = prog_spin_init(960, &m, "magenta");
    let pb2 = prog_spin_init(480, &m, "yellow");
    prog_spin_msg(&pb, "Wiskess - Setup Windows".to_string());
    prog_spin_msg(&pb2, "Installing packages...".to_string());

    // change director to tool_path
    let main_path = env::current_dir()?;
    env::set_current_dir(tool_path)?;

    let mut outmsg = String::new();
    let options = ScriptOptions::new();
    let (code, output, error) = run_script::run_script!(
        r#"
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
        RefreshEnv.cmd
        choco install -y git 7zip python2 fd osfmount awscli
        choco install -y --force ripgrep
        RefreshEnv.cmd
        "#
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));
    
    prog_spin_msg(&pb2, "Getting Python-Cim and Azcopy...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
        py -2 -m pip install python-cim python-registry six
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://aka.ms/downloadazcopy-v10-windows' -OutFile '.\AzCopy.zip' -UseBasicParsing"
        7z e ".\AzCopy.zip" -o"azcopy\" azcopy.exe -r -aoa
        del ".\AzCopy.zip"
        "#
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));

    let pb3 = prog_spin_init(240, &m, "white");

    prog_spin_msg(&pb2, "Installing python packages using pip...".to_string());
    let pips = vec![
        "pip",
        "polars",
        "chardet",
        "datetime",
        "filetype",
        "requests",
        "python-magic",
        "python-magic-bin",
        "PyQt6",
        "libesedb-python",
    ];
    for pip in pips.iter() {
        let msg = format!("Python installing: {}", pip);
        prog_spin_msg(&pb3, msg.to_string());    
        let (code, output, error) = run_script::run_script!(
            r#"
            py -3 -m pip install -U %1
            "#,
            &vec![pip.to_string()],
            &options
        ).unwrap();
        outmsg.push_str(&output_script(v, code, output, error));
    }

    prog_spin_msg(&pb2, "Getting latest releases of tools from github...".to_string());
    let urls = vec![
        "https://github.com/countercept/chainsaw",
        "https://github.com/Yamato-Security/hayabusa",
        "https://github.com/omerbenamram/evtx.git",
        "https://github.com/omerbenamram/mft",
	    "https://github.com/forensicmatt/RustyUsn",
        "https://github.com/obsidianforensics/hindsight.git",
        "https://github.com/Neo23x0/loki.git",
    ];
    for url in urls.iter() {
        let msg = format!("Getting: {}", url);
        prog_spin_msg(&pb3, msg.to_string());    
    	let (code, output, error) = run_script::run_script!(
            r#"
            py ./setup_get_git.py "%1" "%2" windows
            "#,
            &vec![github_token.clone(), url.to_string()],
            &options
        ).unwrap();
        outmsg.push_str(&output_script(v, code, output, error));
    }

    prog_spin_msg(&pb2, "Git cloning github repositories...".to_string());
    let repos = vec![
         "https://github.com/brimorlabs/KStrike",
         "https://github.com/ANSSI-FR/bmc-tools.git",
         "https://github.com/EricZimmerman/Get-ZimmermanTools.git",
         "https://github.com/williballenthin/python-registry.git",
         "https://github.com/williballenthin/shellbags",
         "https://github.com/keydet89/RegRipper3.0.git"
    ];
    for repo in repos.iter() {
        let msg = format!("Cloning: {}", repo);
        prog_spin_msg(&pb3, msg.to_string());    
    	let (code, output, error) = run_script::run_script!(
            r#"
            git clone "%1"
            "#,
            &vec![repo.to_string()],
            &options
        ).unwrap();
        outmsg.push_str(&output_script(v, code, output, error));
    }
 
    prog_spin_stop(&pb3, "".to_string());

    prog_spin_msg(&pb2, "Installing Loki and dependencies...".to_string());
    // change directory to loki folder
    env::set_current_dir(Path::new(tool_path).join("loki").join("loki"))?;
    let (code, output, error) = run_script::run_script!(
        r#"
         .\loki-upgrader.exe
         "#
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));
    // change directory to tool_path
    env::set_current_dir(tool_path)?;

    prog_spin_msg(&pb2, "Getting EZTools and Chainsaw shimcache patterns...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "& .\Get-ZimmermanTools\Get-ZimmermanTools.ps1 -NetVersion 6 -Dest .\Get-ZimmermanTools"
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/analysis/shimcache_patterns.txt' -OutFile .\shimcache_patterns.txt"
        "#
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));

    // Change directory back to what it was before setup
    env::set_current_dir(main_path)?;

    prog_spin_stop(&pb2, "".to_string());

    prog_spin_stop(&pb, "[ ] Setup complete".to_string());
    print!("{}", outmsg);

    Ok(())
}
