use std::{env, io, path::Path, time::Duration};
use chrono::Utc;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use run_script::ScriptOptions;

use crate::ops::{exe_ops, file_ops::{self, make_folders}};
// extern crate git2;
// use git2::Repository;

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
      outmsg = format!("{}\n{}", outmsg, error);
    }
    if code != 0 {
      outmsg = format!("{}\nExit code: {}", outmsg, code);
    }
    outmsg
}

/// start logging and return the path to the log file
fn start_setup_log(setup_log_path: &Path) {
    // Start logging 
    let date_time_fmt = "%Y-%m-%dT%H%M%S".to_string();
    let log_time = Utc::now();
    let log_time_str = log_time.format(&date_time_fmt).to_string();
    file_ops::log_msg(
        setup_log_path,
         format!("[SETUP] Starting the setup of wiskess tools at {}", log_time_str)
    );
}

pub fn setup_linux(v: bool, github_token: String, tool_path: &Path) -> io::Result<()> {
    // Setup progress bars    
    let m = MultiProgress::new();
    let pb = prog_spin_init(960, &m, "magenta");
    let pb2 = prog_spin_init(480, &m, "yellow");
    prog_spin_msg(&pb, "Wiskess - Setup Linux".to_string());
    prog_spin_msg(&pb2, "Installing packages...".to_string());
    let mut outmsg = String::new();
    let options = ScriptOptions::new();

    // start the log
    let setup_log_path = Path::new("wiskess_setup.log");
    start_setup_log(setup_log_path);

    // change director to tool_path
    let main_path = env::current_dir()?;
    let tool_path_str = tool_path.as_os_str().to_os_string().into_string().unwrap();
    env::set_current_dir(tool_path)?;

    let pb3 = prog_spin_init(240, &m, "white");

    let apt_pkgs = vec![
        "p7zip-full",
      //"awscli",
        "fd-find",
        "git",
        "ripgrep",
        "python-pip",
        "regripper",
        "python3-pip",
        "python3-venv",
        "jq",
    ];    
    prog_spin_msg(&pb2, "Installing APT packages...".to_string());
    for pkg in apt_pkgs.iter() {
        let msg = format!("Getting: {}", pkg);
        prog_spin_msg(&pb3, msg.to_string());    
    	let (code, output, error) = run_script::run_script!(
            r#"
             pkg="$1"
             apt-get -y install $pkg
             "#,
             &vec![pkg.to_string()],
             &options
        ).unwrap();
        outmsg.push_str(&output_script(v, code, output, error));
    }


    prog_spin_msg(&pb2, "Installing Python packages...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
        tool_path="$1"
         python3 -m venv venv
         . $tool_path/venv/bin/activate
         apt install python3-pip
         python -m ensurepip --default-pip
         python -m pip install polars chardet datetime filetype requests libesedb-python python-magic --no-warn-script-location
         python -m pip install colorama yara-python psutil rfc5424-logging-handler netaddr --no-warn-script-location
         pip2 install python-registry
         "#,
         &vec![tool_path_str.to_string()],
         &options
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));


    prog_spin_msg(&pb2, "Installing python packages using pip...".to_string());
    let pips = vec![
        "pip",
        "polars",
        "chardet",
        "datetime",
        "filetype",
        "requests",
        "python-magic",
        "PyQt6",
        "libesedb-python",
        "awscli",
        "pyhindsight",
        "git+https://github.com/cclgroupltd/ccl_chromium_reader.git"
    ];
    for pip in pips.iter() {
        let msg = format!("Python installing: {}", pip);
        prog_spin_msg(&pb3, msg.to_string());    
        let (code, output, error) = run_script::run_script!(
            r#"
            tool_path="$1"
            . $tool_path/venv/bin/activate
            python -m pip install -U $2
            "#,
            &vec![tool_path_str.to_string(), pip.to_string()],
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
        "https://github.com/williballenthin/shellbags",
        "https://github.com/Velocidex/velociraptor"
    ];
    for url in urls.iter() {
        let msg = format!("Getting: {}", url);
        prog_spin_msg(&pb3, msg.to_string());    
    	let (code, output, error) = run_script::run_script!(
            r#"
    	     github_token="$1"
             url="$2"
             tool_path="$3"
             . $tool_path/venv/bin/activate
             python ./setup_get_git.py $github_token $url linux
             "#,
             &vec![github_token.clone(), url.to_string(), tool_path_str.to_string()],
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
         tool_dir="$1"
         cd "$tool_dir/loki"
         $tool_dir/venv/bin/python3 loki-upgrader.py
         "#,
         &vec![tool_path_str.to_string()],
         &options
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));

    prog_spin_msg(&pb2, "Getting Chainsaw shimcache patterns...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
         tool_dir="$1"
         wget -nv "https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/analysis/shimcache_patterns.txt" -O "$tool_dir/shimcache_patterns.txt"
         "#,
         &vec![tool_path_str.to_string()],
         &options
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));

    prog_spin_msg(&pb2, "Installing Vector...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
         tool_dir="$1"
         curl --proto '=https' --tlsv1.2 -sSfL https://sh.vector.dev | bash -s -- -y
         wget -nv https://aka.ms/downloadazcopy-v10-linux
         tar -xvf downloadazcopy-v10-linux
         mv "$tool_dir"/azcopy_linux_amd64_* "$tool_dir"/azcopy
         ln -s "$tool_dir"/azcopy/azcopy "$tool_dir"/azcopy/azcopy.exe
         rm -rf downloadazcopy-v10-linux
         ln -s "`which 7z`" /usr/bin/7z.exe
         exit 0
         "#,
         &vec![tool_path_str.to_string()],
         &options
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));

    prog_spin_msg(&pb2, "Installing dotnet9...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
        toolpath=$1
        wget -nv https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
        chmod +x dotnet-install.sh
        ./dotnet-install.sh --channel 9.0 --install-dir "$toolpath/.dotnet"
         "#,
         &vec![tool_path_str.to_string()],
         &options
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));

    prog_spin_msg(&pb2, "Installing eztools...".to_string());
    let ez_path = &tool_path.join("Get-ZimmermanTools").join("net9");
    let ez_path_str = &ez_path.clone().into_os_string().into_string().unwrap();
    make_folders(&ez_path);
    let eztools = vec![
        "AmcacheParser",
        "AppCompatCacheParser",
        "bstrings",
        "EvtxECmd",
        "EZViewer",
        "JLECmd",
        "JumpListExplorer",
        "LECmd",
        "MFTECmd",
        "MFTExplorer",
        "PECmd",
        "RBCmd",
        "RecentFileCacheParser",
        "RECmd",
        "RegistryExplorer",
        "RLA",
        "SDBExplorer",
        "SBECmd",
        "ShellBagsExplorer",
        "SQLECmd",
        "SrumECmd",
        "SumECmd",
        "TimelineExplorer",
        "VSCMount",
        "WxTCmd"
    ];
    for eztool in eztools.iter() {
        let msg = format!("Downloading EZTool: {}", eztool);
        prog_spin_msg(&pb3, msg.to_string());    
    	let (code, output, error) = run_script::run_script!(
            r#"
             ezpath="$1"
             eztool="$2"
             wget -nv "https://download.ericzimmermanstools.com/net9/$eztool.zip" -O "$ezpath/$eztool.zip"
             7z x -r -aoa "$ezpath/$eztool.zip" -o"$ezpath/"
             rm "$ezpath/$eztool.zip"
             "#,
             &vec![ez_path_str.to_string(), eztool.to_string()],
             &options
        ).unwrap();
        outmsg.push_str(&output_script(v, code, output, error));
    }

    // Change directory back to what it was before setup
    env::set_current_dir(main_path)?;
    prog_spin_stop(&pb2, "".to_string());

    prog_spin_stop(&pb, "[ ] Setup complete".to_string());
    print!("{}", outmsg);

    Ok(())
}

pub fn setup_win(v: bool, github_token: String, tool_path: &Path) -> io::Result<()> {
    // Setup progress bars    
    let m = MultiProgress::new();
    let pb = prog_spin_init(960, &m, "magenta");
    let pb2 = prog_spin_init(480, &m, "yellow");
    prog_spin_msg(&pb, "Wiskess - Setup Windows".to_string());
    prog_spin_msg(&pb2, "Installing packages...".to_string());
    
    // start the log
    let setup_log_path = Path::new("wiskess_setup.log");
    start_setup_log(setup_log_path);
    
        // change director to tool_path
    let main_path = env::current_dir()?;
    env::set_current_dir(tool_path)?;

    let mut outmsg = String::new();
    let options = ScriptOptions::new();
    let (code, output, error) = run_script::run_script!(
        r#"
        @echo off
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
        RefreshEnv.cmd
        "#
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));
    
    prog_spin_msg(&pb2, "Installing from choco repo: git, 7zip, fdfind, osfmount, arsenalimagemounter, awscli, jq, python and ripgrep...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
        @echo off
        choco install -y git 7zip fd osfmount awscli jq arsenalimagemounter python
        choco install -y --force ripgrep
        set PATH=%PATH%;C:\Program Files\Git\cmd\
        RefreshEnv.cmd
        "#
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));
    
    prog_spin_msg(&pb2, "Getting Python-Cim and Azcopy...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
        @echo off
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
            @echo off
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
        "https://github.com/MarkBaggett/srum-dump.git"
    ];
    for url in urls.iter() {
        let msg = format!("Getting: {}", url);
        prog_spin_msg(&pb3, msg.to_string());    
    	let (code, output, error) = run_script::run_script!(
            r#"
            @echo off
            py ./setup_get_git.py %1 %2 windows
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
         "https://github.com/keydet89/RegRipper3.0.git",
    ];
    for repo in repos.iter() {
        let msg = format!("Cloning: {}", repo);
        prog_spin_msg(&pb3, msg.to_string());    
    	let (code, output, error) = run_script::run_script!(
            r#"
            @echo off
            set PATH=%PATH%;C:\Program Files\Git\cmd\
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
        @echo off
         .\loki-upgrader.exe
         "#
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));
    // change directory to tool_path
    env::set_current_dir(tool_path)?;

    prog_spin_msg(&pb2, "Getting EZTools and Chainsaw shimcache patterns...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
        @echo off
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "& .\Get-ZimmermanTools\Get-ZimmermanTools.ps1 -NetVersion 9 -Dest .\Get-ZimmermanTools"
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/analysis/shimcache_patterns.txt' -OutFile .\shimcache_patterns.txt"
        "#
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));

    prog_spin_msg(&pb2, "Installing dotnet9...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
        @echo off
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "invoke-WebRequest -Uri "https://download.visualstudio.microsoft.com/download/pr/b0032fde-aac9-4c3e-b78c-4bd605910241/8d2aa21baac4aef9b996671cd8a48fb2/dotnet-sdk-9.0.202-win-x64.exe" -OutFile "dotnet-sdk-9.0.202-win-x64.exe" -UseBasicParsing"
        .\dotnet-sdk-9.0.202-win-x64.exe /install /passive
        "#
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));

    // Change directory back to what it was before setup
    env::set_current_dir(main_path)?;

    prog_spin_stop(&pb2, "".to_string());

    let msg = format!("[ ] Setup completed. Please check the setup log for any errors: {}", setup_log_path.display());
    prog_spin_stop(&pb, msg);
    file_ops::log_msg(setup_log_path, outmsg);

Ok(())
}

/// check_installed see if the packages are installed, otherwise inform user how to install
/// will run commands using a switch like -v or -h to see if there's no error
/// will also check if files exist under the tools folder
pub fn check_installed(tool_path: &Path) {
    println!("[ ] Checking wiskess setup installed binaries and packages...");
    // list of binaries to check on OS path
    let exe_on_path = ["choco", "py", "7z", "git", "fd", "C:\\Program Files\\OSFMount\\OSFMount.com", "aws", "jq", "arsenalimagemounter", "rg", "pwsh"];
    let err_list: Vec<&str> = exe_on_path
        .into_iter()
        .filter(|b| exe_ops::installed_binary_check(true, &b.to_string()) != "")
        .collect();
    // list of tools to check exist under the folder wiskess/tools
    // if err_list is empty tell user setup OK
    if err_list.len() == 0 {
        println!("[+] Check complete. Wiskess is setup OK.")
    } else {
        // loop through err_list and inform user of those that failed to install or are not on the path
        println!("[ ] Please check the installation of: ");
        err_list.into_iter().for_each(|b| println!("    {b}"));
    }
}