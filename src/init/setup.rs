use std::{env, io, path::{Path, PathBuf}, process::exit, time::Duration};
use chrono::Utc;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use inquire::Text;
use regex::Regex;
use run_script::ScriptOptions;
use ureq::Agent;

use crate::ops::{exe_ops, file_ops::{self, make_folders}};
// extern crate git2;
// use git2::Repository;

/// The result of checking a GitHub personal access token against the GitHub API
#[derive(Debug, PartialEq)]
pub enum TokenCheck {
    /// GitHub accepted the token
    Valid,
    /// GitHub rejected the token, with the reason to show the user
    Invalid(String),
    /// The check couldn't be completed, i.e. no network
    Unknown(String),
}

/// check the token looks like a fine-grained personal access token
pub fn is_github_token_format(token: &str) -> bool {
    Regex::new(r"^github_pat_").unwrap().is_match(token)
}

/// map the HTTP status of the GitHub API response to a token check outcome
pub fn classify_github_status(code: u32) -> TokenCheck {
    match code {
        200 => TokenCheck::Valid,
        401 => TokenCheck::Invalid(
            "bad credentials - the token is invalid, expired or has been revoked".to_string()
        ),
        403 | 429 => TokenCheck::Unknown(
            "GitHub rate limited or blocked the request".to_string()
        ),
        _ => TokenCheck::Unknown(format!("unexpected HTTP status {}", code)),
    }
}

/// ask the GitHub API for the rate limit, a lightweight endpoint that doesn't use up any quota
fn github_api_status(token: &str) -> Result<u32, String> {
    let gh_api_str: &str = "https://api.github.com/rate_limit";
    let agent = Agent::new_with_config(
        Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(15)))
            .build()
    );
    match agent.get(gh_api_str)
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {}", token))
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "wiskess")
        .call()
    {
        Ok(response) => Ok(response.status().as_u16() as u32),
        // the api replied, but with an error status, i.e. 401 when the token is no good
        Err(ureq::Error::StatusCode(code)) => Ok(code as u32),
        // no reply at all, i.e. no network or dns failure
        Err(e) => Err(format!("unable to reach {}: {}", gh_api_str, e)),
    }
}

/// check_github_token sees if the personal access token is accepted by the GitHub API
/// Args:
/// * `token` - the github personal access token supplied by the user
///
/// returns whether the token is valid, invalid or couldn't be checked
pub fn check_github_token(token: &str) -> TokenCheck {
    if !is_github_token_format(token) {
        return TokenCheck::Invalid(
            "the token is either missing or doesn't start with `github_pat_`".to_string()
        );
    }
    match github_api_status(token) {
        Ok(code) => classify_github_status(code),
        Err(e) => TokenCheck::Unknown(e),
    }
}

/// ensure_valid_github_token checks the token before setup starts
/// Args:
/// * `token` - the github personal access token supplied by the user
/// * `silent` - no user input, so exit instead of prompting
///
/// returns a token that the GitHub API accepted, or that we were unable to check
pub fn ensure_valid_github_token(token: String, silent: bool) -> String {
    let mut token = token;
    for _ in 0..3 {
        println!("[ ] Checking the GitHub token with the GitHub API...");
        match check_github_token(&token) {
            TokenCheck::Valid => {
                println!("[+] GitHub token validated against the GitHub API");
                return token;
            },
            TokenCheck::Unknown(msg) => {
                println!("[!] Could not verify the GitHub token: {}. Continuing with setup.", msg);
                return token;
            },
            TokenCheck::Invalid(msg) => {
                println!("[!] The GitHub token was not accepted: {}", msg);
                println!("Setup needs a github token to download from public repos, if unsure how to setup see https://github.blog/2022-10-18-introducing-fine-grained-personal-access-tokens-for-github/");
                if silent {
                    println!("[!] Running in silent mode, unable to prompt for another token. Exiting.");
                    exit(1);
                }
                token = Text::new("Please enter your GitHub token (starts with github_pat_):")
                    .prompt()
                    .unwrap();
            },
        }
    }
    println!("[!] The GitHub token is still not valid. Please generate a new one and run setup again.");
    exit(1);
}

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
fn start_setup_log(setup_log_path: &PathBuf) {
    // Start logging 
    let date_time_fmt = "%Y-%m-%dT%H%M%S".to_string();
    let log_time = Utc::now();
    let log_time_str = log_time.format(&date_time_fmt).to_string();
    file_ops::log_msg(
        setup_log_path,
         format!("[SETUP] Starting the setup of wiskess tools at {}", log_time_str)
    );
}

pub fn setup_linux(v: bool, github_token: String, tool_path: &Path, update: bool) -> io::Result<()> {
    // Setup progress bars    
    let m = MultiProgress::new();
    let pb = prog_spin_init(960, &m, "magenta");
    let pb2 = prog_spin_init(480, &m, "yellow");
    prog_spin_msg(&pb, "Wiskess - Setup Linux".to_string());
    prog_spin_msg(&pb2, "Installing packages...".to_string());
    let mut outmsg = String::new();
    let options = ScriptOptions::new();

    // start the log
    let setup_log_path = tool_path.parent().unwrap().join("wiskess_setup.log");
    start_setup_log(&setup_log_path);

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
    // refresh the package lists so apt-get install upgrades packages already installed
    if update {
        let (code, output, error) = run_script::run_script!("apt-get -y update", &vec![], &options).unwrap();
        outmsg.push_str(&output_script(v, code, output, error));
    }
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

    // shellbags.pl, shellbags_tln.pl and comdlg32.pl scan a shell item byte by byte for the
    // 0xbeef extension block (and the NUL ending the short name) with no end-of-data check,
    // so a malformed item spins at 100% CPU forever. Bound each scan to the item length.
    // Idempotent - patched loops no longer match. Re-run setup after an apt upgrade of regripper.
    prog_spin_msg(&pb3, "Patching regripper plugins".to_string());
    let (code, output, error) = run_script::run_script!(
        r##"
         patch_expr='
         s/while\s*\(\$tag\)\s*\{(\s*if \(unpack\("v",substr\(\$data,\$ofs \+ \$cnt,2\)\) == 0xbeef\))/while (\$tag && \$ofs + \$cnt + 2 <= length(\$data)) {$1/g;
         s/while\s*\(\$tag\)\s*\{(\s*if \(unpack\("v",substr\(\$data,\$ofs,2\)\) == 0xbeef\))/while (\$tag && \$ofs + 2 <= length(\$data)) {$1/g;
         s/while\s*\(\$tag\)\s*\{(\s*my \$s = substr\(\$data,\$ofs_shortname \+ \$cnt,1\);)/while (\$tag && \$ofs_shortname + \$cnt < length(\$data)) {$1/g;
         '
         seen=""
         for d in /usr/share/regripper/plugins /usr/lib/regripper/plugins; do
             [ -d "$d" ] || continue
             real=$(readlink -f "$d")
             case " $seen " in *" $real "*) continue ;; esac
             seen="$seen $real"
             for f in shellbags.pl shellbags_tln.pl comdlg32.pl; do
                 [ -f "$real/$f" ] || continue
                 perl -0pi -e "$patch_expr" "$real/$f" && echo "Patched: $real/$f"
             done
         done
         [ -n "$seen" ] || echo "No regripper plugin directory found"
         "##,
         &vec![],
         &options
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));

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
        "git+https://github.com/cclgroupltd/ccl_chromium_reader.git",
        "fastexcel",
        "pyarrow"
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
    let update_arg = if update { "--update" } else { "" };
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
             python ./setup_get_git.py $github_token $url linux $4
             "#,
             &vec![github_token.clone(), url.to_string(), tool_path_str.to_string(), update_arg.to_string()],
             &options
        ).unwrap();
        outmsg.push_str(&output_script(v, code, output, error));
    }

    prog_spin_msg(&pb2, "Git cloning github repositories...".to_string());
    let repos = vec![
         "https://github.com/brimorlabs/KStrike",
         "https://github.com/ANSSI-FR/bmc-tools.git",
         "https://github.com/Neo23x0/loki.git",
         "https://github.com/williballenthin/shellbags",
    ];
    for repo in repos.iter() {
        let msg = format!("Cloning: {}", repo);
        prog_spin_msg(&pb3, msg.to_string());    
        outmsg.push_str(&output_script(v, 0, git_clone_or_pull(repo, update), String::new()));
    }

    prog_spin_msg(&pb2, "Git cloning srum-dump and installing requirements...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#" 
            tool_dir="$1"
            rm -rf "$tool_dir/srum-dump"
            git clone https://github.com/vividDuck/srum-dump
            cd "$tool_dir/srum-dump"
            $tool_dir/venv/bin/python3 -m pip install -r requirements.txt
            "#,
            &vec![tool_path_str.to_string()],
            &options
    ).unwrap();
    outmsg.push_str(&output_script(v, code, output, error));

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
    let ez_path = &tool_path.join("Get-ZimmermanTools").join("net");
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
             wget -nv "https://download.ericzimmermanstools.com/net/$eztool.zip" -O "$ezpath/$eztool.zip"
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

pub fn setup_win(v: bool, github_token: String, tool_path: &Path, update: bool) -> io::Result<()> {
    // Setup progress bars    
    let m = MultiProgress::new();
    let pb = prog_spin_init(960, &m, "magenta");
    let pb2 = prog_spin_init(480, &m, "yellow");
    prog_spin_msg(&pb, "Wiskess - Setup Windows".to_string());
    prog_spin_msg(&pb2, "Installing packages...".to_string());
    
    // start the log
    let setup_log_path = tool_path.parent().unwrap().join("wiskess_setup.log");
    start_setup_log(&setup_log_path);
    
        // change director to tool_path
    let main_path = env::current_dir()?;
    env::set_current_dir(tool_path)?;

    let options = ScriptOptions::new();
    let (code, output, error) = run_script::run_script!(
        r#"
        @echo off
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri 'https://download.visualstudio.microsoft.com/download/pr/2d6bb6b2-226a-4baa-bdec-798822606ff1/8494001c276a4b96804cde7829c04d7f/ndp48-x86-x64-allos-enu.exe' -OutFile '.\ndp48-x86-x64-allos-enu.exe' -UseBasicParsing"
        .\ndp48-x86-x64-allos-enu.exe /passive /AcceptEULA /norestart
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
        RefreshEnv.cmd
        "#
    ).unwrap();
    file_ops::log_msg(&setup_log_path, output_script(v, code, output, error));
    
    prog_spin_msg(&pb2, "Installing from choco repo: git, 7zip, fdfind, osfmount, arsenalimagemounter, awscli, jq, python, pwsh and ripgrep...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
        @echo off
        choco %1 -y git 7zip fd osfmount awscli jq arsenalimagemounter python pwsh dotnet-9.0-runtime
        choco install -y --force ripgrep
        set PATH=%PATH%;C:\Program Files\Git\cmd\
        RefreshEnv.cmd
        "#,
        // upgrade also installs any package that is missing
        &vec![if update { "upgrade" } else { "install" }.to_string()],
        &ScriptOptions::new()
    ).unwrap();
    file_ops::log_msg(&setup_log_path, output_script(v, code, output, error));
    
    prog_spin_msg(&pb2, "Getting Azcopy...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
        @echo off
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri 'https://aka.ms/downloadazcopy-v10-windows' -OutFile '.\AzCopy.zip' -UseBasicParsing"
        7z e ".\AzCopy.zip" -o"azcopy\" azcopy.exe -r -aoa
        del ".\AzCopy.zip"
        "#
    ).unwrap();
    file_ops::log_msg(&setup_log_path, output_script(v, code, output, error));

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
        "fastexcel",
        "pyarrow"
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
        file_ops::log_msg(&setup_log_path, output_script(v, code, output, error));
    }

    prog_spin_msg(&pb2, "Getting latest releases of tools from github...".to_string());
    let update_arg = if update { "--update" } else { "" };
    let urls = vec![
        "https://github.com/countercept/chainsaw",
        "https://github.com/Yamato-Security/hayabusa",
        "https://github.com/omerbenamram/evtx.git",
        "https://github.com/omerbenamram/mft",
	    "https://github.com/forensicmatt/RustyUsn",
        "https://github.com/obsidianforensics/hindsight.git",
        "https://github.com/Neo23x0/loki.git",
        "https://github.com/MarkBaggett/srum-dump.git",
        "https://github.com/Velocidex/velociraptor"
    ];
    for url in urls.iter() {
        let msg = format!("Getting: {}", url);
        prog_spin_msg(&pb3, msg.to_string());    
    	let (code, output, error) = run_script::run_script!(
            r#"
            @echo off
            py ./setup_get_git.py %1 %2 windows %3
            "#,
            &vec![github_token.clone(), url.to_string(), update_arg.to_string()],
            &options
        ).unwrap();
        file_ops::log_msg(&setup_log_path, output_script(v, code, output, error));
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
        file_ops::log_msg(&setup_log_path, output_script(v, 0, git_clone_or_pull(repo, update), String::new()));
    }

    // same shellbags/comdlg32 infinite-loop patch as setup_linux, done in Rust as perl is not on Windows
    prog_spin_msg(&pb3, "Patching regripper plugins".to_string());
    let plugin_dir = tool_path.join("RegRipper3.0").join("plugins");
    file_ops::log_msg(&setup_log_path, patch_regripper_plugins(&plugin_dir).join("\n"));

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
    file_ops::log_msg(&setup_log_path, output_script(v, code, output, error));
    // change directory to tool_path
    env::set_current_dir(tool_path)?;

    prog_spin_msg(&pb2, "Getting EZTools and Chainsaw shimcache patterns...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
        @echo off
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "& .\Get-ZimmermanTools\Get-ZimmermanTools.ps1 -NetVersion 9 -Dest .\Get-ZimmermanTools"
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/analysis/shimcache_patterns.txt' -OutFile .\shimcache_patterns.txt"
        "#
    ).unwrap();
    file_ops::log_msg(&setup_log_path, output_script(v, code, output, error));

    prog_spin_msg(&pb2, "Installing dotnet9...".to_string());
    let (code, output, error) = run_script::run_script!(
        r#"
        @echo off
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "$ProgressPreference = 'SilentlyContinue'; invoke-WebRequest -Uri "https://download.visualstudio.microsoft.com/download/pr/b0032fde-aac9-4c3e-b78c-4bd605910241/8d2aa21baac4aef9b996671cd8a48fb2/dotnet-sdk-9.0.202-win-x64.exe" -OutFile "dotnet-sdk-9.0.202-win-x64.exe" -UseBasicParsing"
        .\dotnet-sdk-9.0.202-win-x64.exe /install /passive
        "#
    ).unwrap();
    file_ops::log_msg(&setup_log_path, output_script(v, code, output, error));

    // Change directory back to what it was before setup
    env::set_current_dir(main_path)?;

    prog_spin_stop(&pb2, "".to_string());

    let msg = format!("[ ] Setup completed. Please check the setup log for any errors: {}", setup_log_path.display());
    prog_spin_stop(&pb, msg);

Ok(())
}

/// Folder name git clone makes for a repo url, i.e. RegRipper3.0 from .../RegRipper3.0.git
pub fn repo_dir_name(repo: &str) -> String {
    let name = repo.trim_end_matches('/').rsplit('/').next().unwrap_or(repo);
    name.strip_suffix(".git").unwrap_or(name).to_string()
}

/// Clone the repo into the current directory, or when update is set and it is already
/// cloned, fast-forward it to the latest commit. Returns the output for the setup log.
fn git_clone_or_pull(repo: &str, update: bool) -> String {
    // choco has just installed git, so it may not be on this process's PATH yet
    let git = if cfg!(windows) && std::process::Command::new("git").arg("--version").output().is_err() {
        r"C:\Program Files\Git\cmd\git.exe"
    } else {
        "git"
    };
    let dir = repo_dir_name(repo);
    let mut cmds: Vec<Vec<&str>> = vec![];
    if !Path::new(&dir).join(".git").exists() {
        cmds.push(vec!["clone", repo]);
    } else if update {
        // undo the wiskess plugin patches so the pull can't conflict, they are re-applied after
        if dir.eq_ignore_ascii_case("RegRipper3.0") {
            cmds.push(vec!["-C", &dir, "checkout", "--", "plugins/shellbags.pl", "plugins/shellbags_tln.pl", "plugins/comdlg32.pl"]);
        }
        cmds.push(vec!["-C", &dir, "pull", "--ff-only"]);
    } else {
        return format!("[ ] {dir} already cloned, use setup --update to pull the latest");
    }
    let mut out = String::new();
    for args in cmds {
        match std::process::Command::new(git).args(&args).output() {
            Ok(o) => out.push_str(&format!("[ ] git {}\n{}{}",
                args.join(" "),
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr))),
            Err(e) => out.push_str(&format!("[!] Unable to run git {}: {e}\n", args.join(" "))),
        }
    }
    out
}

/// Bound the 0xbeef / short name scans in shellbags.pl, shellbags_tln.pl and comdlg32.pl to the
/// shell item length, so a malformed item can't spin rip at 100% CPU forever. Mirrors the perl
/// patch in setup_linux. Idempotent - patched loops no longer match. Returns a log line per file.
pub fn patch_regripper_plugins(plugin_dir: &Path) -> Vec<String> {
    let patches = [
        (r#"while\s*\(\$tag\)\s*\{(\s*if \(unpack\("v",substr\(\$data,\$ofs \+ \$cnt,2\)\) == 0xbeef\))"#,
         "while ($$tag && $$ofs + $$cnt + 2 <= length($$data)) {${1}"),
        (r#"while\s*\(\$tag\)\s*\{(\s*if \(unpack\("v",substr\(\$data,\$ofs,2\)\) == 0xbeef\))"#,
         "while ($$tag && $$ofs + 2 <= length($$data)) {${1}"),
        (r#"while\s*\(\$tag\)\s*\{(\s*my \$s = substr\(\$data,\$ofs_shortname \+ \$cnt,1\);)"#,
         "while ($$tag && $$ofs_shortname + $$cnt < length($$data)) {${1}"),
    ];
    if !plugin_dir.is_dir() {
        return vec![format!("No regripper plugin directory found: {}", plugin_dir.display())];
    }
    let mut msgs = vec![];
    for f in ["shellbags.pl", "shellbags_tln.pl", "comdlg32.pl"] {
        let path = plugin_dir.join(f);
        // plugins can contain non-utf8 bytes, so patch as bytes
        let Ok(data) = std::fs::read(&path) else { continue };
        let mut patched = data.clone();
        for (re, rep) in patches.iter() {
            patched = regex::bytes::Regex::new(re).unwrap().replace_all(&patched, rep.as_bytes()).into_owned();
        }
        if patched == data {
            msgs.push(format!("Already patched: {}", path.display()));
        } else {
            match std::fs::write(&path, &patched) {
                Ok(_) => msgs.push(format!("Patched: {}", path.display())),
                Err(e) => msgs.push(format!("Failed to patch {}: {}", path.display(), e)),
            }
        }
    }
    msgs
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
    let exe_in_tools = [
        "azcopy\\azcopy.exe",
        "chainsaw\\chainsaw.exe",
        "evtx\\evtx.exe",
        "Get-ZimmermanTools\\net\\MFTECmd.exe",
        "Get-ZimmermanTools\\net\\AmcacheParser.exe",
        "Get-ZimmermanTools\\net\\SrumECmd.exe",
        "Get-ZimmermanTools\\net\\SumECmd.exe",
        "Get-ZimmermanTools\\net\\SBECmd.exe",
        "Get-ZimmermanTools\\net\\LECmd.exe",
        "Get-ZimmermanTools\\net\\JLECmd.exe",
        "RustyUsn\\RustyUsn.exe",
        "RegRipper3.0\\rip.exe",
        "mft\\mft.exe",
        "loki\\loki.exe",
        "hayabusa\\hayabusa.exe",
        "velociraptor\\velociraptor.exe",
    ];
    // check each tool in the list, if it exists on filesystem, try to run it, collecting only failed ones
    let err_list_tools: Vec<&str> = exe_in_tools
        .into_iter()
        .filter(|b| {
            let file_path = tool_path.join(b);
            match file_path.exists() {
                true => {
                    let file_path_str = &file_path.into_os_string().into_string().unwrap();
                    exe_ops::installed_binary_check(true, file_path_str) != ""
                },
                false => true,
            }
        })
        .collect();

    // if err_list is empty tell user setup OK
    if err_list.len() == 0 && err_list_tools.len() == 0 {
        println!("[+] Check complete. Wiskess is setup OK.")
    }
    
    if err_list.len() != 0 {
        // loop through err_list and inform user of those that failed to install or are not on the path
        println!("[ ] Please check the installation of these programs: ");
        err_list.into_iter().for_each(|b| println!("    {b}"));
        println!("[?] Please first try closing and re-opening your terminal, then run `wiskess_rust.exe setup -c` to check the setup has worked.");
        println!("   If that still reports missing packages: You can either try running setup again, installing them individually with `choco install <program>, or find them with a search engine, i.e. Google, Bing, DuckDuckGo, etc.");
    }

    if err_list_tools.len() != 0 {
        // loop through err_list and inform user of those that failed to install or are not on the path
        println!("[ ] Please check the installation of these programs: ");
        err_list_tools.into_iter().for_each(|b| println!("    {b}"));
        println!("[?] You can either try running setup again, or download or clone the latest release from github");
    }
}