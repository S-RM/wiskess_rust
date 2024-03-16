pub fn setup_linux() {
    // simple call to run script with only the script text
    let (code, output, error) = run_script::run_script!(
        r#"
         echo "[+] Wiskess - Setup Linux"
         tool_dir="$PWD/tools/"
         cd $tool_dir
         sudo apt-get -y install p7zip-full awscli fd-find git ripgrep python2.7
         python3 -m pip install polars chardet datetime filetype requests --no-warn-script-location
         echo "[ ] Installing tools from github"
         for url in 'https://github.com/countercept/chainsaw' 'https://github.com/Yamato-Security/hayabusa' 'https://github.com/omerbenamram/evtx.git' 'https://github.com/omerbenamram/mft'
         do
           python3 $tool_dir/setup_get_git.py "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" $url "linux"
         done
         echo "[ ] Installing Loki and dependencies"
         python3 -m pip install colorama yara-python psutil rfc5424-logging-handler netaddr --no-warn-script-location
         git clone https://github.com/Neo23x0/Loki.git "$tool_dir/loki"
         cd "$tool_dir/loki"
         python3 loki-upgrader.py
         cd $tool_dir
         echo "[ ] Getting Chainsaw shimcache patterns"
         wget "https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/analysis/shimcache_patterns.txt" -O "$tool_dir/shimcache_patterns.txt"
         echo "[ ] Installing Vector"
         curl --proto '=https' --tlsv1.2 -sSfL https://sh.vector.dev | bash -s -- -y
         # TODO: azcopy
         exit 0
         "#
    )
    .unwrap();

    println!("Exit Code: {}", code);
    println!("Output: {}", output);
    println!("Error: {}", error);
}
