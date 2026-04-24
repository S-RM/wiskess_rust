#[cfg(test)]
mod tests {
    use clap::Parser;

    /// Mock Args struct for testing - mirrors main.rs Args
    #[derive(Parser, Debug)]
    #[command(author, version, about, long_about = None)]
    struct TestArgs {
        #[arg(short, long, default_value = "")]
        tool_path: String,
        #[arg(short, long, action = clap::ArgAction::SetTrue)]
        silent: bool,
        #[clap(subcommand)]
        command: TestCommands,
        #[arg(short, long, action = clap::ArgAction::SetFalse)]
        no_collection: bool
    }

    #[derive(Debug, clap::Subcommand)]
    enum TestCommands {
        Setup {
            #[arg(short, long, default_value = "")]
            github_token: String,
            #[arg(short, long, action = clap::ArgAction::SetTrue)]
            verbose: bool,
            #[arg(short, long, action = clap::ArgAction::SetTrue)]
            check_install: bool,
        },
        Wiskess {
            #[arg(short, long, default_value = "main.yaml")]
            config: std::path::PathBuf,
            #[arg(short, long, default_value = "artefacts.yaml")]
            artefacts_config: std::path::PathBuf,
            #[arg(short, long)]
            data_source: String,
            #[arg(short, long)]
            out_path: String,
            #[arg(long)]
            start_date: String,
            #[arg(long)]
            end_date: String,
            #[arg(short, long)]
            ioc_file: String,
        },
        Whipped {
            #[arg(short, long, default_value = "main.yaml")]
            config: std::path::PathBuf,
            #[arg(short, long, default_value = "artefacts.yaml")]
            artefacts_config: std::path::PathBuf,
            #[arg(short, long, default_value = "")]
            data_source_list: String,
            #[arg(short, long)]
            local_storage: String,
            #[arg(long)]
            start_date: String,
            #[arg(long)]
            end_date: String,
            #[arg(short, long, default_value = "iocs.txt")]
            ioc_file: String,
            #[arg(long)]
            in_link: String,
            #[arg(long)]
            out_link: String,
            #[arg(short, long)]
            update: bool,
            #[arg(short, long)]
            keep_evidence: bool,
        },
    }

    /// Test parsing Setup command with all flags
    #[test]
    fn test_parse_setup_command_full() {
        let args = vec![
            "wiskess",
            "setup",
            "-g", "github_pat_testtoken123",
            "-v",
            "-c"
        ];

        let parsed = TestArgs::try_parse_from(args);

        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();

        match parsed.command {
            TestCommands::Setup { github_token, verbose, check_install } => {
                assert_eq!(github_token, "github_pat_testtoken123");
                assert_eq!(verbose, true);
                assert_eq!(check_install, true);
            }
            _ => panic!("Expected Setup command"),
        }
    }

    /// Test parsing Setup command with minimal args
    #[test]
    fn test_parse_setup_command_minimal() {
        let args = vec!["wiskess", "setup"];

        let parsed = TestArgs::try_parse_from(args);

        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();

        match parsed.command {
            TestCommands::Setup { github_token, verbose, check_install } => {
                assert_eq!(github_token, "");
                assert_eq!(verbose, false);
                assert_eq!(check_install, false);
            }
            _ => panic!("Expected Setup command"),
        }
    }

    /// Test parsing Wiskess command with all required args
    #[test]
    fn test_parse_wiskess_command() {
        let args = vec![
            "wiskess",
            "wiskess",
            "-d", "/mnt/evidence/dc01",
            "-o", "/cases/output",
            "--start-date", "2023-01-01",
            "--end-date", "2023-12-31",
            "-i", "iocs.txt"
        ];

        let parsed = TestArgs::try_parse_from(args);

        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();

        match parsed.command {
            TestCommands::Wiskess { data_source, out_path, start_date, end_date, ioc_file, .. } => {
                assert_eq!(data_source, "/mnt/evidence/dc01");
                assert_eq!(out_path, "/cases/output");
                assert_eq!(start_date, "2023-01-01");
                assert_eq!(end_date, "2023-12-31");
                assert_eq!(ioc_file, "iocs.txt");
            }
            _ => panic!("Expected Wiskess command"),
        }
    }

    /// Test parsing Wiskess command with default config values
    #[test]
    fn test_parse_wiskess_command_default_configs() {
        let args = vec![
            "wiskess",
            "wiskess",
            "-d", "/mnt/evidence",
            "-o", "/output",
            "--start-date", "2023-01-01",
            "--end-date", "2023-12-31",
            "-i", "iocs.txt"
        ];

        let parsed = TestArgs::try_parse_from(args);

        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();

        match parsed.command {
            TestCommands::Wiskess { config, artefacts_config, .. } => {
                assert_eq!(config.to_str().unwrap(), "main.yaml");
                assert_eq!(artefacts_config.to_str().unwrap(), "artefacts.yaml");
            }
            _ => panic!("Expected Wiskess command"),
        }
    }

    /// Test parsing Whipped command with all args
    #[test]
    fn test_parse_whipped_command_full() {
        let args = vec![
            "wiskess",
            "whipped",
            "-d", "host1.vmdk,host2.e01",
            "-l", "/tmp/storage",
            "--start-date", "2023-06-01",
            "--end-date", "2023-06-30",
            "--in-link", "s3://bucket/evidence",
            "--out-link", "s3://bucket/results",
            "-u",
            "-k"
        ];

        let parsed = TestArgs::try_parse_from(args);

        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();

        match parsed.command {
            TestCommands::Whipped {
                data_source_list,
                local_storage,
                start_date,
                end_date,
                in_link,
                out_link,
                update,
                keep_evidence,
                ..
            } => {
                assert_eq!(data_source_list, "host1.vmdk,host2.e01");
                assert_eq!(local_storage, "/tmp/storage");
                assert_eq!(start_date, "2023-06-01");
                assert_eq!(end_date, "2023-06-30");
                assert_eq!(in_link, "s3://bucket/evidence");
                assert_eq!(out_link, "s3://bucket/results");
                assert_eq!(update, true);
                assert_eq!(keep_evidence, true);
            }
            _ => panic!("Expected Whipped command"),
        }
    }

    /// Test parsing Whipped command with Azure links
    #[test]
    fn test_parse_whipped_command_azure() {
        let args = vec![
            "wiskess",
            "whipped",
            "-l", "/storage",
            "--start-date", "2023-01-01",
            "--end-date", "2023-12-31",
            "--in-link", "https://account.blob.core.windows.net/container?sig=xyz",
            "--out-link", "https://account.blob.core.windows.net/results?sig=abc"
        ];

        let parsed = TestArgs::try_parse_from(args);

        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();

        match parsed.command {
            TestCommands::Whipped { in_link, out_link, .. } => {
                assert!(in_link.contains("blob.core.windows.net"));
                assert!(out_link.contains("blob.core.windows.net"));
            }
            _ => panic!("Expected Whipped command"),
        }
    }

    /// Test tool_path flag
    #[test]
    fn test_parse_tool_path_flag() {
        let args = vec![
            "wiskess",
            "-t", "/custom/tools",
            "setup"
        ];

        let parsed = TestArgs::try_parse_from(args);

        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.tool_path, "/custom/tools");
    }

    /// Test silent flag
    #[test]
    fn test_parse_silent_flag() {
        let args = vec![
            "wiskess",
            "-s",
            "setup"
        ];

        let parsed = TestArgs::try_parse_from(args);

        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.silent, true);
    }

    /// Test no_collection flag
    #[test]
    fn test_parse_no_collection_flag() {
        let args = vec![
            "wiskess",
            "-n",
            "setup"
        ];

        let parsed = TestArgs::try_parse_from(args);

        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.no_collection, false); // SetFalse action
    }

    /// Test missing required arguments returns error
    #[test]
    fn test_parse_wiskess_missing_required() {
        let args = vec![
            "wiskess",
            "wiskess",
            "-d", "/evidence"
            // missing: out_path, start_date, end_date, ioc_file
        ];

        let parsed = TestArgs::try_parse_from(args);

        // should fail due to missing required arguments
        assert!(parsed.is_err());
    }

    /// Test missing required arguments for whipped
    #[test]
    fn test_parse_whipped_missing_required() {
        let args = vec![
            "wiskess",
            "whipped",
            "-l", "/storage"
            // missing: start_date, end_date, in_link, out_link
        ];

        let parsed = TestArgs::try_parse_from(args);

        // should fail due to missing required arguments
        assert!(parsed.is_err());
    }

    /// Test invalid command returns error
    #[test]
    fn test_parse_invalid_command() {
        let args = vec![
            "wiskess",
            "invalid_command"
        ];

        let parsed = TestArgs::try_parse_from(args);

        // should fail due to invalid subcommand
        assert!(parsed.is_err());
    }
}
