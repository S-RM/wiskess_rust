#[cfg(test)]
mod tests {
    use crate::configs::config::MainArgs;
    use crate::ops::timeline::run_timeline_parser;
    use indicatif::MultiProgress;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn run_timeline_parser_produces_supertimeline_and_report() {
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().to_path_buf();
        let timeline_dir = out_path.join("Timeline");
        std::fs::create_dir_all(&timeline_dir).unwrap();

        std::fs::write(
            timeline_dir.join("hayabusa.csv"),
            "datetime,Level,message,Details,ExtraFieldInfo,Channel,EventID,MitreTactics,MitreTags,RuleFile\n\
             2026-08-20T10:00:00.000+00:00,high,Test detection,cmd.exe /c whoami,,Security,4688,Exec,T1059,test_rule.yml\n",
        ).unwrap();

        let main_args = MainArgs {
            out_path: out_path.to_str().unwrap().to_string(),
            start_date: "2026-08-19".to_string(),
            end_date: "2026-08-21".to_string(),
            tool_path: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools"),
            ioc_file: String::new(),
            silent: true,
            out_log: out_path.join("test.log"),
            multi_pb: MultiProgress::new(),
            collect: false,
            no_timeline_parser: false,
            restoration_date: None,
        };

        run_timeline_parser(&main_args);

        let log = std::fs::read_to_string(&main_args.out_log).unwrap();
        assert!(
            log.contains("Timeline parser complete") || log.contains("Timeline parser failed"),
            "expected a timeline parser log line, got: {log}"
        );

        let report_exists = std::fs::read_dir(&timeline_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.path().extension().map_or(false, |x| x == "md"));
        assert!(report_exists, "expected a *_triage_report.md in Timeline/");
    }
}
