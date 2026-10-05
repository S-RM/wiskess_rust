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

        // The run writes into two directories, and which file goes where is the
        // point. Triage/ is for a human opening the folder; Timeline/ is what the
        // worker ingests, and it ingests by filename — every entry ending in
        // `json`, nothing else. This used to assert the markdown report was in
        // Timeline/, which nothing has ever written there.
        let names = |dir: &std::path::Path| -> Vec<String> {
            std::fs::read_dir(dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        };

        let triage = names(&out_path.join("Triage"));
        for suffix in ["_triage_report.md", "_supertimeline.csv", "_triage_timeline.csv"] {
            assert!(
                triage.iter().any(|n| n.ends_with(suffix)),
                "expected a *{suffix} in Triage/, saw {triage:?}"
            );
        }

        // All four ingestible documents, in the one directory the worker reads.
        // Three of them were being written into Triage/ instead, where nothing
        // looks, and the report NDJSON was not produced at all.
        let ingested: Vec<String> = names(&timeline_dir)
            .into_iter()
            .filter(|n| n.ends_with("json") && !n.ends_with("jsonl"))
            .collect();
        for suffix in ["_triage.json", "_triage_report.json", "_restoration.json"] {
            assert!(
                ingested.iter().any(|n| n.ends_with(suffix)),
                "expected a *{suffix} in Timeline/, saw {ingested:?}"
            );
        }
    }
}
