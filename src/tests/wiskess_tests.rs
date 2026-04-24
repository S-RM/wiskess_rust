#[cfg(test)]
mod tests {
    use crate::ops::wiskess;
    use crate::configs::config::MainArgs;
    use std::path::PathBuf;
    use indicatif::MultiProgress;
    use tempfile::TempDir;

    /// Helper function to create test MainArgs
    fn create_test_args(out_path: String) -> MainArgs {
        MainArgs {
            out_path,
            start_date: "2023-01-01".to_string(),
            end_date: "2023-12-31".to_string(),
            tool_path: PathBuf::from("/tmp/tools"),
            ioc_file: "test_iocs.txt".to_string(),
            silent: true,
            collect: false,
            out_log: PathBuf::from("/tmp/test.log"),
            multi_pb: MultiProgress::new()
        }
    }

    /// Test init_wiskess creates output directory
    #[test]
    fn test_init_wiskess_creates_directory() {
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().join("wiskess_output");

        let args = create_test_args(out_path.to_str().unwrap().to_string());

        let (_date_fmt, _start_time, main_args) = wiskess::init_wiskess(args);

        // should create the output directory
        assert!(out_path.exists());
        assert!(out_path.is_dir());

        // should set dates correctly
        assert_eq!(main_args.start_date, "2023-01-01");
        assert_eq!(main_args.end_date, "2023-12-31");
    }

    /// Test init_wiskess creates log file
    #[test]
    fn test_init_wiskess_creates_log() {
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().join("log_test");

        let args = create_test_args(out_path.to_str().unwrap().to_string());

        let (_date_fmt, _start_time, main_args) = wiskess::init_wiskess(args);

        // log file should exist in output directory
        assert!(main_args.out_log.exists());
        assert!(main_args.out_log.to_str().unwrap().starts_with(out_path.to_str().unwrap()));
    }

    /// Test init_wiskess validates and formats dates
    #[test]
    fn test_init_wiskess_date_validation() {
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().join("date_test");

        let mut args = create_test_args(out_path.to_str().unwrap().to_string());
        args.start_date = "2023-06-15".to_string();
        args.end_date = "2023-12-31".to_string();

        let (_date_fmt, _start_time, main_args) = wiskess::init_wiskess(args);

        // dates should be validated
        assert_eq!(main_args.start_date, "2023-06-15");
        assert_eq!(main_args.end_date, "2023-12-31");
    }

    /// Test end_wiskess calculates duration
    #[test]
    fn test_end_wiskess_duration_calculation() {
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().join("duration_test");

        let args = create_test_args(out_path.to_str().unwrap().to_string());
        let (date_fmt, start_time, main_args) = wiskess::init_wiskess(args);

        // wait a short time
        std::thread::sleep(std::time::Duration::from_millis(100));

        // should not panic
        wiskess::end_wiskess(start_time, main_args.clone(), &date_fmt);

        // check log file has finish message
        let log_content = std::fs::read_to_string(&main_args.out_log).unwrap();
        assert!(log_content.contains("Wiskess finished at"));
        assert!(log_content.contains("which took"));
    }

    /// Test end_wiskess formats duration correctly
    #[test]
    fn test_end_wiskess_duration_format() {
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().join("format_test");

        let args = create_test_args(out_path.to_str().unwrap().to_string());
        let (date_fmt, start_time, main_args) = wiskess::init_wiskess(args);

        wiskess::end_wiskess(start_time, main_args.clone(), &date_fmt);

        let log_content = std::fs::read_to_string(&main_args.out_log).unwrap();

        // duration should be in HH:MM:SS format
        assert!(log_content.contains("00:00:00") ||
                log_content.contains("00:00:01") ||
                log_content.contains("[H:M:S]"));
    }
}
