#[cfg(test)]
mod tests {
    use crate::ops::file_ops;
    use std::path::PathBuf;
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::TempDir;

    /// Test make_folders creates directories successfully
    #[test]
    fn test_make_folders_creates_directory() {
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path().join("test_folder").join("nested").join("deep");

        file_ops::make_folders(&test_path);

        assert!(test_path.exists());
        assert!(test_path.is_dir());
    }

    /// Test make_folders handles existing directories
    #[test]
    fn test_make_folders_existing_directory() {
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path().join("existing_folder");

        // create it first
        fs::create_dir(&test_path).unwrap();

        // should not panic when called again
        file_ops::make_folders(&test_path);

        assert!(test_path.exists());
    }

    /// Test check_date with valid date format
    #[test]
    fn test_check_date_valid_format() {
        let test_date = "2023-12-25".to_string();
        let date_type = "test date".to_string();

        let result = file_ops::check_date(test_date.clone(), &date_type);

        assert_eq!(result, test_date);
    }

    /// Test check_date with valid date format alternative
    #[test]
    fn test_check_date_valid_format_with_slashes() {
        let test_date = "2023-01-15".to_string();
        let date_type = "start date".to_string();

        let result = file_ops::check_date(test_date.clone(), &date_type);

        // should return the date string unchanged
        assert_eq!(result, test_date);
    }

    /// Test line_count with a file containing known number of lines
    #[test]
    fn test_line_count_returns_correct_count() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test_lines.txt");

        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "line 1").unwrap();
        writeln!(file, "line 2").unwrap();
        writeln!(file, "line 3").unwrap();
        writeln!(file, "line 4").unwrap();
        writeln!(file, "line 5").unwrap();

        let count = file_ops::line_count(&test_file);

        assert_eq!(count, 5);
    }

    /// Test line_count with non-existent file returns 0
    #[test]
    fn test_line_count_nonexistent_file() {
        let fake_path = PathBuf::from("/tmp/this_file_does_not_exist_12345.txt");

        let count = file_ops::line_count(&fake_path);

        assert_eq!(count, 0);
    }

    /// Test line_count with empty file returns 0
    #[test]
    fn test_line_count_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("empty.txt");

        File::create(&test_file).unwrap();

        let count = file_ops::line_count(&test_file);

        assert_eq!(count, 0);
    }

    /// Test log_msg writes to log file
    #[test]
    fn test_log_msg_writes_message() {
        let temp_dir = TempDir::new().unwrap();
        let log_file = temp_dir.path().join("test.log");

        file_ops::log_msg(&log_file, "Test log message".to_string());

        assert!(log_file.exists());
        let content = fs::read_to_string(&log_file).unwrap();
        assert!(content.contains("Test log message"));
    }

    /// Test log_msg appends multiple messages
    #[test]
    fn test_log_msg_appends_messages() {
        let temp_dir = TempDir::new().unwrap();
        let log_file = temp_dir.path().join("append_test.log");

        file_ops::log_msg(&log_file, "First message".to_string());
        file_ops::log_msg(&log_file, "Second message".to_string());
        file_ops::log_msg(&log_file, "Third message".to_string());

        let content = fs::read_to_string(&log_file).unwrap();
        assert!(content.contains("First message"));
        assert!(content.contains("Second message"));
        assert!(content.contains("Third message"));
    }

    /// Test check_path with existing file
    #[test]
    fn test_check_path_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("existing.txt");
        File::create(&test_file).unwrap();

        let result = file_ops::check_path(test_file.clone());

        assert_eq!(result, test_file);
    }

    /// Test file_exists_overwrite in silent mode with existing file
    #[test]
    fn test_file_exists_overwrite_silent_mode() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("overwrite_test.txt");

        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "original content").unwrap();

        // in silent mode, should return false (do not overwrite)
        let result = file_ops::file_exists_overwrite(&test_file, true);

        assert_eq!(result, false);
    }

    /// Test file_exists_overwrite with non-existent file returns true
    #[test]
    fn test_file_exists_overwrite_new_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("new_file.txt");

        // file does not exist, should return true
        let result = file_ops::file_exists_overwrite(&test_file, true);

        assert_eq!(result, true);
    }
}
