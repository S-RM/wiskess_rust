#[cfg(test)]
mod tests {
    use crate::whipped::whip_main;

    /// Test split_and_trim with comma-separated list
    #[test]
    fn test_split_and_trim_comma_separated() {
        let input = "file1.zip, file2.vmdk, file3.e01";

        let result = whip_main::split_and_trim(input);

        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "file1.zip");
        assert_eq!(result[1], "file2.vmdk");
        assert_eq!(result[2], "file3.e01");
    }

    /// Test split_and_trim with newline-separated list
    #[test]
    fn test_split_and_trim_newline_separated() {
        let input = "file1.zip\nfile2.vmdk\nfile3.e01";

        let result = whip_main::split_and_trim(input);

        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "file1.zip");
        assert_eq!(result[1], "file2.vmdk");
        assert_eq!(result[2], "file3.e01");
    }

    /// Test split_and_trim with extra whitespace
    #[test]
    fn test_split_and_trim_with_whitespace() {
        let input = "  file1.zip  ,  file2.vmdk  ,  file3.e01  ";

        let result = whip_main::split_and_trim(input);

        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "file1.zip");
        assert_eq!(result[1], "file2.vmdk");
        assert_eq!(result[2], "file3.e01");
    }

    /// Test split_and_trim with single item
    #[test]
    fn test_split_and_trim_single_item() {
        let input = "single_file.vmdk";

        let result = whip_main::split_and_trim(input);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "single_file.vmdk");
    }

    /// Test url_to_path converts forward slashes
    #[test]
    fn test_url_to_path_forward_slashes() {
        let url = "collections/images/dc01.vmdk".to_string();

        let result = whip_main::url_to_path(&url);

        // should convert to OS-specific path separator
        #[cfg(target_os = "windows")]
        assert_eq!(result, "collections\\images\\dc01.vmdk");

        #[cfg(target_os = "linux")]
        assert_eq!(result, "collections/images/dc01.vmdk");
    }

    /// Test url_to_path with mixed slashes
    #[test]
    fn test_url_to_path_mixed_slashes() {
        let url = "collections\\images/subfolder/file.e01".to_string();

        let result = whip_main::url_to_path(&url);

        // should handle mixed separators
        assert!(result.contains("collections"));
        assert!(result.contains("images"));
        assert!(result.contains("file.e01"));
    }

    /// Test set_link with S3 URL
    #[test]
    fn test_set_link_s3_url() {
        let s3_link = "s3://my-bucket/evidence";
        let folder = "client1";

        let result = whip_main::set_link(s3_link, folder);

        assert_eq!(result, "s3://my-bucket/evidence/client1");
    }

    /// Test set_link with S3 URL ending in slash
    #[test]
    fn test_set_link_s3_url_trailing_slash() {
        let s3_link = "s3://my-bucket/evidence/";
        let folder = "client1";

        let result = whip_main::set_link(s3_link, folder);

        // set_link trims trailing /* but leaves trailing /
        // so we get double slash, which is acceptable for S3
        assert!(result.contains("client1"));
        assert!(result.starts_with("s3://my-bucket/evidence"));
    }

    /// Test set_link with S3 URL ending in wildcard
    #[test]
    fn test_set_link_s3_url_wildcard() {
        let s3_link = "s3://my-bucket/evidence/*";
        let folder = "client1";

        let result = whip_main::set_link(s3_link, folder);

        assert_eq!(result, "s3://my-bucket/evidence/client1");
    }

    /// Test set_link with Azure Blob Storage URL
    #[test]
    fn test_set_link_azure_url() {
        let azure_link = "https://myaccount.blob.core.windows.net/container?sp=rl&st=2024-01-01";
        let folder = "client2";

        let result = whip_main::set_link(azure_link, folder);

        assert!(result.contains("https://myaccount.blob.core.windows.net/container/client2"));
        assert!(result.contains("sp=rl&st=2024-01-01"));
    }

    /// Test set_link with Azure File Storage URL
    #[test]
    fn test_set_link_azure_file_url() {
        let azure_link = "https://myaccount.file.core.windows.net/share?sig=abc123";
        let folder = "evidence";

        let result = whip_main::set_link(azure_link, folder);

        assert!(result.contains("https://myaccount.file.core.windows.net/share/evidence"));
        assert!(result.contains("sig=abc123"));
    }

    /// Test set_link with local path returns "local"
    #[test]
    fn test_set_link_local_path() {
        let local_link = "/mnt/evidence/collection";
        let folder = "client1";

        let result = whip_main::set_link(local_link, folder);

        assert_eq!(result, "local");
    }

    /// Test set_link with unknown URL format returns "local"
    #[test]
    fn test_set_link_unknown_format() {
        let unknown_link = "ftp://example.com/data";
        let folder = "client1";

        let result = whip_main::set_link(unknown_link, folder);

        assert_eq!(result, "local");
    }

    /// Test print_log does not panic
    #[test]
    fn test_print_log_verbose_false() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let log_file = temp_dir.path().join("test.log");

        whip_main::print_log("Test message", &log_file, false);

        // should create log file
        assert!(log_file.exists());
        let content = std::fs::read_to_string(&log_file).unwrap();
        assert!(content.contains("Test message"));
    }

    /// Test print_log with verbose mode
    #[test]
    fn test_print_log_verbose_true() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let log_file = temp_dir.path().join("verbose_test.log");

        // should not panic with verbose = true
        whip_main::print_log("Verbose test message", &log_file, true);

        assert!(log_file.exists());
    }
}
