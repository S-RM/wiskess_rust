#[cfg(test)]
mod tests {
    use crate::whipped::whip_main;
    use std::fs::{self, File};
    use std::path::PathBuf;
    use tempfile::TempDir;
    use walkdir::WalkDir;

    /// Test extracting a drive letter from the plain encoded form
    #[test]
    fn test_extract_drive_letter_plain_form() {
        assert_eq!(whip_main::extract_drive_letter("F%3A"), Some('F'));
    }

    /// Test extracting a drive letter from the UNC device encoded form
    #[test]
    fn test_extract_drive_letter_unc_device_form() {
        assert_eq!(whip_main::extract_drive_letter("%5C%5C.%5CF%3A"), Some('F'));
    }

    /// Test extracting a drive letter from lowercase input, both forms
    #[test]
    fn test_extract_drive_letter_lowercase_input() {
        assert_eq!(whip_main::extract_drive_letter("f%3a"), Some('F'));
        assert_eq!(whip_main::extract_drive_letter("%5c%5c.%5cf%3a"), Some('F'));
    }

    /// Test that non-drive-letter strings return None
    #[test]
    fn test_extract_drive_letter_non_matching_string() {
        assert_eq!(whip_main::extract_drive_letter("Users"), None);
        assert_eq!(whip_main::extract_drive_letter("uploads"), None);
        assert_eq!(whip_main::extract_drive_letter(""), None);
        assert_eq!(whip_main::extract_drive_letter("files"), None);
    }

    /// Test has_windows_child returns true when a Windows folder is present
    #[test]
    fn test_has_windows_child_true() {
        let temp_dir = TempDir::new().unwrap();
        fs::create_dir_all(temp_dir.path().join("Windows")).unwrap();

        assert!(whip_main::has_windows_child(temp_dir.path()));
    }

    /// Test has_windows_child is case-insensitive
    #[test]
    fn test_has_windows_child_case_insensitive() {
        let temp_dir = TempDir::new().unwrap();
        fs::create_dir_all(temp_dir.path().join("windows")).unwrap();

        assert!(whip_main::has_windows_child(temp_dir.path()));
    }

    /// Test has_windows_child returns false when no Windows folder is present
    #[test]
    fn test_has_windows_child_false_no_windows_folder() {
        let temp_dir = TempDir::new().unwrap();
        fs::create_dir_all(temp_dir.path().join("Users")).unwrap();

        assert!(!whip_main::has_windows_child(temp_dir.path()));
    }

    /// Test has_windows_child returns false when Windows exists but is a file, not a dir
    #[test]
    fn test_has_windows_child_false_windows_is_a_file() {
        let temp_dir = TempDir::new().unwrap();
        File::create(temp_dir.path().join("Windows")).unwrap();

        assert!(!whip_main::has_windows_child(temp_dir.path()));
    }

    /// Test find_os_drive_letters still finds the C-drive when that's the only one collected
    #[test]
    fn test_find_os_drive_letters_c_drive_regression() {
        let temp_dir = TempDir::new().unwrap();
        let uploads_dir = temp_dir.path().join("uploads");
        fs::create_dir_all(uploads_dir.join("auto").join("C%3A").join("Windows")).unwrap();

        assert_eq!(whip_main::find_os_drive_letters(&uploads_dir), vec!['C']);
    }

    /// Test find_os_drive_letters picks the drive with Windows out of multiple collected drives
    #[test]
    fn test_find_os_drive_letters_multi_drive_scenario() {
        let temp_dir = TempDir::new().unwrap();
        let uploads_dir = temp_dir.path().join("uploads");
        // D-drive collected by default, but it's not the OS drive
        fs::create_dir_all(uploads_dir.join("auto").join("D%3A").join("Users")).unwrap();
        // F-drive is the real OS drive, present in both auto and ntfs, two encoded forms
        fs::create_dir_all(uploads_dir.join("auto").join("F%3A").join("Windows")).unwrap();
        fs::create_dir_all(uploads_dir.join("ntfs").join("%5C%5C.%5CF%3A").join("$Extend")).unwrap();

        assert_eq!(whip_main::find_os_drive_letters(&uploads_dir), vec!['F']);
    }

    /// Test find_os_drive_letters returns empty when no drive has a Windows folder
    #[test]
    fn test_find_os_drive_letters_no_windows_anywhere() {
        let temp_dir = TempDir::new().unwrap();
        let uploads_dir = temp_dir.path().join("uploads");
        fs::create_dir_all(uploads_dir.join("auto").join("D%3A").join("Users")).unwrap();

        assert!(whip_main::find_os_drive_letters(&uploads_dir).is_empty());
    }

    /// Test the depth-3 filter predicate (as used in pre_process_zip) selects only
    /// entries under the confirmed drive, excluding other collected drives
    #[test]
    fn test_filter_selects_only_confirmed_drive_entries() {
        let temp_dir = TempDir::new().unwrap();
        let uploads_dir = temp_dir.path().join("uploads");
        fs::create_dir_all(uploads_dir.join("auto").join("D%3A").join("Users")).unwrap();
        fs::create_dir_all(uploads_dir.join("auto").join("F%3A").join("Windows")).unwrap();
        fs::create_dir_all(uploads_dir.join("ntfs").join("%5C%5C.%5CF%3A").join("$Extend")).unwrap();

        let confirmed_drives = whip_main::find_os_drive_letters(&uploads_dir);
        assert_eq!(confirmed_drives, vec!['F']);

        let entries: Vec<PathBuf> = WalkDir::new(&uploads_dir)
            .min_depth(3)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|entry| {
                entry.path().components().any(|component| {
                    component.as_os_str().to_str()
                        .and_then(whip_main::extract_drive_letter)
                        .map_or(false, |letter| confirmed_drives.contains(&letter))
                })
            })
            .map(|e| e.into_path())
            .collect();

        assert!(!entries.is_empty());
        for entry in &entries {
            let entry_str = entry.to_str().unwrap();
            assert!(
                entry_str.contains("F%3A"),
                "entry {} should be under a confirmed F-drive component",
                entry_str
            );
        }
    }

    /// Test the fallback: when no drive is confirmed, nothing gets filtered out
    #[test]
    fn test_filter_fallback_includes_everything_when_no_drive_confirmed() {
        let temp_dir = TempDir::new().unwrap();
        let uploads_dir = temp_dir.path().join("uploads");
        fs::create_dir_all(uploads_dir.join("auto").join("D%3A").join("Users")).unwrap();

        let confirmed_drives = whip_main::find_os_drive_letters(&uploads_dir);
        let no_drive_confirmed = confirmed_drives.is_empty();
        assert!(no_drive_confirmed);

        let entries: Vec<PathBuf> = WalkDir::new(&uploads_dir)
            .min_depth(3)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|entry| {
                no_drive_confirmed || entry.path().components().any(|component| {
                    component.as_os_str().to_str()
                        .and_then(whip_main::extract_drive_letter)
                        .map_or(false, |letter| confirmed_drives.contains(&letter))
                })
            })
            .map(|e| e.into_path())
            .collect();

        assert!(!entries.is_empty(), "fallback should not filter out the D-drive entry");
    }

    /// Test the CYLR-style generalization: a folder not literally named "C" but
    /// containing a Windows child should now be recognised as the drive root
    #[test]
    fn test_cylr_non_c_folder_with_windows_included() {
        let temp_dir = TempDir::new().unwrap();
        let drive_folder = temp_dir.path().join("OS_Drive");
        fs::create_dir_all(drive_folder.join("Windows")).unwrap();

        assert!(whip_main::has_windows_child(&drive_folder));
    }

    /// Test the CYLR-style generalization: a folder literally named "C" but with
    /// no Windows child should now be excluded (previously always included)
    #[test]
    fn test_cylr_c_folder_without_windows_excluded() {
        let temp_dir = TempDir::new().unwrap();
        let drive_folder = temp_dir.path().join("C");
        fs::create_dir_all(&drive_folder).unwrap();
        File::create(drive_folder.join("data.txt")).unwrap();

        assert!(!whip_main::has_windows_child(&drive_folder));
    }
}
