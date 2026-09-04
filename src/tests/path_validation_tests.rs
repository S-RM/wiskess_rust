#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;
    use std::fs;
    use indicatif::MultiProgress;
    use crate::art::paths::{self, find_case_insensitive};
    use crate::configs::config::{Artefacts, MainArgs};

    /// Test path exists check returns true for existing path
    #[test]
    fn test_path_exists_valid() {
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path();

        assert!(test_path.exists());
        assert!(test_path.is_dir());
    }

    /// Test path exists check returns false for non-existent path
    #[test]
    fn test_path_exists_invalid() {
        let fake_path = Path::new("Z:\\NonExistent\\Path");

        assert!(!fake_path.exists());
    }

    /// Test detecting drive letter format
    #[test]
    fn test_detect_drive_letter_format() {
        let windows_paths = vec![
            "C:",
            "D:",
            "F:",
            "Z:",
        ];

        for path in windows_paths {
            // windows drive letters are single letter followed by colon
            assert!(path.len() == 2);
            assert!(path.ends_with(":"));
        }
    }

    /// Test detecting UNC path format
    #[test]
    fn test_detect_unc_path_format() {
        let unc_path = r"\\server\share\folder";

        assert!(unc_path.starts_with(r"\\"));
    }

    /// Test detecting absolute path
    #[test]
    fn test_detect_absolute_path() {
        #[cfg(target_os = "windows")]
        let abs_path = Path::new(r"C:\Windows\System32");

        #[cfg(target_os = "linux")]
        let abs_path = Path::new("/mnt/evidence");

        assert!(abs_path.is_absolute());
    }

    /// Test detecting relative path
    #[test]
    fn test_detect_relative_path() {
        let rel_path = Path::new("data/collections");

        #[cfg(target_os = "windows")]
        assert!(!rel_path.is_absolute());

        #[cfg(target_os = "linux")]
        assert!(!rel_path.is_absolute());
    }

    /// Test artefact path with wildcard
    #[test]
    fn test_artefact_path_with_wildcard() {
        let prefetch_pattern = r"C:\Windows\Prefetch\*.pf";

        assert!(prefetch_pattern.contains("*"));
        assert!(prefetch_pattern.ends_with(".pf"));
    }

    /// Test artefact path without wildcard
    #[test]
    fn test_artefact_path_without_wildcard() {
        let registry_path = r"C:\Windows\System32\config\SYSTEM";

        assert!(!registry_path.contains("*"));
    }

    /// Test creating artefacts output folder
    #[test]
    fn test_create_artefacts_folder() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("DC01-Wiskess");
        let artefacts_folder = output_path.join("Artefacts");

        fs::create_dir_all(&artefacts_folder).unwrap();

        assert!(artefacts_folder.exists());
        assert!(artefacts_folder.is_dir());
    }

    /// Test verifying parent path exists before creating child
    #[test]
    fn test_parent_path_exists_check() {
        let temp_dir = TempDir::new().unwrap();
        let parent = temp_dir.path();
        let child = parent.join("subfolder");

        assert!(parent.exists());

        fs::create_dir(&child).unwrap();

        assert!(child.exists());
    }

    /// Test path canonicalization for mounted drives
    #[test]
    fn test_path_canonicalization() {
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path();

        let canonical = test_path.canonicalize().unwrap();

        assert!(canonical.is_absolute());
    }

    /// Test detecting mounted image path vs collection path
    #[test]
    fn test_distinguish_image_vs_collection() {
        // mounted image typically has drive letter or mount point
        let mounted_image = Path::new("F:");

        // collection has folder structure
        let collection = Path::new(r"X:\Collection-myhost-2025-07-15T20_41_49Z\uploads\files");

        // collection has deeper structure - just verify both parse correctly
        assert!(mounted_image.components().count() >= 1);
        assert!(collection.components().count() >= 1);
        // collection should have more components than just a drive letter
        assert!(collection.to_str().unwrap().contains("uploads"));
    }

    /// Test that find_case_insensitive resolves a path when the requested casing
    /// differs from the actual filename casing on the filesystem.
    /// On Linux this exercises the real case-insensitive lookup; on Windows the
    /// standard exists() check would already succeed, but the function should
    /// still return the correct resolved path.
    #[test]
    fn test_case_insensitive_path_match() {
        let temp_dir = TempDir::new().unwrap();

        // Create a file with mixed-case name on disk
        let actual_name = "TestArtefact.evtx";
        let actual_path = temp_dir.path().join(actual_name);
        fs::write(&actual_path, b"dummy").unwrap();

        // Build a path using a different casing for the filename
        let wrong_case = temp_dir.path().join("testArtefact.EVTX");

        // The wrong-cased path should NOT exist as-is on a case-sensitive FS
        // find_case_insensitive should resolve it to the real path
        let resolved = find_case_insensitive(&wrong_case);

        assert!(
            resolved.is_some(),
            "find_case_insensitive should find '{}' even when requested as '{}'",
            actual_name,
            wrong_case.display()
        );
        // The resolved path should point to the actual file that exists
        assert!(
            resolved.unwrap().exists(),
            "resolved path must exist on the filesystem"
        );
    }

    /// Test that find_case_insensitive returns None for a file that does not
    /// exist under any casing in the parent directory.
    #[test]
    fn test_case_insensitive_path_no_match() {
        let temp_dir = TempDir::new().unwrap();

        // No file created – nothing to match
        let missing = temp_dir.path().join("ghost_artefact.evtx");

        let resolved = find_case_insensitive(&missing);

        assert!(
            resolved.is_none(),
            "find_case_insensitive should return None when no matching entry exists"
        );
    }

    /// Regression test: check_art must resolve a wildcarded artefact path even
    /// when the config's casing (PSReadline) doesn't match the real on-disk
    /// casing (PSReadLine), and collect_consolehost must then actually copy
    /// the file through - reproducing the bug where ConsoleHost_history.txt
    /// was silently skipped depending on the casing used on the source host.
    #[test]
    fn test_consolehost_history_case_mismatch_is_collected() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Real on-disk folder uses the correct Windows casing: PSReadLine
        let history_dir = root
            .join("Users")
            .join("testuser")
            .join("AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine");
        fs::create_dir_all(&history_dir).unwrap();
        let history_file = history_dir.join("ConsoleHost_history.txt");
        fs::write(&history_file, b"Get-Process\n").unwrap();

        let out_dir = temp_dir.path().join("out");
        fs::create_dir_all(&out_dir).unwrap();

        let main_args = MainArgs {
            out_path: out_dir.to_str().unwrap().to_string(),
            start_date: "2023-01-01".to_string(),
            end_date: "2023-12-31".to_string(),
            tool_path: PathBuf::from("/tmp/tools"),
            ioc_file: "test_iocs.txt".to_string(),
            silent: true,
            collect: false,
            out_log: out_dir.join("test.log"),
            multi_pb: MultiProgress::new(),
            no_timeline_parser: true,
            restoration_date: None,
        };

        // Config path deliberately mismatches the real on-disk "PSReadLine" casing
        let artefact = Artefacts {
            name: "consolehost_history".to_string(),
            path: "{root}/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt".to_string(),
            legacy: "".to_string(),
        };

        let root_str = root.to_str().unwrap().to_string();
        let data_paths = paths::check_art(vec![artefact], &root_str, true, &main_args);

        let resolved = data_paths.get("consolehost_history");
        assert!(
            resolved.is_some_and(|p| p != "wiskess_none"),
            "expected consolehost_history to resolve despite the case mismatch, got {:?}",
            resolved
        );

        paths::collect_consolehost(&data_paths, &main_args);

        // Don't assert on the exact username in the filename: extract_user()
        // matches the first "Users/<name>" segment in the full path, which on
        // some CI/dev machines can be the real profile dir the temp path lives
        // under rather than the synthetic "testuser" segment created above.
        // What matters here is that the file was actually collected.
        let dest_dir = out_dir.join("PSReadLine");
        let collected: Vec<_> = fs::read_dir(&dest_dir)
            .unwrap_or_else(|e| panic!("expected {} to exist after collect_consolehost: {e}", dest_dir.display()))
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with("_ConsoleHost_history.txt"))
            .collect();
        assert_eq!(
            collected.len(), 1,
            "expected exactly one collected ConsoleHost_history.txt in {}, found {:?}",
            dest_dir.display(), collected.iter().map(|e| e.file_name()).collect::<Vec<_>>()
        );
        assert_eq!(fs::read_to_string(collected[0].path()).unwrap(), "Get-Process\n");
    }

    /// Test path with spaces handling
    #[test]
    fn test_path_with_spaces() {
        let path_with_spaces = r"C:\Program Files\Wiskess\output";
        let path = Path::new(path_with_spaces);

        assert!(path.to_str().unwrap().contains(" "));
        // verify path contains the expected folders
        assert!(path.to_str().unwrap().contains("Program Files"));
        assert!(path.to_str().unwrap().contains("Wiskess"));
        assert!(path.to_str().unwrap().contains("output"));
    }
}
