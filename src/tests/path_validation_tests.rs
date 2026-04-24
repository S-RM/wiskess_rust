#[cfg(test)]
mod tests {
    use std::path::Path;
    use tempfile::TempDir;
    use std::fs;

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
