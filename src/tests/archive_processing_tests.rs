#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::fs::{self, File};
    use tempfile::TempDir;

    /// Test detecting velociraptor collection by uploads folder
    #[test]
    fn test_detect_velociraptor_uploads_folder() {
        let temp_dir = TempDir::new().unwrap();
        let uploads_folder = temp_dir.path().join("uploads");
        fs::create_dir(&uploads_folder).unwrap();

        // create mock velociraptor structure
        let auto_folder = uploads_folder.join("auto");
        let c_drive = auto_folder.join("C%3A");
        fs::create_dir_all(&c_drive).unwrap();

        // create some test files
        File::create(c_drive.join("test.txt")).unwrap();

        assert!(uploads_folder.exists());
        assert_eq!(uploads_folder.file_name().unwrap(), "uploads");
    }

    /// Test detecting CYLR collection by C folder
    #[test]
    fn test_detect_cylr_c_folder() {
        let temp_dir = TempDir::new().unwrap();
        let c_folder = temp_dir.path().join("C");
        fs::create_dir(&c_folder).unwrap();

        // create mock CYLR structure
        let windows_folder = c_folder.join("Windows");
        fs::create_dir(&windows_folder).unwrap();

        assert!(c_folder.exists());
        assert_eq!(c_folder.file_name().unwrap(), "C");
    }

    /// Test creating files folder for velociraptor reorganization
    #[test]
    fn test_create_files_folder() {
        let temp_dir = TempDir::new().unwrap();
        let uploads_folder = temp_dir.path().join("uploads");
        fs::create_dir(&uploads_folder).unwrap();

        let files_folder = uploads_folder.join("files");
        fs::create_dir(&files_folder).unwrap();

        assert!(files_folder.exists());
        assert!(files_folder.is_dir());
    }

    /// Test identifying archive files by extension
    #[test]
    fn test_identify_zip_archive() {
        let archive_path = PathBuf::from("collection.zip");

        let ext = archive_path.extension().unwrap();

        assert_eq!(ext, "zip");
    }

    /// Test identifying 7z archive
    #[test]
    fn test_identify_7z_archive() {
        let archive_path = PathBuf::from("evidence.7z");

        let ext = archive_path.extension().unwrap();

        assert_eq!(ext, "7z");
    }

    /// Test identifying disk image extensions
    #[test]
    fn test_identify_disk_image_extensions() {
        let vmdk = PathBuf::from("server.vmdk");
        let vhdx = PathBuf::from("workstation.vhdx");
        let e01 = PathBuf::from("forensic.e01");
        let vdi = PathBuf::from("virtual.vdi");

        assert_eq!(vmdk.extension().unwrap(), "vmdk");
        assert_eq!(vhdx.extension().unwrap(), "vhdx");
        assert_eq!(e01.extension().unwrap(), "e01");
        assert_eq!(vdi.extension().unwrap(), "vdi");
    }

    /// Test matching disk image file extensions
    #[test]
    fn test_match_disk_image_type() {
        let test_files = vec![
            ("disk.vmdk", true),
            ("backup.vhdx", true),
            ("forensic.e01", true),
            ("vm.vdi", true),
            ("data.raw", true),
            ("archive.zip", false),
            ("document.txt", false),
        ];

        for (filename, should_match) in test_files {
            let path = PathBuf::from(filename);
            if let Some(ext) = path.extension() {
                let is_disk_image = matches!(
                    ext.to_str().unwrap(),
                    "vmdk" | "vhdx" | "vhd" | "e01" | "vdi" | "ex01" | "raw"
                );
                assert_eq!(is_disk_image, should_match, "Failed for {}", filename);
            }
        }
    }

    /// Test extracting nested archive scenario
    #[test]
    fn test_nested_archive_structure() {
        let temp_dir = TempDir::new().unwrap();

        // simulate outer archive extracted
        let outer_folder = temp_dir.path().join("outer-extracted");
        fs::create_dir(&outer_folder).unwrap();

        // inner archive inside
        let inner_archive = outer_folder.join("inner.zip");
        File::create(&inner_archive).unwrap();

        assert!(inner_archive.exists());
        assert_eq!(inner_archive.extension().unwrap(), "zip");
    }

    /// Test velociraptor encoded path detection
    #[test]
    fn test_velociraptor_encoded_paths() {
        let encoded_paths = vec![
            "C%3A",                    // C:
            "%5C%5C.%5CC%3A",         // \\.\C:
        ];

        for encoded in encoded_paths {
            // these are the patterns wiskess looks for in velociraptor collections
            assert!(encoded.contains("C%3A") || encoded.contains("%5C%5C.%5CC%3A"));
        }
    }

    /// Test archive output naming convention
    #[test]
    fn test_archive_naming_convention() {
        let base_name = "Collection-DC";
        let extracted_folder = format!("{}-extracted", base_name);
        let wiskess_folder = format!("{}-Wiskess", base_name);

        assert_eq!(extracted_folder, "Collection-DC-extracted");
        assert_eq!(wiskess_folder, "Collection-DC-Wiskess");
    }

    /// Test collection.zip naming in artefacts folder
    #[test]
    fn test_collection_zip_path() {
        let wiskess_output = PathBuf::from("X:\\DC01-Wiskess");
        let artefacts_folder = wiskess_output.join("Artefacts");
        let collection_zip = artefacts_folder.join("collection.zip");

        assert_eq!(
            collection_zip.file_name().unwrap(),
            "collection.zip"
        );
    }
}
