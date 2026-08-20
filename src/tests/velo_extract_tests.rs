#[cfg(test)]
mod tests {
    use crate::whipped::whip_velo;
    use std::fs::{self, File};
    use tempfile::TempDir;

    /// Test the velociraptor container markers are found in an archive listing
    #[test]
    fn test_has_velo_markers_container_listing() {
        let listing = "\
uploads/auto/C%3A/Windows/System32/config/SYSTEM
uploads.json
results/Windows.KapeFiles.Targets/All File Metadata.json
collection_report.html";

        assert!(whip_velo::has_velo_markers(listing));
    }

    /// Test an archive without the container metadata files is not a velociraptor collection
    #[test]
    fn test_has_velo_markers_other_archive_listing() {
        let listing = "\
C/Windows/System32/config/SYSTEM
C/$MFT";

        assert!(!whip_velo::has_velo_markers(listing));
    }

    /// Test an archive missing the file metadata, i.e. the timestamps, is not extracted by velociraptor
    #[test]
    fn test_has_velo_markers_missing_file_metadata() {
        let listing = "\
uploads/auto/C%3A/Windows/System32/config/SYSTEM
uploads.json";

        assert!(!whip_velo::has_velo_markers(listing));
    }

    /// Test finding the velociraptor binary symlinked by the wiskess setup
    #[test]
    fn test_find_velo_bin_setup_link() {
        let temp_dir = TempDir::new().unwrap();
        let velo_dir = temp_dir.path().join("velociraptor");
        fs::create_dir(&velo_dir).unwrap();
        let velo_bin = velo_dir.join("velociraptor.exe");
        File::create(&velo_bin).unwrap();

        assert_eq!(whip_velo::find_velo_bin(temp_dir.path()), Some(velo_bin));
    }

    /// Test finding the versioned velociraptor release binary in the tools folder
    #[test]
    fn test_find_velo_bin_versioned_release() {
        let temp_dir = TempDir::new().unwrap();
        let velo_bin = temp_dir.path().join("velociraptor-v0.72.0-windows-amd64.exe");
        File::create(&velo_bin).unwrap();

        assert_eq!(whip_velo::find_velo_bin(temp_dir.path()), Some(velo_bin));
    }

    /// Test the extract folder keeps the same layout as a 7zip extracted container,
    /// i.e. `uploads/<accessor>/<drive>/<artefacts>`
    #[test]
    fn test_velo_folder_keeps_container_layout() {
        let temp_dir = TempDir::new().unwrap();
        let out_folder = temp_dir.path().join("uploads").join(whip_velo::VELO_FOLDER);
        let drive_folder = out_folder.join("C%3A");
        fs::create_dir_all(&drive_folder).unwrap();

        let drives = whip_main_os_drives(&drive_folder);
        assert_eq!(drives, vec!['C']);
    }

    /// helper to confirm the drive detection of an extracted collection, by making the
    /// Windows folder that marks the OS drive then finding the drive letters
    fn whip_main_os_drives(drive_folder: &std::path::Path) -> Vec<char> {
        use crate::whipped::whip_main;

        fs::create_dir_all(drive_folder.join("Windows")).unwrap();
        // uploads is two levels up from the drive folder, i.e. uploads/<accessor>/<drive>
        let uploads_dir = drive_folder.parent().unwrap().parent().unwrap();
        whip_main::find_os_drive_letters(uploads_dir)
    }
}
