#[cfg(test)]
mod tests {
    use std::fs;
    use tempfile::TempDir;
    use crate::init::setup::{patch_regripper_plugins, repo_dir_name};

    const UNPATCHED: &str = r#"
		while($tag) {
			if (unpack("v",substr($data,$ofs + $cnt,2)) == 0xbeef) {
				$tag = 0;
			}
		}
	while ($tag) {
		if (unpack("v",substr($data,$ofs,2)) == 0xbeef) {
			$tag = 0;
		}
	}
	while ($tag) {
		my $s = substr($data,$ofs_shortname + $cnt,1);
	}
"#;

    /// Test each unbounded scan loop is bounded by the data length, and a re-run changes nothing
    #[test]
    fn test_patch_regripper_plugins_bounds_loops() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("shellbags.pl");
        fs::write(&f, UNPATCHED).unwrap();

        let msgs = patch_regripper_plugins(dir.path());
        assert!(msgs.iter().any(|m| m.starts_with("Patched:")));
        let out = fs::read_to_string(&f).unwrap();
        assert!(out.contains("while ($tag && $ofs + $cnt + 2 <= length($data)) {"));
        assert!(out.contains("while ($tag && $ofs + 2 <= length($data)) {"));
        assert!(out.contains("while ($tag && $ofs_shortname + $cnt < length($data)) {"));
        assert!(!out.contains("while($tag)") && !out.contains("while ($tag)"));

        let msgs = patch_regripper_plugins(dir.path());
        assert!(msgs.iter().any(|m| m.starts_with("Already patched:")));
        assert_eq!(fs::read_to_string(&f).unwrap(), out);
    }

    /// Test a missing plugin directory is reported, not a panic
    #[test]
    fn test_patch_regripper_plugins_missing_dir() {
        let dir = TempDir::new().unwrap();
        let msgs = patch_regripper_plugins(&dir.path().join("nope"));
        assert!(msgs[0].starts_with("No regripper plugin directory found"));
    }

    /// Test the folder name matches what git clone makes, so setup --update pulls the right repo
    #[test]
    fn test_repo_dir_name() {
        assert_eq!(repo_dir_name("https://github.com/keydet89/RegRipper3.0.git"), "RegRipper3.0");
        assert_eq!(repo_dir_name("https://github.com/brimorlabs/KStrike"), "KStrike");
        assert_eq!(repo_dir_name("https://github.com/williballenthin/shellbags/"), "shellbags");
    }
}
