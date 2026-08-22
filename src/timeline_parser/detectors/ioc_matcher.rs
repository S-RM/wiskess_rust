//! Case IOCs, and an honest account of how many of them there were.
//!
//! Two things about IOC matching are load-bearing and were previously silent.
//!
//! A path that does not exist used to be ignored: `--iocs /wrong/path` loaded
//! nothing, matched nothing, and exited 0. The report then said what a genuinely
//! clean host says. A mistyped path must fail loudly, because the failure mode
//! is a report that reads as evidence of absence.
//!
//! A plain-text IOC list used to put every line into `filenames`, so hashes in
//! `iocs.txt` were never visible to [`IOCMatcher::check_hash`] and never matched
//! an Amcache SHA1. Lines are now classified by shape.
//!
//! [`IocCoverage`] exists so the report can distinguish "no IOCs matched" from
//! "no IOCs were supplied". Those are opposite findings and they rendered
//! identically.

use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;

/// Line-level accounting for a supplied IOC file. The operator asked for the
/// line count of `iocs.txt` specifically: if 40 lines yield 12 indicators, the
/// other 28 need explaining, and this is what explains them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IocSource {
    pub path: String,
    pub format: String,
    pub lines_total: usize,
    pub lines_comment: usize,
    pub lines_blank: usize,
    /// Lines that produced at least one indicator (text lists only).
    pub lines_indicator: usize,
}

/// What was supplied and how it broke down, for the report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IocCoverage {
    /// `None` means no IOC file was supplied at all — no matching was performed.
    pub source: Option<IocSource>,
    pub ips: usize,
    pub domains: usize,
    pub hashes: usize,
    pub filenames: usize,
    pub usernames: usize,
}

impl IocCoverage {
    pub fn total(&self) -> usize {
        self.ips + self.domains + self.hashes + self.filenames + self.usernames
    }
    pub fn supplied(&self) -> bool {
        self.source.is_some()
    }
}

#[derive(Debug)]
pub struct IOCMatcher {
    pub ips: HashSet<String>,
    pub domains: HashSet<String>,
    pub hashes: HashSet<String>,
    pub filenames: HashSet<String>,
    pub usernames: HashSet<String>,
    source: Option<IocSource>,
    compiled_all: Option<Regex>,
}

/// Is this token an MD5/SHA1/SHA256 digest?
fn looks_like_hash(s: &str) -> bool {
    matches!(s.len(), 32 | 40 | 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Is this token a dotted-quad IPv4 address? Deliberately strict: `1.2.3.4.5`
/// and `192.168.1` are not addresses and must not be filed as one.
fn looks_like_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// A domain, as distinct from a filename. `evil.com` is a domain; `evil.exe` is
/// not, and neither is anything carrying a path separator.
fn looks_like_domain(s: &str) -> bool {
    if s.contains('/') || s.contains('\\') || s.contains(' ') || !s.contains('.') {
        return false;
    }
    let tld = s.rsplit('.').next().unwrap_or("");
    tld.len() >= 2
        && tld.chars().all(|c| c.is_ascii_alphabetic())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        && !EXECUTABLE_SUFFIXES.iter().any(|e| s.to_lowercase().ends_with(e))
}

const EXECUTABLE_SUFFIXES: &[&str] = &[
    ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".hta",
    ".scr", ".msi", ".jar", ".lnk", ".tmp", ".dat", ".bin", ".zip", ".7z", ".rar",
];

/// How one line of a plain-text IOC list was classified.
#[derive(Debug, PartialEq, Eq)]
pub enum TxtKind {
    Ip,
    Hash,
    Domain,
    Filename,
}

pub fn classify_txt_line(line: &str) -> TxtKind {
    if looks_like_ipv4(line) {
        TxtKind::Ip
    } else if looks_like_hash(line) {
        TxtKind::Hash
    } else if looks_like_domain(line) {
        TxtKind::Domain
    } else {
        TxtKind::Filename
    }
}

impl IOCMatcher {
    /// Load IOCs, or build an empty matcher when no file was supplied.
    ///
    /// A supplied path that does not exist is an error. It used to be ignored,
    /// which produced a run that performed no IOC matching and said nothing
    /// about it.
    pub fn new(ioc_file: Option<&Path>) -> Result<Self> {
        let mut matcher = Self {
            ips: HashSet::new(),
            domains: HashSet::new(),
            hashes: HashSet::new(),
            filenames: HashSet::new(),
            usernames: HashSet::new(),
            source: None,
            compiled_all: None,
        };

        if let Some(path) = ioc_file {
            // A template that substituted nothing yields `-i ""`. That is a
            // configuration artefact rather than an operator's intent, so it
            // degrades to "no IOCs" — which the report states plainly — instead
            // of failing the whole run on a path that was never a path.
            if path.as_os_str().is_empty() {
                eprintln!(
                    "[!] --iocs was given an empty path — treating as no IOC file. \
                     No IOC matching will be performed."
                );
                return Ok(matcher);
            }
            if !path.exists() {
                anyhow::bail!(
                    "IOC file {} does not exist. Refusing to continue: a run with no IOCs \
                     loaded produces a report indistinguishable from one where every IOC was \
                     checked and none matched.",
                    path.display()
                );
            }
            matcher.load(path)?;
        }

        Ok(matcher)
    }

    /// What was supplied, for the report.
    pub fn coverage(&self) -> IocCoverage {
        IocCoverage {
            source: self.source.clone(),
            ips: self.ips.len(),
            domains: self.domains.len(),
            hashes: self.hashes.len(),
            filenames: self.filenames.len(),
            usernames: self.usernames.len(),
        }
    }

    fn load(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read IOC file {}", path.display()))?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();

        let mut src = IocSource {
            path: path.display().to_string(),
            format: if ext == "yaml" || ext == "yml" { "yaml".into() } else { "text".into() },
            lines_total: content.lines().count(),
            ..Default::default()
        };

        if src.format == "yaml" {
            self.load_yaml(&content, path)?;
        } else {
            self.load_txt(&content, &mut src);
        }

        self.source = Some(src);
        self.compile();
        Ok(())
    }

    fn load_yaml(&mut self, content: &str, path: &Path) -> Result<()> {
        let data: serde_yaml::Value = serde_yaml::from_str(content)
            .with_context(|| format!("cannot parse IOC YAML {}", path.display()))?;
        let iocs = data.get("iocs").unwrap_or(&data);

        if let Some(ips) = iocs.get("ips").and_then(|v| v.as_sequence()) {
            for ip in ips {
                if let Some(s) = ip.as_str() {
                    self.ips.insert(s.to_string());
                }
            }
        }
        if let Some(domains) = iocs.get("domains").and_then(|v| v.as_sequence()) {
            for d in domains {
                if let Some(s) = d.as_str() {
                    self.domains.insert(s.to_string());
                }
            }
        }
        if let Some(hashes) = iocs.get("hashes") {
            match hashes {
                serde_yaml::Value::Mapping(map) => {
                    for (_k, v) in map {
                        match v {
                            serde_yaml::Value::Sequence(seq) => {
                                for item in seq {
                                    if let Some(s) = item.as_str() {
                                        self.hashes.insert(s.to_lowercase());
                                    }
                                }
                            }
                            serde_yaml::Value::String(s) => {
                                self.hashes.insert(s.to_lowercase());
                            }
                            _ => {}
                        }
                    }
                }
                serde_yaml::Value::Sequence(seq) => {
                    for item in seq {
                        if let Some(s) = item.as_str() {
                            self.hashes.insert(s.to_lowercase());
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(filenames) = iocs.get("filenames").and_then(|v| v.as_sequence()) {
            for f in filenames {
                if let Some(s) = f.as_str() {
                    self.filenames.insert(s.to_string());
                }
            }
        }
        if let Some(usernames) = iocs.get("usernames").and_then(|v| v.as_sequence()) {
            for u in usernames {
                if let Some(s) = u.as_str() {
                    self.usernames.insert(s.to_string());
                }
            }
        }
        Ok(())
    }

    /// One indicator per line, classified by shape.
    ///
    /// Everything unrecognised is still filed as a filename — an IOC list may
    /// carry a mutex name, a service name or a fragment of a command line, and
    /// dropping those would lose real detections. The point of classifying is
    /// that hashes reach `hashes` rather than being invisible to
    /// [`IOCMatcher::check_hash`].
    fn load_txt(&mut self, content: &str, src: &mut IocSource) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                src.lines_blank += 1;
                continue;
            }
            if line.starts_with('#') || line.starts_with("//") {
                src.lines_comment += 1;
                continue;
            }
            match classify_txt_line(line) {
                TxtKind::Ip => {
                    self.ips.insert(line.to_string());
                }
                TxtKind::Hash => {
                    self.hashes.insert(line.to_lowercase());
                }
                TxtKind::Domain => {
                    self.domains.insert(line.to_string());
                }
                TxtKind::Filename => {
                    self.filenames.insert(line.to_string());
                }
            }
            src.lines_indicator += 1;
        }
    }

    fn compile(&mut self) {
        let mut all_iocs: Vec<&str> = Vec::new();
        for ip in &self.ips { all_iocs.push(ip); }
        for d in &self.domains { all_iocs.push(d); }
        for f in &self.filenames { all_iocs.push(f); }
        for u in &self.usernames { all_iocs.push(u); }
        // Hashes are searched as literals too. A digest turning up in a command
        // line or a filename is worth the same hit as one matched against an
        // Amcache SHA1, and `check_hash` only ever sees a hash column.
        for h in &self.hashes { all_iocs.push(h); }

        if all_iocs.is_empty() {
            self.compiled_all = None;
            return;
        }

        let escaped: Vec<String> = all_iocs.iter().map(|i| regex::escape(i)).collect();
        let pattern = escaped.join("|");
        self.compiled_all = Regex::new(&format!("(?i){}", pattern)).ok();
    }

    pub fn check(&self, text: &str) -> Vec<String> {
        if text.is_empty() {
            return Vec::new();
        }
        let Some(ref re) = self.compiled_all else { return Vec::new() };
        re.find_iter(text)
            .map(|m| format!("IOC:{}", m.as_str()))
            .collect()
    }

    pub fn check_hash(&self, hash_val: &str) -> Vec<String> {
        if hash_val.is_empty() {
            return Vec::new();
        }
        if self.hashes.contains(&hash_val.to_lowercase()) {
            vec![format!("IOC_HASH:{}", hash_val)]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(dir: &tempfile::TempDir, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.path().join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    /// The defect: a hash in `iocs.txt` went into `filenames`, so `check_hash`
    /// never saw it and an Amcache SHA1 match was impossible.
    #[test]
    fn a_hash_in_a_text_list_is_matchable_as_a_hash() {
        let dir = tempfile::tempdir().unwrap();
        let sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let p = write(&dir, "iocs.txt", &format!("{sha1}\n"));
        let m = IOCMatcher::new(Some(&p)).unwrap();
        assert_eq!(m.hashes.len(), 1);
        assert_eq!(m.check_hash(sha1), vec![format!("IOC_HASH:{sha1}")]);
        // Uppercase in the evidence must still match a lowercase list entry.
        assert_eq!(m.check_hash(&sha1.to_uppercase()).len(), 1);
    }

    #[test]
    fn text_lines_are_classified_by_shape() {
        assert_eq!(classify_txt_line("192.168.1.10"), TxtKind::Ip);
        assert_eq!(classify_txt_line("1.2.3.4.5"), TxtKind::Filename);
        assert_eq!(classify_txt_line("999.1.1.1"), TxtKind::Filename);
        assert_eq!(classify_txt_line("d41d8cd98f00b204e9800998ecf8427e"), TxtKind::Hash);
        assert_eq!(classify_txt_line("evil-c2.example.com"), TxtKind::Domain);
        assert_eq!(classify_txt_line("beacon.exe"), TxtKind::Filename);
        assert_eq!(classify_txt_line(r"C:\Temp\svch0st.exe"), TxtKind::Filename);
    }

    /// The line accounting the operator asked for: every line of the file is
    /// either an indicator, a comment or blank, and the three sum to the total.
    #[test]
    fn every_line_of_the_file_is_accounted_for() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            &dir,
            "iocs.txt",
            "# case IOCs\n\n10.0.0.5\nevil.example.com\nbeacon.exe\n\n// another comment\n\
             d41d8cd98f00b204e9800998ecf8427e\n",
        );
        let cov = IOCMatcher::new(Some(&p)).unwrap().coverage();
        let s = cov.source.as_ref().unwrap();
        assert_eq!(s.lines_total, 8);
        assert_eq!(s.lines_comment, 2);
        assert_eq!(s.lines_blank, 2);
        assert_eq!(s.lines_indicator, 4);
        assert_eq!(s.lines_indicator + s.lines_comment + s.lines_blank, s.lines_total);
        assert_eq!(cov.total(), 4);
        assert_eq!((cov.ips, cov.domains, cov.hashes, cov.filenames), (1, 1, 1, 1));
    }

    /// A mistyped path must not produce a run that quietly checks nothing.
    #[test]
    fn a_missing_ioc_file_is_an_error_rather_than_silence() {
        let err = IOCMatcher::new(Some(Path::new("/nonexistent/iocs.txt")))
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not exist"), "{err}");
        assert!(err.contains("indistinguishable"), "{err}");
    }

    /// wiskess substitutes `{ioc_file}` into the reporter args. If that variable
    /// is empty the parser receives `-i ""`, which is not a missing file — it is
    /// a missing setting, and failing the whole collection over it would be
    /// worse than running without IOCs and saying so.
    #[test]
    fn an_empty_path_degrades_to_no_iocs_rather_than_failing_the_run() {
        let m = IOCMatcher::new(Some(Path::new(""))).unwrap();
        assert!(!m.coverage().supplied());
    }

    /// No file supplied is a valid run, and must be distinguishable from a file
    /// that supplied nothing.
    #[test]
    fn no_file_and_an_empty_file_are_different_states() {
        let none = IOCMatcher::new(None).unwrap().coverage();
        assert!(!none.supplied());

        let dir = tempfile::tempdir().unwrap();
        let p = write(&dir, "iocs.txt", "# nothing but a comment\n");
        let empty = IOCMatcher::new(Some(&p)).unwrap().coverage();
        assert!(empty.supplied());
        assert_eq!(empty.total(), 0);
    }

    #[test]
    fn yaml_lists_still_load_by_type() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            &dir,
            "iocs.yaml",
            "iocs:\n  ips:\n    - 10.0.0.5\n  domains:\n    - evil.example.com\n  \
             hashes:\n    - D41D8CD98F00B204E9800998ECF8427E\n  usernames:\n    - svc_backup\n",
        );
        let m = IOCMatcher::new(Some(&p)).unwrap();
        let cov = m.coverage();
        assert_eq!(cov.source.as_ref().unwrap().format, "yaml");
        assert_eq!((cov.ips, cov.domains, cov.hashes, cov.usernames), (1, 1, 1, 1));
        assert!(m.hashes.contains("d41d8cd98f00b204e9800998ecf8427e"));
    }

    #[test]
    fn an_ip_in_evidence_text_is_matched() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(&dir, "iocs.txt", "10.0.0.5\n");
        let m = IOCMatcher::new(Some(&p)).unwrap();
        assert_eq!(m.check("logon from 10.0.0.5 succeeded"), vec!["IOC:10.0.0.5"]);
        assert!(m.check("logon from 10.0.0.6 succeeded").is_empty());
    }
}
