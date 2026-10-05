//! What kind of file is this, and is the path even readable?
//!
//! The MFT and USN parsers each carried their own literal extension list, and
//! `.jsp` was in neither — nor in any path rule, nor in the browser or hindsight
//! lists. The consequence was not a missed severity: `mft.rs` dropped any row
//! whose extension was not "high interest" **before** building an event, so a set
//! of JSP webshells written into a ColdFusion webroot produced no event at all.
//! Not a low-severity one. None. The path rules and the classifier never saw
//! them, because there was nothing left to see.
//!
//! Two decisions follow from that.
//!
//! **The extension lists are compiled in, not YAML.** They are control flow —
//! they decide whether a row becomes an event — and a missing or truncated
//! `--data-dir` must not be able to empty them. Paths stay in
//! `suspicious_paths.yaml`, where a site-specific webroot belongs and where being
//! able to add one without a rebuild is the point.
//!
//! **Path shape is normalised in one place.** The same file arrives spelled three
//! ways across this collection format: `MFTECmd.csv` gives a *relative*
//! `.\ColdFusion2018\cfusion\...`, `mft_dump.csv` gives `/`-separated
//! `FullPath`, and the rusty USN parse gives `[root]/Users/...`. Rules written
//! against one spelling silently miss the other two.

/// Extensions worth an event on their own.
///
/// Wider than "executable" on purpose: a webshell is a text file that the server
/// happens to execute, so the interpreter's extension is the signal. Ordered
/// roughly by family, and the server-side script block is the one that was
/// missing.
pub const SCRIPT_EXT: &[&str] = &[
    // PE and friends
    ".exe", ".dll", ".com", ".scr", ".sys", ".msi", ".msp", ".cpl", ".ocx", ".pif", ".drv",
    // Windows scripting
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".sct", ".inf", ".reg", ".lnk", ".url",
    // Server-side script: the gap that let the webshells through.
    ".jsp", ".jspx", ".jspf", ".jsv", ".jsw", ".soap",
    ".asp", ".aspx", ".ashx", ".asmx", ".ascx",
    ".cfm", ".cfml", ".cfc",
    ".war", ".jar", ".java", ".class",
    // Cross-platform interpreters
    ".py", ".pl", ".rb", ".sh", ".xsl", ".xslt",
];

/// Archive formats — staging and exfiltration containers.
pub const ARCHIVE_EXT: &[&str] = &[
    ".zip", ".rar", ".7z", ".cab", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".iso", ".vhd", ".vhdx", ".img",
];

/// High-churn extensions that carry no signal by themselves.
///
/// Note `.dll` is **not** here even though it is high-churn: a dropped DLL is a
/// finding, and the servicing stack's own DLLs are removed by classification
/// (`os:component-store`, `os:servicing`) rather than by extension. Filtering
/// them here would take the finding with them.
pub const NOISE_EXT: &[&str] = &[
    ".tmp", ".log", ".etl", ".mum", ".manifest", ".cat", ".evtx", ".pf", ".db", ".dat",
];

/// Is this an extension we keep an event for?
///
/// The `.ph*` arm covers `.php`, `.phtml`, `.php5`, `.php7`, `.phar` and `.pht`
/// in one go — the PHP family is open-ended enough that enumerating it invites
/// exactly the gap this function exists to close.
pub fn is_script(ext: &str) -> bool {
    let e = normalise_ext(ext);
    if SCRIPT_EXT.contains(&e.as_str()) {
        return true;
    }
    // .php .phtml .php5 .phar .pht ...
    e.starts_with(".ph") && e.len() >= 3
}

pub fn is_archive(ext: &str) -> bool {
    ARCHIVE_EXT.contains(&normalise_ext(ext).as_str())
}

pub fn is_noise(ext: &str) -> bool {
    NOISE_EXT.contains(&normalise_ext(ext).as_str())
}

/// Lowercase an extension and give it a leading dot.
///
/// Sources disagree: `MFTECmd.csv` writes `.jsp`, other tools write `jsp`, and a
/// derived one may carry trailing space.
fn normalise_ext(ext: &str) -> String {
    let t = ext.trim().to_lowercase();
    if t.is_empty() || t == "." {
        String::new()
    } else if t.starts_with('.') {
        t
    } else {
        format!(".{t}")
    }
}

/// The extension of a filename, for the files whose CSV has no `Extension`
/// column (the rusty USN parse, `mft_dump.csv`).
///
/// Returns `""` rather than guessing when there is no dot, and ignores a leading
/// dot so `.gitignore` is not read as having extension `.gitignore`.
pub fn ext_of(filename: &str) -> String {
    let name = filename.trim().trim_end_matches(['/', '\\']);
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    // `> 0`, not `>= 0`: a leading dot is a dotfile, not an extension.
    match base.rfind('.') {
        Some(i) if i > 0 => normalise_ext(&base[i..]),
        _ => String::new(),
    }
}

/// The filename at the end of a path, either separator.
///
/// For `mft_dump.csv`, which carries only `FullPath` — no `FileName` column — so
/// the extension and the name have to come out of the path itself.
pub fn base_of(path: &str) -> String {
    let p = path.trim().trim_end_matches(['/', '\\']);
    p.rsplit(['/', '\\']).next().unwrap_or(p).to_string()
}

/// Bring a path to one spelling before any rule looks at it.
///
/// - `/` becomes `\`, because every rule and every allowlist in this codebase is
///   written in Windows form;
/// - the rusty USN parser's `[root]` volume marker is dropped;
/// - a leading `.\` (MFTECmd's relative form) is kept as `\` so a rule anchored
///   on a directory boundary still matches the first segment.
///
/// What it deliberately does **not** do is invent a drive letter. The MFT rows
/// genuinely do not say which volume they came from, and writing `C:` in would be
/// asserting something the evidence does not.
pub fn normalise_path(raw: &str) -> String {
    let mut p = raw.trim().replace('/', "\\");
    for prefix in ["[root]", "[ROOT]"] {
        if let Some(rest) = p.strip_prefix(prefix) {
            p = rest.to_string();
        }
    }
    if let Some(rest) = p.strip_prefix(".\\") {
        p = format!("\\{rest}");
    }
    p
}

/// Join a parent directory and a filename, tolerating either separator and an
/// absent parent.
pub fn join_path(parent: &str, name: &str) -> String {
    let parent = normalise_path(parent);
    let name = name.trim();
    if parent.is_empty() {
        return name.to_string();
    }
    if name.is_empty() {
        return parent;
    }
    format!("{}\\{}", parent.trim_end_matches('\\'), name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The miss that started this: a JSP is a script.
    #[test]
    fn server_side_script_extensions_are_recognised() {
        for ext in [".jsp", ".jspx", ".jspf", ".asp", ".aspx", ".cfm", ".cfc", ".class", ".war"] {
            assert!(is_script(ext), "{ext} must be a script extension");
        }
        // Case and a missing dot are both tolerated, because sources vary.
        assert!(is_script("JSP"));
        assert!(is_script(" .Jsp "));
    }

    #[test]
    fn the_php_family_is_matched_by_prefix_not_enumeration() {
        for ext in [".php", ".phtml", ".php5", ".php7", ".phar", ".pht"] {
            assert!(is_script(ext), "{ext} must be a script extension");
        }
    }

    #[test]
    fn ordinary_documents_are_not_scripts() {
        for ext in [".txt", ".docx", ".pdf", ".png", ".css", ".html", ""] {
            assert!(!is_script(ext), "{ext} must not be a script extension");
        }
    }

    /// `.html` is not executable, so it is not a script — the webroot rule is
    /// what makes a file *in a served tree* interesting, not the extension alone.
    #[test]
    fn markup_is_left_to_the_path_rules() {
        assert!(!is_script(".html"));
        assert!(!is_script(".htm"));
    }

    #[test]
    fn a_dll_is_never_treated_as_noise() {
        assert!(!is_noise(".dll"), "a dropped DLL is a finding; the classifier removes vendor ones");
        assert!(is_noise(".tmp"));
        assert!(is_noise(".LOG"));
    }

    #[test]
    fn extensions_are_derived_when_the_csv_has_no_column_for_them() {
        assert_eq!(ext_of("shell.jsp"), ".jsp");
        assert_eq!(ext_of("[root]/srv/wwwroot/shell.JSP"), ".jsp");
        assert_eq!(ext_of("archive.tar.gz"), ".gz");
        assert_eq!(ext_of("noextension"), "");
        assert_eq!(ext_of(".gitignore"), "", "a dotfile has no extension");
        assert_eq!(ext_of(""), "");
    }

    /// All three spellings of the same file must reach the rules identically.
    #[test]
    fn the_three_path_spellings_normalise_to_one() {
        let want = r"\srv\wwwroot\shell.jsp";
        assert_eq!(normalise_path(r".\srv\wwwroot\shell.jsp"), want, "MFTECmd relative form");
        assert_eq!(normalise_path("[root]/srv/wwwroot/shell.jsp"), want, "rusty USN form");
        assert_eq!(normalise_path("/srv/wwwroot/shell.jsp"), want, "mft_dump form");
        assert_eq!(normalise_path(r"\srv\wwwroot\shell.jsp"), want, "already normal");
    }

    /// A drive letter is not invented, because the evidence does not carry one.
    #[test]
    fn a_rooted_path_keeps_its_drive_and_a_relative_one_gains_nothing() {
        assert_eq!(normalise_path(r"C:\srv\shell.jsp"), r"C:\srv\shell.jsp");
        assert!(!normalise_path(r".\srv\shell.jsp").contains(':'));
    }

    #[test]
    fn joining_tolerates_either_separator_and_an_absent_parent() {
        assert_eq!(join_path(r".\srv\wwwroot", "shell.jsp"), r"\srv\wwwroot\shell.jsp");
        assert_eq!(join_path("[root]/srv/wwwroot/", "shell.jsp"), r"\srv\wwwroot\shell.jsp");
        assert_eq!(join_path("", "shell.jsp"), "shell.jsp");
        assert_eq!(join_path(r"\srv", ""), r"\srv");
    }
}
