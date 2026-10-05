//! What is installed on this host, and what about it is worth an analyst's time.
//!
//! Two registry sources carry the Add/Remove Programs inventory, and wiskess
//! emits both:
//!
//!   * `registry.csv`, rows with `Category = "Installed Software"`, whose
//!     `ValueData` packs the Uninstall key into one string —
//!     `KeyName: … DisplayName: … DisplayVersion: … Publisher: … InstallDate: …`
//!   * `regripper.csv`, rows whose description reads `[Uninstall] - <name> v.<version>`
//!
//! Neither is authoritative alone: RegRipper's list is flatter, and the registry
//! export is sometimes taken from `RegBack\SOFTWARE`, a backup hive that can
//! predate the incident by weeks. Both are read, merged on (name, version), and
//! the hive each came from is reported — a stale inventory that looks current is
//! worse than no inventory.
//!
//! On the exposure question this module is deliberately narrow. It asserts two
//! things it can actually know: a product is **past its vendor EOL** (a date, not
//! a CVE — unsupported software is unpatched by definition), or a product is
//! **below an operator-supplied `min_safe_version`**. Everything else is
//! categorised — remote access, tunnelling, file transfer, dual-use — and
//! reported as "look at this", never as "this is vulnerable". Naming CVEs from
//! an offline binary would be inventing forensic findings.

use anyhow::{Context, Result};
use chrono::NaiveDate;
use regex::Regex;
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::detectors::{warn_skipped, SkippedRule};
use crate::timeline_parser::output::event::UnifiedEvent;
use crate::timeline_parser::parsers::columns::{Columns, Field, DATETIME};

/// The packed `Name: value` blob RECmd writes for an Add/Remove Programs key.
/// Required: it is the whole inventory, so a rename means no software list at all.
const VALUE_DATA: Field = Field::required("value_data", &["ValueData"]);
const VALUE_DATA2: Field = Field::optional("value_data2", &["ValueData2"]);
/// Either of these identifies the Add/Remove Programs rows, and the code matches
/// on whichever is present, so neither on its own is required.
const CATEGORY: Field = Field::optional("category", &["Category"]);
const DESCRIPTION: Field = Field::optional("description", &["Description", "description"]);
const HIVE_PATH: Field = Field::optional("hive_path", &["HivePath"]);
/// RegRipper's finding text, which is where the `[Uninstall] - …` lines live.
const RR_DESCRIPTION: Field = Field::required("description", &["description", "Description"]);

/// One installed product, as the registry recorded it.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Installed {
    pub name: String,
    pub version: String,
    pub publisher: String,
    /// `InstallDate` if the key carried one, else the Uninstall key's own
    /// last-write time, which is the closest thing to an install date there is.
    pub installed_at: String,
    pub source: String,
    pub hive: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Past vendor end of support on the given date.
    EndOfLife { eol: String },
    /// Below a `min_safe_version` supplied in the rule file.
    BelowMinSafe { min_safe: String },
    /// Category of interest; presence reported, no vulnerability asserted.
    Review { category: String },
}

impl Verdict {
    pub fn label(&self) -> String {
        match self {
            Verdict::EndOfLife { eol } => format!("END OF LIFE (unsupported since {eol})"),
            Verdict::BelowMinSafe { min_safe } => format!("BELOW MIN SAFE VERSION ({min_safe})"),
            Verdict::Review { category } => format!("review — {category}"),
        }
    }
    pub fn severity(&self) -> &'static str {
        match self {
            Verdict::EndOfLife { .. } | Verdict::BelowMinSafe { .. } => "high",
            Verdict::Review { .. } => "med",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Flag {
    pub product: Installed,
    pub rule: String,
    pub verdict: Verdict,
    pub note: String,
}

#[derive(Debug, Clone, Default)]
pub struct SoftwareInventory {
    pub installed: Vec<Installed>,
    pub flags: Vec<Flag>,
    /// Files that contributed rows.
    pub sources: BTreeSet<String>,
    /// Hives the registry rows came from — `RegBack\SOFTWARE` means the
    /// inventory may not reflect the host at collection time.
    pub hives: BTreeSet<String>,
    /// OS product name from `Host_Information.csv`, and its own EOL verdict.
    pub os_product: Option<String>,
    pub os_flag: Option<Flag>,
    pub rules_eol: usize,
    pub rules_product: usize,
    /// Product rules that carried a `min_safe_version`. Zero means no
    /// version-based determination was possible for anything.
    pub rules_with_versions: usize,
}

impl SoftwareInventory {
    /// Was any inventory found at all? An empty inventory is not a clean host;
    /// it means the SOFTWARE hive was not collected or not parsed.
    pub fn any(&self) -> bool {
        !self.installed.is_empty()
    }
    pub fn from_backup_hive(&self) -> bool {
        self.hives.iter().any(|h| h.to_lowercase().contains("regback"))
    }
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct EolRule {
    re: Regex,
    name: String,
    eol: String,
}

#[derive(Debug)]
struct ProductRule {
    re: Regex,
    name: String,
    category: String,
    min_safe_version: Option<String>,
    note: String,
}

#[derive(Debug, Default)]
pub struct SoftwareRules {
    eol: Vec<EolRule>,
    products: Vec<ProductRule>,
    skipped: Vec<SkippedRule>,
}

impl SoftwareRules {
    /// Load `vulnerable_software.yaml` from the detection data directory.
    ///
    /// A missing file is not an error: the inventory is still worth reporting
    /// without any rules, and refusing to run because a rule pack is absent
    /// would trade a partial answer for none.
    pub fn load(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("vulnerable_software.yaml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let doc: serde_yaml::Value = serde_yaml::from_str(&text)
            .with_context(|| format!("cannot parse {}", path.display()))?;

        let mut out = Self::default();
        for r in doc.get("end_of_life").and_then(|v| v.as_sequence()).into_iter().flatten() {
            let (Some(p), Some(n), Some(e)) = (
                r.get("pattern").and_then(|v| v.as_str()),
                r.get("name").and_then(|v| v.as_str()),
                r.get("eol").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            match Regex::new(p) {
                Ok(re) => out.eol.push(EolRule { re, name: n.into(), eol: e.into() }),
                Err(err) => out.skipped.push(SkippedRule {
                    section: "vulnerable_software.yaml: end_of_life".to_string(),
                    reason: n.to_string(),
                    pattern: p.to_string(),
                    error: err.to_string(),
                }),
            }
        }
        for r in doc.get("products").and_then(|v| v.as_sequence()).into_iter().flatten() {
            let (Some(p), Some(n)) = (
                r.get("pattern").and_then(|v| v.as_str()),
                r.get("name").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            match Regex::new(p) {
                Ok(re) => out.products.push(ProductRule {
                    re,
                    name: n.into(),
                    category: r
                        .get("category")
                        .and_then(|v| v.as_str())
                        .unwrap_or("uncategorised")
                        .into(),
                    min_safe_version: r
                        .get("min_safe_version")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    note: r.get("note").and_then(|v| v.as_str()).unwrap_or("").into(),
                }),
                Err(err) => out.skipped.push(SkippedRule {
                    section: "vulnerable_software.yaml: products".to_string(),
                    reason: n.to_string(),
                    pattern: p.to_string(),
                    error: err.to_string(),
                }),
            }
        }

        warn_skipped("installed-software", &out.skipped, out.eol.len() + out.products.len());
        Ok(out)
    }

    /// Software patterns present in `vulnerable_software.yaml` that are not active.
    pub fn skipped_rules(&self) -> &[SkippedRule] {
        &self.skipped
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        (
            self.eol.len(),
            self.products.len(),
            self.products.iter().filter(|p| p.min_safe_version.is_some()).count(),
        )
    }

    /// Evaluate one product. First matching rule wins, EOL before category —
    /// "unsupported" is the stronger statement and must not be masked by a
    /// category match on the same name.
    pub fn evaluate(&self, p: &Installed, as_of: Option<NaiveDate>) -> Option<Flag> {
        let haystack = format!("{} {}", p.name, p.publisher);

        if let Some(r) = self.eol.iter().find(|r| r.re.is_match(&haystack)) {
            let past = match (NaiveDate::parse_from_str(&r.eol, "%Y-%m-%d").ok(), as_of) {
                (Some(eol), Some(now)) => now > eol,
                // With no reference date the EOL cannot be decided, so it is not
                // asserted. Saying "unsupported" without knowing when is the
                // kind of claim this module exists to avoid.
                _ => false,
            };
            if past {
                return Some(Flag {
                    product: p.clone(),
                    rule: r.name.clone(),
                    verdict: Verdict::EndOfLife { eol: r.eol.clone() },
                    note: "vendor support ended; receives no security updates".into(),
                });
            }
        }

        let r = self.products.iter().find(|r| r.re.is_match(&haystack))?;
        if let Some(min) = &r.min_safe_version {
            if cmp_version(&p.version, min) == Some(Ordering::Less) {
                return Some(Flag {
                    product: p.clone(),
                    rule: r.name.clone(),
                    verdict: Verdict::BelowMinSafe { min_safe: min.clone() },
                    note: r.note.clone(),
                });
            }
        }
        Some(Flag {
            product: p.clone(),
            rule: r.name.clone(),
            verdict: Verdict::Review { category: r.category.clone() },
            note: r.note.clone(),
        })
    }
}

/// Compare dotted version strings numerically.
///
/// `None` when either side does not parse — an undecidable comparison must not
/// silently become "safe". `148.0.2` vs `98.1` is 148 > 98, which a string
/// compare gets backwards.
pub fn cmp_version(a: &str, b: &str) -> Option<Ordering> {
    let parts = |s: &str| -> Option<Vec<u64>> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let v: Vec<u64> = s
            .split(|c: char| c == '.' || c == '-' || c == '_')
            .take_while(|seg| seg.chars().all(|c| c.is_ascii_digit()) && !seg.is_empty())
            .filter_map(|seg| seg.parse().ok())
            .collect();
        (!v.is_empty()).then_some(v)
    };
    let (mut x, mut y) = (parts(a)?, parts(b)?);
    let n = x.len().max(y.len());
    x.resize(n, 0);
    y.resize(n, 0);
    Some(x.cmp(&y))
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

/// Split `KeyName: A DisplayName: B DisplayVersion: C Publisher: D InstallDate: E`
/// into its fields.
///
/// The labels are the delimiters — values contain spaces (`Mozilla Firefox
/// (x64 en-GB)`) so splitting on whitespace loses them. Each label is located in
/// turn and the text between it and the next label is the value.
pub fn parse_packed_value(s: &str) -> HashMap<&'static str, String> {
    const LABELS: &[&str] = &[
        "KeyName:", "DisplayName:", "DisplayVersion:", "Publisher:", "InstallDate:",
        "InstallSource:", "InstallLocation:", "UninstallString:", "Timestamp:",
    ];
    let mut hits: Vec<(usize, &'static str)> = Vec::new();
    for label in LABELS {
        if let Some(at) = s.find(label) {
            hits.push((at, label));
        }
    }
    hits.sort();

    let mut out = HashMap::new();
    for (i, (at, label)) in hits.iter().enumerate() {
        let start = at + label.len();
        let end = hits.get(i + 1).map(|(n, _)| *n).unwrap_or(s.len());
        let value = s[start..end].trim().to_string();
        if !value.is_empty() {
            out.insert(label.trim_end_matches(':'), value);
        }
    }
    out
}

/// Read the Add/Remove Programs rows out of `registry.csv`.
pub fn from_registry_csv(path: &Path) -> Result<Vec<Installed>> {
    let file = std::fs::File::open(path)?;
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(BufReader::new(file));
    let headers = rdr.headers()?.clone();
    let cols = Columns::resolve(
        "software-registry",
        path,
        &headers,
        &[VALUE_DATA, VALUE_DATA2, CATEGORY, DESCRIPTION, HIVE_PATH],
    );

    let mut out = Vec::new();
    for result in rdr.records() {
        let Ok(rec) = result else { continue };
        let category = cols.get(&rec, "category");
        let description = cols.get(&rec, "description");
        // Match on either, so a wiskess build that renames the category but
        // keeps the description (or the reverse) still yields an inventory.
        if !category.eq_ignore_ascii_case("Installed Software")
            && !description.contains("Add/Remove Programs")
        {
            continue;
        }

        let packed = cols.get(&rec, "value_data");
        let fields = parse_packed_value(packed);
        // DisplayName is often empty on OS component keys; KeyName is the
        // fallback and is what an analyst would read off the hive anyway.
        let name = fields
            .get("DisplayName")
            .or_else(|| fields.get("KeyName"))
            .cloned()
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }

        let ts = parse_packed_value(cols.get(&rec, "value_data2"));
        out.push(Installed {
            name,
            version: fields.get("DisplayVersion").cloned().unwrap_or_default(),
            publisher: fields.get("Publisher").cloned().unwrap_or_default(),
            installed_at: fields
                .get("InstallDate")
                .cloned()
                .or_else(|| ts.get("Timestamp").cloned())
                .unwrap_or_default(),
            source: "registry.csv".into(),
            hive: cols.get(&rec, "hive_path").to_string(),
        });
    }
    Ok(out)
}

/// Read `[Uninstall] - <name> v.<version>` rows out of `regripper.csv`.
pub fn from_regripper_csv(path: &Path) -> Result<Vec<Installed>> {
    let file = std::fs::File::open(path)?;
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(BufReader::new(file));
    let headers = rdr.headers()?.clone();
    let cols = Columns::resolve("software-regripper", path, &headers, &[DATETIME, RR_DESCRIPTION]);

    let mut out = Vec::new();
    for result in rdr.records() {
        let Ok(rec) = result else { continue };
        let desc = cols.get(&rec, "description");
        let Some(rest) = desc.strip_prefix("[Uninstall] - ") else { continue };
        let (name, version) = match rest.rsplit_once(" v.") {
            Some((n, v)) => (n.trim().to_string(), v.trim().to_string()),
            None => (rest.trim().to_string(), String::new()),
        };
        if name.is_empty() {
            continue;
        }
        out.push(Installed {
            name,
            version,
            publisher: String::new(),
            installed_at: cols.get(&rec, "datetime").to_string(),
            source: "regripper.csv".into(),
            hive: String::new(),
        });
    }
    Ok(out)
}

/// Merge both sources, evaluate the rules, and note where the data came from.
///
/// `as_of` is the collection date, which is what an EOL is decided against. It
/// is passed in rather than read from the clock: a collection analysed two years
/// after it was taken must be judged as it stood, not as it stands today.
pub fn build(
    registry_csv: Option<&Path>,
    regripper_csv: Option<&Path>,
    rules: &SoftwareRules,
    as_of: Option<NaiveDate>,
) -> Result<SoftwareInventory> {
    let mut inv = SoftwareInventory::default();
    let (e, p, v) = rules.counts();
    inv.rules_eol = e;
    inv.rules_product = p;
    inv.rules_with_versions = v;

    let mut all: Vec<Installed> = Vec::new();
    if let Some(path) = registry_csv {
        let rows = from_registry_csv(path)?;
        if !rows.is_empty() {
            inv.sources.insert("registry.csv".into());
        }
        for r in &rows {
            if !r.hive.is_empty() {
                inv.hives.insert(r.hive.clone());
            }
        }
        all.extend(rows);
    }
    if let Some(path) = regripper_csv {
        let rows = from_regripper_csv(path)?;
        if !rows.is_empty() {
            inv.sources.insert("regripper.csv".into());
        }
        all.extend(rows);
    }

    // Merge on (lowercased name, version). The two sources overlap heavily and
    // a doubled inventory would double every flag.
    all.sort();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for p in all {
        let key = (p.name.to_lowercase(), p.version.clone());
        if seen.insert(key) {
            inv.installed.push(p);
        }
    }

    for p in &inv.installed {
        if let Some(f) = rules.evaluate(p, as_of) {
            inv.flags.push(f);
        }
    }
    // Strongest first: an EOL product should not be below a category note.
    inv.flags.sort_by_key(|f| match f.verdict {
        Verdict::EndOfLife { .. } => 0,
        Verdict::BelowMinSafe { .. } => 1,
        Verdict::Review { .. } => 2,
    });

    Ok(inv)
}

/// Judge the operating system itself, from the Host_Information product name.
pub fn evaluate_os(
    inv: &mut SoftwareInventory,
    product_name: &str,
    build_lab: &str,
    rules: &SoftwareRules,
    as_of: Option<NaiveDate>,
) {
    if product_name.trim().is_empty() {
        return;
    }
    inv.os_product = Some(product_name.to_string());
    let os = Installed {
        name: product_name.to_string(),
        version: build_lab.to_string(),
        publisher: "Microsoft".into(),
        source: "Host_Information.csv".into(),
        ..Default::default()
    };
    inv.os_flag = rules.evaluate(&os, as_of);
}

/// Flagged products become timeline events, so exposure is visible to anything
/// reading the supertimeline rather than only to a human reading the report.
///
/// Only products with a usable install timestamp are emitted: an event with no
/// time is noise in a timeline, and the report carries the rest.
pub fn to_events(inv: &SoftwareInventory, hostname: &str) -> Vec<UnifiedEvent> {
    let mut out = Vec::new();
    for f in &inv.flags {
        let ts = f.product.installed_at.trim();
        if ts.is_empty() {
            continue;
        }
        out.push(UnifiedEvent {
            timestamp: ts.to_string(),
            source: "software-inventory".to_string(),
            event_type: "software_exposure".to_string(),
            severity: f.verdict.severity().to_string(),
            description: format!(
                "Installed: {} {} ({}) — {}{}",
                f.product.name,
                f.product.version,
                f.rule,
                f.verdict.label(),
                if f.note.is_empty() { String::new() } else { format!("; {}", f.note) }
            ),
            indicators: vec![format!("SOFTWARE:{}", f.rule)],
            mitre_tactic: String::new(),
            mitre_technique: String::new(),
            user: String::new(),
            hostname: hostname.to_string(),
            detection_rule: "installed_software_exposure".to_string(),
            ..Default::default()
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn data_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/threat_intel")
    }

    fn rules() -> SoftwareRules {
        SoftwareRules::load(&data_dir()).unwrap()
    }

    fn day(s: &str) -> Option<NaiveDate> {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
    }

    /// The shipped rule pack must actually compile under Rust's regex engine —
    /// it has no lookaround, and a pattern that fails to compile is dropped
    /// silently, which would leave a rule that looks present and never fires.
    #[test]
    fn every_shipped_rule_compiles() {
        let text = std::fs::read_to_string(data_dir().join("vulnerable_software.yaml")).unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();
        let mut declared = 0;
        for section in ["end_of_life", "products"] {
            for r in doc.get(section).and_then(|v| v.as_sequence()).into_iter().flatten() {
                declared += 1;
                let p = r.get("pattern").and_then(|v| v.as_str()).unwrap();
                assert!(Regex::new(p).is_ok(), "{section} pattern does not compile: {p}");
            }
        }
        let (e, prod, _) = rules().counts();
        assert_eq!(e + prod, declared, "a rule was dropped during load");
    }

    /// The packed `ValueData` string is the whole inventory; values contain
    /// spaces and parentheses, so the labels have to be the delimiters.
    #[test]
    fn the_packed_uninstall_value_splits_on_its_labels() {
        let f = parse_packed_value(
            "KeyName: Mozilla Firefox DisplayName: Mozilla Firefox (x64 en-GB) \
             DisplayVersion: 148.0.2 Publisher: Mozilla InstallDate: ",
        );
        assert_eq!(f.get("KeyName").unwrap(), "Mozilla Firefox");
        assert_eq!(f.get("DisplayName").unwrap(), "Mozilla Firefox (x64 en-GB)");
        assert_eq!(f.get("DisplayVersion").unwrap(), "148.0.2");
        assert_eq!(f.get("Publisher").unwrap(), "Mozilla");
        assert!(f.get("InstallDate").is_none(), "an empty value is absent, not blank");
    }

    #[test]
    fn versions_compare_numerically_not_lexically() {
        assert_eq!(cmp_version("148.0.2", "98.1"), Some(Ordering::Greater));
        assert_eq!(cmp_version("7.2.4", "7.2.5"), Some(Ordering::Less));
        assert_eq!(cmp_version("15.51", "15.51.0"), Some(Ordering::Equal));
        // Undecidable must stay undecidable rather than defaulting to safe.
        assert_eq!(cmp_version("", "1.0"), None);
        assert_eq!(cmp_version("v-next", "1.0"), None);
    }

    fn registry_fixture(dir: &tempfile::TempDir, rows: &[(&str, &str)]) -> std::path::PathBuf {
        let p = dir.path().join("registry.csv");
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "datetime,Description,Category,ValueName,ValueData,ValueData2,HivePath").unwrap();
        for (packed, hive) in rows {
            writeln!(
                f,
                "2026-04-08T15:59:13.477Z,Add/Remove Programs Entries,Installed Software,Multiple,\"{}\",\"Timestamp: 2026-03-19 08:31:18.6950921\",\"{}\"",
                packed, hive
            )
            .unwrap();
        }
        p
    }

    #[test]
    fn the_registry_inventory_is_extracted_with_its_hive() {
        let dir = tempfile::tempdir().unwrap();
        let p = registry_fixture(
            &dir,
            &[(
                "KeyName: AnyDesk DisplayName: AnyDesk DisplayVersion: 7.0.15 Publisher: AnyDesk Software GmbH InstallDate: ",
                r"\\?\X:\...\config\RegBack\SOFTWARE",
            )],
        );
        let inv = build(Some(&p), None, &rules(), day("2026-05-11")).unwrap();
        assert_eq!(inv.installed.len(), 1);
        assert_eq!(inv.installed[0].name, "AnyDesk");
        assert_eq!(inv.installed[0].version, "7.0.15");
        // No InstallDate on the key, so the key's own write time stands in.
        assert!(inv.installed[0].installed_at.starts_with("2026-03-19"));
        assert!(inv.from_backup_hive(), "a RegBack hive must be disclosed as possibly stale");
    }

    /// The operator's ask: remote-access software installed on the host.
    #[test]
    fn remote_access_software_is_flagged_for_review_not_called_vulnerable() {
        let dir = tempfile::tempdir().unwrap();
        let p = registry_fixture(
            &dir,
            &[(
                "KeyName: AnyDesk DisplayName: AnyDesk DisplayVersion: 7.0.15 Publisher: AnyDesk Software GmbH InstallDate: ",
                "SOFTWARE",
            )],
        );
        let inv = build(Some(&p), None, &rules(), day("2026-05-11")).unwrap();
        assert_eq!(inv.flags.len(), 1);
        assert_eq!(inv.flags[0].rule, "AnyDesk");
        assert!(matches!(inv.flags[0].verdict, Verdict::Review { .. }));
        assert!(inv.flags[0].verdict.label().contains("remote-access"));
        // Presence is not a vulnerability claim.
        assert!(!inv.flags[0].verdict.label().contains("VULNERABLE"));
    }

    /// Ordinary software is inventoried and not flagged — otherwise every host
    /// produces sixty findings and the section is worthless.
    #[test]
    fn ordinary_software_is_inventoried_but_not_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let p = registry_fixture(
            &dir,
            &[(
                "KeyName: Mozilla Firefox DisplayName: Mozilla Firefox (x64 en-GB) DisplayVersion: 148.0.2 Publisher: Mozilla InstallDate: ",
                "SOFTWARE",
            )],
        );
        let inv = build(Some(&p), None, &rules(), day("2026-05-11")).unwrap();
        assert_eq!(inv.installed.len(), 1);
        assert!(inv.flags.is_empty(), "{:?}", inv.flags);
    }

    #[test]
    fn regripper_uninstall_lines_are_extracted() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("regripper.csv");
        std::fs::write(
            &p,
            "datetime,source,user,description\n\
             2026-02-01T14:08:02.000Z,REG,,[Uninstall] - Mozilla Firefox (x64 en-GB) v.148.0.2\n\
             2026-02-01T14:08:02.000Z,REG,,[Uninstall] - Qualys Cloud Security Agent v.6.4.1.22\n\
             2026-02-01T14:08:02.000Z,REG,,M... AppCompatCache - C:\\Windows\\notepad.exe\n",
        )
        .unwrap();
        let rows = from_regripper_csv(&p).unwrap();
        assert_eq!(rows.len(), 2, "only the [Uninstall] rows are inventory");
        assert_eq!(rows[0].name, "Mozilla Firefox (x64 en-GB)");
        assert_eq!(rows[0].version, "148.0.2");
    }

    /// The two sources overlap; a doubled inventory would double every flag.
    #[test]
    fn the_two_sources_are_merged_rather_than_concatenated() {
        let dir = tempfile::tempdir().unwrap();
        let reg = registry_fixture(
            &dir,
            &[(
                "KeyName: AnyDesk DisplayName: AnyDesk DisplayVersion: 7.0.15 Publisher: AnyDesk InstallDate: ",
                "SOFTWARE",
            )],
        );
        let rr = dir.path().join("regripper.csv");
        std::fs::write(
            &rr,
            "datetime,source,user,description\n\
             2026-02-01T14:08:02.000Z,REG,,[Uninstall] - AnyDesk v.7.0.15\n",
        )
        .unwrap();
        let inv = build(Some(&reg), Some(&rr), &rules(), day("2026-05-11")).unwrap();
        assert_eq!(inv.installed.len(), 1, "{:?}", inv.installed);
        assert_eq!(inv.flags.len(), 1);
        assert_eq!(inv.sources.len(), 2, "both sources are still credited");
    }

    /// An EOL date is a fact about a date, so it must be judged against the
    /// collection — not against whenever the analysis happens to run.
    #[test]
    fn end_of_life_is_judged_against_the_collection_date() {
        let mut past = SoftwareInventory::default();
        evaluate_os(&mut past, "Windows Server 2012 R2 Standard", "9600", &rules(), day("2026-05-11"));
        let f = past.os_flag.expect("2012 R2 was unsupported by 2026");
        assert!(matches!(f.verdict, Verdict::EndOfLife { .. }));
        assert!(f.verdict.label().contains("2023-10-10"), "{}", f.verdict.label());

        // The same host collected before that date is not an EOL finding.
        let mut then = SoftwareInventory::default();
        evaluate_os(&mut then, "Windows Server 2012 R2 Standard", "9600", &rules(), day("2020-01-01"));
        assert!(then.os_flag.is_none(), "{:?}", then.os_flag);
    }

    /// The corpus host: supported at collection, so no EOL finding. Getting this
    /// wrong would put a false "unsupported OS" on a current server.
    #[test]
    fn a_supported_os_is_not_flagged() {
        let mut inv = SoftwareInventory::default();
        evaluate_os(&mut inv, "Windows Server 2016 Standard", "14393", &rules(), day("2026-05-11"));
        assert_eq!(inv.os_product.as_deref(), Some("Windows Server 2016 Standard"));
        assert!(inv.os_flag.is_none(), "2016 is supported until 2027-01-12");
    }

    /// Ordering, not lookaround, is what keeps R2 distinct from non-R2.
    #[test]
    fn the_r2_rule_wins_over_the_base_rule() {
        let mut inv = SoftwareInventory::default();
        evaluate_os(&mut inv, "Windows Server 2008 R2 Standard", "7601", &rules(), day("2026-05-11"));
        assert_eq!(inv.os_flag.unwrap().rule, "Windows Server 2008 R2");
    }

    /// A `min_safe_version` in the rule pack turns a category note into a
    /// version determination.
    #[test]
    fn a_min_safe_version_downgrades_an_outdated_product() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("vulnerable_software.yaml"),
            "products:\n  - pattern: '(?i)\\bforticlient\\b'\n    name: FortiClient\n    \
             category: vpn-client\n    min_safe_version: '7.2.5'\n",
        )
        .unwrap();
        let r = SoftwareRules::load(dir.path()).unwrap();
        assert_eq!(r.counts(), (0, 1, 1));

        let old = Installed { name: "FortiClient".into(), version: "7.2.4".into(), ..Default::default() };
        let new = Installed { name: "FortiClient".into(), version: "7.2.5".into(), ..Default::default() };
        assert!(matches!(r.evaluate(&old, None).unwrap().verdict, Verdict::BelowMinSafe { .. }));
        assert!(matches!(r.evaluate(&new, None).unwrap().verdict, Verdict::Review { .. }));
    }

    /// A missing rule pack must degrade to "inventory only", not to no report.
    #[test]
    fn a_missing_rule_pack_still_produces_an_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let empty = SoftwareRules::load(dir.path()).unwrap();
        assert_eq!(empty.counts(), (0, 0, 0));
        let p = registry_fixture(
            &dir,
            &[("KeyName: AnyDesk DisplayName: AnyDesk DisplayVersion: 7.0.15 Publisher: AnyDesk InstallDate: ", "SOFTWARE")],
        );
        let inv = build(Some(&p), None, &empty, day("2026-05-11")).unwrap();
        assert!(inv.any());
        assert!(inv.flags.is_empty());
    }

    #[test]
    fn flagged_products_with_a_timestamp_become_timeline_events() {
        let dir = tempfile::tempdir().unwrap();
        let p = registry_fixture(
            &dir,
            &[("KeyName: AnyDesk DisplayName: AnyDesk DisplayVersion: 7.0.15 Publisher: AnyDesk InstallDate: ", "SOFTWARE")],
        );
        let inv = build(Some(&p), None, &rules(), day("2026-05-11")).unwrap();
        let events = to_events(&inv, "MY-DC02");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, "software-inventory");
        assert!(events[0].indicators.contains(&"SOFTWARE:AnyDesk".to_string()));
        assert!(events[0].timestamp.starts_with("2026-03-19"));
    }
}
