use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::timeline_parser::parsers::columns::{Columns, Field, MESSAGE};

/// The host stamped on every row of a normalised timeline CSV.
///
/// Optional on purpose: this is asked of several files speculatively, and a file
/// that does not carry it is not a coverage failure — it is just not the place the
/// hostname lives. Resolving it through [`Columns`] rather than a local
/// lowercase comparison is what makes `Computer_Name` and `host-name` match too.
const HOSTNAME_COL: Field =
    Field::optional("hostname", &["hostname", "Computer", "ComputerName", "Computer_Name"]);

/// Resolve the host this collection came from.
///
/// Order, most to least authoritative:
///   1. `Host_Information.csv` in the Timeline/ folder (wiskess writes it).
///   2. `Host_Information.txt` in the collection root.
///   3. The `hostname` column carried by the timeline CSVs themselves —
///      registry.csv and event-logs.csv are stamped with it on every row.
///   4. The collection folder name, `Collection-<host>-...`.
///
/// Previously every one of these lived inside `if let Some(hayabusa) =
/// artifacts.get("hayabusa")`, so a Timeline/ without a hayabusa.csv resolved
/// to None and the run was labelled UNKNOWN — even when registry.csv and
/// event-logs.csv both said NSKSTG-GWDB01 on thousands of rows. hayabusa is
/// only produced for event logs and is absent from plenty of valid outputs; it
/// was never the right thing to gate on. The hostname names every output file
/// (`<host>_supertimeline.jsonl`), so getting it wrong strands the results:
/// anything asking for them by host finds nothing.
/// Every name this collection resolves for the host, and where each came from.
///
/// wiskess writes its own `hostname` field as a comma-joined pair —
/// `<device-reported name>, <AD/DNS-resolved name>` — whenever the two differ.
/// That is legitimate information: the parser resolved a second name for the
/// device. But expressing it *only* by concatenating both into one field means
/// nothing querying by the device's plain name ever finds the output filed under
/// the pair. On a 31-host pilot that cost 5 hosts an unnecessary slow fallback
/// or an outright failure.
///
/// So the divergence is stated as a fact — `Device name: MY-NPS01 (also
/// resolves to WIN-A1B2C3D4E5F)` — rather than left as an accident of how a
/// field got indexed.
#[derive(Debug, Clone, Default)]
pub struct HostIdentity {
    /// The name used for output files and the report title.
    pub name: String,
    /// Every distinct name observed, with the artefact that reported it.
    pub observed: Vec<(String, String)>,
}

impl HostIdentity {
    /// Names that are genuinely *different* from the primary one.
    ///
    /// An FQDN of the same machine is not a divergence — `MY-DC02` and
    /// `MY-DC02.domain.local` are one name written two ways, and reporting
    /// that on every domain-joined host would bury the case this exists for
    /// (`MY-NPS01` also answering to `WIN-A1B2C3D4E5F`). Comparison is on the
    /// short name.
    pub fn aliases(&self) -> Vec<&(String, String)> {
        let short = |h: &str| h.split('.').next().unwrap_or(h).trim().to_lowercase();
        let primary = short(&self.name);
        let mut seen: Vec<String> = Vec::new();
        let mut out = Vec::new();
        for pair in &self.observed {
            let s = short(&pair.1);
            if s == primary || seen.contains(&s) {
                continue;
            }
            seen.push(s);
            out.push(pair);
        }
        out
    }

    pub fn diverges(&self) -> bool {
        !self.aliases().is_empty()
    }
}

/// Resolve the host's identity: its primary name plus every alias the
/// collection reports for it.
pub fn resolve_identity(
    artifacts: &HashMap<String, PathBuf>,
    timeline_dir: &Path,
) -> HostIdentity {
    let mut observed: Vec<(String, String)> = Vec::new();
    let mut note = |source: &str, name: &str| {
        // wiskess joins a divergent pair with a comma; split it back apart so
        // both names are visible as names rather than as one odd string.
        for part in name.split(',') {
            let n = part.trim();
            if n.is_empty() || n == "-" || n.eq_ignore_ascii_case("n/a") {
                continue;
            }
            if !observed
                .iter()
                .any(|(s, existing)| s == source && existing.eq_ignore_ascii_case(n))
            {
                observed.push((source.to_string(), n.to_string()));
            }
        }
    };

    let host_info_csv = timeline_dir.join("Host_Information.csv");
    if host_info_csv.exists() {
        for (key, value) in host_info_fields(&host_info_csv) {
            if key.starts_with("Hostname") {
                note(&key, &value);
            }
        }
    }
    for key in ["registry", "event-logs", "amcache", "appcompatcache"] {
        if let Some(path) = artifacts.get(key) {
            if let Some(n) = hostname_from_csv_column(path) {
                note(key, &n);
            }
        }
    }
    // Same, for files sitting in Timeline/ but not in the artifact map — the
    // fallback `get_hostname` already relies on.
    for name in ["registry.csv", "event-logs.csv"] {
        if artifacts.values().any(|p| p.file_name().and_then(|f| f.to_str()) == Some(name)) {
            continue;
        }
        let p = timeline_dir.join(name);
        if p.exists() {
            if let Some(n) = hostname_from_csv_column(&p) {
                note(name, &n);
            }
        }
    }

    let name = get_hostname(artifacts, timeline_dir).unwrap_or_else(|| "UNKNOWN".to_string());
    HostIdentity { name, observed }
}

pub fn get_hostname(artifacts: &HashMap<String, PathBuf>, timeline_dir: &Path) -> Option<String> {
    // 1. Host_Information.csv, written into Timeline/ by wiskess.
    let host_info_csv = timeline_dir.join("Host_Information.csv");
    if host_info_csv.exists() {
        if let Some(name) = parse_host_info_csv(&host_info_csv) {
            return Some(name);
        }
    }

    // 2. Host_Information.txt in the collection root (Timeline/'s parent).
    if let Some(root) = timeline_dir.parent() {
        let host_info_txt = root.join("Host_Information.txt");
        if host_info_txt.exists() {
            if let Ok(content) = std::fs::read_to_string(&host_info_txt) {
                for line in content.lines() {
                    if line.contains("Computer Name") || line.contains("Hostname") {
                        if let Some((_, after)) = line.split_once(':') {
                            let name = after.trim();
                            if !name.is_empty() {
                                return Some(name.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. The `hostname` column of the timeline CSVs. Registry first: it comes
    //    from the SYSTEM hive, so it is the host's own name rather than
    //    whatever a log record happened to reference.
    for key in ["registry", "event-logs", "amcache", "appcompatcache"] {
        if let Some(path) = artifacts.get(key) {
            if let Some(name) = hostname_from_csv_column(path) {
                return Some(name);
            }
        }
    }
    // Same, for files present in Timeline/ but not in the artifact map.
    for name in ["registry.csv", "event-logs.csv"] {
        let p = timeline_dir.join(name);
        if p.exists() {
            if let Some(h) = hostname_from_csv_column(&p) {
                return Some(h);
            }
        }
    }

    // 4. Collection-<host>-... folder name.
    if let Some(root) = timeline_dir.parent() {
        if let Some(dir_name) = root.file_name().and_then(|n| n.to_str()) {
            if let Some(rest) = dir_name.strip_prefix("Collection-") {
                let host = rest.split(['-', '_']).next().unwrap_or("").trim();
                if !host.is_empty() {
                    return Some(host.to_string());
                }
            }
        }
    }

    None
}

/// Read the `hostname` column from a wiskess timeline CSV and return the most
/// common non-empty value.
///
/// Most common, not first: a log line can reference another machine, but the
/// host that produced the collection dominates its own artefacts. Only the
/// first 5000 rows are read — registry.csv runs to millions of lines and this
/// is a label, not an analysis.
fn hostname_from_csv_column(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(std::io::BufReader::new(file));

    let headers = rdr.headers().ok()?.clone();
    let cols = Columns::resolve("host-identity", path, &headers, &[HOSTNAME_COL]);
    if !cols.has("hostname") {
        return None;
    }

    let mut counts: HashMap<String, usize> = HashMap::new();
    for record in rdr.records().flatten().take(5000) {
        let v = cols.get(&record, "hostname");
        // "-" and "N/A" are how these tools spell "no value".
        if v.is_empty() || v == "-" || v.eq_ignore_ascii_case("n/a") {
            continue;
        }
        *counts.entry(v.to_string()).or_default() += 1;
    }

    counts.into_iter().max_by_key(|(_, n)| *n).map(|(h, _)| h)
}

/// Every `key: value` fact wiskess writes into `Host_Information.csv`.
///
/// The file is one fact per row in a `message` column — `Install Date: …`,
/// `Windows Version (Product Name): …`, `Security Log Retention: From: … to: …`.
/// Three separate checks were reaching into it for one field each; this reads it
/// once and hands back all of them.
///
/// Split on the FIRST `": "` only: `Security Log Retention` has colons in its
/// value, and splitting on every colon truncates it to "From".
pub fn host_info_fields(path: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(content) = std::fs::read_to_string(path) else { return out };
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(content.as_bytes());
    let Ok(headers) = rdr.headers().cloned() else { return out };
    let cols = Columns::resolve("host-information", path, &headers, &[MESSAGE]);
    if !cols.has("message") {
        return out;
    }

    for record in rdr.records().flatten() {
        let msg = cols.get(&record, "message");
        if let Some((key, value)) = msg.split_once(": ") {
            let value = value.trim();
            if !key.is_empty() && !value.is_empty() {
                // First wins: the file lists each fact once, and a later row
                // repeating a key is the summary line rather than the value.
                out.entry(key.trim().to_string()).or_insert_with(|| value.to_string());
            }
        }
    }
    out
}

fn parse_host_info_csv(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(content.as_bytes());
    let headers = rdr.headers().ok()?.clone();
    let cols = Columns::resolve("host-information", path, &headers, &[MESSAGE]);
    if !cols.has("message") {
        return None;
    }
    for result in rdr.records().flatten() {
        let msg = cols.get(&result, "message");
        // Lines like "Hostname Registry: WKS-0001" or "Hostname Event Logs: WKS-0001"
        if msg.starts_with("Hostname") {
            if let Some((_, after)) = msg.split_once(':') {
                let name = after.trim().to_string();
                if !name.is_empty() {
                    return Some(name);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three checks that read this file all need different keys out of it.
    #[test]
    fn host_information_facts_are_read_as_key_value_pairs() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Host_Information.csv");
        std::fs::write(
            &p,
            "datetime,timestamp_desc,message\n\
             2026-05-11 14:58:47.6,Hostinfo,Hostname Registry: MY-DC02\n\
             2026-05-11 14:58:47.6,Hostinfo,Windows Version (Product Name): Windows Server 2016 Standard\n\
             2026-05-11 14:58:47.6,Hostinfo,Build Lab: 14393.rs1_release.260227-2344\n\
             2026-05-11 14:58:47.6,Hostinfo,Install Date: 2019-06-07 23:37:44.0000000\n\
             2026-05-11 14:58:47.6,Hostinfo,\"Security Log Retention: From: 2026-05-05 07:24:05 to: 2026-05-11 09:35:03\"\n",
        )
        .unwrap();
        let f = host_info_fields(&p);
        assert_eq!(f.get("Windows Version (Product Name)").unwrap(), "Windows Server 2016 Standard");
        assert_eq!(f.get("Install Date").unwrap(), "2019-06-07 23:37:44.0000000");
        // The value has its own colons and must survive intact.
        assert_eq!(
            f.get("Security Log Retention").unwrap(),
            "From: 2026-05-05 07:24:05 to: 2026-05-11 09:35:03"
        );
    }

    #[test]
    fn a_missing_host_information_file_yields_no_facts_rather_than_panicking() {
        assert!(host_info_fields(Path::new("/nonexistent/Host_Information.csv")).is_empty());
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hostinfo-{}-{tag}", std::process::id()));
        std::fs::remove_dir_all(&d).ok();
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The regression: a Timeline/ with no hayabusa.csv but a registry.csv that
    /// states the hostname on every row. This resolved to UNKNOWN, which named
    /// every output file UNKNOWN_* and stranded the results.
    #[test]
    fn resolves_hostname_from_registry_csv_without_hayabusa() {
        let d = tmp("registry");
        std::fs::write(
            d.join("registry.csv"),
            "datetime,message,hostname\n\
             2024-07-09T09:24:21Z,something,NSKSTG-GWDB01\n\
             2024-07-09T09:24:22Z,other,NSKSTG-GWDB01\n",
        ).unwrap();

        let got = get_hostname(&HashMap::new(), &d);
        std::fs::remove_dir_all(&d).ok();
        assert_eq!(got.as_deref(), Some("NSKSTG-GWDB01"));
    }

    /// A stray reference to another machine must not outvote the host's own
    /// artefacts.
    #[test]
    fn picks_the_dominant_hostname_not_the_first_row() {
        let d = tmp("dominant");
        std::fs::write(
            d.join("event-logs.csv"),
            "datetime,hostname\n\
             t,OTHER-BOX\n\
             t,REAL-HOST\n\
             t,REAL-HOST\n\
             t,REAL-HOST\n",
        ).unwrap();

        let got = get_hostname(&HashMap::new(), &d);
        std::fs::remove_dir_all(&d).ok();
        assert_eq!(got.as_deref(), Some("REAL-HOST"));
    }

    #[test]
    fn empty_and_placeholder_values_are_ignored() {
        let d = tmp("placeholder");
        std::fs::write(
            d.join("registry.csv"),
            "datetime,hostname\nt,-\nt,\nt,N/A\nt,GOOD-HOST\n",
        ).unwrap();

        let got = get_hostname(&HashMap::new(), &d);
        std::fs::remove_dir_all(&d).ok();
        assert_eq!(got.as_deref(), Some("GOOD-HOST"));
    }

    /// Host_Information.csv is authoritative and wins over the CSV columns.
    #[test]
    fn host_information_csv_wins() {
        let d = tmp("hostinfo");
        std::fs::write(
            d.join("Host_Information.csv"),
            "datetime,message\nt,Hostname Registry: FROM-HOSTINFO\n",
        ).unwrap();
        std::fs::write(d.join("registry.csv"), "datetime,hostname\nt,FROM-REGISTRY\n").unwrap();

        let got = get_hostname(&HashMap::new(), &d);
        std::fs::remove_dir_all(&d).ok();
        assert_eq!(got.as_deref(), Some("FROM-HOSTINFO"));
    }

    /// Last resort: the collection folder name.
    #[test]
    fn falls_back_to_the_collection_folder_name() {
        let base = tmp("foldername");
        let tl = base.join("Collection-WS08_corp-2026-07-04").join("Timeline");
        std::fs::create_dir_all(&tl).unwrap();

        let got = get_hostname(&HashMap::new(), &tl);
        std::fs::remove_dir_all(&base).ok();
        assert_eq!(got.as_deref(), Some("WS08"));
    }

    /// Nothing to go on — still None, never a panic.
    #[test]
    fn no_signal_is_none() {
        let d = tmp("empty");
        let got = get_hostname(&HashMap::new(), &d);
        std::fs::remove_dir_all(&d).ok();
        assert_eq!(got, None);
    }

    /// The case this exists for: a device answering to a second, unrelated name.
    /// Nothing querying by the device's plain name finds output filed under the
    /// pair, and on a 31-host pilot that cost 5 hosts a fallback or a failure.
    #[test]
    fn a_genuinely_different_second_name_is_surfaced_as_an_alias() {
        let d = tmp("alias");
        std::fs::write(
            d.join("Host_Information.csv"),
            "datetime,message\n\
             t,Hostname Registry: MY-NPS01\n\
             t,Hostname Event Logs: WIN-A1B2C3D4E5F\n",
        ).unwrap();

        let id = resolve_identity(&HashMap::new(), &d);
        std::fs::remove_dir_all(&d).ok();
        assert_eq!(id.name, "MY-NPS01");
        assert!(id.diverges());
        let names: Vec<&str> = id.aliases().iter().map(|(_, n)| n.as_str()).collect();
        assert_eq!(names, vec!["WIN-A1B2C3D4E5F"]);
    }

    /// An FQDN is the same name written twice. Reporting it as a divergence on
    /// every domain-joined host would bury the real ones.
    #[test]
    fn an_fqdn_of_the_same_host_is_not_a_divergence() {
        let d = tmp("fqdn");
        std::fs::write(
            d.join("Host_Information.csv"),
            "datetime,message\n\
             t,Hostname Registry: MY-DC02\n\
             t,Hostname Event Logs: MY-DC02.domain.local\n",
        ).unwrap();

        let id = resolve_identity(&HashMap::new(), &d);
        std::fs::remove_dir_all(&d).ok();
        assert_eq!(id.name, "MY-DC02");
        assert!(!id.diverges(), "{:?}", id.aliases());
    }

    /// wiskess writes a divergent pair comma-joined into one field. Both halves
    /// have to come back out as names.
    #[test]
    fn a_comma_joined_pair_is_split_back_into_two_names() {
        let d = tmp("joined");
        std::fs::write(
            d.join("registry.csv"),
            "datetime,hostname\nt,\"MY-NPS01, WIN-A1B2C3D4E5F\"\n",
        ).unwrap();

        let id = resolve_identity(&HashMap::new(), &d);
        std::fs::remove_dir_all(&d).ok();
        assert!(id.observed.iter().any(|(_, n)| n == "MY-NPS01"), "{:?}", id.observed);
        assert!(id.observed.iter().any(|(_, n)| n == "WIN-A1B2C3D4E5F"), "{:?}", id.observed);
    }

    /// A CSV with no hostname column must not be mistaken for a source.
    #[test]
    fn csv_without_hostname_column_is_skipped() {
        let d = tmp("nocol");
        std::fs::write(d.join("registry.csv"), "datetime,message\nt,nothing here\n").unwrap();
        let got = get_hostname(&HashMap::new(), &d);
        std::fs::remove_dir_all(&d).ok();
        assert_eq!(got, None);
    }
}
