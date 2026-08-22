//! SHA1 hash reputation lookup for Amcache execution evidence.
//!
//! Pipeline (adapted from the uac-parser/uniqess `hash_lookup` module):
//!   1. Offline local lists  — known-good / known-bad SHA1 files (air-gap friendly)
//!   2. CIRCL hashlookup     — NSRL + software-package known-clean filter (online)
//!   3. Malware Bazaar       — abuse.ch known-bad, free, no API key (online)
//!   4. VirusTotal           — unknowns only, requires API key (online, opt-in)
//!
//! NOTE: Amcache stores **SHA1**. The uac-parser offline step used ClamAV `.hdb`
//! databases which are **MD5-only**, so that step does not apply here — offline
//! coverage is provided by local SHA1 allow/deny lists instead.

use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum Classification {
    KnownClean,
    KnownBad,
    VtMalicious,
    VtClean,
    Unknown,
}

impl Classification {
    pub fn label(&self) -> &'static str {
        match self {
            Classification::KnownClean => "known-clean",
            Classification::KnownBad => "known-bad",
            Classification::VtMalicious => "vt-malicious",
            Classification::VtClean => "vt-clean",
            Classification::Unknown => "unknown",
        }
    }
    /// True when the verdict means the hash is malicious / should raise severity.
    pub fn is_bad(&self) -> bool {
        matches!(self, Classification::KnownBad | Classification::VtMalicious)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HashResult {
    pub sha1: String,
    pub classification: Classification,
    pub detail: String,
}

/// Options controlling which online sources are queried.
pub struct HashLookupOpts {
    /// Run online OSINT (CIRCL + Malware Bazaar). Off in `--offline` mode.
    pub online: bool,
    /// Also submit remaining unknowns to VirusTotal (requires API key).
    pub use_vt: bool,
    /// VirusTotal API key (from `--vt-key` or `WTP_VT_API_KEY` / `UNIQESS_VT_API_KEY`).
    pub vt_key: Option<String>,
    /// VT requests per minute (4 = free tier). 0 = unlimited.
    pub vt_rate_limit: u32,
    pub verbose: bool,
}

impl Default for HashLookupOpts {
    fn default() -> Self {
        Self { online: false, use_vt: false, vt_key: None, vt_rate_limit: 4, verbose: false }
    }
}

/// Offline allow/deny lists loaded from `tools/threat_intel/`.
#[derive(Default)]
pub struct OfflineLists {
    pub known_good: HashSet<String>,
    /// sha1 -> label
    pub known_bad: HashMap<String, String>,
}

impl OfflineLists {
    /// Load `tools/threat_intel/known_good_hashes.txt` and `known_bad_hashes.txt`
    /// if present. Each line: a SHA1, optionally `sha1:label` for the bad list.
    /// Lines starting with `#` are comments.
    pub fn load(dir: &Path) -> Self {
        let mut lists = OfflineLists::default();
        if let Ok(content) = std::fs::read_to_string(dir.join("known_good_hashes.txt")) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                let h = line.split_whitespace().next().unwrap_or("").to_lowercase();
                if h.len() == 40 { lists.known_good.insert(h); }
            }
        }
        if let Ok(content) = std::fs::read_to_string(dir.join("known_bad_hashes.txt")) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                let (h, label) = match line.split_once(':') {
                    Some((h, l)) => (h.trim(), l.trim()),
                    None => (line, ""),
                };
                let h = h.to_lowercase();
                if h.len() == 40 {
                    lists.known_bad.insert(h, if label.is_empty() { "local known-bad list".into() } else { label.to_string() });
                }
            }
        }
        lists
    }

    pub fn count(&self) -> usize {
        self.known_good.len() + self.known_bad.len()
    }
}

/// Run the full lookup pipeline over `hashes` (unique, lowercase SHA1).
/// Returns a verdict for every input hash. Network failures degrade gracefully
/// (the affected hashes stay `Unknown`).
pub fn run(hashes: &[String], offline: &OfflineLists, opts: &HashLookupOpts) -> HashMap<String, HashResult> {
    let mut results: HashMap<String, HashResult> = hashes.iter().map(|h| {
        (h.clone(), HashResult { sha1: h.clone(), classification: Classification::Unknown, detail: String::new() })
    }).collect();

    // Step 1: offline lists (fast, always on)
    for (sha1, r) in results.iter_mut() {
        if let Some(label) = offline.known_bad.get(sha1) {
            r.classification = Classification::KnownBad;
            r.detail = format!("local: {}", label);
        } else if offline.known_good.contains(sha1) {
            r.classification = Classification::KnownClean;
            r.detail = "local known-good list".to_string();
        }
    }

    if !opts.online {
        return results;
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("wiskess-timeline-parser")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[hash-lookup] HTTP client init failed, staying offline: {}", e);
            return results;
        }
    };

    // Step 2: CIRCL hashlookup (known-clean filter) on current unknowns
    let unknowns: Vec<String> = unknown_keys(&results);
    if !unknowns.is_empty() {
        match query_circl_bulk(&client, &unknowns, opts.verbose) {
            Ok(known) => {
                for sha1 in &known {
                    if let Some(r) = results.get_mut(sha1) {
                        if r.classification == Classification::Unknown {
                            r.classification = Classification::KnownClean;
                            r.detail = "CIRCL NSRL/package".to_string();
                        }
                    }
                }
                eprintln!("[hash-lookup] CIRCL: {} known-clean", known.len());
            }
            Err(e) => eprintln!("[hash-lookup] CIRCL query failed: {}", e),
        }
    }

    // Step 3: Malware Bazaar (known-bad) on remaining unknowns
    let unknowns: Vec<String> = unknown_keys(&results);
    if !unknowns.is_empty() {
        match query_malware_bazaar(&client, &unknowns, opts.verbose) {
            Ok(hits) => {
                for (sha1, detail) in &hits {
                    if let Some(r) = results.get_mut(sha1) {
                        if r.classification == Classification::Unknown {
                            r.classification = Classification::KnownBad;
                            r.detail = detail.clone();
                        }
                    }
                }
                eprintln!("[hash-lookup] Malware Bazaar: {} known-bad", hits.len());
            }
            Err(e) => eprintln!("[hash-lookup] Malware Bazaar query failed: {}", e),
        }
    }

    // Step 4: VirusTotal (optional, unknowns only)
    if opts.use_vt {
        match &opts.vt_key {
            Some(key) => {
                let unknowns: Vec<String> = unknown_keys(&results);
                query_virustotal(&client, &unknowns, key, opts.vt_rate_limit, &mut results, opts.verbose);
            }
            None => eprintln!("[hash-lookup] --vt set but no API key (set WTP_VT_API_KEY); skipping VT"),
        }
    }

    results
}

fn unknown_keys(results: &HashMap<String, HashResult>) -> Vec<String> {
    results.iter()
        .filter(|(_, r)| r.classification == Classification::Unknown)
        .map(|(k, _)| k.clone())
        .collect()
}

fn query_circl_bulk(client: &reqwest::blocking::Client, hashes: &[String], verbose: bool) -> Result<HashSet<String>> {
    let mut known: HashSet<String> = HashSet::new();
    let batch_size = 100;
    let mut backoff = Duration::from_secs(1);

    for (batch_idx, chunk) in hashes.chunks(batch_size).enumerate() {
        let upper: Vec<String> = chunk.iter().map(|h| h.to_uppercase()).collect();
        let body = serde_json::json!({ "hashes": upper });

        let mut attempts = 0;
        loop {
            let resp = client.post("https://hashlookup.circl.lu/bulk/sha1").json(&body).send();
            match resp {
                Ok(r) => {
                    if r.status().as_u16() == 429 {
                        attempts += 1;
                        if attempts > 5 { return Ok(known); }
                        std::thread::sleep(backoff);
                        backoff = (backoff * 2).min(Duration::from_secs(30));
                        continue;
                    }
                    if !r.status().is_success() {
                        if verbose { eprintln!("[circl] batch {} HTTP {}", batch_idx, r.status()); }
                        break;
                    }
                    backoff = Duration::from_secs(1);
                    if let Ok(items) = r.json::<Vec<serde_json::Value>>() {
                        for item in &items {
                            if let Some(h) = item.get("SHA-1").or_else(|| item.get("SHA1")).and_then(|v| v.as_str()) {
                                known.insert(h.to_lowercase());
                            }
                        }
                    }
                    break;
                }
                Err(e) => { if verbose { eprintln!("[circl] batch {} failed: {}", batch_idx, e); } break; }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(known)
}

fn query_malware_bazaar(client: &reqwest::blocking::Client, hashes: &[String], verbose: bool) -> Result<HashMap<String, String>> {
    let mut hits: HashMap<String, String> = HashMap::new();
    for (i, hash) in hashes.iter().enumerate() {
        let form = [("query", "get_info"), ("hash", hash.as_str())];
        match client.post("https://mb-api.abuse.ch/api/v1/").form(&form).send() {
            Ok(r) => {
                if r.status().as_u16() == 429 {
                    if verbose { eprintln!("[malware-bazaar] rate limited at {}, stopping", i); }
                    break;
                }
                if r.status().is_success() {
                    if let Ok(body) = r.json::<serde_json::Value>() {
                        if body.get("query_status").and_then(|v| v.as_str()) == Some("ok") {
                            let data = body.get("data").and_then(|d| d.get(0));
                            let sig = data.and_then(|d| d.get("signature")).and_then(|v| v.as_str()).unwrap_or("malware");
                            let tags = data.and_then(|d| d.get("tags")).and_then(|v| v.as_array())
                                .map(|a| a.iter().filter_map(|t| t.as_str()).collect::<Vec<_>>().join(", "))
                                .unwrap_or_default();
                            let detail = if tags.is_empty() {
                                format!("MalwareBazaar: {}", sig)
                            } else {
                                format!("MalwareBazaar: {} [{}]", sig, tags)
                            };
                            hits.insert(hash.clone(), detail);
                        }
                    }
                }
            }
            Err(e) => { if verbose { eprintln!("[malware-bazaar] {} failed: {}", hash, e); } }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(hits)
}

fn query_virustotal(
    client: &reqwest::blocking::Client,
    hashes: &[String],
    api_key: &str,
    rate_limit: u32,
    results: &mut HashMap<String, HashResult>,
    verbose: bool,
) {
    let interval = if rate_limit > 0 { Some(Duration::from_secs(60) / rate_limit) } else { None };
    let mut last = std::time::Instant::now() - interval.unwrap_or(Duration::ZERO);
    let mut malicious = 0u32;

    eprintln!("[hash-lookup] Submitting {} unknowns to VirusTotal...", hashes.len());
    for hash in hashes {
        if let Some(iv) = interval {
            let el = last.elapsed();
            if el < iv { std::thread::sleep(iv - el); }
        }
        last = std::time::Instant::now();

        let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);
        match client.get(&url).header("x-apikey", api_key).send() {
            Ok(r) => {
                match r.status().as_u16() {
                    404 => continue,
                    429 => { eprintln!("[vt] rate limited — stopping"); break; }
                    s if !(200..300).contains(&s) => {
                        if verbose { eprintln!("[vt] {} HTTP {}", hash, s); }
                        continue;
                    }
                    _ => {}
                }
                if let Ok(body) = r.json::<serde_json::Value>() {
                    let stats = &body["data"]["attributes"]["last_analysis_stats"];
                    let mal = stats["malicious"].as_u64().unwrap_or(0);
                    let sus = stats["suspicious"].as_u64().unwrap_or(0);
                    let total = mal + sus + stats["undetected"].as_u64().unwrap_or(0) + stats["harmless"].as_u64().unwrap_or(0);
                    if let Some(res) = results.get_mut(hash) {
                        if mal + sus > 0 {
                            res.classification = Classification::VtMalicious;
                            res.detail = format!("VirusTotal: {}/{} engines flagged", mal + sus, total);
                            malicious += 1;
                        } else {
                            res.classification = Classification::VtClean;
                            res.detail = format!("VirusTotal: 0/{} clean", total);
                        }
                    }
                }
            }
            Err(e) => { if verbose { eprintln!("[vt] {} failed: {}", hash, e); } }
        }
    }
    eprintln!("[hash-lookup] VirusTotal: {} malicious", malicious);
}

/// Resolve a VirusTotal API key from CLI override then environment.
pub fn resolve_vt_key(cli_key: Option<&str>) -> Option<String> {
    if let Some(k) = cli_key {
        if !k.is_empty() { return Some(k.to_string()); }
    }
    for var in ["WTP_VT_API_KEY", "UNIQESS_VT_API_KEY"] {
        if let Ok(k) = std::env::var(var) {
            if !k.is_empty() { return Some(k); }
        }
    }
    None
}

/// Write the text + JSON hash-lookup reports into `out_dir`.
pub fn write_reports(results: &HashMap<String, HashResult>, out_dir: &Path) -> Result<()> {
    use std::collections::BTreeMap;
    let mut by_class: BTreeMap<&str, Vec<&HashResult>> = BTreeMap::new();
    for r in results.values() {
        by_class.entry(r.classification.label()).or_default().push(r);
    }
    let total = results.len();
    let count = |c: &Classification| results.values().filter(|r| &r.classification == c).count();

    let mut report = String::new();
    report.push_str("=== Amcache SHA1 Hash Lookup Report ===\n");
    report.push_str(&format!("Total unique SHA1 hashes: {}\n", total));
    report.push_str(&"-".repeat(60));
    report.push('\n');
    report.push_str(&format!("  Known-bad:        {:>5}\n", count(&Classification::KnownBad)));
    report.push_str(&format!("  VT malicious:     {:>5}\n", count(&Classification::VtMalicious)));
    report.push_str(&format!("  Known-clean:      {:>5}\n", count(&Classification::KnownClean)));
    report.push_str(&format!("  VT clean:         {:>5}\n", count(&Classification::VtClean)));
    report.push_str(&format!("  Unknown:          {:>5}\n", count(&Classification::Unknown)));

    let mut bad: Vec<&HashResult> = results.values().filter(|r| r.classification.is_bad()).collect();
    bad.sort_by(|a, b| a.sha1.cmp(&b.sha1));
    if !bad.is_empty() {
        report.push_str("\nMALICIOUS\n");
        report.push_str(&"-".repeat(60));
        report.push('\n');
        for r in &bad {
            report.push_str(&format!("  {} | {} | {}\n", r.sha1, r.classification.label(), r.detail));
        }
    }

    std::fs::create_dir_all(out_dir)?;
    std::fs::write(out_dir.join("hash_lookup.txt"), &report)?;

    let json = serde_json::json!({
        "total": total,
        "summary": {
            "known_bad": count(&Classification::KnownBad),
            "vt_malicious": count(&Classification::VtMalicious),
            "known_clean": count(&Classification::KnownClean),
            "vt_clean": count(&Classification::VtClean),
            "unknown": count(&Classification::Unknown),
        },
        "results": results.values().map(|r| serde_json::json!({
            "sha1": r.sha1,
            "classification": r.classification.label(),
            "detail": r.detail,
        })).collect::<Vec<_>>(),
    });
    std::fs::write(out_dir.join("hash_lookup.json"), serde_json::to_string_pretty(&json)?)?;
    Ok(())
}
