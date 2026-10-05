use anyhow::Result;
use std::collections::HashSet;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::PipelineConfig;
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::detectors::ta_tools::TAToolDetector;
use crate::timeline_parser::detectors::Attack;
use crate::timeline_parser::intel::geo::GeoReaders;
use crate::timeline_parser::output::event::UnifiedEvent;
use crate::timeline_parser::parsers::columns::{self, Columns, Field, DATETIME};

/// Which of hindsight's record shapes this row is. Required: the parser dispatches
/// on it, so an unresolved `data_type` matches no arm and the artifact goes silent.
const DATA_TYPE: Field = Field::required("data_type", &["data_type"]);
/// The visited/downloaded URL. Required for the same reason as in `browser_hist`.
const URL: Field = Field::required("url", &["url", "URL"]);
/// The download's save path, for `chrome:history:file_downloaded`.
const VALUE: Field = Field::optional("value", &["value"]);
/// The Chrome profile directory the record came out of — a **filesystem path**,
/// not a user. See [`profile_user`].
const PROFILE: Field = Field::optional("profile", &["profile"]);
const MESSAGE_HINDSIGHT: Field = Field::optional("message_hindsight", &["message_hindsight"]);

/// The account a Chrome profile path belongs to, or empty.
///
/// `user` used to be set to the last path segment of `profile`, which is the
/// browser's own directory name (`Default`, `Profile 1`), not a person. On one host
/// that produced a single Account Activity row of 55,977 events keyed on a
/// directory. A profile path does name the account — it sits under
/// `\Users\<name>\` — so that is what is extracted, and when it cannot be, the
/// field is left empty rather than filled with something that is not a user.
fn profile_user(profile: &str) -> String {
    let normalised = profile.replace('/', "\\");
    let lower = normalised.to_lowercase();
    let Some(at) = lower.find("\\users\\") else { return String::new() };
    let rest = &normalised[at + "\\users\\".len()..];
    let name = rest.split('\\').next().unwrap_or("").trim();
    if name.is_empty() { String::new() } else { name.to_string() }
}

/// Append IP-literal geo enrichment to a browser event's indicators, returning a
/// severity bump ("high") when the host is an anonymising/hosting service.
fn enrich_ip(url: &str, geo: &GeoReaders, indicators: &mut Vec<String>) -> Option<&'static str> {
    let ip = crate::timeline_parser::intel::geo::url_ip_literal(url)?;
    indicators.push(format!("IP:{}", ip));
    let gi = geo.lookup(&ip);
    if !gi.is_empty() {
        indicators.push(format!("GEO:{}", gi.summary()));
    }
    if gi.is_anonymizing() {
        indicators.push(format!("GEO:anonymizing_{}", gi.proxy_type));
        Some("high")
    } else {
        None
    }
}

static KNOWN_GOOD_DOMAINS: &[&str] = &[
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com",
    "office365.com", "live.com", "outlook.com", "azure.com", "msn.com",
    "bing.com", "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "firefox.com", "mozilla.org", "mozilla.com", "mozilla.net",
    "apple.com", "icloud.com", "akamai.net", "akamaized.net",
    "cloudflare.com", "cloudfront.net", "amazonaws.com",
    "github.com", "githubusercontent.com", "digicert.com", "verisign.com",
    "letsencrypt.org", "symantec.com", "norton.com", "mcafee.com",
    "linkedin.com", "facebook.com", "twitter.com", "instagram.com",
    "manageengine.com", "zoho.com", "zohocdn.com",
    "microsoftonline.com", "azureedge.net", "msedge.net", "msftauth.net",
    "wikipedia.org", "wikimedia.org",
    "googletagmanager.com", "doubleclick.net", "googlesyndication.com",
    "bullhornstaffing.com", "badgernotes.net",
];

static EXECUTABLE_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
    ".msi", ".cab", ".scr", ".com", ".pif", ".jar", ".wsf", ".lnk",
];

fn extract_domain(url: &str) -> String {
    let without_scheme = url
        .strip_prefix("https://").or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = without_scheme.split('/').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or(host);
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        host.to_string()
    }
}

fn domain_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn is_executable(path: &str) -> bool {
    let lower = path.to_lowercase();
    EXECUTABLE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

pub fn parse(
    filepath: &Path,
    cfg: &PipelineConfig,
    ioc_matcher: &IOCMatcher,
    ta_detector: &TAToolDetector,
    geo: &GeoReaders,
    hostname: &str,
) -> Result<Vec<UnifiedEvent>> {
    let known_good: HashSet<&str> = KNOWN_GOOD_DOMAINS.iter().copied().collect();
    let mut events = Vec::new();

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(reader);
    let headers = rdr.headers()?.clone();

    let cols = Columns::resolve(
        "hindsight",
        filepath,
        &headers,
        &[DATETIME, DATA_TYPE, URL, VALUE, PROFILE, MESSAGE_HINDSIGHT],
    );

    let mut rows = 0usize;
    for result in rdr.records() {
        let Ok(record) = result else { continue };
        rows += 1;

        let ts = cols.get(&record, "datetime").to_string();
        if ts.is_empty() {
            continue;
        }

        match cols.get(&record, "data_type") {
            "chrome:history:page_visited" => {
                if let Some(ev) = process_page_visited(
                    &record, ts, &cols,
                    cfg, ioc_matcher, ta_detector, geo, &known_good, hostname,
                ) {
                    events.push(ev);
                }
            }
            "chrome:history:file_downloaded" => {
                if let Some(ev) = process_file_downloaded(
                    &record, ts, &cols,
                    cfg, ioc_matcher, ta_detector, geo, hostname,
                ) {
                    events.push(ev);
                }
            }
            "chrome:login_item:entry" => {
                if let Some(ev) = process_login_item(
                    &record, ts, &cols, cfg, ioc_matcher, geo, hostname,
                ) {
                    events.push(ev);
                }
            }
            _ => {}
        }
    }

    columns::note_rows("hindsight", rows);
    Ok(events)
}

fn process_page_visited(
    record: &csv::StringRecord,
    ts: String,
    cols: &Columns,
    cfg: &PipelineConfig,
    ioc_matcher: &IOCMatcher,
    ta_detector: &TAToolDetector,
    geo: &GeoReaders,
    known_good: &HashSet<&str>,
    hostname: &str,
) -> Option<UnifiedEvent> {
    let url = cols.get(record, "url");
    if url.is_empty() {
        return None;
    }

    let domain = extract_domain(url);
    let base_domain = domain.split('.').next().unwrap_or(&domain);
    let is_known_good = known_good.iter().any(|kg| domain.ends_with(kg));
    let is_ip_literal = crate::timeline_parser::intel::geo::url_ip_literal(url).is_some();

    let scan_text = format!("{} {}", url, domain);
    let ioc_hits = ioc_matcher.check(&scan_text);
    let mut attack = Attack::default();
    let ta_hits: Vec<String> = ta_detector
        .scan(&scan_text)
        .into_iter()
        .map(|m| {
            attack.from_tool(&m);
            format!("TA_TOOL:{}", m.name)
        })
        .collect();

    let mut is_suspicious_domain = is_ip_literal;
    if !is_known_good && !domain.is_empty() {
        let entropy = domain_entropy(base_domain);
        if entropy > 3.5 && base_domain.len() > 8 {
            is_suspicious_domain = true;
        }
        if base_domain.len() <= 3 && !base_domain.is_empty() {
            is_suspicious_domain = true;
        }
    }

    let in_window = cfg.in_timewindow(&ts);

    if ioc_hits.is_empty() && ta_hits.is_empty() && !is_suspicious_domain && !in_window {
        return None;
    }
    if is_known_good && ioc_hits.is_empty() && ta_hits.is_empty() {
        return None;
    }

    let mut indicators: Vec<String> = ioc_hits;
    indicators.extend(ta_hits);
    let mut severity = "low".to_string();

    if is_ip_literal {
        if let Some(bump) = enrich_ip(url, geo, &mut indicators) {
            severity = bump.to_string();
        } else {
            severity = "med".to_string();
        }
    } else if is_suspicious_domain {
        indicators.push(format!("DOMAIN:high_entropy_{}", domain));
        severity = "med".to_string();
    }
    if in_window && !is_known_good {
        indicators.push("BROWSER:visited_during_attack_window".to_string());
        if severity == "low" {
            severity = "low".to_string();
        }
    }
    if indicators.iter().any(|i| i.starts_with("IOC:") || i.starts_with("TA_TOOL:")) {
        severity = "high".to_string();
    }

    let title = cols.get(record, "message_hindsight");
    let profile = cols.get(record, "profile");

    Some(UnifiedEvent {
        timestamp: ts,
        source: "hindsight".to_string(),
        event_type: "web_navigation".to_string(),
        severity,
        description: describe(&format!("Visited: {} | {}", url, title), profile),
        indicators,
        mitre_tactic: attack.tactic,
        mitre_technique: attack.technique,
        user: profile_user(profile),
        hostname: hostname.to_string(),
        detection_rule: "browser_hindsight".to_string(),
        ..Default::default()
    })
}

/// Put the browser profile where it belongs — in the description, as context —
/// rather than in the `user` field, where it is not an account.
fn describe(base: &str, profile: &str) -> String {
    if profile.is_empty() {
        base.to_string()
    } else {
        format!("{base} | Profile: {profile}")
    }
}

fn process_file_downloaded(
    record: &csv::StringRecord,
    ts: String,
    cols: &Columns,
    cfg: &PipelineConfig,
    ioc_matcher: &IOCMatcher,
    ta_detector: &TAToolDetector,
    geo: &GeoReaders,
    hostname: &str,
) -> Option<UnifiedEvent> {
    let url = cols.get(record, "url");
    let save_path = cols.get(record, "value");

    let filename = save_path
        .split(['/', '\\'])
        .last()
        .unwrap_or(save_path);

    let scan_text = format!("{} {} {}", url, save_path, filename);
    let ioc_hits = ioc_matcher.check(&scan_text);
    let ta_hits: Vec<String> = ta_detector.scan(&scan_text).into_iter().map(|m| format!("TA_TOOL:{}", m.name)).collect();

    let executable = is_executable(save_path) || is_executable(url);
    let in_window = cfg.in_timewindow(&ts);

    if !executable && !in_window && ioc_hits.is_empty() && ta_hits.is_empty() {
        return None;
    }

    let mut indicators: Vec<String> = ioc_hits;
    indicators.extend(ta_hits);
    let mut severity = "low".to_string();

    if executable {
        indicators.push("BROWSER:executable_download".to_string());
        severity = "med".to_string();
    }
    if let Some(bump) = enrich_ip(url, geo, &mut indicators) {
        severity = bump.to_string();
    }
    if in_window {
        indicators.push("BROWSER:downloaded_during_attack_window".to_string());
    }
    if indicators.iter().any(|i| i.starts_with("IOC:") || i.starts_with("TA_TOOL:")) {
        severity = "high".to_string();
    }

    let profile = cols.get(record, "profile");

    Some(UnifiedEvent {
        timestamp: ts,
        source: "hindsight".to_string(),
        event_type: "file_download".to_string(),
        severity,
        description: describe(&format!("Downloaded: {} → {}", url, save_path), profile),
        indicators,
        mitre_tactic: "Collection".to_string(),
        mitre_technique: "T1213".to_string(),
        user: profile_user(profile),
        hostname: hostname.to_string(),
        detection_rule: "browser_hindsight_download".to_string(),
        ..Default::default()
    })
}

fn process_login_item(
    record: &csv::StringRecord,
    ts: String,
    cols: &Columns,
    cfg: &PipelineConfig,
    ioc_matcher: &IOCMatcher,
    geo: &GeoReaders,
    hostname: &str,
) -> Option<UnifiedEvent> {
    let url = cols.get(record, "url");
    let in_window = cfg.in_timewindow(&ts);
    let ioc_hits = ioc_matcher.check(url);
    let is_ip_literal = crate::timeline_parser::intel::geo::url_ip_literal(url).is_some();

    if !in_window && ioc_hits.is_empty() && !is_ip_literal {
        return None;
    }

    let mut indicators: Vec<String> = ioc_hits;
    let mut severity = "low".to_string();

    if let Some(bump) = enrich_ip(url, geo, &mut indicators) {
        severity = bump.to_string();
    } else if is_ip_literal {
        severity = "med".to_string();
    }
    if in_window {
        indicators.push("BROWSER:login_entry_during_attack_window".to_string());
        if severity == "low" {
            severity = "med".to_string();
        }
    }
    if indicators.iter().any(|i| i.starts_with("IOC:")) {
        severity = "high".to_string();
    }

    let profile = cols.get(record, "profile");

    Some(UnifiedEvent {
        timestamp: ts,
        source: "hindsight".to_string(),
        event_type: "saved_credential".to_string(),
        severity,
        description: describe(&format!("Saved login: {}", url), profile),
        indicators,
        mitre_tactic: "Credential Access".to_string(),
        mitre_technique: "T1555.003".to_string(),
        user: profile_user(profile),
        hostname: hostname.to_string(),
        detection_rule: "browser_hindsight_login".to_string(),
        ..Default::default()
    })
}
