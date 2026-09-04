use anyhow::Result;
use std::collections::HashSet;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::PipelineConfig;
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::intel::geo::GeoReaders;
use crate::timeline_parser::output::event::UnifiedEvent;

static KNOWN_GOOD_DOMAINS: &[&str] = &[
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com",
    "office365.com", "live.com", "outlook.com", "azure.com", "msn.com",
    "bing.com", "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "firefox.com", "mozilla.org", "mozilla.com", "mozilla.net",
    "apple.com", "icloud.com", "akamai.net", "akamaized.net",
    "cloudflare.com", "cloudfront.net", "amazonaws.com",
    "github.com", "githubusercontent.com", "digicert.com", "verisign.com",
    "letsencrypt.org", "symantec.com", "norton.com", "mcafee.com",
    "linkedin.com", "facebook.com", "twitter.com",
    "manageengine.com", "zoho.com", "zohocdn.com",
    "microsoftonline.com", "azureedge.net", "msedge.net", "msftauth.net",
    "bullhornstaffing.com", "badgernotes.net",
];

fn extract_domain(url: &str) -> String {
    let without_scheme = url
        .strip_prefix("https://").or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = without_scheme.split('/').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or(host);
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len()-2], parts[parts.len()-1])
    } else {
        host.to_string()
    }
}

fn domain_entropy(domain: &str) -> f64 {
    if domain.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in domain.bytes() {
        freq[b as usize] += 1;
    }
    let len = domain.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn parse(
    filepath: &Path,
    cfg: &PipelineConfig,
    ioc_matcher: &IOCMatcher,
    geo: &GeoReaders,
    hostname: &str,
) -> Result<Vec<UnifiedEvent>> {
    let known_good: HashSet<&str> = KNOWN_GOOD_DOMAINS.iter().copied().collect();
    let mut events = Vec::new();

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    let col = |name: &str| headers.iter().position(|h| h == name);
    let ts_idx = col("datetime").unwrap_or(0);
    let url_idx = col("URL").unwrap_or(1);
    let title_idx = col("Title");
    let profile_idx = col("User Profile");

    for result in rdr.records() {
        let Ok(record) = result else { continue };

        let ts = record.get(ts_idx).unwrap_or("").to_string();
        let url = record.get(url_idx).unwrap_or("");
        let title = title_idx.and_then(|i| record.get(i)).unwrap_or("");
        let user_profile = profile_idx.and_then(|i| record.get(i)).unwrap_or("");

        let domain = extract_domain(url);
        let base_domain = domain.split('.').next().unwrap_or(&domain);

        let scan_text = format!("{} {}", url, domain);
        let ioc_hits = ioc_matcher.check(&scan_text);

        let is_known_good = known_good.iter().any(|kg| domain.ends_with(kg));
        let mut is_suspicious_domain = false;

        // A raw IP-literal host (no domain) is itself noteworthy — force it into the output.
        let ip_host = crate::timeline_parser::intel::geo::url_ip_literal(url);
        if ip_host.is_some() {
            is_suspicious_domain = true;
        }

        if !is_known_good && !domain.is_empty() {
            let entropy = domain_entropy(base_domain);
            if entropy > 3.5 && base_domain.len() > 8 {
                is_suspicious_domain = true;
            }
            if base_domain.len() <= 3 {
                is_suspicious_domain = true;
            }
        }

        if ioc_hits.is_empty() && !is_suspicious_domain && !cfg.in_timewindow(&ts) {
            continue;
        }
        if is_known_good && ioc_hits.is_empty() {
            continue;
        }

        let mut indicators: Vec<String> = ioc_hits;
        let mut severity = "low".to_string();

        if let Some(ref ip) = ip_host {
            indicators.push(format!("IP:{}", ip));
            severity = "med".to_string();
            let gi = geo.lookup(ip);
            if !gi.is_empty() {
                indicators.push(format!("GEO:{}", gi.summary()));
            }
            if gi.is_anonymizing() {
                indicators.push(format!("GEO:anonymizing_{}", gi.proxy_type));
                severity = "high".to_string();
            }
        } else if is_suspicious_domain {
            indicators.push(format!("DOMAIN:high_entropy_{}", domain));
            severity = "med".to_string();
        }
        if indicators.iter().any(|i| i.starts_with("IOC:")) {
            severity = "high".to_string();
        }
        if cfg.in_timewindow(&ts) && !is_known_good {
            indicators.push("BROWSER:visited_during_attack_window".to_string());
        }

        let url_trunc = url.char_indices().nth(200).map_or(url, |(i, _)| &url[..i]);
        let title_trunc = title.char_indices().nth(80).map_or(title, |(i, _)| &title[..i]);

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "browser-hist".to_string(),
            event_type: "web_navigation".to_string(),
            severity,
            description: format!("Browsed: {} | Title: {}", url_trunc, title_trunc),
            indicators,
            mitre_tactic: String::new(),
            mitre_technique: String::new(),
            user: user_profile.to_string(),
            hostname: hostname.to_string(),
            detection_rule: "browser_analysis".to_string(),
            ..Default::default()
        });
    }

    Ok(events)
}
