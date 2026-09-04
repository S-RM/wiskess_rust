use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::LazyLock;

use crate::timeline_parser::config::{severity_order, PipelineConfig, TimeWindow};
use crate::timeline_parser::detectors::classify::Automation;
use crate::timeline_parser::detectors::restoration::{self, PHASE_POST, PHASE_PRE, PHASE_PROCESS, PHASE_RESPONDER};
use crate::timeline_parser::parsers::host_info::HostIdentity;
use crate::timeline_parser::detectors::ioc_matcher::IocCoverage;
use crate::timeline_parser::detectors::restoration::{Continuity, GapKind};
use crate::timeline_parser::detectors::software::{SoftwareInventory, Verdict};
use crate::timeline_parser::intel::geo::GeoReaders;
use crate::timeline_parser::parsers::wiskess_log::CollectionGap;
use super::event::UnifiedEvent;

/// Max characters of an event description rendered in the report before truncating.
const DESC_MAX_CHARS: usize = 300;
/// Characters of the description head kept verbatim (preserves the EventID / source prefix).
const HEAD_CHARS: usize = 100;
/// Characters of context kept on each side of the matched rule hit.
const HIT_CONTEXT: usize = 60;

static IP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap());

/// Hostnames that break the corporate naming convention and warrant attention —
/// default Windows/installer names, pentest distros, personal machines.
static STANDOUT_HOST_RE: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (Regex::new(r"(?i)^DESKTOP-[A-Z0-9]{7}$").unwrap(), "default Windows workstation name"),
        (Regex::new(r"(?i)^WIN-[A-Z0-9]{11}$").unwrap(), "default Windows Server name"),
        (Regex::new(r"(?i)^LAPTOP-[A-Z0-9]{7}$").unwrap(), "default Windows laptop name"),
        (Regex::new(r"(?i)kali").unwrap(), "Kali Linux (offensive distro)"),
        (Regex::new(r"(?i)parrot").unwrap(), "Parrot OS (offensive distro)"),
        (Regex::new(r"(?i)blackarch").unwrap(), "BlackArch (offensive distro)"),
        (Regex::new(r"(?i)pentest|redteam|offsec|attacker|hack").unwrap(), "offensive-tooling keyword"),
        (Regex::new(r"(?i)^MACBOOK|^MBP-|^MAC-").unwrap(), "personal macOS device"),
    ]
});

/// If a hostname matches a standout naming convention, return why.
fn suspicious_hostname(host: &str) -> Option<&'static str> {
    let h = host.trim();
    if h.is_empty() {
        return None;
    }
    STANDOUT_HOST_RE.iter().find(|(re, _)| re.is_match(h)).map(|(_, why)| *why)
}

/// Is this IP a real remote peer worth tabulating (not loopback/broadcast/empty)?
fn tabulatable_ip(ip: &str) -> bool {
    !ip.is_empty() && ip != "0.0.0.0" && !ip.starts_with("127.")
}

/// Normalise a username for grouping: strip domain/realm/SID, lowercase.
fn clean_user(user: &str) -> String {
    let lower = user.to_lowercase();
    let u = lower.split('(').next().unwrap_or(&lower).trim();
    let u = u.split('@').next().unwrap_or(u);
    let u = u.rsplit('\\').next().unwrap_or(u).trim();
    u.to_string()
}

/// Skip machine accounts, system principals, SIDs and raw DNs in the per-user table.
fn is_real_user(u: &str) -> bool {
    !u.is_empty()
        && u != "-"
        && !u.ends_with('$')
        && u != "system"
        && u != "localsystem"
        && u != "anonymous logon"
        && !u.starts_with("nt authority")
        && !u.starts_with("local service")
        && !u.starts_with("network service")
        && !u.starts_with("dwm-")
        && !u.starts_with("umfd-")
        && !u.starts_with("s-1-")            // raw SID
        && !u.contains("=")                  // LDAP distinguished name (cn=…,dc=…)
        && !u.chars().all(|c| c.is_ascii_digit()) // bare numeric ids
}

/// Pull a searchable "needle" out of an indicator (the literal text that triggered the
/// detection).
fn indicator_needle(indicator: &str) -> Option<&str> {
    let val = indicator.rsplit(':').next().unwrap_or(indicator);
    let val = val.strip_prefix("high_entropy_").unwrap_or(val);
    if val.trim().len() >= 3 { Some(val.trim()) } else { None }
}

/// Render a description for the triage report, splicing rule-hit context when truncated.
fn trunc_desc(desc: &str, indicators: &[String]) -> String {
    let chars: Vec<char> = desc.chars().collect();
    if chars.len() <= DESC_MAX_CHARS {
        return desc.to_string();
    }

    let lower: String = desc.to_lowercase();

    let hit_at = indicators.iter()
        .filter_map(|ind| indicator_needle(ind))
        .filter_map(|needle| {
            lower.find(&needle.to_lowercase()).map(|byte_idx| {
                let char_idx = desc[..byte_idx].chars().count();
                (char_idx, needle.chars().count())
            })
        })
        .filter(|(start, _)| *start + 1 > HEAD_CHARS)
        .min_by_key(|(start, _)| *start);

    let head: String = chars[..HEAD_CHARS].iter().collect();

    match hit_at {
        Some((start, len)) => {
            let ctx_start = start.saturating_sub(HIT_CONTEXT);
            let ctx_end = (start + len + HIT_CONTEXT).min(chars.len());
            let context: String = chars[ctx_start..ctx_end].iter().collect();
            let tail = if ctx_end < chars.len() { " …" } else { "" };
            format!("{} … {}{}", head, context, tail)
        }
        None => format!("{}…", head),
    }
}

/// Collapse a markdown table cell: strip pipes/newlines so the row stays intact.
fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\n', '\r'], " ")
}

// ---------------------------------------------------------------------------
// Summary aggregations
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Agg {
    count: usize,
    max_sev: u8,
    first: String,
    last: String,
    tactics: std::collections::BTreeSet<String>,
    inbound: bool,
    outbound: bool,
}

impl Agg {
    fn observe(&mut self, e: &UnifiedEvent) {
        self.count += 1;
        let so = severity_order(&e.severity);
        if so > self.max_sev {
            self.max_sev = so;
        }
        // A timestamp that does not parse must never define a first/last.
        // `20200922` sorts below every ISO value, and on one host it silently
        // became the start of the case-wide activity span.
        if crate::timeline_parser::detectors::restoration::timestamp_is_usable(&e.timestamp) {
            if self.first.is_empty() || e.timestamp < self.first {
                self.first = e.timestamp.clone();
            }
            if e.timestamp > self.last {
                self.last = e.timestamp.clone();
            }
        }
        if !e.mitre_tactic.is_empty() {
            self.tactics.insert(e.mitre_tactic.clone());
        }
    }
}

fn sev_label(order: u8) -> &'static str {
    match order {
        4 => "CRIT",
        3 => "HIGH",
        2 => "MED",
        1 => "LOW",
        _ => "INFO",
    }
}

/// Which detection rule packs were live for this run.
///
/// A parser started from the wrong working directory finds no `ta_tools.yaml`
/// and no `suspicious_paths.yaml`, warns once on stderr, and then produces a
/// complete-looking report — on the corpus this crate is tested against, 13
/// curated hits instead of 238. In a container nobody reads stderr. The rule
/// counts belong in the report, next to the findings they produced.
#[derive(Debug, Clone, Default)]
pub struct DetectionCoverage {
    pub data_dir: String,
    pub ta_patterns: usize,
    pub path_rules: usize,
    pub software_rules: usize,
}

impl DetectionCoverage {
    pub fn degraded(&self) -> bool {
        self.ta_patterns == 0 || self.path_rules == 0
    }
}

/// State the rule packs before anything they produced.
fn write_detection_coverage<W: Write>(w: &mut W, d: &DetectionCoverage) -> Result<()> {
    writeln!(w, "## Detection Coverage")?;
    writeln!(w)?;
    writeln!(w, "| Rule pack | Loaded |")?;
    writeln!(w, "|-----------|--------|")?;
    writeln!(w, "| Threat-actor tool patterns | {} |", d.ta_patterns)?;
    writeln!(w, "| Suspicious path/filename rules | {} |", d.path_rules)?;
    writeln!(w, "| Installed-software rules | {} |", d.software_rules)?;
    writeln!(w, "| Rule directory | `{}` |", d.data_dir)?;
    writeln!(w)?;

    if d.degraded() {
        writeln!(w, "> **DETECTION RULES ARE MISSING — THIS REPORT IS NOT A CLEAN RESULT.**")?;
        writeln!(w, ">")?;
        writeln!(w, "> One or more rule packs failed to load from `{}`, so the corresponding \
            detections could not fire. The timeline below is thinner than the evidence supports \
            and must not be read as a quiet host. Point the parser at its rule directory with \
            `--data-dir` or `WTP_DATA_DIR` and run it again.", d.data_dir)?;
        writeln!(w)?;
    }
    Ok(())
}

/// Everything the report needs beyond the events themselves.
pub struct ReportContext<'a> {
    pub window: &'a Option<TimeWindow>,
    pub identity: &'a HostIdentity,
    pub elapsed: f64,
    pub gaps: &'a [CollectionGap],
    pub geo: &'a GeoReaders,
    pub ioc_coverage: &'a IocCoverage,
    pub detection: &'a DetectionCoverage,
    pub continuity: &'a Continuity,
    pub software: &'a SoftwareInventory,
    pub cfg: &'a PipelineConfig,
    pub automations: &'a [Automation],
    /// A restoration date the operator supplied, as opposed to one inferred.
    pub restoration_supplied: Option<&'a str>,
}

/// Write the triage report and hand back its text.
///
/// The text is returned, not just written, because the markdown narrative is
/// otherwise unreachable: a consumer reading this tool's JSON from an index
/// never sees the report at all, and the sections below are the only place
/// several of these findings are stated in full. The caller indexes them.
pub fn generate_report(
    events: &[UnifiedEvent],
    ctx: &ReportContext<'_>,
    report_path: &Path,
) -> Result<String> {
    let ReportContext {
        window, identity, elapsed, gaps, geo, ioc_coverage, detection, continuity, software,
        cfg, automations, restoration_supplied,
    } = *ctx;
    let hostname = identity.name.as_str();
    let mut w: Vec<u8> = Vec::new();

    let mut sev_counts: HashMap<&str, usize> = HashMap::new();
    for e in events {
        *sev_counts.entry(e.severity.as_str()).or_insert(0) += 1;
    }

    writeln!(w, "# Triage Report: {}", hostname)?;
    writeln!(w)?;
    writeln!(w, "**Generated**: {}Z", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S"))?;
    writeln!(w, "**Events After Filtering**: {}", events.len())?;
    writeln!(w, "**Processing Time**: {:.1}s", elapsed)?;
    writeln!(w)?;

    writeln!(w, "## Executive Summary")?;
    writeln!(w)?;
    writeln!(w, "Analysis identified **{}** events of interest. \
        Severity breakdown: {} critical, {} high, {} medium, {} low, {} informational.",
        events.len(),
        sev_counts.get("crit").unwrap_or(&0),
        sev_counts.get("high").unwrap_or(&0),
        sev_counts.get("med").unwrap_or(&0),
        sev_counts.get("low").unwrap_or(&0),
        sev_counts.get("info").unwrap_or(&0),
    )?;
    writeln!(w)?;

    writeln!(w, "## Timeframe of Interest")?;
    writeln!(w)?;
    if let Some(win) = window {
        writeln!(w, "- **Start**: {}", win.start)?;
        writeln!(w, "- **End**: {}", win.end)?;
        writeln!(w, "- **High-severity events in window**: {}", win.event_count)?;
        writeln!(w, "- **Confidence**: {}", win.confidence)?;
    } else {
        writeln!(w, "- No specific timeframe detected (full range analysed)")?;
    }
    writeln!(w)?;

    write_identity(&mut w, identity)?;
    write_detection_coverage(&mut w, detection)?;
    write_continuity(&mut w, continuity)?;
    write_phases(&mut w, events, continuity, restoration_supplied)?;
    write_evidence_coverage(&mut w, events, continuity)?;

    write_user_table(&mut w, events)?;
    write_ip_table(&mut w, events, geo)?;
    write_external_touchpoints(&mut w, events, geo)?;
    write_hostname_table(&mut w, events)?;
    write_access_timeline(&mut w, events)?;
    write_baseline(&mut w, events, cfg)?;
    write_lateral_section(&mut w, events)?;

    write_ta_tools(&mut w, events)?;
    write_iocs(&mut w, events, ioc_coverage)?;
    write_software(&mut w, software)?;
    write_classifications(&mut w, events, automations)?;
    write_tactic_findings(&mut w, events)?;
    write_gaps(&mut w, gaps)?;

    let markdown = String::from_utf8(w)
        .map_err(|e| anyhow::anyhow!("report is not valid UTF-8: {e}"))?;
    let file = File::create(report_path)?;
    let mut out = BufWriter::new(file);
    out.write_all(markdown.as_bytes())?;
    out.flush()?;
    Ok(markdown)
}


// ---------------------------------------------------------------------------
// Device identity, external touchpoints, evidence coverage, phases
// ---------------------------------------------------------------------------

/// State the host's name, and any second name the collection resolved for it.
///
/// The divergence is real information and it belongs in the report as a
/// readable line, not only as a comma-joined field that a consumer has to
/// already know to look for.
fn write_identity<W: Write>(w: &mut W, id: &HostIdentity) -> Result<()> {
    writeln!(w, "## Device Identity")?;
    writeln!(w)?;
    let aliases = id.aliases();
    if aliases.is_empty() {
        writeln!(w, "- **Device name**: {}", cell(&id.name))?;
        writeln!(w)?;
        return Ok(());
    }

    let names: Vec<&str> = aliases.iter().map(|(_, n)| n.as_str()).collect();
    writeln!(w, "- **Device name**: {} (also resolves to {})",
        cell(&id.name), cell(&names.join(", ")))?;
    writeln!(w)?;
    writeln!(w, "> **This host answers to more than one name.** Output for it is filed under \
        `{}`. Anything querying by {} will not find it unless it also asks for that name.",
        cell(&id.name), names.iter().map(|n| format!("`{n}`")).collect::<Vec<_>>().join(" or "))?;
    writeln!(w)?;
    writeln!(w, "| Reported by | Name |")?;
    writeln!(w, "|-------------|------|")?;
    for (source, name) in &id.observed {
        writeln!(w, "| {} | {} |", cell(source), cell(name))?;
    }
    writeln!(w)?;
    Ok(())
}

/// Is this a public (routable) IPv4 — not RFC1918, loopback, link-local,
/// CGNAT, multicast, broadcast or documentation space?
fn is_public_ip(ip: &str) -> bool {
    let Ok(a) = ip.parse::<std::net::Ipv4Addr>() else { return false };
    let o = a.octets();
    !(a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_unspecified()
        || o[0] == 0
        || (o[0] == 100 && (64..128).contains(&o[1]))     // CGNAT 100.64/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)        // TEST-NET-1
        || (o[0] == 198 && (18..20).contains(&o[1]))      // benchmarking
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)     // TEST-NET-2
        || (o[0] == 203 && o[1] == 0 && o[2] == 113))     // TEST-NET-3
}

/// A domain reached through a URL: `https://host/...`, `ftp://host`, `\\host\share`.
static URL_HOST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:https?|ftp|ftps|ws|wss)://(?:[^/@\s"'|,;)\]]*@)?([a-z0-9.\-]+\.[a-z]{2,24})"#)
        .unwrap()
});

/// A domain named by a field that says it is one — a DNS query name, a URL
/// field, a server or host field.
static LABELLED_HOST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:QueryName|DnsQuery|DestinationHostname|TargetServerName|ServerName|HostName|Host|Domain|Url|Uri)["' :=]{1,4}\s*([a-z0-9][a-z0-9.\-]*\.[a-z]{2,24})\b"#,
    )
    .unwrap()
});

/// Suffixes that make a "domain-looking" token a filename, a version string or
/// an internal name rather than an external domain.
const NOT_A_DOMAIN_SUFFIX: &[&str] = &[
    ".exe", ".dll", ".sys", ".log", ".tmp", ".dat", ".csv", ".json", ".xml", ".txt", ".evtx",
    ".ps1", ".bat", ".cmd", ".msi", ".cab", ".inf", ".ini", ".lnk", ".db", ".etl", ".mui",
    ".zip", ".rar", ".7z", ".png", ".jpg", ".gif", ".pdf", ".docx", ".xlsx",
    ".local", ".localdomain", ".internal", ".corp", ".lan", ".home", ".arpa", ".invalid",
];

/// Does this token read as an external domain name?
fn looks_like_external_domain(token: &str) -> bool {
    let t = token.trim_end_matches('.').to_lowercase();
    if t.parse::<std::net::Ipv4Addr>().is_ok() {
        return false;
    }
    if NOT_A_DOMAIN_SUFFIX.iter().any(|s| t.ends_with(s)) {
        return false;
    }
    if t.matches('.').count() < 1 {
        return false;
    }
    // A numeric last label is a version string (`4.18.2311.4`), not a TLD.
    let tld = t.rsplit('.').next().unwrap_or("");
    tld.len() >= 2 && tld.len() <= 24 && tld.chars().all(|c| c.is_ascii_alphabetic())
}

/// External domains an event actually names, as opposed to strings that happen
/// to contain a dot.
///
/// **Deliberately conservative.** A free-text scan for "something.something"
/// pulls in usernames (`user.name`), download filenames (`audit.zip` — `.zip`
/// is a real TLD), .NET assembly names
/// (`microsoft.azure.activedirectory.synchronization.upgrader`) and shimcache
/// entries, and presents every one of them as a domain this host touched. A
/// section whose purpose is to stop a security product's blocklist being read as
/// 23 compromises must not manufacture its own false signal on the way.
///
/// So a domain is taken only from a URL, or from a field that says it is a host
/// (`QueryName`, `DestinationHostname`, `Url`, …), or from an operator-supplied
/// IOC. Bare domain-shaped strings in free text remain in the supertimeline,
/// where an analyst can search for them, and are not asserted here.
fn extract_domains(e: &UnifiedEvent) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let mut take = |d: &str| {
        let d = d.trim().trim_end_matches('.').to_lowercase();
        if looks_like_external_domain(&d) {
            out.insert(d);
        }
    };
    for c in URL_HOST_RE.captures_iter(&e.description) {
        take(&c[1]);
    }
    for c in LABELLED_HOST_RE.captures_iter(&e.description) {
        take(&c[1]);
    }
    for ind in &e.indicators {
        for tag in ["IOC:", "IOC_DOMAIN:", "DOMAIN:"] {
            if let Some(v) = ind.strip_prefix(tag) {
                take(v);
            }
        }
    }
    out
}

/// Where a string was seen: something the host *did*, or something its software
/// is *configured* with.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum Provenance {
    /// A network connection, DNS resolution, browser visit or process execution.
    Activity,
    /// A registry value, policy or product settings tree.
    Configuration,
}

impl Provenance {
    fn of(e: &UnifiedEvent) -> Provenance {
        if e.classification.starts_with("config:")
            || matches!(e.source.as_str(), "registry" | "regripper")
            || crate::timeline_parser::detectors::classify::is_configuration_key(&e.description)
        {
            Provenance::Configuration
        } else {
            Provenance::Activity
        }
    }
}

#[derive(Default)]
struct Touchpoint {
    hits: usize,
    max_sev: u8,
    first: String,
    last: String,
    sources: std::collections::BTreeSet<String>,
    example: String,
}

impl Touchpoint {
    fn observe(&mut self, e: &UnifiedEvent) {
        self.hits += 1;
        let so = severity_order(&e.severity);
        if so > self.max_sev {
            self.max_sev = so;
        }
        if crate::timeline_parser::detectors::restoration::timestamp_is_usable(&e.timestamp) {
            if self.first.is_empty() || e.timestamp < self.first {
                self.first = e.timestamp.clone();
            }
            if e.timestamp > self.last {
                self.last = e.timestamp.clone();
            }
        }
        self.sources.insert(e.source.clone());
        if self.example.is_empty() {
            self.example = trunc_desc(&e.description, &e.indicators);
        }
    }
}

/// External IP addresses and domains this host's evidence touched.
///
/// Split by provenance, and that split is the whole point. An F-Secure
/// Ultralight registry value (`...\Settings\nif.untrusted_urls`) enumerates
/// dozens of domains in a `REG_MULTI_SZ` — the product's own sinkhole list,
/// carrying `anydesk.com` and `teamviewer.com` beside genuinely malicious-looking
/// names. It appeared on 23 hosts in one pilot and was first read as 23 separate
/// compromises. A section that lists everything matching a string pattern
/// manufactures exactly that, at scale.
fn write_external_touchpoints<W: Write>(
    w: &mut W,
    events: &[UnifiedEvent],
    geo: &GeoReaders,
) -> Result<()> {
    let mut ips: HashMap<(String, Provenance), Touchpoint> = HashMap::new();
    let mut domains: HashMap<(String, Provenance), Touchpoint> = HashMap::new();

    for e in events {
        let prov = Provenance::of(e);
        let mut seen_ip: std::collections::HashSet<String> = std::collections::HashSet::new();
        for c in IP_RE.captures_iter(&e.description) {
            seen_ip.insert(c[1].to_string());
        }
        for ind in &e.indicators {
            for tag in ["LOGON_FROM:", "COMPROMISED_IP:", "IOC:", "IP:"] {
                if let Some(v) = ind.strip_prefix(tag) {
                    if let Some(c) = IP_RE.captures(v) {
                        seen_ip.insert(c[1].to_string());
                    }
                }
            }
        }
        for ip in seen_ip {
            if is_public_ip(&ip) {
                ips.entry((ip, prov)).or_default().observe(e);
            }
        }

        for d in extract_domains(e) {
            domains.entry((d, prov)).or_default().observe(e);
        }
    }

    writeln!(w, "## External Touchpoints (public IPs and domains)")?;
    writeln!(w)?;
    if ips.is_empty() && domains.is_empty() {
        writeln!(w, "No public IP address or external domain was observed in this host's parsed \
            evidence. Note that this is a statement about the artefacts collected, not about the \
            host's network activity as a whole — no firewall, proxy or DNS log is in scope here.")?;
        writeln!(w)?;
        return Ok(());
    }

    let mut activity_ips: Vec<_> = ips.iter().filter(|((_, p), _)| *p == Provenance::Activity).collect();
    let mut config_ips: Vec<_> = ips.iter().filter(|((_, p), _)| *p == Provenance::Configuration).collect();
    let mut activity_dom: Vec<_> = domains.iter().filter(|((_, p), _)| *p == Provenance::Activity).collect();
    let mut config_dom: Vec<_> = domains.iter().filter(|((_, p), _)| *p == Provenance::Configuration).collect();
    for v in [&mut activity_ips, &mut config_ips, &mut activity_dom, &mut config_dom] {
        v.sort_by(|a, b| b.1.max_sev.cmp(&a.1.max_sev)
            .then(b.1.hits.cmp(&a.1.hits))
            .then(a.0 .0.cmp(&b.0 .0)));
    }

    writeln!(w, "### Observed in activity")?;
    writeln!(w)?;
    writeln!(w, "Seen in network, browser, execution or event-log evidence — that is, in a record \
        of something this host did. Domains are taken only from URLs, from fields that say they \
        are hosts (`QueryName`, `DestinationHostname`, …), or from supplied IOCs; a bare \
        domain-shaped string in free text is not asserted here as a domain this host contacted.")?;
    writeln!(w)?;
    if activity_ips.is_empty() && activity_dom.is_empty() {
        writeln!(w, "None.")?;
        writeln!(w)?;
    } else {
        writeln!(w, "| Indicator | Kind | Hits | Max Sev | First Seen | Last Seen | Sources | Geo / ASN |")?;
        writeln!(w, "|-----------|------|------|---------|-----------|-----------|---------|-----------|")?;
        for ((ip, _), t) in &activity_ips {
            let g = geo.lookup(ip);
            let geo_cell = if g.is_empty() { "—".to_string() }
                else if g.is_anonymizing() { format!("⚠ {}", g.summary()) }
                else { g.summary() };
            writeln!(w, "| {} | public IP | {} | {} | {} | {} | {} | {} |",
                ip, t.hits, sev_label(t.max_sev), t.first, t.last,
                cell(&t.sources.iter().cloned().collect::<Vec<_>>().join(", ")), cell(&geo_cell))?;
        }
        for ((d, _), t) in &activity_dom {
            writeln!(w, "| {} | domain | {} | {} | {} | {} | {} | — |",
                cell(d), t.hits, sev_label(t.max_sev), t.first, t.last,
                cell(&t.sources.iter().cloned().collect::<Vec<_>>().join(", ")))?;
        }
        writeln!(w)?;
    }

    if !config_ips.is_empty() || !config_dom.is_empty() {
        writeln!(w, "### Present in configuration only — NOT evidence of contact")?;
        writeln!(w)?;
        writeln!(w, "These strings were read out of registry values, policy or security-product \
            settings. A blocklist naming a domain is the software saying it would block it, not \
            the host saying it went there. Do not read a row below as a connection.")?;
        writeln!(w)?;
        writeln!(w, "| Indicator | Kind | Hits | Sources | Where |")?;
        writeln!(w, "|-----------|------|------|---------|-------|")?;
        for ((ip, _), t) in config_ips.iter().take(50) {
            writeln!(w, "| {} | public IP | {} | {} | {} |", ip, t.hits,
                cell(&t.sources.iter().cloned().collect::<Vec<_>>().join(", ")), cell(&t.example))?;
        }
        for ((d, _), t) in config_dom.iter().take(50) {
            writeln!(w, "| {} | domain | {} | {} | {} |", cell(d), t.hits,
                cell(&t.sources.iter().cloned().collect::<Vec<_>>().join(", ")), cell(&t.example))?;
        }
        let extra = (config_ips.len() + config_dom.len()).saturating_sub(100);
        if extra > 0 {
            writeln!(w, "\n_… {extra} more configuration-sourced strings; the complete set is in the supertimeline._")?;
        }
        writeln!(w)?;
    }
    Ok(())
}

/// What each artefact family could see, and where its record starts.
///
/// "Treating a start-of-available-log as a start-of-activity is the flaw running
/// through the whole timing table." A 239-day "gap" that is really the edge of
/// log retention is an evidence-availability boundary, not attacker cadence, and
/// a finding sitting at that boundary means *we cannot see earlier* — which is
/// categorically different from *nothing happened earlier*.
fn write_evidence_coverage<W: Write>(
    w: &mut W,
    events: &[UnifiedEvent],
    c: &Continuity,
) -> Result<()> {
    #[derive(Default)]
    struct Span {
        count: usize,
        first: String,
        last: String,
        first_hit: String,
    }
    let mut by_source: HashMap<&str, Span> = HashMap::new();
    for e in events {
        if !crate::timeline_parser::detectors::restoration::timestamp_is_usable(&e.timestamp) {
            continue;
        }
        let s = by_source.entry(e.source.as_str()).or_default();
        s.count += 1;
        if s.first.is_empty() || e.timestamp < s.first {
            s.first = e.timestamp.clone();
        }
        if e.timestamp > s.last {
            s.last = e.timestamp.clone();
        }
        if severity_order(&e.severity) >= severity_order("high")
            && (s.first_hit.is_empty() || e.timestamp < s.first_hit)
        {
            s.first_hit = e.timestamp.clone();
        }
    }
    if by_source.is_empty() {
        return Ok(());
    }

    writeln!(w, "## Evidence Coverage (what could be seen, and from when)")?;
    writeln!(w)?;
    if let Some(k) = &c.collection_at {
        writeln!(w, "- **Collected at**: {} (from the host's own Security log retention range)", k)?;
    }
    if let Some(r) = &c.security_log_retention {
        writeln!(w, "- **Security log retention**: {}", r)?;
    }
    if let (Some(f), Some(l)) = (&c.series_first, &c.series_last) {
        writeln!(w, "- **Event-log record actually spans**: {f} to {l} — this is the \
            retention boundary, and it is the only artefact family here whose true \
            earliest is known")?;
    }
    writeln!(w)?;
    writeln!(w, "| Artefact family | Events kept | Earliest in output | Latest in output | Earliest high+ finding | At the retention edge? |")?;
    writeln!(w, "|-----------------|-------------|--------------------|------------------|------------------------|------------------------|")?;
    let mut rows: Vec<_> = by_source.into_iter().collect();
    rows.sort_by_key(|(k, _)| *k);
    // The true earliest is only known where nothing filtered it: the continuity
    // scan reads every row of event-logs.csv, including the ones the parser
    // discards. Every other family's minimum is the earliest row that *survived
    // filtering*, which is a fact about the filter, not about the evidence — so
    // no boundary claim is made from it.
    let record_start = c.series_first.as_deref().and_then(restoration::parse_ts);
    for (source, s) in rows {
        let edge = if source == "event-logs" {
            match (record_start, restoration::parse_ts(&s.first_hit)) {
                (Some(a), Some(b)) if (b - a).num_hours().abs() <= 24 => {
                    "**yes — cannot see earlier**"
                }
                (Some(_), Some(_)) => "no",
                _ => "—",
            }
        } else {
            "not determinable"
        };
        writeln!(w, "| {} | {} | {} | {} | {} | {} |",
            source, s.count, s.first, s.last,
            if s.first_hit.is_empty() { "—" } else { &s.first_hit },
            edge)?;
    }
    writeln!(w)?;
    writeln!(w, "**\"Earliest in output\" is not \"earliest available\".** Every family except \
        `event-logs` is filtered before it reaches this table, so its minimum is the earliest row \
        that survived filtering — a fact about the filter, not about what the artefact holds. \
        No retention claim is drawn from those rows.")?;
    writeln!(w)?;
    writeln!(w, "Where the boundary *is* known, it bounds the conclusion: a finding at the edge \
        of the retained record means **we cannot see earlier**, which is categorically different \
        from **nothing happened earlier**. A long \"gap\" measured back to that edge is an \
        evidence-availability boundary, not attacker cadence.")?;
    writeln!(w)?;
    Ok(())
}

/// Findings after the restoration date, partitioned so the interesting category
/// is small and loud.
fn write_phases<W: Write>(
    w: &mut W,
    events: &[UnifiedEvent],
    c: &Continuity,
    supplied: Option<&str>,
) -> Result<()> {
    let date = supplied
        .map(str::to_string)
        .or_else(|| c.best_candidate().map(|k| k.resumes.clone()));
    let Some(date) = date else { return Ok(()) };

    writeln!(w, "## Restoration Phases")?;
    writeln!(w)?;
    writeln!(w, "- **Restoration date used**: {} ({})", date,
        if supplied.is_some() { "supplied by the operator" } else { "inferred from log continuity" })?;
    writeln!(w)?;

    if !c.candidates.is_empty() {
        writeln!(w, "All candidate dates, ranked — a host restored twice, or with a long outage \
            before the restore, has more than one:")?;
        writeln!(w)?;
        writeln!(w, "| Rank | Resumes | Record stops | Gap | Assessment | Corroboration |")?;
        writeln!(w, "|------|---------|--------------|-----|------------|---------------|")?;
        for (i, k) in c.candidates.iter().enumerate().take(6) {
            writeln!(w, "| {} | {} | {} | {}h | {} | {} |",
                i + 1, k.resumes, k.stops, k.gap_hours, k.kind.label(),
                if k.corroboration.is_empty() { "—".to_string() } else { cell(&k.corroboration.join("; ")) })?;
        }
        writeln!(w)?;
    }

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for e in events {
        if !e.phase.is_empty() {
            *counts.entry(e.phase.as_str()).or_default() += 1;
        }
    }
    writeln!(w, "| Phase | Events | Reading |")?;
    writeln!(w, "|-------|--------|---------|")?;
    writeln!(w, "| {} | {} | Before the restore. Belongs to the machine that was replaced. |",
        PHASE_PRE, counts.get(PHASE_PRE).unwrap_or(&0))?;
    writeln!(w, "| {} | {} | EDR deployment, domain rejoin, patching, OS servicing. Expected. |",
        PHASE_PROCESS, counts.get(PHASE_PROCESS).unwrap_or(&0))?;
    writeln!(w, "| {} | {} | The forensic collection itself. Not attacker activity. |",
        PHASE_RESPONDER, counts.get(PHASE_RESPONDER).unwrap_or(&0))?;
    writeln!(w, "| {} | {} | **Unexplained after the rebuild — the serious category.** |",
        PHASE_POST, counts.get(PHASE_POST).unwrap_or(&0))?;
    writeln!(w)?;

    // "Definitionally true and evidentially empty" — the reviewer's phrase for a
    // host whose entire 7.7-hour record postdated its restoration, and which was
    // therefore reported as carrying post-restoration activity. If most of the
    // record sits after the date, the partition is describing the record's shape
    // rather than anything about the rebuild, and saying so is the finding.
    let pre = *counts.get(PHASE_PRE).unwrap_or(&0);
    let post = *counts.get(PHASE_POST).unwrap_or(&0);
    if post > 0 && post >= pre {
        writeln!(w, "> **Most of this host's record postdates the restoration date, so \
            \"post-restoration activity\" here is close to definitionally true.** {post} of \
            {} phased events fall after {date}, against {pre} before it. Either the date is \
            early for this record — check it against the ranked candidates above — or the \
            collection simply does not reach far enough back to say what preceded the rebuild. \
            Read the list below as ordinary triage, not as evidence of a post-rebuild intrusion.",
            pre + post)?;
        writeln!(w)?;
    }

    let in_window: Vec<&UnifiedEvent> = events
        .iter()
        .filter(|e| {
            e.indicators.iter().any(|i| i.starts_with("RESTORE_WINDOW:"))
                && crate::timeline_parser::output::supertimeline::is_triage_hit(e)
        })
        .collect();
    if !in_window.is_empty() {
        let days = in_window[0]
            .indicators
            .iter()
            .find_map(|i| i.strip_prefix("RESTORE_WINDOW:"))
            .unwrap_or("");
        writeln!(w, "### Highest-relevance window (the {} before the restore)", days)?;
        writeln!(w)?;
        writeln!(w, "A compromise that led to this restore happened in the window that ends at \
            it. {} triage hit(s) fall inside that window; findings predating it by a wide margin \
            describe a machine that was subsequently replaced.", in_window.len())?;
        writeln!(w)?;
        let mut rows = in_window.clone();
        rows.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        for e in rows.iter().take(25) {
            writeln!(w, "- **[{}]** `{}` — {}", e.severity.to_uppercase(), e.timestamp,
                trunc_desc(&e.description, &e.indicators))?;
        }
        if rows.len() > 25 {
            writeln!(w, "- _… {} more; filter the triage timeline on `RESTORE_WINDOW`._", rows.len() - 25)?;
        }
        writeln!(w)?;
    }

    let mut post: Vec<&UnifiedEvent> = events
        .iter()
        .filter(|e| e.phase == PHASE_POST && crate::timeline_parser::output::supertimeline::is_triage_hit(e))
        .collect();
    post.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    writeln!(w, "### Post-restoration, unexplained")?;
    writeln!(w)?;
    if post.is_empty() {
        writeln!(w, "Nothing after the restoration date is both a triage hit and unaccounted for \
            by the restoration process or the responder's own collection.")?;
        writeln!(w)?;
        return Ok(());
    }
    writeln!(w, "{} finding(s) postdate the restore and are not explained by rebuild activity or \
        by the collection. This is either the most serious result a sheep-dip can produce or a \
        mis-tagged job; nothing else in this report distinguishes them, so read every row.",
        post.len())?;
    writeln!(w)?;
    for e in post.iter().take(40) {
        writeln!(w, "- **[{}]** `{}` — {}", e.severity.to_uppercase(), e.timestamp,
            trunc_desc(&e.description, &e.indicators))?;
        if !e.indicators.is_empty() {
            writeln!(w, "  - Indicators: {}", cell(&e.indicators.iter().take(4).cloned().collect::<Vec<_>>().join(", ")))?;
        }
    }
    if post.len() > 40 {
        writeln!(w, "- _… {} more; filter the triage timeline on `Phase == {}`._",
            post.len() - 40, PHASE_POST)?;
    }
    writeln!(w)?;
    Ok(())
}

/// What the parser decided, so nothing downstream has to decide it again.
fn write_classifications<W: Write>(
    w: &mut W,
    events: &[UnifiedEvent],
    automations: &[Automation],
) -> Result<()> {
    let mut by_class: HashMap<&str, usize> = HashMap::new();
    for e in events {
        if !e.classification.is_empty() {
            *by_class.entry(e.classification.as_str()).or_default() += 1;
        }
    }
    if by_class.is_empty() && automations.is_empty() {
        return Ok(());
    }

    writeln!(w, "## Deterministic Classifications")?;
    writeln!(w)?;
    writeln!(w, "Events the parser could account for from their own fields. They remain in the \
        supertimeline — the evidence is not suppressed — but they are **not findings** and are \
        excluded from the triage timeline unless a direct IOC or malicious-hash verdict overrides \
        the classification.")?;
    writeln!(w)?;
    writeln!(w, "Classification is drawn from the **path**, not the filename — `fls.exe` is Sleuth \
        Kit and also ships inside F-Secure's response package, and `7za.exe` ships with VMware \
        Tools. An Authenticode signer would be the better key, because a path allowlist is \
        spoofable; the wiskess Timeline export carries no signature field, so none was available. \
        A supplied-IOC match or a malicious hash verdict overrides any classification below.")?;
    writeln!(w)?;
    writeln!(w, "| Classification | Events | Means |")?;
    writeln!(w, "|----------------|--------|-------|")?;
    let mut rows: Vec<_> = by_class.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    for (class, n) in rows {
        let meaning = if class.starts_with("vendor:") {
            "sits inside a security-product or platform install tree; the path decides, not the filename"
        } else if class == "os:component-store" || class == "os:driver-store" || class == "os:gac"
            || class == "os:windows-update" || class == "os:msi-cache" {
            "OS servicing store — presence here is not evidence of execution"
        } else if class == "os:servicing" {
            "an OS-shipped task or service changed by the OS"
        } else if class.starts_with("automation:") {
            "a scheduled/managed process, not a person"
        } else if class.starts_with("responder:") {
            "the forensic collection's own footprint"
        } else if class.starts_with("config:") {
            "a product's settings, including its blocklists — not a record of contact"
        } else if class.starts_with("removal:") {
            "describes a deletion or disable; cannot support a persistence tag"
        } else {
            "—"
        };
        writeln!(w, "| `{}` | {} | {} |", class, n, meaning)?;
    }
    writeln!(w)?;

    if !automations.is_empty() {
        writeln!(w, "### Machine-account automation")?;
        writeln!(w)?;
        writeln!(w, "Group-membership changes performed by a machine account or SYSTEM, on a \
            regular cadence, over a small recurring member set — the signature of Group Policy \
            Restricted Groups or a management agent. Stated as a rate, because \"776 admin group \
            additions\" and \"776 additions of the same 3 SIDs at ~1.5h intervals\" are different \
            statements and only the second is decidable by a reader.")?;
        writeln!(w)?;
        writeln!(w, "| Subject | Group | Rate | Members | First | Last |")?;
        writeln!(w, "|---------|-------|------|---------|-------|------|")?;
        for a in automations {
            writeln!(w, "| {} | {} | {} | {} | {} | {} |",
                cell(&a.subject), cell(&a.group), cell(&a.as_rate()),
                cell(&a.members.join(", ")), a.first, a.last)?;
        }
        writeln!(w)?;
        writeln!(w, "A change that breaks the pattern — a member outside the recurring set — is \
            **not** classified as automation and stays in the triage timeline, tagged \
            `OFF_CADENCE_MEMBER`. That single event is the finding.")?;
        writeln!(w)?;
    }

    // Presence vs execution.
    let mut exec: HashMap<&str, usize> = HashMap::new();
    for e in events {
        if !e.execution_evidence.is_empty() {
            *exec.entry(e.execution_evidence.as_str()).or_default() += 1;
        }
    }
    if !exec.is_empty() {
        writeln!(w, "### Presence vs execution")?;
        writeln!(w)?;
        writeln!(w, "| Execution evidence | Events | Means |")?;
        writeln!(w, "|--------------------|--------|-------|")?;
        for (k, meaning) in [
            ("executed", "prefetch / jump-list / LNK / shimcache 'Executed: Yes' — it ran"),
            ("registered", "an Amcache or shimcache entry — the file was seen by the OS, not necessarily run"),
            ("none", "the file exists on disk and **nothing shows it ran**"),
        ] {
            if let Some(n) = exec.get(k) {
                writeln!(w, "| {} | {} | {} |", k, n, meaning)?;
            }
        }
        writeln!(w)?;
    }
    Ok(())
}

/// The baseline record, carried only when `--verbose-events` is set.
fn write_baseline<W: Write>(w: &mut W, events: &[UnifiedEvent], cfg: &PipelineConfig) -> Result<()> {
    if !cfg.verbosity.baseline() {
        return Ok(());
    }
    let baseline: Vec<&UnifiedEvent> = events
        .iter()
        .filter(|e| e.indicators.iter().any(|i| i == "BASELINE_LOGON"))
        .collect();

    writeln!(w, "## Baseline Logon Activity")?;
    writeln!(w)?;
    writeln!(w, "Every successful logon by a real (non-machine, non-service-principal) account, \
        carried because `--verbose-events` was set. Working hours are {:02}:00–{:02}:00 UTC; \
        weekends count as out of hours. A (user, logon type, source) combination seen fewer than \
        {} times across the record is flagged rare.",
        cfg.business_hours.0, cfg.business_hours.1, cfg.rare_logon_max)?;
    writeln!(w)?;
    if baseline.is_empty() {
        writeln!(w, "No successful logon by a real account was found in the event-log record.")?;
        writeln!(w)?;
        return Ok(());
    }

    // user -> (type, source) -> count, with the flags that matter.
    #[derive(Default)]
    struct Row {
        count: usize,
        off_hours: usize,
        rare: bool,
        first: String,
        last: String,
    }
    let mut rows: std::collections::BTreeMap<(String, String, String), Row> = Default::default();
    for e in &baseline {
        let ltype = e.indicators.iter()
            .find_map(|i| i.strip_prefix("LOGON_TYPE:"))
            .unwrap_or("Other")
            .to_string();
        let from = e.indicators.iter()
            .find_map(|i| i.strip_prefix("LOGON_FROM:"))
            .unwrap_or("—")
            .to_string();
        let r = rows.entry((clean_user(&e.user), ltype, from)).or_default();
        r.count += 1;
        if e.indicators.iter().any(|i| i == "OFF_HOURS_LOGON") {
            r.off_hours += 1;
        }
        r.rare |= e.indicators.iter().any(|i| i.starts_with("RARE_LOGON:"));
        if r.first.is_empty() || e.timestamp < r.first {
            r.first = e.timestamp.clone();
        }
        if e.timestamp > r.last {
            r.last = e.timestamp.clone();
        }
    }

    writeln!(w, "| User | Logon type | From | Logons | Out of hours | Rare | First | Last |")?;
    writeln!(w, "|------|-----------|------|--------|--------------|------|-------|------|")?;
    let mut sorted: Vec<_> = rows.into_iter().collect();
    // Rare first, then out-of-hours, then loudest.
    sorted.sort_by(|a, b| b.1.rare.cmp(&a.1.rare)
        .then(b.1.off_hours.cmp(&a.1.off_hours))
        .then(b.1.count.cmp(&a.1.count)));
    for ((user, ltype, from), r) in sorted.iter().take(200) {
        writeln!(w, "| {} | {} | {} | {} | {} | {} | {} | {} |",
            cell(user), cell(ltype), cell(from), r.count,
            if r.off_hours > 0 { r.off_hours.to_string() } else { "—".to_string() },
            if r.rare { "**yes**" } else { "—" }, r.first, r.last)?;
    }
    if sorted.len() > 200 {
        writeln!(w, "\n_… {} more combinations; the full set is in the supertimeline._", sorted.len() - 200)?;
    }
    writeln!(w)?;
    Ok(())
}

/// Per-user activity — who touched the box, how loudly, and across which tactics.
fn write_user_table<W: Write>(w: &mut W, events: &[UnifiedEvent]) -> Result<()> {
    let mut by_user: HashMap<String, Agg> = HashMap::new();
    for e in events {
        let u = clean_user(&e.user);
        if !is_real_user(&u) {
            continue;
        }
        by_user.entry(u).or_default().observe(e);
    }
    if by_user.is_empty() {
        return Ok(());
    }

    writeln!(w, "## Account Activity")?;
    writeln!(w)?;
    writeln!(w, "| User | Events | Max Severity | First Seen | Last Seen | Tactics |")?;
    writeln!(w, "|------|--------|--------------|-----------|-----------|---------|")?;
    let mut rows: Vec<_> = by_user.into_iter().collect();
    rows.sort_by(|a, b| b.1.max_sev.cmp(&a.1.max_sev).then(b.1.count.cmp(&a.1.count)));
    for (user, a) in rows {
        let tactics = a.tactics.iter().cloned().collect::<Vec<_>>().join(", ");
        writeln!(w, "| {} | {} | {} | {} | {} | {} |",
            cell(&user), a.count, sev_label(a.max_sev), a.first, a.last, cell(&tactics))?;
    }
    writeln!(w)?;
    Ok(())
}

/// Per-IP analysis — direction (inbound logon vs outbound lateral), volume, and
/// geo/ASN/anonymizing enrichment when MaxMind DBs are present.
fn write_ip_table<W: Write>(w: &mut W, events: &[UnifiedEvent], geo: &GeoReaders) -> Result<()> {
    let mut by_ip: HashMap<String, Agg> = HashMap::new();
    for e in events {
        // Direction hints from the event.
        let inbound = e.indicators.iter().any(|i| i.starts_with("LOGON_FROM:"))
            || e.event_type == "rdp_logon"
            || e.event_type == "precursor_logon";
        let outbound = e.event_type == "lateral_movement_outbound"
            || e.event_type == "network_connection";

        // Collect IPs from indicators and the description.
        let mut ips: std::collections::HashSet<String> = std::collections::HashSet::new();
        for ind in &e.indicators {
            for tag in ["LOGON_FROM:", "COMPROMISED_IP:", "IOC:", "IP:"] {
                if let Some(v) = ind.strip_prefix(tag) {
                    if let Some(c) = IP_RE.captures(v) {
                        ips.insert(c[1].to_string());
                    }
                }
            }
        }
        for c in IP_RE.captures_iter(&e.description) {
            ips.insert(c[1].to_string());
        }

        for ip in ips {
            if !tabulatable_ip(&ip) {
                continue;
            }
            let a = by_ip.entry(ip).or_default();
            a.observe(e);
            a.inbound |= inbound;
            a.outbound |= outbound;
        }
    }
    if by_ip.is_empty() {
        return Ok(());
    }

    writeln!(w, "## IP Address Analysis")?;
    writeln!(w)?;
    if !geo.available() {
        writeln!(w, "_GeoIP enrichment disabled (no MaxMind `.mmdb` on search path). \
            Most addresses below are RFC1918 internal hosts._")?;
        writeln!(w)?;
    }
    writeln!(w, "| IP | Hits | Direction | Max Sev | First Seen | Last Seen | Geo / ASN |")?;
    writeln!(w, "|----|------|-----------|---------|-----------|-----------|-----------|")?;
    let mut rows: Vec<_> = by_ip.into_iter().collect();
    rows.sort_by(|a, b| b.1.max_sev.cmp(&a.1.max_sev).then(b.1.count.cmp(&a.1.count)));
    for (ip, a) in rows {
        let dir = match (a.inbound, a.outbound) {
            (true, true) => "in+out",
            (true, false) => "inbound",
            (false, true) => "outbound",
            (false, false) => "—",
        };
        let geo_info = geo.lookup(&ip);
        let geo_cell = if geo_info.is_empty() {
            if ip.parse::<std::net::Ipv4Addr>().map(|a| a.is_private()).unwrap_or(false) {
                "internal".to_string()
            } else {
                "—".to_string()
            }
        } else {
            let mut s = geo_info.summary();
            if geo_info.is_anonymizing() {
                s = format!("⚠ {}", s);
            }
            s
        };
        writeln!(w, "| {} | {} | {} | {} | {} | {} | {} |",
            ip, a.count, dir, sev_label(a.max_sev), a.first, a.last, cell(&geo_cell))?;
    }
    writeln!(w)?;
    Ok(())
}

/// Hostnames observed in the data, flagging any that break naming convention
/// (`WIN-*`, `DESKTOP-*`, `kali`, …) or were outbound lateral-movement targets.
fn write_hostname_table<W: Write>(w: &mut W, events: &[UnifiedEvent]) -> Result<()> {
    // host -> (count, is_lateral_target, max_sev)
    let mut hosts: HashMap<String, (usize, bool, u8)> = HashMap::new();
    let note = |hosts: &mut HashMap<String, (usize, bool, u8)>, h: &str, lateral: bool, sev: u8| {
        let h = h.trim().trim_end_matches('$');
        if h.len() < 3 || h == "-" {
            return;
        }
        let entry = hosts.entry(h.to_uppercase()).or_insert((0, false, 0));
        entry.0 += 1;
        entry.1 |= lateral;
        if sev > entry.2 {
            entry.2 = sev;
        }
    };

    for e in events {
        let sev = severity_order(&e.severity);
        for ind in &e.indicators {
            if let Some(server) = ind.strip_prefix("LATERAL_OUTBOUND:") {
                let short = server.split('.').next().unwrap_or(server);
                note(&mut hosts, short, true, sev);
            }
        }
        // Surface only standout hostnames from free-text descriptions to avoid noise.
        for tok in e.description.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_')) {
            if suspicious_hostname(tok).is_some() {
                note(&mut hosts, tok, false, sev);
            }
        }
    }
    if hosts.is_empty() {
        return Ok(());
    }

    writeln!(w, "## Hostname Analysis")?;
    writeln!(w)?;
    writeln!(w, "Hostnames that break naming convention or were lateral-movement targets. \
        ⚠ = standout name (default Windows / offensive distro / personal device).")?;
    writeln!(w)?;
    writeln!(w, "| Hostname | Hits | Lateral Target | Max Sev | Standout? |")?;
    writeln!(w, "|----------|------|----------------|---------|-----------|")?;
    let mut rows: Vec<_> = hosts.into_iter().collect();
    rows.sort_by(|a, b| b.1 .2.cmp(&a.1 .2).then(b.1 .0.cmp(&a.1 .0)));
    for (host, (count, lateral, sev)) in rows {
        let standout = match suspicious_hostname(&host) {
            Some(why) => format!("⚠ {}", why),
            None => "—".to_string(),
        };
        writeln!(w, "| {} | {} | {} | {} | {} |",
            cell(&host), count, if lateral { "yes" } else { "—" }, sev_label(sev), standout)?;
    }
    writeln!(w)?;
    Ok(())
}

/// Chronological access timeline: inbound RDP logon/logoff and correlated
/// precursor sessions — the actor's interactive presence on the host.
fn write_access_timeline<W: Write>(w: &mut W, events: &[UnifiedEvent]) -> Result<()> {
    let mut sessions: Vec<&UnifiedEvent> = events.iter()
        .filter(|e| matches!(e.event_type.as_str(), "rdp_logon" | "rdp_logoff" | "precursor_logon"))
        .collect();
    if sessions.is_empty() {
        return Ok(());
    }
    sessions.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    writeln!(w, "## Access & Session Timeline")?;
    writeln!(w)?;
    writeln!(w, "Inbound RDP/SMB logons that established the actor's sessions, plus the \
        precursor logon correlated to each downstream finding.")?;
    writeln!(w)?;
    for e in sessions {
        let kind = match e.event_type.as_str() {
            "rdp_logon" => "RDP LOGON",
            "rdp_logoff" => "RDP LOGOFF",
            _ => "PRECURSOR",
        };
        let from = e.indicators.iter()
            .find_map(|i| i.strip_prefix("LOGON_FROM:"))
            .map(|ip| format!(" from {}", ip))
            .unwrap_or_default();
        let user = clean_user(&e.user);
        let user = if user.is_empty() { String::new() } else { format!(" — {}", user) };
        writeln!(w, "- **[{}]** `{}`{}{} — {}", kind, e.timestamp, user, from, trunc_desc(&e.description, &e.indicators))?;
    }
    writeln!(w)?;
    Ok(())
}

/// Outbound lateral movement from this host during the actor window.
fn write_lateral_section<W: Write>(w: &mut W, events: &[UnifiedEvent]) -> Result<()> {
    let mut lateral: Vec<&UnifiedEvent> = events.iter()
        .filter(|e| e.event_type == "lateral_movement_outbound")
        .collect();
    if lateral.is_empty() {
        return Ok(());
    }
    lateral.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    writeln!(w, "## Lateral Movement (Outbound)")?;
    writeln!(w)?;
    writeln!(w, "Connections initiated **from** this host to other systems while the actor \
        was logged on (explicit-credential / outbound RDP/SMB).")?;
    writeln!(w)?;
    writeln!(w, "| Time | Source User | Target Host | Run-As User |")?;
    writeln!(w, "|------|-------------|-------------|-------------|")?;
    for e in lateral {
        let target = e.indicators.iter().find_map(|i| i.strip_prefix("LATERAL_OUTBOUND:")).unwrap_or("");
        let runas = e.indicators.iter().find_map(|i| i.strip_prefix("RUNAS_USER:")).unwrap_or("");
        writeln!(w, "| {} | {} | {} | {} |",
            e.timestamp, cell(&clean_user(&e.user)), cell(target), cell(runas))?;
    }
    writeln!(w)?;
    Ok(())
}

fn write_ta_tools<W: Write>(w: &mut W, events: &[UnifiedEvent]) -> Result<()> {
    let mut tools_found: HashMap<&str, Vec<&UnifiedEvent>> = HashMap::new();
    for e in events {
        for ind in &e.indicators {
            if let Some(tool_name) = ind.strip_prefix("TA_TOOL:") {
                tools_found.entry(tool_name).or_default().push(e);
            }
        }
    }
    if tools_found.is_empty() {
        return Ok(());
    }

    writeln!(w, "## Threat Actor Tools Detected")?;
    writeln!(w)?;
    writeln!(w, "| Tool | Count | First Seen | Last Seen | Source |")?;
    writeln!(w, "|------|-------|-----------|----------|--------|")?;
    let mut tools: Vec<_> = tools_found.iter().collect();
    tools.sort_by_key(|(name, _)| *name);
    for (tool, tool_events) in tools {
        let mut sorted = tool_events.clone();
        sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        let sources: Vec<_> = sorted.iter().map(|e| e.source.as_str()).collect::<std::collections::HashSet<_>>()
            .into_iter().collect();
        writeln!(w, "| {} | {} | {} | {} | {} |",
            tool, tool_events.len(),
            sorted.first().map(|e| e.timestamp.as_str()).unwrap_or(""),
            sorted.last().map(|e| e.timestamp.as_str()).unwrap_or(""),
            sources.join(", "))?;
    }
    writeln!(w)?;
    Ok(())
}

/// IOC matching, stated whether or not anything matched.
///
/// This section used to return early when nothing matched, so a host checked
/// against 200 indicators with no hits and a host where no IOC file was ever
/// supplied produced byte-identical reports. Those are opposite findings: one
/// is evidence, the other is an untested host. The section is now always
/// written, and says which of the two it is.
fn write_iocs<W: Write>(
    w: &mut W,
    events: &[UnifiedEvent],
    coverage: &IocCoverage,
) -> Result<()> {
    let mut iocs_found: HashMap<&str, Vec<&UnifiedEvent>> = HashMap::new();
    for e in events {
        for ind in &e.indicators {
            if ind.starts_with("IOC:") || ind.starts_with("IOC_HASH:") {
                iocs_found.entry(ind.as_str()).or_default().push(e);
            }
        }
    }

    writeln!(w, "## IOC Matches")?;
    writeln!(w)?;

    match &coverage.source {
        None => {
            writeln!(w, "**No IOC file was supplied — no IOC matching was performed.**")?;
            writeln!(w)?;
            writeln!(w, "This host has not been checked against any case indicators. The absence \
                of IOC hits below is not a result; it means the check did not run. Supply a list \
                with `--iocs <file>` to perform it.")?;
            writeln!(w)?;
            return Ok(());
        }
        Some(src) => {
            writeln!(w, "**Indicators supplied**: {} from `{}` ({})",
                coverage.total(), src.path, src.format)?;
            writeln!(w)?;
            writeln!(w, "| Source accounting | Count |")?;
            writeln!(w, "|-------------------|-------|")?;
            writeln!(w, "| Lines in file | {} |", src.lines_total)?;
            if src.format == "text" {
                writeln!(w, "| Lines yielding an indicator | {} |", src.lines_indicator)?;
                writeln!(w, "| Comment lines skipped | {} |", src.lines_comment)?;
                writeln!(w, "| Blank lines skipped | {} |", src.lines_blank)?;
            }
            writeln!(w, "| IP addresses | {} |", coverage.ips)?;
            writeln!(w, "| Domains | {} |", coverage.domains)?;
            writeln!(w, "| File hashes | {} |", coverage.hashes)?;
            writeln!(w, "| Filenames / strings | {} |", coverage.filenames)?;
            writeln!(w, "| Usernames | {} |", coverage.usernames)?;
            writeln!(w)?;

            if coverage.total() == 0 {
                writeln!(w, "**The supplied IOC file yielded no indicators.** Every line was \
                    blank or a comment, so no matching was performed — treat this host as \
                    unchecked rather than clear.")?;
                writeln!(w)?;
                return Ok(());
            }
        }
    }

    if iocs_found.is_empty() {
        writeln!(w, "**{} indicators were searched across every parsed artefact. None matched.**",
            coverage.total())?;
        writeln!(w)?;
        writeln!(w, "This is a result: the indicators supplied were not observed in the evidence \
            that was parsed. It is bounded by the Collection Gaps section below — an indicator \
            can only be absent from an artefact that was collected.")?;
        writeln!(w)?;
        return Ok(());
    }

    writeln!(w, "{} of {} supplied indicators matched.",
        iocs_found.len(), coverage.total())?;
    writeln!(w)?;
    writeln!(w, "| IOC | Hits | First Seen | Last Seen | Sources |")?;
    writeln!(w, "|-----|------|-----------|----------|---------|")?;
    let mut iocs: Vec<_> = iocs_found.iter().collect();
    iocs.sort_by_key(|(name, _)| *name);
    for (ioc, ioc_events) in iocs {
        let mut sorted = ioc_events.clone();
        sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        let sources: Vec<_> = sorted.iter().map(|e| e.source.as_str()).collect::<std::collections::HashSet<_>>()
            .into_iter().collect();
        writeln!(w, "| {} | {} | {} | {} | {} |",
            ioc, ioc_events.len(),
            sorted.first().map(|e| e.timestamp.as_str()).unwrap_or(""),
            sorted.last().map(|e| e.timestamp.as_str()).unwrap_or(""),
            sources.join(", "))?;
    }
    writeln!(w)?;
    Ok(())
}

/// Condensed per-tactic findings (top 10 each) — the detail behind the summary
/// tables above. Full event text lives in the supertimeline CSV/JSONL.
fn write_tactic_findings<W: Write>(w: &mut W, events: &[UnifiedEvent]) -> Result<()> {
    let tactic_order = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact",
    ];

    let mut tactics: HashMap<&str, Vec<&UnifiedEvent>> = HashMap::new();
    let mut explained_skipped = 0usize;
    for e in events {
        if severity_order(&e.severity) >= severity_order("med") {
            // An event the parser could account for is not a finding, and must
            // not swell a tactic count. Impact appearing on 18 of 28 hosts —
            // including all three the reviewer called clean — carries no
            // information, and presenting it as "ransomware-deployment
            // candidates" would be a material overstatement.
            if e.is_explained() {
                explained_skipped += 1;
                continue;
            }
            let tactic = if e.mitre_tactic.is_empty() { "Unknown/Uncategorized" } else { &e.mitre_tactic };
            tactics.entry(tactic).or_default().push(e);
        }
    }

    writeln!(w, "## Findings by ATT&CK Tactic (condensed)")?;
    writeln!(w)?;
    writeln!(w, "_Top events per tactic; the complete, untruncated set is in the supertimeline CSV/JSONL._")?;
    writeln!(w)?;

    let total: usize = tactics.values().map(|v| v.len()).sum();
    if total > 0 {
        writeln!(w, "| Tactic | Events | Share of tagged findings |")?;
        writeln!(w, "|--------|--------|--------------------------|")?;
        let mut counts: Vec<(&str, usize)> = tactics.iter().map(|(k, v)| (*k, v.len())).collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        for (tactic, n) in &counts {
            let share = (*n as f64) * 100.0 / (total as f64);
            writeln!(w, "| {} | {} | {:.1}% {} |", tactic, n, share,
                if share >= 60.0 { "← dominates this host; discount accordingly" } else { "" })?;
        }
        writeln!(w)?;
        writeln!(w, "A tactic carrying most of a host's findings is describing the host's ordinary \
            furniture, not an intrusion — a Persistence count that is really an inventory of every \
            scheduled task, service and autorun the machine ships with. Compare these shares across \
            the estate before reading any one of them as a result: a tag present on most hosts in a \
            collection carries no information about any of them.")?;
        writeln!(w)?;
    }
    if explained_skipped > 0 {
        writeln!(w, "_{explained_skipped} medium-or-higher event(s) are excluded from the counts \
            above because the parser could account for them (vendor tree, OS servicing, scheduled \
            automation, or the responder's own collection). They remain in the supertimeline; see \
            **Deterministic Classifications**._")?;
        writeln!(w)?;
    }

    for tactic in tactic_order {
        if let Some(tactic_events) = tactics.get(tactic) {
            writeln!(w, "### {} ({})", tactic, tactic_events.len())?;
            writeln!(w)?;
            let mut sorted = tactic_events.clone();
            sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
            for e in sorted.iter().take(10) {
                let desc_trunc = trunc_desc(&e.description, &e.indicators);
                writeln!(w, "- **[{}]** `{}` {}", e.severity.to_uppercase(), e.timestamp, desc_trunc)?;
                if !e.indicators.is_empty() {
                    let ind_str = e.indicators.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
                    writeln!(w, "  - Indicators: {}", ind_str)?;
                }
            }
            if sorted.len() > 10 {
                writeln!(w, "  - _… {} more in supertimeline_", sorted.len() - 10)?;
            }
            writeln!(w)?;
        }
    }

    if let Some(uncategorized) = tactics.get("Unknown/Uncategorized") {
        writeln!(w, "### Unknown/Uncategorized ({})", uncategorized.len())?;
        writeln!(w)?;
        let mut sorted = uncategorized.clone();
        sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        for e in sorted.iter().take(10) {
            let desc_trunc = trunc_desc(&e.description, &e.indicators);
            writeln!(w, "- **[{}]** `{}` {}", e.severity.to_uppercase(), e.timestamp, desc_trunc)?;
        }
        writeln!(w)?;
    }
    Ok(())
}

/// Log continuity: does this host's record run without a break, and if not, why?
///
/// Placed high in the report deliberately. Every finding below it is bounded by
/// this section: if the record restarts three days before collection, nothing
/// stated about the weeks before that describes the machine that was collected.
fn write_continuity<W: Write>(w: &mut W, c: &Continuity) -> Result<()> {
    writeln!(w, "## Log Continuity and Restoration")?;
    writeln!(w)?;

    if c.events_scanned == 0 {
        writeln!(w, "**No event-log records were available to test for continuity.** \
            Restoration cannot be ruled in or out for this host.")?;
        writeln!(w)?;
        return Ok(());
    }

    writeln!(w, "- **Record spans**: {} to {}",
        c.series_first.as_deref().unwrap_or("?"),
        c.series_last.as_deref().unwrap_or("?"))?;
    writeln!(w, "- **Days with events**: {} ({} records examined)",
        c.days_with_events, c.events_scanned)?;
    if let Some(d) = &c.install_date {
        writeln!(w, "- **OS install date**: {}{}", d,
            if c.install_is_recent { "  ← **within 90 days of the last logged event**" } else { "" })?;
    }
    if let Some(r) = &c.security_log_retention {
        writeln!(w, "- **Security log retention**: {}", r)?;
    }
    writeln!(w)?;

    if let Some(hours) = c.trailing_gap_hours {
        writeln!(w, "> **The record stops {}h before the host was collected.** The last parsed \
            event is {}, but the host's own hive says it was still logging at {}. Nothing was \
            observed in that window — it is a blind spot at the most recent, and usually the \
            most relevant, end of the timeline. Check whether the collection captured every \
            log channel.",
            hours,
            c.series_last.as_deref().unwrap_or("?"),
            c.collection_at.as_deref().unwrap_or("?"))?;
        writeln!(w)?;
    }

    if let Some(date) = c.restoration_date() {
        writeln!(w, "> **POSSIBLE RESTORATION — the record resumes at {}.**", date)?;
        writeln!(w, ">")?;
        writeln!(w, "> The event log stops and restarts with no shutdown, boot or log-clear \
            record to explain the break. That is the shape a restore from image leaves. \
            Evidence dated before this point may belong to the pre-restore system and \
            should not be read as describing the host as collected.")?;
        writeln!(w)?;
    } else if c.install_is_recent {
        writeln!(w, "> **The operating system was installed shortly before collection.** \
            No gap was needed to produce this: a rebuilt host has no earlier record to break. \
            Treat the absence of older evidence as expected rather than as a clean history.")?;
        writeln!(w)?;
    }

    if c.gaps.is_empty() {
        writeln!(w, "No break of {}h or more was found in the event-log record.",
            crate::timeline_parser::detectors::restoration::MIN_GAP_HOURS)?;
        writeln!(w)?;
        return Ok(());
    }

    writeln!(w, "| Record stops | Resumes | Gap | Assessment | Basis |")?;
    writeln!(w, "|--------------|---------|-----|------------|-------|")?;
    for g in &c.gaps {
        writeln!(w, "| {} | {} | {}h | {} | {} |",
            g.before, g.after, g.hours, g.kind.label(), cell(&g.evidence))?;
    }
    writeln!(w)?;

    let downtime = c.gaps.iter().filter(|g| g.kind == GapKind::Downtime).count();
    if downtime > 0 {
        writeln!(w, "{} of these are accounted for by a shutdown/boot pair and are not \
            treated as findings — listed so that the exclusion is visible rather than assumed.",
            downtime)?;
        writeln!(w)?;
    }
    if !c.cleared_at.is_empty() {
        writeln!(w, "**Event log clearing recorded at**: {}", c.cleared_at.join(", "))?;
        writeln!(w)?;
    }
    Ok(())
}

/// Installed software, and what about it is worth an analyst's time.
///
/// The distinction this section holds to: an end-of-life product is stated as
/// unsupported, because a support date is a fact. Everything else is stated as a
/// category worth reviewing. No CVE is named — an offline binary cannot know
/// which apply, and inventing them would be inventing forensic findings.
fn write_software<W: Write>(w: &mut W, inv: &SoftwareInventory) -> Result<()> {
    writeln!(w, "## Installed Software and Exposure")?;
    writeln!(w)?;

    if let Some(os) = &inv.os_product {
        match &inv.os_flag {
            Some(f) => writeln!(w, "- **Operating system**: {} — **{}**", os, f.verdict.label())?,
            None => writeln!(w, "- **Operating system**: {} (supported at the collection date)", os)?,
        }
    }

    if !inv.any() {
        writeln!(w)?;
        writeln!(w, "**No installed-software inventory was recovered.** The SOFTWARE hive was \
            not collected or not parsed, so no statement can be made about what is installed \
            on this host — including that nothing risky is.")?;
        writeln!(w)?;
        return Ok(());
    }

    writeln!(w, "- **Products inventoried**: {} (from {})",
        inv.installed.len(),
        inv.sources.iter().cloned().collect::<Vec<_>>().join(", "))?;
    writeln!(w, "- **Rules applied**: {} end-of-life, {} product categories, {} with a version threshold",
        inv.rules_eol, inv.rules_product, inv.rules_with_versions)?;
    writeln!(w)?;

    if inv.from_backup_hive() {
        writeln!(w, "> **The inventory was read from a `RegBack` backup hive.** Windows writes \
            these periodically, so this list may predate the incident and may omit software \
            installed after the last backup — including anything a threat actor installed.")?;
        writeln!(w)?;
    }

    if inv.rules_eol + inv.rules_product == 0 {
        writeln!(w, "**No software rules were loaded, so nothing was assessed.** The inventory \
            above is complete; the exposure question was not asked. This is not a statement that \
            the host runs nothing risky.")?;
        writeln!(w)?;
        return Ok(());
    }

    if inv.flags.is_empty() {
        writeln!(w, "No inventoried product matched an end-of-life or category rule.")?;
        writeln!(w)?;
    } else {
        writeln!(w, "| Product | Version | Assessment | Rule | Installed | Note |")?;
        writeln!(w, "|---------|---------|------------|------|-----------|------|")?;
        for f in &inv.flags {
            writeln!(w, "| {} | {} | {} | {} | {} | {} |",
                cell(&f.product.name),
                cell(&f.product.version),
                f.verdict.label(),
                cell(&f.rule),
                cell(&f.product.installed_at),
                cell(&f.note))?;
        }
        writeln!(w)?;
        let review = inv.flags.iter()
            .filter(|f| matches!(f.verdict, Verdict::Review { .. }))
            .count();
        if review > 0 {
            writeln!(w, "{} of these are flagged by category, not by version: their presence is \
                reported because these products are routinely abused for access, not because a \
                vulnerability has been established. Confirm the version against vendor advisories \
                before treating any of them as exploitable.", review)?;
            writeln!(w)?;
        }
    }

    if inv.rules_with_versions == 0 {
        writeln!(w, "*No version thresholds were configured, so no product was assessed as \
            out-of-date by version. Populate `min_safe_version` in `vulnerable_software.yaml` \
            from case threat intel, or run a CVE lookup against the inventory above.*")?;
        writeln!(w)?;
    }
    Ok(())
}

fn write_gaps<W: Write>(w: &mut W, gaps: &[CollectionGap]) -> Result<()> {
    if gaps.is_empty() {
        return Ok(());
    }
    writeln!(w, "## Collection Gaps")?;
    writeln!(w)?;
    writeln!(w, "The following artefacts were not processed by Wiskess (empty or missing output). \
        Data from these sources is absent from this timeline.")?;
    writeln!(w)?;
    writeln!(w, "| Artefact | Data Source | Expected File | Lines |")?;
    writeln!(w, "|----------|-------------|---------------|-------|")?;
    for gap in gaps {
        writeln!(w, "| {} | `{}` | `{}` | {} |",
            gap.name, gap.data_source, gap.analysis_file, gap.lines)?;
    }
    writeln!(w)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::timeline_parser::detectors::ioc_matcher::IocSource;

    fn render_iocs(events: &[UnifiedEvent], cov: &IocCoverage) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_iocs(&mut buf, events, cov).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn ioc_event(indicator: &str) -> UnifiedEvent {
        UnifiedEvent {
            timestamp: "2026-05-05T09:00:00Z".into(),
            source: "event-logs".into(),
            event_type: "logon".into(),
            severity: "high".into(),
            description: "logon from 10.0.0.5".into(),
            indicators: vec![indicator.into()],
            mitre_tactic: String::new(),
            mitre_technique: String::new(),
            user: "svc".into(),
            hostname: "H".into(),
            detection_rule: "t".into(),
            ..Default::default()
        }
    }

    fn supplied(n: usize) -> IocCoverage {
        IocCoverage {
            source: Some(IocSource {
                path: "/case/iocs.txt".into(),
                format: "text".into(),
                lines_total: n + 2,
                lines_comment: 1,
                lines_blank: 1,
                lines_indicator: n,
            }),
            ips: n,
            ..Default::default()
        }
    }

    /// The defect this section exists to fix: with no IOC file, a report that
    /// simply omitted the section was indistinguishable from a checked-and-clean
    /// one. It must say the check did not run.
    #[test]
    fn no_ioc_file_reads_as_unchecked_not_as_clean() {
        let out = render_iocs(&[], &IocCoverage::default());
        assert!(out.contains("## IOC Matches"), "{out}");
        assert!(out.contains("no IOC matching was performed"), "{out}");
        assert!(out.contains("not a result"), "{out}");
    }

    /// The opposite state, and it must read as a genuine finding.
    #[test]
    fn supplied_but_unmatched_reads_as_a_result() {
        let out = render_iocs(&[], &supplied(12));
        assert!(out.contains("12 indicators were searched"), "{out}");
        assert!(out.contains("None matched"), "{out}");
        assert!(out.contains("This is a result"), "{out}");
    }

    /// The operator asked for the line count of `iocs.txt` by name.
    #[test]
    fn the_source_file_line_accounting_is_reported() {
        let out = render_iocs(&[], &supplied(3));
        assert!(out.contains("/case/iocs.txt"), "{out}");
        assert!(out.contains("| Lines in file | 5 |"), "{out}");
        assert!(out.contains("| Lines yielding an indicator | 3 |"), "{out}");
        assert!(out.contains("| Comment lines skipped | 1 |"), "{out}");
    }

    /// A file that parsed to nothing is a third state, and it is not a result.
    #[test]
    fn a_file_that_yielded_no_indicators_reads_as_unchecked() {
        let mut cov = supplied(0);
        cov.ips = 0;
        let out = render_iocs(&[], &cov);
        assert!(out.contains("yielded no indicators"), "{out}");
        assert!(out.contains("unchecked rather than clear"), "{out}");
    }

    use crate::timeline_parser::detectors::restoration::{Continuity, LogGap};
    use crate::timeline_parser::detectors::software::{Flag, Installed, SoftwareInventory, Verdict};

    fn render_continuity(c: &Continuity) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_continuity(&mut buf, c).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn render_software(inv: &SoftwareInventory) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_software(&mut buf, inv).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn gap(before: &str, after: &str, hours: i64, kind: GapKind) -> LogGap {
        LogGap {
            before: before.into(),
            after: after.into(),
            hours,
            kind,
            evidence: "no shutdown or boot record brackets this gap".into(),
        }
    }

    fn render_detection(d: &DetectionCoverage) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_detection_coverage(&mut buf, d).unwrap();
        String::from_utf8(buf).unwrap()
    }

    /// The silent failure this block exists for: run from the wrong directory,
    /// the rule packs do not load, and the report looks like a quiet host.
    #[test]
    fn a_run_with_no_rules_loaded_refuses_to_read_as_clean() {
        let out = render_detection(&DetectionCoverage {
            data_dir: "tools/threat_intel".into(),
            ta_patterns: 0,
            path_rules: 0,
            software_rules: 0,
        });
        assert!(out.contains("NOT A CLEAN RESULT"), "{out}");
        assert!(out.contains("--data-dir"), "{out}");
    }

    /// A healthy run states the counts and raises nothing.
    #[test]
    fn a_fully_loaded_run_states_the_counts_without_a_warning() {
        let out = render_detection(&DetectionCoverage {
            data_dir: "/opt/wtp/tools/threat_intel".into(),
            ta_patterns: 117,
            path_rules: 14,
            software_rules: 48,
        });
        assert!(out.contains("| Threat-actor tool patterns | 117 |"), "{out}");
        assert!(!out.contains("NOT A CLEAN RESULT"), "{out}");
    }

    /// Zero rules and zero matches are different findings here too.
    #[test]
    fn a_software_section_with_no_rules_does_not_claim_nothing_matched() {
        let inv = SoftwareInventory {
            installed: vec![Installed { name: "AnyDesk".into(), ..Default::default() }],
            sources: ["registry.csv".to_string()].into_iter().collect(),
            rules_eol: 0,
            rules_product: 0,
            ..Default::default()
        };
        let out = render_software(&inv);
        assert!(out.contains("No software rules were loaded"), "{out}");
        assert!(!out.contains("No inventoried product matched"), "{out}");
    }

    /// A host with no event logs must not read as continuous. "No gap found" and
    /// "nothing to look at" are the same sentence unless this says otherwise.
    #[test]
    fn continuity_with_no_event_logs_refuses_to_rule_restoration_out() {
        let out = render_continuity(&Continuity::default());
        assert!(out.contains("## Log Continuity and Restoration"), "{out}");
        assert!(out.contains("cannot be ruled in or out"), "{out}");
    }

    /// The date the operator asked to be reported on.
    #[test]
    fn a_restoration_is_reported_with_its_resume_date() {
        let c = Continuity {
            events_scanned: 1000,
            days_with_events: 40,
            series_first: Some("2026-01-01T00:00:00Z".into()),
            series_last: Some("2026-05-10T23:00:00Z".into()),
            gaps: vec![gap("2026-05-02T23:00:00Z", "2026-05-09T01:00:00Z", 146,
                           GapKind::PossibleRestoration)],
            ..Default::default()
        };
        let out = render_continuity(&c);
        assert!(out.contains("POSSIBLE RESTORATION"), "{out}");
        assert!(out.contains("2026-05-09T01:00:00Z"), "{out}");
        assert!(out.contains("may belong to the pre-restore system"), "{out}");
    }

    /// Downtime is listed, and listed as excluded — so a reader can see it was
    /// considered rather than never looked for.
    #[test]
    fn downtime_is_shown_as_considered_and_excluded() {
        let c = Continuity {
            events_scanned: 1000,
            days_with_events: 40,
            series_last: Some("2026-05-10T23:00:00Z".into()),
            gaps: vec![gap("2026-05-02T23:00:00Z", "2026-05-09T01:00:00Z", 146, GapKind::Downtime)],
            ..Default::default()
        };
        let out = render_continuity(&c);
        assert!(!out.contains("POSSIBLE RESTORATION"), "{out}");
        assert!(out.contains("accounted for by a shutdown/boot pair"), "{out}");
        assert!(out.contains("exclusion is visible rather than assumed"), "{out}");
    }

    /// A blind spot at the end of the timeline is the easiest kind to miss and
    /// the most likely to matter.
    #[test]
    fn a_trailing_gap_is_reported_as_a_blind_spot() {
        let c = Continuity {
            events_scanned: 224923,
            days_with_events: 95,
            series_first: Some("2026-02-01T00:01:31Z".into()),
            series_last: Some("2026-05-06T20:00:27Z".into()),
            collection_at: Some("2026-05-11 09:35:03".into()),
            trailing_gap_hours: Some(109),
            ..Default::default()
        };
        let out = render_continuity(&c);
        assert!(out.contains("stops 109h before the host was collected"), "{out}");
        assert!(out.contains("2026-05-06T20:00:27Z"), "{out}");
        assert!(out.contains("blind spot"), "{out}");
    }

    /// A rebuild leaves no gap to find, so the install date has to carry it.
    #[test]
    fn a_recent_os_install_is_reported_without_any_gap() {
        let c = Continuity {
            events_scanned: 500,
            days_with_events: 10,
            series_last: Some("2026-05-10T23:00:00Z".into()),
            install_date: Some("2026-04-20 10:00:00.0000000".into()),
            install_is_recent: true,
            ..Default::default()
        };
        let out = render_continuity(&c);
        assert!(out.contains("installed shortly before collection"), "{out}");
        assert!(out.contains("expected rather than as a clean history"), "{out}");
    }

    fn flagged(name: &str, version: &str, verdict: Verdict) -> Flag {
        Flag {
            product: Installed {
                name: name.into(),
                version: version.into(),
                installed_at: "2026-03-19 08:31:18".into(),
                source: "registry.csv".into(),
                ..Default::default()
            },
            rule: name.into(),
            verdict,
            note: String::new(),
        }
    }

    /// An empty inventory is not a clean host, and must not read as one.
    #[test]
    fn an_absent_software_inventory_is_not_a_clean_result() {
        let out = render_software(&SoftwareInventory::default());
        assert!(out.contains("No installed-software inventory was recovered"), "{out}");
        assert!(out.contains("including that nothing risky is"), "{out}");
    }

    /// The line this section will not cross: presence is not a vulnerability.
    #[test]
    fn a_category_match_is_reported_as_review_not_as_a_vulnerability() {
        let inv = SoftwareInventory {
            installed: vec![Installed { name: "AnyDesk".into(), ..Default::default() }],
            flags: vec![flagged("AnyDesk", "7.0.15", Verdict::Review { category: "remote-access".into() })],
            sources: ["registry.csv".to_string()].into_iter().collect(),
            rules_eol: 15,
            rules_product: 33,
            rules_with_versions: 0,
            ..Default::default()
        };
        let out = render_software(&inv);
        assert!(out.contains("AnyDesk"), "{out}");
        assert!(out.contains("review — remote-access"), "{out}");
        assert!(out.contains("not because a vulnerability has been established"), "{out}");
        assert!(out.contains("No version thresholds were configured"), "{out}");
    }

    /// An EOL product is the one exposure claim this section does make.
    #[test]
    fn an_end_of_life_product_is_stated_as_unsupported() {
        let inv = SoftwareInventory {
            installed: vec![Installed { name: "Adobe Flash Player".into(), ..Default::default() }],
            flags: vec![flagged("Adobe Flash Player", "32.0.0.465",
                                Verdict::EndOfLife { eol: "2020-12-31".into() })],
            sources: ["registry.csv".to_string()].into_iter().collect(),
            rules_eol: 15,
            rules_product: 33,
            ..Default::default()
        };
        let out = render_software(&inv);
        assert!(out.contains("END OF LIFE (unsupported since 2020-12-31)"), "{out}");
    }

    /// A backup hive can predate the incident. Reporting it as current would
    /// state that nothing was installed during the intrusion.
    #[test]
    fn a_backup_hive_inventory_is_disclosed_as_possibly_stale() {
        let inv = SoftwareInventory {
            installed: vec![Installed { name: "x".into(), ..Default::default() }],
            hives: [r"\\?\X:\...\config\RegBack\SOFTWARE".to_string()].into_iter().collect(),
            sources: ["registry.csv".to_string()].into_iter().collect(),
            rules_eol: 15,
            rules_product: 33,
            ..Default::default()
        };
        let out = render_software(&inv);
        assert!(out.contains("RegBack"), "{out}");
        assert!(out.contains("may predate the incident"), "{out}");
    }

    #[test]
    fn matches_are_tabulated_against_the_supplied_total() {
        let events = vec![ioc_event("IOC:10.0.0.5")];
        let out = render_iocs(&events, &supplied(12));
        assert!(out.contains("1 of 12 supplied indicators matched"), "{out}");
        assert!(out.contains("IOC:10.0.0.5"), "{out}");
    }

    #[test]
    fn short_description_is_verbatim() {
        let d = "EventID 100: session connected";
        assert_eq!(trunc_desc(d, &[]), d);
    }

    #[test]
    fn truncation_without_hit_falls_back_to_head_ellipsis() {
        let d = "A".repeat(400);
        let out = trunc_desc(&d, &[]);
        assert!(out.ends_with('…'));
        assert!(!out.contains(" … "));
        assert_eq!(out.chars().count(), HEAD_CHARS + 1);
    }

    #[test]
    fn hit_past_head_is_spliced_with_context() {
        let mut d = "H".repeat(150);
        d.push_str("malicious_service_screenconnect_here");
        d.push_str(&"T".repeat(200));
        let out = trunc_desc(&d, &["TA_TOOL:screenconnect".to_string()]);
        assert!(out.contains(" … "), "expected splice markers: {out}");
        assert!(out.to_lowercase().contains("screenconnect"), "hit must be visible: {out}");
        assert!(out.starts_with(&"H".repeat(50)));
    }

    fn ev_desc(source: &str, desc: &str) -> UnifiedEvent {
        UnifiedEvent {
            source: source.to_string(),
            description: desc.to_string(),
            ..Default::default()
        }
    }

    /// Every one of these was produced by a free-text "something.something" scan
    /// on the corpus, and every one was presented as a domain the host touched.
    #[test]
    fn domain_extraction_refuses_usernames_filenames_and_assembly_names() {
        for junk in [
            "AuthenticatedUserName: user.name",
            r"Program Execution: AppCompatCache = SIGN.MEDIA=65AA183C 00 Archive",
            r"File created: C:\Users\frank\Downloads\net82.zip",
            "Amcache: microsoft.azure.activedirectory.synchronization.upgrader",
            r"Extension: PNG Absolute path: This PC\Z:\frank\WINSCP-UPDATED.PNG",
            "Defender platform version 4.18.2311.4",
        ] {
            let got = extract_domains(&ev_desc("registry", junk));
            assert!(got.is_empty(), "{junk} produced {got:?}");
        }
    }

    /// ...while a domain the evidence actually names still comes through.
    #[test]
    fn domain_extraction_keeps_urls_labelled_hosts_and_supplied_iocs() {
        let url = extract_domains(&ev_desc(
            "browser-hist",
            "Visited https://cdn.evil-c2.net/beacon?id=1",
        ));
        assert!(url.contains("cdn.evil-c2.net"), "{url:?}");

        let dns = extract_domains(&ev_desc(
            "hayabusa",
            "DNS query | QueryName: pastebin.com | result ok",
        ));
        assert!(dns.contains("pastebin.com"), "{dns:?}");

        let ioc = extract_domains(&UnifiedEvent {
            indicators: vec!["IOC:dragonforce-panel.onion.to".to_string()],
            ..ev_desc("event-logs", "nothing in the text")
        });
        assert!(ioc.contains("dragonforce-panel.onion.to"), "{ioc:?}");
    }

    /// The touchpoint table is about *external* addresses. Internal space,
    /// CGNAT and the documentation ranges are not that.
    #[test]
    fn only_routable_addresses_count_as_external() {
        for public in ["87.106.179.142", "8.8.8.8", "217.194.210.5"] {
            assert!(is_public_ip(public), "{public}");
        }
        for internal in [
            "10.0.0.2", "172.16.1.5", "192.168.40.3", "127.0.0.1", "169.254.1.1",
            "100.64.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1", "203.0.113.9",
        ] {
            assert!(!is_public_ip(internal), "{internal}");
        }
    }

    /// A registry value is configuration. The F-Secure blocklist that read as 23
    /// separate host compromises must land on the other side of the split.
    #[test]
    fn a_registry_sourced_string_is_configuration_not_activity() {
        let reg = ev_desc(
            "registry",
            r"F-Secure\Ultralight\Settings\nif.untrusted_urls = anydesk.com;teamviewer.com",
        );
        assert_eq!(Provenance::of(&reg), Provenance::Configuration);
        let net = ev_desc("browser-hist", "Visited https://anydesk.com/download");
        assert_eq!(Provenance::of(&net), Provenance::Activity);
    }

    fn phased(ts: &str, phase: &str, sev: &str) -> UnifiedEvent {
        UnifiedEvent {
            timestamp: ts.to_string(),
            source: "event-logs".to_string(),
            severity: sev.to_string(),
            description: "a thing happened".to_string(),
            phase: phase.to_string(),
            ..Default::default()
        }
    }

    fn render_phases(events: &[UnifiedEvent], c: &Continuity, supplied: Option<&str>) -> String {
        let mut w: Vec<u8> = Vec::new();
        write_phases(&mut w, events, c, supplied).unwrap();
        String::from_utf8(w).unwrap()
    }

    /// "Definitionally true and evidentially empty" — a host whose whole record
    /// postdates its restoration must not be reported as carrying
    /// post-restoration attacker activity.
    #[test]
    fn a_record_that_wholly_postdates_the_restore_says_so_instead_of_claiming_a_finding() {
        let events = vec![
            phased("2026-05-20T01:00:00Z", PHASE_POST, "high"),
            phased("2026-05-20T02:00:00Z", PHASE_POST, "high"),
        ];
        let out = render_phases(&events, &Continuity::default(), Some("2026-05-19T00:00:00Z"));
        assert!(out.contains("Most of this host's record postdates the restoration date"), "{out}");
        assert!(out.contains("supplied by the operator"));
    }

    /// The ordinary shape: a rebuild with most of the record before it, and one
    /// unexplained finding after. That one is the whole point of the section.
    #[test]
    fn a_single_unexplained_post_restoration_finding_is_shown_without_the_caveat() {
        let mut events: Vec<UnifiedEvent> = (0..10)
            .map(|i| phased(&format!("2026-05-0{i}T01:00:00Z"), PHASE_PRE, "high"))
            .collect();
        events.push(phased("2026-05-21T01:00:00Z", PHASE_POST, "high"));
        let out = render_phases(&events, &Continuity::default(), Some("2026-05-19T00:00:00Z"));
        assert!(!out.contains("Most of this host's record postdates"), "{out}");
        assert!(out.contains("### Post-restoration, unexplained"));
        assert!(out.contains("1 finding(s) postdate the restore"), "{out}");
    }

    /// With no restoration date there is nothing to partition against, and the
    /// section must not appear at all rather than appear empty.
    #[test]
    fn no_restoration_date_means_no_phase_section() {
        let out = render_phases(&[], &Continuity::default(), None);
        assert!(out.is_empty(), "{out}");
    }

    #[test]
    fn standout_hostnames_flagged() {
        assert!(suspicious_hostname("DESKTOP-A1B2C3D").is_some());
        assert!(suspicious_hostname("WIN-ABCDEFG1234").is_some());
        assert!(suspicious_hostname("kali").is_some());
        assert!(suspicious_hostname("MY-FILE01").is_none());
        assert!(suspicious_hostname("MY-DC02").is_none());
    }

    #[test]
    fn user_cleaning_strips_domain_and_sid() {
        assert_eq!(clean_user("domain\\Super Admin (S-1-5-21-...)"), "super admin");
        assert_eq!(clean_user("alice@domain.local"), "alice");
        assert!(!is_real_user("MY-DC02$"));
        assert!(is_real_user("super admin"));
    }
}
