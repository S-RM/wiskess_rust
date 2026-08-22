use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::LazyLock;

use crate::timeline_parser::config::{severity_order, TimeWindow};
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
        if self.first.is_empty() || e.timestamp < self.first {
            self.first = e.timestamp.clone();
        }
        if e.timestamp > self.last {
            self.last = e.timestamp.clone();
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

pub fn generate_report(
    events: &[UnifiedEvent],
    window: &Option<TimeWindow>,
    hostname: &str,
    elapsed: f64,
    gaps: &[CollectionGap],
    geo: &GeoReaders,
    ioc_coverage: &IocCoverage,
    detection: &DetectionCoverage,
    continuity: &Continuity,
    software: &SoftwareInventory,
    report_path: &Path,
) -> Result<()> {
    let file = File::create(report_path)?;
    let mut w = BufWriter::new(file);

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

    write_detection_coverage(&mut w, detection)?;
    write_continuity(&mut w, continuity)?;

    write_user_table(&mut w, events)?;
    write_ip_table(&mut w, events, geo)?;
    write_hostname_table(&mut w, events)?;
    write_access_timeline(&mut w, events)?;
    write_lateral_section(&mut w, events)?;

    write_ta_tools(&mut w, events)?;
    write_iocs(&mut w, events, ioc_coverage)?;
    write_software(&mut w, software)?;
    write_tactic_findings(&mut w, events)?;
    write_gaps(&mut w, gaps)?;

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
    for e in events {
        if severity_order(&e.severity) >= severity_order("med") {
            let tactic = if e.mitre_tactic.is_empty() { "Unknown/Uncategorized" } else { &e.mitre_tactic };
            tactics.entry(tactic).or_default().push(e);
        }
    }

    writeln!(w, "## Findings by ATT&CK Tactic (condensed)")?;
    writeln!(w)?;
    writeln!(w, "_Top events per tactic; the complete, untruncated set is in the supertimeline CSV/JSONL._")?;
    writeln!(w)?;

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

    #[test]
    fn standout_hostnames_flagged() {
        assert!(suspicious_hostname("DESKTOP-BBETH6K").is_some());
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
