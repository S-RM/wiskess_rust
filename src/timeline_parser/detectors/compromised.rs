use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

use crate::timeline_parser::output::event::UnifiedEvent;

static IP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:::ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap()
});

static USER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:TgtUser|User|Acct|SrcUser):\s*([^\s¦|,]+)").unwrap()
});

static HOSTNAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:SrcComp|Workstation|Computer):\s*([A-Za-z0-9_-]+)").unwrap()
});

pub struct CompromisedEntities {
    pub users: HashSet<String>,
    pub ips: HashSet<String>,
    pub hostnames: HashSet<String>,
}

impl CompromisedEntities {
    pub fn new() -> Self {
        Self {
            users: HashSet::new(),
            ips: HashSet::new(),
            hostnames: HashSet::new(),
        }
    }

    pub fn add_ips(&mut self, ips: &HashSet<String>) {
        for ip in ips {
            self.ips.insert(ip.to_lowercase());
        }
    }

    pub fn add_users(&mut self, users: &HashSet<String>) {
        for u in users {
            self.users.insert(u.to_lowercase());
        }
    }

    pub fn learn_from_event(&mut self, event: &UnifiedEvent) {
        let has_ioc = event.indicators.iter().any(|i| i.starts_with("IOC:"));
        let has_ta_tool = event.indicators.iter().any(|i| i.starts_with("TA_TOOL:"));
        let is_high_sev = event.severity == "high" || event.severity == "crit";

        for indicator in &event.indicators {
            if let Some(ip) = indicator.strip_prefix("IOC:") {
                if ip.chars().all(|c| c.is_ascii_digit() || c == '.') && ip.contains('.') {
                    self.ips.insert(ip.to_lowercase());
                }
            }
            if let Some(ip) = indicator.strip_prefix("COMPROMISED_IP:") {
                self.ips.insert(ip.to_lowercase());
            }
            if let Some(user) = indicator.strip_prefix("COMPROMISED_USER:") {
                self.users.insert(user.to_lowercase());
            }
        }

        let desc = &event.description;
        let event_has_compromised_ip = self.description_contains_known_ip(desc);

        // Mark user as compromised only when directly linked to malicious tooling or IOC
        // (not just because a known-bad IP is in the same event — that user might be a victim)
        if !event.user.is_empty() && (has_ta_tool || has_ioc) {
            let user_clean = event.user.split('@').next().unwrap_or(&event.user);
            let user_clean = user_clean.split('(').next().unwrap_or(user_clean).trim();
            let user_clean = user_clean.rsplit('\\').next().unwrap_or(user_clean);
            if user_clean != "-" && !user_clean.is_empty()
                && !user_clean.ends_with('$')
                && user_clean.len() > 1
            {
                self.users.insert(user_clean.to_lowercase());
            }
        }

        // Extract users from description only for TA_TOOL or direct IOC hits
        // Also extract when a known-bad IP appears AND the event shows authentication FROM that IP
        let extract_user = has_ta_tool || has_ioc
            || (event_has_compromised_ip && (desc.contains("SrcIP:") || desc.contains("SrcComp:")));

        if extract_user {
            for cap in USER_RE.captures_iter(desc) {
                let user = &cap[1];
                let user_clean = user.split('@').next().unwrap_or(user);
                let user_clean = user_clean.rsplit('\\').next().unwrap_or(user_clean);
                if !user_clean.is_empty() && user_clean != "-"
                    && !user_clean.ends_with('$')
                    && user_clean.len() > 1
                {
                    self.users.insert(user_clean.to_lowercase());
                }
            }
        }

        // Extract IPs from description text and mark compromised if event is malicious
        if has_ioc || has_ta_tool || is_high_sev {
            for cap in IP_RE.captures_iter(desc) {
                let ip = &cap[1];
                if !ip.starts_with("127.") && ip != "0.0.0.0" && !ip.starts_with("::") {
                    self.ips.insert(ip.to_string());
                }
            }
        }

        // Extract DESKTOP-* hostnames from description or SrcComp fields
        if desc.contains("DESKTOP-") {
            if let Some(start) = desc.find("DESKTOP-") {
                let hostname: String = desc[start..]
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '-')
                    .collect();
                if hostname.len() > 8 {
                    self.hostnames.insert(hostname.to_uppercase());
                }
            }
        }
        for cap in HOSTNAME_RE.captures_iter(desc) {
            let h = &cap[1];
            if h.starts_with("DESKTOP-") || h.starts_with("WIN-") {
                self.hostnames.insert(h.to_uppercase());
            }
        }
    }

    fn description_contains_known_ip(&self, desc: &str) -> bool {
        for cap in IP_RE.captures_iter(desc) {
            let ip = &cap[1];
            if self.ips.contains(ip) {
                return true;
            }
        }
        false
    }

    pub fn is_user_compromised(&self, user: &str) -> bool {
        if user.is_empty() {
            return false;
        }
        let lower = user.to_lowercase();
        // Strip domain prefix and SID suffix: "domain\user.name (S-1-5-...)" → "user.name"
        let user_clean = lower.split('(').next().unwrap_or(&lower).trim();
        let user_clean = user_clean.split('@').next().unwrap_or(user_clean);
        let user_clean = user_clean.rsplit('\\').next().unwrap_or(user_clean).trim();

        if user_clean.is_empty() || user_clean.ends_with('$') {
            return false;
        }
        // Skip system accounts
        if user_clean == "system" || user_clean.starts_with("nt authority")
            || user_clean.starts_with("local service") || user_clean.starts_with("network service")
            || user_clean.starts_with("dwm-") || user_clean == "-"
        {
            return false;
        }

        self.users.contains(user_clean)
    }

    pub fn is_ip_compromised(&self, ip: &str) -> bool {
        if ip.is_empty() {
            return false;
        }
        self.ips.contains(&ip.to_lowercase())
    }

    pub fn is_hostname_compromised(&self, hostname: &str) -> bool {
        if hostname.is_empty() {
            return false;
        }
        self.hostnames.contains(&hostname.to_uppercase())
    }
}

