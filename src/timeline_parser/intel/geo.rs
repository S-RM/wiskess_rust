//! MaxMind GeoIP / ASN / Anonymous-IP enrichment for IP-literal hosts.
//!
//! Adapted from uac-parser/uniqess `intel::ip_analysis`. Databases are optional:
//! when no `.mmdb` files are found, `GeoReaders::open` yields empty readers and
//! every lookup returns an empty `GeoInfo` (enrichment is simply skipped).

use maxminddb::geoip2;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct GeoInfo {
    pub country: String,
    pub city: String,
    pub asn: String,
    pub org: String,
    /// "VPN", "Proxy", "Tor", "Hosting", "Residential Proxy", joined by ", ".
    /// Empty when the Anonymous-IP DB is absent; "Benign" when present but no flags.
    pub proxy_type: String,
}

impl GeoInfo {
    pub fn is_empty(&self) -> bool {
        self.country.is_empty() && self.asn.is_empty() && self.org.is_empty()
            && (self.proxy_type.is_empty() || self.proxy_type == "Benign")
    }
    /// True when the IP is flagged as an anonymising/hosting service — worth raising severity.
    pub fn is_anonymizing(&self) -> bool {
        !self.proxy_type.is_empty() && self.proxy_type != "Benign"
    }
    /// Compact one-line summary for an indicator string.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.country.is_empty() {
            if self.city.is_empty() { parts.push(self.country.clone()); }
            else { parts.push(format!("{}/{}", self.country, self.city)); }
        }
        if !self.org.is_empty() {
            parts.push(if self.asn.is_empty() { self.org.clone() } else { format!("{} {}", self.asn, self.org) });
        }
        if self.is_anonymizing() { parts.push(self.proxy_type.clone()); }
        parts.join(" | ")
    }
}

pub struct GeoReaders {
    city: Option<maxminddb::Reader<Vec<u8>>>,
    asn: Option<maxminddb::Reader<Vec<u8>>>,
    anon: Option<maxminddb::Reader<Vec<u8>>>,
}

impl GeoReaders {
    pub fn open(paths: &GeoDbPaths) -> Self {
        Self {
            city: paths.city.as_ref().and_then(|p| maxminddb::Reader::open_readfile(p).ok()),
            asn: paths.asn.as_ref().and_then(|p| maxminddb::Reader::open_readfile(p).ok()),
            anon: paths.anon.as_ref().and_then(|p| maxminddb::Reader::open_readfile(p).ok()),
        }
    }

    /// True if at least one database loaded (otherwise lookups are no-ops).
    pub fn available(&self) -> bool {
        self.city.is_some() || self.asn.is_some() || self.anon.is_some()
    }

    pub fn lookup(&self, ip_str: &str) -> GeoInfo {
        let mut info = GeoInfo::default();
        let ip: IpAddr = match ip_str.parse() {
            Ok(i) => i,
            Err(_) => return info,
        };

        if let Some(c) = self.city.as_ref().and_then(|r| r.lookup::<geoip2::City>(ip).ok()) {
            info.country = c.country.and_then(|co| co.names).and_then(|n| n.get("en").copied()).unwrap_or("").to_string();
            info.city = c.city.and_then(|ci| ci.names).and_then(|n| n.get("en").copied()).unwrap_or("").to_string();
        }
        if let Some(a) = self.asn.as_ref().and_then(|r| r.lookup::<geoip2::Asn>(ip).ok()) {
            info.org = a.autonomous_system_organization.unwrap_or("").to_string();
            info.asn = a.autonomous_system_number.map(|n| format!("AS{}", n)).unwrap_or_default();
        }
        if let Some(a) = self.anon.as_ref().and_then(|r| r.lookup::<geoip2::AnonymousIp>(ip).ok()) {
            let mut types = Vec::new();
            if a.is_anonymous_vpn.unwrap_or(false) { types.push("VPN"); }
            if a.is_public_proxy.unwrap_or(false) { types.push("Proxy"); }
            if a.is_tor_exit_node.unwrap_or(false) { types.push("Tor"); }
            if a.is_hosting_provider.unwrap_or(false) { types.push("Hosting"); }
            if a.is_residential_proxy.unwrap_or(false) { types.push("Residential Proxy"); }
            info.proxy_type = if types.is_empty() { "Benign".to_string() } else { types.join(", ") };
        }
        info
    }
}

#[derive(Default)]
pub struct GeoDbPaths {
    pub city: Option<PathBuf>,
    pub asn: Option<PathBuf>,
    pub anon: Option<PathBuf>,
}

/// Search standard locations for MaxMind `.mmdb` files (checks `MAXMIND_DB_DIR` first).
pub fn find_geo_dbs() -> GeoDbPaths {
    let mut paths = GeoDbPaths::default();

    if let Ok(dir) = std::env::var("MAXMIND_DB_DIR") {
        try_load_from_dir(Path::new(&dir), &mut paths);
    }

    // User home: HOME on Unix, USERPROFILE on Windows.
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).ok();
    if let Some(home) = home {
        try_load_from_dir(&PathBuf::from(home).join(".local/share/GeoIP"), &mut paths);
    }

    #[cfg(unix)]
    for dir in ["/usr/share/GeoIP", "/usr/local/share/GeoIP", "/opt/GeoIP"] {
        try_load_from_dir(Path::new(dir), &mut paths);
    }

    // Windows system locations: %ProgramData%\GeoIP and %LOCALAPPDATA%\GeoIP.
    #[cfg(windows)]
    for var in ["ProgramData", "LOCALAPPDATA"] {
        if let Ok(base) = std::env::var(var) {
            try_load_from_dir(&PathBuf::from(base).join("GeoIP"), &mut paths);
        }
    }

    paths
}

/// If a URL's host is an IP literal (v4 or v6), return it (without scheme/port/path).
/// Domains return `None` — they can't be geo-located without DNS resolution.
pub fn url_ip_literal(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://").or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = without_scheme.split('/').next().unwrap_or("");
    // Strip a trailing :port for IPv4; bracketed IPv6 handled below.
    let host = if let Some(inner) = host.strip_prefix('[') {
        inner.split(']').next().unwrap_or(inner) // [::1]:443 -> ::1
    } else {
        host.split(':').next().unwrap_or(host)
    };
    host.parse::<IpAddr>().ok().map(|_| host.to_string())
}

fn try_load_from_dir(dir: &Path, paths: &mut GeoDbPaths) {
    let pick = |names: &[&str]| names.iter().map(|n| dir.join(n)).find(|p| p.is_file());
    if paths.city.is_none() { paths.city = pick(&["GeoLite2-City.mmdb", "GeoIP2-City.mmdb"]); }
    if paths.asn.is_none() { paths.asn = pick(&["GeoLite2-ASN.mmdb", "GeoIP2-ISP.mmdb"]); }
    if paths.anon.is_none() { paths.anon = pick(&["GeoIP2-Anonymous-IP.mmdb"]); }
}
