//! User Access Logging — `network.csv` (SumECmd) and `network-kstrike.csv`.
//!
//! UAL records, per server role, which client address and account reached it and
//! how many times. Two things about it drove this rewrite.
//!
//! **`network-kstrike.csv` was never discovered.** It is the Linux-Wiskess parse
//! of the same database, and because discovery named `network.csv` and nothing
//! else, every UAL row on a Linux-collected host was missing from the output with
//! no warning. Its header is also spelled differently throughout, so simply
//! finding the file was not enough: `AuthenticatedUserName` is the only column
//! name the two parses share.
//!
//! **Rarity is the signal, and the old threshold was too tight.** A peer or
//! account that touched a role once or twice is the interesting case; one that
//! touched it five thousand times is the file server doing its job. The curated
//! cut kept only `TotalAccesses <= 5` *and* in-window, which is narrower than the
//! operator's rule of "fewer than ten" and, worse, discarded the artifact
//! entirely whenever the analysis window predated collection. A UAL row is a
//! **summary stamped with an `InsertDate`**, not a point-in-time event: the
//! accesses it counts happened across the days in `DatesAndAccesses`, so
//! filtering the row by its stamp throws away the whole record. So the window no
//! longer gates inclusion here — it only nudges severity.
//!
//! Rare rows carry `NET:rare_access_count_<n>`, which is in `STRONG_PREFIXES`, so
//! they reach the curated triage timeline on their rarity rather than on a
//! severity they do not deserve.

use anyhow::Result;
use std::io::BufReader;
use std::path::Path;

use crate::timeline_parser::config::{raise, PipelineConfig};
use crate::timeline_parser::detectors::compromised::CompromisedEntities;
use crate::timeline_parser::detectors::ioc_matcher::IOCMatcher;
use crate::timeline_parser::output::event::UnifiedEvent;
use crate::timeline_parser::parsers::columns::{
    self, Columns, Field, AUTH_USER, DATES_AND_ACCESSES, DATETIME, TOTAL_ACCESSES, UAL_ADDRESS,
    UAL_RAW_ADDRESS, UAL_ROLE,
};

/// Pull the common name out of an LDAP distinguished name.
///
/// `AuthenticatedUserName` arrives in three shapes: a plain account (`testuser`),
/// a machine account (`domain\my-web01$`), and — for AD DS role access — a full
/// DN, `cn=test user,ou=users,ou=site,dc=domain,dc=local`.
///
/// The DN form was being carried through verbatim, and the report's per-user
/// table rejects anything containing `=` as a raw DN. The effect was that every
/// UAL access by a named human vanished from Account Activity — the one table
/// where "who reached this DC" belongs. The name is right there in the first
/// RDN; this takes it.
fn normalise_ual_user(raw: &str) -> String {
    let t = raw.trim();
    if !t.contains('=') {
        return t.to_string();
    }
    for rdn in t.split(',') {
        let rdn = rdn.trim();
        if let Some((attr, value)) = rdn.split_once('=') {
            if attr.trim().eq_ignore_ascii_case("cn") && !value.trim().is_empty() {
                return value.trim().to_string();
            }
        }
    }
    t.to_string()
}

/// Split a UAL address cell into the address and any correlated peer hostnames.
///
/// kstrike spells the column `ConvertedAddress (Correlated_HostName(s))` and
/// fills it with `<ip> ('<HOSTNAME>')`, or with a literal `Local Host <addr>`
/// for the machine's own accesses. SumECmd supplies a bare `IpAddress`. All
/// three come out of here as an address plus zero or more peer names.
///
/// The peer name matters: it is the only place a UAL row says *which host* an
/// address belonged to at collection time, and the report's hostname table picks
/// it up out of the description.
fn split_address(raw: &str) -> (String, Vec<String>) {
    let t = raw.trim();
    // The machine's own access, labelled rather than correlated. `get` rather
    // than a slice: the cell is free text and may not be ASCII.
    let t = match t.get(..11) {
        Some(p) if p.eq_ignore_ascii_case("local host ") => t[11..].trim(),
        _ => t,
    };
    let (addr, rest) = match t.split_once(" (") {
        Some((a, r)) => (a.trim(), r.trim_end().trim_end_matches(')')),
        None => (t, ""),
    };
    let hosts: Vec<String> = rest
        .split(',')
        .map(|h| h.trim().trim_matches(['\'', '"']).trim())
        .filter(|h| !h.is_empty() && *h != "-")
        .map(str::to_string)
        .collect();
    (addr.to_string(), hosts)
}

/// The display form of a UAL role. kstrike writes `{<guid>} (<Role Name>)`;
/// SumECmd writes the name alone. The name is what a reader needs; the GUID
/// identifies the same role in every collection and nothing else.
fn role_name(raw: &str) -> String {
    let t = raw.trim();
    match t.split_once(" (") {
        Some((guid, name)) if guid.trim_start().starts_with('{') => {
            name.trim_end().trim_end_matches(')').trim().to_string()
        }
        _ => t.to_string(),
    }
}

/// A Windows builtin, not a case detail: an unauthenticated caller that reached a
/// server role. `NT AUTHORITY\ANONYMOUS LOGON` appearing as the *authenticated*
/// user of a UAL role is a finding on its own.
fn is_anonymous(user: &str) -> bool {
    user.to_lowercase().contains("anonymous logon")
}

pub fn parse(
    filepath: &Path,
    cfg: &PipelineConfig,
    ioc_matcher: &IOCMatcher,
    hostname: &str,
    compromised: &CompromisedEntities,
) -> Result<Vec<UnifiedEvent>> {
    let mut events = Vec::new();
    let mut rows = 0usize;

    let file = std::fs::File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers()?.clone();

    let cols = Columns::resolve(
        "network",
        filepath,
        &headers,
        &[
            DATETIME,
            AUTH_USER,
            UAL_ADDRESS,
            UAL_RAW_ADDRESS,
            UAL_ROLE,
            TOTAL_ACCESSES,
            DATES_AND_ACCESSES,
            Field::optional("message", &["message"]),
        ],
    );

    // Rarity is the whole detection here, so its absence has to be said out loud
    // rather than discovered later as a table of zeroes.
    let counts_readable = cols.has("total_accesses");
    if !counts_readable {
        eprintln!(
            "[WARN] network: no TotalAccesses column in {} — rare-access detection is OFF for \
             this file; rows are carried as baseline records only",
            cols.file()
        );
    }

    for result in rdr.records() {
        let Ok(record) = result else { continue };
        rows += 1;

        let ts = cols.get(&record, "datetime").to_string();
        if ts.is_empty() {
            continue;
        }

        let user = normalise_ual_user(cols.get(&record, "auth_user"));
        let raw_addr = {
            let converted = cols.get(&record, "address");
            if converted.is_empty() { cols.get(&record, "raw_address") } else { converted }
        };
        let (ip, peers) = split_address(raw_addr);
        let role = role_name(cols.get(&record, "role"));

        // `None` means "the column did not resolve, or the cell did not parse" —
        // never `0`. A confident `rare_access_count_0` on every row of a file
        // whose header we could not read is exactly the failure mode this whole
        // change exists to remove.
        let total_accesses: Option<u32> = if counts_readable {
            cols.get(&record, "total_accesses").replace(',', "").parse().ok()
        } else {
            None
        };

        let is_in_window = cfg.in_timewindow(&ts);
        let scan_text = format!("{} {} {}", ip, user, peers.join(" "));
        let ioc_hits = ioc_matcher.check(&scan_text);

        let mut indicators: Vec<String> = ioc_hits;
        let mut severity = "low".to_string();
        let mut flagged = !indicators.is_empty();
        if flagged {
            severity = "high".to_string();
        }

        if is_anonymous(&user) {
            flagged = true;
            indicators.push("NET:anonymous_logon_ual".to_string());
            raise(&mut severity, "high");
        }

        if compromised.is_user_compromised(&user) && is_in_window {
            flagged = true;
            indicators.push(format!("COMPROMISED_USER:{}", user));
            raise(&mut severity, "med");
        }

        if compromised.is_ip_compromised(&ip) {
            flagged = true;
            indicators.push(format!("COMPROMISED_IP:{}", ip));
            raise(&mut severity, "med");
        }

        // A peer that reached this server role twice is more interesting than one
        // that reached it ten thousand times. "Fewer than ten" is the operator's
        // rule and applies in both verbosities; the window does not gate it (see
        // the module doc). `NET:rare_access_count` is in `STRONG_PREFIXES`, so
        // these rows reach the triage cut on their rarity, not on severity.
        if let Some(n) = total_accesses.filter(|n| *n < cfg.rare_logon_max as u32) {
            flagged = true;
            indicators.push(format!("NET:rare_access_count_{}", n));
            if is_in_window && n <= 2 {
                raise(&mut severity, "med");
            }
        }

        if !flagged {
            // UAL is a Quiet artifact: a row nothing fired on is still the record
            // of who reached this host, and it belongs in the supertimeline. `info`
            // keeps it out of the curated cut and the markdown report.
            if !cfg.emit_quiet_baseline {
                continue;
            }
            severity = "info".to_string();
            indicators.push("NET:ual_record".to_string());
        }

        let mut parts: Vec<String> = Vec::new();
        if !role.is_empty() {
            parts.push(role);
        }
        parts.push(format!("User: {}", if user.is_empty() { "-" } else { &user }));
        parts.push(format!("IP: {}", if ip.is_empty() { "-" } else { &ip }));
        if !peers.is_empty() {
            parts.push(format!("Peer: {}", peers.join(", ")));
        }
        parts.push(match total_accesses {
            Some(n) => format!("Accesses: {}", n),
            None => "Accesses: unknown".to_string(),
        });
        // The per-day breakdown, but not a five-kilobyte description: a busy
        // client accumulates one entry per day of the retention period, and the
        // rows where the detail earns its space are the rare ones, which are short.
        let days = cols.get(&record, "dates_and_accesses");
        if !days.is_empty() {
            if days.len() <= 160 {
                parts.push(format!("Days: {}", days));
            } else {
                parts.push(format!("Days: {} dates", days.matches(':').count()));
            }
        }

        events.push(UnifiedEvent {
            timestamp: ts,
            source: "network".to_string(),
            event_type: "network_connection".to_string(),
            severity,
            description: parts.join(" | "),
            indicators,
            mitre_tactic: String::new(),
            mitre_technique: String::new(),
            user,
            hostname: hostname.to_string(),
            detection_rule: "network_correlated".to_string(),
            ..Default::default()
        });
    }

    columns::note_rows("network", rows);
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline_parser::config::{TimeWindow, Verbosity};
    use crate::timeline_parser::output::supertimeline::is_triage_hit;
    use std::io::Write;

    /// The kstrike header, verbatim. Every column name in it differs from the
    /// SumECmd parse except `AuthenticatedUserName`.
    const KSTRIKE_HEADER: &str = "datetime,timestamp_desc,message,AuthenticatedUserName,\
        ConvertedAddress (Correlated_HostName(s)),TotalAccesses,RoleGuid (RoleName),\
        DatesAndAccesses,RawAddress,hostname,doc_type,timestamp";

    /// The SumECmd header this parser was written against.
    const SUM_HEADER: &str =
        "datetime,RoleDescription,TotalAccesses,AuthenticatedUserName,IpAddress";

    fn run_with(header: &str, body: &str, cfg: PipelineConfig) -> Vec<UnifiedEvent> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("network-kstrike.csv");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "{header}").unwrap();
        f.write_all(body.as_bytes()).unwrap();
        drop(f);
        parse(
            &path,
            &cfg,
            &IOCMatcher::new(None).unwrap(),
            "MY-WEB01",
            &CompromisedEntities::new(),
        )
        .unwrap()
    }

    /// A window that the fixture rows sit *outside*, to prove the window does not
    /// gate a UAL summary row.
    fn windowed(verbosity: Verbosity) -> PipelineConfig {
        PipelineConfig {
            verbosity,
            window: Some(TimeWindow::new(
                "2026-05-05T00:00:00Z",
                "2026-05-07T00:00:00Z",
                0,
                "user-specified",
            )),
            ..Default::default()
        }
    }

    fn kstrike_rows() -> String {
        // user, converted address, accesses, role, dates, raw address
        [
            "2026-09-09T07:51:12.973Z,d,m,\"domain.local\\testuser\",172.16.0.21 ('MY-APP02'),1,\
             {00000000-0000-0000-0000-000000000001} (Active Directory Domain Services),\
             2026-09-09: 1,172.16.0.21,MY-WEB01,network_sum_kstrike,1\n",
            "2026-09-09T07:51:13.973Z,d,m,\"domain.local\\svcweb\",172.16.0.22 ('MY-APP03'),9,\
             {00000000-0000-0000-0000-000000000001} (Active Directory Domain Services),\
             2026-09-09: 9,172.16.0.22,MY-WEB01,network_sum_kstrike,2\n",
            "2026-09-09T07:51:14.973Z,d,m,\"domain.local\\svcbackup\",172.16.0.23 ('MY-APP04'),10,\
             {00000000-0000-0000-0000-000000000001} (Active Directory Domain Services),\
             2026-09-09: 10,172.16.0.23,MY-WEB01,network_sum_kstrike,3\n",
            "2026-09-09T07:51:15.973Z,d,m,\"domain.local\\my-app05$\",172.16.0.24 ('MY-APP05'),4883,\
             {00000000-0000-0000-0000-000000000001} (Active Directory Domain Services),\
             2026-09-09: 4883,172.16.0.24,MY-WEB01,network_sum_kstrike,4\n",
        ]
        .concat()
    }

    /// The operator's requirement, by name: every rare access count below ten is
    /// carried, and nothing above it acquires the indicator.
    #[test]
    fn every_access_count_below_the_threshold_is_flagged_rare() {
        let events = run_with(KSTRIKE_HEADER, &kstrike_rows(), windowed(Verbosity::Curated));
        assert_eq!(events.len(), 4, "a quiet artifact carries every row");

        let rare: Vec<&str> = events
            .iter()
            .filter(|e| e.indicators.iter().any(|i| i.starts_with("NET:rare_access_count_")))
            .map(|e| e.user.as_str())
            .collect();
        assert_eq!(
            rare,
            vec![r"domain.local\testuser", r"domain.local\svcweb"],
            "1 and 9 are rare; 10 and 4883 are not"
        );
        assert!(events[0].indicators.iter().any(|i| i == "NET:rare_access_count_1"));
        assert!(events[1].indicators.iter().any(|i| i == "NET:rare_access_count_9"));
    }

    /// The threshold applies in the curated cut too — it was `<= 5` and in-window
    /// only, which is not what "fewer than ten" means.
    #[test]
    fn the_threshold_is_the_same_in_both_verbosities() {
        for verbosity in [Verbosity::Curated, Verbosity::Baseline] {
            let events = run_with(KSTRIKE_HEADER, &kstrike_rows(), windowed(verbosity));
            let n = events
                .iter()
                .filter(|e| e.indicators.iter().any(|i| i.starts_with("NET:rare_access_count_")))
                .count();
            assert_eq!(n, 2, "{verbosity:?}");
        }
    }

    /// A UAL row is a summary stamped with an `InsertDate`, so windowing it
    /// discards the artifact whenever the window predates collection. Every row
    /// above is outside the window and every one of them is still here.
    #[test]
    fn a_ual_row_outside_the_analysis_window_is_still_carried() {
        let events = run_with(KSTRIKE_HEADER, &kstrike_rows(), windowed(Verbosity::Curated));
        assert_eq!(events.len(), 4);
        assert!(events.iter().all(|e| !cfg_in_window(&e.timestamp)));

        fn cfg_in_window(ts: &str) -> bool {
            windowed(Verbosity::Curated).in_timewindow(ts)
        }
    }

    /// Rarity, not severity, is what carries these into the curated timeline —
    /// the operator reads that file.
    #[test]
    fn a_rare_row_reaches_the_triage_cut_and_a_busy_one_does_not() {
        let events = run_with(KSTRIKE_HEADER, &kstrike_rows(), windowed(Verbosity::Curated));
        assert!(is_triage_hit(&events[0]), "1 access: {:?}", events[0].indicators);
        assert!(is_triage_hit(&events[1]), "9 accesses: {:?}", events[1].indicators);
        assert!(!is_triage_hit(&events[2]), "10 accesses is ordinary");
        assert!(!is_triage_hit(&events[3]), "4,883 accesses is the role doing its job");
    }

    /// The baseline rows are for the supertimeline, not the report.
    #[test]
    fn a_row_no_rule_fired_on_is_a_baseline_record_below_the_cut() {
        let events = run_with(KSTRIKE_HEADER, &kstrike_rows(), windowed(Verbosity::Curated));
        assert_eq!(events[3].severity, "info");
        assert!(events[3].indicators.iter().any(|i| i == "NET:ual_record"));
        assert!(!is_triage_hit(&events[3]));
    }

    #[test]
    fn the_baseline_can_be_switched_off_without_losing_the_rare_rows() {
        let cfg = PipelineConfig { emit_quiet_baseline: false, ..windowed(Verbosity::Curated) };
        let events = run_with(KSTRIKE_HEADER, &kstrike_rows(), cfg);
        assert_eq!(events.len(), 2, "only the two rare rows survive");
        assert!(events.iter().all(|e| e.indicators.iter().any(|i| i.contains("rare_access_count"))));
    }

    /// The bug that made this dangerous: `TotalAccesses` resolved by position, or
    /// defaulted to `0`, gives every row of a file a confident "rare access count
    /// of zero" at medium severity.
    #[test]
    fn an_unreadable_access_count_never_becomes_a_confident_zero() {
        let header = "datetime,timestamp_desc,message,AuthenticatedUserName,\
            ConvertedAddress (Correlated_HostName(s)),RoleGuid (RoleName)";
        let body = "2026-09-09T07:51:12.973Z,d,m,testuser,172.16.0.21 ('MY-APP02'),\
            {00000000-0000-0000-0000-000000000001} (Active Directory Domain Services)\n";
        let events = run_with(header, body, PipelineConfig::default());
        assert_eq!(events.len(), 1, "the row is still carried as a baseline record");
        assert!(
            !events[0].indicators.iter().any(|i| i.contains("rare_access_count")),
            "an absent count is unknown, not zero: {:?}",
            events[0].indicators
        );
        assert!(events[0].description.contains("Accesses: unknown"));
        assert_eq!(events[0].severity, "info");

        // Same for a cell that is present but unparseable.
        let events = run_with(
            KSTRIKE_HEADER,
            "2026-09-09T07:51:12.973Z,d,m,testuser,172.16.0.21 ('MY-APP02'),n/a,\
             {0} (Active Directory Domain Services),,172.16.0.21,MY-WEB01,network,1\n",
            PipelineConfig::default(),
        );
        assert!(!events[0].indicators.iter().any(|i| i.contains("rare_access_count")));
    }

    /// An anonymous caller authenticating to a server role is a finding on its own.
    #[test]
    fn an_anonymous_logon_to_a_server_role_is_high_severity() {
        let events = run_with(
            KSTRIKE_HEADER,
            "2026-09-09T09:35:47.159Z,d,m,\"nt authority\\anonymous logon\",\
             172.16.0.30 ('MY-APP06'),4883,{0} (Active Directory Domain Services),\
             2026-09-09: 4883,172.16.0.30,MY-WEB01,network,1\n",
            PipelineConfig::default(),
        );
        assert_eq!(events[0].severity, "high");
        assert!(events[0].indicators.iter().any(|i| i == "NET:anonymous_logon_ual"));
        assert!(is_triage_hit(&events[0]), "high severity reaches the cut");
    }

    /// The kstrike cell holds two facts. Both have to come out: the report's IP
    /// table reads the address out of the description and its hostname table
    /// reads the peer name.
    #[test]
    fn the_address_cell_yields_both_the_address_and_the_peer_name() {
        assert_eq!(
            split_address("172.16.0.21 ('MY-APP02')"),
            ("172.16.0.21".to_string(), vec!["MY-APP02".to_string()])
        );
        assert_eq!(
            split_address("172.16.0.21 ('MY-APP02', 'MY-APP03')"),
            ("172.16.0.21".to_string(), vec!["MY-APP02".to_string(), "MY-APP03".to_string()])
        );
        // SumECmd's bare address, and the machine's own access.
        assert_eq!(split_address("172.16.0.21"), ("172.16.0.21".to_string(), vec![]));
        assert_eq!(split_address("Local Host ::1"), ("::1".to_string(), vec![]));
        assert_eq!(split_address(""), (String::new(), vec![]));

        let events = run_with(KSTRIKE_HEADER, &kstrike_rows(), PipelineConfig::default());
        assert!(events[0].description.contains("IP: 172.16.0.21"));
        assert!(events[0].description.contains("Peer: MY-APP02"));
    }

    #[test]
    fn the_raw_address_is_used_when_the_converted_one_is_empty() {
        let events = run_with(
            KSTRIKE_HEADER,
            "2026-09-09T07:51:12.973Z,d,m,testuser,,3,{0} (File Server),2026-09-09: 3,\
             172.16.0.99,MY-WEB01,network,1\n",
            PipelineConfig::default(),
        );
        assert!(events[0].description.contains("IP: 172.16.0.99"), "{}", events[0].description);
    }

    /// The role GUID identifies the role in every collection; the name is what a
    /// reader needs.
    #[test]
    fn the_role_name_is_read_out_of_either_spelling() {
        assert_eq!(
            role_name("{00000000-0000-0000-0000-000000000001} (Active Directory Domain Services)"),
            "Active Directory Domain Services"
        );
        assert_eq!(role_name("File Server"), "File Server");
        assert_eq!(role_name(""), "");
    }

    /// Both parses of the same database must produce the same findings.
    #[test]
    fn the_two_ual_parses_agree_on_what_is_rare() {
        let kstrike = run_with(KSTRIKE_HEADER, &kstrike_rows(), PipelineConfig::default());
        let sum = run_with(
            SUM_HEADER,
            "2026-09-09T07:51:12.973Z,Active Directory Domain Services,1,testuser,172.16.0.21\n\
             2026-09-09T07:51:13.973Z,Active Directory Domain Services,9,svcweb,172.16.0.22\n\
             2026-09-09T07:51:14.973Z,Active Directory Domain Services,10,svcbackup,172.16.0.23\n\
             2026-09-09T07:51:15.973Z,Active Directory Domain Services,4883,my-app05$,172.16.0.24\n",
            PipelineConfig::default(),
        );
        let rare = |evs: &[UnifiedEvent]| -> Vec<String> {
            evs.iter()
                .flat_map(|e| e.indicators.iter())
                .filter(|i| i.starts_with("NET:rare_access_count_"))
                .cloned()
                .collect()
        };
        assert_eq!(rare(&kstrike), rare(&sum));
        assert_eq!(kstrike.len(), sum.len());
    }

    /// The regression: every UAL access by a named human was vanishing from the
    /// report's Account Activity table, because a raw DN is rejected there.
    #[test]
    fn an_ldap_distinguished_name_resolves_to_the_person_it_names() {
        assert_eq!(
            normalise_ual_user("cn=test user,ou=users,ou=site,ou=org,dc=domain,dc=local"),
            "test user"
        );
        assert_eq!(normalise_ual_user("CN=Test User,OU=Staff,DC=domain"), "Test User");
        // Everything that is not a DN is left exactly as it was.
        assert_eq!(normalise_ual_user("testuser"), "testuser");
        assert_eq!(normalise_ual_user(r"domain\my-web01$"), r"domain\my-web01$");
        assert_eq!(normalise_ual_user(""), "");
        // A DN with no CN is not invented into one.
        assert_eq!(normalise_ual_user("ou=users,dc=domain"), "ou=users,dc=domain");
    }

    #[test]
    fn the_resolved_name_reaches_the_event() {
        let events = run_with(
            SUM_HEADER,
            "2026-05-05T10:00:00Z,Active Directory Domain Services,4,\
             \"cn=test user,ou=users,dc=domain,dc=local\",172.16.0.21\n",
            PipelineConfig::default(),
        );
        assert_eq!(events[0].user, "test user");
        assert!(events[0].description.contains("test user"));
    }

    /// The per-day breakdown is the reason UAL is worth reading, but a client
    /// with a year of retention must not put five kilobytes in a description.
    #[test]
    fn the_per_day_breakdown_is_carried_but_bounded() {
        let long: String =
            (1..=20).map(|d| format!("2026-09-{d:02}: 12, ")).collect::<Vec<_>>().concat();
        let events = run_with(
            KSTRIKE_HEADER,
            &format!(
                "2026-09-09T07:51:12.973Z,d,m,testuser,172.16.0.21 ('MY-APP02'),240,\
                 {{0}} (File Server),\"{long}\",172.16.0.21,MY-WEB01,network,1\n"
            ),
            PipelineConfig::default(),
        );
        assert!(events[0].description.contains("dates"), "{}", events[0].description);
        assert!(events[0].description.len() < 300);

        let events = run_with(KSTRIKE_HEADER, &kstrike_rows(), PipelineConfig::default());
        assert!(events[0].description.contains("Days: 2026-09-09: 1"));
    }
}
