//! Header resolution for the Wiskess `Timeline/*.csv` files.
//!
//! Every parser used to find its columns like this:
//!
//! ```ignore
//! let col = |name: &str| headers.iter().position(|h| h == name);
//! let name_idx = col("Name").unwrap_or(1);
//! ```
//!
//! Two things are wrong with it, and both are silent.
//!
//! The match is exact and case-sensitive, so when the timeliner renamed its
//! columns to snake_case (`Name` -> `file_name`, `EventId` -> `event_id`,
//! `UpdateReasons` -> `reason`) every one of those lookups stopped resolving. And
//! `unwrap_or(<index>)` then made the failure *invisible*: instead of an error,
//! the parser read whichever column happens to sit at that index — usually
//! `timestamp_desc`. The USN journal parser asked for `UpdateReasons`, got
//! `None`, matched no update reason on any row, and emitted **0 events from
//! 439,051**. The event-log parser asked for `EventId`, resolved to
//! `timestamp_desc`, parsed every event ID as `0`, and emitted **11 from
//! 840,821**. Nothing in either run said so.
//!
//! So this module does three things:
//!
//! 1. matches one way — trimmed and case-insensitive, ignoring `_`, `-` and
//!    spaces — which collapses the three conventions that had grown up across
//!    the parsers and resolves `file_name`/`FileName` with no alias at all;
//! 2. **never falls back to a positional index.** An unresolved column reads as
//!    empty, which is wrong in a way that is visible, rather than wrong in a way
//!    that looks like data;
//! 3. records every failure so the run can say what it could not read. A parser
//!    that returns nothing must not be indistinguishable from an artifact that
//!    contained nothing.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

/// One logical column, and the header spellings that mean it.
///
/// Aliases are tried in order, so put the current spelling first. Matching is
/// insensitive to case, surrounding space, `_` and `-`, so a snake_case rename of
/// an existing alias needs no new entry.
#[derive(Clone, Copy, Debug)]
pub struct Field {
    pub logical: &'static str,
    pub aliases: &'static [&'static str],
    /// A required column that does not resolve is a coverage failure: the parser
    /// cannot do its job and the report has to say so.
    pub required: bool,
}

impl Field {
    pub const fn required(logical: &'static str, aliases: &'static [&'static str]) -> Self {
        Self { logical, aliases, required: true }
    }

    pub const fn optional(logical: &'static str, aliases: &'static [&'static str]) -> Self {
        Self { logical, aliases, required: false }
    }

    /// The same column, not required here.
    ///
    /// For artifacts that accept either of two shapes: `MFTECmd.csv` names the
    /// file in `FileName` + `ParentPath`, `mft_dump.csv` only in `FullPath`, so
    /// neither is required *on its own* — the parser declares a combined required
    /// field for "something that names the file" and reads these two optionally.
    pub const fn optional_form(self) -> Self {
        Self { logical: self.logical, aliases: self.aliases, required: false }
    }
}

/// Fold a header or alias to its comparison key.
///
/// `"  File Name "`, `"file_name"`, `"FileName"` and `"file-name"` all fold to
/// `filename`. This is what makes the snake_case migration a non-event.
fn key(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '_' | '-' | ' ' | '\t'))
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// What a parser could not read, and what that costs.
#[derive(Clone, Debug)]
pub struct ColumnFailure {
    pub artifact: String,
    pub file: String,
    pub logical: String,
    pub aliases: Vec<String>,
    pub header: Vec<String>,
}

impl ColumnFailure {
    pub fn describe(&self) -> String {
        format!(
            "{}: required column `{}` (tried {}) is not in {}",
            self.artifact,
            self.logical,
            self.aliases.join(", "),
            self.file
        )
    }
}

/// Resolved header for one file.
///
/// Holds no record of what was *missing*: a failure to resolve a required column
/// is reported once, run-wide, by [`record_failure`], so the report can state it
/// without every parser having to remember to ask.
pub struct Columns {
    file: String,
    idx: HashMap<&'static str, usize>,
}

impl Columns {
    /// Resolve `fields` against `headers`, reporting anything required that is
    /// missing — immediately on stderr, and into the run-wide record that the
    /// report reads.
    pub fn resolve(
        artifact: &'static str,
        file: &Path,
        headers: &csv::StringRecord,
        fields: &[Field],
    ) -> Self {
        let observed: Vec<(String, usize)> = headers
            .iter()
            .enumerate()
            .map(|(i, h)| (key(h), i))
            .collect();

        let filename = file
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<unnamed>")
            .to_string();

        let mut idx = HashMap::new();

        for field in fields {
            let found = field.aliases.iter().find_map(|alias| {
                let want = key(alias);
                observed.iter().find(|(h, _)| *h == want).map(|(_, i)| *i)
            });
            match found {
                Some(i) => {
                    idx.insert(field.logical, i);
                }
                None if field.required => {
                    let failure = ColumnFailure {
                        artifact: artifact.to_string(),
                        file: filename.clone(),
                        logical: field.logical.to_string(),
                        aliases: field.aliases.iter().map(|s| s.to_string()).collect(),
                        header: headers.iter().map(|h| h.to_string()).collect(),
                    };
                    eprintln!(
                        "[!] {}: required column `{}` not found in {} (tried: {})",
                        artifact,
                        field.logical,
                        filename,
                        field.aliases.join(", ")
                    );
                    eprintln!(
                        "[!]   header is [{}]",
                        failure.header.join(", ")
                    );
                    eprintln!(
                        "[!]   -> this artifact will lose events it should have kept. COVERAGE FAILURE."
                    );
                    record_failure(failure);
                }
                None => {}
            }
        }

        Self { file: filename, idx }
    }

    /// The value of `logical` in this record, or `""` when the column did not
    /// resolve. Deliberately not `Option`: callers that treated a missing column
    /// as position 0 are what this module exists to remove, and an empty string
    /// fails detection rather than matching the wrong thing.
    ///
    /// Trims control characters as well as space. kstrike reads UAL's
    /// `AuthenticatedUserName` out of a fixed-width wide-char field and keeps the
    /// terminator, so every one of its rows arrives as `domain\user\0`. That is a
    /// different string from `domain\user`: the two would be two accounts in the
    /// report's account table, two keys in any downstream aggregation, and one
    /// `NUL` is enough to make `grep` call the markdown report a binary file and
    /// print nothing. Measured on one export: 37 of 48 UAL rows.
    ///
    /// A subslice trim, so this stays allocation-free on the MFT's millions of
    /// rows. It therefore fixes a terminator, not a control character in the
    /// middle of a cell — that has not been observed, and fixing it would mean
    /// allocating on every read.
    pub fn get<'r>(&self, record: &'r csv::StringRecord, logical: &str) -> &'r str {
        self.idx
            .get(logical)
            .and_then(|i| record.get(*i))
            .unwrap_or("")
            .trim_matches(|c: char| c.is_whitespace() || c.is_control())
    }

    /// Lowercased convenience form, for extensions and reason strings.
    pub fn get_lower(&self, record: &csv::StringRecord, logical: &str) -> String {
        self.get(record, logical).to_lowercase()
    }

    /// Did this column resolve at all?
    ///
    /// **Never a positional fallback.** A caller that must distinguish "column
    /// absent" from "column empty" — a parsed access count, say, where a missing
    /// column read as `0` would invent a confident finding — asks this first.
    pub fn has(&self, logical: &str) -> bool {
        self.idx.contains_key(logical)
    }

    pub fn file(&self) -> &str {
        &self.file
    }
}

// ---------------------------------------------------------------------------
// Run-wide coverage record.
//
// A `Mutex` static rather than a parameter threaded through every parser: the
// parsers run under `rayon::join`, and the alternative is changing the signature
// of a dozen functions to carry a reporting channel none of them care about.
// ---------------------------------------------------------------------------

static FAILURES: Mutex<Vec<ColumnFailure>> = Mutex::new(Vec::new());
static ROWS_READ: Mutex<Vec<(String, usize)>> = Mutex::new(Vec::new());

fn record_failure(f: ColumnFailure) {
    if let Ok(mut guard) = FAILURES.lock() {
        guard.push(f);
    }
}

/// Record how many data rows an artifact's file actually held.
///
/// This is the other half of the coverage assertion: `rows_read > 0` with zero
/// events emitted is the shape of every bug in this module's doc comment.
pub fn note_rows(artifact: &str, rows: usize) {
    if let Ok(mut guard) = ROWS_READ.lock() {
        guard.push((artifact.to_string(), rows));
    }
}

/// Every column failure recorded so far.
pub fn failures() -> Vec<ColumnFailure> {
    FAILURES.lock().map(|g| g.clone()).unwrap_or_default()
}

/// Rows read per artifact, summed across files.
pub fn rows_read() -> HashMap<String, usize> {
    let mut out: HashMap<String, usize> = HashMap::new();
    if let Ok(guard) = ROWS_READ.lock() {
        for (artifact, n) in guard.iter() {
            *out.entry(artifact.clone()).or_insert(0) += n;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Shared field definitions.
//
// One place for the spellings, because the same column appears in several files
// and a rename should be a one-line change here rather than a hunt.
// ---------------------------------------------------------------------------

/// The timeliner stamps every normalised row with this.
///
/// Note what is **not** an alias: `timestamp`. In this schema that column is
/// epoch milliseconds, so accepting it here would reintroduce exactly the
/// wrong-column bug this module removes — silently, and on every artifact.
pub const DATETIME: Field = Field::required("datetime", &["datetime", "Timestamp_UTC", "TimeCreated"]);
pub const TIMESTAMP_DESC: Field = Field::optional("timestamp_desc", &["timestamp_desc"]);
pub const MESSAGE: Field = Field::optional("message", &["message"]);
pub const USER_NAME: Field = Field::optional("user_name", &["user_name", "UserName", "user"]);

/// `Name` is the legacy spelling and stays last: `file_name` and `FileName` fold
/// to the same key, so the alias list documents what has been observed rather
/// than doing work.
pub const FILE_NAME: Field = Field::required("file_name", &["file_name", "FileName", "Name"]);
pub const EXTENSION: Field = Field::optional("extension", &["Extension", "FileExtension"]);
pub const PARENT_PATH: Field = Field::optional("parent_path", &["ParentPath"]);
/// A path already joined by the source tool. `full_name` is the rusty USN
/// parse's derived path — the column that makes that file the better of the two.
pub const FULL_PATH: Field =
    Field::optional("full_path", &["full_name", "FullPath", "FullName", "AbsolutePath"]);
pub const FILE_SIZE: Field = Field::optional("file_size", &["FileSize", "file_size"]);
/// The USN update reasons. `reason` is the current spelling in both parses;
/// `UpdateReasons` is what this code asked for and no current file provides,
/// which is how 439,051 rows became zero events.
pub const REASON: Field =
    Field::required("reason", &["reason", "UpdateReasons", "UpdateReason", "Reasons"]);
/// The $MFT entry number: the file's identity on the volume, and what separates
/// two same-second records of two different files that share a name.
pub const ENTRY_NUMBER: Field = Field::optional("entry_number", &["EntryNumber"]);
pub const EVENT_ID: Field = Field::required("event_id", &["event_id", "EventId", "EventID"]);

// ── User Access Logging (network.csv / network-kstrike.csv) ──────────────────
//
// Two tools parse the same UAL database and agree on nothing. SumECmd's
// `network.csv` has `IpAddress`, `RoleDescription`, a plain user name; kstrike's
// `network-kstrike.csv` folds the correlated peer name into the address header
// and the role name into the GUID header. Both spellings live here so the parser
// reads one shape.

/// The account that authenticated to the role. Arrives plain, as `DOMAIN\name`,
/// or as a full LDAP distinguished name — see `network::normalise_ual_user`.
pub const AUTH_USER: Field =
    Field::optional("auth_user", &["AuthenticatedUserName", "user_name", "UserName"]);
/// The client address. The kstrike spelling carries the correlated peer hostname
/// in the same cell (`<ip> ('<HOSTNAME>')`), which `network::split_address` splits.
pub const UAL_ADDRESS: Field = Field::optional(
    "address",
    &["ConvertedAddress (Correlated_HostName(s))", "IpAddress", "ConvertedAddress"],
);
/// kstrike's unconverted address, used when the converted cell is empty.
pub const UAL_RAW_ADDRESS: Field = Field::optional("raw_address", &["RawAddress"]);
pub const UAL_ROLE: Field =
    Field::optional("role", &["RoleDescription", "RoleGuid (RoleName)", "RoleName"]);
/// Accesses by this client to this role over the record. **Optional on purpose**:
/// a missing count must read as unknown, not as `0` — `unwrap_or(0)` here would
/// label all 48 rows of a kstrike file "rare access count 0".
pub const TOTAL_ACCESSES: Field = Field::optional("total_accesses", &["TotalAccesses"]);
/// The per-day access breakdown, `YYYY-MM-DD: <n>, …`. The reason UAL is worth
/// reading at all: it says *which* days a peer touched the role.
pub const DATES_AND_ACCESSES: Field =
    Field::optional("dates_and_accesses", &["DatesAndAccesses", "DaysAccessed"]);

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(cols: &[&str]) -> csv::StringRecord {
        csv::StringRecord::from(cols.to_vec())
    }

    fn row(cells: &[&str]) -> csv::StringRecord {
        csv::StringRecord::from(cells.to_vec())
    }

    const NAME: Field = Field::required("file_name", &["file_name", "FileName", "Name"]);
    const EXT: Field = Field::optional("extension", &["Extension"]);

    /// Just the failures one test's own resolution recorded.
    ///
    /// The run-wide record is append-only and these tests share a process, so each
    /// resolves under its own artifact name instead of clearing the record and
    /// racing every other parser's resolutions — the convention `mft.rs` follows.
    fn failures_for(artifact: &str) -> Vec<ColumnFailure> {
        failures().into_iter().filter(|f| f.artifact == artifact).collect()
    }

    /// Assertions are on the **value read**, not on an index: an index is an
    /// implementation detail, and reading the wrong cell is the bug.
    #[test]
    fn a_snake_case_rename_of_a_pascal_case_alias_needs_no_new_alias() {
        let r = row(&["2026-01-01T00:00:00Z", "mft - t.csv: Created", "payload.dll", ".dll"]);

        // The exact drift that cost 439,051 rows.
        let h = headers(&["datetime", "timestamp_desc", "file_name", "Extension"]);
        let c = Columns::resolve("resolve-snake", Path::new("t.csv"), &h, &[DATETIME, NAME, EXT]);
        assert_eq!(c.get(&r, "file_name"), "payload.dll");
        assert!(failures_for("resolve-snake").is_empty());

        // ...and the legacy spelling still resolves, from the same table.
        let h = headers(&["datetime", "timestamp_desc", "Name", "Extension"]);
        let c = Columns::resolve("resolve-pascal", Path::new("t.csv"), &h, &[DATETIME, NAME, EXT]);
        assert_eq!(c.get(&r, "file_name"), "payload.dll");
        assert!(failures_for("resolve-pascal").is_empty());
    }

    #[test]
    fn matching_ignores_case_space_and_separators() {
        let h = headers(&["  DateTime ", "FILE-NAME"]);
        let c = Columns::resolve("resolve-folding", Path::new("t.csv"), &h, &[DATETIME, NAME]);
        let r = row(&["2026-01-01T00:00:00Z", "payload.dll"]);
        assert_eq!(c.get(&r, "datetime"), "2026-01-01T00:00:00Z");
        assert_eq!(c.get(&r, "file_name"), "payload.dll");
    }

    #[test]
    fn aliases_are_tried_in_declared_order() {
        let h = headers(&["Name", "file_name"]);
        let c = Columns::resolve("resolve-order", Path::new("t.csv"), &h, &[NAME]);
        let r = row(&["from-Name", "from-file_name"]);
        assert_eq!(c.get(&r, "file_name"), "from-file_name", "the first alias declared wins");
    }

    /// The core of it: no index is ever guessed.
    #[test]
    fn an_unresolved_column_reads_empty_and_never_falls_back_to_a_position() {
        let h = headers(&["datetime", "timestamp_desc", "something_else"]);
        let c = Columns::resolve("resolve-missing", Path::new("t.csv"), &h, &[DATETIME, NAME]);
        assert!(!c.has("file_name"));

        let r = row(&["2026-01-01T00:00:00Z", "mft - t.csv: Created", "junk"]);
        assert_eq!(c.get(&r, "file_name"), "", "not `timestamp_desc`, which is what index 1 held");

        let f = failures_for("resolve-missing");
        assert_eq!(f.len(), 1, "recorded once: {:?}", f);
        assert_eq!(f[0].logical, "file_name");
        assert!(f[0].describe().contains("t.csv"));
    }

    /// `timestamp` is epoch millis in this schema. Accepting it as `datetime`
    /// would be the same class of bug, so it must not resolve.
    #[test]
    fn the_epoch_millis_column_is_not_accepted_as_the_iso_one() {
        let h = headers(&["timestamp", "message"]);
        let c = Columns::resolve("resolve-epoch", Path::new("t.csv"), &h, &[DATETIME]);
        assert!(!c.has("datetime"), "`timestamp` must not satisfy `datetime`");
        let r = row(&["1767225845000", "m"]);
        assert_eq!(c.get(&r, "datetime"), "", "and it must not be read as one either");
        assert_eq!(
            failures_for("resolve-epoch").len(),
            1,
            "an unresolved required column is a reported coverage failure"
        );
    }

    #[test]
    fn an_optional_column_that_is_missing_is_not_a_failure() {
        let h = headers(&["datetime", "file_name"]);
        let c = Columns::resolve("resolve-optional", Path::new("t.csv"), &h, &[DATETIME, NAME, EXT]);
        assert!(c.has("datetime") && c.has("file_name"));
        assert!(!c.has("extension"));
        assert!(failures_for("resolve-optional").is_empty());
    }

    /// kstrike keeps UAL's wide-char terminator, so the account name arrives with
    /// a trailing `NUL`. Untrimmed it is a second, near-invisible spelling of the
    /// same account, and one of them in the markdown report is enough to make
    /// `grep` treat the whole file as binary.
    #[test]
    fn a_wide_char_terminator_is_not_part_of_the_value() {
        let h = headers(&["datetime", "AuthenticatedUserName"]);
        let c = Columns::resolve("resolve-nul", Path::new("t.csv"), &h, &[DATETIME, AUTH_USER]);
        let r = row(&["2026-01-01T00:00:00Z", "domain.local\\testuser\u{0}"]);
        assert_eq!(c.get(&r, "auth_user"), "domain.local\\testuser");
        assert!(
            !c.get(&r, "auth_user").chars().any(char::is_control),
            "no control character reaches an event field, or the CSV and the md carry it"
        );
    }

    #[test]
    fn the_resolved_file_is_named_for_the_coverage_table() {
        let h = headers(&["datetime"]);
        let c = Columns::resolve("resolve-file", Path::new("/tmp/dir/network-kstrike.csv"), &h, &[DATETIME]);
        assert_eq!(c.file(), "network-kstrike.csv");
    }
}
