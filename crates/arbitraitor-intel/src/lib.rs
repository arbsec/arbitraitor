//! Threat intelligence feed management.
//!
//! See `.spec/` for the full specification.
//!
//! Feed retrieval is delegated to [`arbitraitor_fetch::Fetcher`]; no reqwest
//! types cross this crate boundary (see ADR 0003).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod feed;
pub mod urlhaus;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use arbitraitor_model::verdict::{Confidence, Severity};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

pub use feed::{FeedAdapter, IngestionReport, ingest_entries, ingest_feed};
pub use urlhaus::UrlhausAdapter;

/// Current threat-intelligence feed entry schema version.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Type of observable represented by an intelligence indicator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndicatorType {
    /// SHA-256 content digest.
    Sha256,
    /// Exact URL as observed.
    ExactUrl,
    /// Canonicalized URL after normalization.
    NormalizedUrl,
    /// URL prefix that matches a family of URLs.
    UrlPrefix,
    /// Hostname indicator.
    Hostname,
    /// Registrable domain indicator.
    RegistrableDomain,
    /// Single IP address indicator.
    IpAddress,
    /// CIDR range indicator.
    CidrRange,
    /// TLS certificate fingerprint indicator.
    TlsCertFingerprint,
    /// Ecosystem package coordinate indicator.
    PackageCoordinate,
    /// Software signer identity indicator.
    SignerIdentity,
    /// Signing key fingerprint indicator.
    SigningKeyFingerprint,
    /// YARA rule indicator.
    YaraRule,
    /// Campaign label indicator.
    Campaign,
}

/// Intelligence indicator value paired with its type.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Indicator {
    /// Indicator type.
    pub indicator_type: IndicatorType,
    /// Indicator value in the canonical form for the indicator type.
    pub value: String,
}

/// Classification assigned to an indicator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Classification {
    /// Indicator is known or believed malicious.
    Malicious,
    /// Indicator is suspicious but not confirmed malicious.
    Suspicious,
    /// Indicator is known or believed benign.
    Benign,
    /// Indicator classification is unknown.
    Unknown,
}

/// Suggested policy handling for an indicator match.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    /// Block matching artifacts or operations.
    Block,
    /// Warn on matching artifacts or operations.
    Warn,
    /// Record an informational match only.
    Informational,
    /// Explicitly allow matching artifacts or operations.
    Allow,
}

/// Source attached to a feed entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedSource {
    /// Source type label, such as vendor, osint, internal, or analyst.
    pub source_type: String,
    /// Source reference safe to store locally.
    pub reference: String,
}

/// Evidence attached to a feed entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedEvidence {
    /// Malware family associated with the indicator, when known.
    pub malware_family: Option<String>,
    /// Analyst or feed notes associated with the indicator.
    pub notes: Option<String>,
}

/// Review state for a feed entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReviewState {
    /// Entry has been reviewed.
    Reviewed,
    /// Entry has not been reviewed.
    Unreviewed,
    /// Entry review is disputed.
    Disputed,
}

/// Review metadata for a feed entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewStatus {
    /// Current review state.
    pub status: ReviewState,
    /// Reviewers that have inspected this entry.
    pub reviewers: Vec<String>,
}

/// Signed intelligence feed entry.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedEntry {
    /// Feed entry schema version. Currently [`CURRENT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Stable feed entry identifier.
    pub id: String,
    /// Indicator described by this feed entry.
    pub indicator: Indicator,
    /// Classification assigned by the feed.
    pub classification: Classification,
    /// Severity assigned to matching this indicator.
    pub severity: Severity,
    /// Confidence assigned to this feed entry.
    pub confidence: Confidence,
    /// Suggested disposition for matches.
    pub disposition: Disposition,
    /// Trust class of the feed source for policy enforcement.
    pub source_class: FeedSourceClass,
    /// First observed timestamp as an RFC 3339 string.
    pub first_seen: String,
    /// Last observed timestamp as an RFC 3339 string.
    pub last_seen: String,
    /// Expiration timestamp as an RFC 3339 string, when the entry expires.
    pub expires_at: Option<String>,
    /// Sources supporting this entry.
    pub sources: Vec<FeedSource>,
    /// Evidence supporting this entry.
    pub evidence: FeedEvidence,
    /// Review metadata for this entry.
    pub review: ReviewStatus,
}

/// Indicator match result with its policy specificity class.
#[derive(Clone, Debug, PartialEq)]
pub struct MatchResult {
    /// Feed entry that matched the queried indicator.
    pub entry: FeedEntry,
    /// Specificity bucket for the matching indicator relationship.
    pub specificity: MatchSpecificity,
}

/// Policy specificity bucket for an indicator match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchSpecificity {
    /// SHA-256 content digest match.
    Exact,
    /// Exact URL or package coordinate match.
    Precise,
    /// Signer identity or URL prefix match.
    Moderate,
    /// Hostname, registrable domain, IP address, or CIDR match.
    Broad,
}

/// Source-class policy evaluation result for matched intelligence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnforcementResult {
    /// Enforcement disposition selected by the policy table.
    pub disposition: Disposition,
    /// Finding severity selected by the policy table.
    pub severity: Severity,
    /// Confidence selected by the policy table.
    pub confidence: Confidence,
    /// Source class responsible for the decision.
    pub deciding_source_class: FeedSourceClass,
}

impl FeedEntry {
    /// Returns true when the entry is expired at the supplied RFC 3339 timestamp.
    #[must_use]
    pub fn is_expired_at(&self, timestamp: &str) -> bool {
        self.expires_at
            .as_deref()
            .is_some_and(|expires_at| expires_at <= timestamp)
    }
}

/// Detached feed entry signature metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedSignature {
    /// Signature algorithm label.
    pub algorithm: String,
    /// Signing key identifier.
    pub key_id: String,
    /// Detached signature bytes.
    pub signature_bytes: Vec<u8>,
}

/// Feed entry with detached signature metadata.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedFeedEntry {
    /// Signed feed entry payload.
    pub entry: FeedEntry,
    /// Detached signature over the canonical entry payload.
    pub signature: FeedSignature,
}

/// Feed source trust class used during reputation policy evaluation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FeedSourceClass {
    /// Enterprise-controlled deny list.
    EnterpriseDeny,
    /// Entry reviewed by Arbitraitor maintainers or delegated reviewers.
    ArbitraitorReviewed,
    /// Authoritative source for this indicator class.
    Authoritative,
    /// Community source corroborated by another independent signal.
    CorroboratedCommunity,
    /// Single unreviewed source.
    SingleUnreviewed,
}

/// Local threat-intelligence store backed by a JSON file.
#[derive(Clone, Debug)]
pub struct IntelStore {
    path: PathBuf,
    entries: Vec<FeedEntry>,
}

impl IntelStore {
    /// Open a local JSON-backed intelligence store, creating an empty in-memory index when absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the store file cannot be read or decoded.
    pub fn open(path: &Path) -> Result<Self> {
        let entries = match fs::read_to_string(path) {
            Ok(contents) if contents.trim().is_empty() => Vec::new(),
            Ok(contents) => serde_json::from_str(&contents).map_err(IntelError::Decode)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(IntelError::Io(error)),
        };

        Ok(Self {
            path: path.to_path_buf(),
            entries,
        })
    }

    /// Add or replace a feed entry and persist the store.
    ///
    /// Entries are keyed by stable entry identifier. A later entry with the same
    /// identifier replaces the prior record.
    ///
    /// # Errors
    ///
    /// Returns an error if the updated store cannot be encoded or written.
    pub fn add_entry(&mut self, entry: FeedEntry) -> Result<()> {
        if let Some(existing) = self.entries.iter_mut().find(|stored| stored.id == entry.id) {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
        self.persist()
    }

    /// Merge many entries by identifier, persisting once.
    ///
    /// Returns `(entries_added, entries_updated)` where an entry is "updated"
    /// when its identifier already existed and "added" otherwise. Existing
    /// entries are replaced in place; new entries are appended in input order.
    ///
    /// This performs a single [`IntelStore::persist`] regardless of entry count
    /// so that bulk feed ingestion does not rewrite the store file once per
    /// row. The identifier lookup is linear per row to match [`IntelStore::add_entry`];
    /// a future index may speed up large feeds.
    ///
    /// # Errors
    ///
    /// Returns an error if the updated store cannot be encoded or written.
    pub fn merge_entries(&mut self, entries: Vec<FeedEntry>) -> Result<(usize, usize)> {
        let mut added = 0_usize;
        let mut updated = 0_usize;
        for entry in entries {
            if let Some(existing) = self.entries.iter_mut().find(|stored| stored.id == entry.id) {
                *existing = entry;
                updated += 1;
            } else {
                self.entries.push(entry);
                added += 1;
            }
        }
        self.persist()?;
        Ok((added, updated))
    }

    /// Query entries matching an indicator by exact indicator type and value.
    #[must_use]
    pub fn query(&self, indicator: &Indicator) -> Vec<&FeedEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.indicator == *indicator)
            .collect()
    }

    /// Purge expired entries using the current system UTC timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be persisted after purging.
    pub fn purge_expired(&mut self) -> Result<usize> {
        let now = current_utc_timestamp();
        let before = self.entries.len();
        self.entries.retain(|entry| !entry.is_expired_at(&now));
        let purged = before - self.entries.len();
        if purged > 0 {
            self.persist()?;
        }
        Ok(purged)
    }

    /// Return all stored entries in insertion order.
    #[must_use]
    pub fn entries(&self) -> &[FeedEntry] {
        &self.entries
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(IntelError::Io)?;
        }
        let json = serde_json::to_string_pretty(&self.entries).map_err(IntelError::Encode)?;
        fs::write(&self.path, json).map_err(IntelError::Io)
    }
}

/// Match a queried indicator against live intelligence entries.
///
/// Results are sorted by the specification ordering: exact hash, exact URL,
/// package coordinate, signer identity, URL prefix, hostname, domain, then IP/CIDR.
#[must_use]
pub fn match_indicator(store: &IntelStore, indicator: &Indicator) -> Vec<MatchResult> {
    let now = current_utc_timestamp();
    let mut matches: Vec<(u8, MatchResult)> = store
        .entries()
        .iter()
        .filter(|entry| !entry.is_expired_at(&now))
        .filter_map(|entry| match_rank(entry, indicator).map(|rank| (rank, entry)))
        .map(|(rank, entry)| {
            (
                rank,
                MatchResult {
                    entry: entry.clone(),
                    specificity: specificity_for_rank(rank),
                },
            )
        })
        .collect();

    matches.sort_by_key(|(rank, result)| (*rank, result.entry.id.clone()));
    matches.into_iter().map(|(_rank, result)| result).collect()
}

/// Evaluate matched indicators using the default source-class enforcement table.
#[must_use]
pub fn evaluate_matches(matches: &[MatchResult]) -> Option<EnforcementResult> {
    matches
        .iter()
        .map(|matched| enforcement_for_source_class(matched.entry.source_class))
        .max_by_key(|result| enforcement_precedence(result.disposition))
}

fn match_rank(entry: &FeedEntry, queried: &Indicator) -> Option<u8> {
    let stored = &entry.indicator;
    match stored.indicator_type {
        IndicatorType::Sha256 if stored == queried => Some(0),
        IndicatorType::ExactUrl | IndicatorType::NormalizedUrl
            if is_url_indicator(queried) && stored.value == queried.value =>
        {
            Some(1)
        }
        IndicatorType::PackageCoordinate if stored == queried => Some(2),
        IndicatorType::SignerIdentity if stored == queried => Some(3),
        IndicatorType::UrlPrefix
            if is_url_indicator(queried) && queried.value.starts_with(&stored.value) =>
        {
            Some(4)
        }
        IndicatorType::Hostname if host_matches_indicator(&stored.value, queried) => Some(5),
        IndicatorType::RegistrableDomain if domain_matches_indicator(&stored.value, queried) => {
            Some(6)
        }
        IndicatorType::IpAddress if ip_matches_indicator(&stored.value, queried) => Some(7),
        IndicatorType::CidrRange if cidr_matches_indicator(&stored.value, queried) => Some(7),
        _ => None,
    }
}

fn specificity_for_rank(rank: u8) -> MatchSpecificity {
    match rank {
        0 => MatchSpecificity::Exact,
        1 | 2 => MatchSpecificity::Precise,
        3 | 4 => MatchSpecificity::Moderate,
        _ => MatchSpecificity::Broad,
    }
}

fn is_url_indicator(indicator: &Indicator) -> bool {
    matches!(
        indicator.indicator_type,
        IndicatorType::ExactUrl | IndicatorType::NormalizedUrl | IndicatorType::UrlPrefix
    )
}

fn host_matches_indicator(stored_host: &str, queried: &Indicator) -> bool {
    match queried.indicator_type {
        IndicatorType::Hostname => stored_host.eq_ignore_ascii_case(&queried.value),
        IndicatorType::ExactUrl | IndicatorType::NormalizedUrl | IndicatorType::UrlPrefix => {
            url_host(&queried.value).is_some_and(|host| stored_host.eq_ignore_ascii_case(&host))
        }
        _ => false,
    }
}

fn domain_matches_indicator(stored_domain: &str, queried: &Indicator) -> bool {
    let parsed_host;
    let host = match queried.indicator_type {
        IndicatorType::Hostname | IndicatorType::RegistrableDomain => queried.value.as_str(),
        IndicatorType::ExactUrl | IndicatorType::NormalizedUrl | IndicatorType::UrlPrefix => {
            parsed_host = url_host(&queried.value);
            parsed_host.as_deref().unwrap_or_default()
        }
        _ => return false,
    };
    domain_suffix_matches(host, stored_domain)
}

fn ip_matches_indicator(stored_ip: &str, queried: &Indicator) -> bool {
    queried.indicator_type == IndicatorType::IpAddress && stored_ip == queried.value
}

fn cidr_matches_indicator(stored_cidr: &str, queried: &Indicator) -> bool {
    if queried.indicator_type != IndicatorType::IpAddress {
        return false;
    }
    let Some((network, prefix)) = stored_cidr.split_once('/') else {
        return false;
    };
    let (Ok(network), Ok(address), Ok(prefix)) = (
        network.parse::<std::net::IpAddr>(),
        queried.value.parse::<std::net::IpAddr>(),
        prefix.parse::<u8>(),
    ) else {
        return false;
    };
    ip_in_prefix(network, address, prefix)
}

fn ip_in_prefix(network: std::net::IpAddr, address: std::net::IpAddr, prefix: u8) -> bool {
    match (network, address) {
        (std::net::IpAddr::V4(network), std::net::IpAddr::V4(address)) if prefix <= 32 => {
            let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
            u32::from(network) & mask == u32::from(address) & mask
        }
        (std::net::IpAddr::V6(network), std::net::IpAddr::V6(address)) if prefix <= 128 => {
            let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn url_host(value: &str) -> Option<String> {
    Url::parse(value)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
}

fn domain_suffix_matches(host: &str, domain: &str) -> bool {
    host.eq_ignore_ascii_case(domain)
        || host
            .to_ascii_lowercase()
            .ends_with(&format!(".{}", domain.to_ascii_lowercase()))
}

fn enforcement_for_source_class(source_class: FeedSourceClass) -> EnforcementResult {
    match source_class {
        FeedSourceClass::EnterpriseDeny => EnforcementResult {
            disposition: Disposition::Block,
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            deciding_source_class: source_class,
        },
        FeedSourceClass::ArbitraitorReviewed | FeedSourceClass::Authoritative => {
            EnforcementResult {
                disposition: Disposition::Block,
                severity: Severity::High,
                confidence: Confidence::High,
                deciding_source_class: source_class,
            }
        }
        FeedSourceClass::CorroboratedCommunity => EnforcementResult {
            disposition: Disposition::Warn,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            deciding_source_class: source_class,
        },
        FeedSourceClass::SingleUnreviewed => EnforcementResult {
            disposition: Disposition::Informational,
            severity: Severity::Informational,
            confidence: Confidence::Low,
            deciding_source_class: source_class,
        },
    }
}

fn enforcement_precedence(disposition: Disposition) -> u8 {
    match disposition {
        Disposition::Block => 3,
        Disposition::Warn => 2,
        Disposition::Informational => 1,
        Disposition::Allow => 0,
    }
}

/// Result type for intelligence store operations.
pub type Result<T> = std::result::Result<T, IntelError>;

/// Errors produced by intelligence feed storage and ingestion.
#[derive(Debug, Error)]
pub enum IntelError {
    /// Store file I/O failed.
    #[error("intelligence store I/O failed: {0}")]
    Io(io::Error),
    /// Store JSON decoding failed.
    #[error("intelligence store decode failed: {0}")]
    Decode(serde_json::Error),
    /// Store JSON encoding failed.
    #[error("intelligence store encode failed: {0}")]
    Encode(serde_json::Error),
    /// Feed retrieval through the [`arbitraitor_fetch::Fetcher`] trait failed.
    #[error("feed fetch failed: {0}")]
    Fetch(#[from] arbitraitor_fetch::FetchError),
    /// Feed payload could not be decoded as a known format (invalid UTF-8,
    /// malformed JSON, missing CSV header, or unrecognized structure).
    #[error("feed decode failed: {reason}")]
    FeedDecode {
        /// Safe diagnostic context naming the format and failure.
        reason: String,
    },
    /// An individual feed row could not be parsed after the payload decoded.
    #[error("feed row {row} could not be parsed: {reason}")]
    FeedRow {
        /// 1-based row number within the payload, when attributable.
        row: u64,
        /// Safe diagnostic context for the parse failure.
        reason: String,
    },
}

/// Returns the current Unix timestamp in seconds since the UTC epoch.
///
/// Failures (system clock before epoch) yield `0`, matching the behavior used
/// by [`current_utc_timestamp`].
#[must_use]
pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Returns the current UTC time as an RFC 3339 string.
#[must_use]
pub fn current_utc_timestamp() -> String {
    format_unix_timestamp(current_unix_timestamp())
}

/// Formats a Unix `seconds` value as an RFC 3339 UTC timestamp.
#[must_use]
pub fn format_unix_timestamp(seconds: u64) -> String {
    let days = seconds / 86_400;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: u64) -> (i64, u64, u64) {
    let days = i64::try_from(days_since_epoch).unwrap_or(i64::MAX) + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let adjusted_year = year + i64::from(month <= 2);
    (
        adjusted_year,
        u64::try_from(month).unwrap_or(0),
        u64::try_from(day).unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    fn sample_indicator(indicator_type: IndicatorType, value: &str) -> Indicator {
        Indicator {
            indicator_type,
            value: value.to_owned(),
        }
    }

    fn sample_entry(indicator: Indicator) -> FeedEntry {
        FeedEntry {
            schema_version: CURRENT_SCHEMA_VERSION,
            id: format!(
                "entry:{}:{}",
                indicator.indicator_type as u8, indicator.value
            ),
            indicator,
            classification: Classification::Malicious,
            severity: Severity::High,
            confidence: Confidence::Confirmed,
            disposition: Disposition::Block,
            source_class: FeedSourceClass::ArbitraitorReviewed,
            first_seen: "2026-06-01T00:00:00Z".to_owned(),
            last_seen: "2026-06-17T00:00:00Z".to_owned(),
            expires_at: None,
            sources: vec![FeedSource {
                source_type: "analyst".to_owned(),
                reference: "case-111".to_owned(),
            }],
            evidence: FeedEvidence {
                malware_family: Some("ExampleRat".to_owned()),
                notes: Some("confirmed in sandbox".to_owned()),
            },
            review: ReviewStatus {
                status: ReviewState::Reviewed,
                reviewers: vec!["analyst@example.com".to_owned()],
            },
        }
    }

    fn temp_store_path(name: &str) -> PathBuf {
        let unique = format!(
            "arbitraitor-intel-{name}-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        );
        std::env::temp_dir().join(unique)
    }

    #[test]
    fn feed_entry_round_trips_through_json() -> std::result::Result<(), Box<dyn Error>> {
        let entry = sample_entry(sample_indicator(IndicatorType::Sha256, &"ab".repeat(32)));
        let json = serde_json::to_string(&entry)?;
        let decoded: FeedEntry = serde_json::from_str(&json)?;
        assert_eq!(decoded, entry);
        Ok(())
    }

    #[test]
    fn queries_by_sha256_indicator() -> std::result::Result<(), Box<dyn Error>> {
        let path = temp_store_path("sha256");
        let indicator = sample_indicator(IndicatorType::Sha256, &"cd".repeat(32));
        let mut store = IntelStore::open(&path)?;
        store.add_entry(sample_entry(indicator.clone()))?;

        let matches = store.query(&indicator);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].indicator, indicator);
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn queries_by_url_indicator() -> std::result::Result<(), Box<dyn Error>> {
        let path = temp_store_path("url");
        let indicator = sample_indicator(IndicatorType::ExactUrl, "https://example.invalid/a.sh");
        let mut store = IntelStore::open(&path)?;
        store.add_entry(sample_entry(indicator.clone()))?;

        assert_eq!(store.query(&indicator).len(), 1);
        assert!(
            store
                .query(&sample_indicator(
                    IndicatorType::ExactUrl,
                    "https://example.invalid/other.sh"
                ))
                .is_empty()
        );
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn purges_expired_entries() -> std::result::Result<(), Box<dyn Error>> {
        let path = temp_store_path("expiry");
        let mut expired = sample_entry(sample_indicator(IndicatorType::Hostname, "bad.example"));
        expired.expires_at = Some("1970-01-01T00:00:00Z".to_owned());
        let live = sample_entry(sample_indicator(IndicatorType::Hostname, "live.example"));
        let mut store = IntelStore::open(&path)?;
        store.add_entry(expired)?;
        store.add_entry(live.clone())?;

        assert_eq!(store.purge_expired()?, 1);
        assert_eq!(store.entries(), &[live]);
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn deny_unknown_fields_rejects_extra_feed_entry_fields() {
        let json = r#"{"schema_version":1,"id":"entry-1","indicator":{"indicator_type":"sha256","value":"abababababababababababababababababababababababababababababababab"},"classification":"malicious","severity":"high","confidence":"confirmed","disposition":"block","source_class":"arbitraitor-reviewed","first_seen":"2026-06-01T00:00:00Z","last_seen":"2026-06-17T00:00:00Z","expires_at":null,"sources":[],"evidence":{"malware_family":null,"notes":null},"review":{"status":"reviewed","reviewers":[]},"extra":true}"#;
        assert!(serde_json::from_str::<FeedEntry>(json).is_err());
    }

    #[test]
    fn match_indicator_orders_exact_hash_before_hostname() -> std::result::Result<(), Box<dyn Error>>
    {
        let path = temp_store_path("specificity");
        let mut store = IntelStore::open(&path)?;
        let hash = sample_indicator(IndicatorType::Sha256, &"ef".repeat(32));
        store.add_entry(sample_entry(sample_indicator(
            IndicatorType::Hostname,
            "example.invalid",
        )))?;
        store.add_entry(sample_entry(hash.clone()))?;

        let matches = match_indicator(&store, &hash);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].specificity, MatchSpecificity::Exact);
        assert_eq!(matches[0].entry.indicator, hash);
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn match_indicator_matches_url_prefix_hostname_and_domain()
    -> std::result::Result<(), Box<dyn Error>> {
        let path = temp_store_path("url-broad");
        let mut store = IntelStore::open(&path)?;
        store.add_entry(sample_entry(sample_indicator(
            IndicatorType::UrlPrefix,
            "https://example.invalid/releases/",
        )))?;
        store.add_entry(sample_entry(sample_indicator(
            IndicatorType::Hostname,
            "example.invalid",
        )))?;
        store.add_entry(sample_entry(sample_indicator(
            IndicatorType::RegistrableDomain,
            "invalid",
        )))?;

        let matches = match_indicator(
            &store,
            &sample_indicator(
                IndicatorType::ExactUrl,
                "https://example.invalid/releases/a.sh",
            ),
        );
        let specificities: Vec<MatchSpecificity> =
            matches.iter().map(|matched| matched.specificity).collect();
        assert_eq!(
            specificities,
            vec![
                MatchSpecificity::Moderate,
                MatchSpecificity::Broad,
                MatchSpecificity::Broad
            ]
        );
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn evaluate_matches_enforces_source_class_table() {
        let mut enterprise =
            sample_entry(sample_indicator(IndicatorType::Sha256, &"12".repeat(32)));
        enterprise.source_class = FeedSourceClass::EnterpriseDeny;
        let mut community = sample_entry(sample_indicator(
            IndicatorType::ExactUrl,
            "https://example.invalid/a",
        ));
        community.source_class = FeedSourceClass::CorroboratedCommunity;

        let result = evaluate_matches(&[
            MatchResult {
                entry: community,
                specificity: MatchSpecificity::Precise,
            },
            MatchResult {
                entry: enterprise,
                specificity: MatchSpecificity::Exact,
            },
        ]);

        assert_eq!(
            result,
            Some(EnforcementResult {
                disposition: Disposition::Block,
                severity: Severity::Critical,
                confidence: Confidence::Confirmed,
                deciding_source_class: FeedSourceClass::EnterpriseDeny,
            })
        );
    }

    #[test]
    fn expired_entries_are_ignored_by_match_indicator() -> std::result::Result<(), Box<dyn Error>> {
        let path = temp_store_path("match-expiry");
        let indicator = sample_indicator(IndicatorType::Sha256, &"34".repeat(32));
        let mut expired = sample_entry(indicator.clone());
        expired.expires_at = Some("1970-01-01T00:00:00Z".to_owned());
        let mut store = IntelStore::open(&path)?;
        store.add_entry(expired)?;

        assert!(match_indicator(&store, &indicator).is_empty());
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn formats_unix_epoch_as_rfc3339_utc() {
        assert_eq!(format_unix_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_timestamp(86_400), "1970-01-02T00:00:00Z");
    }
}
