//! Threat intelligence feed management.
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use arbitraitor_model::verdict::{Confidence, Severity};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

/// Result type for intelligence store operations.
pub type Result<T> = std::result::Result<T, IntelError>;

/// Errors produced by intelligence feed storage.
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
}

fn current_utc_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    format_unix_timestamp(seconds)
}

fn format_unix_timestamp(seconds: u64) -> String {
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
        let json = r#"{"schema_version":1,"id":"entry-1","indicator":{"indicator_type":"sha256","value":"abababababababababababababababababababababababababababababababab"},"classification":"malicious","severity":"high","confidence":"confirmed","disposition":"block","first_seen":"2026-06-01T00:00:00Z","last_seen":"2026-06-17T00:00:00Z","expires_at":null,"sources":[],"evidence":{"malware_family":null,"notes":null},"review":{"status":"reviewed","reviewers":[]},"extra":true}"#;
        assert!(serde_json::from_str::<FeedEntry>(json).is_err());
    }

    #[test]
    fn formats_unix_epoch_as_rfc3339_utc() {
        assert_eq!(format_unix_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_timestamp(86_400), "1970-01-02T00:00:00Z");
    }
}
