//! `URLhaus` feed adapter.
//!
//! [`URLhaus`](https://urlhaus.abuse.ch/) is an authoritative malware-URL
//! exchange operated by abuse.ch. The adapter accepts either the public CSV
//! export (`"id","dateadded","url","url_status","threat","tags","urlhaus_link"`)
//! or the JSON payload returned by the v1 API (`{"urls":[...]}`). The format is
//! detected from the first non-whitespace byte: `{` selects JSON, everything
//! else selects CSV.
//!
//! Parsed rows become [`FeedEntry`] records with
//! [`FeedSourceClass::Authoritative`] per specification §21.4, `Block`
//! disposition, `High` severity, and `Confirmed` confidence — matching the
//! default enforcement table for authoritative sources.

#![allow(clippy::module_name_repetitions)]

use serde::Deserialize;

use crate::feed::FeedAdapter;
use crate::{
    CURRENT_SCHEMA_VERSION, Classification, Confidence, Disposition, FeedEntry, FeedEvidence,
    FeedSource, FeedSourceClass, Indicator, IndicatorType, IntelError, Result, ReviewState,
    ReviewStatus, Severity, current_unix_timestamp, format_unix_timestamp,
};

/// Default `URLhaus` CSV export endpoint.
pub const URLHAUS_DEFAULT_CSV_URL: &str = "https://urlhaus.abuse.ch/downloads/csv/";

/// Default time-to-live (days) for `URLhaus`-sourced entries.
///
/// `URLhaus` records rotate quickly; entries older than this window are
/// considered stale and eligible for purge by [`crate::IntelStore::purge_expired`].
pub const URLHAUS_DEFAULT_TTL_DAYS: u64 = 7;

const SECONDS_PER_DAY: u64 = 86_400;

/// `URLhaus` feed adapter.
///
/// Construct with [`UrlhausAdapter::new`] for the default CSV endpoint, or
/// [`UrlhausAdapter::with_url`] to point at a mirror or the JSON API. The
/// adapter itself performs no network I/O; retrieval is driven by
/// [`crate::ingest_feed`] through a [`arbitraitor_fetch::Fetcher`].
#[derive(Clone, Debug)]
pub struct UrlhausAdapter {
    feed_url: String,
    ttl_days: u64,
}

impl UrlhausAdapter {
    /// Creates an adapter targeting the default `URLhaus` CSV export with a
    /// [`URLHAUS_DEFAULT_TTL_DAYS`]-day expiry window.
    #[must_use]
    pub fn new() -> Self {
        Self {
            feed_url: URLHAUS_DEFAULT_CSV_URL.to_owned(),
            ttl_days: URLHAUS_DEFAULT_TTL_DAYS,
        }
    }

    /// Creates an adapter targeting `url` (CSV or JSON) with the default TTL.
    #[must_use]
    pub fn with_url(url: impl Into<String>) -> Self {
        Self {
            feed_url: url.into(),
            ttl_days: URLHAUS_DEFAULT_TTL_DAYS,
        }
    }

    /// Creates an adapter targeting `url` with a custom entry TTL in days.
    #[must_use]
    pub fn with_url_and_ttl(url: impl Into<String>, ttl_days: u64) -> Self {
        Self {
            feed_url: url.into(),
            ttl_days,
        }
    }

    /// Returns the configured TTL in days.
    #[must_use]
    pub fn ttl_days(&self) -> u64 {
        self.ttl_days
    }
}

impl Default for UrlhausAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl FeedAdapter for UrlhausAdapter {
    fn source_class(&self) -> FeedSourceClass {
        FeedSourceClass::Authoritative
    }

    fn source_name(&self) -> &'static str {
        "urlhaus"
    }

    fn feed_url(&self) -> &str {
        &self.feed_url
    }

    fn parse(&self, bytes: &[u8]) -> Result<Vec<FeedEntry>> {
        let first = bytes
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace());
        match first {
            None => Ok(Vec::new()),
            Some(b'{') => parse_json(bytes, self.ttl_days),
            Some(_) => parse_csv(bytes, self.ttl_days),
        }
    }
}

/// Normalized `URLhaus` record used internally to build [`FeedEntry`].
struct UrlhausRecord {
    id: String,
    url: String,
    date_added: String,
    threat: String,
    tags: String,
    urlhaus_link: String,
}

/// CSV row schema (matches the `URLhaus` CSV header exactly).
#[derive(Debug, Deserialize)]
struct UrlhausCsvRow {
    id: String,
    dateadded: String,
    url: String,
    #[serde(default)]
    #[allow(dead_code)]
    url_status: String,
    #[serde(default)]
    threat: String,
    #[serde(default)]
    tags: String,
    #[serde(default)]
    urlhaus_link: String,
}

impl From<UrlhausCsvRow> for UrlhausRecord {
    fn from(row: UrlhausCsvRow) -> Self {
        Self {
            id: row.id,
            url: row.url,
            date_added: row.dateadded,
            threat: row.threat,
            tags: row.tags,
            urlhaus_link: row.urlhaus_link,
        }
    }
}

/// JSON payload returned by the `URLhaus` v1 recent-urls API.
#[derive(Debug, Deserialize)]
struct UrlhausJsonPayload {
    #[serde(default)]
    #[allow(dead_code)]
    query_status: String,
    #[serde(default)]
    urls: Vec<UrlhausJsonRow>,
}

/// JSON row schema (note: `date_added` uses an underscore, unlike CSV).
#[derive(Debug, Deserialize)]
struct UrlhausJsonRow {
    id: String,
    url: String,
    #[serde(default)]
    date_added: String,
    #[serde(default)]
    #[allow(dead_code)]
    url_status: String,
    #[serde(default)]
    threat: String,
    #[serde(default)]
    tags: String,
    #[serde(default)]
    urlhaus_link: String,
}

impl From<UrlhausJsonRow> for UrlhausRecord {
    fn from(row: UrlhausJsonRow) -> Self {
        Self {
            id: row.id,
            url: row.url,
            date_added: row.date_added,
            threat: row.threat,
            tags: row.tags,
            urlhaus_link: row.urlhaus_link,
        }
    }
}

fn parse_csv(bytes: &[u8], ttl_days: u64) -> Result<Vec<FeedEntry>> {
    let text = std::str::from_utf8(bytes).map_err(|error| IntelError::FeedDecode {
        reason: format!("urlhaus csv is not valid UTF-8: {error}"),
    })?;
    let header = text
        .find(CSV_HEADER_MARKER)
        .ok_or_else(|| IntelError::FeedDecode {
            reason: "urlhaus csv missing required header row".to_owned(),
        })?;
    let body = &text[header..];

    let now = current_unix_timestamp();
    let mut entries = Vec::new();
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(body.as_bytes());
    for (index, result) in reader.deserialize::<UrlhausCsvRow>().enumerate() {
        match result {
            Ok(row) => {
                let record = UrlhausRecord::from(row);
                if record.url.trim().is_empty() {
                    tracing::warn!(row = index + 1, "skipping urlhaus csv row with empty url");
                    continue;
                }
                entries.push(urlhaus_record_to_entry(record, now, ttl_days));
            }
            Err(error) => {
                tracing::warn!(
                    row = index + 1,
                    "skipping malformed urlhaus csv row: {error}"
                );
            }
        }
    }
    Ok(entries)
}

fn parse_json(bytes: &[u8], ttl_days: u64) -> Result<Vec<FeedEntry>> {
    let payload: UrlhausJsonPayload =
        serde_json::from_slice(bytes).map_err(|error| IntelError::FeedDecode {
            reason: format!("urlhaus json payload is malformed: {error}"),
        })?;
    let now = current_unix_timestamp();
    let mut entries = Vec::with_capacity(payload.urls.len());
    for (index, row) in payload.urls.into_iter().enumerate() {
        let record = UrlhausRecord::from(row);
        if record.url.trim().is_empty() {
            tracing::warn!(row = index, "skipping urlhaus json entry with empty url");
            continue;
        }
        entries.push(urlhaus_record_to_entry(record, now, ttl_days));
    }
    Ok(entries)
}

fn urlhaus_record_to_entry(record: UrlhausRecord, now_seconds: u64, ttl_days: u64) -> FeedEntry {
    let now_ts = format_unix_timestamp(now_seconds);
    let expires_at = format_unix_timestamp(now_seconds + ttl_days * SECONDS_PER_DAY);
    let indicator_value = record.url;
    let entry_id = format!("urlhaus:{}", record.id);
    FeedEntry {
        schema_version: CURRENT_SCHEMA_VERSION,
        id: entry_id,
        indicator: Indicator {
            indicator_type: IndicatorType::ExactUrl,
            value: indicator_value,
        },
        classification: Classification::Malicious,
        severity: Severity::High,
        confidence: Confidence::Confirmed,
        disposition: Disposition::Block,
        source_class: FeedSourceClass::Authoritative,
        first_seen: normalize_urlhaus_timestamp(&record.date_added, &now_ts),
        last_seen: now_ts,
        expires_at: Some(expires_at),
        sources: vec![FeedSource {
            source_type: "osint".to_owned(),
            reference: record.urlhaus_link,
        }],
        evidence: FeedEvidence {
            malware_family: non_empty(record.threat),
            notes: non_empty(record.tags),
        },
        review: ReviewStatus {
            status: ReviewState::Unreviewed,
            reviewers: Vec::new(),
        },
    }
}

/// Converts a `URLhaus` timestamp (`2025-06-18 08:00:00 UTC`) into RFC 3339
/// (`2025-06-18T08:00:00Z`). Falls back to `fallback` when the input does not
/// match the expected shape so a malformed date never blocks ingestion.
fn normalize_urlhaus_timestamp(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    let mut parts = trimmed.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some(date), Some(time), Some(tz)) if tz.eq_ignore_ascii_case("UTC") => {
            format!("{date}T{time}Z")
        }
        _ => fallback.to_owned(),
    }
}

fn non_empty(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Distinctive prefix of the `URLhaus` CSV header row, used to skip the
/// preamble lines that precede it in the public export.
const CSV_HEADER_MARKER: &str = "\"id\",\"dateadded\"";

#[cfg(test)]
mod tests {
    use super::*;

    const CSV_PAYLOAD: &str = "\
# urlhaus csv export
# generated: 2026-06-18
\"id\",\"dateadded\",\"url\",\"url_status\",\"threat\",\"tags\",\"urlhaus_link\"
\"1\",\"2026-06-18 08:00:00 UTC\",\"http://evil.example/payload\",\"online\",\"malware_download\",\"Loader,Emotet\",\"https://urlhaus.abuse.ch/url/1/\"
\"2\",\"2026-06-18 09:00:00 UTC\",\"http://evil.example/dropper\",\"offline\",\"malware_download\",\"\",\"https://urlhaus.abuse.ch/url/2/\"
";

    const JSON_PAYLOAD: &str = r#"{
  "query_status": "ok",
  "url_count": 1,
  "urls": [
    {
      "id": "42",
      "url": "http://evil.example/json-payload",
      "url_status": "online",
      "date_added": "2026-06-18 10:00:00 UTC",
      "threat": "malware_download",
      "tags": "Ransomware",
      "urlhaus_link": "https://urlhaus.abuse.ch/url/42/"
    }
  ]
}"#;

    #[test]
    fn csv_parses_into_feed_entries() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let adapter = UrlhausAdapter::new();
        let entries = adapter.parse(CSV_PAYLOAD.as_bytes())?;
        assert_eq!(entries.len(), 2);

        let first = &entries[0];
        assert_eq!(first.id, "urlhaus:1");
        assert_eq!(first.indicator.indicator_type, IndicatorType::ExactUrl);
        assert_eq!(first.indicator.value, "http://evil.example/payload");
        assert_eq!(first.classification, Classification::Malicious);
        assert_eq!(first.severity, Severity::High);
        assert_eq!(first.confidence, Confidence::Confirmed);
        assert_eq!(first.disposition, Disposition::Block);
        assert_eq!(first.source_class, FeedSourceClass::Authoritative);
        assert_eq!(first.first_seen, "2026-06-18T08:00:00Z");
        assert_eq!(
            first.evidence.malware_family.as_deref(),
            Some("malware_download")
        );
        assert_eq!(first.evidence.notes.as_deref(), Some("Loader,Emotet"));
        assert_eq!(first.sources[0].source_type, "osint");
        assert_eq!(first.review.status, ReviewState::Unreviewed);
        assert!(first.expires_at.is_some());
        Ok(())
    }

    #[test]
    fn csv_empty_tags_become_none_in_evidence()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let adapter = UrlhausAdapter::new();
        let entries = adapter.parse(CSV_PAYLOAD.as_bytes())?;
        let second = &entries[1];
        assert_eq!(second.evidence.notes, None);
        Ok(())
    }

    #[test]
    fn json_parses_into_feed_entries() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let adapter = UrlhausAdapter::new();
        let entries = adapter.parse(JSON_PAYLOAD.as_bytes())?;
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.id, "urlhaus:42");
        assert_eq!(entry.indicator.value, "http://evil.example/json-payload");
        assert_eq!(entry.first_seen, "2026-06-18T10:00:00Z");
        assert_eq!(entry.source_class, FeedSourceClass::Authoritative);
        Ok(())
    }

    #[test]
    fn empty_payload_produces_zero_entries() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let adapter = UrlhausAdapter::new();
        assert!(adapter.parse(b"")?.is_empty());
        assert!(adapter.parse(b"   \n\t  ")?.is_empty());
        Ok(())
    }

    #[test]
    fn invalid_utf8_csv_is_rejected() {
        let adapter = UrlhausAdapter::new();
        let invalid = [0xFF, 0xFE, 0x00];
        let error = adapter.parse(&invalid);
        assert!(matches!(error, Err(IntelError::FeedDecode { .. })));
    }

    #[test]
    fn malformed_json_is_rejected() {
        let adapter = UrlhausAdapter::new();
        let error = adapter.parse(b"{ not json");
        assert!(matches!(error, Err(IntelError::FeedDecode { .. })));
    }

    #[test]
    fn csv_without_header_is_rejected() {
        let adapter = UrlhausAdapter::new();
        let no_header = "garbage,data,without,header,row\n1,2,3,4,5,6,7\n";
        let error = adapter.parse(no_header.as_bytes());
        assert!(matches!(error, Err(IntelError::FeedDecode { .. })));
    }

    #[test]
    fn date_normalization_handles_urlhaus_format() {
        assert_eq!(
            normalize_urlhaus_timestamp("2026-06-18 08:00:00 UTC", "fallback"),
            "2026-06-18T08:00:00Z"
        );
    }

    #[test]
    fn date_normalization_falls_back_for_unknown_format() {
        assert_eq!(
            normalize_urlhaus_timestamp("not a date", "2026-06-18T00:00:00Z"),
            "2026-06-18T00:00:00Z"
        );
    }

    #[test]
    fn expiry_is_ttl_days_after_now() {
        let now = 0_u64;
        let ttl = 7_u64;
        let entry = urlhaus_record_to_entry(
            UrlhausRecord {
                id: "1".to_owned(),
                url: "http://evil.example/x".to_owned(),
                date_added: String::new(),
                threat: String::new(),
                tags: String::new(),
                urlhaus_link: String::new(),
            },
            now,
            ttl,
        );
        assert_eq!(entry.expires_at.as_deref(), Some("1970-01-08T00:00:00Z"));
    }

    #[test]
    fn adapter_source_metadata_is_authoritative() {
        let adapter = UrlhausAdapter::new();
        assert_eq!(adapter.source_class(), FeedSourceClass::Authoritative);
        assert_eq!(adapter.source_name(), "urlhaus");
        assert_eq!(adapter.feed_url(), URLHAUS_DEFAULT_CSV_URL);
    }

    #[test]
    fn with_url_overrides_default_endpoint() {
        let adapter = UrlhausAdapter::with_url("https://mirror.example/urlhaus.csv");
        assert_eq!(adapter.feed_url(), "https://mirror.example/urlhaus.csv");
    }

    #[test]
    fn csv_skips_rows_with_empty_urls() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let csv = "\
\"id\",\"dateadded\",\"url\",\"url_status\",\"threat\",\"tags\",\"urlhaus_link\"
\"1\",\"2026-06-18 08:00:00 UTC\",\"\",\"online\",\"malware_download\",\"\",\"https://urlhaus.abuse.ch/url/1/\"
\"2\",\"2026-06-18 09:00:00 UTC\",\"http://evil.example/real\",\"online\",\"malware_download\",\"\",\"https://urlhaus.abuse.ch/url/2/\"
";
        let adapter = UrlhausAdapter::new();
        let entries = adapter.parse(csv.as_bytes())?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "urlhaus:2");
        Ok(())
    }

    #[test]
    fn csv_tolerates_extra_columns_via_flexible_mode()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let csv = "\
\"id\",\"dateadded\",\"url\",\"url_status\",\"threat\",\"tags\",\"urlhaus_link\",\"extra\"
\"9\",\"2026-06-18 08:00:00 UTC\",\"http://evil.example/extra\",\"online\",\"malware_download\",\"\",\"https://urlhaus.abuse.ch/url/9/\",\"surprise\"
";
        let adapter = UrlhausAdapter::new();
        let entries = adapter.parse(csv.as_bytes())?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].indicator.value, "http://evil.example/extra");
        Ok(())
    }
}
