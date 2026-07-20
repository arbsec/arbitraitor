//! Threat-intelligence feed adapters required by specification §21.5.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::{
    CURRENT_SCHEMA_VERSION, Classification, Confidence, Disposition, FeedAdapter, FeedEntry,
    FeedEvidence, FeedSource, FeedSourceClass, Indicator, IndicatorType, IntelError, Result,
    ReviewState, ReviewStatus, Severity, current_utc_timestamp,
};

/// Offline stub for the `ThreatFox` malware-intelligence feed.
#[derive(Clone, Copy, Debug, Default)]
pub struct ThreatFoxAdapter;

impl FeedAdapter for ThreatFoxAdapter {
    fn name(&self) -> &'static str {
        "threatfox"
    }

    fn fetch_indicators(&self) -> Result<Vec<FeedEntry>> {
        // TODO: Parse a caller-provided ThreatFox snapshot when its format contract is implemented.
        Ok(Vec::new())
    }

    fn source_class(&self) -> FeedSourceClass {
        FeedSourceClass::Authoritative
    }

    fn feed_url(&self) -> &'static str {
        ""
    }
}

/// Offline stub for the `OpenSSF` malicious-packages feed.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenSSFMaliciousAdapter;

impl FeedAdapter for OpenSSFMaliciousAdapter {
    fn name(&self) -> &'static str {
        "openssf-malicious"
    }

    fn fetch_indicators(&self) -> Result<Vec<FeedEntry>> {
        Ok(Vec::new())
    }

    fn source_class(&self) -> FeedSourceClass {
        FeedSourceClass::Authoritative
    }

    fn feed_url(&self) -> &'static str {
        ""
    }
}

/// Offline stub for the OSV advisory feed, including CISA KEV records.
#[derive(Clone, Copy, Debug, Default)]
pub struct OSVAdapter;

impl FeedAdapter for OSVAdapter {
    fn name(&self) -> &'static str {
        "osv"
    }

    fn fetch_indicators(&self) -> Result<Vec<FeedEntry>> {
        Ok(Vec::new())
    }

    fn source_class(&self) -> FeedSourceClass {
        FeedSourceClass::Authoritative
    }

    fn feed_url(&self) -> &'static str {
        ""
    }
}

/// Adapter for an enterprise-managed local allow/deny list.
#[derive(Clone, Debug)]
pub struct AllowDenyListAdapter {
    path: PathBuf,
}

impl AllowDenyListAdapter {
    /// Create an adapter that reads indicators from `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Return the configured list path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl FeedAdapter for AllowDenyListAdapter {
    fn name(&self) -> &'static str {
        "allow-deny-list"
    }

    fn fetch_indicators(&self) -> Result<Vec<FeedEntry>> {
        let contents = fs::read_to_string(&self.path).map_err(IntelError::Io)?;
        let observed_at = current_utc_timestamp();
        Ok(contents
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| allow_deny_entry(line, &observed_at))
            .collect())
    }

    fn source_class(&self) -> FeedSourceClass {
        FeedSourceClass::EnterpriseDeny
    }

    fn feed_url(&self) -> &'static str {
        ""
    }
}

fn allow_deny_entry(value: &str, observed_at: &str) -> FeedEntry {
    let digest = Sha256::digest(value.as_bytes());
    FeedEntry {
        schema_version: CURRENT_SCHEMA_VERSION,
        id: format!("allow-deny-list:{}", hex_digest(&digest)),
        indicator: Indicator {
            indicator_type: IndicatorType::ExactUrl,
            value: value.to_owned(),
        },
        classification: Classification::Malicious,
        severity: Severity::Critical,
        confidence: Confidence::Confirmed,
        disposition: Disposition::Block,
        source_class: FeedSourceClass::EnterpriseDeny,
        first_seen: observed_at.to_owned(),
        last_seen: observed_at.to_owned(),
        expires_at: None,
        sources: vec![FeedSource {
            source_type: "internal".to_owned(),
            reference: "local-allow-deny-list".to_owned(),
        }],
        evidence: FeedEvidence {
            malware_family: None,
            notes: None,
        },
        review: ReviewStatus {
            status: ReviewState::Unreviewed,
            reviewers: Vec::new(),
        },
    }
}

fn hex_digest(digest: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::{Disposition, FeedAdapter, FeedSourceClass, IndicatorType, IntelError};

    fn temp_list_path(name: &str) -> PathBuf {
        let unique = format!(
            "arbitraitor-intel-{name}-{}-{}.txt",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        );
        std::env::temp_dir().join(unique)
    }

    fn assert_adapter_surface(
        adapter: &dyn FeedAdapter,
        expected_name: &str,
        expected_class: FeedSourceClass,
    ) -> std::result::Result<(), Box<dyn Error>> {
        assert_eq!(adapter.name(), expected_name);
        assert_eq!(adapter.source_class(), expected_class);
        assert!(adapter.fetch_indicators()?.is_empty());
        Ok(())
    }

    #[test]
    fn stub_adapters_implement_feed_adapter_surface() -> std::result::Result<(), Box<dyn Error>> {
        // Given
        let adapters: [(&dyn FeedAdapter, &str); 3] = [
            (&ThreatFoxAdapter, "threatfox"),
            (&OpenSSFMaliciousAdapter, "openssf-malicious"),
            (&OSVAdapter, "osv"),
        ];

        // When / Then
        for (adapter, expected_name) in adapters {
            assert_adapter_surface(adapter, expected_name, FeedSourceClass::Authoritative)?;
        }
        Ok(())
    }

    #[test]
    fn allow_deny_list_reads_nonempty_noncomment_lines() -> std::result::Result<(), Box<dyn Error>>
    {
        // Given
        let path = temp_list_path("allow-deny");
        fs::write(
            &path,
            "# local policy\n\nhttps://bad.example/payload\n  https://blocked.example/tool  \n",
        )?;
        let adapter = AllowDenyListAdapter::new(&path);

        // When
        let entries = adapter.fetch_indicators()?;

        // Then
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].indicator.indicator_type, IndicatorType::ExactUrl);
        assert_eq!(entries[0].indicator.value, "https://bad.example/payload");
        assert_eq!(entries[1].indicator.value, "https://blocked.example/tool");
        assert!(
            entries
                .iter()
                .all(|entry| entry.disposition == Disposition::Block)
        );
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn allow_deny_list_exposes_enterprise_source_metadata() {
        // Given
        let adapter = AllowDenyListAdapter::new("policy/deny-list.txt");

        // When / Then
        assert_eq!(adapter.name(), "allow-deny-list");
        assert_eq!(adapter.source_class(), FeedSourceClass::EnterpriseDeny);
        assert_eq!(adapter.path(), std::path::Path::new("policy/deny-list.txt"));
    }

    #[test]
    fn allow_deny_list_propagates_file_read_errors() {
        // Given
        let path = temp_list_path("missing");
        let adapter = AllowDenyListAdapter::new(path);

        // When
        let result = adapter.fetch_indicators();

        // Then
        assert!(matches!(result, Err(IntelError::Io(_))));
    }
}
