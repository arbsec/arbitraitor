//! `OpenSSF` malicious-packages feed adapter backed by OSV.dev.

use std::str::FromStr;

use arbitraitor_model::osv::OsvMalId;
use serde::Deserialize;

use crate::feed::FeedAdapter;
use crate::{
    CURRENT_SCHEMA_VERSION, Classification, Confidence, Disposition, FeedEntry, FeedEvidence,
    FeedSource, FeedSourceClass, Indicator, IndicatorType, IntelError, Result, ReviewState,
    ReviewStatus, Severity, current_utc_timestamp,
};

/// Default OSV.dev batch-query endpoint for package-version lookups.
pub const OSV_QUERYBATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

/// Feed adapter for `OpenSSF` malicious-packages `MAL-` IDs returned by OSV.dev.
#[derive(Clone, Debug)]
pub struct OssfMaliciousPackagesAdapter {
    feed_url: String,
}

impl OssfMaliciousPackagesAdapter {
    /// Creates an adapter targeting the OSV.dev `querybatch` endpoint.
    #[must_use]
    pub fn new() -> Self {
        Self {
            feed_url: OSV_QUERYBATCH_URL.to_owned(),
        }
    }

    /// Creates an adapter targeting an OSV-compatible batch-response URL.
    #[must_use]
    pub fn with_url(url: impl Into<String>) -> Self {
        Self {
            feed_url: url.into(),
        }
    }
}

impl Default for OssfMaliciousPackagesAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl FeedAdapter for OssfMaliciousPackagesAdapter {
    fn name(&self) -> &'static str {
        "ossf-malicious-packages"
    }

    fn fetch_indicators(&self) -> Result<Vec<FeedEntry>> {
        Ok(Vec::new())
    }

    fn source_class(&self) -> FeedSourceClass {
        FeedSourceClass::OssfMaliciousPackages
    }

    fn feed_url(&self) -> &str {
        &self.feed_url
    }

    fn parse(&self, bytes: &[u8]) -> Result<Vec<FeedEntry>> {
        parse_osv_batch(bytes)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OsvBatchResponse {
    results: Vec<OsvQueryResult>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OsvQueryResult {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OsvVulnerability {
    id: String,
    #[serde(default)]
    modified: Option<String>,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OsvAffected {
    #[serde(default)]
    package: Option<OsvPackage>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OsvPackage {
    #[serde(default)]
    ecosystem: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

fn parse_osv_batch(bytes: &[u8]) -> Result<Vec<FeedEntry>> {
    let payload: OsvBatchResponse =
        serde_json::from_slice(bytes).map_err(|error| IntelError::FeedDecode {
            reason: format!("OSV querybatch payload is malformed: {error}"),
        })?;
    let observed_at = current_utc_timestamp();
    let mut entries = Vec::new();
    for vulnerability in payload
        .results
        .into_iter()
        .flat_map(|result| result.vulns.into_iter())
    {
        match OsvMalId::from_str(&vulnerability.id) {
            Ok(mal_id) => entries.push(osv_vulnerability_to_entry(
                &mal_id,
                &vulnerability,
                &observed_at,
            )),
            Err(error) => tracing::debug!(
                id = vulnerability.id,
                "skipping non-MAL OSV advisory: {error}"
            ),
        }
    }
    Ok(entries)
}

fn osv_vulnerability_to_entry(
    mal_id: &OsvMalId,
    vulnerability: &OsvVulnerability,
    observed_at: &str,
) -> FeedEntry {
    let mal_id_text = mal_id.as_str();
    let source_timestamp = vulnerability
        .modified
        .as_ref()
        .or(vulnerability.published.as_ref())
        .cloned()
        .unwrap_or_else(|| observed_at.to_owned());
    FeedEntry {
        schema_version: CURRENT_SCHEMA_VERSION,
        id: format!("ossf-malicious-packages:{mal_id_text}"),
        indicator: Indicator {
            indicator_type: IndicatorType::OsvMal,
            value: mal_id_text.to_owned(),
        },
        classification: Classification::Malicious,
        severity: Severity::High,
        confidence: Confidence::Confirmed,
        disposition: Disposition::Block,
        source_class: FeedSourceClass::OssfMaliciousPackages,
        first_seen: source_timestamp.clone(),
        last_seen: observed_at.to_owned(),
        source_update_time: Some(source_timestamp),
        expires_at: None,
        sources: vec![FeedSource {
            source_type: "osv".to_owned(),
            reference: format!("https://osv.dev/vulnerability/{mal_id_text}"),
        }],
        evidence: FeedEvidence {
            malware_family: package_label(vulnerability),
            notes: evidence_notes(vulnerability),
        },
        review: ReviewStatus {
            status: ReviewState::Unreviewed,
            reviewers: Vec::new(),
        },
    }
}

fn package_label(vulnerability: &OsvVulnerability) -> Option<String> {
    vulnerability.affected.iter().find_map(|affected| {
        let package = affected.package.as_ref()?;
        Some(match (&package.ecosystem, &package.name) {
            (Some(ecosystem), Some(name)) => format!("{ecosystem}:{name}"),
            (None, Some(name)) => name.clone(),
            (Some(ecosystem), None) => ecosystem.clone(),
            (None, None) => return None,
        })
    })
}

fn evidence_notes(vulnerability: &OsvVulnerability) -> Option<String> {
    let summary = vulnerability
        .summary
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    let details = vulnerability
        .details
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    let aliases = if vulnerability.aliases.is_empty() {
        None
    } else {
        Some(format!("aliases: {}", vulnerability.aliases.join(",")))
    };
    [
        summary.map(str::to_owned),
        details.map(str::to_owned),
        aliases,
    ]
    .into_iter()
    .flatten()
    .next()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OSV_QUERYBATCH_FIXTURE: &str = r#"{
  "results": [
    {
      "vulns": [
        {
          "id": "MAL-2026-1234",
          "modified": "2026-05-20T00:00:00Z",
          "published": "2026-05-19T00:00:00Z",
          "summary": "Malicious npm package",
          "details": "OpenSSF malicious-packages report",
          "aliases": ["GHSA-test-test-test"],
          "affected": [
            {
              "package": {
                "ecosystem": "npm",
                "name": "eslint-config-malicious"
              }
            }
          ]
        }
      ]
    }
  ]
}"#;

    #[test]
    fn parses_real_mal_id_from_osv_querybatch_fixture()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Given
        let adapter = OssfMaliciousPackagesAdapter::new();

        // When
        let entries = adapter.parse(OSV_QUERYBATCH_FIXTURE.as_bytes())?;

        // Then
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.id, "ossf-malicious-packages:MAL-2026-1234");
        assert_eq!(entry.indicator.indicator_type, IndicatorType::OsvMal);
        assert_eq!(entry.indicator.value, "MAL-2026-1234");
        assert_eq!(entry.source_class, FeedSourceClass::OssfMaliciousPackages);
        assert_eq!(entry.disposition, Disposition::Block);
        assert_eq!(entry.confidence, Confidence::Confirmed);
        assert_eq!(
            entry.source_update_time.as_deref(),
            Some("2026-05-20T00:00:00Z")
        );
        assert_eq!(
            entry.evidence.malware_family.as_deref(),
            Some("npm:eslint-config-malicious")
        );
        assert_eq!(
            entry.sources[0].reference,
            "https://osv.dev/vulnerability/MAL-2026-1234"
        );
        Ok(())
    }

    #[test]
    fn skips_non_mal_osv_advisories() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Given
        let payload = r#"{"results":[{"vulns":[{"id":"GHSA-xxxx-yyyy-zzzz"}]}]}"#;
        let adapter = OssfMaliciousPackagesAdapter::new();

        // When
        let entries = adapter.parse(payload.as_bytes())?;

        // Then
        assert!(entries.is_empty());
        Ok(())
    }

    #[test]
    fn adapter_targets_osv_querybatch_endpoint() {
        // Given
        let adapter = OssfMaliciousPackagesAdapter::new();

        // When / Then
        assert_eq!(adapter.name(), "ossf-malicious-packages");
        assert_eq!(
            adapter.source_class(),
            FeedSourceClass::OssfMaliciousPackages
        );
        assert_eq!(adapter.feed_url(), OSV_QUERYBATCH_URL);
    }
}
