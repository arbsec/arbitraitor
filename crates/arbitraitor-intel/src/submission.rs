//! Community-submitted threat indicator schema and validation.
//!
//! A [`FeedSubmission`] represents an untrusted, community-sourced threat
//! indicator. Submissions are validated for structural completeness and policy
//! compliance via [`validate_submission`] before they enter the review
//! workflow ([`crate::workflow::SubmissionWorkflow`]).
//!
//! All submission types use [`serde`] with `deny_unknown_fields` so unexpected
//! keys are rejected at the deserialization boundary, matching the convention
//! for security-critical untrusted input (see `docs/conventions.md`).

use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// MD5 hex digest length in characters.
const MD5_HEX_LEN: usize = 32;
/// SHA-256 hex digest length in characters.
const SHA256_HEX_LEN: usize = 64;

/// A community-submitted threat indicator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeedSubmission {
    /// Identity and trust classification of the submitter.
    pub submitter: SubmitterIdentity,
    /// The indicator being reported.
    pub indicator: SubmittedIndicator,
    /// Supporting evidence for the submission.
    pub evidence: SubmissionEvidence,
    /// Submitter-attached metadata.
    pub metadata: SubmissionMetadata,
}

/// Identity and trust classification of a community submitter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitterIdentity {
    /// Human-readable handle for the submitter.
    pub handle: String,
    /// Trust tier assigned to the submitter.
    pub trust_tier: TrustTier,
    /// Optional fingerprint of the submitter's signing key.
    pub key_fingerprint: Option<String>,
}

/// Trust tier assigned to a community submitter.
///
/// Variants are ordered from least to most trusted so that derived [`Ord`]
/// reflects trust ranking: `Anonymous < Registered < Verified < Trusted`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// Unauthenticated, anonymous submission.
    Anonymous,
    /// Registered but unverified account.
    Registered,
    /// Identity-verified account.
    Verified,
    /// Explicitly trusted contributor (e.g. established researcher).
    Trusted,
}

/// The indicator being reported by a submission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmittedIndicator {
    /// Category of the indicator value.
    pub indicator_type: IndicatorType,
    /// Raw indicator value in the canonical form for its type.
    pub value: String,
    /// Submitter-assigned confidence in the indicator.
    pub confidence: ConfidenceLevel,
}

/// Category of a submitted indicator value.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    /// Uniform resource locator.
    Url,
    /// Domain name.
    Domain,
    /// IPv4 or IPv6 address.
    IpAddress,
    /// File content hash (MD5 or SHA-256).
    FileHash,
    /// File system path.
    FilePath,
    /// Operating system registry key.
    RegistryKey,
}

/// Submitter-assigned confidence in a reported indicator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    /// Low confidence — needs corroboration.
    Low,
    /// Medium confidence.
    Medium,
    /// High confidence.
    High,
    /// Independently confirmed.
    Confirmed,
}

/// Supporting evidence attached to a submission.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionEvidence {
    /// Hashes of related malware samples.
    pub sample_hashes: Vec<String>,
    /// Other indicators related to this submission.
    pub related_indicators: Vec<String>,
    /// Free-form description of the finding.
    pub description: String,
    /// Unix timestamp (seconds since epoch) when the indicator was first observed.
    pub first_seen: Option<u64>,
    /// Unix timestamp (seconds since epoch) when the indicator was last observed.
    pub last_seen: Option<u64>,
}

/// Submitter-attached metadata for a submission.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionMetadata {
    /// Originating source label (e.g. tool name, organization).
    pub source: String,
    /// Free-form tags categorizing the submission.
    pub tags: Vec<String>,
    /// Unix timestamp (seconds since epoch) when the submission should expire.
    pub expires_at: Option<u64>,
}

/// Lifecycle status of a community feed submission.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionStatus {
    /// Awaiting initial triage.
    Pending,
    /// Actively under human review.
    UnderReview,
    /// Reviewed and accepted into the feed.
    Accepted,
    /// Reviewed and rejected.
    Rejected,
    /// Past expiration without review.
    Expired,
}

/// Errors produced by [`validate_submission`].
#[derive(Debug, Eq, Error, PartialEq)]
pub enum ValidationError {
    /// Submitter handle is empty or whitespace-only.
    #[error("submitter handle must not be empty")]
    EmptyHandle,
    /// Indicator value is empty or whitespace-only.
    #[error("indicator value must not be empty")]
    EmptyIndicatorValue,
    /// Anonymous submissions cannot assert high or confirmed confidence.
    #[error("anonymous submissions cannot assert high or confirmed confidence")]
    AnonymousOverconfident,
    /// Confirmed confidence requires at least one sample hash in evidence.
    #[error("confirmed confidence requires at least one sample hash in evidence")]
    ConfirmedRequiresEvidence,
    /// URL indicator is not parseable or lacks a host.
    #[error("url indicator must be parseable and contain a host")]
    InvalidUrl,
    /// File hash is not valid hex of length 32 (MD5) or 64 (SHA-256).
    #[error("file hash must be valid hex of length 32 (MD5) or 64 (SHA-256)")]
    InvalidFileHash,
    /// IP address indicator does not parse as IPv4 or IPv6.
    #[error("ip address indicator must be a valid IPv4 or IPv6 address")]
    InvalidIpAddress,
}

/// Validates a submission for completeness and policy compliance.
///
/// Checks the following rules:
///
/// - `submitter.handle` is non-empty.
/// - `indicator.value` is non-empty.
/// - `indicator.value` matches the format implied by `indicator_type`
///   (URLs require a parseable host; file hashes require valid hex of the
///   right length; IP addresses must parse).
/// - [`TrustTier::Anonymous`] submissions cannot carry
///   [`ConfidenceLevel::High`] or [`ConfidenceLevel::Confirmed`].
/// - [`ConfidenceLevel::Confirmed`] requires at least one entry in
///   [`SubmissionEvidence::sample_hashes`].
///
/// # Errors
///
/// Returns the first [`ValidationError`] encountered, in the order listed above.
pub fn validate_submission(submission: &FeedSubmission) -> Result<(), ValidationError> {
    if submission.submitter.handle.trim().is_empty() {
        return Err(ValidationError::EmptyHandle);
    }

    if submission.indicator.value.trim().is_empty() {
        return Err(ValidationError::EmptyIndicatorValue);
    }

    validate_indicator_format(&submission.indicator)?;

    if submission.submitter.trust_tier == TrustTier::Anonymous
        && matches!(
            submission.indicator.confidence,
            ConfidenceLevel::High | ConfidenceLevel::Confirmed
        )
    {
        return Err(ValidationError::AnonymousOverconfident);
    }

    if submission.indicator.confidence == ConfidenceLevel::Confirmed
        && submission.evidence.sample_hashes.is_empty()
    {
        return Err(ValidationError::ConfirmedRequiresEvidence);
    }

    Ok(())
}

/// Checks that `indicator.value` matches the structural format implied by its
/// `indicator_type`.
fn validate_indicator_format(indicator: &SubmittedIndicator) -> Result<(), ValidationError> {
    match indicator.indicator_type {
        IndicatorType::Url => validate_url(&indicator.value),
        IndicatorType::FileHash => validate_file_hash(&indicator.value),
        IndicatorType::IpAddress => validate_ip_address(&indicator.value),
        IndicatorType::Domain | IndicatorType::FilePath | IndicatorType::RegistryKey => {
            // Non-empty check already passed; no additional structural format
            // constraint is defined for these types.
            Ok(())
        }
    }
}

/// Requires a parseable URL with a non-empty host.
fn validate_url(value: &str) -> Result<(), ValidationError> {
    let has_host = Url::parse(value)
        .ok()
        .and_then(|url| url.host_str().map(str::is_empty))
        .is_some_and(|is_empty| !is_empty);
    if has_host {
        Ok(())
    } else {
        Err(ValidationError::InvalidUrl)
    }
}

/// Requires valid lowercase or uppercase hex of length 32 (MD5) or 64 (SHA-256).
fn validate_file_hash(value: &str) -> Result<(), ValidationError> {
    let valid = value.len() == MD5_HEX_LEN || value.len() == SHA256_HEX_LEN;
    let valid = valid && value.bytes().all(|b| b.is_ascii_hexdigit());
    if valid {
        Ok(())
    } else {
        Err(ValidationError::InvalidFileHash)
    }
}

/// Requires a parseable IPv4 or IPv6 address.
fn validate_ip_address(value: &str) -> Result<(), ValidationError> {
    if IpAddr::from_str(value.trim()).is_ok() {
        Ok(())
    } else {
        Err(ValidationError::InvalidIpAddress)
    }
}

/// Serializes a submission for the transparency log.
///
/// Produces a compact JSON representation suitable for appending to an
/// append-only log. The transparency log itself is tracked separately in #155.
///
/// # Errors
///
/// Returns an error if serialization fails (e.g. non-representable types).
pub fn serialize_for_log(submission: &FeedSubmission) -> Result<String, serde_json::Error> {
    serde_json::to_string(submission)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a valid submission with sensible defaults for test customization.
    fn sample_submission() -> FeedSubmission {
        FeedSubmission {
            submitter: SubmitterIdentity {
                handle: "analyst@example".to_owned(),
                trust_tier: TrustTier::Registered,
                key_fingerprint: None,
            },
            indicator: SubmittedIndicator {
                indicator_type: IndicatorType::Url,
                value: "https://evil.example/payload".to_owned(),
                confidence: ConfidenceLevel::Medium,
            },
            evidence: SubmissionEvidence {
                sample_hashes: Vec::new(),
                related_indicators: Vec::new(),
                description: "Dropper observed in the wild".to_owned(),
                first_seen: None,
                last_seen: None,
            },
            metadata: SubmissionMetadata {
                source: "sandbox".to_owned(),
                tags: Vec::new(),
                expires_at: None,
            },
        }
    }

    #[test]
    fn valid_submission_accepted() {
        let submission = sample_submission();
        assert!(validate_submission(&submission).is_ok());
    }

    #[test]
    fn anonymous_rejects_high_confidence() {
        let mut submission = sample_submission();
        submission.submitter.trust_tier = TrustTier::Anonymous;
        submission.indicator.confidence = ConfidenceLevel::High;
        assert_eq!(
            validate_submission(&submission),
            Err(ValidationError::AnonymousOverconfident)
        );
    }

    #[test]
    fn confirmed_requires_evidence() {
        let mut submission = sample_submission();
        submission.indicator.confidence = ConfidenceLevel::Confirmed;
        assert_eq!(
            validate_submission(&submission),
            Err(ValidationError::ConfirmedRequiresEvidence)
        );
    }

    #[test]
    fn confirmed_with_evidence_passes() {
        let mut submission = sample_submission();
        submission.indicator.confidence = ConfidenceLevel::Confirmed;
        submission
            .evidence
            .sample_hashes
            .push("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned());
        assert!(validate_submission(&submission).is_ok());
    }

    #[test]
    fn empty_handle_rejected() {
        let mut submission = sample_submission();
        submission.submitter.handle = "   ".to_owned();
        assert_eq!(
            validate_submission(&submission),
            Err(ValidationError::EmptyHandle)
        );
    }

    #[test]
    fn invalid_url_rejected() {
        let mut submission = sample_submission();
        submission.indicator.indicator_type = IndicatorType::Url;
        submission.indicator.value = "not-a-url".to_owned();
        assert_eq!(
            validate_submission(&submission),
            Err(ValidationError::InvalidUrl)
        );
    }

    #[test]
    fn url_without_host_rejected() {
        let mut submission = sample_submission();
        submission.indicator.indicator_type = IndicatorType::Url;
        submission.indicator.value = "http://".to_owned();
        assert_eq!(
            validate_submission(&submission),
            Err(ValidationError::InvalidUrl)
        );
    }

    #[test]
    fn valid_sha256_accepted() {
        let mut submission = sample_submission();
        submission.indicator.indicator_type = IndicatorType::FileHash;
        submission.indicator.value =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned();
        assert!(validate_submission(&submission).is_ok());
    }

    #[test]
    fn valid_md5_accepted() {
        let mut submission = sample_submission();
        submission.indicator.indicator_type = IndicatorType::FileHash;
        submission.indicator.value = "d41d8cd98f00b204e9800998ecf8427e".to_owned();
        assert!(validate_submission(&submission).is_ok());
    }

    #[test]
    fn invalid_hash_length_rejected() {
        let mut submission = sample_submission();
        submission.indicator.indicator_type = IndicatorType::FileHash;
        submission.indicator.value = "abc123".to_owned();
        assert_eq!(
            validate_submission(&submission),
            Err(ValidationError::InvalidFileHash)
        );
    }

    #[test]
    fn invalid_ip_address_rejected() {
        let mut submission = sample_submission();
        submission.indicator.indicator_type = IndicatorType::IpAddress;
        submission.indicator.value = "not.an.ip".to_owned();
        assert_eq!(
            validate_submission(&submission),
            Err(ValidationError::InvalidIpAddress)
        );
    }

    #[test]
    fn valid_ipv4_accepted() {
        let mut submission = sample_submission();
        submission.indicator.indicator_type = IndicatorType::IpAddress;
        submission.indicator.value = "192.168.1.1".to_owned();
        assert!(validate_submission(&submission).is_ok());
    }

    #[test]
    fn valid_ipv6_accepted() {
        let mut submission = sample_submission();
        submission.indicator.indicator_type = IndicatorType::IpAddress;
        submission.indicator.value = "::1".to_owned();
        assert!(validate_submission(&submission).is_ok());
    }

    #[test]
    fn serialize_round_trips() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let submission = sample_submission();
        let json = serialize_for_log(&submission)?;
        let decoded: FeedSubmission = serde_json::from_str(&json)?;
        assert_eq!(decoded, submission);
        Ok(())
    }

    #[test]
    fn deny_unknown_fields_rejects_extra_keys() {
        let json = r#"{
            "submitter": {
                "handle": "a",
                "trust_tier": "registered",
                "key_fingerprint": null,
                "extra": true
            },
            "indicator": {
                "indicator_type": "domain",
                "value": "evil.example",
                "confidence": "low"
            },
            "evidence": {
                "sample_hashes": [],
                "related_indicators": [],
                "description": "",
                "first_seen": null,
                "last_seen": null
            },
            "metadata": {
                "source": "",
                "tags": [],
                "expires_at": null
            }
        }"#;
        assert!(serde_json::from_str::<FeedSubmission>(json).is_err());
    }

    #[test]
    fn trust_tier_orders_anonymous_lowest() {
        assert!(TrustTier::Anonymous < TrustTier::Registered);
        assert!(TrustTier::Registered < TrustTier::Verified);
        assert!(TrustTier::Verified < TrustTier::Trusted);
    }
}
