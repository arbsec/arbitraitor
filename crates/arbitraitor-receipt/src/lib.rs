//! Immutable scan receipt generation and verification
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt::Write as _;
use std::io::Cursor;

use arbitraitor_model::finding::{Finding, FindingCategory, SourceLocation};
use arbitraitor_model::verdict::{Confidence, Severity, Verdict};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// Current receipt schema version.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Tamper-evident audit record for an inspected artifact.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// Receipt schema version. Currently [`CURRENT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Arbitraitor version that produced the receipt.
    pub arbitraitor_version: String,
    /// Digest of the effective configuration snapshot, when available.
    pub config_digest: Option<String>,
    /// Digest of the effective policy snapshot, when available.
    pub policy_digest: Option<String>,
    /// SHA-256 digest of the inspected artifact as lowercase hexadecimal.
    pub artifact_sha256: String,
    /// Size of the inspected artifact in bytes.
    pub artifact_size: u64,
    /// Optional artifact type label.
    pub artifact_type: Option<String>,
    /// Optional redacted retrieval metadata.
    pub retrieval: Option<RetrievalInfo>,
    /// Finding summaries included in the receipt.
    pub findings: Vec<FindingSummary>,
    /// Final policy verdict information.
    pub verdict: VerdictInfo,
    /// Optional release information.
    pub release: Option<ReleaseInfo>,
    /// Detector versions that contributed to this receipt.
    pub detector_versions: Vec<DetectorVersion>,
    /// Receipt creation and update timestamps.
    pub timestamps: ReceiptTimestamps,
    /// Optional detached signature over the canonical unsigned receipt.
    pub signature: Option<ReceiptSignature>,
}

impl Receipt {
    /// Return RFC 8785 JSON Canonicalization Scheme bytes for this receipt.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReceiptError> {
        serde_json_canonicalizer::to_vec(self).map_err(ReceiptError::Canonicalize)
    }

    /// Return canonical bytes with the signature field cleared.
    ///
    /// This is the exact payload signed by [`sign_receipt`] and verified by
    /// [`verify_receipt`], preventing recursive signatures.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, ReceiptError> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        unsigned.canonical_bytes()
    }
}

/// Redacted transport metadata for artifact retrieval.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalInfo {
    requested_url: String,
    final_url: Option<String>,
    redirect_chain: Vec<String>,
    status_code: Option<u16>,
    content_type: Option<String>,
    byte_count: Option<u64>,
    tls_version: Option<String>,
    peer_cert_fingerprint: Option<String>,
}

impl RetrievalInfo {
    /// Create retrieval metadata while redacting URL credentials and query strings.
    #[must_use]
    pub fn new(requested_url: impl AsRef<str>) -> Self {
        Self {
            requested_url: redact_url(requested_url.as_ref()),
            final_url: None,
            redirect_chain: Vec::new(),
            status_code: None,
            content_type: None,
            byte_count: None,
            tls_version: None,
            peer_cert_fingerprint: None,
        }
    }

    /// Set the final URL after redirects, redacting secrets.
    #[must_use]
    pub fn with_final_url(mut self, final_url: impl AsRef<str>) -> Self {
        self.final_url = Some(redact_url(final_url.as_ref()));
        self
    }

    /// Set the redirect chain, redacting every URL.
    #[must_use]
    pub fn with_redirect_chain<I, S>(mut self, redirect_chain: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.redirect_chain = redirect_chain
            .into_iter()
            .map(|url| redact_url(url.as_ref()))
            .collect();
        self
    }

    /// Set the HTTP status code.
    #[must_use]
    pub const fn with_status_code(mut self, status_code: u16) -> Self {
        self.status_code = Some(status_code);
        self
    }

    /// Set the response content type.
    #[must_use]
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Set the retrieved byte count.
    #[must_use]
    pub const fn with_byte_count(mut self, byte_count: u64) -> Self {
        self.byte_count = Some(byte_count);
        self
    }

    /// Set the negotiated TLS version.
    #[must_use]
    pub fn with_tls_version(mut self, tls_version: impl Into<String>) -> Self {
        self.tls_version = Some(tls_version.into());
        self
    }

    /// Set the peer certificate fingerprint.
    #[must_use]
    pub fn with_peer_cert_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.peer_cert_fingerprint = Some(fingerprint.into());
        self
    }

    /// Redacted originally requested URL.
    #[must_use]
    pub fn requested_url(&self) -> &str {
        &self.requested_url
    }

    /// Redacted final URL, if known.
    #[must_use]
    pub fn final_url(&self) -> Option<&str> {
        self.final_url.as_deref()
    }

    /// Redacted redirect chain.
    #[must_use]
    pub fn redirect_chain(&self) -> &[String] {
        &self.redirect_chain
    }
}

/// Finding subset recorded in receipts.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingSummary {
    /// Stable finding identifier.
    pub id: String,
    /// Finding category.
    pub category: FindingCategory,
    /// Finding severity.
    pub severity: Severity,
    /// Finding confidence.
    pub confidence: Confidence,
    /// Human-readable finding title.
    pub title: String,
    /// Optional source location.
    pub location: Option<SourceLocation>,
}

impl From<&Finding> for FindingSummary {
    fn from(finding: &Finding) -> Self {
        Self {
            id: finding.id.clone(),
            category: finding.category,
            severity: finding.severity,
            confidence: finding.confidence,
            title: finding.title.clone(),
            location: finding.location.clone(),
        }
    }
}

/// Policy verdict information included in receipts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictInfo {
    /// Final policy verdict.
    pub verdict: Verdict,
    /// Policy rule that decided the verdict, when known.
    pub deciding_rule: Option<String>,
    /// Safe, bounded policy trace entries.
    pub policy_trace: Vec<String>,
}

/// Release information included when an artifact is released.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseInfo {
    /// Release method.
    pub method: ReleaseMethod,
    /// Release destination, if applicable.
    pub destination: Option<String>,
    /// Whether SHA-256 was re-verified immediately before release.
    pub sha256_verified: bool,
    /// Release timestamp.
    pub timestamp: String,
}

/// Supported artifact release methods.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseMethod {
    /// Release to a file path.
    File,
    /// Release to standard output.
    Stdout,
    /// Release to controlled execution.
    Execute,
}

/// Detector identity and version included in receipts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorVersion {
    /// Detector identifier.
    pub id: String,
    /// Detector version string.
    pub version: String,
}

/// Receipt timestamps.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptTimestamps {
    /// Receipt creation timestamp.
    pub created: String,
    /// Receipt last-modified timestamp.
    pub modified: String,
}

/// Minisign signature metadata embedded in a signed receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptSignature {
    /// Signature algorithm label.
    pub algorithm: String,
    /// Minisign key identifier as uppercase hexadecimal.
    pub key_id: String,
    /// Minisign signature box bytes.
    pub signature_bytes: Vec<u8>,
}

/// Receipt wrapped after signing.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReceipt {
    /// Receipt containing a signature.
    pub receipt: Receipt,
}

/// Builder for constructing receipts incrementally.
#[derive(Clone, Debug)]
pub struct ReceiptBuilder {
    receipt: Receipt,
}

impl ReceiptBuilder {
    /// Start a receipt for the supplied artifact identity and verdict.
    #[must_use]
    pub fn new(
        arbitraitor_version: impl Into<String>,
        artifact_sha256: impl Into<String>,
        artifact_size: u64,
        verdict: VerdictInfo,
        timestamps: ReceiptTimestamps,
    ) -> Self {
        Self {
            receipt: Receipt {
                schema_version: CURRENT_SCHEMA_VERSION,
                arbitraitor_version: arbitraitor_version.into(),
                config_digest: None,
                policy_digest: None,
                artifact_sha256: artifact_sha256.into(),
                artifact_size,
                artifact_type: None,
                retrieval: None,
                findings: Vec::new(),
                verdict,
                release: None,
                detector_versions: Vec::new(),
                timestamps,
                signature: None,
            },
        }
    }

    /// Set the configuration digest.
    #[must_use]
    pub fn config_digest(mut self, digest: impl Into<String>) -> Self {
        self.receipt.config_digest = Some(digest.into());
        self
    }

    /// Set the policy digest.
    #[must_use]
    pub fn policy_digest(mut self, digest: impl Into<String>) -> Self {
        self.receipt.policy_digest = Some(digest.into());
        self
    }

    /// Set the artifact type label.
    #[must_use]
    pub fn artifact_type(mut self, artifact_type: impl Into<String>) -> Self {
        self.receipt.artifact_type = Some(artifact_type.into());
        self
    }

    /// Set retrieval metadata.
    #[must_use]
    pub fn retrieval(mut self, retrieval: RetrievalInfo) -> Self {
        self.receipt.retrieval = Some(retrieval);
        self
    }

    /// Add a finding summary.
    #[must_use]
    pub fn finding(mut self, finding: FindingSummary) -> Self {
        self.receipt.findings.push(finding);
        self
    }

    /// Add multiple finding summaries.
    #[must_use]
    pub fn findings<I>(mut self, findings: I) -> Self
    where
        I: IntoIterator<Item = FindingSummary>,
    {
        self.receipt.findings.extend(findings);
        self
    }

    /// Set release metadata.
    #[must_use]
    pub fn release(mut self, release: ReleaseInfo) -> Self {
        self.receipt.release = Some(release);
        self
    }

    /// Add detector version metadata.
    #[must_use]
    pub fn detector_version(mut self, detector_version: DetectorVersion) -> Self {
        self.receipt.detector_versions.push(detector_version);
        self
    }

    /// Finish the receipt.
    #[must_use]
    pub fn build(self) -> Receipt {
        self.receipt
    }
}

/// Errors produced while serializing or signing receipts.
#[derive(Debug, Error)]
pub enum ReceiptError {
    /// Receipt canonicalization failed.
    #[error("receipt canonicalization failed: {0}")]
    Canonicalize(serde_json::Error),
    /// Receipt signing failed.
    #[error("receipt signing failed: {reason}")]
    Sign {
        /// Safe diagnostic reason for signing failure.
        reason: String,
    },
}

/// Errors produced while verifying signed receipts.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The signed receipt did not contain a signature.
    #[error("receipt signature is missing")]
    MissingSignature,
    /// Receipt canonicalization failed before verification.
    #[error("receipt canonicalization failed: {0}")]
    Canonicalize(serde_json::Error),
    /// Signature bytes were not a valid minisign signature box.
    #[error("receipt signature is malformed: {reason}")]
    MalformedSignature {
        /// Safe diagnostic reason for malformed signature data.
        reason: String,
    },
    /// Signature verification failed.
    #[error("receipt signature is invalid: {reason}")]
    InvalidSignature {
        /// Safe diagnostic reason for verification failure.
        reason: String,
    },
}

/// Sign a receipt using minisign over its canonical unsigned form.
///
/// # Errors
///
/// Returns an error if canonicalization or minisign signing fails.
pub fn sign_receipt(
    receipt: &Receipt,
    key: &minisign::KeyPair,
) -> Result<SignedReceipt, ReceiptError> {
    let canonical = receipt.unsigned_canonical_bytes()?;
    let signature = minisign::sign(
        Some(&key.pk),
        &key.sk,
        Cursor::new(canonical),
        Some("arbitraitor receipt"),
        Some("signature from arbitraitor receipt key"),
    )
    .map_err(|error| ReceiptError::Sign {
        reason: error.to_string(),
    })?;

    let mut signed_receipt = receipt.clone();
    signed_receipt.signature = Some(ReceiptSignature {
        algorithm: "minisign-ed25519-blake2b-prehashed".to_owned(),
        key_id: hex_upper(key.pk.keynum()),
        signature_bytes: signature.to_bytes(),
    });

    Ok(SignedReceipt {
        receipt: signed_receipt,
    })
}

/// Verify a minisign-signed receipt over its canonical unsigned form.
///
/// # Errors
///
/// Returns an error when the receipt has no signature, the signature is
/// malformed, canonicalization fails, or minisign verification fails.
pub fn verify_receipt(
    signed: &SignedReceipt,
    public_key: &minisign::PublicKey,
) -> Result<(), VerifyError> {
    let signature = signed
        .receipt
        .signature
        .as_ref()
        .ok_or(VerifyError::MissingSignature)?;
    let signature_text = std::str::from_utf8(&signature.signature_bytes).map_err(|error| {
        VerifyError::MalformedSignature {
            reason: error.to_string(),
        }
    })?;
    let signature_box = minisign::SignatureBox::from_string(signature_text).map_err(|error| {
        VerifyError::MalformedSignature {
            reason: error.to_string(),
        }
    })?;
    let canonical = signed
        .receipt
        .unsigned_canonical_bytes()
        .map_err(|error| match error {
            ReceiptError::Canonicalize(error) => VerifyError::Canonicalize(error),
            ReceiptError::Sign { reason } => VerifyError::InvalidSignature { reason },
        })?;

    minisign::verify(
        public_key,
        &signature_box,
        Cursor::new(canonical),
        true,
        false,
        false,
    )
    .map_err(|error| VerifyError::InvalidSignature {
        reason: error.to_string(),
    })
}

/// Redact credentials and query strings from a URL-like string.
#[must_use]
pub fn redact_url(value: &str) -> String {
    match Url::parse(value) {
        Ok(mut url) => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => redact_url_fallback(value),
    }
}

fn redact_url_fallback(value: &str) -> String {
    let without_fragment = value.split_once('#').map_or(value, |(prefix, _)| prefix);
    let without_query = without_fragment
        .split_once('?')
        .map_or(without_fragment, |(prefix, _)| prefix);
    if let Some((scheme, rest)) = without_query.split_once("://") {
        let authority_end = rest.find('/').unwrap_or(rest.len());
        let (authority, path) = rest.split_at(authority_end);
        if let Some((_, host)) = authority.rsplit_once('@') {
            return format!("{scheme}://{host}{path}");
        }
    }
    without_query.to_owned()
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02X}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample_receipt() -> Receipt {
        ReceiptBuilder::new(
            "0.1.0",
            "ab".repeat(32),
            12,
            VerdictInfo {
                verdict: Verdict::Warn,
                deciding_rule: Some("rule.warn.suspicious".to_owned()),
                policy_trace: vec!["matched suspicious script rule".to_owned()],
            },
            ReceiptTimestamps {
                created: "2026-06-17T00:00:00Z".to_owned(),
                modified: "2026-06-17T00:00:00Z".to_owned(),
            },
        )
        .config_digest("config:01")
        .policy_digest("policy:01")
        .artifact_type("shell-script")
        .retrieval(
            RetrievalInfo::new("https://user:secret@example.com/install.sh?token=secret#frag")
                .with_final_url("https://example.com/releases/install.sh?sig=secret")
                .with_redirect_chain(["https://user:pass@example.com/redirect?token=secret"])
                .with_status_code(200)
                .with_content_type("text/x-shellscript")
                .with_byte_count(12)
                .with_tls_version("TLSv1.3")
                .with_peer_cert_fingerprint("sha256:abcd"),
        )
        .finding(FindingSummary {
            id: "finding-1".to_owned(),
            category: FindingCategory::SuspiciousScriptBehavior,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "suspicious shell behavior".to_owned(),
            location: None,
        })
        .release(ReleaseInfo {
            method: ReleaseMethod::File,
            destination: Some("/tmp/install.sh".to_owned()),
            sha256_verified: true,
            timestamp: "2026-06-17T00:00:01Z".to_owned(),
        })
        .detector_version(DetectorVersion {
            id: "detector.shell".to_owned(),
            version: "1.2.3".to_owned(),
        })
        .build()
    }

    #[test]
    fn receipt_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let receipt = sample_receipt();
        let json = serde_json::to_string(&receipt)?;
        let decoded: Receipt = serde_json::from_str(&json)?;
        assert_eq!(decoded, receipt);
        Ok(())
    }

    #[test]
    fn canonical_form_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let receipt = sample_receipt();
        assert_eq!(receipt.canonical_bytes()?, receipt.canonical_bytes()?);
        Ok(())
    }

    #[test]
    fn deny_unknown_fields_rejects_extra_fields() {
        let json = r#"{"schema_version":1,"arbitraitor_version":"0.1.0","config_digest":null,"policy_digest":null,"artifact_sha256":"abababababababababababababababababababababababababababababababab","artifact_size":1,"artifact_type":null,"retrieval":null,"findings":[],"verdict":{"verdict":"pass","deciding_rule":null,"policy_trace":[]},"release":null,"detector_versions":[],"timestamps":{"created":"2026-06-17T00:00:00Z","modified":"2026-06-17T00:00:00Z"},"signature":null,"extra":true}"#;
        assert!(serde_json::from_str::<Receipt>(json).is_err());
    }

    #[test]
    fn redacts_url_credentials_queries_and_fragments() {
        let redacted = redact_url("https://user:password@example.com/path?token=secret#fragment");
        assert_eq!(redacted, "https://example.com/path");
        assert!(!redacted.contains("user"));
        assert!(!redacted.contains("password"));
        assert!(!redacted.contains("token"));
    }

    #[test]
    fn schema_version_is_present() -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_value(sample_receipt())?;
        assert_eq!(json["schema_version"], CURRENT_SCHEMA_VERSION);
        Ok(())
    }

    #[test]
    fn signs_and_verifies_receipt() -> Result<(), Box<dyn std::error::Error>> {
        let key = minisign::KeyPair::generate_unencrypted_keypair()?;
        let receipt = sample_receipt();
        let signed = sign_receipt(&receipt, &key)?;
        verify_receipt(&signed, &key.pk)?;

        let mut tampered = signed.clone();
        tampered.receipt.artifact_size += 1;
        assert!(matches!(
            verify_receipt(&tampered, &key.pk),
            Err(VerifyError::InvalidSignature { .. })
        ));
        Ok(())
    }

    fn receipt_strategy() -> impl Strategy<Value = Receipt> {
        (
            "[a-z0-9.-]{1,24}",
            prop::collection::vec("[0-9a-f]{64}", 1..2),
            0_u64..1_000_000,
            prop::option::of("[a-z0-9:/._-]{1,32}"),
            prop::collection::vec("[a-z0-9._-]{1,16}", 0..8),
        )
            .prop_map(|(version, digests, size, artifact_type, trace)| {
                let mut builder = ReceiptBuilder::new(
                    version,
                    digests[0].clone(),
                    size,
                    VerdictInfo {
                        verdict: Verdict::Pass,
                        deciding_rule: None,
                        policy_trace: trace,
                    },
                    ReceiptTimestamps {
                        created: "2026-06-17T00:00:00Z".to_owned(),
                        modified: "2026-06-17T00:00:00Z".to_owned(),
                    },
                );
                if let Some(artifact_type) = artifact_type {
                    builder = builder.artifact_type(artifact_type);
                }
                builder.build()
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn canonical_form_is_deterministic_for_random_receipts(receipt in receipt_strategy()) {
            prop_assert_eq!(receipt.canonical_bytes()?, receipt.canonical_bytes()?);
        }
    }
}
