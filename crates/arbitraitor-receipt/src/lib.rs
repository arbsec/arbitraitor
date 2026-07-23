//! Immutable scan receipt generation and verification
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod signing;
pub use signing::{
    MinisignSigner, ReceiptSigner, Signature, SignerError, SigningMethod, StubSigner,
};

use std::fmt::Write as _;
use std::io::Cursor;
use std::time::SystemTime;

use arbitraitor_analysis::PayloadGraph;
use arbitraitor_exec::EffectiveControls;
use arbitraitor_model::finding::{DetectorProvenance, Finding, FindingCategory, SourceLocation};
use arbitraitor_model::ids::{Sha256Digest, Sha256DigestParseError};
use arbitraitor_model::taxonomy::TaxonomyRef;
use arbitraitor_model::transport::RedirectCredentialSecrecy;
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
    /// Security-relevant operator decisions recorded for audit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_trail: Vec<AuditEvent>,
    /// Binary provenance for subprocess detectors (sha256, version, ruleset digest).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detector_provenance: Vec<DetectorProvenance>,
    /// Receipt creation and update timestamps.
    pub timestamps: ReceiptTimestamps,
    /// Per-control effective-controls matrix (ADR-0007). Present only for
    /// contained execution contexts; `None` for inspect/mediated.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub effective_controls: Option<EffectiveControls>,
    /// Metadata from allow rules that authorized release.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_rule_metadata: Vec<AllowRuleMetadata>,
    /// Plan-bound approval and override binding metadata, when execution used approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalInfo>,
    /// Identity of the verifier that accepted a Sigstore bundle (ADR-0014,
    /// issue #457). Records the cosign/sigstore-rust version used for
    /// verification so downstream consumers can audit which verifier accepted
    /// the attestation. `None` when no Sigstore verification was performed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_identity: Option<String>,
    /// Payload graph recording artifacts and their relationships (spec §20,
    /// issue #517). `None` when no recursive payload discovery was performed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_graph: Option<PayloadGraph>,
    /// Optional detached signature over the canonical unsigned receipt.
    pub signature: Option<ReceiptSignature>,
    /// Signatures produced by [`ReceiptSigner`] adapters (spec §31.3).
    ///
    /// Multiple signatures may be attached when more than one signing method
    /// is requested. The canonical bytes exclude this field (see
    /// [`Receipt::unsigned_canonical_bytes`]) so signatures are not
    /// self-referential (ADR-0014).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<Signature>,
}

/// Metadata from an allow rule recorded in the receipt audit trail.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRuleMetadata {
    /// Rule identifier that supplied this metadata.
    pub rule_id: String,

    /// Expiration time for the allow, when declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<SystemTime>,

    /// Scope for the allow: `user`, `project`, or `org`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Identity that created the allow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,

    /// Reason why the allow was granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Plan-bound approval and override metadata embedded in execution receipts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalInfo {
    /// Digest of the ADR-0013 canonical operation plan bound by the approval.
    pub plan_digest: Sha256Digest,
    /// SHA-256 digest of the artifact bound by the approval.
    pub artifact_digest: Sha256Digest,
    /// Approval expiry time, when the binding is time-limited.
    pub expiry: Option<SystemTime>,
    /// Unique approval nonce preventing replay of the binding.
    pub nonce: String,
    /// Network, filesystem, and process capabilities bound by the approval.
    pub bound_capabilities: Vec<String>,
    /// Human-readable override reason, when this approval was an override.
    pub override_reason: Option<String>,
    /// Override scope, when this approval was scoped.
    pub override_scope: Option<String>,
    /// Execution exit status observed for the approved operation.
    pub exit_status: Option<i32>,
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
        unsigned.signatures.clear();
        unsigned.canonical_bytes()
    }

    /// Exports the receipt as an in-toto Statement envelope (spec §31.3.1,
    /// ADR-0023). The canonical on-disk receipt format (RFC 8785 JCS) is
    /// NOT changed. This is a derived, optional export format for
    /// interoperability with supply-chain tools like GUAC, Sigstore, and
    /// in-toto verifylib (spec §21.9).
    ///
    /// # Errors
    ///
    /// Returns an error if serialization of the Statement or its predicate
    /// fails.
    pub fn to_intoto_statement(&self) -> Result<IntotoStatement, ReceiptError> {
        let artifact_sha256 = self
            .artifact_sha256
            .parse::<Sha256Digest>()
            .map_err(ReceiptError::InvalidArtifactDigest)?;
        let predicate = serde_json::to_value(self).map_err(ReceiptError::Canonicalize)?;
        Ok(IntotoStatement {
            statement_type: "https://in-toto.io/Statement/v1".to_owned(),
            subject: vec![IntotoSubject {
                name: format!("sha256:{artifact_sha256}"),
                digest: IntotoDigest {
                    sha256: artifact_sha256,
                },
            }],
            predicate_type: "https://arbitraitor.dev/verdict/v1".to_owned(),
            predicate,
        })
    }
}

/// in-toto Statement v1 envelope (spec §31.3.1, ADR-0023).
///
/// Derived from the canonical RFC 8785 JCS receipt. The Statement is
/// signed with the same key/capability as the canonical receipt and the
/// signature envelope is DSSE per in-toto conventions.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntotoStatement {
    /// Fixed: `https://in-toto.io/Statement/v1`.
    #[serde(rename = "_type")]
    pub statement_type: String,
    /// Artifact subjects the statement attests.
    pub subject: Vec<IntotoSubject>,
    /// Fixed: `https://arbitraitor.dev/verdict/v1`.
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// Full Arbitraitor receipt object, verbatim.
    pub predicate: serde_json::Value,
}

/// A subject entry inside an in-toto Statement.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntotoSubject {
    /// Subject name, e.g. `sha256:<hex>`.
    pub name: String,
    /// Digest map keyed by algorithm.
    pub digest: IntotoDigest,
}

/// SHA-256 digest map for in-toto subject.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntotoDigest {
    /// SHA-256 hex digest.
    pub sha256: Sha256Digest,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    redirect_credential_secrecy: Option<RedirectCredentialSecrecy>,
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
            redirect_credential_secrecy: None,
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

    /// Set the redirect credential-secrecy outcome.
    #[must_use]
    pub const fn with_redirect_credential_secrecy(
        mut self,
        secrecy: RedirectCredentialSecrecy,
    ) -> Self {
        self.redirect_credential_secrecy = Some(secrecy);
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
    /// Representative evidence snippet or matched pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Recommended remediation guidance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// External finding references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    /// Machine-readable taxonomy mappings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taxonomies: Vec<TaxonomyRef>,
}

impl From<&Finding> for FindingSummary {
    fn from(finding: &Finding) -> Self {
        let evidence = finding
            .evidence
            .iter()
            .find_map(|evidence| evidence.content.clone())
            .or_else(|| {
                finding
                    .evidence
                    .first()
                    .map(|evidence| evidence.description.clone())
            });
        Self {
            id: finding.id.clone(),
            category: finding.category,
            severity: finding.severity,
            confidence: finding.confidence,
            title: finding.title.clone(),
            location: finding.location.clone(),
            evidence,
            remediation: finding.remediation.clone(),
            references: finding.references.clone(),
            taxonomies: finding.taxonomies.clone(),
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

/// A security-relevant decision captured in the receipt audit trail.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    /// Stable event kind.
    pub kind: String,
    /// Human-readable audit detail.
    pub detail: String,
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
                audit_trail: Vec::new(),
                detector_provenance: Vec::new(),
                timestamps,
                effective_controls: None,
                allow_rule_metadata: Vec::new(),
                approval: None,
                verifier_identity: None,
                payload_graph: None,
                signature: None,
                signatures: Vec::new(),
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

    /// Add a security audit event.
    #[must_use]
    pub fn audit_event(mut self, event: AuditEvent) -> Self {
        self.receipt.audit_trail.push(event);
        self
    }

    /// Add detector binary provenance metadata (subprocess detectors).
    #[must_use]
    pub fn detector_provenance(mut self, provenance: DetectorProvenance) -> Self {
        self.receipt.detector_provenance.push(provenance);
        self
    }

    /// Set the per-control effective-controls matrix (ADR-0007).
    #[must_use]
    pub fn effective_controls(mut self, controls: EffectiveControls) -> Self {
        self.receipt.effective_controls = Some(controls);
        self
    }

    /// Add allow-rule metadata to the receipt audit trail.
    #[must_use]
    pub fn allow_rule_metadata<I>(mut self, metadata: I) -> Self
    where
        I: IntoIterator<Item = AllowRuleMetadata>,
    {
        self.receipt.allow_rule_metadata.extend(metadata);
        self
    }

    /// Set plan-bound approval metadata.
    #[must_use]
    pub fn approval(mut self, approval: ApprovalInfo) -> Self {
        self.receipt.approval = Some(approval);
        self
    }

    /// Set the verifier identity for Sigstore bundle verification (ADR-0014,
    /// issue #457).
    #[must_use]
    pub fn verifier_identity(mut self, identity: impl Into<String>) -> Self {
        self.receipt.verifier_identity = Some(identity.into());
        self
    }

    /// Set the payload graph (spec §20, issue #517).
    #[must_use]
    pub fn payload_graph(mut self, graph: PayloadGraph) -> Self {
        self.receipt.payload_graph = Some(graph);
        self
    }

    /// Add a receipt signature (spec §31.3).
    #[must_use]
    pub fn signature(mut self, signature: Signature) -> Self {
        self.receipt.signatures.push(signature);
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
    /// Receipt artifact digest was not valid SHA-256 hex.
    #[error("receipt artifact SHA-256 is invalid: {0}")]
    InvalidArtifactDigest(Sha256DigestParseError),
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
            ReceiptError::InvalidArtifactDigest(error) => VerifyError::InvalidSignature {
                reason: error.to_string(),
            },
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
    use std::time::{Duration, UNIX_EPOCH};

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
                .with_peer_cert_fingerprint("sha256:abcd")
                .with_redirect_credential_secrecy(RedirectCredentialSecrecy::Ok),
        )
        .finding(FindingSummary {
            id: "finding-1".to_owned(),
            category: FindingCategory::SuspiciousScriptBehavior,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "suspicious shell behavior".to_owned(),
            location: None,
            evidence: None,
            remediation: None,
            references: Vec::new(),
            taxonomies: Vec::new(),
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
        .detector_provenance(DetectorProvenance {
            binary_sha256: Some("sha256:abcd".to_owned()),
            binary_version: Some("tirith 0.4.1".to_owned()),
            ruleset_digest: Some("sha256:rules".to_owned()),
        })
        .build()
    }

    fn sample_digest(value: u8) -> Sha256Digest {
        Sha256Digest::new([value; 32])
    }

    fn sample_approval(exit_status: Option<i32>) -> ApprovalInfo {
        ApprovalInfo {
            plan_digest: sample_digest(0x11),
            artifact_digest: sample_digest(0xab),
            expiry: Some(UNIX_EPOCH + Duration::from_mins(5)),
            nonce: "approval-nonce-1".to_owned(),
            bound_capabilities: vec![
                "process:execute".to_owned(),
                "network:isolated".to_owned(),
                "filesystem:none".to_owned(),
            ],
            override_reason: Some("policy prompt override".to_owned()),
            override_scope: Some("single execution".to_owned()),
            exit_status,
        }
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
    fn receipt_round_trips_with_approval_info() -> Result<(), Box<dyn std::error::Error>> {
        let receipt = ReceiptBuilder::new(
            "0.1.0",
            sample_digest(0xab).to_string(),
            12,
            VerdictInfo {
                verdict: Verdict::Prompt,
                deciding_rule: Some("rule.prompt.execution".to_owned()),
                policy_trace: vec!["approval required".to_owned()],
            },
            ReceiptTimestamps {
                created: "2026-06-17T00:00:00Z".to_owned(),
                modified: "2026-06-17T00:00:00Z".to_owned(),
            },
        )
        .approval(sample_approval(Some(0)))
        .build();

        let json = serde_json::to_string(&receipt)?;
        let decoded: Receipt = serde_json::from_str(&json)?;

        assert_eq!(decoded, receipt);
        assert_eq!(
            decoded.approval.as_ref().and_then(|info| info.exit_status),
            Some(0)
        );
        Ok(())
    }

    #[test]
    fn receipt_round_trips_with_allow_rule_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let expiry = UNIX_EPOCH + Duration::from_mins(10);
        let metadata = AllowRuleMetadata {
            rule_id: "allow-url-pattern".to_owned(),
            expiry: Some(expiry),
            scope: Some("project".to_owned()),
            creator: Some("security@example.invalid".to_owned()),
            reason: Some("temporary exception while upstream release is fixed".to_owned()),
        };
        let receipt = ReceiptBuilder::new(
            "0.1.0",
            sample_digest(0xcd).to_string(),
            12,
            VerdictInfo {
                verdict: Verdict::Pass,
                deciding_rule: Some("allow-url-pattern".to_owned()),
                policy_trace: vec!["matched allow rule".to_owned()],
            },
            ReceiptTimestamps {
                created: "2026-06-17T00:00:00Z".to_owned(),
                modified: "2026-06-17T00:00:00Z".to_owned(),
            },
        )
        .allow_rule_metadata([metadata.clone()])
        .build();

        let json = serde_json::to_string(&receipt)?;
        let decoded: Receipt = serde_json::from_str(&json)?;

        assert_eq!(decoded.allow_rule_metadata, vec![metadata]);
        Ok(())
    }

    #[test]
    fn receipt_without_approval_info_still_parses() -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&sample_receipt())?;

        let decoded: Receipt = serde_json::from_str(&json)?;

        assert_eq!(decoded.approval, None);
        Ok(())
    }

    #[test]
    fn verifier_identity_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let receipt = ReceiptBuilder::new(
            "0.1.0",
            sample_digest(0xab).to_string(),
            12,
            VerdictInfo {
                verdict: Verdict::Pass,
                deciding_rule: None,
                policy_trace: Vec::new(),
            },
            ReceiptTimestamps {
                created: "2026-06-17T00:00:00Z".to_owned(),
                modified: "2026-06-17T00:00:00Z".to_owned(),
            },
        )
        .verifier_identity("cosign 3.0.5")
        .build();

        let json = serde_json::to_string(&receipt)?;
        let decoded: Receipt = serde_json::from_str(&json)?;

        assert_eq!(decoded.verifier_identity.as_deref(), Some("cosign 3.0.5"));
        Ok(())
    }

    #[test]
    fn verifier_identity_absent_when_not_set() -> Result<(), Box<dyn std::error::Error>> {
        let receipt = sample_receipt();
        let json = serde_json::to_string(&receipt)?;
        assert!(
            !json.contains("verifier_identity"),
            "verifier_identity must be omitted when None"
        );
        let decoded: Receipt = serde_json::from_str(&json)?;
        assert_eq!(decoded.verifier_identity, None);
        Ok(())
    }

    #[test]
    fn payload_graph_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        use arbitraitor_analysis::{PayloadEdgeType, PayloadGraph, payload_graph::PayloadNode};
        use arbitraitor_artifact::ArtifactType;

        let mut graph = PayloadGraph::new();
        let root = graph.add_node(PayloadNode {
            digest: sample_digest(0x01),
            name: "install.sh".to_owned(),
            artifact_type: Some(ArtifactType::ShellScript(
                arbitraitor_artifact::ShellKind::Bash,
            )),
        });
        let tool = graph.add_node(PayloadNode {
            digest: sample_digest(0x02),
            name: "tool.tar.gz".to_owned(),
            artifact_type: Some(ArtifactType::GzipCompressed),
        });
        graph.add_edge(root, tool, PayloadEdgeType::Downloads)?;

        let receipt = ReceiptBuilder::new(
            "0.1.0",
            sample_digest(0x01).to_string(),
            12,
            VerdictInfo {
                verdict: Verdict::Pass,
                deciding_rule: None,
                policy_trace: Vec::new(),
            },
            ReceiptTimestamps {
                created: "2026-06-17T00:00:00Z".to_owned(),
                modified: "2026-06-17T00:00:00Z".to_owned(),
            },
        )
        .payload_graph(graph)
        .build();

        let json = serde_json::to_string(&receipt)?;
        let decoded: Receipt = serde_json::from_str(&json)?;

        let decoded_graph = decoded
            .payload_graph
            .as_ref()
            .ok_or("payload graph missing")?;
        assert_eq!(decoded_graph.nodes.len(), 2);
        assert_eq!(decoded_graph.edges.len(), 1);
        assert_eq!(decoded_graph.edges[0].edge_type, PayloadEdgeType::Downloads);
        Ok(())
    }

    #[test]
    fn payload_graph_absent_when_not_set() -> Result<(), Box<dyn std::error::Error>> {
        let receipt = sample_receipt();
        let json = serde_json::to_string(&receipt)?;
        assert!(
            !json.contains("payload_graph"),
            "payload_graph must be omitted when None"
        );
        let decoded: Receipt = serde_json::from_str(&json)?;
        assert_eq!(decoded.payload_graph, None);
        Ok(())
    }

    #[test]
    fn null_approval_info_does_not_change_canonical_bytes() -> Result<(), Box<dyn std::error::Error>>
    {
        let receipt = sample_receipt();
        let mut value = serde_json::to_value(&receipt)?;
        let object = value
            .as_object_mut()
            .ok_or("receipt JSON must be an object")?;
        object.insert("approval".to_owned(), serde_json::Value::Null);
        let decoded: Receipt = serde_json::from_value(value)?;

        assert_eq!(decoded.approval, None);
        assert_eq!(decoded.canonical_bytes()?, receipt.canonical_bytes()?);
        assert!(
            !serde_json::to_value(&decoded)?
                .as_object()
                .ok_or("receipt JSON must be an object")?
                .contains_key("approval")
        );
        Ok(())
    }

    proptest! {
        #[test]
        fn retrieval_info_redacts_credential_text_in_receipts(secret in "SECRET-[A-Za-z0-9]{16,64}") {
            let requested = format!("https://user:{secret}@example.com/artifact?api_key={secret}#{secret}");
            let redirected = format!("https://example.com/redirect?signature={secret}#{secret}");
            let retrieval = RetrievalInfo::new(&requested)
                .with_final_url(&redirected)
                .with_redirect_chain([requested.as_str(), redirected.as_str()])
                .with_redirect_credential_secrecy(RedirectCredentialSecrecy::BearerLeaked);
            let json = match serde_json::to_string(&retrieval) {
                Ok(json) => json,
                Err(error) => {
                    prop_assert!(false, "retrieval info must serialize: {error}");
                    String::new()
                }
            };

            prop_assert!(!json.contains(&secret));
            prop_assert!(json.contains("bearer_leaked"));
        }
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
    fn effective_controls_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        use arbitraitor_exec::{ControlStatus, EffectiveControl};

        let controls = EffectiveControls {
            filesystem_isolation: Some(EffectiveControl {
                requested: true,
                applied: ControlStatus::Enforced,
                proof: Some("landlock".to_owned()),
            }),
            network_isolation: Some(EffectiveControl {
                requested: true,
                applied: ControlStatus::Enforced,
                proof: Some("network-namespace".to_owned()),
            }),
            process_tree_control: Some(EffectiveControl {
                requested: true,
                applied: ControlStatus::Partial,
                proof: Some("pid-namespace".to_owned()),
            }),
            privilege_suppression: Some(EffectiveControl {
                requested: true,
                applied: ControlStatus::Enforced,
                proof: Some("no-new-privs".to_owned()),
            }),
            syscall_filtering: Some(EffectiveControl {
                requested: true,
                applied: ControlStatus::Enforced,
                proof: Some("seccomp-bpf".to_owned()),
            }),
            resource_limits: Some(EffectiveControl {
                requested: true,
                applied: ControlStatus::Enforced,
                proof: Some("setrlimit".to_owned()),
            }),
            landlock_abi_version: Some(serde_json::from_value(serde_json::json!(7))?),
            io_uring_available: Some(false),
            userns_available: Some(true),
            container_runtime: None,
        };
        let receipt = ReceiptBuilder::new(
            "0.1.0",
            "ab".repeat(32),
            1,
            VerdictInfo {
                verdict: Verdict::Pass,
                deciding_rule: None,
                policy_trace: Vec::new(),
            },
            ReceiptTimestamps {
                created: "2026-06-17T00:00:00Z".to_owned(),
                modified: "2026-06-17T00:00:00Z".to_owned(),
            },
        )
        .effective_controls(controls.clone())
        .build();

        let json = serde_json::to_string(&receipt)?;
        assert!(
            json.contains("effective_controls"),
            "serialized receipt must include effective_controls"
        );
        assert!(
            json.contains("landlock_abi_version"),
            "serialized receipt must include effective Landlock ABI version"
        );
        assert!(
            json.contains("userns_available"),
            "serialized receipt must include user namespace availability"
        );
        let decoded: Receipt = serde_json::from_str(&json)?;
        assert_eq!(decoded.effective_controls, Some(controls));
        Ok(())
    }

    #[test]
    fn effective_controls_absent_when_not_set() -> Result<(), Box<dyn std::error::Error>> {
        let receipt = sample_receipt();
        let json = serde_json::to_string(&receipt)?;
        assert!(
            !json.contains("effective_controls"),
            "effective_controls must be skipped when None"
        );
        Ok(())
    }

    #[test]
    fn effective_controls_accepts_legacy_json_without_landlock_abi()
    -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"filesystem_isolation":{"requested":true,"applied":"enforced","proof":"landlock"},"network_isolation":{"requested":true,"applied":"enforced","proof":"network-namespace"},"process_tree_control":{"requested":true,"applied":"enforced","proof":"pid-namespace"},"privilege_suppression":{"requested":true,"applied":"enforced","proof":"no-new-privs"},"syscall_filtering":{"requested":true,"applied":"enforced","proof":"seccomp-bpf"},"resource_limits":{"requested":true,"applied":"enforced","proof":"setrlimit"}}"#;
        let controls: EffectiveControls = serde_json::from_str(json)?;
        assert_eq!(controls.landlock_abi_version, None);
        assert_eq!(controls.userns_available, None);
        assert_eq!(controls.container_runtime, None);
        Ok(())
    }

    #[test]
    fn effective_controls_omits_absent_landlock_abi() -> Result<(), Box<dyn std::error::Error>> {
        use arbitraitor_exec::{ControlStatus, EffectiveControl};

        let controls = EffectiveControls {
            filesystem_isolation: Some(EffectiveControl {
                requested: true,
                applied: ControlStatus::Enforced,
                proof: Some("landlock".to_owned()),
            }),
            landlock_abi_version: None,
            ..EffectiveControls::default()
        };
        let json = serde_json::to_string(&controls)?;
        assert!(!json.contains("landlock_abi_version"));
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

    #[test]
    fn receipt_with_signatures_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let receipt = ReceiptBuilder::new(
            "0.1.0",
            sample_digest(0xab).to_string(),
            12,
            VerdictInfo {
                verdict: Verdict::Pass,
                deciding_rule: None,
                policy_trace: Vec::new(),
            },
            ReceiptTimestamps {
                created: "2026-06-17T00:00:00Z".to_owned(),
                modified: "2026-06-17T00:00:00Z".to_owned(),
            },
        )
        .signature(Signature {
            method: SigningMethod::Minisign,
            key_id: Some("ABCD1234".to_owned()),
            signature: vec![0_u8, 1, 2, 3],
        })
        .signature(Signature {
            method: SigningMethod::Tpm,
            key_id: None,
            signature: vec![0xFF; 16],
        })
        .build();

        let json = serde_json::to_string(&receipt)?;
        let decoded: Receipt = serde_json::from_str(&json)?;
        assert_eq!(decoded, receipt);
        assert_eq!(decoded.signatures.len(), 2);
        assert_eq!(decoded.signatures[0].method, SigningMethod::Minisign);
        assert_eq!(decoded.signatures[1].method, SigningMethod::Tpm);
        Ok(())
    }

    #[test]
    fn receipt_without_signatures_omits_field() -> Result<(), Box<dyn std::error::Error>> {
        let receipt = sample_receipt();
        let json = serde_json::to_string(&receipt)?;
        assert!(
            !json.contains("signatures"),
            "empty signatures must be omitted from JSON"
        );
        Ok(())
    }

    #[test]
    fn unsigned_canonical_bytes_clears_signatures() -> Result<(), Box<dyn std::error::Error>> {
        let receipt = ReceiptBuilder::new(
            "0.1.0",
            sample_digest(0xab).to_string(),
            12,
            VerdictInfo {
                verdict: Verdict::Pass,
                deciding_rule: None,
                policy_trace: Vec::new(),
            },
            ReceiptTimestamps {
                created: "2026-06-17T00:00:00Z".to_owned(),
                modified: "2026-06-17T00:00:00Z".to_owned(),
            },
        )
        .signature(Signature {
            method: SigningMethod::Minisign,
            key_id: Some("ABCD".to_owned()),
            signature: vec![1, 2, 3],
        })
        .build();

        let canonical = receipt.unsigned_canonical_bytes()?;
        let canonical_str = std::str::from_utf8(&canonical)?;
        assert!(
            !canonical_str.contains("signatures"),
            "canonical bytes must not contain signatures field"
        );
        Ok(())
    }

    #[test]
    fn receipt_signer_trait_minisign_signs_canonical_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = minisign::KeyPair::generate_unencrypted_keypair()?;
        let signer = MinisignSigner::new(key.clone());
        let receipt = sample_receipt();
        let canonical = receipt.unsigned_canonical_bytes()?;
        let signature = signer.sign(&canonical)?;

        assert_eq!(signature.method, SigningMethod::Minisign);
        assert_eq!(signature.key_id, Some(signer.key_id()));

        let signature_text = std::str::from_utf8(&signature.signature)?;
        let signature_box = minisign::SignatureBox::from_string(signature_text)?;
        minisign::verify(
            &key.pk,
            &signature_box,
            Cursor::new(&canonical),
            true,
            false,
            false,
        )?;
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

    #[test]
    fn intoto_statement_has_correct_predicate_type() -> Result<(), Box<dyn std::error::Error>> {
        let receipt = sample_receipt();
        let stmt = receipt.to_intoto_statement()?;
        assert_eq!(stmt.statement_type, "https://in-toto.io/Statement/v1");
        assert_eq!(stmt.predicate_type, "https://arbitraitor.dev/verdict/v1");
        assert!(!stmt.subject.is_empty());
        Ok(())
    }

    #[test]
    fn intoto_statement_round_trips_json() -> Result<(), Box<dyn std::error::Error>> {
        let receipt = sample_receipt();
        let stmt = receipt.to_intoto_statement()?;
        let json = serde_json::to_string(&stmt)?;
        let parsed: IntotoStatement = serde_json::from_str(&json)?;
        assert_eq!(parsed, stmt);
        Ok(())
    }

    #[test]
    fn intoto_statement_serializes_statement_type_url() -> Result<(), Box<dyn std::error::Error>> {
        let receipt = sample_receipt();
        let json = serde_json::to_value(receipt.to_intoto_statement()?)?;

        assert_eq!(json["_type"], "https://in-toto.io/Statement/v1");
        assert_eq!(json["predicateType"], "https://arbitraitor.dev/verdict/v1");
        assert!(json.get("predicate_type").is_none());
        Ok(())
    }

    #[test]
    fn intoto_statement_subject_contains_artifact_sha256() -> Result<(), Box<dyn std::error::Error>>
    {
        let receipt = sample_receipt();
        let json = serde_json::to_value(receipt.to_intoto_statement()?)?;

        assert_eq!(
            json["subject"][0]["name"],
            format!("sha256:{}", receipt.artifact_sha256)
        );
        assert_eq!(
            json["subject"][0]["digest"]["sha256"],
            receipt.artifact_sha256
        );
        Ok(())
    }

    #[test]
    fn intoto_statement_predicate_contains_full_receipt() -> Result<(), Box<dyn std::error::Error>>
    {
        let receipt = sample_receipt();
        let statement = receipt.to_intoto_statement()?;

        assert_eq!(statement.predicate, serde_json::to_value(receipt)?);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SARIF output (spec §31.4)
// ---------------------------------------------------------------------------

/// SARIF 2.1.0 report root (spec §31.4).
#[derive(Clone, Debug, Serialize)]
pub struct SarifReport {
    /// Fixed schema version.
    pub version: String,
    /// Contains the runs with results.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// One run per scan.
    pub runs: Vec<SarifRun>,
}

/// A single SARIF run containing results.
#[derive(Clone, Debug, Serialize)]
pub struct SarifRun {
    /// Tool that produced the results.
    pub tool: SarifTool,
    /// Findings as SARIF results.
    pub results: Vec<SarifResult>,
}

/// Tool metadata in SARIF.
#[derive(Clone, Debug, Serialize)]
pub struct SarifTool {
    /// Driver information.
    pub driver: SarifDriver,
}

/// Driver metadata in SARIF.
#[derive(Clone, Debug, Serialize)]
pub struct SarifDriver {
    /// Tool name.
    pub name: String,
    /// Tool version.
    pub version: String,
    /// Rule definitions.
    pub rules: Vec<SarifRule>,
}

/// A SARIF rule definition with taxonomy (spec §3.59).
#[derive(Clone, Debug, Serialize)]
pub struct SarifRule {
    /// Rule identifier.
    pub id: String,
    /// Short description.
    pub short_description: SarifMessage,
    /// Full description.
    pub full_description: Option<SarifMessage>,
    /// Taxonomy mappings (CWE, CAPEC, OWASP, ATT&CK).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub taxonomy: Vec<SarifTaxonomyEntry>,
}

/// SARIF taxonomy entry per rule (spec §3.59).
#[derive(Clone, Debug, Serialize)]
pub struct SarifTaxonomyEntry {
    /// Taxonomy name (e.g. "CWE", "CAPEC").
    pub name: String,
    /// Taxonomy-specific ID.
    pub id: String,
}

/// SARIF message (text + optional markdown).
#[derive(Clone, Debug, Serialize)]
pub struct SarifMessage {
    /// Plain text.
    pub text: String,
}

/// A SARIF result (finding).
#[derive(Clone, Debug, Serialize)]
pub struct SarifResult {
    /// Rule ID that produced this result.
    pub rule_id: String,
    /// Severity level: "error", "warning", "info", "none".
    pub level: String,
    /// Result message.
    pub message: SarifMessage,
    /// Artifact hash for locations inside extracted/decoded artifacts.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub locations: Vec<SarifLocation>,
}

/// SARIF location with artifact hash.
#[derive(Clone, Debug, Serialize)]
pub struct SarifLocation {
    /// Physical location.
    pub physical_location: SarifPhysicalLocation,
}

/// SARIF physical location.
#[derive(Clone, Debug, Serialize)]
pub struct SarifPhysicalLocation {
    /// Artifact location with hash.
    pub artifact_location: SarifArtifactLocation,
    /// Source region.
    pub region: Option<SarifRegion>,
}

/// SARIF artifact location.
#[derive(Clone, Debug, Serialize)]
pub struct SarifArtifactLocation {
    /// Virtual path (e.g. "sha256:abc...:install.sh:42").
    pub uri: String,
}

/// SARIF source region.
#[derive(Clone, Debug, Serialize)]
pub struct SarifRegion {
    /// Line number (1-based).
    pub start_line: u32,
}

impl Receipt {
    /// Converts the receipt's findings to a SARIF 2.1.0 report (spec §31.4).
    #[must_use]
    pub fn to_sarif(&self, tool_name: &str, tool_version: &str) -> SarifReport {
        let rules: Vec<SarifRule> = self
            .findings
            .iter()
            .map(|f| SarifRule {
                id: f.id.clone(),
                short_description: SarifMessage {
                    text: f.title.clone(),
                },
                full_description: f
                    .remediation
                    .as_ref()
                    .map(|r| SarifMessage { text: r.clone() }),
                taxonomy: f
                    .taxonomies
                    .iter()
                    .map(|t| SarifTaxonomyEntry {
                        name: format!("{:?}", t.name),
                        id: t.id.clone(),
                    })
                    .collect(),
            })
            .collect();

        let results: Vec<SarifResult> = self
            .findings
            .iter()
            .map(|f| {
                let level = match f.severity {
                    Severity::Critical | Severity::High => "error",
                    Severity::Medium => "warning",
                    Severity::Low | Severity::Informational => "info",
                };
                let locations = f
                    .location
                    .as_ref()
                    .map(|loc| {
                        vec![SarifLocation {
                            physical_location: SarifPhysicalLocation {
                                artifact_location: SarifArtifactLocation {
                                    uri: format!(
                                        "sha256:{}:line:{}",
                                        self.artifact_sha256, loc.line
                                    ),
                                },
                                region: Some(SarifRegion {
                                    start_line: loc.line.get(),
                                }),
                            },
                        }]
                    })
                    .unwrap_or_default();
                SarifResult {
                    rule_id: f.id.clone(),
                    level: level.to_owned(),
                    message: SarifMessage {
                        text: f.title.clone(),
                    },
                    locations,
                }
            })
            .collect();

        SarifReport {
            version: "2.1.0".to_owned(),
            schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json".to_owned(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: tool_name.to_owned(),
                        version: tool_version.to_owned(),
                        rules,
                    },
                },
                results,
            }],
        }
    }
}
