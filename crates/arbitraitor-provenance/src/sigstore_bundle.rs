//! Sigstore Bundle policy enforcement (spec §14.2.1).
//!
//! Implements policy evaluation for Sigstore Bundle consumption as required by
//! [spec §14.2.1](../../../.spec/spec.md). The verifier records bundle metadata
//! and policy evaluates:
//!
//! - **Bundle version**: media-type must be one of the accepted version strings
//!   (`application/vnd.dev.sigstore.bundle+json;version=0.1`, `0.2`, `0.3`).
//!   Refusal of older versions is a policy decision.
//! - **Verification material form**: form (1) `X509CertificateChain`, form (2)
//!   `PublicKey`, form (3) single `X509Certificate`. The verifier must accept
//!   all three; rejecting form (3) rejects every modern keyless signature.
//! - **Tlog entries**: `repeated` in v0.3 (Sharded Rekor). Each entry's
//!   inclusion proof is verified independently. A Bundle with no tlog entry is
//!   accepted only when policy explicitly permits offline-only mode.
//! - **RFC 3161 timestamps**: accepted as evidence of signing time when Rekor
//!   is unreachable (air-gapped hosts, SSRF-restricted networks).
//! - **Identity/issuer binding**: per `--identity` (SAN pattern) and `--issuer`
//!   (Fulcio OIDC issuer URL). Identity/issuer policy is **not** inferred from
//!   the Bundle — it is supplied by local policy.
//! - **Online vs offline mode**: offline verification is the default. Online
//!   Rekor search is opt-in and never produces a stronger verdict than offline
//!   inclusion-proof verification.
//!
//! References:
//! - [Sigstore protobuf-specs](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto)
//! - [Sigstore Bundle media type registration](https://github.com/sigstore/protocol/blob/main/README.md)

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{SigstoreVerificationMode, VerificationMaterialForm, determine_material_form};

/// Transparency-log evidence policy for Sigstore Bundle consumption
/// (spec §14.2.1).
///
/// Controls what transparency-log evidence is required. The spec states:
/// "Each entry's inclusion proof is verified independently. A Bundle with no
/// tlog entry is accepted only when policy explicitly permits offline-only
/// mode."
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlogPolicy {
    /// Require at least one tlog entry, and each entry must carry an
    /// [`inclusionProof`](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto#L102)
    /// (Merkle inclusion proof). This is the default and strongest evidence
    /// mode.
    #[default]
    RequireInclusionProof,
    /// Require at least one tlog entry, and each entry must carry an
    /// [`inclusionPromise`](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto#L98)
    /// (signed promise from Rekor that the entry will be included).
    RequireInclusionPromise,
    /// Require at least one tlog entry, and each entry must carry both an
    /// inclusion proof and an inclusion promise.
    RequireBoth,
    /// Tlog entries are optional; the bundle may rely on RFC 3161 timestamps
    /// alone. Per spec §14.2.1: "A Bundle with no tlog entry is accepted only
    /// when policy explicitly permits offline-only mode."
    Optional,
}

/// Policy governing Sigstore Bundle consumption (spec §14.2.1).
///
/// Controls which bundle versions, verification material forms, and
/// transparency-log evidence are accepted. Identity/issuer binding is **not**
/// inferred from the Bundle — it is supplied by local policy via `--identity`
/// and `--issuer`.
///
/// # Secure defaults
///
/// [`SigstoreBundlePolicy::new()`] creates a policy with secure defaults per
/// spec §14.2.1:
///
/// | Field | Default | Rationale |
/// |---|---|---|
/// | `accepted_media_types` | all three (0.1, 0.2, 0.3) | spec: "MUST accept" |
/// | `accepted_forms` | all three forms | spec: "must accept all three" |
/// | `tlog_policy` | `RequireInclusionProof` | spec: offline default, inclusion proof is strongest |
/// | `accept_rfc3161_timestamps` | `true` | spec: "accepted as evidence of signing time" |
/// | `verification_mode` | `Offline` | spec: "offline verification is the default" |
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigstoreBundlePolicy {
    /// Accepted bundle media-type strings. Defaults to all three versions
    /// (`0.1`, `0.2`, `0.3`) per spec §14.2.1.
    pub accepted_media_types: Vec<String>,
    /// Accepted verification material forms. Defaults to all three forms
    /// per spec §14.2.1.
    pub accepted_forms: Vec<VerificationMaterialForm>,
    /// Transparency-log evidence policy. Defaults to
    /// [`TlogPolicy::RequireInclusionProof`].
    pub tlog_policy: TlogPolicy,
    /// Whether RFC 3161 timestamps are accepted as signing-time evidence
    /// (spec §14.2.1). Defaults to `true`.
    pub accept_rfc3161_timestamps: bool,
    /// Verification mode. Offline by default; online is opt-in and never
    /// produces a stronger verdict than offline (spec §14.2.1).
    pub verification_mode: SigstoreVerificationMode,
}

impl Default for SigstoreBundlePolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl SigstoreBundlePolicy {
    /// Creates a policy with secure defaults per spec §14.2.1.
    ///
    /// Accepts all three media types, all three verification material forms,
    /// requires inclusion proofs, accepts RFC 3161 timestamps, and uses
    /// offline verification mode.
    #[must_use]
    pub fn new() -> Self {
        Self {
            accepted_media_types: crate::SIGSTORE_BUNDLE_MEDIA_TYPES
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            accepted_forms: [
                VerificationMaterialForm::X509CertificateChain,
                VerificationMaterialForm::PublicKey,
                VerificationMaterialForm::X509Certificate,
            ]
            .to_vec(),
            tlog_policy: TlogPolicy::RequireInclusionProof,
            accept_rfc3161_timestamps: true,
            verification_mode: SigstoreVerificationMode::Offline,
        }
    }

    /// Sets the transparency-log evidence policy.
    #[must_use]
    pub const fn with_tlog_policy(mut self, policy: TlogPolicy) -> Self {
        self.tlog_policy = policy;
        self
    }

    /// Sets whether RFC 3161 timestamps are accepted as signing-time evidence.
    #[must_use]
    pub const fn with_rfc3161_timestamps(mut self, accept: bool) -> Self {
        self.accept_rfc3161_timestamps = accept;
        self
    }

    /// Sets the verification mode.
    #[must_use]
    pub const fn with_verification_mode(mut self, mode: SigstoreVerificationMode) -> Self {
        self.verification_mode = mode;
        self
    }

    /// Validates a Sigstore Bundle against this policy (spec §14.2.1).
    ///
    /// Checks:
    /// - `mediaType` is present and in the accepted list.
    /// - `verificationMaterial` is present.
    /// - Either `messageSignature` or `dsseEnvelope` is present.
    /// - The verification material form is in the accepted list.
    /// - Tlog evidence satisfies the policy.
    ///
    /// # Errors
    ///
    /// Returns [`SigstoreBundleError`] when the bundle violates policy.
    pub fn validate_bundle(&self, bundle: &serde_json::Value) -> Result<(), SigstoreBundleError> {
        validate_media_type(bundle, &self.accepted_media_types)?;
        validate_verification_material(bundle, &self.accepted_forms)?;
        validate_signature_payload(bundle)?;
        validate_tlog_policy(bundle, self.tlog_policy)?;
        Ok(())
    }

    /// Validates a Sigstore Bundle from raw JSON bytes against this policy.
    ///
    /// Parses the bytes as JSON, then delegates to [`Self::validate_bundle`].
    ///
    /// # Errors
    ///
    /// Returns [`SigstoreBundleError`] when the bytes are not valid JSON or
    /// the bundle violates policy.
    pub fn validate_bundle_bytes(&self, bundle_bytes: &[u8]) -> Result<(), SigstoreBundleError> {
        let bundle: serde_json::Value = serde_json::from_slice(bundle_bytes)
            .map_err(|source| SigstoreBundleError::InvalidJson { source })?;
        self.validate_bundle(&bundle)
    }
}

/// Sigstore Bundle policy enforcement errors (spec §14.2.1).
///
/// Each variant names the specific policy violation so callers can distinguish
/// "bundle is malformed" from "bundle is well-formed but does not satisfy
/// policy".
#[derive(Debug, Error)]
pub enum SigstoreBundleError {
    /// Bundle `mediaType` field is missing or not a string.
    #[error("bundle mediaType is missing or not a string")]
    MissingMediaType,
    /// Bundle `mediaType` is not in the accepted list.
    #[error("bundle mediaType not accepted: {media_type}")]
    UnknownMediaType {
        /// The rejected media type string.
        media_type: String,
    },
    /// Bundle is missing the `verificationMaterial` field.
    #[error("bundle is missing verificationMaterial")]
    MissingVerificationMaterial,
    /// Bundle is missing both `messageSignature` and `dsseEnvelope`.
    #[error("bundle must contain either messageSignature or dsseEnvelope")]
    MissingSignaturePayload,
    /// Verification material form is not in the accepted list.
    #[error("verification material form not accepted: {form:?}")]
    FormNotAccepted {
        /// The rejected form.
        form: VerificationMaterialForm,
    },
    /// Tlog evidence requirement not met: no entries present when required.
    #[error("tlog entries required by policy but none present")]
    TlogEntriesRequired,
    /// Tlog evidence requirement not met: an entry is missing required evidence.
    #[error("tlog entry {index} is missing {missing}")]
    TlogEntryMissingEvidence {
        /// Zero-based index of the offending tlog entry.
        index: usize,
        /// The missing evidence field name (`inclusionProof` or `inclusionPromise`).
        missing: &'static str,
    },
    /// Bundle JSON is invalid.
    #[error("bundle JSON is invalid: {source}")]
    InvalidJson {
        /// Underlying JSON error.
        source: serde_json::Error,
    },
}

/// Validates the `mediaType` field against the accepted list.
fn validate_media_type(
    bundle: &serde_json::Value,
    accepted: &[String],
) -> Result<(), SigstoreBundleError> {
    let media_type = bundle
        .get("mediaType")
        .filter(|v| !v.is_null())
        .and_then(serde_json::Value::as_str)
        .ok_or(SigstoreBundleError::MissingMediaType)?;

    if accepted.iter().any(|accepted_mt| accepted_mt == media_type) {
        Ok(())
    } else {
        Err(SigstoreBundleError::UnknownMediaType {
            media_type: media_type.to_owned(),
        })
    }
}

/// Validates the `verificationMaterial` field and its form.
fn validate_verification_material(
    bundle: &serde_json::Value,
    accepted_forms: &[VerificationMaterialForm],
) -> Result<(), SigstoreBundleError> {
    let material = bundle
        .get("verificationMaterial")
        .filter(|v| !v.is_null())
        .ok_or(SigstoreBundleError::MissingVerificationMaterial)?;

    let form = determine_material_form(bundle);
    debug_assert!(
        material.is_object(),
        "verificationMaterial must be an object"
    );

    if accepted_forms.contains(&form) {
        Ok(())
    } else {
        Err(SigstoreBundleError::FormNotAccepted { form })
    }
}

/// Validates that the bundle contains either `messageSignature` or `dsseEnvelope`.
fn validate_signature_payload(bundle: &serde_json::Value) -> Result<(), SigstoreBundleError> {
    let has_message_signature = bundle.get("messageSignature").is_some_and(|v| !v.is_null());
    let has_dsse_envelope = bundle.get("dsseEnvelope").is_some_and(|v| !v.is_null());

    if has_message_signature || has_dsse_envelope {
        Ok(())
    } else {
        Err(SigstoreBundleError::MissingSignaturePayload)
    }
}

/// Returns `true` when `key` is present and non-null on `entry`.
fn has_field(entry: &serde_json::Value, key: &str) -> bool {
    entry.get(key).is_some_and(|v| !v.is_null())
}

/// Validates tlog entries against the transparency-log evidence policy.
fn validate_tlog_policy(
    bundle: &serde_json::Value,
    policy: TlogPolicy,
) -> Result<(), SigstoreBundleError> {
    if policy == TlogPolicy::Optional {
        return Ok(());
    }

    let entries = bundle
        .get("verificationMaterial")
        .and_then(|m| m.get("tlogEntries"))
        .filter(|v| !v.is_null())
        .and_then(serde_json::Value::as_array);

    let entry_count = entries.map_or(0, Vec::len);
    if entry_count == 0 {
        return Err(SigstoreBundleError::TlogEntriesRequired);
    }

    let require_proof = matches!(
        policy,
        TlogPolicy::RequireInclusionProof | TlogPolicy::RequireBoth
    );
    let require_promise = matches!(
        policy,
        TlogPolicy::RequireInclusionPromise | TlogPolicy::RequireBoth
    );

    let empty = Vec::new();
    let entries = entries.unwrap_or(&empty);
    for (index, entry) in entries.iter().enumerate() {
        if require_proof && !has_field(entry, "inclusionProof") {
            return Err(SigstoreBundleError::TlogEntryMissingEvidence {
                index,
                missing: "inclusionProof",
            });
        }
        if require_promise && !has_field(entry, "inclusionPromise") {
            return Err(SigstoreBundleError::TlogEntryMissingEvidence {
                index,
                missing: "inclusionPromise",
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SIGSTORE_BUNDLE_MEDIA_TYPES;

    // --- Test fixtures ---

    /// A complete, valid v0.3 bundle with all required fields.
    fn valid_bundle_v03() -> serde_json::Value {
        serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
            "verificationMaterial": {
                "content": {
                    "x509Certificate": {
                        "rawBytes": "MIIB..."
                    }
                },
                "tlogEntries": [
                    {
                        "logIndex": 1,
                        "inclusionProof": {
                            "checkpoint": "sigstore:rekor:1",
                            "hashes": [{"algorithm": "SHA2_256", "value": "abc"}],
                            "logIndex": 1,
                            "rootHash": "def",
                            "treeSize": "2"
                        },
                        "inclusionPromise": {
                            "signedEntry": "base64data"
                        }
                    }
                ],
                "timestampVerificationData": {
                    "rfc3161Timestamps": [
                        {"signedTimestamper": "MIAGCSqGSIb3DQEHA"}
                    ]
                }
            },
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": "abCd"
                }
            }
        })
    }

    /// A valid v0.1 bundle with a public key and DSSE envelope.
    fn valid_bundle_v01_dsse() -> serde_json::Value {
        serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
            "verificationMaterial": {
                "content": {
                    "publicKey": {"rawBytes": "key"}
                },
                "tlogEntries": [
                    {
                        "logIndex": 0,
                        "inclusionProof": {
                            "checkpoint": "sigstore:rekor:1",
                            "hashes": [{"algorithm": "SHA2_256", "value": "abc"}],
                            "logIndex": 0,
                            "rootHash": "def",
                            "treeSize": "1"
                        }
                    }
                ]
            },
            "dsseEnvelope": {
                "payload": "base64payload",
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [{"sig": "base64sig", "keyid": "key1"}]
            }
        })
    }

    // --- Happy path: valid bundles pass default policy ---

    #[test]
    fn valid_v03_bundle_passes_default_policy() -> Result<(), String> {
        let policy = SigstoreBundlePolicy::new();
        policy
            .validate_bundle(&valid_bundle_v03())
            .map_err(|e| format!("valid v0.3 bundle should pass default policy: {e}"))
    }

    #[test]
    fn valid_v01_bundle_with_dsse_passes_default_policy() -> Result<(), String> {
        let policy = SigstoreBundlePolicy::new();
        policy
            .validate_bundle(&valid_bundle_v01_dsse())
            .map_err(|e| format!("valid v0.1 DSSE bundle should pass default policy: {e}"))
    }

    #[test]
    fn valid_bundle_passes_require_both_policy() -> Result<(), String> {
        let policy = SigstoreBundlePolicy::new().with_tlog_policy(TlogPolicy::RequireBoth);
        policy
            .validate_bundle(&valid_bundle_v03())
            .map_err(|e| format!("valid v0.3 bundle should pass RequireBoth policy: {e}"))
    }

    #[test]
    fn valid_bundle_passes_require_promise_policy() -> Result<(), String> {
        let policy =
            SigstoreBundlePolicy::new().with_tlog_policy(TlogPolicy::RequireInclusionPromise);
        policy.validate_bundle(&valid_bundle_v03()).map_err(|e| {
            format!("valid v0.3 bundle should pass RequireInclusionPromise policy: {e}")
        })
    }

    #[test]
    fn bundle_without_tlog_passes_optional_policy() -> Result<(), String> {
        let policy = SigstoreBundlePolicy::new().with_tlog_policy(TlogPolicy::Optional);
        let mut bundle = valid_bundle_v03();
        bundle["verificationMaterial"]["tlogEntries"].take();
        policy
            .validate_bundle(&bundle)
            .map_err(|e| format!("bundle without tlog should pass Optional policy: {e}"))
    }

    #[test]
    fn bundle_with_rfc3161_only_passes_optional_policy() -> Result<(), String> {
        let policy = SigstoreBundlePolicy::new().with_tlog_policy(TlogPolicy::Optional);
        let mut bundle = valid_bundle_v03();
        bundle["verificationMaterial"]["tlogEntries"].take();
        policy
            .validate_bundle(&bundle)
            .map_err(|e| format!("bundle with RFC 3161 only should pass Optional policy: {e}"))
    }

    // --- Malformed bundles ---

    #[test]
    fn missing_media_type_is_rejected() {
        let policy = SigstoreBundlePolicy::new();
        let mut bundle = valid_bundle_v03();
        bundle["mediaType"].take();
        assert!(matches!(
            policy.validate_bundle(&bundle),
            Err(SigstoreBundleError::MissingMediaType)
        ));
    }

    #[test]
    fn unknown_media_type_version_is_rejected() {
        let policy = SigstoreBundlePolicy::new();
        let mut bundle = valid_bundle_v03();
        bundle["mediaType"] =
            serde_json::json!("application/vnd.dev.sigstore.bundle+json;version=0.99");
        assert!(matches!(
            policy.validate_bundle(&bundle),
            Err(SigstoreBundleError::UnknownMediaType { .. })
        ));
    }

    #[test]
    fn missing_verification_material_is_rejected() {
        let policy = SigstoreBundlePolicy::new();
        let mut bundle = valid_bundle_v03();
        bundle["verificationMaterial"].take();
        assert!(matches!(
            policy.validate_bundle(&bundle),
            Err(SigstoreBundleError::MissingVerificationMaterial)
        ));
    }

    #[test]
    fn missing_both_signature_payloads_is_rejected() {
        let policy = SigstoreBundlePolicy::new();
        let mut bundle = valid_bundle_v03();
        bundle["messageSignature"].take();
        bundle["dsseEnvelope"].take();
        assert!(matches!(
            policy.validate_bundle(&bundle),
            Err(SigstoreBundleError::MissingSignaturePayload)
        ));
    }

    #[test]
    fn dsse_envelope_alone_satisfies_payload_requirement() -> Result<(), String> {
        let policy = SigstoreBundlePolicy::new();
        let mut bundle = valid_bundle_v03();
        bundle["messageSignature"].take();
        bundle["dsseEnvelope"] = serde_json::json!({
            "payload": "base64payload",
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": "base64sig"}]
        });
        policy
            .validate_bundle(&bundle)
            .map_err(|e| format!("DSSE envelope alone should satisfy payload requirement: {e}"))
    }

    // --- Policy-denied: tlog ---

    #[test]
    fn tlog_missing_when_required_is_rejected() {
        let policy = SigstoreBundlePolicy::new();
        let mut bundle = valid_bundle_v03();
        bundle["verificationMaterial"]["tlogEntries"].take();
        assert!(matches!(
            policy.validate_bundle(&bundle),
            Err(SigstoreBundleError::TlogEntriesRequired)
        ));
    }

    #[test]
    fn tlog_empty_when_required_is_rejected() {
        let policy = SigstoreBundlePolicy::new();
        let mut bundle = valid_bundle_v03();
        bundle["verificationMaterial"]["tlogEntries"] = serde_json::json!([]);
        assert!(matches!(
            policy.validate_bundle(&bundle),
            Err(SigstoreBundleError::TlogEntriesRequired)
        ));
    }

    #[test]
    fn tlog_entry_missing_inclusion_proof_is_rejected() {
        let policy = SigstoreBundlePolicy::new();
        let mut bundle = valid_bundle_v03();
        bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"].take();
        assert!(matches!(
            policy.validate_bundle(&bundle),
            Err(SigstoreBundleError::TlogEntryMissingEvidence {
                missing: "inclusionProof",
                ..
            })
        ));
    }

    #[test]
    fn tlog_entry_missing_inclusion_promise_is_rejected_under_promise_policy() {
        let policy =
            SigstoreBundlePolicy::new().with_tlog_policy(TlogPolicy::RequireInclusionPromise);
        let mut bundle = valid_bundle_v03();
        bundle["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"].take();
        assert!(matches!(
            policy.validate_bundle(&bundle),
            Err(SigstoreBundleError::TlogEntryMissingEvidence {
                missing: "inclusionPromise",
                ..
            })
        ));
    }

    #[test]
    fn tlog_entry_missing_proof_rejected_under_both_policy() {
        let policy = SigstoreBundlePolicy::new().with_tlog_policy(TlogPolicy::RequireBoth);
        let mut bundle = valid_bundle_v03();
        bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"].take();
        assert!(matches!(
            policy.validate_bundle(&bundle),
            Err(SigstoreBundleError::TlogEntryMissingEvidence {
                missing: "inclusionProof",
                ..
            })
        ));
    }

    #[test]
    fn tlog_entry_missing_promise_rejected_under_both_policy() {
        let policy = SigstoreBundlePolicy::new().with_tlog_policy(TlogPolicy::RequireBoth);
        let mut bundle = valid_bundle_v03();
        bundle["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"].take();
        assert!(matches!(
            policy.validate_bundle(&bundle),
            Err(SigstoreBundleError::TlogEntryMissingEvidence {
                missing: "inclusionPromise",
                ..
            })
        ));
    }

    // --- Policy-passing on optional ---

    #[test]
    fn tlog_entry_without_proof_passes_under_optional_policy() -> Result<(), String> {
        let policy = SigstoreBundlePolicy::new().with_tlog_policy(TlogPolicy::Optional);
        let mut bundle = valid_bundle_v03();
        bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"].take();
        policy
            .validate_bundle(&bundle)
            .map_err(|e| format!("entry without proof should pass Optional policy: {e}"))
    }

    #[test]
    fn empty_tlog_passes_under_optional_policy() -> Result<(), String> {
        let policy = SigstoreBundlePolicy::new().with_tlog_policy(TlogPolicy::Optional);
        let mut bundle = valid_bundle_v03();
        bundle["verificationMaterial"]["tlogEntries"] = serde_json::json!([]);
        policy
            .validate_bundle(&bundle)
            .map_err(|e| format!("empty tlog should pass Optional policy: {e}"))
    }

    // --- Form acceptance ---

    #[test]
    fn all_three_forms_accepted_by_default() {
        let policy = SigstoreBundlePolicy::new();
        assert!(
            policy
                .accepted_forms
                .contains(&VerificationMaterialForm::X509CertificateChain)
        );
        assert!(
            policy
                .accepted_forms
                .contains(&VerificationMaterialForm::PublicKey)
        );
        assert!(
            policy
                .accepted_forms
                .contains(&VerificationMaterialForm::X509Certificate)
        );
    }

    #[test]
    fn x509_certificate_chain_form_accepted() -> Result<(), String> {
        let policy = SigstoreBundlePolicy::new();
        let mut bundle = valid_bundle_v03();
        bundle["verificationMaterial"]["content"] = serde_json::json!({
            "x509CertificateChain": {
                "certificates": [{"rawBytes": "MIIB..."}]
            }
        });
        policy
            .validate_bundle(&bundle)
            .map_err(|e| format!("X509CertificateChain form should be accepted: {e}"))
    }

    #[test]
    fn public_key_form_accepted() -> Result<(), String> {
        let policy = SigstoreBundlePolicy::new();
        let mut bundle = valid_bundle_v03();
        bundle["verificationMaterial"]["content"] = serde_json::json!({
            "publicKey": {"rawBytes": "key"}
        });
        policy
            .validate_bundle(&bundle)
            .map_err(|e| format!("PublicKey form should be accepted: {e}"))
    }

    #[test]
    fn form_not_accepted_is_rejected() {
        let policy = SigstoreBundlePolicy {
            accepted_forms: vec![VerificationMaterialForm::PublicKey],
            ..SigstoreBundlePolicy::new()
        };
        let bundle = valid_bundle_v03();
        assert!(matches!(
            policy.validate_bundle(&bundle),
            Err(SigstoreBundleError::FormNotAccepted { .. })
        ));
    }

    // --- Media type acceptance ---

    #[test]
    fn all_three_media_types_accepted_by_default() {
        let policy = SigstoreBundlePolicy::new();
        for media_type in SIGSTORE_BUNDLE_MEDIA_TYPES {
            assert!(
                policy
                    .accepted_media_types
                    .contains(&(*media_type).to_owned()),
                "media type {media_type} should be accepted"
            );
        }
    }

    #[test]
    fn v01_media_type_accepted() -> Result<(), String> {
        let policy = SigstoreBundlePolicy::new();
        policy
            .validate_bundle(&valid_bundle_v01_dsse())
            .map_err(|e| format!("v0.1 media type should be accepted: {e}"))
    }

    #[test]
    fn v02_media_type_accepted() -> Result<(), String> {
        let policy = SigstoreBundlePolicy::new();
        let mut bundle = valid_bundle_v03();
        bundle["mediaType"] =
            serde_json::json!("application/vnd.dev.sigstore.bundle+json;version=0.2");
        policy
            .validate_bundle(&bundle)
            .map_err(|e| format!("v0.2 media type should be accepted: {e}"))
    }

    // --- validate_bundle_bytes ---

    #[test]
    fn validate_bundle_bytes_accepts_valid_json() -> Result<(), String> {
        let policy = SigstoreBundlePolicy::new();
        let bundle_bytes = serde_json::to_vec(&valid_bundle_v03())
            .map_err(|e| format!("failed to serialize test bundle: {e}"))?;
        policy
            .validate_bundle_bytes(&bundle_bytes)
            .map_err(|e| format!("valid bundle bytes should pass: {e}"))
    }

    #[test]
    fn validate_bundle_bytes_rejects_invalid_json() {
        let policy = SigstoreBundlePolicy::new();
        let result = policy.validate_bundle_bytes(b"not json at all");
        assert!(matches!(
            result,
            Err(SigstoreBundleError::InvalidJson { .. })
        ));
    }

    // --- Builder methods ---

    #[test]
    fn builder_with_tlog_policy_sets_policy() {
        let policy = SigstoreBundlePolicy::new()
            .with_tlog_policy(TlogPolicy::Optional)
            .with_rfc3161_timestamps(false)
            .with_verification_mode(SigstoreVerificationMode::Online);
        assert_eq!(policy.tlog_policy, TlogPolicy::Optional);
        assert!(!policy.accept_rfc3161_timestamps);
        assert_eq!(policy.verification_mode, SigstoreVerificationMode::Online);
    }

    #[test]
    fn default_impl_matches_new() {
        assert_eq!(SigstoreBundlePolicy::default(), SigstoreBundlePolicy::new());
    }

    #[test]
    fn tlog_policy_default_is_require_inclusion_proof() {
        assert_eq!(TlogPolicy::default(), TlogPolicy::RequireInclusionProof);
    }

    // --- Multiple tlog entries ---

    #[test]
    fn multiple_tlog_entries_all_must_have_evidence() -> Result<(), String> {
        let policy = SigstoreBundlePolicy::new();
        let mut bundle = valid_bundle_v03();
        let entries = bundle["verificationMaterial"]["tlogEntries"]
            .as_array_mut()
            .ok_or("tlogEntries should be an array")?;
        entries.push(serde_json::json!({
            "logIndex": 2,
            "inclusionPromise": {"signedEntry": "base64data2"}
        }));
        assert!(matches!(
            policy.validate_bundle(&bundle),
            Err(SigstoreBundleError::TlogEntryMissingEvidence {
                index: 1,
                missing: "inclusionProof",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn multiple_tlog_entries_all_with_evidence_pass() -> Result<(), String> {
        let policy = SigstoreBundlePolicy::new();
        let mut bundle = valid_bundle_v03();
        let entries = bundle["verificationMaterial"]["tlogEntries"]
            .as_array_mut()
            .ok_or("tlogEntries should be an array")?;
        entries.push(serde_json::json!({
            "logIndex": 2,
            "inclusionProof": {
                "checkpoint": "sigstore:rekor:1",
                "hashes": [{"algorithm": "SHA2_256", "value": "ghi"}],
                "logIndex": 2,
                "rootHash": "jkl",
                "treeSize": "3"
            },
            "inclusionPromise": {"signedEntry": "base64data2"}
        }));
        policy
            .validate_bundle(&bundle)
            .map_err(|e| format!("multiple entries with evidence should pass: {e}"))
    }
}
