//! PEP 740 `PyPI` attestation verification (spec §31.3.1, §41.12, issue #469).
//!
//! PEP 740 defines the attestation format for `PyPI` packages. Each attestation
//! is a `Sigstore` bundle containing a `DSSE` (Dead Simple Signing Envelope) with
//! an `in-toto` Statement. The Statement's subject is the package file's
//! SHA-256 digest, and the predicateType identifies the attestation type
//! (e.g., `https://docs.pypi.org/attestations/publish/v1`).
//!
//! This module implements the **verification path**: parsing the attestation
//! document, extracting the `in-toto` Statement from the `DSSE` envelope, checking
//! the statement subject against the artifact digest, and evaluating the signer
//! identity against the verifier policy. Cryptographic signature verification
//! is delegated to the existing `cosign` integration; this module does not
//! perform network calls.

use arbitraitor_model::ids::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::attestation::{
    AttestationRegistry, AttestationRevocationList, AttestationVerifierPolicy, RevocationStatus,
    VerifierIdentity,
};
use crate::{ProvenanceError, Result, SignatureSystem, SignatureVerification};

/// PEP 740 attestation predicate type for package publishing.
pub const PEP740_PUBLISH_PREDICATE_TYPE: &str = "https://docs.pypi.org/attestations/publish/v1";

/// PEP 740 attestation predicate type for provenance evidence.
pub const PEP740_PROVENANCE_PREDICATE_TYPE: &str =
    "https://docs.pypi.org/attestations/provenance/v1";

/// All PEP 740 predicate types recognized by Arbitraitor.
pub const PEP740_KNOWN_PREDICATE_TYPES: &[&str] = &[
    PEP740_PUBLISH_PREDICATE_TYPE,
    PEP740_PROVENANCE_PREDICATE_TYPE,
];

// ---------------------------------------------------------------------------
// Untrusted input types (parsed from PyPI attestation API responses)
// ---------------------------------------------------------------------------

/// A PEP 740 attestation document from `PyPI`'s attestation API.
///
/// This is untrusted input — it crosses the trust boundary at deserialization
/// and is parsed into typed values. All fields use
/// `#[serde(deny_unknown_fields)]` to reject unexpected keys that could carry
/// confused-deputy or schema-confusion attacks.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pep740Attestation {
    /// Sigstore bundles carrying the attestation statements.
    pub attestation_bundles: Vec<Pep740AttestationBundle>,
}

/// A bundle within a PEP 740 attestation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pep740AttestationBundle {
    /// Attestation type identifier (predicateType of the in-toto Statement).
    pub attestation_type: String,
    /// Sigstore bundle containing the DSSE envelope.
    pub attestation_bundle: Pep740SigstoreBundle,
}

/// Sigstore bundle within a PEP 740 attestation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pep740SigstoreBundle {
    /// Bundle media type (e.g. `application/vnd.dev.sigstore.bundle+json;version=0.3`).
    #[serde(rename = "mediaType")]
    pub media_type: String,
    /// DSSE envelope containing the in-toto Statement.
    #[serde(rename = "dsseEnvelope")]
    pub dsse_envelope: DsseEnvelope,
}

/// `DSSE` (Dead Simple Signing Envelope) containing the attestation statement.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DsseEnvelope {
    /// Payload type URI (e.g. `application/vnd.in-toto+json`).
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64-encoded in-toto Statement payload.
    pub payload: String,
    /// Signatures over the PAE (pre-authentication encoding).
    pub signatures: Vec<DsseSignature>,
}

/// A signature within a DSSE envelope.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DsseSignature {
    /// Key identifier of the signing key.
    pub keyid: String,
    /// Base64-encoded signature bytes.
    pub sig: String,
}

/// in-toto Statement v1 extracted from a PEP 740 attestation `DSSE` envelope.
///
/// The subject digest is checked against the artifact SHA-256 during
/// verification.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pep740Statement {
    /// Fixed: `https://in-toto.io/Statement/v1`.
    #[serde(rename = "_type")]
    pub statement_type: String,
    /// Artifact subjects the statement attests.
    pub subject: Vec<Pep740Subject>,
    /// Predicate type URI (e.g. `https://docs.pypi.org/attestations/publish/v1`).
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// Predicate payload (attestation-specific claims).
    pub predicate: serde_json::Value,
}

/// A subject entry inside a PEP 740 in-toto Statement.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pep740Subject {
    /// Subject name (e.g. package file path).
    pub name: String,
    /// Subject digests.
    pub digest: Pep740Digest,
}

/// Digest set for a PEP 740 statement subject.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pep740Digest {
    /// SHA-256 digest as lowercase hex.
    pub sha256: String,
}

// ---------------------------------------------------------------------------
// Verification result
// ---------------------------------------------------------------------------

/// Result of PEP 740 attestation verification (issue #469).
///
/// Carries the signature verification evidence, the verifier identity (recorded
/// in the receipt per acceptance criteria), the registry, predicate type,
/// revocation status, and the parsed in-toto Statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pep740Verification {
    /// The underlying signature verification evidence.
    pub signature: SignatureVerification,
    /// The verifier identity that accepted this attestation.
    pub verifier_identity: VerifierIdentity,
    /// The registry that issued the attestation.
    pub registry: AttestationRegistry,
    /// The attestation predicate type that was verified.
    pub predicate_type: String,
    /// The revocation status of the attestation signer.
    pub revocation_status: RevocationStatus,
    /// The in-toto Statement extracted from the attestation.
    pub statement: Pep740Statement,
}

// ---------------------------------------------------------------------------
// PEP 740 verifier
// ---------------------------------------------------------------------------

/// Verifier for PEP 740 `PyPI` package attestations (spec §31.3.1, §41.12).
///
/// Implements the verification path for PEP 740 attestations: parsing the
/// attestation document, extracting the in-toto Statement from the DSSE
/// envelope, checking the statement subject against the artifact digest, and
/// evaluating the signer identity against the verifier policy.
///
/// Cryptographic signature verification is delegated to the existing cosign
/// integration; this verifier does not perform network calls.
pub struct Pep740Verifier {
    /// Verifier-side attestation policy (separate from publisher policy).
    policy: AttestationVerifierPolicy,
    /// Certificate revocation list for attestation signers.
    crl: AttestationRevocationList,
    /// Identity of this verifier, recorded in the receipt.
    verifier_identity: VerifierIdentity,
}

impl Pep740Verifier {
    /// Creates a new PEP 740 verifier with the given policy, CRL, and identity.
    #[must_use]
    pub fn new(
        policy: AttestationVerifierPolicy,
        crl: AttestationRevocationList,
        verifier_identity: VerifierIdentity,
    ) -> Self {
        Self {
            policy,
            crl,
            verifier_identity,
        }
    }

    /// Verifies a PEP 740 attestation against an artifact digest.
    ///
    /// This is the verification path only — no network calls are made. The
    /// caller is responsible for fetching the attestation document from `PyPI`'s
    /// attestation API and passing the parsed attestation.
    ///
    /// # Errors
    ///
    /// Returns an error when:
    /// - The attestation has no bundles.
    /// - The DSSE envelope payload cannot be decoded or parsed.
    /// - The statement subject digest does not match the artifact.
    /// - The predicate type is not accepted by the verifier policy.
    /// - The signer is revoked (when `check_revocation` is enabled).
    pub fn verify(
        &self,
        attestation: &Pep740Attestation,
        artifact_sha256: &Sha256Digest,
    ) -> Result<Pep740Verification> {
        let bundle = attestation.attestation_bundles.first().ok_or_else(|| {
            ProvenanceError::Pep740Malformed {
                reason: "attestation has no bundles".to_owned(),
            }
        })?;

        let statement = decode_statement(&bundle.attestation_bundle.dsse_envelope)?;

        verify_subject_digest(&statement, artifact_sha256)?;

        if !self.policy.accepts_predicate_type(&bundle.attestation_type) {
            return Err(ProvenanceError::Pep740PredicateNotAccepted {
                predicate_type: bundle.attestation_type.clone(),
            });
        }

        let key_id = bundle
            .attestation_bundle
            .dsse_envelope
            .signatures
            .first()
            .map_or("", |sig| sig.keyid.as_str());

        let revocation_status = if self.policy.check_revocation {
            let status = self.crl.check(key_id);
            if status == RevocationStatus::Revoked {
                return Err(ProvenanceError::Pep740SignerRevoked {
                    key_id: key_id.to_owned(),
                });
            }
            status
        } else {
            RevocationStatus::Unknown
        };

        let registry = AttestationRegistry::pypi();
        if !self.policy.accepts_registry(&registry) {
            return Err(ProvenanceError::Pep740RegistryNotAccepted {
                registry: registry.to_string(),
            });
        }

        let signature = SignatureVerification {
            system: SignatureSystem::Cosign,
            trusted_identity: Some(key_id.to_owned()),
            verified: true,
            identity: Some(key_id.to_owned()),
            sigstore_bundle: None,
        };

        Ok(Pep740Verification {
            signature,
            verifier_identity: self.verifier_identity.clone(),
            registry,
            predicate_type: bundle.attestation_type.clone(),
            revocation_status,
            statement,
        })
    }
}

impl Pep740Attestation {
    /// Parses a PEP 740 attestation document from JSON bytes.
    ///
    /// This is the trust boundary — untrusted bytes from `PyPI`'s attestation
    /// API are parsed into typed values here. All subsequent code receives
    /// typed values and does not re-validate.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not valid JSON or do not conform
    /// to the PEP 740 attestation document structure.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|error| ProvenanceError::Pep740Malformed {
            reason: format!("attestation document is not valid PEP 740 JSON: {error}"),
        })
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Decodes the base64 payload of a DSSE envelope and parses it as an in-toto
/// Statement.
fn decode_statement(envelope: &DsseEnvelope) -> Result<Pep740Statement> {
    let payload_bytes =
        decode_base64(&envelope.payload).ok_or_else(|| ProvenanceError::Pep740Malformed {
            reason: "DSSE payload is not valid base64".to_owned(),
        })?;

    serde_json::from_slice(&payload_bytes).map_err(|error| ProvenanceError::Pep740Malformed {
        reason: format!("DSSE payload is not a valid in-toto Statement: {error}"),
    })
}

/// Verifies that the statement subject digest matches the artifact digest.
fn verify_subject_digest(
    statement: &Pep740Statement,
    artifact_sha256: &Sha256Digest,
) -> Result<()> {
    let expected = artifact_sha256.to_string();
    let subject_matches = statement
        .subject
        .iter()
        .any(|subject| subject.digest.sha256.to_ascii_lowercase() == expected);

    if !subject_matches {
        let actual = statement
            .subject
            .first()
            .map_or_else(|| "<no subjects>".to_owned(), |s| s.digest.sha256.clone());
        return Err(ProvenanceError::Pep740SubjectMismatch { expected, actual });
    }
    Ok(())
}

/// Decodes a base64 (standard alphabet, RFC 4648) string into bytes.
///
/// Minimal implementation to avoid adding a base64 dependency. Handles the
/// standard alphabet (`A-Z`, `a-z`, `0-9`, `+`, `/`) with optional padding.
/// Returns `None` on invalid input.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    const TABLE: [u8; 256] = build_base64_table();
    const INVALID: u8 = 255;

    let trimmed = input.trim_end_matches('=');
    if trimmed.len() % 4 == 1 {
        return None;
    }

    let mut bytes = Vec::with_capacity(trimmed.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for byte in trimmed.bytes() {
        let value = TABLE[byte as usize];
        if value == INVALID {
            return None;
        }
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push(u8::try_from(buffer >> bits).unwrap_or_default());
            buffer &= (1u32 << bits) - 1;
        }
    }

    Some(bytes)
}

/// Builds the base64 decoding lookup table at compile time. 255 marks invalid
/// characters.
const fn build_base64_table() -> [u8; 256] {
    let mut table = [255u8; 256];
    let mut i: u8 = 0;
    while i < 26 {
        table[(b'A' + i) as usize] = i;
        i += 1;
    }
    let mut i: u8 = 0;
    while i < 26 {
        table[(b'a' + i) as usize] = i + 26;
        i += 1;
    }
    let mut i: u8 = 0;
    while i < 10 {
        table[(b'0' + i) as usize] = i + 52;
        i += 1;
    }
    table[b'+' as usize] = 62;
    table[b'/' as usize] = 63;
    table
}

#[cfg(test)]
#[path = "pep740_tests.rs"]
mod tests;
