//! Tests for PEP 740 attestation verification (issue #469).

use arbitraitor_model::ids::Sha256Digest;

use super::super::attestation::{
    AttestationRegistry, AttestationRevocationList, AttestationVerifierPolicy, RevocationEntry,
    RevocationStatus, VerifierIdentity,
};
use super::super::crates_io::{CratesIoAttestationVerifier, CratesIoVerification};
use super::{
    DsseEnvelope, DsseSignature, PEP740_PUBLISH_PREDICATE_TYPE, Pep740Attestation,
    Pep740AttestationBundle, Pep740SigstoreBundle, Pep740Statement, Pep740Subject, Pep740Verifier,
    decode_base64,
};
use crate::{ProvenanceError, VerificationPolicy};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Encodes bytes as base64 (standard alphabet, RFC 4648) with padding.
/// Test-only mirror of the `decode_base64` function in `pep740.rs`.
fn encode_base64(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i];
        let b1 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] } else { 0 };

        result.push(CHARS[(b0 >> 2) as usize] as char);
        result.push(CHARS[((b0 & 0x03) << 4 | b1 >> 4) as usize] as char);
        if i + 1 < input.len() {
            result.push(CHARS[((b1 & 0x0f) << 2 | b2 >> 6) as usize] as char);
        } else {
            result.push('=');
        }
        if i + 2 < input.len() {
            result.push(CHARS[(b2 & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
        i += 3;
    }
    result
}

/// Builds a valid PEP 740 attestation fixture for the given artifact digest.
fn valid_attestation(
    artifact_sha256: &Sha256Digest,
    key_id: &str,
) -> std::result::Result<Pep740Attestation, Box<dyn std::error::Error>> {
    let statement = Pep740Statement {
        statement_type: "https://in-toto.io/Statement/v1".to_owned(),
        subject: vec![Pep740Subject {
            name: "test-package.tar.gz".to_owned(),
            digest: super::Pep740Digest {
                sha256: artifact_sha256.to_string(),
            },
        }],
        predicate_type: PEP740_PUBLISH_PREDICATE_TYPE.to_owned(),
        predicate: serde_json::json!({}),
    };
    let payload_json = serde_json::to_vec(&statement)?;
    let payload = encode_base64(&payload_json);

    Ok(Pep740Attestation {
        attestation_bundles: vec![Pep740AttestationBundle {
            attestation_type: PEP740_PUBLISH_PREDICATE_TYPE.to_owned(),
            attestation_bundle: Pep740SigstoreBundle {
                media_type: "application/vnd.dev.sigstore.bundle+json;version=0.3".to_owned(),
                dsse_envelope: DsseEnvelope {
                    payload_type: "application/vnd.in-toto+json".to_owned(),
                    payload,
                    signatures: vec![DsseSignature {
                        keyid: key_id.to_owned(),
                        sig: "dGVzdC1zaWduYXR1cmU=".to_owned(),
                    }],
                },
            },
        }],
    })
}

fn test_verifier() -> Pep740Verifier {
    Pep740Verifier::new(
        AttestationVerifierPolicy::new(),
        AttestationRevocationList::new(),
        VerifierIdentity::new("arbitraitor-pep740-verifier"),
    )
}

fn test_digest() -> Sha256Digest {
    Sha256Digest::new([0x11; 32])
}

// ---------------------------------------------------------------------------
// Valid attestation verifies
// ---------------------------------------------------------------------------

#[test]
fn valid_pep740_attestation_verifies() -> TestResult {
    // Given: a valid PEP 740 attestation matching the artifact digest
    let digest = test_digest();
    let attestation = valid_attestation(&digest, "signer-key-1")?;
    let verifier = test_verifier();

    // When: the verifier checks the attestation
    let verification = verifier.verify(&attestation, &digest)?;

    // Then: verification succeeds with the correct metadata
    assert!(verification.signature.verified);
    assert_eq!(
        verification.verifier_identity.as_str(),
        "arbitraitor-pep740-verifier"
    );
    assert_eq!(verification.registry, AttestationRegistry::pypi());
    assert_eq!(verification.predicate_type, PEP740_PUBLISH_PREDICATE_TYPE);
    assert_eq!(
        verification.signature.identity.as_deref(),
        Some("signer-key-1")
    );
    Ok(())
}

#[test]
fn valid_pep740_attestation_parses_from_json() -> TestResult {
    // Given: a valid PEP 740 attestation as JSON bytes
    let digest = test_digest();
    let attestation = valid_attestation(&digest, "signer-key-1")?;
    let json = serde_json::to_vec(&attestation)?;

    // When: the attestation is parsed from bytes
    let parsed = Pep740Attestation::parse(&json)?;

    // Then: the parsed attestation matches the original
    assert_eq!(parsed, attestation);
    Ok(())
}

// ---------------------------------------------------------------------------
// Invalid attestation rejected
// ---------------------------------------------------------------------------

#[test]
fn invalid_json_rejected() {
    // Given: invalid JSON bytes
    let bytes = b"not json at all";

    // When: parsing is attempted
    let result = Pep740Attestation::parse(bytes);

    // Then: a malformed error is returned
    assert!(matches!(
        result,
        Err(ProvenanceError::Pep740Malformed { .. })
    ));
}

#[test]
fn empty_attestation_bundles_rejected() {
    // Given: an attestation with no bundles
    let attestation = Pep740Attestation {
        attestation_bundles: vec![],
    };
    let verifier = test_verifier();

    // When: verification is attempted
    let result = verifier.verify(&attestation, &test_digest());

    // Then: a malformed error is returned
    assert!(matches!(
        result,
        Err(ProvenanceError::Pep740Malformed { .. })
    ));
}

#[test]
fn subject_digest_mismatch_rejected() -> TestResult {
    // Given: an attestation whose subject digest does not match the artifact
    let attestation_digest = Sha256Digest::new([0x11; 32]);
    let artifact_digest = Sha256Digest::new([0x22; 32]);
    let attestation = valid_attestation(&attestation_digest, "signer-key-1")?;
    let verifier = test_verifier();

    // When: verification is attempted against a different artifact
    let result = verifier.verify(&attestation, &artifact_digest);

    // Then: a subject mismatch error is returned
    assert!(matches!(
        result,
        Err(ProvenanceError::Pep740SubjectMismatch { .. })
    ));
    Ok(())
}

#[test]
fn invalid_base64_payload_rejected() {
    // Given: an attestation with a non-base64 payload
    let attestation = Pep740Attestation {
        attestation_bundles: vec![Pep740AttestationBundle {
            attestation_type: PEP740_PUBLISH_PREDICATE_TYPE.to_owned(),
            attestation_bundle: Pep740SigstoreBundle {
                media_type: "application/vnd.dev.sigstore.bundle+json;version=0.3".to_owned(),
                dsse_envelope: DsseEnvelope {
                    payload_type: "application/vnd.in-toto+json".to_owned(),
                    payload: "!!!not-base64!!!".to_owned(),
                    signatures: vec![DsseSignature {
                        keyid: "key-1".to_owned(),
                        sig: "sig".to_owned(),
                    }],
                },
            },
        }],
    };
    let verifier = test_verifier();

    // When: verification is attempted
    let result = verifier.verify(&attestation, &test_digest());

    // Then: a malformed error is returned
    assert!(matches!(
        result,
        Err(ProvenanceError::Pep740Malformed { .. })
    ));
}

#[test]
fn unaccepted_predicate_type_rejected() -> TestResult {
    // Given: a verifier policy that only accepts provenance predicate type
    let digest = test_digest();
    let attestation = valid_attestation(&digest, "signer-key-1")?;
    let policy = AttestationVerifierPolicy {
        accepted_predicate_types: vec![
            "https://docs.pypi.org/attestations/provenance/v1".to_owned(),
        ],
        ..AttestationVerifierPolicy::new()
    };
    let verifier = Pep740Verifier::new(
        policy,
        AttestationRevocationList::new(),
        VerifierIdentity::new("strict-verifier"),
    );

    // When: verification is attempted with a publish-type attestation
    let result = verifier.verify(&attestation, &digest);

    // Then: a predicate-not-accepted error is returned
    assert!(matches!(
        result,
        Err(ProvenanceError::Pep740PredicateNotAccepted { .. })
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Revoked attestation rejected
// ---------------------------------------------------------------------------

#[test]
fn revoked_attestation_rejected() -> TestResult {
    // Given: a verifier with a CRL that revokes the signer
    let digest = test_digest();
    let attestation = valid_attestation(&digest, "revoked-key")?;
    let mut crl = AttestationRevocationList::new();
    crl.add(RevocationEntry {
        key_id: "revoked-key".to_owned(),
        status: RevocationStatus::Revoked,
        revoked_at: "2026-07-23T00:00:00Z".to_owned(),
    });
    let verifier = Pep740Verifier::new(
        AttestationVerifierPolicy::new(),
        crl,
        VerifierIdentity::new("revocation-verifier"),
    );

    // When: verification is attempted
    let result = verifier.verify(&attestation, &digest);

    // Then: a signer-revoked error is returned
    assert!(matches!(
        result,
        Err(ProvenanceError::Pep740SignerRevoked { key_id })
            if key_id == "revoked-key"
    ));
    Ok(())
}

#[test]
fn withdrawn_attestation_not_rejected_but_recorded() -> TestResult {
    // Given: a verifier with a CRL that marks the signer as withdrawn
    let digest = test_digest();
    let attestation = valid_attestation(&digest, "withdrawn-key")?;
    let mut crl = AttestationRevocationList::new();
    crl.add(RevocationEntry {
        key_id: "withdrawn-key".to_owned(),
        status: RevocationStatus::Withdrawn,
        revoked_at: "2026-07-23T00:00:00Z".to_owned(),
    });
    let verifier = Pep740Verifier::new(
        AttestationVerifierPolicy::new(),
        crl,
        VerifierIdentity::new("withdrawal-verifier"),
    );

    // When: verification is attempted
    let verification = verifier.verify(&attestation, &digest)?;

    // Then: verification succeeds but records the withdrawn status
    assert_eq!(verification.revocation_status, RevocationStatus::Withdrawn);
    Ok(())
}

#[test]
fn valid_signer_in_crl_passes() -> TestResult {
    // Given: a verifier with a CRL that marks the signer as valid
    let digest = test_digest();
    let attestation = valid_attestation(&digest, "valid-key")?;
    let mut crl = AttestationRevocationList::new();
    crl.add(RevocationEntry {
        key_id: "valid-key".to_owned(),
        status: RevocationStatus::Valid,
        revoked_at: "2026-07-23T00:00:00Z".to_owned(),
    });
    let verifier = Pep740Verifier::new(
        AttestationVerifierPolicy::new(),
        crl,
        VerifierIdentity::new("valid-verifier"),
    );

    // When: verification is attempted
    let verification = verifier.verify(&attestation, &digest)?;

    // Then: verification succeeds with Valid status
    assert_eq!(verification.revocation_status, RevocationStatus::Valid);
    Ok(())
}

#[test]
fn signer_not_in_crl_returns_unknown() -> TestResult {
    // Given: a verifier with a populated CRL that does not contain the signer
    let digest = test_digest();
    let attestation = valid_attestation(&digest, "unknown-key")?;
    let mut crl = AttestationRevocationList::new();
    crl.add(RevocationEntry {
        key_id: "other-key".to_owned(),
        status: RevocationStatus::Revoked,
        revoked_at: "2026-07-23T00:00:00Z".to_owned(),
    });
    let verifier = Pep740Verifier::new(
        AttestationVerifierPolicy::new(),
        crl,
        VerifierIdentity::new("unknown-verifier"),
    );

    // When: verification is attempted
    let verification = verifier.verify(&attestation, &digest)?;

    // Then: verification succeeds with Unknown status
    assert_eq!(verification.revocation_status, RevocationStatus::Unknown);
    Ok(())
}

#[test]
fn revocation_check_disabled_returns_unknown() -> TestResult {
    // Given: a verifier with revocation checking disabled and a revoked signer
    let digest = test_digest();
    let attestation = valid_attestation(&digest, "revoked-key")?;
    let mut crl = AttestationRevocationList::new();
    crl.add(RevocationEntry {
        key_id: "revoked-key".to_owned(),
        status: RevocationStatus::Revoked,
        revoked_at: "2026-07-23T00:00:00Z".to_owned(),
    });
    let policy = AttestationVerifierPolicy {
        check_revocation: false,
        ..AttestationVerifierPolicy::new()
    };
    let verifier =
        Pep740Verifier::new(policy, crl, VerifierIdentity::new("no-revocation-verifier"));

    // When: verification is attempted
    let verification = verifier.verify(&attestation, &digest)?;

    // Then: verification succeeds (revocation not checked) with Unknown status
    assert_eq!(verification.revocation_status, RevocationStatus::Unknown);
    Ok(())
}

// ---------------------------------------------------------------------------
// Verifier policy separate from publisher policy
// ---------------------------------------------------------------------------

#[test]
fn verifier_policy_is_separate_type_from_publisher_policy() {
    // Given: a verifier policy and a publisher policy
    let verifier_policy = AttestationVerifierPolicy::new();
    let publisher_policy = VerificationPolicy::new();

    // Then: they are different types and cannot be confused
    assert_ne!(
        std::any::type_name_of_val(&verifier_policy),
        std::any::type_name_of_val(&publisher_policy)
    );
}

#[test]
fn verifier_policy_accepts_known_predicate_types_by_default() {
    // Given: a default verifier policy
    let policy = AttestationVerifierPolicy::new();

    // Then: all known PEP 740 predicate types are accepted
    assert!(policy.accepts_predicate_type(PEP740_PUBLISH_PREDICATE_TYPE));
    assert!(policy.accepts_predicate_type("https://docs.pypi.org/attestations/provenance/v1"));
}

#[test]
fn verifier_policy_rejects_unknown_predicate_types_by_default() {
    // Given: a default verifier policy
    let policy = AttestationVerifierPolicy::new();

    // Then: unknown predicate types are rejected
    assert!(!policy.accepts_predicate_type("https://example.test/unknown/v1"));
}

#[test]
fn verifier_policy_rejects_registry_not_in_accepted_list() {
    // Given: a policy that only accepts PyPI
    let policy = AttestationVerifierPolicy {
        accepted_registries: vec![AttestationRegistry::pypi()],
        ..AttestationVerifierPolicy::new()
    };

    // Then: PyPI is accepted but crates.io is not
    assert!(policy.accepts_registry(&AttestationRegistry::pypi()));
    assert!(!policy.accepts_registry(&AttestationRegistry::crates_io()));
}

#[test]
fn verifier_policy_accepts_all_registries_by_default() {
    // Given: a default verifier policy
    let policy = AttestationVerifierPolicy::new();

    // Then: all registries are accepted
    assert!(policy.accepts_registry(&AttestationRegistry::pypi()));
    assert!(policy.accepts_registry(&AttestationRegistry::crates_io()));
    assert!(policy.accepts_registry(&AttestationRegistry::new("custom")));
}

// ---------------------------------------------------------------------------
// Base64 decoder tests
// ---------------------------------------------------------------------------

#[test]
fn base64_decodes_standard_alphabet() {
    // Given: a known base64 string
    let encoded = "aGVsbG8gd29ybGQ="; // "hello world"

    // When: decoded
    let decoded = decode_base64(encoded);

    // Then: the bytes match
    assert_eq!(decoded, Some(b"hello world".to_vec()));
}

#[test]
fn base64_decodes_without_padding() {
    // Given: a base64 string without padding
    let encoded = "aGVsbG8gd29ybGQ";

    // When: decoded
    let decoded = decode_base64(encoded);

    // Then: the bytes match
    assert_eq!(decoded, Some(b"hello world".to_vec()));
}

#[test]
fn base64_rejects_invalid_characters() {
    // Given: a string with invalid base64 characters
    let encoded = "!!!invalid!!!";

    // When: decoded
    let decoded = decode_base64(encoded);

    // Then: None is returned
    assert_eq!(decoded, None);
}

#[test]
fn base64_rejects_invalid_length() {
    // Given: a base64 string with invalid length (1 char after padding strip)
    let encoded = "A";

    // When: decoded
    let decoded = decode_base64(encoded);

    // Then: None is returned
    assert_eq!(decoded, None);
}

#[test]
fn base64_round_trips_with_encoder() {
    // Given: arbitrary bytes
    let original = b"{\"_type\":\"https://in-toto.io/Statement/v1\"}";

    // When: encoded then decoded
    let encoded = encode_base64(original);
    let decoded = decode_base64(&encoded);

    // Then: the round trip preserves the original bytes
    assert_eq!(decoded, Some(original.to_vec()));
}

// ---------------------------------------------------------------------------
// Crates.io stub tests
// ---------------------------------------------------------------------------

#[test]
fn crates_io_disabled_by_default() -> TestResult {
    // Given: a verifier created from a default policy
    let policy = AttestationVerifierPolicy::new();
    let verifier = CratesIoAttestationVerifier::from_policy(&policy);

    // When: verification is attempted
    let status = verifier.verify()?;

    // Then: Disabled is returned
    assert_eq!(status, CratesIoVerification::Disabled);
    Ok(())
}

#[test]
fn crates_io_not_implemented_when_enabled() -> TestResult {
    // Given: a verifier with crates.io recognition enabled
    let policy = AttestationVerifierPolicy {
        recognize_crates_io: true,
        ..AttestationVerifierPolicy::new()
    };
    let verifier = CratesIoAttestationVerifier::from_policy(&policy);

    // When: verification is attempted
    let status = verifier.verify()?;

    // Then: NotImplemented is returned (RFC GA Q3-Q4 2026)
    assert_eq!(status, CratesIoVerification::NotImplemented);
    Ok(())
}

#[test]
fn crates_io_explicit_disable() -> TestResult {
    // Given: a verifier explicitly disabled
    let verifier = CratesIoAttestationVerifier::new(false);

    // When: verification is attempted
    let status = verifier.verify()?;

    // Then: Disabled is returned
    assert_eq!(status, CratesIoVerification::Disabled);
    Ok(())
}

// ---------------------------------------------------------------------------
// Revocation list tests
// ---------------------------------------------------------------------------

#[test]
fn crl_returns_unknown_for_empty_list() {
    // Given: an empty CRL
    let crl = AttestationRevocationList::new();

    // When: checking any key
    let status = crl.check("any-key");

    // Then: Unknown is returned
    assert_eq!(status, RevocationStatus::Unknown);
}

#[test]
fn crl_finds_revoked_entry() {
    // Given: a CRL with a revoked entry
    let mut crl = AttestationRevocationList::new();
    crl.add(RevocationEntry {
        key_id: "key-1".to_owned(),
        status: RevocationStatus::Revoked,
        revoked_at: "2026-07-23T00:00:00Z".to_owned(),
    });

    // When: checking the revoked key
    let status = crl.check("key-1");

    // Then: Revoked is returned
    assert_eq!(status, RevocationStatus::Revoked);
}

#[test]
fn revocation_status_is_valid_only_for_valid() {
    assert!(RevocationStatus::Valid.is_valid());
    assert!(!RevocationStatus::Revoked.is_valid());
    assert!(!RevocationStatus::Withdrawn.is_valid());
    assert!(!RevocationStatus::Unknown.is_valid());
}

// ---------------------------------------------------------------------------
// Registry and verifier identity newtype tests
// ---------------------------------------------------------------------------

#[test]
fn registry_newtypes_are_distinct() {
    let pypi = AttestationRegistry::pypi();
    let crates_io = AttestationRegistry::crates_io();
    let custom = AttestationRegistry::new("custom");

    assert_ne!(pypi, crates_io);
    assert_ne!(pypi, custom);
    assert_ne!(crates_io, custom);
    assert_eq!(pypi.as_str(), "pypi");
    assert_eq!(crates_io.as_str(), "crates.io");
    assert_eq!(custom.as_str(), "custom");
}

#[test]
fn verifier_identity_displays() {
    let identity = VerifierIdentity::new("arbitraitor-verifier");
    assert_eq!(identity.as_str(), "arbitraitor-verifier");
    assert_eq!(identity.to_string(), "arbitraitor-verifier");
}
