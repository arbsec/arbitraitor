//! Shared attestation types used by PEP 740 and crates.io verifiers
//! (spec §31.3.1, §41.12, issue #469).
//!
//! These types are deliberately separate from the publisher-side
//! [`VerificationPolicy`](crate::VerificationPolicy) (spec §14.3). See
//! [`AttestationVerifierPolicy`] for the separation rationale.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Registry and verifier identity newtypes
// ---------------------------------------------------------------------------

/// A package registry that issues attestations (spec §41.12).
///
/// Newtype over `String` to prevent confusing registry identities with signer
/// identities or verifier identities.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AttestationRegistry(String);

impl AttestationRegistry {
    /// Creates a registry identity from a string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Creates the `PyPI` registry identity.
    #[must_use]
    pub fn pypi() -> Self {
        Self("pypi".to_owned())
    }

    /// Creates the crates.io registry identity.
    #[must_use]
    pub fn crates_io() -> Self {
        Self("crates.io".to_owned())
    }

    /// Returns the registry identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AttestationRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The identity of a verifier that checked an attestation (issue #469).
///
/// Recorded in the receipt so downstream consumers can audit which verifier
/// accepted the attestation. This is separate from the signer identity (who
/// produced the attestation) and the publisher identity (who published the
/// artifact).
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VerifierIdentity(String);

impl VerifierIdentity {
    /// Creates a verifier identity from a string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the verifier identity as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for VerifierIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Verifier-side policy (separate from publisher-side VerificationPolicy)
// ---------------------------------------------------------------------------

/// Verifier-side attestation policy (spec §31.3.1, issue #469).
///
/// This is **separate from the publisher-side
/// [`VerificationPolicy`](crate::VerificationPolicy)** (spec §14.3). The
/// publisher policy governs which signer identities are trusted to have
/// produced an artifact. The verifier policy governs which attestation types,
/// registries, and revocation states are accepted by the verifier when
/// evaluating provenance evidence.
///
/// Separation rationale (issue #469): a publisher may be trusted to sign
/// releases, but the verifier may still reject attestations from a registry
/// that has not been explicitly opted in, or whose revocation list is stale.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AttestationVerifierPolicy {
    /// Accepted attestation predicate types. Empty means all PEP 740 predicate
    /// types in [`PEP740_KNOWN_PREDICATE_TYPES`](crate::PEP740_KNOWN_PREDICATE_TYPES)
    /// are accepted.
    pub accepted_predicate_types: Vec<String>,
    /// Accepted registry identities. Empty means all registries are accepted.
    pub accepted_registries: Vec<AttestationRegistry>,
    /// Whether crates.io attestations are recognized (spec §41.12). Requires
    /// policy-side opt-in because Cargo RFC #3724 is GA Q3-Q4 2026.
    pub recognize_crates_io: bool,
    /// Whether to check the revocation list (CRL) before accepting an
    /// attestation. When `false`, revocation status is `Unknown`.
    pub check_revocation: bool,
    /// Maximum age of an attestation in seconds before it's considered stale.
    /// `None` means no age limit.
    pub max_attestation_age_secs: Option<u64>,
}

impl AttestationVerifierPolicy {
    /// Creates a policy with secure defaults: check revocation, do not
    /// recognize crates.io, accept all known PEP 740 predicate types.
    #[must_use]
    pub fn new() -> Self {
        Self {
            check_revocation: true,
            ..Self::default()
        }
    }

    /// Checks whether a predicate type is accepted by this policy.
    #[must_use]
    pub fn accepts_predicate_type(&self, predicate_type: &str) -> bool {
        if self.accepted_predicate_types.is_empty() {
            return crate::PEP740_KNOWN_PREDICATE_TYPES.contains(&predicate_type);
        }
        self.accepted_predicate_types
            .iter()
            .any(|accepted| accepted == predicate_type)
    }

    /// Checks whether a registry is accepted by this policy.
    #[must_use]
    pub fn accepts_registry(&self, registry: &AttestationRegistry) -> bool {
        if self.accepted_registries.is_empty() {
            return true;
        }
        self.accepted_registries
            .iter()
            .any(|accepted| accepted == registry)
    }
}

// ---------------------------------------------------------------------------
// Revocation (issue #469: CRL/withdrawal story)
// ---------------------------------------------------------------------------

/// Revocation status of an attestation signer (issue #469).
///
/// Extends the binary Active/Revoked model from `arbitraitor-plugin-host` with
/// `Withdrawn` (publisher-initiated) and `Unknown` (CRL check not performed or
/// unavailable).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    /// Attestation signer is valid and not revoked.
    Valid,
    /// Attestation signer has been revoked by the registry or CA (CRL match).
    Revoked,
    /// Attestation has been withdrawn by the publisher (not a revocation).
    Withdrawn,
    /// Revocation status could not be determined (CRL unavailable or not checked).
    Unknown,
}

impl RevocationStatus {
    /// Returns `true` when the signer is valid and not revoked or withdrawn.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// An entry in an attestation revocation list (issue #469).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEntry {
    /// Key identifier of the revoked or withdrawn attestation signer.
    pub key_id: String,
    /// Revocation status.
    pub status: RevocationStatus,
    /// RFC 3339 timestamp when the revocation was recorded.
    pub revoked_at: String,
}

/// A certificate revocation list for attestation signers (issue #469).
///
/// Provides the CRL check path for [`Pep740Verifier`](crate::Pep740Verifier).
/// When [`AttestationVerifierPolicy::check_revocation`] is `true`, the verifier
/// consults this list before accepting an attestation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct AttestationRevocationList {
    /// Revocation entries.
    pub entries: Vec<RevocationEntry>,
}

impl AttestationRevocationList {
    /// Creates an empty revocation list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks the revocation status of a signer by key identifier.
    ///
    /// Returns [`RevocationStatus::Unknown`] when the signer is not in the
    /// list (no revocation record found, but CRL was consulted).
    #[must_use]
    pub fn check(&self, key_id: &str) -> RevocationStatus {
        self.entries
            .iter()
            .find(|entry| entry.key_id == key_id)
            .map_or(RevocationStatus::Unknown, |entry| entry.status)
    }

    /// Adds a revocation entry.
    pub fn add(&mut self, entry: RevocationEntry) {
        self.entries.push(entry);
    }
}
