//! crates.io Cargo RFC #3724 attestation verifier stub (spec §41.12, issue #469).
//!
//! Cargo RFC #3724 was accepted Q4 2025 and is rolling to GA in Q3-Q4 2026.
//! This module provides a policy-side opt-in stub so policy authors can
//! recognize crates.io Rekor tiles before the implementation is complete.
//! The verifier returns [`CratesIoVerification::NotImplemented`] until
//! sigstore-rust 0.11+ integration lands.

use crate::Result;
use crate::attestation::AttestationVerifierPolicy;

/// Stub verifier for crates.io Cargo RFC #3724 attestations (spec §41.12).
///
/// Policy-side opt-in is required via
/// [`AttestationVerifierPolicy::recognize_crates_io`] because the RFC is not
/// yet GA. When disabled, all verification attempts return
/// [`CratesIoVerification::Disabled`].
pub struct CratesIoAttestationVerifier {
    /// Whether this verifier is enabled (policy-side opt-in).
    enabled: bool,
}

/// Result of a crates.io attestation verification attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CratesIoVerification {
    /// crates.io attestation verification is not yet implemented.
    ///
    /// The RFC is GA Q3-Q4 2026; sigstore-rust 0.11+ integration is required.
    NotImplemented,
    /// crates.io attestation verification is disabled by policy.
    Disabled,
}

impl CratesIoAttestationVerifier {
    /// Creates a new crates.io verifier from the verifier policy. When
    /// [`AttestationVerifierPolicy::recognize_crates_io`] is `false`, all
    /// verification attempts return [`CratesIoVerification::Disabled`].
    #[must_use]
    pub fn from_policy(policy: &AttestationVerifierPolicy) -> Self {
        Self {
            enabled: policy.recognize_crates_io,
        }
    }

    /// Creates a new crates.io verifier with explicit enable/disable.
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Attempts to verify a crates.io attestation.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok`. This will change when sigstore-rust 0.11+
    /// integration lands and actual verification is implemented.
    pub fn verify(&self) -> Result<CratesIoVerification> {
        if !self.enabled {
            return Ok(CratesIoVerification::Disabled);
        }
        Ok(CratesIoVerification::NotImplemented)
    }
}
