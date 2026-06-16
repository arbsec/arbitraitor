//! Error types for signed update verification.

use thiserror::Error;

/// Errors produced while verifying update metadata or targets.
#[derive(Debug, Error)]
pub enum UpdateError {
    /// The supplied minisign signature did not verify.
    #[error("update signature is invalid: {reason}")]
    SignatureInvalid {
        /// Safe diagnostic reason for the signature failure.
        reason: String,
    },

    /// No signature was supplied for a manifest.
    #[error("update signature is missing for manifest version {manifest_version}")]
    SignatureMissing {
        /// Manifest version associated with the missing signature, or `unknown`.
        manifest_version: String,
    },

    /// The attempted manifest version is not newer than the current version.
    #[error(
        "update manifest rollback rejected: current version {current}, attempted version {attempted}"
    )]
    VersionRollback {
        /// Current trusted manifest version.
        current: u64,
        /// Attempted manifest version that was not newer.
        attempted: u64,
    },

    /// The manifest expired before the supplied current time.
    #[error("update manifest expired at {expired_at}")]
    ManifestExpired {
        /// ISO 8601 expiration timestamp from the manifest.
        expired_at: String,
    },

    /// The manifest uses an unsupported schema version.
    #[error("unsupported update manifest schema version {found}; expected {expected}")]
    UnsupportedSchema {
        /// Schema version found in the manifest.
        found: u32,
        /// Schema version supported by this verifier.
        expected: u32,
    },

    /// The manifest could not be parsed or violates manifest invariants.
    #[error("update manifest is invalid: {reason}")]
    InvalidManifest {
        /// Safe diagnostic reason for the invalid manifest.
        reason: String,
    },

    /// The manifest could not be parsed or a target verification failed.
    #[error("update manifest is malformed: {reason}")]
    ManifestMalformed {
        /// Safe diagnostic reason for the malformed manifest or target mismatch.
        reason: String,
    },

    /// The configured verifier cannot be constructed or used.
    #[error("update verifier unavailable: {reason}")]
    VerifierUnavailable {
        /// Safe diagnostic reason the verifier could not be constructed or used.
        reason: String,
    },
}
