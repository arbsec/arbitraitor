//! Error type for policy loading and evaluation.

use thiserror::Error;

/// Errors that arise during policy parsing, validation, or digest computation.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The TOML document could not be parsed.
    #[error("failed to parse policy TOML: {0}")]
    Parse(#[from] toml::de::Error),

    /// The parsed policy is structurally valid TOML but semantically invalid
    /// (unsupported version, malformed condition, etc.).
    #[error("invalid policy: {0}")]
    Invalid(String),

    /// Canonical serialization for the digest failed.
    #[error("failed to serialize policy for digest: {0}")]
    Digest(String),

    /// A lower-precedence policy tried to weaken an inherited layer.
    #[error("policy layer {layer:?} weakens inherited policy: {detail}")]
    Weakening {
        /// Layer that attempted the weakening change.
        layer: crate::PolicyPrecedence,
        /// Human-readable monotonicity violations.
        detail: String,
    },

    /// A CLI override was provided without explicit audit consent.
    #[error("CLI policy override requires --audit-override")]
    AuditOverrideRequired,
}
