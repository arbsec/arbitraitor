//! Retention policy modes for quarantined artifacts.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Store retention mode for an artifact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionMode {
    /// Delete immediately after the operation completes.
    Ephemeral,
    /// Delete when the Arbitraitor process exits.
    Session,
    /// Retain indefinitely for forensic analysis.
    Forensic,
    /// Retain artifacts that passed inspection; delete blocked ones.
    Cache,
    /// Retain all artifacts until explicitly deleted.
    Indefinite,
}
