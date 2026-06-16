//! Versioned update manifest data structures.

use serde::{Deserialize, Serialize};

/// Current update manifest schema version.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Signed metadata describing update targets for a single channel.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateManifest {
    /// Manifest schema version. Currently [`CURRENT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Monotonically increasing manifest version for rollback protection.
    pub manifest_version: u64,
    /// Update channel this manifest applies to.
    pub channel: UpdateChannel,
    /// Files covered by this manifest.
    pub targets: Vec<UpdateTarget>,
    /// ISO 8601 publication timestamp.
    pub published_at: String,

    /// ISO 8601 expiration timestamp. The manifest is invalid after this time.
    pub expires_at: String,
    /// Signing key identifier for the publisher.
    pub publisher: String,
}

/// A file described by an update manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTarget {
    /// Relative path to the target file.
    pub path: String,
    /// Expected SHA-256 digest encoded as lowercase or uppercase hex.
    pub sha256: String,
    /// Expected byte count.
    pub size: u64,
    /// Semantic version of the target payload.
    pub target_version: String,
}

/// Supported signed update channels.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateChannel {
    /// Built-in rule packs.
    RulePacks,
    /// Intelligence feeds.
    IntelFeeds,
    /// Trust-root metadata.
    TrustRoot,
    /// Plugin registry metadata.
    PluginRegistry,
}
