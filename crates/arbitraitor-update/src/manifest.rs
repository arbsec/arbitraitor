//! Versioned update manifest data structures.

use std::fmt;
use std::path::Path;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::UpdateError;

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

impl UpdateManifest {
    /// Validate security invariants required for trusted update metadata.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::InvalidManifest`] when a manifest invariant is
    /// violated.
    pub fn validate_manifest(&self) -> Result<(), UpdateError> {
        if self.targets.is_empty() {
            return Err(invalid_manifest(
                "manifest must contain at least one target",
            ));
        }
        validate_bounded_non_empty("publisher", &self.publisher, 256)?;
        for target in &self.targets {
            target.validate()?;
        }
        Ok(())
    }
}

/// A file described by an update manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTarget {
    /// Relative path to the target file.
    pub path: TargetPath,
    /// Expected SHA-256 digest encoded as 64 lowercase hex characters.
    pub sha256: Sha256Digest,
    /// Expected byte count.
    pub size: u64,
    /// Semantic version of the target payload.
    pub target_version: String,
}

impl UpdateTarget {
    fn validate(&self) -> Result<(), UpdateError> {
        validate_bounded_non_empty("target_version", &self.target_version, 128)?;
        if self.size == 0 {
            return Err(invalid_manifest(format!(
                "target {} size must be greater than 0",
                self.path
            )));
        }
        Ok(())
    }
}

/// Validated relative update target path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TargetPath(String);

impl TargetPath {
    /// Construct a target path after rejecting traversal and platform-absolute forms.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::InvalidManifest`] when `path` is empty, absolute,
    /// contains traversal components, a Windows drive prefix, backslashes, or NUL.
    pub fn new(path: impl Into<String>) -> Result<Self, UpdateError> {
        let path = path.into();
        validate_target_path(&path)?;
        Ok(Self(path))
    }
}
impl AsRef<Path> for TargetPath {
    fn as_ref(&self) -> &Path {
        Path::new(&self.0)
    }
}

impl fmt::Display for TargetPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for TargetPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TargetPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TargetPathVisitor;

        impl Visitor<'_> for TargetPathVisitor {
            type Value = TargetPath;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a safe relative target path")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                TargetPath::new(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(TargetPathVisitor)
    }
}

/// Parsed SHA-256 digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Parse a digest from 64 lowercase hex characters.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::InvalidManifest`] when the digest is not exactly
    /// 64 lowercase hexadecimal characters.
    pub fn from_hex(value: &str) -> Result<Self, UpdateError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(invalid_manifest(
                "sha256 must be exactly 64 lowercase hex characters",
            ));
        }

        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(value, &mut bytes)
            .map_err(|error| invalid_manifest(error.to_string()))?;
        Ok(Self(bytes))
    }

    /// Construct a digest from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DigestVisitor;

        impl Visitor<'_> for DigestVisitor {
            type Value = Sha256Digest;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("64 lowercase hex characters")
            }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Sha256Digest::from_hex(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(DigestVisitor)
    }
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

fn validate_bounded_non_empty(name: &str, value: &str, max_len: usize) -> Result<(), UpdateError> {
    if value.is_empty() {
        return Err(invalid_manifest(format!("{name} must not be empty")));
    }
    if value.len() > max_len {
        return Err(invalid_manifest(format!(
            "{name} must be at most {max_len} bytes"
        )));
    }
    Ok(())
}

fn validate_target_path(path: &str) -> Result<(), UpdateError> {
    if path.is_empty() {
        return Err(invalid_manifest("target path must not be empty"));
    }
    if path.as_bytes().contains(&0) {
        return Err(invalid_manifest("target path must not contain NUL bytes"));
    }
    if path.starts_with('/') || path.starts_with('\\') || has_windows_drive_prefix(path) {
        return Err(invalid_manifest("target path must be relative"));
    }
    if path.contains('\\') {
        return Err(invalid_manifest("target path must use forward slashes"));
    }
    if path.split('/').any(|component| component == "..") {
        return Err(invalid_manifest(
            "target path must not contain traversal components",
        ));
    }
    Ok(())
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn invalid_manifest(reason: impl Into<String>) -> UpdateError {
    UpdateError::InvalidManifest {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_relative_target_path() -> Result<(), Box<dyn std::error::Error>> {
        let path = TargetPath::new("rules/core.yar")?;
        assert_eq!(path.to_string(), "rules/core.yar");
        assert_eq!(path.as_ref(), Path::new("rules/core.yar"));
        Ok(())
    }

    #[test]
    fn rejects_target_path_traversal() {
        let error = TargetPath::new("rules/../../.ssh/authorized_keys").err();
        assert!(matches!(error, Some(UpdateError::InvalidManifest { .. })));
    }

    #[test]
    fn rejects_absolute_target_path() {
        let error = TargetPath::new("/etc/passwd").err();
        assert!(matches!(error, Some(UpdateError::InvalidManifest { .. })));
    }

    #[test]
    fn rejects_empty_target_path() {
        let error = TargetPath::new("").err();
        assert!(matches!(error, Some(UpdateError::InvalidManifest { .. })));
    }

    #[test]
    fn rejects_windows_target_path() {
        let drive_error = TargetPath::new("C:\\Windows\\System32").err();
        assert!(matches!(
            drive_error,
            Some(UpdateError::InvalidManifest { .. })
        ));

        let backslash_error = TargetPath::new("rules\\core.yar").err();
        assert!(matches!(
            backslash_error,
            Some(UpdateError::InvalidManifest { .. })
        ));
    }

    #[test]
    fn rejects_target_path_with_nul() {
        let error = TargetPath::new("rules/core\0.yar").err();
        assert!(matches!(error, Some(UpdateError::InvalidManifest { .. })));
    }

    #[test]
    fn parses_lowercase_sha256_digest() -> Result<(), Box<dyn std::error::Error>> {
        let digest = Sha256Digest::from_hex(
            "3cfe5c044c1050206b76c938a3b5645d9c6ad975748b078516f871bbb384875b",
        )?;
        assert_eq!(
            digest.to_string(),
            "3cfe5c044c1050206b76c938a3b5645d9c6ad975748b078516f871bbb384875b"
        );
        Ok(())
    }

    #[test]
    fn rejects_non_lowercase_sha256_digest() {
        let error = Sha256Digest::from_hex(
            "3CFE5C044C1050206B76C938A3B5645D9C6AD975748B078516F871BBB384875B",
        )
        .err();
        assert!(matches!(error, Some(UpdateError::InvalidManifest { .. })));
    }

    #[test]
    fn validates_manifest_invariants() -> Result<(), Box<dyn std::error::Error>> {
        let mut manifest = valid_manifest()?;
        manifest.validate_manifest()?;

        manifest.targets.clear();
        let error = manifest.validate_manifest().err();
        assert!(matches!(error, Some(UpdateError::InvalidManifest { .. })));
        Ok(())
    }
    #[test]
    fn rejects_empty_or_oversized_publisher() -> Result<(), Box<dyn std::error::Error>> {
        let mut manifest = valid_manifest()?;
        manifest.publisher.clear();
        let empty_error = manifest.validate_manifest().err();
        assert!(matches!(
            empty_error,
            Some(UpdateError::InvalidManifest { .. })
        ));

        manifest.publisher = "p".repeat(257);
        let long_error = manifest.validate_manifest().err();
        assert!(matches!(
            long_error,
            Some(UpdateError::InvalidManifest { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_empty_or_oversized_target_version() -> Result<(), Box<dyn std::error::Error>> {
        let mut manifest = valid_manifest()?;
        manifest.targets[0].target_version.clear();
        let empty_error = manifest.validate_manifest().err();
        assert!(matches!(
            empty_error,
            Some(UpdateError::InvalidManifest { .. })
        ));
        manifest.targets[0].target_version = "v".repeat(129);
        let long_error = manifest.validate_manifest().err();
        assert!(matches!(
            long_error,
            Some(UpdateError::InvalidManifest { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_zero_sized_target() -> Result<(), Box<dyn std::error::Error>> {
        let mut manifest = valid_manifest()?;
        manifest.targets[0].size = 0;
        let error = manifest.validate_manifest().err();
        assert!(matches!(error, Some(UpdateError::InvalidManifest { .. })));
        Ok(())
    }

    fn valid_manifest() -> Result<UpdateManifest, UpdateError> {
        Ok(UpdateManifest {
            schema_version: CURRENT_SCHEMA_VERSION,
            manifest_version: 7,
            channel: UpdateChannel::RulePacks,
            targets: vec![UpdateTarget {
                path: TargetPath::new("rules/core.yar")?,
                sha256: Sha256Digest::from_hex(
                    "3cfe5c044c1050206b76c938a3b5645d9c6ad975748b078516f871bbb384875b",
                )?,
                size: 12,
                target_version: "1.2.3".to_owned(),
            }],
            published_at: "2026-06-16T00:00:00Z".to_owned(),
            expires_at: "2026-12-31T23:59:59Z".to_owned(),
            publisher: "test-key".to_owned(),
        })
    }
}
