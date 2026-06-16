//! Identifier and digest newtypes used across the domain model.

use core::fmt;
use core::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

const SHA256_HEX_LEN: usize = 64;

/// A SHA-256 content digest.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

/// Error returned when parsing a [`Sha256Digest`] from hexadecimal text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sha256DigestParseError {
    /// The hex string was not exactly 64 characters long.
    InvalidLength,
    /// The hex string contained a non-hexadecimal character.
    InvalidHex,
}

impl fmt::Display for Sha256DigestParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => formatter.write_str("sha256 digest must be 64 hex characters"),
            Self::InvalidHex => formatter.write_str("sha256 digest contains invalid hex"),
        }
    }
}

impl std::error::Error for Sha256DigestParseError {}
impl Sha256Digest {
    /// Creates a digest from exactly 32 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Sha256Digest {
    type Err = Sha256DigestParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != SHA256_HEX_LEN {
            return Err(Sha256DigestParseError::InvalidLength);
        }

        let mut bytes = [0_u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_hex_digit(chunk[0])?;
            let low = decode_hex_digit(chunk[1])?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

fn decode_hex_digit(value: u8) -> Result<u8, Sha256DigestParseError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(Sha256DigestParseError::InvalidHex),
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
        struct Sha256DigestVisitor;

        impl Visitor<'_> for Sha256DigestVisitor {
            type Value = Sha256Digest;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a 64-character SHA-256 hex digest")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(Sha256DigestVisitor)
    }
}

/// Stable artifact identity, derived from the artifact SHA-256 digest.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ArtifactId(pub Sha256Digest);

/// Unique identifier for a planned or executed operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OperationId(Uuid);

impl OperationId {
    /// Generates a new sortable operation identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for OperationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for OperationId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for OperationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OperationIdVisitor;

        impl Visitor<'_> for OperationIdVisitor {
            type Value = OperationId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a UUID string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Uuid::parse_str(value).map(OperationId).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(OperationIdVisitor)
    }
}

/// Unique identifier for a detector or policy plugin.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PluginId(pub String);
#[cfg(test)]
mod tests {
    use super::{ArtifactId, OperationId, PluginId, Sha256Digest};

    fn sample_digest() -> Sha256Digest {
        Sha256Digest::new([0xab; 32])
    }

    #[test]
    fn digest_displays_and_parses_hex() -> Result<(), Box<dyn std::error::Error>> {
        let digest = sample_digest();
        let hex = digest.to_string();
        assert_eq!(hex, "ab".repeat(32));
        assert_eq!(hex.parse::<Sha256Digest>()?, digest);
        assert_eq!("AB".repeat(32).parse::<Sha256Digest>()?, digest);
        Ok(())
    }

    #[test]
    fn digest_rejects_invalid_hex_edges() {
        assert!("".parse::<Sha256Digest>().is_err());
        assert!("00".repeat(31).parse::<Sha256Digest>().is_err());
        assert!(
            format!("{}zz", "00".repeat(31))
                .parse::<Sha256Digest>()
                .is_err()
        );
    }

    #[test]
    fn digest_round_trips_as_json_string() -> Result<(), Box<dyn std::error::Error>> {
        let digest = sample_digest();
        let json = serde_json::to_string(&digest)?;
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        assert_eq!(serde_json::from_str::<Sha256Digest>(&json)?, digest);
        Ok(())
    }

    #[test]
    fn id_newtypes_round_trip_edge_values() -> Result<(), Box<dyn std::error::Error>> {
        let artifact = ArtifactId(Sha256Digest::new([u8::MAX; 32]));
        let operation = OperationId::new();
        let plugin = PluginId("plugin.example.detector".to_owned());

        assert_eq!(
            serde_json::from_str::<ArtifactId>(&serde_json::to_string(&artifact)?)?,
            artifact
        );
        assert_eq!(
            serde_json::from_str::<OperationId>(&serde_json::to_string(&operation)?)?,
            operation
        );
        assert_eq!(
            serde_json::from_str::<PluginId>(&serde_json::to_string(&plugin)?)?,
            plugin
        );
        Ok(())
    }

    #[test]
    fn operation_id_rejects_empty_json_string() {
        assert!(serde_json::from_str::<OperationId>("\"\"").is_err());
    }
}
