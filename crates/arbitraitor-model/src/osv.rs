//! OSV advisory identifier newtypes.

use core::fmt;
use core::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const OSV_MAL_PREFIX: &str = "MAL-";
const OSV_MAL_YEAR_LEN: usize = 4;
const OSV_MAL_MIN_NUMBER_LEN: usize = 4;

/// `OpenSSF` malicious-packages OSV identifier (`MAL-YYYY-NNNN...`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OsvMalId(String);

/// Error returned when parsing an [`OsvMalId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OsvMalIdParseError {
    /// The identifier did not start with `MAL-`.
    InvalidPrefix,
    /// The identifier was missing a four-digit year segment.
    InvalidYear,
    /// The identifier was missing a numeric sequence with at least four digits.
    InvalidNumber,
    /// The identifier had extra separators or trailing content.
    InvalidShape,
}

impl fmt::Display for OsvMalIdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix => formatter.write_str("OSV MAL ID must start with MAL-"),
            Self::InvalidYear => formatter.write_str("OSV MAL ID must include a four-digit year"),
            Self::InvalidNumber => formatter
                .write_str("OSV MAL ID must include a numeric sequence of at least four digits"),
            Self::InvalidShape => formatter.write_str("OSV MAL ID must have shape MAL-YYYY-NNNN"),
        }
    }
}

impl std::error::Error for OsvMalIdParseError {}

impl OsvMalId {
    /// Parses an `OpenSSF` malicious-packages OSV identifier.
    ///
    /// # Errors
    /// Returns [`OsvMalIdParseError`] when `value` is not `MAL-YYYY-NNNN...`.
    pub fn parse(value: &str) -> Result<Self, OsvMalIdParseError> {
        value.parse()
    }

    /// Returns the identifier as canonical text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OsvMalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for OsvMalId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for OsvMalId {
    type Err = OsvMalIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(rest) = value.strip_prefix(OSV_MAL_PREFIX) else {
            return Err(OsvMalIdParseError::InvalidPrefix);
        };
        let Some((year, number)) = rest.split_once('-') else {
            return Err(OsvMalIdParseError::InvalidShape);
        };
        if number.contains('-') {
            return Err(OsvMalIdParseError::InvalidShape);
        }
        if year.len() != OSV_MAL_YEAR_LEN || !year.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(OsvMalIdParseError::InvalidYear);
        }
        if number.len() < OSV_MAL_MIN_NUMBER_LEN
            || !number.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(OsvMalIdParseError::InvalidNumber);
        }
        Ok(Self(value.to_owned()))
    }
}

impl Serialize for OsvMalId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for OsvMalId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OsvMalIdVisitor;

        impl Visitor<'_> for OsvMalIdVisitor {
            type Value = OsvMalId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an OpenSSF malicious-packages MAL-YYYY-NNNN identifier")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(OsvMalIdVisitor)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::OsvMalId;

    #[test]
    fn osv_mal_id_accepts_real_identifier_shape() -> Result<(), Box<dyn std::error::Error>> {
        let id = "MAL-2026-1234".parse::<OsvMalId>()?;

        assert_eq!(id.as_str(), "MAL-2026-1234");
        assert_eq!(id.to_string(), "MAL-2026-1234");
        Ok(())
    }

    #[test]
    fn osv_mal_id_rejects_invalid_shapes() {
        for invalid in [
            "",
            "mal-2026-1234",
            "MAL-26-1234",
            "MAL-2026-12",
            "MAL-2026-abcd",
            "MAL--1234",
            "MAL-2026-1234-extra",
        ] {
            assert!(invalid.parse::<OsvMalId>().is_err(), "accepted {invalid}");
        }
    }

    proptest! {
        #[test]
        fn osv_mal_id_round_trips_valid_generated_ids(year in 2000_u16..=9999, number in 1000_u32..=999_999) {
            let rendered = format!("MAL-{year:04}-{number}");
            let parsed = rendered.parse::<OsvMalId>()?;

            prop_assert_eq!(parsed.as_str(), rendered.as_str());
            prop_assert_eq!(parsed.to_string(), rendered);
        }
    }
}
