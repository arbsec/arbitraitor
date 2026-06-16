//! Detector findings and detector metadata.

use core::fmt;
use core::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactKind;
use crate::ids::Sha256Digest;
use crate::verdict::{Confidence, Severity};

/// Category describing the security or analysis concern behind a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingCategory {
    /// Provenance or origin concern.
    Provenance,
    /// Reputation concern.
    Reputation,
    /// Transport-layer concern.
    Transport,
    /// Expected and observed content differ.
    ContentMismatch,
    /// Malware signature match.
    MalwareSignature,
    /// Suspicious script behavior.
    SuspiciousScriptBehavior,
    /// Obfuscation detected.
    Obfuscation,
    /// Credential access behavior.
    CredentialAccess,
    /// Persistence behavior.
    Persistence,
    /// Privilege escalation behavior.
    PrivilegeEscalation,
    /// Destructive behavior.
    DestructiveBehavior,
    /// Network behavior.
    NetworkBehavior,
    /// Dynamic code execution behavior.
    DynamicCodeExecution,
    /// Archive hazard.
    ArchiveHazard,
    /// Package ecosystem risk.
    PackageRisk,
    /// Policy violation.
    PolicyViolation,
    /// Parser error.
    ParserError,
    /// Resource limit event.
    ResourceLimitEvent,
}

/// A detector finding emitted for an artifact.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// Stable finding identifier within the detector output.
    pub id: String,
    /// Identifier of the detector that produced the finding.
    pub detector: String,
    /// Finding category.
    pub category: FindingCategory,
    /// Finding severity.
    pub severity: Severity,
    /// Detector confidence in this finding.
    pub confidence: Confidence,
    /// Human-readable finding title.
    pub title: String,
    /// Detailed finding description.
    pub description: String,
    /// Supporting evidence for the finding.
    pub evidence: Vec<Evidence>,
    /// SHA-256 digest of the artifact this finding applies to.
    pub artifact_sha256: Sha256Digest,
    /// Optional source location for findings tied to text or bytes.
    pub location: Option<SourceLocation>,
    /// Optional remediation guidance.
    pub remediation: Option<String>,
    /// External references for this finding.
    pub references: Vec<String>,
    /// Machine-readable tags for grouping or policy matching.
    pub tags: Vec<String>,
}

/// Supporting evidence attached to a finding.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Evidence kind.
    pub kind: EvidenceKind,
    /// Human-readable evidence description.
    pub description: String,
    /// Optional bounded evidence content.
    pub content: Option<String>,
}

impl fmt::Debug for Evidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("Evidence");
        debug.field("kind", &self.kind);
        debug.field("description", &self.description);

        let redacted_content = self.content.as_deref().map(bounded_debug_text);
        debug.field("content", &redacted_content);
        debug.finish()
    }
}

fn bounded_debug_text(value: &str) -> String {
    const MAX_DEBUG_CHARS: usize = 80;

    let escaped: String = value.escape_debug().collect();
    let mut bounded: String = escaped.chars().take(MAX_DEBUG_CHARS).collect();
    if escaped.chars().count() > MAX_DEBUG_CHARS {
        bounded.push('…');
    }
    bounded
}
/// Evidence representation kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    /// Source snippet evidence.
    SourceSnippet,
    /// Decoded content evidence.
    DecodedContent,
    /// URL evidence.
    Url,
    /// Command evidence.
    Command,
    /// File path evidence.
    FilePath,
    /// Network endpoint evidence.
    NetworkEndpoint,
    /// Other evidence kind.
    Other,
}

/// Source or byte location for a finding.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SourceLocation {
    /// 1-indexed line number.
    pub line: NonZeroU32,
    /// 1-indexed column number.
    pub column: NonZeroU32,
    /// Optional 1-indexed ending line number.
    pub end_line: Option<NonZeroU32>,
    /// Optional 1-indexed ending column number.
    pub end_column: Option<NonZeroU32>,
    /// Optional zero-indexed byte offset.
    pub byte_offset: Option<u64>,
}

impl SourceLocation {
    /// Creates a validated source location.
    ///
    /// # Errors
    ///
    /// Returns [`SourceLocationError::ReversedRange`] when an end position precedes the start.
    pub fn new(
        line: NonZeroU32,
        column: NonZeroU32,
        end_line: Option<NonZeroU32>,
        end_column: Option<NonZeroU32>,
        byte_offset: Option<u64>,
    ) -> Result<Self, SourceLocationError> {
        let location = Self {
            line,
            column,
            end_line,
            end_column,
            byte_offset,
        };
        location.validate_range()?;
        Ok(location)
    }

    fn validate_range(&self) -> Result<(), SourceLocationError> {
        match (self.end_line, self.end_column) {
            (Some(end_line), Some(end_column)) => {
                SourceRange::new(
                    SourcePosition::new(self.line, self.column),
                    SourcePosition::new(end_line, end_column),
                )?;
                Ok(())
            }
            (Some(end_line), None) if end_line < self.line => {
                Err(SourceLocationError::ReversedRange)
            }
            (None, Some(end_column)) if end_column < self.column => {
                Err(SourceLocationError::ReversedRange)
            }
            _ => Ok(()),
        }
    }
}

impl<'de> Deserialize<'de> for SourceLocation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawSourceLocation {
            line: NonZeroU32,
            column: NonZeroU32,
            end_line: Option<NonZeroU32>,
            end_column: Option<NonZeroU32>,
            byte_offset: Option<u64>,
        }

        let raw = RawSourceLocation::deserialize(deserializer)?;
        Self::new(
            raw.line,
            raw.column,
            raw.end_line,
            raw.end_column,
            raw.byte_offset,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// 1-indexed source position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePosition {
    /// 1-indexed line number.
    pub line: NonZeroU32,
    /// 1-indexed column number.
    pub column: NonZeroU32,
}

impl SourcePosition {
    /// Creates a source position.
    #[must_use]
    pub const fn new(line: NonZeroU32, column: NonZeroU32) -> Self {
        Self { line, column }
    }
}

/// Inclusive source range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct SourceRange {
    /// Start position.
    pub start: SourcePosition,
    /// End position.
    pub end: SourcePosition,
}

impl SourceRange {
    /// Creates a source range whose end is not before its start.
    ///
    /// # Errors
    ///
    /// Returns [`SourceLocationError::ReversedRange`] when `end` precedes `start`.
    pub fn new(start: SourcePosition, end: SourcePosition) -> Result<Self, SourceLocationError> {
        if (end.line, end.column) < (start.line, start.column) {
            return Err(SourceLocationError::ReversedRange);
        }
        Ok(Self { start, end })
    }
}

impl<'de> Deserialize<'de> for SourceRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawSourceRange {
            start: SourcePosition,
            end: SourcePosition,
        }

        let raw = RawSourceRange::deserialize(deserializer)?;
        Self::new(raw.start, raw.end).map_err(serde::de::Error::custom)
    }
}

/// Invalid source location or range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceLocationError {
    /// End position precedes start position.
    ReversedRange,
}

impl fmt::Display for SourceLocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReversedRange => formatter.write_str("source range end precedes start"),
        }
    }
}

impl std::error::Error for SourceLocationError {}

/// Metadata advertised by a detector implementation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorMetadata {
    /// Detector identifier.
    pub id: String,
    /// Detector version string.
    pub version: String,
    /// Artifact kinds supported by this detector.
    pub supported_artifact_kinds: Vec<ArtifactKind>,
    /// Named detector capabilities.
    pub capabilities: Vec<String>,
    /// Whether the detector runs locally.
    pub is_local: bool,
    /// Whether the detector may upload content or metadata.
    pub may_upload: bool,
    /// Default detector timeout in milliseconds.
    pub default_timeout_ms: u64,
    /// Whether the detector is deterministic for identical inputs.
    pub is_deterministic: bool,
}
#[cfg(test)]
mod tests {
    use super::{
        DetectorMetadata, Evidence, EvidenceKind, Finding, FindingCategory, SourceLocation,
        SourcePosition, SourceRange,
    };
    use crate::artifact::{ArtifactKind, ShellDialect};
    use crate::ids::Sha256Digest;
    use crate::verdict::{Confidence, Severity};
    use core::num::NonZeroU32;

    fn digest() -> Sha256Digest {
        Sha256Digest::new([0x42; 32])
    }

    #[test]
    fn finding_category_round_trips_edge_variant() -> Result<(), Box<dyn std::error::Error>> {
        let value = FindingCategory::ResourceLimitEvent;
        assert_eq!(
            serde_json::from_str::<FindingCategory>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }

    #[test]
    fn evidence_kind_round_trips_edge_variant() -> Result<(), Box<dyn std::error::Error>> {
        let value = EvidenceKind::NetworkEndpoint;
        assert_eq!(
            serde_json::from_str::<EvidenceKind>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }

    #[test]
    fn evidence_round_trips_empty_content_edge() -> Result<(), Box<dyn std::error::Error>> {
        let value = Evidence {
            kind: EvidenceKind::Other,
            description: String::new(),
            content: None,
        };
        assert_eq!(
            serde_json::from_str::<Evidence>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }

    fn nonzero(value: u32) -> Result<NonZeroU32, Box<dyn std::error::Error>> {
        NonZeroU32::new(value).ok_or_else(|| "test value must be non-zero".into())
    }

    #[test]
    fn source_location_round_trips_valid_edges() -> Result<(), Box<dyn std::error::Error>> {
        let value = SourceLocation::new(
            nonzero(u32::MAX)?,
            nonzero(u32::MAX)?,
            Some(nonzero(u32::MAX)?),
            Some(nonzero(u32::MAX)?),
            Some(u64::MAX),
        )?;
        assert_eq!(
            serde_json::from_str::<SourceLocation>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }

    #[test]
    fn source_location_rejects_zero_and_reversed_ranges() {
        let zero_line =
            r#"{"line":0,"column":1,"end_line":null,"end_column":null,"byte_offset":null}"#;
        assert!(serde_json::from_str::<SourceLocation>(zero_line).is_err());

        let reversed = r#"{"line":2,"column":1,"end_line":1,"end_column":1,"byte_offset":null}"#;
        assert!(serde_json::from_str::<SourceLocation>(reversed).is_err());
    }

    #[test]
    fn source_range_constructor_rejects_reversed_range() -> Result<(), Box<dyn std::error::Error>> {
        let start = SourcePosition::new(nonzero(2)?, nonzero(1)?);
        let end = SourcePosition::new(nonzero(1)?, nonzero(1)?);
        assert!(SourceRange::new(start, end).is_err());
        Ok(())
    }

    #[test]
    fn evidence_debug_bounds_and_escapes_content() {
        let value = Evidence {
            kind: EvidenceKind::Other,
            description: "description".to_owned(),
            content: Some(format!("line\n{}", "x".repeat(100))),
        };
        let debug = format!("{value:?}");
        assert!(debug.contains("line\\\\n"));
        assert!(debug.contains('…'));
        assert!(!debug.contains("x".repeat(100).as_str()));
    }

    #[test]
    fn finding_round_trips_with_optional_edges() -> Result<(), Box<dyn std::error::Error>> {
        let value = Finding {
            id: String::new(),
            detector: "detector.local".to_owned(),
            category: FindingCategory::ContentMismatch,
            severity: Severity::High,
            confidence: Confidence::Confirmed,
            title: "unexpected content".to_owned(),
            description: "expected script, observed html".to_owned(),
            evidence: vec![Evidence {
                kind: EvidenceKind::SourceSnippet,
                description: "snippet".to_owned(),
                content: Some("<html>".to_owned()),
            }],
            artifact_sha256: digest(),
            location: None,
            remediation: None,
            references: Vec::new(),
            tags: vec!["classifier".to_owned()],
        };
        assert_eq!(
            serde_json::from_str::<Finding>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }
    #[test]
    fn detector_metadata_round_trips_with_empty_capabilities()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = DetectorMetadata {
            id: "detector".to_owned(),
            version: String::new(),
            supported_artifact_kinds: vec![ArtifactKind::ShellScript(ShellDialect::Posix)],
            capabilities: Vec::new(),
            is_local: true,
            may_upload: false,
            default_timeout_ms: u64::MAX,
            is_deterministic: true,
        };
        assert_eq!(
            serde_json::from_str::<DetectorMetadata>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }
}
