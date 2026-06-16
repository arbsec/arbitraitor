//! Detector findings and detector metadata.

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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Evidence kind.
    pub kind: EvidenceKind,
    /// Human-readable evidence description.
    pub description: String,
    /// Optional bounded evidence content.
    pub content: Option<String>,
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SourceLocation {
    /// 1-indexed line number.
    pub line: u32,
    /// 1-indexed column number.
    pub column: u32,
    /// Optional 1-indexed ending line number.
    pub end_line: Option<u32>,
    /// Optional 1-indexed ending column number.
    pub end_column: Option<u32>,
    /// Optional zero-indexed byte offset.
    pub byte_offset: Option<usize>,
}

/// Metadata advertised by a detector implementation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    };
    use crate::artifact::{ArtifactKind, ShellDialect};
    use crate::ids::Sha256Digest;
    use crate::verdict::{Confidence, Severity};

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

    #[test]
    fn source_location_round_trips_max_edges() -> Result<(), Box<dyn std::error::Error>> {
        let value = SourceLocation {
            line: u32::MAX,
            column: u32::MAX,
            end_line: Some(u32::MAX),
            end_column: Some(u32::MAX),
            byte_offset: Some(usize::MAX),
        };
        assert_eq!(
            serde_json::from_str::<SourceLocation>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
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
