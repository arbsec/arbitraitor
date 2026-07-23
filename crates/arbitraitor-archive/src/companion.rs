//! SBOM/VEX companion-artifact discovery and parsing (spec §19.5).
//!
//! Companion artifacts (SBOM, VEX) discovered near a fetched artifact are
//! parsed under bounded resource limits. VEX statements are recorded as
//! `verifies` edges. Anti-suppression rules ensure VEX cannot suppress
//! Critical (Block-level) findings (invariant 6).

use std::path::{Path, PathBuf};

use arbitraitor_model::verdict::Severity;
use arbitraitor_model::vex::{
    CompanionFormat, VexLimits, VexStatement, VexStatus, csaf_to_statements,
    parse_csaf_vex_with_limits, parse_openvex_all_with_limits,
};
use serde::Deserialize;

use crate::{ArchiveError, ArchiveLimits};

const DEFAULT_MAX_COMPONENTS: usize = 10_000;
const COMPANION_EXTENSIONS: &[(&str, CompanionFormat)] = &[
    (".cdx.json", CompanionFormat::CycloneDx),
    (".cdx.xml", CompanionFormat::CycloneDx),
    (".spdx.json", CompanionFormat::Spdx),
    (".spdx.rdf", CompanionFormat::Spdx),
    (".bom.json", CompanionFormat::CycloneDx),
    (".vex.json", CompanionFormat::OpenVex),
    (".csaf.json", CompanionFormat::Csaf),
];

/// A discovered companion artifact on the filesystem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompanionArtifact {
    /// Filesystem path of the companion artifact.
    pub path: PathBuf,
    /// Detected companion format.
    pub format: CompanionFormat,
}

/// A parsed SBOM component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    /// Component name (e.g., package name).
    pub name: String,
    /// Component version, when available.
    pub version: Option<String>,
    /// Package URL (purl) identifier, when available.
    pub purl: Option<String>,
}

/// A parsed companion artifact (SBOM or VEX).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedCompanion {
    /// Detected companion format.
    pub format: CompanionFormat,
    /// SBOM components (empty for VEX-only documents).
    pub components: Vec<Component>,
    /// VEX statements (empty for SBOM-only documents).
    pub vex_statements: Vec<VexStatement>,
}

/// Scans a directory for companion artifacts by file extension.
///
/// Only top-level files in `dir` are considered — subdirectories are not
/// recursed. Unrecognized extensions are ignored (discovery is additive).
#[must_use]
pub fn discover_companion_artifacts(dir: &Path) -> Vec<CompanionArtifact> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|ft| ft.is_file()))
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.to_string_lossy();
            let lower = name.to_ascii_lowercase();
            for (ext, format) in COMPANION_EXTENSIONS {
                if lower.ends_with(ext) {
                    return Some(CompanionArtifact {
                        path,
                        format: *format,
                    });
                }
            }
            None
        })
        .collect()
}

/// Parses a companion artifact under bounded resource limits.
///
/// The file size is checked against `limits.max_single_file_bytes` before
/// reading. VEX documents are parsed with [`VexLimits::default`] and SBOM
/// component counts are bounded by [`DEFAULT_MAX_COMPONENTS`].
///
/// # Errors
///
/// Returns [`ArchiveError::Io`] for filesystem failures,
/// [`ArchiveError::LimitExceeded`] when the file or component count exceeds
/// configured limits, and [`ArchiveError::MalformedArchive`] when the
/// document is not valid JSON for its detected format.
pub fn parse_companion(
    artifact: &CompanionArtifact,
    limits: &ArchiveLimits,
) -> Result<ParsedCompanion, ArchiveError> {
    let metadata = std::fs::metadata(&artifact.path)?;
    if metadata.len() > limits.max_single_file_bytes {
        return Err(ArchiveError::LimitExceeded {
            limit: "max_single_file_bytes",
        });
    }
    let bytes = std::fs::read(&artifact.path)?;

    match artifact.format {
        CompanionFormat::CycloneDx => parse_cyclonedx(&bytes),
        CompanionFormat::Spdx => parse_spdx(&bytes),
        CompanionFormat::OpenVex => {
            let vex_statements = parse_openvex_all_with_limits(&bytes, &VexLimits::default())
                .map_err(|e| {
                    ArchiveError::MalformedArchive(format!("OpenVEX parse failed: {e}"))
                })?;
            Ok(ParsedCompanion {
                format: CompanionFormat::OpenVex,
                components: Vec::new(),
                vex_statements,
            })
        }
        CompanionFormat::Csaf => {
            let document = parse_csaf_vex_with_limits(&bytes, &VexLimits::default())
                .map_err(|e| ArchiveError::MalformedArchive(format!("CSAF parse failed: {e}")))?;
            let vex_statements = csaf_to_statements(&document).map_err(|e| {
                ArchiveError::MalformedArchive(format!("CSAF conversion failed: {e}"))
            })?;
            Ok(ParsedCompanion {
                format: CompanionFormat::Csaf,
                components: Vec::new(),
                vex_statements,
            })
        }
    }
}

/// Anti-suppression rule (spec §19.5, invariant 6).
///
/// A VEX `not_affected` statement can never suppress a Critical severity
/// finding (which produces a Block verdict). Fail closed: the finding
/// always stands.
#[must_use]
pub fn vex_can_suppress_finding(severity: Severity, vex_status: VexStatus) -> bool {
    if severity == Severity::Critical && vex_status == VexStatus::NotAffected {
        return false;
    }
    true
}

fn parse_cyclonedx(bytes: &[u8]) -> Result<ParsedCompanion, ArchiveError> {
    let document: CycloneDxDocument = serde_json::from_slice(bytes)
        .map_err(|e| ArchiveError::MalformedArchive(format!("CycloneDX parse failed: {e}")))?;
    if document.components.len() > DEFAULT_MAX_COMPONENTS {
        return Err(ArchiveError::LimitExceeded {
            limit: "max_components",
        });
    }
    let components = document
        .components
        .into_iter()
        .map(|c| Component {
            name: c.name,
            version: c.version,
            purl: c.purl,
        })
        .collect();
    Ok(ParsedCompanion {
        format: CompanionFormat::CycloneDx,
        components,
        vex_statements: Vec::new(),
    })
}

fn parse_spdx(bytes: &[u8]) -> Result<ParsedCompanion, ArchiveError> {
    let document: SpdxDocument = serde_json::from_slice(bytes)
        .map_err(|e| ArchiveError::MalformedArchive(format!("SPDX parse failed: {e}")))?;
    if document.packages.len() > DEFAULT_MAX_COMPONENTS {
        return Err(ArchiveError::LimitExceeded {
            limit: "max_components",
        });
    }
    let components = document
        .packages
        .into_iter()
        .map(|p| Component {
            name: p.name,
            version: p.version,
            purl: p
                .external_refs
                .into_iter()
                .find_map(|r| (r.reference_type == "purl").then_some(r.reference_locator)),
        })
        .collect();
    Ok(ParsedCompanion {
        format: CompanionFormat::Spdx,
        components,
        vex_statements: Vec::new(),
    })
}

#[derive(Deserialize)]
struct CycloneDxDocument {
    #[serde(default)]
    components: Vec<CycloneDxComponent>,
}

#[derive(Deserialize)]
struct CycloneDxComponent {
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    purl: Option<String>,
}

#[derive(Deserialize)]
struct SpdxDocument {
    #[serde(default)]
    packages: Vec<SpdxPackage>,
}

#[derive(Deserialize)]
struct SpdxPackage {
    name: String,
    #[serde(default, rename = "versionInfo")]
    version: Option<String>,
    #[serde(default, rename = "externalRefs")]
    external_refs: Vec<SpdxExternalRef>,
}

#[derive(Deserialize)]
struct SpdxExternalRef {
    #[serde(rename = "referenceType")]
    reference_type: String,
    #[serde(rename = "referenceLocator")]
    reference_locator: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn write_temp_file(
        name: &str,
        content: &[u8],
    ) -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(name);
        let mut file = fs::File::create(&path)?;
        file.write_all(content)?;
        Ok((dir, path))
    }

    fn default_limits() -> ArchiveLimits {
        ArchiveLimits::default()
    }

    #[test]
    fn discover_finds_cdx_json() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("sbom.cdx.json"), b"{}")?;
        fs::write(dir.path().join("readme.txt"), b"hello")?;

        let found = discover_companion_artifacts(dir.path());

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].format, CompanionFormat::CycloneDx);
        assert!(found[0].path.to_string_lossy().ends_with("sbom.cdx.json"));
        Ok(())
    }

    #[test]
    fn discover_finds_vex_and_csaf() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("stmt.vex.json"), b"{}")?;
        fs::write(dir.path().join("adv.csaf.json"), b"{}")?;

        let found = discover_companion_artifacts(dir.path());

        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|a| a.format == CompanionFormat::OpenVex));
        assert!(found.iter().any(|a| a.format == CompanionFormat::Csaf));
        Ok(())
    }

    #[test]
    fn discover_ignores_subdirectories() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        fs::create_dir(dir.path().join("sub"))?;
        fs::write(dir.path().join("sub/sbom.cdx.json"), b"{}")?;

        let found = discover_companion_artifacts(dir.path());

        assert!(found.is_empty());
        Ok(())
    }

    #[test]
    fn parse_cyclonedx_extracts_components() -> Result<(), Box<dyn std::error::Error>> {
        let json = br#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {"type": "library", "name": "serde", "version": "1.0", "purl": "pkg:cargo/serde@1.0"},
                {"type": "library", "name": "tokio", "version": "1.0"}
            ]
        }"#;
        let (_dir, path) = write_temp_file("sbom.cdx.json", json)?;
        let artifact = CompanionArtifact {
            path,
            format: CompanionFormat::CycloneDx,
        };

        let parsed = parse_companion(&artifact, &default_limits())?;

        assert_eq!(parsed.format, CompanionFormat::CycloneDx);
        assert_eq!(parsed.components.len(), 2);
        assert_eq!(parsed.components[0].name, "serde");
        assert_eq!(
            parsed.components[0].purl.as_deref(),
            Some("pkg:cargo/serde@1.0")
        );
        assert_eq!(parsed.components[1].name, "tokio");
        assert!(parsed.components[1].purl.is_none());
        assert!(parsed.vex_statements.is_empty());
        Ok(())
    }

    #[test]
    fn parse_openvex_extracts_statements() -> Result<(), Box<dyn std::error::Error>> {
        let json = br#"{
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://openvex.dev/docs/example/vex",
            "author": "pkg:github/owner/repo",
            "timestamp": "2023-01-08T18:02:03Z",
            "version": 1,
            "statements": [{
                "vulnerability": {"name": "CVE-2023-12345"},
                "products": [{"@id": "pkg:foo@1.0"}],
                "status": "not_affected"
            }]
        }"#;
        let (_dir, path) = write_temp_file("stmt.vex.json", json)?;
        let artifact = CompanionArtifact {
            path,
            format: CompanionFormat::OpenVex,
        };

        let parsed = parse_companion(&artifact, &default_limits())?;

        assert_eq!(parsed.format, CompanionFormat::OpenVex);
        assert!(parsed.components.is_empty());
        assert_eq!(parsed.vex_statements.len(), 1);
        assert_eq!(
            parsed.vex_statements[0].vulnerability.as_str(),
            "CVE-2023-12345"
        );
        assert_eq!(parsed.vex_statements[0].status, VexStatus::NotAffected);
        Ok(())
    }

    #[test]
    fn parse_rejects_file_exceeding_size_limit() -> Result<(), Box<dyn std::error::Error>> {
        let json = br#"{"components": []}"#;
        let (_dir, path) = write_temp_file("sbom.cdx.json", json)?;
        let artifact = CompanionArtifact {
            path,
            format: CompanionFormat::CycloneDx,
        };
        let limits = ArchiveLimits {
            max_single_file_bytes: 1,
            ..ArchiveLimits::default()
        };

        let result = parse_companion(&artifact, &limits);

        assert!(matches!(
            result,
            Err(ArchiveError::LimitExceeded {
                limit: "max_single_file_bytes"
            })
        ));
        Ok(())
    }

    #[test]
    fn vex_cannot_suppress_critical_not_affected() {
        assert!(!vex_can_suppress_finding(
            Severity::Critical,
            VexStatus::NotAffected
        ));
    }

    #[test]
    fn vex_can_suppress_non_critical_not_affected() {
        assert!(vex_can_suppress_finding(
            Severity::High,
            VexStatus::NotAffected
        ));
    }

    #[test]
    fn vex_can_suppress_critical_fixed() {
        assert!(vex_can_suppress_finding(
            Severity::Critical,
            VexStatus::Fixed
        ));
    }
}
