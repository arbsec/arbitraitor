//! VEX (Vulnerability Exploitability eXchange) statement model.
//!
//! Implements the VEX consumption model from spec §19.5: a discovered VEX
//! statement is parsed into a [`VexStatement`] that records the issuer,
//! subject, status, and justification. The anti-suppression rules are
//! enforced by the policy engine, not this module.

use serde::{Deserialize, Serialize};

/// VEX statement status per `OpenVEX` v0.2+.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VexStatus {
    /// The product is not affected by the vulnerability.
    NotAffected,
    /// The product is affected by the vulnerability.
    Affected,
    /// The vulnerability has been fixed in this version.
    Fixed,
    /// The impact is unknown or unclear.
    Unknown,
}

/// Justification codes for `not_affected` VEX statements (OpenVEX/CSAF).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VexJustification {
    /// The vulnerable component is not present in the product.
    ComponentNotPresent,
    /// The component is present but not in the vulnerable configuration.
    VulnerableCodeNotPresent,
    /// The vulnerable code is present but cannot be executed.
    VulnerableCodeNotInExecutePath,
    /// The vulnerable code is present but the attack requires a prior condition.
    VulnerableCodeCannotBeControlledByAdversary,
    /// The product is built with a compiler that mitigates the vulnerability.
    InlineMitigationsAlreadyExist,
}

/// A parsed VEX statement discovered as a companion artifact.
///
/// Per spec §19.5, VEX statements are recorded as `verifies` edges. The
/// anti-suppression policy (5 binding conditions + invariant 21 exclusions)
/// is evaluated by the policy engine, not this struct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VexStatement {
    /// Identity of the VEX issuer (e.g., "pkg:github/owner/repo").
    pub issuer: String,
    /// Subject identifier — package coordinate or digest reference.
    pub subject: String,
    /// VEX status for this subject.
    pub status: VexStatus,
    /// Optional justification code (required for `not_affected`).
    pub justification: Option<VexJustification>,
    /// Optional human-readable statement from the issuer.
    pub statement: Option<String>,
    /// Unix timestamp (seconds) when the VEX statement was issued.
    pub timestamp: Option<i64>,
}

/// Format of a discovered companion artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompanionFormat {
    /// `CycloneDX` SBOM (`.cdx.json` / `.cdx.xml`).
    CycloneDx,
    /// `SPDX` SBOM (`.spdx.json` / `.spdx.rdf`).
    Spdx,
    /// `OpenVEX` statement (`.vex.json`).
    OpenVex,
    /// `CSAF` VEX document (`.csaf.json`).
    Csaf,
}

/// A discovered companion artifact inside an archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompanionArtifact {
    /// Entry path as found in the archive.
    pub name: String,
    /// Detected format.
    pub format: CompanionFormat,
}

/// File extensions that indicate companion artifacts (spec §19.5).
/// First-level entries only — deeper entries are ignored.
const COMPANION_EXTENSIONS: &[(&str, CompanionFormat)] = &[
    (".cdx.json", CompanionFormat::CycloneDx),
    (".cdx.xml", CompanionFormat::CycloneDx),
    (".spdx.json", CompanionFormat::Spdx),
    (".spdx.rdf", CompanionFormat::Spdx),
    (".bom.json", CompanionFormat::CycloneDx),
    (".vex.json", CompanionFormat::OpenVex),
    (".csaf.json", CompanionFormat::Csaf),
];

/// Returns a list of companion artifacts discovered in the given entry names.
/// Only first-level entries (no path separators) are considered.
/// Unrecognized extensions are ignored — discovery is purely additive.
#[must_use]
pub fn discover_companion_artifacts(entry_names: &[String]) -> Vec<CompanionArtifact> {
    entry_names
        .iter()
        .filter_map(|name| {
            let base = name.rsplit('/').next().unwrap_or(name);
            if base != name {
                return None;
            }
            let lower = name.to_ascii_lowercase();
            for (ext, format) in COMPANION_EXTENSIONS {
                if lower.ends_with(ext) {
                    return Some(CompanionArtifact {
                        name: name.clone(),
                        format: *format,
                    });
                }
            }
            None
        })
        .collect()
}

/// Parses an `OpenVEX` v0.2+ JSON document into a [`VexStatement`].
///
/// `OpenVEX` products use `@id` fields and a `statements` array. This parser
/// extracts the first statement whose subject matches `expected_subject`,
/// or the first statement if no match is found.
///
/// # Errors
///
/// Returns `Err` if the JSON is not a valid `OpenVEX` document or required
/// fields are missing.
pub fn parse_openvex(json: &[u8], expected_subject: &str) -> Result<VexStatement, String> {
    let value: serde_json::Value =
        serde_json::from_slice(json).map_err(|e| format!("invalid JSON: {e}"))?;

    let statements = value
        .get("statements")
        .and_then(|s| s.as_array())
        .ok_or("missing 'statements' array")?;

    let issuer = value
        .get("author")
        .and_then(|a| a.as_str())
        .or_else(|| value.get("id").and_then(|i| i.as_str()))
        .ok_or("missing 'author' or 'id'")?
        .to_owned();

    let stmt = statements
        .iter()
        .find(|s| {
            s.get("product")
                .and_then(|p| p.as_str())
                .is_some_and(|p| p == expected_subject)
        })
        .or_else(|| statements.first())
        .ok_or("empty 'statements' array")?;

    let status_str = stmt
        .get("status")
        .and_then(|s| s.as_str())
        .ok_or("missing 'status'")?;

    let status = match status_str {
        "not_affected" => VexStatus::NotAffected,
        "affected" => VexStatus::Affected,
        "fixed" => VexStatus::Fixed,
        _ => VexStatus::Unknown,
    };

    let justification = stmt
        .get("justification")
        .and_then(|j| j.as_str())
        .and_then(|j| match j {
            "component_not_present" => Some(VexJustification::ComponentNotPresent),
            "vulnerable_code_not_present" => Some(VexJustification::VulnerableCodeNotPresent),
            "vulnerable_code_not_in_execute_path" => {
                Some(VexJustification::VulnerableCodeNotInExecutePath)
            }
            "vulnerable_code_cannot_be_controlled_by_adversary" => {
                Some(VexJustification::VulnerableCodeCannotBeControlledByAdversary)
            }
            "inline_mitigations_already_exist" => {
                Some(VexJustification::InlineMitigationsAlreadyExist)
            }
            _ => None,
        });

    let statement = stmt
        .get("statement")
        .and_then(|s| s.as_str())
        .map(str::to_owned);

    let timestamp = value
        .get("timestamp")
        .and_then(|t| t.as_str())
        .and_then(parse_iso8601);

    Ok(VexStatement {
        issuer,
        subject: expected_subject.to_owned(),
        status,
        justification,
        statement,
        timestamp,
    })
}

fn parse_iso8601(s: &str) -> Option<i64> {
    let s = s.get(..19).unwrap_or(s);
    let s = s.replacen(['T', 't'], " ", 1);
    if s.len() < 19 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(5..7)?.parse().ok()?;
    let day: u32 = s.get(8..10)?.parse().ok()?;
    let hour: u32 = s.get(11..13)?.parse().ok()?;
    let min: u32 = s.get(14..16)?.parse().ok()?;
    let sec: u32 = s.get(17..19)?.parse().ok()?;
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + i64::from(hour * 3600 + min * 60 + sec))
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = u32::try_from(y - era * 400).unwrap_or(0);
    let m = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = i64::from(yoe * 365 + yoe / 4 - yoe / 100 + doy);
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_finds_cdx_json() {
        let names = vec![
            "pkg.cdx.json".to_owned(),
            "README.md".to_owned(),
            "subdir/bom.json".to_owned(),
        ];
        let found = discover_companion_artifacts(&names);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "pkg.cdx.json");
        assert_eq!(found[0].format, CompanionFormat::CycloneDx);
    }

    #[test]
    fn discover_skips_nested_entries() {
        let names = vec!["nested/dir/pkg.vex.json".to_owned()];
        let found = discover_companion_artifacts(&names);
        assert!(found.is_empty());
    }

    #[test]
    fn discover_finds_multiple_formats() {
        let names = vec![
            "bom.spdx.json".to_owned(),
            "advisory.csaf.json".to_owned(),
            "vuln.vex.json".to_owned(),
            "sbom.cdx.xml".to_owned(),
        ];
        let found = discover_companion_artifacts(&names);
        assert_eq!(found.len(), 4);
    }

    #[test]
    fn parse_openvex_not_affected() -> Result<(), String> {
        let json = br#"{
            "@id": "pkg:github/owner/repo/vex@v1",
            "author": "pkg:github/owner/repo",
            "timestamp": "2026-01-15T10:30:00Z",
            "statements": [
                {
                    "product": "pkg:github/owner/repo@v1.2.3",
                    "status": "not_affected",
                    "justification": "component_not_present",
                    "statement": "The vulnerable component is not included in this release."
                }
            ]
        }"#;
        let stmt = parse_openvex(json, "pkg:github/owner/repo@v1.2.3")?;
        assert_eq!(stmt.issuer, "pkg:github/owner/repo");
        assert_eq!(stmt.status, VexStatus::NotAffected);
        assert_eq!(
            stmt.justification,
            Some(VexJustification::ComponentNotPresent)
        );
        assert!(stmt.timestamp.is_some());
        Ok(())
    }

    #[test]
    fn parse_openvex_fixed_status() -> Result<(), String> {
        let json = br#"{
            "author": "vendor@example.com",
            "statements": [
                {"product": "pkg:foo@1.0", "status": "fixed"}
            ]
        }"#;
        let stmt = parse_openvex(json, "pkg:foo@1.0")?;
        assert_eq!(stmt.status, VexStatus::Fixed);
        assert!(stmt.justification.is_none());
        Ok(())
    }

    #[test]
    fn parse_openvex_unknown_status() -> Result<(), String> {
        let json = br#"{
            "author": "vendor@example.com",
            "statements": [
                {"product": "pkg:bar@2.0", "status": "some_new_status"}
            ]
        }"#;
        let stmt = parse_openvex(json, "pkg:bar@2.0")?;
        assert_eq!(stmt.status, VexStatus::Unknown);
        Ok(())
    }

    #[test]
    fn parse_openvex_missing_statements_returns_error() {
        let json = br#"{"author": "x"}"#;
        assert!(parse_openvex(json, "pkg:x@1").is_err());
    }

    #[test]
    fn parse_openvex_picks_matching_subject() -> Result<(), String> {
        let json = br#"{
            "author": "issuer",
            "statements": [
                {"product": "pkg:other@1.0", "status": "affected"},
                {"product": "pkg:target@1.0", "status": "not_affected"}
            ]
        }"#;
        let stmt = parse_openvex(json, "pkg:target@1.0")?;
        assert_eq!(stmt.status, VexStatus::NotAffected);
        Ok(())
    }
}
