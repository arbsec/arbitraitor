//! VEX (Vulnerability Exploitability eXchange) statement model.
//!
//! Implements the VEX consumption model from spec §19.5: a discovered VEX
//! statement is parsed into a [`VexStatement`] that records the issuer,
//! subject, status, and justification. The anti-suppression rules are
//! enforced by the policy engine, not this module.

// allow: SIZE_OK — VEX wire-format schema definitions are intentionally colocated for API discoverability.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `OpenVEX` 0.2.0 JSON-LD namespace.
pub const OPENVEX_CONTEXT_V0_2_0: &str = "https://openvex.dev/ns/v0.2.0";

macro_rules! string_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates a new typed string wrapper.
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Returns the wrapped text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self::new(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::new(value)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

string_newtype!(
    /// JSON-LD context URI for a VEX document.
    VexContext
);
string_newtype!(
    /// IRI identifying a VEX document or statement.
    VexDocumentId
);
string_newtype!(
    /// Machine-readable VEX issuer identity.
    VexIssuer
);
string_newtype!(
    /// Software product identifier used by VEX matching.
    VexProductId
);
string_newtype!(
    /// Vulnerability identifier used by VEX matching.
    VexVulnerabilityId
);
string_newtype!(
    /// RFC 3339 timestamp text from a VEX document.
    VexTimestamp
);
string_newtype!(
    /// Hash algorithm label used in VEX component hashes.
    VexHashAlgorithm
);
string_newtype!(
    /// Hash digest text for algorithms not modeled as SHA-256 newtypes.
    VexHashDigest
);
string_newtype!(
    /// CVSS 4.0 vector string carried by CSAF 2.1 VEX documents.
    CvssV4Vector
);

/// VEX format and version detected for a parsed document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VexFormatVersion {
    /// `OpenVEX` 0.0.x documents are rejected by the parser.
    OpenVex0_0X,
    /// `OpenVEX` 0.1.x documents are deprecated and rejected by the parser.
    OpenVex0_1X,
    /// `OpenVEX` 0.2.0 documents are supported.
    OpenVex0_2_0,
    /// CSAF 2.0 VEX profile documents are supported.
    Csaf2_0,
    /// CSAF 2.1 VEX profile documents are preferred.
    Csaf2_1,
}

/// VEX statement status per `OpenVEX` and CSAF VEX profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VexStatus {
    /// The product is not affected by the vulnerability.
    NotAffected,
    /// The product is affected by the vulnerability.
    Affected,
    /// The vulnerability has been fixed in this version.
    Fixed,
    /// The impact is under investigation.
    UnderInvestigation,
    /// The impact is unknown or unclear.
    Unknown,
}

/// Justification codes for `not_affected` VEX statements (OpenVEX/CSAF).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
#[serde(deny_unknown_fields)]
pub struct VexStatement {
    /// Format version that produced this normalized statement.
    pub format_version: VexFormatVersion,
    /// Identity of the VEX issuer (e.g., `pkg:github/owner/repo`).
    pub issuer: VexIssuer,
    /// Subject identifier — package coordinate or digest reference.
    pub subject: VexProductId,
    /// Vulnerability identifier asserted by this statement.
    pub vulnerability: VexVulnerabilityId,
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

/// `OpenVEX` 0.2.0 document metadata and statements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenVexDocument {
    /// JSON-LD namespace; must be [`OPENVEX_CONTEXT_V0_2_0`].
    #[serde(rename = "@context")]
    pub context: VexContext,
    /// IRI identifying this document.
    #[serde(rename = "@id")]
    pub id: VexDocumentId,
    /// Machine-readable author identity.
    pub author: VexIssuer,
    /// Optional author role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Document issuance timestamp.
    pub timestamp: VexTimestamp,
    /// Optional last-updated timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<VexTimestamp>,
    /// Monotonic document version.
    pub version: u64,
    /// Optional tooling description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tooling: Option<String>,
    /// VEX statements in this document.
    pub statements: Vec<OpenVexStatement>,
}

/// `OpenVEX` 0.2.0 statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenVexStatement {
    /// Optional IRI identifying this statement.
    #[serde(default, rename = "@id", skip_serializing_if = "Option::is_none")]
    pub id: Option<VexDocumentId>,
    /// Optional statement version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    /// Optional statement-specific timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<VexTimestamp>,
    /// Optional statement-specific last-updated timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<VexTimestamp>,
    /// Vulnerability asserted by this statement.
    pub vulnerability: OpenVexVulnerability,
    /// Products asserted by this statement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub products: Vec<OpenVexProduct>,
    /// VEX status.
    pub status: VexStatus,
    /// Optional supplier identity text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supplier: Option<String>,
    /// Optional machine-readable status note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_notes: Option<String>,
    /// Optional not-affected justification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub justification: Option<VexJustification>,
    /// Optional free-form impact statement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact_statement: Option<String>,
    /// Optional remediation or mitigation action statement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_statement: Option<String>,
    /// Optional timestamp for the action statement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_statement_timestamp: Option<VexTimestamp>,
}

/// `OpenVEX` product object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenVexProduct {
    /// Optional product IRI, commonly a package URL.
    #[serde(default, rename = "@id", skip_serializing_if = "Option::is_none")]
    pub id: Option<VexProductId>,
    /// Software identifiers keyed by identifier type (`purl`, `cpe23`, ...).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub identifiers: BTreeMap<String, VexProductId>,
    /// Component hashes keyed by IANA hash algorithm label.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub hashes: BTreeMap<VexHashAlgorithm, VexHashDigest>,
    /// Nested subcomponents relevant to this statement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subcomponents: Vec<OpenVexComponent>,
}

/// `OpenVEX` component object used by product subcomponents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenVexComponent {
    /// Optional component IRI, commonly a package URL.
    #[serde(default, rename = "@id", skip_serializing_if = "Option::is_none")]
    pub id: Option<VexProductId>,
    /// Software identifiers keyed by identifier type (`purl`, `cpe23`, ...).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub identifiers: BTreeMap<String, VexProductId>,
    /// Component hashes keyed by IANA hash algorithm label.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub hashes: BTreeMap<VexHashAlgorithm, VexHashDigest>,
}

/// `OpenVEX` vulnerability object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenVexVulnerability {
    /// Optional IRI for the vulnerability record.
    #[serde(default, rename = "@id", skip_serializing_if = "Option::is_none")]
    pub id: Option<VexDocumentId>,
    /// Primary vulnerability identifier.
    pub name: VexVulnerabilityId,
    /// Optional vulnerability description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional vulnerability aliases.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<VexVulnerabilityId>,
}

/// CSAF 2.0/2.1 VEX profile document subset consumed by Arbitraitor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsafVexDocument {
    /// CSAF document metadata.
    pub document: CsafDocumentMetadata,
    /// CSAF product tree, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_tree: Option<CsafProductTree>,
    /// Vulnerability entries with VEX status, scores, and involvements.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<CsafVulnerability>,
}

/// CSAF document metadata needed to classify VEX format versions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsafDocumentMetadata {
    /// CSAF category, expected to identify the CSAF VEX profile.
    pub category: String,
    /// CSAF specification version (`2.0` or `2.1`).
    pub csaf_version: String,
    /// Publisher metadata.
    pub publisher: CsafPublisher,
    /// Tracking metadata.
    pub tracking: CsafTracking,
    /// Optional document title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// CSAF publisher metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsafPublisher {
    /// Publisher category.
    pub category: String,
    /// Publisher name.
    pub name: String,
    /// Publisher namespace.
    pub namespace: VexDocumentId,
}

/// CSAF tracking metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsafTracking {
    /// CSAF document identifier.
    pub id: VexDocumentId,
    /// Initial release timestamp.
    pub initial_release_date: VexTimestamp,
    /// Current release timestamp.
    pub current_release_date: VexTimestamp,
    /// Revision history.
    pub revision_history: Vec<CsafRevision>,
    /// CSAF tracking status.
    pub status: String,
    /// CSAF document version.
    pub version: String,
}

/// CSAF revision-history entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsafRevision {
    /// Revision date.
    pub date: VexTimestamp,
    /// Revision number.
    pub number: String,
    /// Revision summary.
    pub summary: String,
}

/// CSAF product tree subset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsafProductTree {
    /// Full product names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub full_product_names: Vec<CsafFullProductName>,
}

/// CSAF full product name entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsafFullProductName {
    /// Human-readable product name.
    pub name: String,
    /// CSAF product identifier.
    pub product_id: VexProductId,
}

/// CSAF vulnerability entry with VEX profile fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsafVulnerability {
    /// Optional CVE identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve: Option<VexVulnerabilityId>,
    /// Product status groups by VEX status.
    pub product_status: CsafProductStatus,
    /// CVSS scores including CSAF 2.1 CVSS v4 vectors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scores: Vec<CsafScore>,
    /// Company involvement statements.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub involvements: Vec<CsafInvolvement>,
}

/// CSAF VEX product status buckets.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsafProductStatus {
    /// Products known to be affected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_affected: Vec<VexProductId>,
    /// Products known not to be affected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_not_affected: Vec<VexProductId>,
    /// Products fixed by this advisory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixed: Vec<VexProductId>,
    /// Products still under investigation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub under_investigation: Vec<VexProductId>,
}

/// CSAF score entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsafScore {
    /// Products covered by this score.
    pub products: Vec<VexProductId>,
    /// CVSS 4.0 vector string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss_v4: Option<CvssV4Vector>,
}

/// CSAF company involvement statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsafInvolvement {
    /// Party making the involvement statement.
    pub party: String,
    /// Involvement status.
    pub status: CsafInvolvementStatus,
    /// Optional statement summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

/// CSAF involvement status values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CsafInvolvementStatus {
    /// Involvement has completed.
    Completed,
    /// Involvement is in progress.
    InProgress,
    /// Involvement determined the product is not affected.
    NotAffected,
    /// Involvement is still under investigation.
    UnderInvestigation,
}

/// VEX parser failures.
#[derive(Debug, Error)]
pub enum VexParseError {
    /// JSON could not be parsed into the requested VEX schema.
    #[error("invalid JSON for {stage}: {source}")]
    Json {
        /// Parser stage.
        stage: &'static str,
        /// Underlying serde error.
        source: serde_json::Error,
    },
    /// `OpenVEX` context was unsupported.
    #[error("unsupported OpenVEX context {context}; supported context is {OPENVEX_CONTEXT_V0_2_0}")]
    UnsupportedOpenVexContext {
        /// Context observed in the document.
        context: VexContext,
    },
    /// No statement matched the expected product subject.
    #[error("no statement found matching subject {subject}")]
    NoMatchingSubject {
        /// Expected subject.
        subject: VexProductId,
    },
    /// A matching statement did not contain a product identifier.
    #[error("OpenVEX statement does not contain product identifiers")]
    MissingOpenVexProduct,
    /// Timestamp text could not be parsed.
    #[error("invalid timestamp format: {timestamp}")]
    InvalidTimestamp {
        /// Invalid timestamp text.
        timestamp: VexTimestamp,
    },
    /// CSAF version is unsupported.
    #[error("unsupported CSAF version {version}; supported versions are 2.0 and 2.1")]
    UnsupportedCsafVersion {
        /// CSAF version observed in the document.
        version: String,
    },
    /// CSAF VEX profile metadata was missing.
    #[error("CSAF document category {category} is not a VEX profile")]
    UnsupportedCsafCategory {
        /// CSAF category observed in the document.
        category: String,
    },
}

/// Parses an `OpenVEX` 0.2.0 JSON document into a normalized [`VexStatement`].
///
/// `OpenVEX` 0.2.0 products use a `products` array of product structs and
/// vulnerabilities use an expanded struct. This parser extracts the first
/// statement whose product identifier matches `expected_subject`.
///
/// # Errors
///
/// Returns [`VexParseError`] if JSON is invalid, the document uses an older
/// unsupported `OpenVEX` context, required fields are missing, or no statement
/// matches `expected_subject`.
pub fn parse_openvex(json: &[u8], expected_subject: &str) -> Result<VexStatement, VexParseError> {
    let document: OpenVexDocument =
        serde_json::from_slice(json).map_err(|source| VexParseError::Json {
            stage: "parse OpenVEX",
            source,
        })?;
    document.ensure_supported_context()?;

    let expected = VexProductId::from(expected_subject);
    let statement = document
        .statements
        .iter()
        .find(|statement| statement.matches_product(&expected))
        .ok_or_else(|| VexParseError::NoMatchingSubject {
            subject: expected.clone(),
        })?;
    let timestamp = statement
        .timestamp
        .as_ref()
        .unwrap_or(&document.timestamp)
        .clone();
    let epoch =
        parse_iso8601(timestamp.as_str()).ok_or(VexParseError::InvalidTimestamp { timestamp })?;

    Ok(VexStatement {
        format_version: VexFormatVersion::OpenVex0_2_0,
        issuer: document.author,
        subject: expected,
        vulnerability: statement.vulnerability.name.clone(),
        status: statement.status,
        justification: statement.justification,
        statement: statement
            .status_notes
            .clone()
            .or_else(|| statement.impact_statement.clone())
            .or_else(|| statement.action_statement.clone()),
        timestamp: Some(epoch),
    })
}

/// Parses a CSAF 2.0 or 2.1 VEX profile JSON document.
///
/// # Errors
///
/// Returns [`VexParseError`] if JSON is invalid, the CSAF version is not 2.0 or
/// 2.1, or the document category is not a CSAF VEX profile.
pub fn parse_csaf_vex(json: &[u8]) -> Result<CsafVexDocument, VexParseError> {
    let document: CsafVexDocument =
        serde_json::from_slice(json).map_err(|source| VexParseError::Json {
            stage: "parse CSAF VEX",
            source,
        })?;
    document.format_version()?;
    Ok(document)
}

impl OpenVexDocument {
    fn ensure_supported_context(&self) -> Result<(), VexParseError> {
        if self.context.as_str() == OPENVEX_CONTEXT_V0_2_0 {
            Ok(())
        } else {
            Err(VexParseError::UnsupportedOpenVexContext {
                context: self.context.clone(),
            })
        }
    }
}

impl OpenVexStatement {
    fn matches_product(&self, expected: &VexProductId) -> bool {
        self.products
            .iter()
            .any(|product| product.matches(expected))
    }
}

impl OpenVexProduct {
    fn matches(&self, expected: &VexProductId) -> bool {
        self.id.as_ref() == Some(expected) || self.identifiers.values().any(|id| id == expected)
    }
}

impl CsafVexDocument {
    /// Returns the CSAF format version after validating VEX profile support.
    ///
    /// # Errors
    ///
    /// Returns [`VexParseError`] if the document is not CSAF 2.0/2.1 VEX.
    pub fn format_version(&self) -> Result<VexFormatVersion, VexParseError> {
        if !self.document.category.to_ascii_lowercase().contains("vex") {
            return Err(VexParseError::UnsupportedCsafCategory {
                category: self.document.category.clone(),
            });
        }
        match self.document.csaf_version.as_str() {
            "2.0" => Ok(VexFormatVersion::Csaf2_0),
            "2.1" => Ok(VexFormatVersion::Csaf2_1),
            version => Err(VexParseError::UnsupportedCsafVersion {
                version: version.to_owned(),
            }),
        }
    }
}

fn parse_iso8601(value: &str) -> Option<i64> {
    let s = value.get(..19).unwrap_or(value);
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
    Some(days * 86_400 + i64::from(hour * 3_600 + min * 60 + sec))
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
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    const OPENVEX_0_2: &[u8] = br#"{
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
        "author": "pkg:github/owner/repo",
        "role": "Document Creator",
        "timestamp": "2023-01-08T18:02:03.647787998-06:00",
        "version": 1,
        "statements": [
            {
                "vulnerability": {"name": "CVE-2023-12345"},
                "products": [
                    {"@id": "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7"},
                    {"@id": "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64"}
                ],
                "status": "fixed"
            }
        ]
    }"#;

    const CSAF_2_1: &[u8] = br#"{
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.1",
            "publisher": {
                "category": "vendor",
                "name": "Example Vendor",
                "namespace": "https://example.com/security"
            },
            "tracking": {
                "id": "example-2026-0001",
                "initial_release_date": "2026-01-01T00:00:00Z",
                "current_release_date": "2026-01-02T00:00:00Z",
                "revision_history": [
                    {"date": "2026-01-01T00:00:00Z", "number": "1", "summary": "Initial release"}
                ],
                "status": "final",
                "version": "1"
            },
            "title": "Example CSAF 2.1 VEX"
        },
        "product_tree": {
            "full_product_names": [
                {"name": "Example Product 1.0", "product_id": "CSAFPID-0001"}
            ]
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2026-0001",
                "product_status": {
                    "known_not_affected": ["CSAFPID-0001"],
                    "under_investigation": ["CSAFPID-0002"]
                },
                "scores": [
                    {
                        "products": ["CSAFPID-0001"],
                        "cvss_v4": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
                    }
                ],
                "involvements": [
                    {
                        "party": "vendor",
                        "status": "completed",
                        "summary": "Vendor completed impact analysis."
                    },
                    {
                        "party": "coordinator",
                        "status": "under_investigation"
                    }
                ]
            }
        ]
    }"#;

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
    fn parse_openvex_0_2_products_and_vulnerability_structs() -> Result<(), VexParseError> {
        let stmt = parse_openvex(OPENVEX_0_2, "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64")?;
        assert_eq!(stmt.format_version, VexFormatVersion::OpenVex0_2_0);
        assert_eq!(stmt.issuer, VexIssuer::from("pkg:github/owner/repo"));
        assert_eq!(stmt.status, VexStatus::Fixed);
        assert_eq!(
            stmt.vulnerability,
            VexVulnerabilityId::from("CVE-2023-12345")
        );
        assert!(stmt.timestamp.is_some());
        Ok(())
    }

    #[test]
    fn reject_openvex_0_0_x_with_clear_error() {
        let json = br#"{
            "@context": "https://openvex.dev/ns/v0.0.1",
            "@id": "https://openvex.dev/docs/example/old",
            "author": "pkg:github/owner/repo",
            "timestamp": "2023-01-08T18:02:03Z",
            "version": 1,
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2023-12345"},
                    "products": [{"@id": "pkg:foo@1.0"}],
                    "status": "fixed"
                }
            ]
        }"#;

        let error = parse_openvex(json, "pkg:foo@1.0").err();
        assert!(matches!(
            error,
            Some(VexParseError::UnsupportedOpenVexContext { .. })
        ));
        assert!(error.is_some_and(|err| err.to_string().contains("v0.2.0")));
    }

    #[test]
    fn parse_csaf_2_1_cvss_v4_and_involvements() -> Result<(), VexParseError> {
        let document = parse_csaf_vex(CSAF_2_1)?;
        assert_eq!(document.format_version()?, VexFormatVersion::Csaf2_1);
        let vulnerability = &document.vulnerabilities[0];
        assert_eq!(
            vulnerability.scores[0].cvss_v4,
            Some(CvssV4Vector::from(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
            ))
        );
        assert_eq!(vulnerability.involvements.len(), 2);
        assert_eq!(
            vulnerability.involvements[0].status,
            CsafInvolvementStatus::Completed
        );
        assert_eq!(
            vulnerability.involvements[1].status,
            CsafInvolvementStatus::UnderInvestigation
        );
        Ok(())
    }

    #[test]
    fn csaf_2_1_round_trips_without_semantic_drift() -> Result<(), Box<dyn std::error::Error>> {
        let document = parse_csaf_vex(CSAF_2_1)?;
        let original: serde_json::Value = serde_json::from_slice(CSAF_2_1)?;
        let encoded = serde_json::to_value(&document)?;
        assert_eq!(encoded, original);
        Ok(())
    }

    #[test]
    fn parse_openvex_rejects_legacy_product_string_shape() {
        let json = br#"{
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://openvex.dev/docs/example/vex",
            "author": "pkg:github/owner/repo",
            "timestamp": "2023-01-08T18:02:03Z",
            "version": 1,
            "statements": [
                {"product": "pkg:foo@1.0", "status": "fixed", "vulnerability": {"name": "CVE-2023-12345"}}
            ]
        }"#;
        assert!(parse_openvex(json, "pkg:foo@1.0").is_err());
    }

    #[test]
    fn parse_csaf_rejects_1_x() -> Result<(), Box<dyn std::error::Error>> {
        let mut value: serde_json::Value = serde_json::from_slice(CSAF_2_1)?;
        value["document"]["csaf_version"] = json!("1.2");
        let bytes = serde_json::to_vec(&value)?;
        assert!(matches!(
            parse_csaf_vex(&bytes),
            Err(VexParseError::UnsupportedCsafVersion { .. })
        ));
        Ok(())
    }

    proptest! {
        #[test]
        fn openvex_denies_unknown_fields(extra_field in "[a-z]{1,16}") {
            prop_assume!(![
                "@context",
                "@id",
                "author",
                "role",
                "timestamp",
                "last_updated",
                "version",
                "tooling",
                "statements",
            ].contains(&extra_field.as_str()));
            let mut value: serde_json::Value = serde_json::from_slice(OPENVEX_0_2)?;
            value[&extra_field] = json!(true);
            let bytes = serde_json::to_vec(&value)?;

            prop_assert!(parse_openvex(&bytes, "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64").is_err());
        }
    }
}
