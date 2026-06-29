//! Taxonomy reference types for multi-category finding classification
//! per spec v0.5 §15.2.
//!
//! A finding may carry zero, one, or many taxonomy references (CWE, CAPEC,
//! OWASP, ATT&CK, or project-specific) so SARIF consumers can roll up
//! findings by multiple taxonomies simultaneously.

use serde::{Deserialize, Serialize};

/// Supported taxonomy names for finding classification.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaxonomyName {
    /// CWE (Common Weakness Enumeration).
    Cwe,
    /// CAPEC (Common Attack Pattern Enumeration and Classification).
    Capec,
    /// OWASP Top 10.
    Owasp,
    /// MITRE ATT&CK.
    Attack,
    /// Custom project-specific taxonomy.
    Custom(String),
}

/// A single taxonomy reference attached to a finding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyRef {
    /// Taxonomy name (e.g. `Cwe`, `Capec`, `Owasp`).
    pub name: TaxonomyName,
    /// Identifier within the taxonomy (e.g. `"CWE-78"`, `"CAPEC-88"`).
    pub id: String,
    /// Confidence in this taxonomy mapping.
    pub confidence: crate::verdict::Confidence,
    /// Optional URL to the taxonomy entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}
