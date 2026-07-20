//! `ShellCheck` interoperability.
//!
//! Exports Arbitraitor findings in [`ShellCheck` JSON format][format] for
//! editor and CI integrations, and invokes the optional `shellcheck` binary
//! to import its advisory diagnostics.
//!
//! [format]: https://github.com/koalaman/shellcheck/wiki/Integration#json-format

#![forbid(unsafe_code)]

use arbitraitor_model::finding::Finding;
use arbitraitor_model::verdict::Severity;
use serde::Serialize;

#[path = "shellcheck_subprocess.rs"]
mod subprocess;

pub use subprocess::{ShellCheckError, ShellCheckFinding, run_shellcheck};

/// `ShellCheck` report — the top-level JSON array wrapper.
#[derive(Clone, Debug, Serialize)]
pub struct ShellCheckReport {
    /// One comment per finding.
    pub comments: Vec<ShellCheckComment>,
}

/// A single `ShellCheck`-style comment.
#[derive(Clone, Debug, Serialize)]
pub struct ShellCheckComment {
    /// Source file name.
    pub file: String,
    /// Start line (1-indexed).
    pub line: usize,
    /// End line (1-indexed).
    pub end_line: usize,
    /// Start column (1-indexed).
    pub column: usize,
    /// End column (1-indexed).
    pub end_column: usize,
    /// ShellCheck-style code number (1000–9999 range for Arbitraitor).
    pub code: u32,
    /// Human-readable message.
    pub message: String,
    /// Optional auto-fix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<ShellCheckFix>,
    /// Severity level: `"error"`, `"warning"`, `"info"`, or `"style"`.
    pub level: String,
}

/// An auto-fix that ShellCheck-compatible tools can apply.
#[derive(Clone, Debug, Serialize)]
pub struct ShellCheckFix {
    /// Replacement list (Arbitraitor emits at most one per comment).
    pub replacements: Vec<ShellCheckReplacement>,
}

/// A single text replacement within a fix.
#[derive(Clone, Debug, Serialize)]
pub struct ShellCheckReplacement {
    /// Precedence for overlapping fixes.
    pub precedence: u32,
    /// Start line (1-indexed).
    pub line: usize,
    /// End line (1-indexed).
    pub end_line: usize,
    /// Start column (1-indexed).
    pub column: usize,
    /// End column (1-indexed).
    pub end_column: usize,
    /// Text to insert at the specified range.
    pub insertion: String,
}

/// Base for Arbitraitor-specific `ShellCheck` codes.
///
/// `ShellCheck` uses codes `1000`–`9999` for user-defined rules. Arbitraitor
/// categories are mapped into the `1000`-range with a per-category offset.
const CODE_BASE: u32 = 1000;

/// Converts Arbitraitor findings to `ShellCheck` JSON format.
///
/// `source_name` is typically the file path or URL of the analyzed script.
#[must_use]
pub fn to_shellcheck_json(findings: &[Finding], source_name: &str) -> ShellCheckReport {
    let comments = findings
        .iter()
        .map(|finding| to_comment(finding, source_name))
        .collect();
    ShellCheckReport { comments }
}

/// Converts a single finding to a `ShellCheck` comment.
fn to_comment(finding: &Finding, source_name: &str) -> ShellCheckComment {
    let (line, end_line, column, end_column) = location_fields(finding);
    ShellCheckComment {
        file: source_name.to_owned(),
        line,
        end_line,
        column,
        end_column,
        code: code_for_category(finding),
        message: format!("{} — {}", finding.title, finding.description),
        fix: None,
        level: level_for_severity(finding.severity),
    }
}

/// Extracts 1-indexed line/column fields from a finding location.
fn location_fields(finding: &Finding) -> (usize, usize, usize, usize) {
    match &finding.location {
        Some(loc) => {
            let line = u32::from(loc.line) as usize;
            let end_line = loc.end_line.map_or(line, |e| u32::from(e) as usize);
            let column = u32::from(loc.column) as usize;
            let end_column = loc.end_column.map_or(column, |e| u32::from(e) as usize);
            (line, end_line, column, end_column)
        }
        None => (1, 1, 1, 1),
    }
}

/// Maps a severity to the `ShellCheck` level string.
fn level_for_severity(severity: Severity) -> String {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "info",
        Severity::Informational => "style",
    }
    .to_owned()
}

/// Assigns a stable `ShellCheck`-style code (`1000`–`9999`) from the finding category.
fn code_for_category(finding: &Finding) -> u32 {
    use arbitraitor_model::finding::FindingCategory as C;
    let offset: u32 = match finding.category {
        C::Provenance => 100,
        C::Reputation => 110,
        C::Transport => 200,
        C::ContentMismatch => 120,
        C::MalwareSignature => 900,
        C::SuspiciousScriptBehavior => 300,
        C::Obfuscation => 400,
        C::CredentialAccess => 500,
        C::Persistence => 600,
        C::PrivilegeEscalation => 610,
        C::DestructiveBehavior => 700,
        C::NetworkBehavior => 710,
        C::DynamicCodeExecution => 800,
        C::ArchiveHazard => 810,
        C::PackageRisk => 820,
        C::PolicyViolation => 910,
        C::ParserError => 920,
        C::ResourceLimitEvent => 930,
        C::SupplyChain => 940,
    };
    CODE_BASE + offset
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitraitor_model::finding::{Evidence, EvidenceKind, FindingCategory, SourceLocation};
    use arbitraitor_model::ids::Sha256Digest;
    use arbitraitor_model::verdict::Confidence;
    use core::num::NonZeroU32;

    fn nonzero(v: u32) -> Result<NonZeroU32, Box<dyn std::error::Error>> {
        NonZeroU32::new(v).ok_or_else(|| "test value must be non-zero".into())
    }

    fn test_finding(
        category: FindingCategory,
        severity: Severity,
        location: Option<SourceLocation>,
    ) -> Finding {
        Finding {
            id: "test".to_owned(),
            detector: "arbitraitor-shell.test".to_owned(),
            category,
            severity,
            confidence: Confidence::High,
            title: "Test title".to_owned(),
            description: "Test description".to_owned(),
            evidence: vec![Evidence {
                kind: EvidenceKind::Command,
                description: "cmd".to_owned(),
                content: Some("echo test".to_owned()),
            }],
            artifact_sha256: Sha256Digest::new([0; 32]),
            location,
            remediation: None,
            references: Vec::new(),
            tags: vec!["test".to_owned()],
            taxonomies: Vec::new(),
        }
    }

    #[test]
    fn shellcheck_json_is_valid_format() -> Result<(), Box<dyn std::error::Error>> {
        let findings = vec![test_finding(
            FindingCategory::DynamicCodeExecution,
            Severity::Critical,
            SourceLocation::new(nonzero(3)?, nonzero(1)?, None, None, None).ok(),
        )];
        let report = to_shellcheck_json(&findings, "install.sh");
        let json = serde_json::to_value(&report)?;
        let comments = json
            .get("comments")
            .and_then(|c| c.as_array())
            .ok_or("missing comments array")?;
        let comment = &comments[0];
        assert_eq!(comment["file"], "install.sh");
        assert_eq!(comment["line"], 3);
        assert_eq!(comment["level"], "error");
        let message = comment["message"]
            .as_str()
            .ok_or("message is not a string")?;
        assert!(message.contains("Test title"));
        let code = comment["code"].as_u64().ok_or("code is not a number")?;
        assert!(code >= 1000);
        Ok(())
    }

    #[test]
    fn shellcheck_level_mapping() {
        let cases = [
            (Severity::Critical, "error"),
            (Severity::High, "error"),
            (Severity::Medium, "warning"),
            (Severity::Low, "info"),
            (Severity::Informational, "style"),
        ];
        for (severity, expected) in cases {
            let finding = test_finding(FindingCategory::Transport, severity, None);
            let report = to_shellcheck_json(&[finding], "test.sh");
            assert_eq!(
                report.comments[0].level, expected,
                "severity {severity:?} should map to {expected}"
            );
        }
    }

    #[test]
    fn shellcheck_code_range() {
        use FindingCategory as C;
        for category in [
            C::Provenance,
            C::Reputation,
            C::Transport,
            C::ContentMismatch,
            C::MalwareSignature,
            C::SuspiciousScriptBehavior,
            C::Obfuscation,
            C::CredentialAccess,
            C::Persistence,
            C::PrivilegeEscalation,
            C::DestructiveBehavior,
            C::NetworkBehavior,
            C::DynamicCodeExecution,
            C::ArchiveHazard,
            C::PackageRisk,
            C::PolicyViolation,
            C::ParserError,
            C::ResourceLimitEvent,
        ] {
            let finding = test_finding(category, Severity::Medium, None);
            let code = code_for_category(&finding);
            assert!(
                (1000..=9999).contains(&code),
                "category {category:?} code {code} outside valid range"
            );
        }
    }

    #[test]
    fn shellcheck_uses_default_location_when_missing() {
        let finding = test_finding(FindingCategory::Obfuscation, Severity::High, None);
        let comment = to_comment(&finding, "script.sh");
        assert_eq!((comment.line, comment.column), (1, 1));
    }
}
