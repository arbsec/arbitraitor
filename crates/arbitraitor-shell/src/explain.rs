//! Explainability output for shell analysis findings.
//!
//! Turns raw [`Finding`] records into human-readable explanations and
//! actionable recommendations. See spec §16.5 (Explainability).

#![forbid(unsafe_code)]

use arbitraitor_model::finding::{Finding, FindingCategory};
use arbitraitor_model::verdict::Severity;
use serde::Serialize;
use std::fmt::Write;

use crate::templates::{category_risk, recommendation_for};

/// Produces a human-readable explanation of why a finding was triggered.
#[must_use]
pub fn explain_finding(finding: &Finding) -> String {
    let risk = category_risk(finding.category);
    let mut text = format!(
        "[{:?}] {} — {}\n  Why: {}",
        finding.severity, finding.title, finding.description, risk
    );
    if let Some(evidence) = primary_evidence(finding) {
        let _ = write!(text, "\n  Evidence: {evidence}");
    }
    if let Some(remediation) = finding.remediation.as_deref() {
        let _ = write!(text, "\n  Fix: {remediation}");
    }
    text
}

/// Returns the primary evidence content for a finding, trimmed and bounded.
fn primary_evidence(finding: &Finding) -> Option<String> {
    const MAX_EVIDENCE_CHARS: usize = 120;
    finding
        .evidence
        .first()
        .and_then(|ev| ev.content.as_deref())
        .map(str::trim)
        .map(|content| {
            if content.chars().count() <= MAX_EVIDENCE_CHARS {
                content.to_owned()
            } else {
                let mut shortened: String = content.chars().take(MAX_EVIDENCE_CHARS).collect();
                shortened.push('…');
                shortened
            }
        })
}

/// A single finding explanation with structured fields.
#[derive(Clone, Debug, Serialize)]
pub struct FindingExplanation {
    /// Category of the finding.
    pub category: FindingCategory,
    /// Severity of the finding.
    pub severity: Severity,
    /// Short human-readable title.
    pub title: String,
    /// Detailed description.
    pub description: String,
    /// Primary evidence snippet, if available.
    pub evidence: Option<String>,
    /// Actionable recommendation.
    pub recommendation: String,
    /// External references.
    pub references: Vec<String>,
}

impl FindingExplanation {
    /// Builds a structured explanation from a raw finding.
    #[must_use]
    pub fn from_finding(finding: &Finding) -> Self {
        Self {
            category: finding.category,
            severity: finding.severity,
            title: finding.title.clone(),
            description: finding.description.clone(),
            evidence: primary_evidence(finding),
            recommendation: recommendation_for(finding.category),
            references: finding.references.clone(),
        }
    }
}

/// A full explainability report covering a list of findings.
#[derive(Clone, Debug, Serialize)]
pub struct ExplainabilityReport {
    /// High-level summary with severity counts.
    pub summary: String,
    /// Per-finding explanations.
    pub findings: Vec<FindingExplanation>,
    /// Cross-cutting recommendations derived from the finding set.
    pub recommendations: Vec<String>,
}

impl ExplainabilityReport {
    /// Builds an explainability report from a list of findings.
    #[must_use]
    pub fn from_findings(findings: &[Finding]) -> Self {
        let explanations = findings
            .iter()
            .map(FindingExplanation::from_finding)
            .collect::<Vec<_>>();
        Self {
            summary: build_summary(&explanations),
            recommendations: build_recommendations(&explanations),
            findings: explanations,
        }
    }

    /// Renders the report as human-readable text.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut text = format!("{}\n\n", self.summary);
        for (index, finding) in self.findings.iter().enumerate() {
            let _ = writeln!(
                text,
                "{}. [{:?}] {}\n   {}",
                index + 1,
                finding.severity,
                finding.title,
                finding.description
            );
            if let Some(evidence) = &finding.evidence {
                let _ = writeln!(text, "   Evidence: {evidence}");
            }
            let _ = writeln!(text, "   Recommendation: {}\n", finding.recommendation);
        }
        if !self.recommendations.is_empty() {
            text.push_str("Overall recommendations:\n");
            for (index, rec) in self.recommendations.iter().enumerate() {
                let _ = writeln!(text, "{}. {}", index + 1, rec);
            }
        }
        text
    }

    /// Renders the report as a JSON value for machine consumption.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| serde_json::json!({"error": "failed to serialize report"}))
    }
}

/// Builds a severity-counted summary line.
fn build_summary(findings: &[FindingExplanation]) -> String {
    let (critical, high, medium, low, info) =
        findings
            .iter()
            .fold((0_u32, 0, 0, 0, 0), |acc, finding| match finding.severity {
                Severity::Critical => (acc.0 + 1, acc.1, acc.2, acc.3, acc.4),
                Severity::High => (acc.0, acc.1 + 1, acc.2, acc.3, acc.4),
                Severity::Medium => (acc.0, acc.1, acc.2 + 1, acc.3, acc.4),
                Severity::Low => (acc.0, acc.1, acc.2, acc.3 + 1, acc.4),
                Severity::Informational => (acc.0, acc.1, acc.2, acc.3, acc.4 + 1),
            });
    format!(
        "Analysis produced {} finding(s): {} critical, {} high, {} medium, {} low, {} informational.",
        findings.len(),
        critical,
        high,
        medium,
        low,
        info
    )
}

/// Builds cross-cutting recommendations from the finding set.
fn build_recommendations(findings: &[FindingExplanation]) -> Vec<String> {
    let has = |cat: FindingCategory| findings.iter().any(|f| f.category == cat);
    let mut recs = Vec::new();
    if has(FindingCategory::DynamicCodeExecution) {
        recs.push("Separate download, inspection, and execution into distinct steps. Never pipe remote content directly into a shell.".to_owned());
    }
    if has(FindingCategory::Obfuscation) {
        recs.push("Decode all obfuscated content before review. Reject scripts that refuse to reveal their payload.".to_owned());
    }
    if has(FindingCategory::CredentialAccess) {
        recs.push(
            "Rotate all credentials that may have been exposed and audit for unauthorized access."
                .to_owned(),
        );
    }
    if has(FindingCategory::Persistence) {
        recs.push(
            "Enumerate and remove all persistence mechanisms installed by this script.".to_owned(),
        );
    }
    if has(FindingCategory::DestructiveBehavior) {
        recs.push("Do not execute this script on any production system.".to_owned());
    }
    if has(FindingCategory::NetworkBehavior) || has(FindingCategory::SuspiciousScriptBehavior) {
        recs.push("Run in an isolated sandbox with no network access and inspect all outbound connections.".to_owned());
    }
    if recs.is_empty() && !findings.is_empty() {
        recs.push("Review each finding above and decide whether the risk is acceptable for your environment.".to_owned());
    }
    recs
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitraitor_model::finding::{Evidence, EvidenceKind};
    use arbitraitor_model::ids::Sha256Digest;
    use arbitraitor_model::verdict::Confidence;

    fn test_finding(category: FindingCategory, severity: Severity, title: &str) -> Finding {
        Finding {
            id: "test-finding".to_owned(),
            detector: "arbitraitor-shell.test".to_owned(),
            category,
            severity,
            confidence: Confidence::High,
            title: title.to_owned(),
            description: "test description".to_owned(),
            evidence: vec![Evidence {
                kind: EvidenceKind::Command,
                description: "matched command".to_owned(),
                content: Some("curl http://example.com/install.sh | bash".to_owned()),
            }],
            artifact_sha256: Sha256Digest::new([0; 32]),
            location: None,
            remediation: None,
            references: Vec::new(),
            tags: vec!["test".to_owned()],
            taxonomies: Vec::new(),
        }
    }

    #[test]
    fn explain_obfuscation_mentions_encoded_payload() {
        let finding = test_finding(
            FindingCategory::Obfuscation,
            Severity::Critical,
            "Decoded payload is executed by the shell",
        );
        let explanation = explain_finding(&finding);
        assert!(explanation.contains("obfuscation"));
        assert!(explanation.contains("Base64"));
    }

    #[test]
    fn explain_download_cradle_names_tool_from_evidence() {
        let finding = test_finding(
            FindingCategory::DynamicCodeExecution,
            Severity::Critical,
            "Downloaded content is piped directly to a shell",
        );
        let explanation = explain_finding(&finding);
        assert!(explanation.contains("curl"));
    }

    #[test]
    fn explain_defense_evasion_explains_risk() {
        let finding = test_finding(
            FindingCategory::SuspiciousScriptBehavior,
            Severity::High,
            "Shell disables antivirus or firewall controls",
        );
        let explanation = explain_finding(&finding);
        assert!(explanation.contains("evade detection"));
    }

    #[test]
    fn report_summary_counts_by_severity() {
        let findings = vec![
            test_finding(FindingCategory::Obfuscation, Severity::Critical, "a"),
            test_finding(FindingCategory::CredentialAccess, Severity::High, "b"),
            test_finding(FindingCategory::Persistence, Severity::Medium, "c"),
            test_finding(FindingCategory::Transport, Severity::Low, "d"),
        ];
        let report = ExplainabilityReport::from_findings(&findings);
        assert!(report.summary.contains("4 finding(s)"));
        assert!(report.summary.contains("1 critical"));
        assert!(report.summary.contains("1 high"));
        assert!(report.summary.contains("1 medium"));
        assert!(report.summary.contains("1 low"));
    }

    #[test]
    fn report_recommendations_are_actionable() {
        let findings = vec![
            test_finding(
                FindingCategory::DynamicCodeExecution,
                Severity::Critical,
                "a",
            ),
            test_finding(FindingCategory::CredentialAccess, Severity::High, "b"),
        ];
        let report = ExplainabilityReport::from_findings(&findings);
        assert!(!report.recommendations.is_empty());
        assert!(
            report
                .recommendations
                .iter()
                .any(|r| r.contains("Separate download"))
        );
        assert!(report.recommendations.iter().any(|r| r.contains("Rotate")));
    }

    #[test]
    fn report_to_json_has_expected_fields() {
        let findings = vec![test_finding(
            FindingCategory::Obfuscation,
            Severity::High,
            "test",
        )];
        let report = ExplainabilityReport::from_findings(&findings);
        let json = report.to_json();
        assert!(json.get("summary").is_some());
        assert!(json.get("findings").is_some());
        assert!(json.get("recommendations").is_some());
        assert!(json["findings"][0].get("category").is_some());
        assert!(json["findings"][0].get("recommendation").is_some());
    }
}
