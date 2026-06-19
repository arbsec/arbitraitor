//! Local antivirus engine adapters
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use arbitraitor_analysis::{AnalysisContext, Detector};
use arbitraitor_model::finding::{
    DetectorMetadata, Evidence, EvidenceKind, Finding, FindingCategory,
};
use arbitraitor_model::verdict::{Confidence, Severity};
use thiserror::Error;

const DETECTOR_ID: &str = "arbitraitor-av.adapter";

/// Adapter interface for local antivirus engines.
///
/// Implementations must scan only the bytes supplied to [`Self::scan`]. Remote
/// upload is intentionally not part of this trait; detector metadata advertises
/// `may_upload = false` so policy can keep AV inspection local by default.
pub trait AntivirusAdapter: Send + Sync {
    /// Stable human-readable adapter or engine name.
    fn name(&self) -> &str;

    /// Returns whether the underlying AV engine is installed and usable.
    fn is_available(&self) -> bool;

    /// Returns the AV engine version when available.
    fn engine_version(&self) -> Option<String>;

    /// Returns the signature database version when available.
    fn signature_db_version(&self) -> Option<String>;

    /// Returns the last signature update time when available.
    fn last_update_time(&self) -> Option<String>;

    /// Scans immutable artifact bytes and returns the local AV verdict.
    ///
    /// # Errors
    ///
    /// Returns [`AvError`] when the adapter cannot complete the scan safely.
    fn scan(&self, data: &[u8]) -> Result<ScanResult, AvError>;
}

/// Result returned by an antivirus adapter scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanResult {
    /// No malware or suspicious content was detected.
    Clean,
    /// A malware signature matched the artifact.
    Detected {
        /// Malware family or signature family reported by the engine.
        malware_family: String,
    },
    /// The engine reported suspicious content without a confirmed family.
    Suspicious,
    /// The engine completed with an error result instead of a detection verdict.
    Error {
        /// Safe diagnostic reason supplied by the adapter.
        reason: String,
    },
}

/// Policy controlling antivirus detector execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvPolicy {
    /// Whether AV scanning is enabled.
    pub enabled: bool,
    /// Whether missing or failed AV scanning must fail closed.
    pub required: bool,
    /// Maximum permitted signature age in hours, when policy enforces freshness.
    pub max_signature_age_hours: Option<u64>,
    /// Detector timeout budget in milliseconds.
    pub timeout_ms: u64,
}

impl Default for AvPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            required: false,
            max_signature_age_hours: None,
            timeout_ms: 5_000,
        }
    }
}

/// Antivirus adapter error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AvError {
    /// The configured engine is not available.
    #[error("antivirus engine is unavailable: {reason}")]
    Unavailable {
        /// Safe diagnostic reason.
        reason: String,
    },
    /// The adapter could not complete scanning.
    #[error("antivirus scan failed: {reason}")]
    ScanFailed {
        /// Safe diagnostic reason.
        reason: String,
    },
}

/// Analysis detector that wraps a local antivirus adapter.
pub struct AvDetector {
    adapter: Box<dyn AntivirusAdapter>,
    policy: AvPolicy,
}

impl AvDetector {
    /// Creates a detector from an antivirus adapter and AV policy.
    #[must_use]
    pub fn new(adapter: Box<dyn AntivirusAdapter>, policy: AvPolicy) -> Self {
        Self { adapter, policy }
    }

    fn unavailable_finding(&self, ctx: &AnalysisContext<'_>) -> Finding {
        Finding {
            id: "av.adapter-unavailable".to_owned(),
            detector: DETECTOR_ID.to_owned(),
            category: FindingCategory::PolicyViolation,
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            title: "Required antivirus adapter is unavailable".to_owned(),
            description: format!(
                "Antivirus policy requires adapter '{}' but the adapter is not available.",
                self.adapter.name()
            ),
            evidence: self.adapter_evidence("availability", Some("unavailable".to_owned())),
            artifact_sha256: ctx.artifact_sha256.clone(),
            location: None,
            remediation: Some(
                "Install or repair the configured antivirus engine before release.".to_owned(),
            ),
            references: vec!["Arbitraitor spec sections 18.2-18.4".to_owned()],
            tags: vec!["antivirus".to_owned(), "fail-closed".to_owned()],
        }
    }

    fn finding_for_result(&self, ctx: &AnalysisContext<'_>, result: ScanResult) -> Option<Finding> {
        match result {
            ScanResult::Clean => None,
            ScanResult::Detected { malware_family } => Some(Finding {
                id: "av.malware-detected".to_owned(),
                detector: DETECTOR_ID.to_owned(),
                category: FindingCategory::MalwareSignature,
                severity: Severity::Critical,
                confidence: Confidence::Confirmed,
                title: "Antivirus detected malware".to_owned(),
                description: format!(
                    "Antivirus adapter '{}' detected malware family '{malware_family}'.",
                    self.adapter.name()
                ),
                evidence: self.adapter_evidence("malware_family", Some(malware_family)),
                artifact_sha256: ctx.artifact_sha256.clone(),
                location: None,
                remediation: Some("Block release and investigate the artifact source.".to_owned()),
                references: vec!["Arbitraitor spec sections 18.2-18.3".to_owned()],
                tags: vec!["antivirus".to_owned(), "malware-signature".to_owned()],
            }),
            ScanResult::Suspicious => Some(Finding {
                id: "av.suspicious".to_owned(),
                detector: DETECTOR_ID.to_owned(),
                category: FindingCategory::MalwareSignature,
                severity: Severity::High,
                confidence: Confidence::High,
                title: "Antivirus reported suspicious content".to_owned(),
                description: format!(
                    "Antivirus adapter '{}' reported suspicious content without a confirmed malware family.",
                    self.adapter.name()
                ),
                evidence: self.adapter_evidence("scan_result", Some("suspicious".to_owned())),
                artifact_sha256: ctx.artifact_sha256.clone(),
                location: None,
                remediation: Some(
                    "Review the artifact manually or require a clean AV result before release."
                        .to_owned(),
                ),
                references: vec!["Arbitraitor spec sections 18.2-18.3".to_owned()],
                tags: vec!["antivirus".to_owned(), "suspicious".to_owned()],
            }),
            ScanResult::Error { reason } => Some(self.scan_error_finding(ctx, &reason)),
        }
    }

    fn scan_error_finding(&self, ctx: &AnalysisContext<'_>, reason: &str) -> Finding {
        Finding {
            id: "av.scan-error".to_owned(),
            detector: DETECTOR_ID.to_owned(),
            category: FindingCategory::PolicyViolation,
            severity: if self.policy.required {
                Severity::Critical
            } else {
                Severity::High
            },
            confidence: Confidence::Confirmed,
            title: "Antivirus scan did not complete cleanly".to_owned(),
            description: format!(
                "Antivirus adapter '{}' returned an error result, so AV coverage is incomplete.",
                self.adapter.name()
            ),
            evidence: self.adapter_evidence("scan_error", Some(reason.to_owned())),
            artifact_sha256: ctx.artifact_sha256.clone(),
            location: None,
            remediation: Some("Fail closed when AV scanning is required by policy.".to_owned()),
            references: vec!["Arbitraitor spec sections 18.2-18.4".to_owned()],
            tags: vec!["antivirus".to_owned(), "incomplete-analysis".to_owned()],
        }
    }

    fn adapter_evidence(&self, result_key: &str, result_value: Option<String>) -> Vec<Evidence> {
        let mut parts = vec![format!("adapter={}", self.adapter.name())];
        if let Some(version) = self.adapter.engine_version() {
            parts.push(format!("engine_version={version}"));
        }
        if let Some(version) = self.adapter.signature_db_version() {
            parts.push(format!("signature_db_version={version}"));
        }
        if let Some(update_time) = self.adapter.last_update_time() {
            parts.push(format!("last_update_time={update_time}"));
        }
        if let Some(value) = result_value {
            parts.push(format!("{result_key}={value}"));
        }

        vec![Evidence {
            kind: EvidenceKind::Other,
            description: "antivirus adapter result".to_owned(),
            content: Some(parts.join("; ")),
        }]
    }
}

impl Detector for AvDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: DETECTOR_ID.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            supported_artifact_kinds: Vec::new(),
            capabilities: vec!["local-antivirus-scan".to_owned()],
            is_local: true,
            may_upload: false,
            default_timeout_ms: self.policy.timeout_ms,
            is_deterministic: false,
        }
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Vec<Finding> {
        if !self.policy.enabled {
            return Vec::new();
        }
        if !self.adapter.is_available() {
            return if self.policy.required {
                vec![self.unavailable_finding(ctx)]
            } else {
                Vec::new()
            };
        }

        match self.adapter.scan(ctx.artifact_bytes) {
            Ok(result) => self.finding_for_result(ctx, result).into_iter().collect(),
            Err(error) => vec![self.scan_error_finding(ctx, &error.to_string())],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AntivirusAdapter, AvDetector, AvError, AvPolicy, ScanResult};
    use arbitraitor_analysis::AnalysisCoordinator;
    use arbitraitor_model::finding::FindingCategory;
    use arbitraitor_model::verdict::{Severity, Verdict};

    struct MockAdapter {
        available: bool,
        result: ScanResult,
    }

    impl MockAdapter {
        fn new(available: bool, result: ScanResult) -> Self {
            Self { available, result }
        }
    }

    impl AntivirusAdapter for MockAdapter {
        fn name(&self) -> &str {
            "mock-av"
        }

        fn is_available(&self) -> bool {
            self.available
        }

        fn engine_version(&self) -> Option<String> {
            Some("1.0.0".to_owned())
        }

        fn signature_db_version(&self) -> Option<String> {
            Some("sig-42".to_owned())
        }

        fn last_update_time(&self) -> Option<String> {
            Some("2026-06-19T00:00:00Z".to_owned())
        }

        fn scan(&self, _data: &[u8]) -> Result<ScanResult, AvError> {
            Ok(self.result.clone())
        }
    }

    fn enabled_policy(required: bool) -> AvPolicy {
        AvPolicy {
            enabled: true,
            required,
            max_signature_age_hours: None,
            timeout_ms: 1_000,
        }
    }

    fn analyze(adapter: MockAdapter, policy: AvPolicy) -> arbitraitor_analysis::AnalysisResult {
        let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(AvDetector::new(
            Box::new(adapter),
            policy,
        ))]);
        coordinator.analyze(b"test artifact")
    }

    #[test]
    fn clean_scan_returns_no_findings() {
        let result = analyze(
            MockAdapter::new(true, ScanResult::Clean),
            enabled_policy(true),
        );

        assert!(result.findings.is_empty());
        assert_eq!(result.verdict, Verdict::Pass);
    }

    #[test]
    fn detected_scan_returns_critical_finding() {
        let result = analyze(
            MockAdapter::new(
                true,
                ScanResult::Detected {
                    malware_family: "EICAR-Test-File".to_owned(),
                },
            ),
            enabled_policy(true),
        );

        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].category,
            FindingCategory::MalwareSignature
        );
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert_eq!(result.verdict, Verdict::Block);
    }

    #[test]
    fn required_unavailable_adapter_fails_closed() {
        let result = analyze(
            MockAdapter::new(false, ScanResult::Clean),
            enabled_policy(true),
        );

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert_eq!(result.verdict, Verdict::Block);
        assert!(
            result.findings[0]
                .tags
                .iter()
                .any(|tag| tag == "fail-closed")
        );
    }

    #[test]
    fn non_required_unavailable_adapter_skips() {
        let result = analyze(
            MockAdapter::new(false, ScanResult::Clean),
            enabled_policy(false),
        );

        assert!(result.findings.is_empty());
        assert_eq!(result.verdict, Verdict::Pass);
    }
}
