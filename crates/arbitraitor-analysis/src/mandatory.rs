//! Mandatory detector coverage per artifact class (spec §9 invariant 1).
//!
//! Spec §9 invariant 1 requires that no artifact byte is emitted before
//! mandatory scanning and policy evaluation complete. Each artifact class has
//! a defined set of mandatory detectors that must run for coverage to be
//! considered complete. If a mandatory detector is missing or unavailable,
//! the verdict is [`Verdict::Block`] (invariant 6 — fail closed).
//!
//! The registry maps [`ArtifactKind`] variants to the detector IDs that must
//! execute for that class. Matching is by variant, not exact value — e.g.
//! `ShellScript(Posix)` and `ShellScript(Bash)` share the same mandatory
//! detector set.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use arbitraitor_model::artifact::ArtifactKind;
use arbitraitor_model::finding::{Evidence, EvidenceKind, Finding, FindingCategory};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity};

use crate::DetectorResult;

/// Detector ID for the URL discovery detector (spec §20.2).
///
/// Not yet registered in the default coordinator. HTML and JSON artifacts
/// fail closed until a detector with this ID is registered.
const URL_DISCOVERY_DETECTOR_ID: &str = "arbitraitor-analysis.url-discovery";

/// Detector ID for the mandatory-coverage validator itself.
const MANDATORY_COVERAGE_DETECTOR_ID: &str = "arbitraitor-analysis.mandatory-coverage";

/// Registry of mandatory detectors per artifact class (spec §9 invariant 1).
///
/// Zero-sized: the coverage matrix is static and encoded in
/// [`Self::mandatory_detectors`]. The registry is intentionally not
/// configurable at runtime — changing mandatory coverage requires a code
/// change and review, not a policy toggle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MandatoryDetectorRegistry;

impl MandatoryDetectorRegistry {
    /// Creates a registry with the default mandatory coverage matrix.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the mandatory detector IDs for the given artifact kind.
    ///
    /// Matching is by variant — `ShellScript(Posix)` and `ShellScript(Bash)`
    /// return the same set. Kinds without mandatory detectors return an
    /// empty slice.
    #[must_use]
    pub fn mandatory_detectors(&self, kind: &ArtifactKind) -> &'static [&'static str] {
        match kind {
            ArtifactKind::ShellScript(_) => &["arbitraitor-analysis.shell"],
            ArtifactKind::PythonScript | ArtifactKind::JavaScript => {
                &["arbitraitor-analysis.python-js"]
            }
            ArtifactKind::ElfExecutable
            | ArtifactKind::PeExecutable
            | ArtifactKind::MachOExecutable
            | ArtifactKind::WindowsShortcut => &["arbitraitor-analysis.artifact"],
            ArtifactKind::Zip
            | ArtifactKind::Tar(_)
            | ArtifactKind::Gzip
            | ArtifactKind::Bzip2
            | ArtifactKind::Xz
            | ArtifactKind::Zstd => &["arbitraitor-analysis.archive-hazards"],
            ArtifactKind::Html | ArtifactKind::Json => &[URL_DISCOVERY_DETECTOR_ID],
            _ => &[],
        }
    }

    /// Validates that all mandatory detectors ran for the artifact's class.
    ///
    /// Returns a [`Finding`] with [`Severity::Critical`] for each mandatory
    /// detector that did not execute. The caller appends these findings to
    /// the analysis result so that [`Verdict::Block`] is derived naturally
    /// from the existing verdict logic (invariant 6 — fail closed).
    #[must_use]
    pub fn validate_coverage(
        &self,
        kind: &ArtifactKind,
        detector_results: &[DetectorResult],
        artifact_sha256: &Sha256Digest,
    ) -> Vec<Finding> {
        let mandatory = self.mandatory_detectors(kind);
        if mandatory.is_empty() {
            return Vec::new();
        }

        let ran_ids: Vec<&str> = detector_results
            .iter()
            .map(|result| result.metadata.id.as_str())
            .collect();

        mandatory
            .iter()
            .filter(|id| !ran_ids.contains(id))
            .map(|id| missing_detector_finding(id, artifact_sha256))
            .collect()
    }
}

/// Constructs a critical finding for a missing mandatory detector.
fn missing_detector_finding(detector_id: &str, artifact_sha256: &Sha256Digest) -> Finding {
    Finding {
        id: "mandatory-detector.missing".to_owned(),
        detector: MANDATORY_COVERAGE_DETECTOR_ID.to_owned(),
        category: FindingCategory::PolicyViolation,
        severity: Severity::Critical,
        confidence: Confidence::Confirmed,
        title: format!("Mandatory detector '{detector_id}' did not run"),
        description: format!(
            "Spec §9 invariant 1 requires mandatory detector '{detector_id}' to complete \
             before any artifact byte is released. The detector was not registered or did \
             not run for this artifact class. Per invariant 6 (fail closed), the verdict \
             is Block."
        ),
        evidence: vec![Evidence {
            kind: EvidenceKind::Other,
            description: "mandatory detector coverage gap".to_owned(),
            content: Some(format!("missing_detector={detector_id}")),
        }],
        artifact_sha256: artifact_sha256.clone(),
        location: None,
        remediation: Some(format!(
            "Register the '{detector_id}' detector or add it to the analysis coordinator \
             before releasing this artifact."
        )),
        references: vec!["Arbitraitor spec section 9".to_owned()],
        tags: vec![
            "mandatory-detector".to_owned(),
            "incomplete-analysis".to_owned(),
            "invariant-1".to_owned(),
        ],
        taxonomies: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_script_variants_share_mandatory_detectors() {
        let registry = MandatoryDetectorRegistry::new();
        for dialect in [
            arbitraitor_model::artifact::ShellDialect::Posix,
            arbitraitor_model::artifact::ShellDialect::Bash,
            arbitraitor_model::artifact::ShellDialect::Zsh,
        ] {
            let kind = ArtifactKind::ShellScript(dialect);
            assert_eq!(
                registry.mandatory_detectors(&kind),
                &["arbitraitor-analysis.shell"]
            );
        }
    }

    #[test]
    fn tar_variants_share_mandatory_detectors() {
        let registry = MandatoryDetectorRegistry::new();
        for compression in [
            arbitraitor_model::artifact::TarCompression::None,
            arbitraitor_model::artifact::TarCompression::Gzip,
            arbitraitor_model::artifact::TarCompression::Zstd,
        ] {
            let kind = ArtifactKind::Tar(compression);
            assert_eq!(
                registry.mandatory_detectors(&kind),
                &["arbitraitor-analysis.archive-hazards"]
            );
        }
    }

    #[test]
    fn generic_text_has_no_mandatory_detectors() {
        let registry = MandatoryDetectorRegistry::new();
        assert_eq!(
            registry.mandatory_detectors(&ArtifactKind::GenericText),
            &[] as &[&str]
        );
    }

    #[test]
    fn html_and_json_require_url_discovery() {
        let registry = MandatoryDetectorRegistry::new();
        for kind in [ArtifactKind::Html, ArtifactKind::Json] {
            assert_eq!(
                registry.mandatory_detectors(&kind),
                &["arbitraitor-analysis.url-discovery"]
            );
        }
    }

    #[test]
    fn validate_coverage_returns_empty_when_all_ran() {
        let registry = MandatoryDetectorRegistry::new();
        let sha = Sha256Digest::new([0xaa; 32]);
        let kind = ArtifactKind::ShellScript(arbitraitor_model::artifact::ShellDialect::Bash);
        let results = vec![DetectorResult {
            metadata: arbitraitor_model::finding::DetectorMetadata {
                id: "arbitraitor-analysis.shell".to_owned(),
                version: "test".to_owned(),
                supported_artifact_kinds: vec![kind.clone()],
                capabilities: Vec::new(),
                is_local: true,
                may_upload: false,
                default_timeout_ms: 1_000,
                is_deterministic: true,
            },
            status: crate::DetectorStatus::Ok,
            finding_count: 0,
            duration_ms: 10,
            provenance: None,
        }];

        let findings = registry.validate_coverage(&kind, &results, &sha);
        assert!(findings.is_empty());
    }

    #[test]
    fn validate_coverage_emits_critical_finding_for_missing_detector() {
        let registry = MandatoryDetectorRegistry::new();
        let sha = Sha256Digest::new([0xbb; 32]);
        let kind = ArtifactKind::ShellScript(arbitraitor_model::artifact::ShellDialect::Posix);
        // No detector results — shell detector is missing.
        let findings = registry.validate_coverage(&kind, &[], &sha);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].category, FindingCategory::PolicyViolation);
        assert_eq!(findings[0].artifact_sha256, sha);
        assert!(
            findings[0]
                .tags
                .iter()
                .any(|tag| tag == "mandatory-detector")
        );
        assert!(findings[0].tags.iter().any(|tag| tag == "invariant-1"));
    }

    #[test]
    fn validate_coverage_skips_kinds_without_mandatory_detectors() {
        let registry = MandatoryDetectorRegistry::new();
        let sha = Sha256Digest::new([0xcc; 32]);
        let kind = ArtifactKind::GenericText;
        let findings = registry.validate_coverage(&kind, &[], &sha);
        assert!(findings.is_empty());
    }
}
