//! Detector coordination for the analysis pipeline
//!
//! See `docs/spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod dep_vuln;
pub mod pyjs;
pub mod tirith;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use arbitraitor_archive::{
    ArchiveError, ArchiveLimits, ArtifactNode, ArtifactOrigin, PayloadIssue, PayloadNode,
    detect_archive_hazards, detect_tar_parser_differentials, open_archive_with_limits,
    walk_payloads,
};
use arbitraitor_artifact::{ArtifactType, ClassificationResult, ShellKind, classify};
use arbitraitor_core::metrics::{OperationMetrics, log_operation};
use arbitraitor_intel::{
    Disposition, Indicator, IndicatorType, IntelStore, MatchResult, evaluate_matches,
    match_indicator,
};
use arbitraitor_model::artifact::{ArtifactKind, ShellDialect, TarCompression};
use arbitraitor_model::finding::{
    DetectorMetadata, DetectorProvenance, Evidence, EvidenceKind, Finding, FindingCategory,
};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity, Verdict};
use arbitraitor_shell::{ParserConfig, ShellParser, detect, detect_system_threats, normalize};
use sha2::{Digest, Sha256};

const ARTIFACT_DETECTOR_ID: &str = "arbitraitor-analysis.artifact";
const ARCHIVE_DETECTOR_ID: &str = "arbitraitor-analysis.archive-hazards";
const REPUTATION_DETECTOR_ID: &str = "arbitraitor-analysis.reputation";
const SHELL_DETECTOR_ID: &str = "arbitraitor-analysis.shell";
const RECURSIVE_PAYLOAD_DETECTOR_ID: &str = "arbitraitor-analysis.recursive-payload";
const PAYLOAD_ORIGIN_ROOT_TAG: &str = "payload-origin:root";
const PAYLOAD_ORIGIN_ENTRY_TAG: &str = "payload-origin:archive-entry";

/// Global resource budget for analysis operations (spec §41.16).
///
/// Bounds recursive graph expansion across bytes, nodes, and depth to
/// prevent resource exhaustion through hostile archives or deep
/// containment trees. When any limit is exceeded, the affected operation
/// returns `Verdict::Incomplete` rather than silently truncating results.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisBudget {
    /// Maximum total bytes processed across all artifacts in the payload graph.
    pub max_total_bytes: u64,
    /// Maximum number of nodes (artifacts) in the payload graph.
    pub max_nodes: u32,
    /// Maximum recursion depth in the payload graph.
    pub max_depth: u32,
    /// When true, fixes detector ordering and disables nondeterministic
    /// concurrency so the same input produces the same receipt bytes
    /// (spec §41.16).
    pub deterministic_mode: bool,
}

impl Default for AnalysisBudget {
    fn default() -> Self {
        Self {
            max_total_bytes: 1_073_741_824,
            max_nodes: 10_000,
            max_depth: 5,
            deterministic_mode: true,
        }
    }
}

impl AnalysisBudget {
    /// Creates a budget with conservative defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum total bytes budget.
    #[must_use]
    pub const fn with_max_bytes(mut self, bytes: u64) -> Self {
        self.max_total_bytes = bytes;
        self
    }

    /// Sets the maximum node count.
    #[must_use]
    pub const fn with_max_nodes(mut self, nodes: u32) -> Self {
        self.max_nodes = nodes;
        self
    }

    /// Sets the maximum recursion depth.
    #[must_use]
    pub const fn with_max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }

    /// Enables or disables deterministic mode.
    #[must_use]
    pub const fn with_deterministic(mut self, deterministic: bool) -> Self {
        self.deterministic_mode = deterministic;
        self
    }

    /// Returns `true` if the budget allows processing `bytes` more bytes
    /// given the `current_total` already processed.
    #[must_use]
    pub const fn allows_bytes(&self, current_total: u64, bytes: u64) -> bool {
        current_total.saturating_add(bytes) <= self.max_total_bytes
    }

    /// Returns `true` if the budget allows `current_count` + 1 nodes.
    #[must_use]
    pub const fn allows_node(&self, current_count: u32) -> bool {
        current_count.saturating_add(1) <= self.max_nodes
    }

    /// Returns `true` if the budget allows recursing at `current_depth`.
    #[must_use]
    pub const fn allows_depth(&self, current_depth: u32) -> bool {
        current_depth < self.max_depth
    }
}

/// Error returned by a detector when analysis cannot be completed.
///
/// Distinguishes "no findings found" — the detector completed successfully and
/// found nothing to report ([`Verdict::Pass`]) — from "could not analyze" — the
/// detector encountered an error and produced no results ([`Verdict::Incomplete`]).
/// This preserves security invariant §6 (fail closed): a detector error is never
/// "clean."
#[derive(Clone, Debug, thiserror::Error)]
pub enum DetectorError {
    /// The detector's binary, ruleset, or other required resource was unavailable.
    #[error("detector unavailable: {0}")]
    Unavailable(String),
    /// The detector subprocess timed out before producing results.
    #[error("detector timed out after {0:?}")]
    Timeout(Duration),
    /// Subprocess output exceeded the configured byte limit.
    #[error("detector output exceeded {limit} bytes")]
    OutputExceeded {
        /// Maximum bytes the detector was allowed to emit.
        limit: usize,
    },
    /// The detector subprocess failed to spawn or exited abnormally.
    #[error("subprocess failure: {0}")]
    SubprocessFailure(String),
    /// The detector could not parse subprocess output as valid data.
    #[error("output parse error: {0}")]
    ParseError(String),
    /// An I/O or resource error prevented detector execution.
    #[error("resource error: {0}")]
    Resource(String),
    /// An uncategorized analysis error not covered by another variant.
    #[error("analysis error: {0}")]
    Other(String),
}

/// Detector trait implemented by analysis stages.
pub trait Detector: Send + Sync {
    /// Detector identity, version, supported artifact kinds, and execution properties.
    fn metadata(&self) -> DetectorMetadata;

    /// Analyze the artifact within the given context.
    ///
    /// Returns `Ok(findings)` when the detector completed analysis (even if it
    /// found zero findings) and `Err(DetectorError)` when analysis could not be
    /// completed — e.g. subprocess crash, parse failure, or resource
    /// unavailability. The coordinator maps `Err` to [`DetectorStatus::Error`]
    /// and the final verdict to [`Verdict::Incomplete`], preserving the fail-closed
    /// security invariant.
    ///
    /// # Errors
    ///
    /// Returns [`Err(DetectorError)`] when the detector cannot complete analysis.
    /// The caller (coordinator) treats any `Err` as [`DetectorStatus::Error`],
    /// which forces [`Verdict::Incomplete`] for the operation.
    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError>;

    /// Optional binary provenance (subprocess detectors). Returns `None` for
    /// pure-Rust detectors that have no external binary or ruleset.
    fn provenance(&self) -> Option<DetectorProvenance> {
        None
    }
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
    /// Optional metrics for this completed operation.
    pub metrics: Option<OperationMetrics>,
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
    /// Detector execution duration in milliseconds.
    pub duration_ms: u64,
    /// Binary provenance for subprocess detectors, when available.
    pub provenance: Option<DetectorProvenance>,
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
    metrics_enabled: bool,
    budget: AnalysisBudget,
}

impl AnalysisCoordinator {
    /// Creates a coordinator with the default MVP detectors.
    #[must_use]
    pub fn new() -> Self {
        Self::with_detectors(vec![
            Box::new(ArchiveHazardDetector),
            Box::new(ArtifactDetector),
            Box::new(pyjs::PythonJsDetector),
            Box::new(ShellDetector),
        ])
    }

    /// Creates a coordinator from explicit detectors sorted by detector id.
    #[must_use]
    pub fn with_detectors(mut detectors: Vec<Box<dyn Detector>>) -> Self {
        detectors.sort_by(|left, right| left.metadata().id.cmp(&right.metadata().id));
        let detectors = detectors.into_iter().map(Arc::from).collect();
        Self {
            detectors,
            metrics_enabled: true,
            budget: AnalysisBudget::default(),
        }
    }

    /// Enables or disables operation metrics collection and completion logs.
    #[must_use]
    pub const fn with_metrics_enabled(mut self, enabled: bool) -> Self {
        self.metrics_enabled = enabled;
        self
    }

    /// Sets the global analysis budget (spec §41.16).
    #[must_use]
    pub const fn with_budget(mut self, budget: AnalysisBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Returns the current analysis budget.
    #[must_use]
    pub const fn budget(&self) -> &AnalysisBudget {
        &self.budget
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
        let scan_started = Instant::now();
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
            tracing::debug!(
                target: "arbitraitor.operation.detector",
                detector_id = %execution.result.metadata.id,
                duration_ms = execution.result.duration_ms,
                finding_count = execution.result.finding_count,
                status = ?execution.result.status,
                "detector completed"
            );
            findings.extend(execution.findings);
            detector_results.push(execution.result);
        }

        let verdict = derive_verdict(&findings, &detector_results);
        let metrics = self.metrics_enabled.then(|| {
            let metrics = OperationMetrics {
                scan_duration_ms: elapsed_millis(scan_started.elapsed()),
                finding_count: findings.len(),
                verdict: format!("{verdict:?}"),
                artifact_size: usize_to_u64(artifact_bytes.len()),
                artifact_type: format!("{:?}", classification.artifact_type),
                detector_count: detector_results.len(),
                detector_errors: detector_results
                    .iter()
                    .filter(|result| !matches!(result.status, DetectorStatus::Ok))
                    .count(),
            };
            log_operation(&metrics);
            metrics
        });
        AnalysisResult {
            findings,
            classification,
            detector_results,
            verdict,
            metrics,
        }
    }
}

impl Default for AnalysisCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs the analysis coordinator recursively across an artifact and every
/// payload contained within nested archives, returning the payload graph and the
/// aggregate of all findings.
///
/// Each reachable node is analyzed with the full coordinator. A node's findings
/// carry that node's SHA-256 (enforced centrally by the coordinator's digest
/// integrity check) and are tagged with their payload origin so consumers can
/// trace each finding back to the archive entry that produced it. Containment
/// cycles, archive errors, and depth truncation are surfaced as additional
/// findings rather than aborting analysis.
///
/// Recursion depth and per-level extraction are bounded by [`ArchiveLimits::default`]
/// and `max_depth`. This does not release or execute any artifact; it only inspects
/// bytes already in memory.
#[must_use]
pub fn analyze_recursive(
    coordinator: &AnalysisCoordinator,
    bytes: &[u8],
    max_depth: u32,
) -> (ArtifactNode, Vec<Finding>) {
    let classification = classify(bytes);
    let limits = ArchiveLimits::default();
    let mut findings: Vec<Finding> = Vec::new();

    let (node, issues) = walk_payloads(
        bytes,
        classification.artifact_type,
        &limits,
        max_depth,
        &mut |node_ref: &PayloadNode<'_>, node_bytes: &[u8]| {
            let result = coordinator.analyze(node_bytes);
            for mut finding in result.findings {
                tag_finding_with_origin(&mut finding, node_ref);
                findings.push(finding);
            }
        },
    );

    for issue in issues {
        findings.push(issue_to_finding(issue));
    }

    (node, findings)
}

fn tag_finding_with_origin(finding: &mut Finding, node: &PayloadNode<'_>) {
    finding.tags.push("recursive-payload".to_owned());
    match node.origin {
        ArtifactOrigin::Root => {
            finding.tags.push(PAYLOAD_ORIGIN_ROOT_TAG.to_owned());
        }
        ArtifactOrigin::ArchiveEntry { entry_name, .. } => {
            finding.tags.push(PAYLOAD_ORIGIN_ENTRY_TAG.to_owned());
            finding.tags.push(format!("payload-entry:{entry_name}"));
        }
    }
    finding.tags.push(format!("payload-depth:{}", node.depth));
}

fn issue_to_finding(issue: PayloadIssue) -> Finding {
    let (id, category, severity, title, description, sha256, tag) = match issue {
        PayloadIssue::Cycle { sha256, origin } => (
            "recursive-payload.cycle",
            FindingCategory::ArchiveHazard,
            Severity::Critical,
            "Recursive payload cycle detected".to_owned(),
            format!(
                "Artifact {sha256} appears within its own containment chain (origin: {origin:?}). \
                 Self-referential archives are characteristic of archive quines or decompression bombs."
            ),
            sha256,
            "payload-cycle",
        ),
        PayloadIssue::ArchiveError {
            error,
            sha256,
            origin,
        } => (
            "recursive-payload.archive-error",
            FindingCategory::ArchiveHazard,
            Severity::Medium,
            "Nested payload could not be extracted".to_owned(),
            format!(
                "An archive error prevented inspecting a contained payload: {error} \
                 (origin: {origin:?})."
            ),
            sha256,
            "payload-archive-error",
        ),
        PayloadIssue::DepthTruncated {
            sha256,
            origin,
            max_depth,
        } => (
            "recursive-payload.depth-truncated",
            FindingCategory::ResourceLimitEvent,
            Severity::Medium,
            "Recursive payload inspection hit the depth limit".to_owned(),
            format!(
                "Archive {sha256} (origin: {origin:?}) was not expanded because the \
                 maximum nesting depth of {max_depth} was reached, so its contained \
                 payloads were not inspected."
            ),
            sha256,
            "payload-depth-truncated",
        ),
    };

    Finding {
        id: id.to_owned(),
        detector: RECURSIVE_PAYLOAD_DETECTOR_ID.to_owned(),
        category,
        severity,
        confidence: Confidence::Confirmed,
        title,
        description,
        evidence: Vec::new(),
        artifact_sha256: sha256,
        location: None,
        remediation: Some(
            "Review the artifact manually or adjust policy limits before release.".to_owned(),
        ),
        references: vec!["Arbitraitor spec section 20.1".to_owned()],
        tags: vec!["recursive-payload".to_owned(), tag.to_owned()],
        taxonomies: Vec::new(),
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
    let provenance = detector.provenance();
    let started = Instant::now();
    let timeout = Duration::from_millis(metadata.default_timeout_ms);
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| detector.analyze(&ctx.as_context())));
        let _ = tx.send((result, ctx.artifact_sha256));
    });

    match rx.recv_timeout(timeout) {
        Ok((Ok(Ok(raw_findings)), artifact_sha256)) => {
            // Enforce finding digest integrity centrally: every finding must
            // reference the artifact SHA-256 from the analysis context, regardless
            // of what the detector set. This prevents buggy or compromised
            // detectors from attributing findings to wrong artifacts.
            let findings = rewrite_artifact_digest(raw_findings, &artifact_sha256);
            DetectorExecution {
                result: DetectorResult {
                    metadata,
                    status: DetectorStatus::Ok,
                    finding_count: findings.len(),
                    duration_ms: elapsed_millis(started.elapsed()),
                    provenance,
                },
                findings,
            }
        }
        Ok((Ok(Err(error)), _artifact_sha256)) => DetectorExecution {
            findings: Vec::new(),
            result: DetectorResult {
                metadata,
                status: DetectorStatus::Error(error.to_string()),
                finding_count: 0,
                duration_ms: elapsed_millis(started.elapsed()),
                provenance,
            },
        },
        Ok((Err(payload), _artifact_sha256)) => DetectorExecution {
            findings: Vec::new(),
            result: DetectorResult {
                metadata,
                status: DetectorStatus::Error(panic_message(payload.as_ref())),
                finding_count: 0,
                duration_ms: elapsed_millis(started.elapsed()),
                provenance,
            },
        },
        Err(mpsc::RecvTimeoutError::Timeout) => DetectorExecution {
            findings: Vec::new(),
            result: DetectorResult {
                metadata,
                status: DetectorStatus::Timeout,
                finding_count: 0,
                duration_ms: elapsed_millis(started.elapsed()),
                provenance,
            },
        },
        Err(mpsc::RecvTimeoutError::Disconnected) => DetectorExecution {
            findings: Vec::new(),
            result: DetectorResult {
                metadata,
                status: DetectorStatus::Error("detector thread disconnected".to_owned()),
                finding_count: 0,
                duration_ms: elapsed_millis(started.elapsed()),
                provenance,
            },
        },
    }
}

fn elapsed_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
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

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        if matches!(ctx.classification.artifact_type, ArtifactType::Unknown) {
            Ok(vec![unknown_artifact_finding(ctx)])
        } else {
            Ok(Vec::new())
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
                "companion-artifact-discovery".to_owned(),
            ],
            is_local: true,
            may_upload: false,
            default_timeout_ms: 5_000,
            is_deterministic: true,
        }
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        let limits = ArchiveLimits::default();
        let mut reader = match open_archive_with_limits(
            ctx.artifact_bytes,
            ctx.classification.artifact_type,
            limits.clone(),
        ) {
            Ok(reader) => reader,
            Err(error) => {
                return Ok(vec![archive_error_finding(ctx, &error)]);
            }
        };
        match reader.entries() {
            Ok(entries) => {
                let mut findings = detect_archive_hazards(&entries, &limits);
                if ctx.classification.artifact_type == ArtifactType::TarArchive {
                    findings.extend(detect_tar_parser_differentials(
                        ctx.artifact_bytes,
                        &entries,
                        &limits,
                    ));
                }
                findings.extend(discover_companion_findings(&entries, ctx));
                Ok(rewrite_artifact_digest(findings, &ctx.artifact_sha256))
            }
            Err(error) => {
                let mut findings = vec![archive_error_finding(ctx, &error)];
                if ctx.classification.artifact_type == ArtifactType::TarArchive {
                    findings.extend(detect_tar_parser_differentials(
                        ctx.artifact_bytes,
                        &[],
                        &limits,
                    ));
                }
                Ok(rewrite_artifact_digest(findings, &ctx.artifact_sha256))
            }
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

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError> {
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
            return Ok(Vec::new());
        };

        Ok(vec![reputation_finding(ctx, &matches, enforcement)])
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

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        let mut parser = match ShellParser::with_config(ParserConfig {
            artifact_sha256: ctx.artifact_sha256.clone(),
            ..ParserConfig::default()
        }) {
            Ok(parser) => parser,
            Err(error) => {
                return Ok(vec![shell_setup_finding(ctx, &error.to_string())]);
            }
        };

        let parse_result = parser.parse_bytes(ctx.artifact_bytes);
        let mut findings = rewrite_artifact_digest(parse_result.parse_errors, &ctx.artifact_sha256);

        let Ok(source) = std::str::from_utf8(ctx.artifact_bytes) else {
            return Ok(findings);
        };
        let normalization = match normalize(&parse_result.ast, source) {
            Ok(normalization) => normalization,
            Err(error) => {
                findings.push(shell_normalization_finding(ctx, &error.to_string()));
                return Ok(findings);
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
        Ok(findings)
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

const COMPANION_REFERENCE: &str = "https://github.com/arbsec/arbitraitor/blob/main/docs/spec/spec.md#195-companion-artifact-consumption-sbom-vex";

fn discover_companion_findings(
    entries: &[arbitraitor_archive::ArchiveEntry],
    ctx: &AnalysisContext<'_>,
) -> Vec<Finding> {
    let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
    let companions = arbitraitor_model::vex::discover_companion_artifacts(&names);
    companions
        .iter()
        .map(|artifact| companion_finding(artifact, ctx))
        .collect()
}

fn companion_finding(
    artifact: &arbitraitor_model::vex::CompanionArtifact,
    ctx: &AnalysisContext<'_>,
) -> Finding {
    let format_name = match artifact.format {
        arbitraitor_model::vex::CompanionFormat::CycloneDx => "CycloneDX SBOM",
        arbitraitor_model::vex::CompanionFormat::Spdx => "SPDX SBOM",
        arbitraitor_model::vex::CompanionFormat::OpenVex => "OpenVEX statement",
        arbitraitor_model::vex::CompanionFormat::Csaf => "CSAF VEX document",
    };
    Finding {
        id: format!("archive.companion.{}", artifact.name.replace('.', "-")),
        detector: ARCHIVE_DETECTOR_ID.to_owned(),
        category: FindingCategory::SupplyChain,
        severity: Severity::Informational,
        confidence: Confidence::Confirmed,
        title: format!("Discovered {format_name} companion artifact"),
        description: format!(
            "Archive entry '{}' is a {format_name}. Per spec §19.5, its contents are recorded as evidence — SBOM components become references, VEX statements may downgrade vulnerability severity under anti-suppression rules.",
            artifact.name
        ),
        evidence: vec![Evidence {
            kind: EvidenceKind::Other,
            description: format!("companion artifact: {format_name}"),
            content: Some(format!(
                "entry={}; format={:?}",
                artifact.name, artifact.format
            )),
        }],
        artifact_sha256: ctx.artifact_sha256.clone(),
        location: None,
        remediation: None,
        references: vec![COMPANION_REFERENCE.to_owned()],
        tags: vec![
            "companion-artifact".to_owned(),
            format!("{:?}", artifact.format).to_ascii_lowercase(),
        ],
        taxonomies: Vec::new(),
    }
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
        taxonomies: Vec::new(),
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
        taxonomies: Vec::new(),
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
        taxonomies: Vec::new(),
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
        taxonomies: Vec::new(),
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
        ArtifactType::WindowsShortcut => ArtifactKind::WindowsShortcut,
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
#[path = "tests.rs"]
mod tests;
