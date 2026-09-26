//! Internal pipeline stage helpers for the engine.
//!
//! Everything in this module is moved — not re-composed — from the three
//! former compositions: `arbitraitor-cli/src/pipeline.rs` (ADR-0027),
//! `arbitraitor-daemon/src/api.rs`, and the MCP tool handlers. Consumers
//! must not depend on these internals; they are crate-private.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use arbitraitor_analysis::{AnalysisCoordinator, RetrievalInfo as AnalysisRetrievalInfo};
use arbitraitor_fetch::{ChildArtifact, FetchSource, FetchUrl};
use arbitraitor_model::finding::FindingCategory;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity};
use arbitraitor_provenance::SignatureVerification;
use arbitraitor_receipt::{
    DetectorVersion, FindingSummary, Receipt, ReceiptBuilder, ReceiptTimestamps,
    RetrievalInfo as ReceiptRetrievalInfo, VerdictInfo,
};
use arbitraitor_store::{ContentStore, RetentionMode};
use arbitraitor_yarax::{RulePackManager, RuleSource, YaraDetector};

use crate::EngineError;

/// Parse an inspection source into a fetch source.
///
/// Accepts `http://`/`https://` URLs, `file://` URLs, and bare local paths.
/// `-` and `stdin://` parse to [`FetchSource::Stdin`]; callers that cannot
/// support stdin reject it themselves so the error names the right command.
///
/// # Errors
///
/// Returns [`EngineError::Config`] for unsupported URI schemes or invalid URLs.
pub fn parse_fetch_source(input: &str) -> Result<FetchSource, EngineError> {
    if input == "-" || input == "stdin://" {
        return Ok(FetchSource::Stdin);
    }
    if input.starts_with("http://") || input.starts_with("https://") {
        return Ok(FetchSource::Url(FetchUrl::parse(input).map_err(
            |error| EngineError::Config(format!("invalid URL: {error}")),
        )?));
    }
    if input.starts_with("file://") {
        let parsed = FetchUrl::parse(input)
            .map_err(|error| EngineError::Config(format!("invalid file:// URL: {error}")))?;
        let path = parsed.as_url().to_file_path().map_err(|()| {
            EngineError::Config("file:// URL does not resolve to a local path".to_owned())
        })?;
        return Ok(FetchSource::File(path));
    }
    if let Some(colon) = input.find(':') {
        let scheme = &input[..colon];
        if !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        {
            return Err(EngineError::Config(format!(
                "unsupported URI scheme '{scheme}'; only http, https, and file are accepted"
            )));
        }
    }
    Ok(FetchSource::File(PathBuf::from(input)))
}

/// Build the artifact analysis coordinator, including optional YARA rules.
///
/// The built-in MVP detectors are always preserved alongside YARA: replacing
/// them with `[Artifact, Shell, Yara]` drops `ArchiveHazard`, `PythonJs`, and
/// `UrlDiscovery` — and `UrlDiscovery` is mandatory for HTML/JSON per
/// `MandatoryDetectorRegistry::mandatory_detectors`, so configuring any
/// YARA rule pack would silently block every HTML/JSON fetch with a
/// mandatory-coverage Critical finding.
pub(crate) fn analysis_coordinator(
    rules_dir: Option<&Path>,
) -> Result<(AnalysisCoordinator, Vec<DetectorVersion>), EngineError> {
    let Some(rules_dir) = rules_dir else {
        return Ok((AnalysisCoordinator::new(), Vec::new()));
    };

    let mut manager = RulePackManager::with_built_in()?;
    manager.load_directory(rules_dir, RuleSource::FileSystem(rules_dir.to_path_buf()))?;
    let rule_pack_versions = manager.pack_versions();
    let scanner = manager.compile_all()?;
    let detector = YaraDetector::from_scanner(&scanner)?;
    let mut detectors = AnalysisCoordinator::default_detectors();
    detectors.push(Box::new(detector));
    Ok((
        AnalysisCoordinator::with_detectors(detectors),
        rule_pack_versions,
    ))
}

/// Return the default content-addressed store directory.
///
/// The default lives in the user's cache root —
/// `$XDG_CACHE_HOME/arbitraitor/cas`, falling back to
/// `$HOME/.cache/arbitraitor/cas` — so interception never materializes a
/// store inside the caller's working directory. When no home directory can
/// be resolved, the legacy relative `.arbitraitor/cas` is returned.
#[must_use]
pub fn default_cas_dir() -> PathBuf {
    match user_cache_root() {
        Some(root) => root.join("arbitraitor").join("cas"),
        None => PathBuf::from(".arbitraitor").join("cas"),
    }
}

/// Return the default receipts directory (sibling of the CAS root).
#[must_use]
pub fn default_receipts_dir() -> PathBuf {
    match user_cache_root() {
        Some(root) => root.join("arbitraitor").join("receipts"),
        None => PathBuf::from(".arbitraitor").join("receipts"),
    }
}

/// Resolves the user's cache root: `$XDG_CACHE_HOME` when set to an absolute
/// path, otherwise `$HOME/.cache`.
fn user_cache_root() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME")
        && !path.is_empty()
    {
        let path = PathBuf::from(path);
        if path.is_absolute() {
            return Some(path);
        }
    }
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(|home| PathBuf::from(home).join(".cache"))
}

/// Return the current timestamp in the receipt timestamp format.
#[must_use]
pub fn receipt_timestamp() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => format!(
            "unix:{}.{:09}Z",
            duration.as_secs(),
            duration.subsec_nanos()
        ),
        Err(error) => format!(
            "unix:-{}.{:09}Z",
            error.duration().as_secs(),
            error.duration().subsec_nanos()
        ),
    }
}

/// Parse a receipt timestamp (`unix:<secs>.<nanos>Z` or a bare epoch-seconds
/// string) into whole seconds since the Unix epoch.
///
/// The bare-seconds form is accepted because receipts written by the former
/// daemon composition used it; unification standardizes on the richer form.
pub(crate) fn receipt_timestamp_seconds(timestamp: &str) -> u64 {
    let seconds = timestamp.strip_prefix("unix:").unwrap_or(timestamp);
    seconds
        .split('.')
        .next()
        .and_then(|secs| secs.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Convert fetch receipt metadata to analysis retrieval metadata.
pub(crate) fn analysis_retrieval_info(
    requested_url: &str,
    fetch_receipt: &arbitraitor_fetch::FetchReceipt,
) -> AnalysisRetrievalInfo {
    AnalysisRetrievalInfo {
        requested_location: Some(arbitraitor_fetch::redact_url(requested_url)),
        final_location: fetch_receipt
            .metadata
            .final_url
            .as_ref()
            .map(ToString::to_string)
            .map(|url| arbitraitor_fetch::redact_url(&url)),
        content_type: fetch_receipt.metadata.content_type.clone(),
        byte_count: Some(fetch_receipt.bytes_written),
    }
}

/// Convert fetch receipt metadata to receipt retrieval metadata.
pub(crate) fn receipt_retrieval_info(
    requested_url: &str,
    fetch_receipt: &arbitraitor_fetch::FetchReceipt,
) -> ReceiptRetrievalInfo {
    let mut retrieval = ReceiptRetrievalInfo::new(requested_url)
        .with_redirect_chain(
            fetch_receipt
                .metadata
                .redirect_chain
                .iter()
                .map(ToString::to_string),
        )
        .with_byte_count(fetch_receipt.bytes_written)
        .with_redirect_credential_secrecy(fetch_receipt.metadata.redirect_credential_secrecy);
    if let Some(final_url) = &fetch_receipt.metadata.final_url {
        retrieval = retrieval.with_final_url(final_url.to_string());
    }
    if let Some(content_type) = &fetch_receipt.metadata.content_type {
        retrieval = retrieval.with_content_type(content_type.clone());
    }
    if let Some(tls_version) = &fetch_receipt.metadata.tls_version {
        retrieval = retrieval.with_tls_version(tls_version.clone());
    }
    if let Some(fingerprint) = &fetch_receipt.metadata.peer_certificate_fingerprint {
        retrieval = retrieval.with_peer_cert_fingerprint(format!("sha256:{fingerprint}"));
    }
    retrieval
}

/// Convert a signature verification into a receipt finding summary.
pub(crate) fn signature_finding(
    index: usize,
    verification: &SignatureVerification,
) -> FindingSummary {
    FindingSummary {
        id: format!(
            "provenance.signature.{}.{}",
            verification.system.as_str(),
            index + 1
        ),
        category: FindingCategory::Provenance,
        severity: Severity::Informational,
        confidence: Confidence::Confirmed,
        title: signature_title(verification),
        location: None,
        evidence: None,
        remediation: None,
        references: Vec::new(),
        taxonomies: Vec::new(),
    }
}

/// Generate a human-readable receipt title for a signature verification.
pub(crate) fn signature_title(verification: &SignatureVerification) -> String {
    let system = verification.system.as_str();
    match verification.identity.as_deref() {
        Some(identity) => format!("{system} signature verified for {identity}"),
        None => format!("{system} signature verified"),
    }
}

/// Inputs to the unified receipt builder.
pub(crate) struct ReceiptInput<'a> {
    /// Requested source string (URL or path) as the consumer supplied it.
    pub(crate) requested_url: &'a str,
    /// Fetch receipt carrying transport metadata and child artifacts.
    pub(crate) fetch_receipt: &'a arbitraitor_fetch::FetchReceipt,
    /// Analysis result carrying findings, classification, and detector output.
    pub(crate) analysis: &'a arbitraitor_analysis::AnalysisResult,
    /// Final policy verdict.
    pub(crate) verdict: arbitraitor_model::verdict::Verdict,
    /// Policy trace entries explaining the verdict.
    pub(crate) policy_trace: Vec<String>,
    /// YARA rule pack versions contributing to the analysis.
    pub(crate) rule_pack_versions: &'a [DetectorVersion],
    /// Completed signature verifications.
    pub(crate) signature_verifications: &'a [SignatureVerification],
}

/// Build the unified inspection receipt.
///
/// This is the single receipt shape for every consumer: the former CLI
/// receipt (transport metadata, signature findings, rule pack versions) is
/// the superset, extended with the former daemon receipt's detector
/// provenance entries.
pub(crate) fn build_receipt(input: &ReceiptInput<'_>) -> Receipt {
    let artifact_size = input.analysis_size();
    let now = receipt_timestamp();
    let mut builder = ReceiptBuilder::new(
        env!("CARGO_PKG_VERSION"),
        input.fetch_receipt.sha256.to_string(),
        artifact_size,
        VerdictInfo {
            verdict: input.verdict,
            deciding_rule: None,
            policy_trace: input.policy_trace.clone(),
        },
        ReceiptTimestamps {
            created: now.clone(),
            modified: now,
        },
    )
    .artifact_type(format!("{:?}", input.analysis.classification.artifact_type))
    .retrieval(receipt_retrieval_info(
        input.requested_url,
        input.fetch_receipt,
    ))
    .findings(input.analysis.findings.iter().map(FindingSummary::from))
    .findings(
        input
            .signature_verifications
            .iter()
            .enumerate()
            .map(|(index, verification)| signature_finding(index, verification)),
    );

    for detector_result in &input.analysis.detector_results {
        builder = builder.detector_version(DetectorVersion {
            id: detector_result.metadata.id.clone(),
            version: detector_result.metadata.version.clone(),
        });
        if let Some(provenance) = &detector_result.provenance {
            builder = builder.detector_provenance(provenance.clone());
        }
    }
    for rule_pack_version in input.rule_pack_versions {
        builder = builder.detector_version(rule_pack_version.clone());
    }

    if let Some(identity) = input
        .signature_verifications
        .iter()
        .find_map(|v| v.verifier_identity.as_deref())
    {
        builder = builder.verifier_identity(identity);
    }

    builder.build()
}

impl ReceiptInput<'_> {
    fn analysis_size(&self) -> u64 {
        self.fetch_receipt.bytes_written
    }
}

/// Discover, extract, and store child artifacts in CAS.
///
/// When the fetched bytes are an archive or compressed stream, extracts
/// each direct child, stores it in CAS, and returns the child artifact
/// metadata for the receipt. Extraction is bounded by
/// `ArchiveLimits::default()` (Invariant 4: bounded processing); each stored
/// child is additionally bounded by the engine's configured per-artifact
/// `max_bytes` so a tiny configured store limit applies to expanded content
/// the same way it applies to the top-level fetch.
pub(crate) fn discover_and_store_children(
    store: &ContentStore,
    bytes: &[u8],
    max_bytes: u64,
) -> Result<Vec<ChildArtifact>, EngineError> {
    let children_with_bytes = arbitraitor_fetch::discover_child_artifacts_with_bytes(bytes);
    let mut child_artifacts = Vec::with_capacity(children_with_bytes.len());
    for (artifact, child_bytes) in children_with_bytes {
        store.store_with_metadata_and_limits(
            child_bytes,
            None,
            None,
            RetentionMode::Cache,
            max_bytes,
        )?;
        child_artifacts.push(artifact);
    }
    Ok(child_artifacts)
}

/// Read a stored artifact's bytes by digest.
pub(crate) fn read_stored_bytes(
    store: &ContentStore,
    digest: &Sha256Digest,
) -> Result<Vec<u8>, arbitraitor_store::StoreError> {
    use std::io::Read as _;
    let handle = store.get(digest)?;
    let size = handle.size();
    let mut reader = handle.read();
    let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    reader
        .read_to_end(&mut bytes)
        .map_err(|source| arbitraitor_store::StoreError::Io {
            stage: "read-stored-artifact",
            source,
        })?;
    Ok(bytes)
}
