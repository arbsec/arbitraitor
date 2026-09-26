//! Programmatic pipeline API for Arbitraitor operations (ADR-0038).
//!
//! This is the single consolidated composition of the
//! fetch → store → analyze → provenance → receipt → verdict pipeline. All
//! integration surfaces (CLI, MCP gateway, Unix-socket daemon, third-party
//! embedders) start with [`crate::Arbitraitor::builder`] or call
//! [`ArbitraitorApi::new`] directly. The engine drives the
//! `arbitraitor-core` pipeline state machine through every inspection and
//! release; consumers never compose pipeline stages themselves.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use arbitraitor_analysis::{AnalysisCoordinator, DetectorStatus, RetrievalInfo};
use arbitraitor_artifact::classify;
use arbitraitor_core::{PipelineOperation, PipelineState, StateError, StateErrorKind};
use arbitraitor_fetch::{
    FetchPolicy, FetchRequest, FetchSource, Fetcher, FileFetcher, HttpFetcher, VecSink, redact_url,
};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::ids::{ArtifactId, OperationId};
use arbitraitor_model::verdict::Verdict;
use arbitraitor_policy::RuleEvaluation;
use arbitraitor_policy::{EvalContext, PolicyEngine, PolicyTrace};
use arbitraitor_receipt::Receipt;
use sha2::{Digest as _, Sha256};

use crate::EngineError;
use crate::pipeline::{
    ReceiptInput, analysis_retrieval_info, build_receipt, default_cas_dir, default_receipts_dir,
    discover_and_store_children, parse_fetch_source, read_stored_bytes, receipt_timestamp_seconds,
};
use crate::signatures::SignatureInputs;

mod builder;

pub use builder::{Arbitraitor, ArbitraitorBuilder};

/// Fail-closed policy for non-interactive surfaces.
///
/// Every artifact that no rule matches prompts, and a prompt in a
/// non-interactive context is upgraded to `block`. The Unix-socket daemon
/// configures the engine with this policy so unattended inspection never
/// silently passes content.
pub const FAIL_CLOSED_POLICY_TOML: &str = "\
version = 1\n\
[defaults]\n\
action = \"prompt\"\n\
non_interactive_prompt_action = \"block\"\n\
";

/// Policy trace entry recorded when the built-in verdict derivation applies.
const BUILTIN_VERDICT_TRACE: &str = "arbitraitor-engine built-in verdict derivation";

/// Default maximum size of an artifact read by [`ArbitraitorApi::scan_path`]
/// (256 MiB). The bound enforces the bounded-processing invariant: every
/// read has an explicit memory limit.
pub const DEFAULT_SCAN_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Programmatic API for Arbitraitor operations.
///
/// Composes fetcher, content store, analysis coordinator, policy engine,
/// provenance verification, and receipt builder into a single in-process
/// interface. Instances are cheap to clone internally (the store and
/// coordinator are behind `Arc`) and safe to share across tasks via `&self`.
#[derive(Clone)]
pub struct ArbitraitorApi {
    store: arbitraitor_store::ContentStore,
    fetcher: HttpFetcher,
    policy: Option<PolicyEngine>,
    coordinator: std::sync::Arc<AnalysisCoordinator>,
    rule_pack_versions: Vec<arbitraitor_receipt::DetectorVersion>,
    fetch_policy: FetchPolicy,
    receipts_dir: PathBuf,
    emit_partial_receipt_on_cancel: bool,
    signatures: SignatureInputs,
    store_max_bytes: u64,
}

/// Tunable construction options for [`ArbitraitorApi`].
#[derive(Clone, Debug)]
pub struct Config {
    /// CAS root directory for content-addressed storage.
    pub store_path: PathBuf,
    /// Directory where inspection receipts are persisted as JSON files.
    pub receipts_path: PathBuf,
    /// Fetch policy controlling timeouts, schemes, and size limits.
    ///
    /// Wrapping this in an engine-owned type is sequenced as stage 6 of the
    /// ADR-0038 rollout, before the crate publishes to crates.io.
    pub fetch_policy: FetchPolicy,
    /// Maximum bytes accepted into storage by every engine-managed write.
    /// Enforced by the CAS streaming sink itself
    /// ([`arbitraitor_store::ContentStore::sink_with_limits`]); defaults to
    /// [`arbitraitor_store::DEFAULT_MAX_BYTES`].
    pub store_max_bytes: u64,
    /// Policy TOML for verdict evaluation. An empty string selects the
    /// built-in verdict derivation (see the crate docs); non-interactive
    /// surfaces pass [`FAIL_CLOSED_POLICY_TOML`] instead.
    pub policy_toml: String,
    /// When `true`, the operation queue writes a partial receipt file
    /// for cancelled operations. Defaults to `false` so
    /// deployments that do not need cancellation forensics are
    /// unaffected.
    pub emit_partial_receipt_on_cancel: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            store_path: default_cas_dir(),
            receipts_path: default_receipts_dir(),
            fetch_policy: FetchPolicy::default(),
            store_max_bytes: arbitraitor_store::DEFAULT_MAX_BYTES,
            policy_toml: String::new(),
            emit_partial_receipt_on_cancel: false,
        }
    }
}

/// Outcome of an [`ArbitraitorApi::inspect`], [`ArbitraitorApi::scan`], or
/// [`ArbitraitorApi::scan_path`] call.
#[derive(Clone, Debug)]
pub struct InspectionResult {
    /// SHA-256 hex digest of the analyzed artifact.
    pub sha256: String,
    /// Artifact size in bytes.
    pub size_bytes: u64,
    /// Declared content type, when known.
    pub content_type: Option<String>,
    /// Final policy verdict.
    pub verdict: Verdict,
    /// All detector findings emitted for this artifact.
    pub findings: Vec<arbitraitor_model::finding::Finding>,
    /// Artifact classification rendered in its debug form (e.g.
    /// `ShellScript(Bash)`).
    pub artifact_type: String,
    /// Per-detector outcome summaries.
    pub detector_results: Vec<DetectorSummary>,
    /// Completed provenance verifications for this artifact.
    pub signature_verifications: Vec<SignatureVerificationSummary>,
    /// Engine-owned receipt wrapper (ADR-0038 decision 6).
    pub receipt: InspectionResultReceipt,
    /// Path to the persisted receipt JSON, when one was written.
    pub receipt_path: Option<PathBuf>,
}

/// Engine-owned summary of one detector's run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectorSummary {
    /// Detector identifier (e.g. `artifact`, `shell-analysis`).
    pub id: String,
    /// Detector version.
    pub version: String,
    /// Declared detector capabilities.
    pub capabilities: Vec<String>,
    /// Whether the detector runs locally.
    pub is_local: bool,
    /// Whether the detector may upload content.
    pub may_upload: bool,
    /// Whether the detector is deterministic.
    pub is_deterministic: bool,
    /// Detector completion status.
    pub status: DetectorStatusSummary,
    /// Number of findings the detector emitted.
    pub finding_count: usize,
}

/// Engine-owned detector completion status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DetectorStatusSummary {
    /// The detector completed successfully.
    Ok,
    /// The detector reported an error (fail-closed: produces `Incomplete`).
    Error(String),
    /// The detector exceeded its time budget.
    Timeout,
}

impl From<&DetectorStatus> for DetectorStatusSummary {
    fn from(status: &DetectorStatus) -> Self {
        match status {
            DetectorStatus::Ok => Self::Ok,
            DetectorStatus::Error(message) => Self::Error(message.clone()),
            DetectorStatus::Timeout => Self::Timeout,
        }
    }
}

/// Engine-owned summary of one completed signature verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureVerificationSummary {
    /// Signature system (`minisign` or `cosign`).
    pub system: String,
    /// Identity observed or bound by the verification, when applicable.
    pub identity: Option<String>,
    /// Whether verification succeeded.
    pub verified: bool,
}

/// Outcome of [`ArbitraitorApi::fetch`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchResult {
    /// SHA-256 hex digest of the stored artifact.
    pub sha256: String,
    /// Number of bytes stored.
    pub size_bytes: u64,
    /// Final URL after redirects.
    pub final_url: String,
    /// Declared content type, when known.
    pub content_type: Option<String>,
}

/// Outcome of [`ArbitraitorApi::release`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseResult {
    /// Destination path where bytes were written.
    pub path: PathBuf,
    /// Number of artifact bytes released.
    pub bytes_written: u64,
    /// Filesystem publication method used by the safe-release primitive.
    ///
    /// Wrapping this in an engine-owned type is sequenced as stage 6 of the
    /// ADR-0038 rollout, before the crate publishes to crates.io.
    pub method: arbitraitor_exec::release::ReleaseMethod,
    /// Whether the SHA-256 was re-verified immediately before and after writing.
    pub sha256_verified: bool,
}

/// Filter applied when querying receipt history.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReceiptFilter {
    /// Maximum number of receipts to return.
    pub limit: Option<usize>,
    /// Only include receipts created at or after this Unix timestamp.
    pub since: Option<u64>,
}

/// Metadata row for a stored artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactSummary {
    /// SHA-256 hex digest.
    pub sha256: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Unix timestamp when the artifact was stored.
    pub stored_at: u64,
}

/// Condensed receipt information returned by [`ArbitraitorApi::query_receipts`].
#[derive(Clone, Debug)]
pub struct ReceiptSummary {
    /// SHA-256 hex digest of the artifact.
    pub sha256: String,
    /// Final policy verdict recorded in the receipt.
    pub verdict: Verdict,
    /// Artifact size in bytes.
    pub size_bytes: u64,
    /// Unix timestamp when the receipt was created.
    pub created_at: u64,
    /// Number of findings recorded in the receipt.
    pub findings_count: usize,
}

/// Engine-owned wrapper around the internal receipt (ADR-0038 decision 6).
///
/// Insulates consumers from `arbitraitor-receipt` schema changes (e.g. the
/// envelope restructure in issue #492): when the internal receipt schema
/// changes, the engine absorbs the mapping and consumers keep seeing this
/// stable type. The wrapper exposes the fields consumers need — verdict,
/// findings count, artifact identity, retrieval metadata — plus
/// serialization for persistence, without leaking `arbitraitor-receipt`
/// types.
#[derive(Clone, Debug)]
pub struct InspectionResultReceipt {
    inner: Receipt,
}

impl InspectionResultReceipt {
    /// SHA-256 hex digest of the inspected artifact.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.inner.artifact.sha256
    }

    /// Size of the inspected artifact in bytes.
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.inner.artifact.size
    }

    /// Final policy verdict recorded in the receipt.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        self.inner.verdict.verdict
    }

    /// Number of findings recorded in the receipt.
    #[must_use]
    pub fn findings_count(&self) -> usize {
        self.inner.findings.len()
    }

    /// Receipt creation timestamp in the engine's canonical format.
    #[must_use]
    pub fn created_at(&self) -> &str {
        &self.inner.timestamps.created
    }

    /// Requested source URL recorded in the receipt, when present.
    #[must_use]
    pub fn requested_url(&self) -> Option<&str> {
        self.inner
            .retrieval
            .as_ref()
            .map(arbitraitor_receipt::RetrievalInfo::requested_url)
    }

    /// Final URL after redirects recorded in the receipt, when present.
    #[must_use]
    pub fn final_url(&self) -> Option<&str> {
        self.inner.retrieval.as_ref().and_then(|r| r.final_url())
    }

    /// Serializes the receipt as pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Receipt`] when serialization fails.
    pub fn to_vec_pretty(&self) -> Result<Vec<u8>, EngineError> {
        serde_json::to_vec_pretty(&self.inner)
            .map_err(|error| EngineError::Receipt(error.to_string()))
    }
}

impl ArbitraitorApi {
    /// Creates a new API instance from the supplied [`Config`].
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Store`] if the content store cannot be opened,
    /// or [`EngineError::Config`] if the policy TOML is invalid.
    pub fn new(config: Config) -> Result<Self, EngineError> {
        Arbitraitor::builder().config(config).build()
    }

    /// Returns the directory where inspection receipts are persisted.
    #[must_use]
    pub fn receipts_dir(&self) -> &Path {
        &self.receipts_dir
    }

    /// Returns whether the API is configured to emit partial receipts for
    /// cancelled operations.
    #[must_use]
    pub fn emit_partial_receipt_on_cancel(&self) -> bool {
        self.emit_partial_receipt_on_cancel
    }

    /// Fetches a URL or local path, stores the artifact in CAS, runs
    /// detectors, verifies provenance, evaluates policy, persists a receipt,
    /// and returns findings plus verdict.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Fetch`] on transport failure,
    /// [`EngineError::Store`] on persistence failure,
    /// [`EngineError::Provenance`] when a configured signature verification
    /// fails, or [`EngineError::Io`] on receipt write failure.
    pub async fn inspect(&self, source: &str) -> Result<InspectionResult, EngineError> {
        self.inspect_pinned(source, None).await
    }

    /// Like [`ArbitraitorApi::inspect`], optionally pinning the expected
    /// artifact digest. A pinned digest that does not match the fetched
    /// bytes fails the retrieval (immutable identity, invariant 2).
    ///
    /// # Errors
    ///
    /// See [`ArbitraitorApi::inspect`].
    pub async fn inspect_pinned(
        &self,
        source: &str,
        expected_sha256: Option<Sha256Digest>,
    ) -> Result<InspectionResult, EngineError> {
        let fetch_source = parse_fetch_source(source)?;
        if matches!(fetch_source, FetchSource::Stdin) {
            return Err(EngineError::Config(
                "stdin source is not supported by inspect; use 'arbitraitor scan --stdin'"
                    .to_owned(),
            ));
        }
        let (bytes, fetch_receipt) = self.fetch_bytes(fetch_source, expected_sha256).await?;
        let digest = fetch_receipt.sha256.clone();
        let mut operation = PipelineOperation::new(OperationId::new(), ArtifactId(digest.clone()));
        // The artifact identity exists once retrieval completes; the
        // transition records the retrieval stage.
        operation = operation.transition_to(PipelineState::Retrieving)?;

        let stored = self.store.store_with_metadata_and_limits(
            bytes.clone(),
            Some(redact_url(source)),
            fetch_receipt.metadata.content_type.clone(),
            arbitraitor_store::RetentionMode::Cache,
            self.store_max_bytes,
        )?;
        if stored.0 != digest {
            return Err(EngineError::Store(format!(
                "CAS digest mismatch: stored={}, expected={}",
                stored.0, digest
            )));
        }
        operation = operation.transition_to(PipelineState::Stored)?;

        let (inspection, _operation) = self.analyze_and_finalize(
            operation,
            &bytes,
            &digest,
            source,
            Some(&fetch_receipt),
            fetch_receipt.metadata.content_type.clone(),
        )?;
        Ok(inspection)
    }

    /// Fetches and stores the raw artifact bytes without running analysis.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Fetch`] on transport failure or
    /// [`EngineError::Store`] on persistence failure.
    pub async fn fetch(&self, url: &str) -> Result<FetchResult, EngineError> {
        self.fetch_pinned(url, None).await
    }

    /// Like [`ArbitraitorApi::fetch`], optionally pinning the expected digest.
    ///
    /// # Errors
    ///
    /// See [`ArbitraitorApi::fetch`].
    pub async fn fetch_pinned(
        &self,
        url: &str,
        expected_sha256: Option<Sha256Digest>,
    ) -> Result<FetchResult, EngineError> {
        let fetch_source = parse_fetch_source(url)?;
        if matches!(fetch_source, FetchSource::Stdin) {
            return Err(EngineError::Config(
                "stdin source is not supported by fetch".to_owned(),
            ));
        }
        let (bytes, receipt) = self.fetch_bytes(fetch_source, expected_sha256).await?;
        let content_type = receipt.metadata.content_type.clone();
        let final_url = receipt
            .metadata
            .final_url
            .as_ref()
            .map_or_else(|| url.to_owned(), ToString::to_string);
        let size = receipt.bytes_written;
        let digest = receipt.sha256.clone();
        self.store.store_with_metadata_and_limits(
            bytes.clone(),
            Some(redact_url(url)),
            content_type.clone(),
            arbitraitor_store::RetentionMode::Cache,
            self.store_max_bytes,
        )?;
        discover_and_store_children(&self.store, &bytes, self.store_max_bytes)?;
        Ok(FetchResult {
            sha256: digest.to_string(),
            size_bytes: size,
            final_url,
            content_type,
        })
    }

    /// Scans an already-stored artifact by SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::NotFound`] when the digest is absent or invalid.
    pub fn scan(&self, sha256: &str) -> Result<InspectionResult, EngineError> {
        let digest = parse_digest(sha256)?;
        self.store
            .get(&digest)
            .map_err(not_found_if_missing(sha256))?;
        let bytes =
            read_stored_bytes(&self.store, &digest).map_err(not_found_if_missing(sha256))?;
        let entry = self.store.metadata_index().get(sha256)?;
        let requested = entry
            .as_ref()
            .and_then(|m| m.source_url.clone())
            .unwrap_or_else(|| sha256.to_owned());
        let mut operation = PipelineOperation::new(OperationId::new(), ArtifactId(digest.clone()));
        // The artifact was retrieved by a previous call; reading it back from
        // CAS re-confirms storage before analysis.
        operation = operation
            .transition_to(PipelineState::Retrieving)?
            .transition_to(PipelineState::Stored)?;
        let (inspection, _operation) = self.analyze_and_finalize(
            operation,
            &bytes,
            &digest,
            &requested,
            None,
            entry.as_ref().and_then(|m| m.content_type.clone()),
        )?;
        Ok(inspection)
    }

    /// Scans a local file by path: bounded read, CAS storage, analysis,
    /// provenance, policy, and receipt.
    ///
    /// Symlinked paths are rejected so a scan cannot be used to traverse
    /// quarantine boundaries, and reads are bounded by `max_bytes` so a
    /// single call cannot exhaust memory.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Config`] when the path is missing, a symlink, a
    /// directory, or exceeds `max_bytes`, and [`EngineError::Io`] on read
    /// failure.
    pub fn scan_path(&self, path: &Path, max_bytes: u64) -> Result<InspectionResult, EngineError> {
        let (bytes, digest) = read_bounded(path, max_bytes)?;
        let mut operation = PipelineOperation::new(OperationId::new(), ArtifactId(digest.clone()));
        operation = operation
            .transition_to(PipelineState::Retrieving)?
            .transition_to(PipelineState::Stored)?;
        self.store.store_with_metadata_and_limits(
            bytes.clone(),
            Some(path.to_string_lossy().into_owned()),
            None,
            arbitraitor_store::RetentionMode::Cache,
            self.store_max_bytes,
        )?;
        let (inspection, _operation) = self.analyze_and_finalize(
            operation,
            &bytes,
            &digest,
            &path.to_string_lossy(),
            None,
            None,
        )?;
        Ok(inspection)
    }

    /// Reads the exact stored bytes for an artifact digest.
    ///
    /// Bytes stay CAS-addressed: consumers that need the artifact (e.g. the
    /// CLI wrapper emitting to stdout) read them through this method and
    /// re-verify the digest before any release (invariant 2).
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::NotFound`] when the digest is absent or invalid.
    pub fn read_artifact(&self, sha256: &str) -> Result<Vec<u8>, EngineError> {
        let digest = parse_digest(sha256)?;
        read_stored_bytes(&self.store, &digest).map_err(not_found_if_missing(sha256))
    }

    /// Releases a stored artifact to `dest` through the ADR-0015 safe-release
    /// primitive.
    ///
    /// Release requires a prior inspection that produced a receipt for the
    /// artifact, and the recorded policy verdict must permit release. The
    /// engine drives the pipeline state machine through
    /// approval → release → completion on the recorded verdict, so a
    /// blocking or incomplete verdict — or any release-prohibited marker —
    /// is rejected by the state machine itself (spec §38.3), not just by a
    /// verdict comparison. The actual write is performed by
    /// [`arbitraitor_exec::release::release_artifact`], which re-verifies the
    /// digest before and after writing, rejects symlinks and hard-link
    /// surprises, writes via a sibling temporary file with restrictive
    /// permissions, and publishes atomically when possible.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::NotFound`] when the digest is absent or
    /// invalid, [`EngineError::NoReceipt`] when no prior inspection receipt
    /// exists for the artifact, [`EngineError::PolicyBlocked`] when the
    /// recorded verdict blocks release, or [`EngineError::Release`] when the
    /// safe-release primitive rejects the destination or fails verification.
    pub fn release(&self, sha256: &str, dest: &Path) -> Result<ReleaseResult, EngineError> {
        let digest = parse_digest(sha256)?;
        let verdict = self.lookup_verdict_for_release(sha256)?;
        let mut operation = reconstruct_operation(&digest, verdict)?;
        operation = operation
            .approve()
            .map_err(|error| policy_blocked(&error, verdict))?;
        let receipt = arbitraitor_exec::release::release_artifact(
            &self.store,
            &digest,
            dest,
            &arbitraitor_exec::release::ReleasePolicy::default(),
        )?;
        let _completed = operation.release()?.complete()?;
        Ok(ReleaseResult {
            path: receipt.destination,
            bytes_written: receipt.bytes_written,
            method: receipt.method,
            sha256_verified: true,
        })
    }

    /// Queries persisted receipts, optionally limited and filtered by time.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Receipt`] when a receipt file cannot be parsed.
    pub fn query_receipts(
        &self,
        filter: ReceiptFilter,
    ) -> Result<Vec<ReceiptSummary>, EngineError> {
        let mut summaries = Vec::new();
        if !self.receipts_dir.is_dir() {
            return Ok(summaries);
        }
        for entry in std::fs::read_dir(&self.receipts_dir)? {
            let path = entry?.path();
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            let data = std::fs::read(&path)?;
            let receipt: Receipt = serde_json::from_slice(&data)
                .map_err(|error| EngineError::Receipt(format!("{}: {error}", path.display())))?;
            let created_at = receipt_timestamp_seconds(&receipt.timestamps.created);
            if filter.since.is_some_and(|since| created_at < since) {
                continue;
            }
            summaries.push(ReceiptSummary {
                sha256: receipt.artifact.sha256.clone(),
                verdict: receipt.verdict.verdict,
                size_bytes: receipt.artifact.size,
                created_at,
                findings_count: receipt.findings.len(),
            });
        }
        if let Some(limit) = filter.limit {
            summaries.truncate(limit);
        }
        Ok(summaries)
    }

    /// Returns the persisted receipt summary for `sha256`, if one exists.
    ///
    /// Read-only: this accessor never re-runs analysis and never rewrites
    /// the receipt file. The audit trail is the write-once product of the
    /// inspection path (`inspect`, `scan`, `scan_path`, `fetch_pinned` +
    /// analysis); a query that mutated the receipt would silently rewrite
    /// policy traces and timestamps, breaking the §31 audit chain.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::NotFound`] when `sha256` is not a valid digest,
    /// [`EngineError::Receipt`] when a present receipt file cannot be
    /// parsed, or [`EngineError::Io`] on read failure.
    pub fn receipt_summary(&self, sha256: &str) -> Result<Option<ReceiptSummary>, EngineError> {
        parse_digest(sha256)?;
        let path = self.receipts_dir.join(format!("{sha256}.json"));
        if !path.is_file() {
            return Ok(None);
        }
        let data = std::fs::read(&path)?;
        let receipt: Receipt = serde_json::from_slice(&data)
            .map_err(|error| EngineError::Receipt(format!("{}: {error}", path.display())))?;
        let created_at = receipt_timestamp_seconds(&receipt.timestamps.created);
        Ok(Some(ReceiptSummary {
            sha256: receipt.artifact.sha256.clone(),
            verdict: receipt.verdict.verdict,
            size_bytes: receipt.artifact.size,
            created_at,
            findings_count: receipt.findings.len(),
        }))
    }

    /// Lists metadata for all stored artifacts.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Store`] when the metadata index cannot be read.
    pub fn list_artifacts(&self) -> Result<Vec<ArtifactSummary>, EngineError> {
        let entries = self.store.metadata_index().list()?;
        Ok(entries
            .into_iter()
            .map(
                |arbitraitor_store::MetadataEntry {
                     sha256,
                     size_bytes,
                     retrieved_at,
                     ..
                 }| ArtifactSummary {
                    sha256,
                    size_bytes,
                    stored_at: retrieved_at,
                },
            )
            .collect())
    }

    /// Fetches a source into a `VecSink` and returns the bytes plus fetch
    /// receipt. The fetcher enforces the configured fetch policy (size
    /// bounds, scheme allowlist, redirect rules) and verifies a pinned
    /// digest during streaming.
    async fn fetch_bytes(
        &self,
        source: FetchSource,
        expected_sha256: Option<Sha256Digest>,
    ) -> Result<(Vec<u8>, arbitraitor_fetch::FetchReceipt), EngineError> {
        let request = FetchRequest {
            source,
            policy: self.fetch_policy.clone(),
            method: arbitraitor_fetch::HttpMethod::Get,
            body: None,
            expected_sha256,
            cancellation: arbitraitor_fetch::FetchCancellation::new(),
            credentials: arbitraitor_fetch::RequestCredentials::default(),
            headers: Vec::new(),
        };
        let mut sink = VecSink::new();
        let receipt = match &request.source {
            FetchSource::File(_) => FileFetcher::new().fetch(request, &mut sink).await?,
            FetchSource::Url(_) => self.fetcher.fetch(request, &mut sink).await?,
            FetchSource::Stdin => {
                return Err(EngineError::Config(
                    "stdin source is not supported by the engine; use 'arbitraitor scan --stdin'"
                        .to_owned(),
                ));
            }
        };
        let bytes = sink.into_bytes();
        // Defense in depth (invariant 2): recompute the digest over the
        // buffered bytes and compare with the transport receipt.
        let recomputed = Sha256Digest::new(Sha256::digest(&bytes).into());
        if recomputed != receipt.sha256 {
            return Err(EngineError::Fetch(format!(
                "fetch digest mismatch: receipt={}, bytes={}",
                receipt.sha256, recomputed
            )));
        }
        Ok((bytes, receipt))
    }

    /// Runs the shared analysis → provenance → policy → receipt tail of the
    /// pipeline, driving the state machine through identification, analysis,
    /// expansion, and evaluation, and recording the verdict.
    ///
    /// Returns the inspection result plus the terminal operation (in
    /// `AwaitingApproval`) so callers and tests can observe the state
    /// machine's position.
    pub(crate) fn analyze_and_finalize(
        &self,
        operation: PipelineOperation,
        bytes: &[u8],
        digest: &Sha256Digest,
        requested_source: &str,
        fetch_receipt: Option<&arbitraitor_fetch::FetchReceipt>,
        content_type: Option<String>,
    ) -> Result<(InspectionResult, PipelineOperation), EngineError> {
        let mut operation = operation;
        let classification = classify(bytes);
        operation = operation.transition_to(PipelineState::Identified)?;

        let retrieval = fetch_receipt
            .map(|receipt| analysis_retrieval_info(requested_source, receipt))
            .or_else(|| {
                content_type.clone().map(|ct| RetrievalInfo {
                    requested_location: Some(requested_source.to_owned()),
                    final_location: None,
                    content_type: Some(ct),
                    byte_count: Some(u64::try_from(bytes.len()).unwrap_or(0)),
                })
            });
        let result = self.coordinator.analyze_with_retrieval(bytes, retrieval);
        operation = operation.transition_to(PipelineState::Analyzing)?;

        discover_and_store_children(&self.store, bytes, self.store_max_bytes)?;
        operation = operation.transition_to(PipelineState::Expanding)?;

        let (verdict, policy_trace) = self.resolve_verdict(&result);
        operation = operation
            .transition_to(PipelineState::Evaluating)?
            .record_verdict(verdict)?;

        let signature_verifications = if self.signatures.is_empty() {
            Vec::new()
        } else {
            self.signatures.verify(bytes)?
        };

        let size_bytes = u64::try_from(bytes.len()).unwrap_or(0);
        let synthetic_receipt;
        let receipt_ref = if let Some(receipt) = fetch_receipt {
            receipt
        } else {
            synthetic_receipt = synthetic_fetch_receipt(digest, size_bytes);
            &synthetic_receipt
        };
        let receipt = build_receipt(&ReceiptInput {
            requested_url: requested_source,
            fetch_receipt: receipt_ref,
            analysis: &result,
            verdict,
            policy_trace,
            rule_pack_versions: &self.rule_pack_versions,
            signature_verifications: &signature_verifications,
        });
        let receipt_path = self.persist_receipt(&digest.to_string(), &receipt)?;

        let inspection = InspectionResult {
            sha256: digest.to_string(),
            size_bytes,
            content_type,
            verdict,
            findings: result.findings,
            artifact_type: format!("{:?}", classification.artifact_type),
            detector_results: result
                .detector_results
                .iter()
                .map(|r| DetectorSummary {
                    id: r.metadata.id.clone(),
                    version: r.metadata.version.clone(),
                    capabilities: r.metadata.capabilities.clone(),
                    is_local: r.metadata.is_local,
                    may_upload: r.metadata.may_upload,
                    is_deterministic: r.metadata.is_deterministic,
                    status: DetectorStatusSummary::from(&r.status),
                    finding_count: r.finding_count,
                })
                .collect(),
            signature_verifications: signature_verifications
                .iter()
                .map(|v| SignatureVerificationSummary {
                    system: v.system.as_str().to_owned(),
                    identity: v.identity.clone(),
                    verified: v.verified,
                })
                .collect(),
            receipt: InspectionResultReceipt { inner: receipt },
            receipt_path: Some(receipt_path),
        };
        Ok((inspection, operation))
    }

    /// Resolves the final verdict for an analysis result.
    ///
    /// Fail-closed first (spec §18.3): any detector failure produces
    /// [`Verdict::Incomplete`] regardless of the configured policy. When a
    /// policy is configured it evaluates the findings in a non-interactive
    /// context; otherwise the built-in derivation applies.
    fn resolve_verdict(
        &self,
        result: &arbitraitor_analysis::AnalysisResult,
    ) -> (Verdict, Vec<String>) {
        if result
            .detector_results
            .iter()
            .any(|r| !matches!(r.status, DetectorStatus::Ok))
        {
            return (
                Verdict::Incomplete,
                vec![
                    "required detector failed or timed out; verdict fail-closed to incomplete"
                        .to_owned(),
                ],
            );
        }
        match &self.policy {
            Some(policy) => {
                let (verdict, trace) =
                    policy.evaluate_with_trace(&result.findings, &EvalContext::new(false));
                (verdict, policy_trace_strings(&trace))
            }
            None => (result.verdict, vec![BUILTIN_VERDICT_TRACE.to_owned()]),
        }
    }

    /// Builds and persists a receipt as a JSON file in the receipts directory.
    fn persist_receipt(&self, sha256: &str, receipt: &Receipt) -> Result<PathBuf, EngineError> {
        let path = self.receipts_dir.join(format!("{sha256}.json"));
        let json = serde_json::to_vec_pretty(receipt)
            .map_err(|error| EngineError::Receipt(error.to_string()))?;
        std::fs::write(&path, json)?;
        Ok(path)
    }

    /// Looks up the policy verdict recorded in the persisted receipt for the
    /// given artifact digest. Release is denied when no receipt exists,
    /// proving the artifact was never analyzed through the inspection
    /// pipeline.
    fn lookup_verdict_for_release(&self, sha256: &str) -> Result<Verdict, EngineError> {
        let path = self.receipts_dir.join(format!("{sha256}.json"));
        if !path.is_file() {
            return Err(EngineError::NoReceipt(sha256.to_owned()));
        }
        let data = std::fs::read(&path)?;
        let receipt: Receipt = serde_json::from_slice(&data)
            .map_err(|error| EngineError::Receipt(format!("{}: {error}", path.display())))?;
        Ok(receipt.verdict.verdict)
    }
}

/// Reconstructs a pipeline operation in `AwaitingApproval` for a stored
/// verdict, driving the §38.3 graph from creation through evaluation.
///
/// The persisted receipt is the authoritative record of the evaluation; the
/// reconstruction replays the stage transitions so `approve`/`release`
/// enforce the graph's blocking-verdict and release-prohibition checks on
/// every release, including across process restarts.
pub(crate) fn reconstruct_operation(
    digest: &Sha256Digest,
    verdict: Verdict,
) -> Result<PipelineOperation, EngineError> {
    let operation = PipelineOperation::new(OperationId::new(), ArtifactId(digest.clone()))
        .transition_to(PipelineState::Retrieving)?
        .transition_to(PipelineState::Stored)?
        .transition_to(PipelineState::Identified)?
        .transition_to(PipelineState::Analyzing)?
        .transition_to(PipelineState::Expanding)?
        .transition_to(PipelineState::Evaluating)?
        .record_verdict(verdict)?;
    Ok(operation)
}

/// Maps a state-machine rejection on the approval edge to the public
/// policy-blocked error carrying the recorded verdict.
fn policy_blocked(error: &StateError, verdict: Verdict) -> EngineError {
    match error.kind {
        StateErrorKind::BlockingVerdict => EngineError::PolicyBlocked(verdict),
        _ => EngineError::State(error.to_string()),
    }
}

/// Renders a policy trace as receipt-safe strings.
fn policy_trace_strings(trace: &PolicyTrace) -> Vec<String> {
    let mut entries: Vec<String> = trace
        .rules_evaluated
        .iter()
        .map(
            |RuleEvaluation {
                 rule_id,
                 matched,
                 reason,
             }| format!("rule {rule_id}: matched={matched} ({reason})"),
        )
        .collect();
    entries.push(format!(
        "final_decision={:?} default_action={:?}",
        trace.final_decision, trace.default_action
    ));
    entries
}

/// Builds a synthetic fetch receipt for receipt assembly on paths that did
/// not retrieve over a transport (stored-artifact and local-file scans).
fn synthetic_fetch_receipt(digest: &Sha256Digest, size: u64) -> arbitraitor_fetch::FetchReceipt {
    arbitraitor_fetch::FetchReceipt {
        artifact_id: ArtifactId(digest.clone()),
        sha256: digest.clone(),
        bytes_written: size,
        metadata: arbitraitor_fetch::FetchMetadata::default(),
        child_artifacts: Vec::new(),
    }
}

/// Reads a local file with an explicit size bound, rejecting symlinks and
/// non-regular files.
fn read_bounded(path: &Path, max_bytes: u64) -> Result<(Vec<u8>, Sha256Digest), EngineError> {
    use std::io::Read as _;
    let metadata = std::fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            EngineError::Config("path not found".to_owned())
        } else {
            EngineError::Io(source)
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(EngineError::Config(
            "scan path is a symlink, which is rejected".to_owned(),
        ));
    }
    if !metadata.is_file() {
        return Err(EngineError::Config(
            "scan path is not a regular file".to_owned(),
        ));
    }
    let size = metadata.len();
    if size > max_bytes {
        return Err(EngineError::Config(format!(
            "scan size exceeded: attempted {size} bytes, maximum {max_bytes} bytes"
        )));
    }
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes.extend_from_slice(&buffer[..read]);
    }
    let digest = Sha256Digest::new(hasher.finalize().into());
    Ok((bytes, digest))
}

fn parse_digest(sha256: &str) -> Result<Sha256Digest, EngineError> {
    Sha256Digest::from_str(sha256)
        .map_err(|_| EngineError::NotFound(format!("invalid sha256 digest: {sha256}")))
}

fn not_found_if_missing(
    sha256: &str,
) -> impl Fn(arbitraitor_store::StoreError) -> EngineError + '_ {
    move |error| match error {
        arbitraitor_store::StoreError::NotFound { .. } => EngineError::NotFound(sha256.to_owned()),
        other => EngineError::Store(other.to_string()),
    }
}
