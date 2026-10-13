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
use std::fmt::Write as _;

use crate::pipeline::{
    ReceiptInput, analysis_retrieval_info, build_receipt, default_cas_dir, default_receipts_dir,
    discover_and_store_children, parse_fetch_source, read_stored_bytes, receipt_timestamp_seconds,
};
use crate::signatures::SignatureInputs;
use crate::{EngineError, FetchFailureKind, FetchTransportError};

mod builder;

pub use builder::{Arbitraitor, ArbitraitorBuilder};

/// Converts a fetch-layer error into an [`EngineError`], preserving the
/// curl-mappable failure class when one exists (HTTP error status, DNS,
/// connection refused, timeout, TLS certificate) so tool-emulating callers
/// can produce the real tool's exit code instead of parsing diagnostics.
fn classify_fetch_error(error: &arbitraitor_fetch::FetchError) -> EngineError {
    match FetchFailureKind::classify(error) {
        Some(kind) => EngineError::FetchTransport(FetchTransportError {
            kind,
            message: error.to_string(),
        }),
        None => EngineError::Fetch(error.to_string()),
    }
}

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
/// interface. Instances are cheap to clone internally (the per-operation
/// store handle and the coordinator are behind `Arc`) and safe to share
/// across tasks via `&self`.
#[derive(Clone)]
pub struct ArbitraitorApi {
    store: StoreHandle,
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

/// Operation-scoped access to the content store behind an API instance.
///
/// redb's metadata index takes a whole-file lock, so a store held open for
/// the lifetime of a long-lived surface (MCP stdio server, daemon) would
/// make the CAS root unusable for every other process. Instead, the handle
/// opens the [`ContentStore`] inside [`Self::with_store`] and **drops** it
/// when the operation ends: the file lock is acquired per operation and
/// released by the drop. Idle surfaces hold no lock, so a CLI fetch can
/// always open the same store. redb opens at millisecond scale, which is
/// acceptable at agent-frequency call rates (#762).
#[derive(Clone)]
struct StoreHandle {
    path: PathBuf,
}

impl StoreHandle {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Runs `f` with a freshly opened store, dropping it when `f` returns.
    ///
    /// The store (and with it the redb whole-file lock) is closed when this
    /// method returns — including on the error path — so no lock survives
    /// an idle period between requests. The closure keeps its native error
    /// type (`E`); the caller converts store-level errors (`From<
    /// StoreError>`) at the single site that knows the user-facing
    /// semantics, so no foreign error is re-wrapped into a misleading
    /// `StoreError::Index`.
    fn with_store<T, E>(
        &self,
        f: impl FnOnce(&arbitraitor_store::ContentStore) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<arbitraitor_store::StoreError>,
    {
        let store = arbitraitor_store::ContentStore::open(&self.path)?;
        let result = f(&store);
        drop(store);
        result
    }
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

/// Outcome of [`ArbitraitorApi::http_egress`] (spec §11.6).
///
/// The bounded body is returned to the calling tool; it is not an artifact
/// and carries no artifact identity. `body_returned == false` means the
/// body was withheld (an `inspect_first` grant with a non-passing verdict,
/// or a bound hit after connect).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressResult {
    /// Grant the request executed under.
    pub grant_id: String,
    /// HTTP response status.
    pub status: u16,
    /// Response media type as received.
    pub content_type: String,
    /// Bounded response body (empty when `body_returned` is false).
    pub body: Vec<u8>,
    /// Whether the body was delivered to the caller.
    pub body_returned: bool,
    /// Body treatment in force: `unscanned` or `inspect_first`.
    pub body_treatment: String,
    /// Final URL after redirects (unredacted; the receipt is redacted).
    pub final_url: String,
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

        let stored = self.store.with_store(|store| {
            store.store_with_metadata_and_limits(
                bytes.clone(),
                Some(redact_url(source)),
                fetch_receipt.metadata.content_type.clone(),
                arbitraitor_store::RetentionMode::Cache,
                self.store_max_bytes,
            )
        })?;
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
            true,
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
        self.store.with_store(|store| -> Result<(), EngineError> {
            store.store_with_metadata_and_limits(
                bytes.clone(),
                Some(redact_url(url)),
                content_type.clone(),
                arbitraitor_store::RetentionMode::Cache,
                self.store_max_bytes,
            )?;
            discover_and_store_children(store, &bytes, self.store_max_bytes).map(|_| ())
        })?;
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
        let (bytes, entry) = self
            .store
            .with_store(|store| -> Result<_, arbitraitor_store::StoreError> {
                store.get(&digest)?;
                let bytes = read_stored_bytes(store, &digest)?;
                let entry = store.metadata_index().get(sha256)?;
                Ok((bytes, entry))
            })
            .map_err(not_found_if_missing(sha256))?;
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
            true,
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
        self.store.with_store(|store| {
            store.store_with_metadata_and_limits(
                bytes.clone(),
                Some(path.to_string_lossy().into_owned()),
                None,
                arbitraitor_store::RetentionMode::Cache,
                self.store_max_bytes,
            )
        })?;
        let (inspection, _operation) = self.analyze_and_finalize(
            operation,
            &bytes,
            &digest,
            &path.to_string_lossy(),
            None,
            None,
            true,
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
        self.store
            .with_store(|store| read_stored_bytes(store, &digest))
            .map_err(not_found_if_missing(sha256))
    }

    /// Executes a mediated HTTP egress request (spec §11.6, ADR-0041).
    ///
    /// The request is authorized against the policy's egress grants before
    /// any transport activity; the bounded body is returned to the caller
    /// without entering the CAS. One egress receipt is persisted per
    /// request, keyed by a digest of the request identity (grant id + URL +
    /// nonce), never colliding with artifact receipts.
    ///
    /// `caller_origin` must be the peer-credential-derived §23.1.1 class
    /// (typed — never a wire-supplied freeform string); the daemon/MCP
    /// derives it from transport authentication. Policy denies listed
    /// origin classes (`network.egress.deny_origins`) before grant
    /// evaluation.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::EgressDenied`] when the origin class is
    /// denied by policy or no grant authorizes the request,
    /// [`EngineError::EgressPolicy`] when the policy carries no compiled
    /// egress section, and [`EngineError::Fetch`] for transport boundaries
    /// after authorization.
    pub async fn http_egress(
        &self,
        url: &str,
        caller_origin: &arbitraitor_model::origin::CallerOrigin,
    ) -> Result<EgressResult, EngineError> {
        // Parse and authorize against the compiled policy's egress grants.
        let policy = self.policy.as_ref().ok_or_else(|| {
            EngineError::EgressPolicy(
                "no policy loaded; egress requires compiled policy".to_owned(),
            )
        })?;
        let egress_config = &policy.policy().network.egress;
        // §11.6 caller-origin binding: deny listed low-trust origin classes
        // before grant evaluation. The class arrives as the peer-derived
        // §23.1.1 label from the daemon/MCP layer, never wire-trusted.
        if egress_config
            .deny_origins
            .iter()
            .any(|d| d.eq_ignore_ascii_case(caller_origin.as_str()))
        {
            return Err(EngineError::EgressDenied(format!(
                "caller origin '{}' is denied for egress by policy",
                caller_origin.as_str()
            )));
        }
        let parsed_url = url::Url::parse(url)
            .map_err(|_| EngineError::EgressDenied("unparseable URL".to_owned()))?;
        let host = parsed_url
            .host_str()
            .ok_or_else(|| EngineError::EgressDenied("URL has no host".to_owned()))?
            .to_lowercase();
        let path = parsed_url.path();
        let grant = egress_config.matching_grant(&host, path).ok_or_else(|| {
            EngineError::EgressDenied("no egress grant matches host/path".to_owned())
        })?;

        // Map the policy grant onto the fetch-layer grant view.
        let fetch_grant = fetch_grant_view(grant);

        let timeouts = arbitraitor_fetch::EgressTimeouts {
            connect: self.fetch_policy.connect_timeout,
            read: self.fetch_policy.read_timeout,
            total: self.fetch_policy.total_timeout,
        };
        let executor = arbitraitor_fetch::EgressExecutor::new();
        let response = executor
            .execute(&fetch_grant, url, &timeouts)
            .await
            .map_err(|e| match e {
                arbitraitor_fetch::EgressError::OutsideGrant { .. }
                | arbitraitor_fetch::EgressError::QueryPolicy { .. }
                | arbitraitor_fetch::EgressError::UserinfoCredentials
                | arbitraitor_fetch::EgressError::NoGrant => {
                    EngineError::EgressDenied(e.to_string())
                }
                other => EngineError::Fetch(other.to_string()),
            })?;

        // §11.6 inspect_first: the body flows through the inspection
        // pipeline before delivery. The body is scanned in-memory through
        // the same analyze tail as `scan_path` (bounded by the grant); only
        // a passing verdict releases it. This is the sole path where egress
        // produces a verdict about the body (spec §11.6 non-goals
        // exception).
        let (body_outcome, delivered_bytes, final_body) =
            self.resolve_egress_body_outcome(&fetch_grant, &response, url)?;

        // Persist the egress receipt: keyed by grant+url+nonce digest so it
        // never collides with an artifact receipt.
        let receipt_key = egress_receipt_key(&response.grant_id, url);
        let egress_info = arbitraitor_receipt::EgressInfo {
            grant_id: response.grant_id.clone(),
            caller_origin: caller_origin.as_str().to_owned(),
            requested_url: redact_egress_url(url, egress_config),
            final_url: Some(redact_egress_url(&response.final_url, egress_config)),
            redirect_chain: response
                .redirect_chain
                .iter()
                .map(|u| redact_egress_url(u, egress_config))
                .collect(),
            status: Some(response.status),
            content_type: Some(response.content_type.clone()),
            query_policy: query_policy_name(grant.query_policy).to_owned(),
            body_outcome: body_outcome.to_owned(),
            delivered_bytes,
        };
        self.persist_egress_receipt(&receipt_key, egress_info)?;

        let body_returned = final_body.is_some();
        Ok(EgressResult {
            grant_id: response.grant_id,
            status: response.status,
            content_type: response.content_type,
            body: final_body.unwrap_or_default(),
            body_returned,
            body_treatment: match fetch_grant.body_treatment {
                arbitraitor_fetch::EgressBodyTreatment::Unscanned => "unscanned".to_owned(),
                arbitraitor_fetch::EgressBodyTreatment::InspectFirst => "inspect_first".to_owned(),
            },
            final_url: response.final_url,
        })
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
        let receipt = self.store.with_store(|store| {
            arbitraitor_exec::release::release_artifact(
                store,
                &digest,
                dest,
                &arbitraitor_exec::release::ReleasePolicy::default(),
            )
            .map_err(|error| EngineError::Release(error.to_string()))
        })?;
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
        let entries = self
            .store
            .with_store(|store| store.metadata_index().list())?;
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
            FetchSource::Url(_) => self
                .fetcher
                .fetch(request, &mut sink)
                .await
                .map_err(|error| classify_fetch_error(&error))?,
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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn analyze_and_finalize(
        &self,
        operation: PipelineOperation,
        bytes: &[u8],
        digest: &Sha256Digest,
        requested_source: &str,
        fetch_receipt: Option<&arbitraitor_fetch::FetchReceipt>,
        content_type: Option<String>,
        store_children: bool,
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

        // §11.6 inspect_first: child discovery is suppressed for egress
        // bodies (ADR-0041 "without CAS population" — extracted children
        // must not persist in the queryable store; the body itself is never
        // CAS-stored). Artifact-path callers keep the expansion stage.
        if store_children {
            self.store.with_store(|store| {
                discover_and_store_children(store, bytes, self.store_max_bytes)
            })?;
        }
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
        // Gen-3 M1 (defense in depth): an egress-class receipt must never
        // authorize release even if one ever lands in the artifact
        // namespace. The namespace move in inspect_egress_body keeps them
        // out; this guard holds the invariant independently.
        if receipt.policy.operation_class.as_deref() == Some("egress") {
            return Err(EngineError::NoReceipt(sha256.to_owned()));
        }
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

/// Maps a policy egress grant onto the fetch-layer grant view.
fn fetch_grant_view(grant: &arbitraitor_policy::EgressGrant) -> arbitraitor_fetch::EgressGrant {
    arbitraitor_fetch::EgressGrant {
        id: grant.id.clone(),
        hosts: grant.hosts.clone(),
        path_prefix: grant.path_prefix.clone(),
        query_policy: match grant.query_policy {
            arbitraitor_policy::EgressQueryPolicy::Forbidden => {
                arbitraitor_fetch::EgressQueryPolicy::Forbidden
            }
            arbitraitor_policy::EgressQueryPolicy::Pinned => {
                arbitraitor_fetch::EgressQueryPolicy::Pinned
            }
            arbitraitor_policy::EgressQueryPolicy::Bounded => {
                arbitraitor_fetch::EgressQueryPolicy::Bounded
            }
            arbitraitor_policy::EgressQueryPolicy::Allowed => {
                arbitraitor_fetch::EgressQueryPolicy::Allowed
            }
        },
        pinned_query: grant.pinned_query.clone(),
        max_query_bytes: grant.max_query_bytes,
        max_query_params: grant.max_query_params,
        max_response_bytes: grant.max_response_bytes,
        allowed_content_types: grant.allowed_content_types.clone(),
        body_treatment: match grant.body_treatment {
            arbitraitor_policy::EgressBodyTreatment::Unscanned => {
                arbitraitor_fetch::EgressBodyTreatment::Unscanned
            }
            arbitraitor_policy::EgressBodyTreatment::InspectFirst => {
                arbitraitor_fetch::EgressBodyTreatment::InspectFirst
            }
        },
    }
}

/// Stable receipt key for an egress request: SHA-256 over
/// `egress/<grant>/<url>/<unix-millis nonce>`. Never collides with an
/// artifact receipt (those are keyed by the artifact digest).
fn egress_receipt_key(grant_id: &str, url: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    // Per-process monotonic counter + nanosecond timestamp: two calls in
    // the same millisecond (the gen-4 LOW-1 collision) can no longer share
    // a key — the counter alone disambiguates same-process calls, and the
    // nanos cover cross-process restarts within a millisecond.
    static CALL_COUNTER: AtomicU64 = AtomicU64::new(0);
    let call = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let digest = Sha256::digest(format!("egress/{grant_id}/{url}/{nonce}/{call}").as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// §11.6 receipt URL redaction: credential-class only. Implements the
/// full §11.6 rule set:
///
/// - userinfo password → class marker (username may be functional);
/// - credential-bearing query parameters (policy denylist + built-ins)
///   are replaced by their class;
/// - **credential value-shape rules**: a query value matching neither the
///   name denylist nor a non-credential shape is redacted when it is
///   (a) a high-entropy opaque token (≥24 chars from `[A-Za-z0-9_-]` with
///   at least one digit, one letter, and mixed case), (b) JWT-shaped
///   (three dot-separated base64url segments), or (c) UUID-shaped in a
///   credential-position parameter (name contains `id`/`token`/`key` or
///   is denylisted);
/// - **unmatched-query fallback (fail-closed)**: a query value matching
///   neither the denylist nor the value shapes and not establishable as
///   non-credential (pure digits, ≤8 chars, or a well-known non-secret
///   parameter name) is redacted to `[REDACTED-UNESTABLISHABLE]`;
/// - **path-segment secret-pattern denylist**: any path segment that is
///   ≥32 chars of hex/base64url or a JWT segment is replaced by
///   `[REDACTED-PATH-SEGMENT]`.
///
/// All other query and path content is preserved verbatim (§11.5's
/// blanket "secrets removed" rule is narrowed for this operation class).
/// The fail-the-request clause for unredactable values cannot fire here:
/// URL components are strings and therefore always redactable — the
/// fail-closed path is exercised by callers handling non-string values,
/// which must fail the request rather than record the value.
///
/// Applies to the requested URL, final URL, and redirect chain (the
/// receipt builder calls this per URL).
pub(crate) fn redact_egress_url(value: &str, egress: &arbitraitor_policy::EgressConfig) -> String {
    let Ok(mut parsed) = url::Url::parse(value) else {
        return arbitraitor_receipt::redact_url(value);
    };
    // Userinfo password → class marker (username may be functional).
    if parsed.password().is_some() {
        let _ = parsed.set_password(Some("[REDACTED-PASSWORD]"));
    }
    // Path-segment secret-pattern denylist (§11.6).
    let segments: Vec<String> = parsed
        .path_segments()
        .map(|segs| segs.map(redact_path_segment).collect())
        .unwrap_or_default();
    if !segments.is_empty() {
        parsed.set_path(&format!("/{}", segments.join("/")));
    }
    if let Some(query) = parsed.query() {
        let deny = |name: &str| {
            BUILTIN_CREDENTIAL_QUERY_PARAMS
                .iter()
                .copied()
                .chain(egress.credential_query_params.iter().map(String::as_str))
                .any(|d| d.eq_ignore_ascii_case(name))
        };
        let redacted: Vec<String> = query
            .split('&')
            .map(|pair| {
                let (name, sep_value) = pair.split_once('=').map_or((pair, ""), |(n, v)| (n, v));
                if sep_value.is_empty() {
                    return name.to_owned();
                }
                if deny(name) {
                    return format!("{name}=[REDACTED-CREDENTIAL]");
                }
                if is_high_entropy_token(sep_value)
                    || is_jwt_shaped(sep_value)
                    || (is_uuid_shaped(sep_value) && is_credential_position(name, &deny))
                {
                    return format!("{name}=[REDACTED-CREDENTIAL]");
                }
                if !is_established_non_credential(name, sep_value) {
                    return format!("{name}=[REDACTED-UNESTABLISHABLE]");
                }
                pair.to_owned()
            })
            .collect();
        parsed.set_query(Some(&redacted.join("&")));
    }
    parsed.to_string()
}

/// High-entropy opaque token: ≥24 chars from `[A-Za-z0-9_-]` with at
/// least one digit, one letter, and mixed upper/lower case.
fn is_high_entropy_token(value: &str) -> bool {
    if value.len() < 24
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return false;
    }
    let has_digit = value.bytes().any(|b| b.is_ascii_digit());
    let has_lower = value.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = value.bytes().any(|b| b.is_ascii_uppercase());
    has_digit && has_lower && has_upper
}

/// JWT shape: exactly three dot-separated base64url segments, each at
/// least 8 chars of `[A-Za-z0-9_-]`.
fn is_jwt_shaped(value: &str) -> bool {
    let segments: Vec<&str> = value.split('.').collect();
    segments.len() == 3
        && segments.iter().all(|s| {
            s.len() >= 8
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

/// UUID shape: 8-4-4-4-12 hex digits.
fn is_uuid_shaped(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    let widths = [8, 4, 4, 4, 12];
    groups.len() == 5
        && groups
            .iter()
            .zip(widths)
            .all(|(g, w)| g.len() == w && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A parameter is in a credential position when its name contains
/// `id`, `token`, or `key`, or it is on the denylist.
fn is_credential_position(name: &str, deny: &impl Fn(&str) -> bool) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("id") || lower.contains("token") || lower.contains("key") || deny(name)
}

/// Well-known non-secret parameter names (lowercase compare).
const NON_CREDENTIAL_QUERY_PARAMS: &[&str] = &[
    "q", "query", "search", "page", "limit", "offset", "sort", "order", "lang", "locale", "format",
    "version", "v", "callback", "fields", "include", "type", "kind", "category", "tag", "tags",
    "filter", "from", "to", "since", "until", "count", "size", "cursor",
];

/// Establishes a query value as non-credential: pure digits, short
/// (≤8 chars), or a well-known non-secret parameter name. Values that
/// match neither this, the denylist, nor the value shapes are
/// unestablishable and fail closed (redacted).
fn is_established_non_credential(name: &str, value: &str) -> bool {
    if value.bytes().all(|b| b.is_ascii_digit()) || value.len() <= 8 {
        return true;
    }
    NON_CREDENTIAL_QUERY_PARAMS
        .iter()
        .any(|p| *p == name.to_ascii_lowercase())
}

/// Path-segment secret-pattern denylist: a segment of ≥32 hex/base64url
/// characters, or a JWT segment (three dot-separated base64url parts),
/// is replaced by its class.
fn redact_path_segment(segment: &str) -> String {
    if is_jwt_shaped(segment)
        || (segment.len() >= 32
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    {
        return "[REDACTED-PATH-SEGMENT]".to_owned();
    }
    segment.to_owned()
}

/// Built-in credential query-parameter names (mirrors the policy crate's
/// egress denylist; the policy value extends this set).
const BUILTIN_CREDENTIAL_QUERY_PARAMS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "access_token",
    "token",
    "auth",
    "key",
    "secret",
    "password",
    "passwd",
    "sig",
    "signature",
    "credential",
    "credentials",
    "session",
    "sid",
    "sessionid",
];

/// Human-readable name of a query policy for the receipt.
fn query_policy_name(policy: arbitraitor_policy::EgressQueryPolicy) -> &'static str {
    match policy {
        arbitraitor_policy::EgressQueryPolicy::Forbidden => "forbidden",
        arbitraitor_policy::EgressQueryPolicy::Pinned => "pinned",
        arbitraitor_policy::EgressQueryPolicy::Bounded => "bounded",
        arbitraitor_policy::EgressQueryPolicy::Allowed => "allowed",
    }
}

/// Resolved §11.6 body outcome: outcome label, delivered byte count, and
/// the body actually returned to the caller (`None` = withheld).
type EgressBodyOutcome = (&'static str, Option<u64>, Option<Vec<u8>>);

impl ArbitraitorApi {
    /// Resolves the §11.6 body outcome for an egress response.
    ///
    /// `inspect_first` grants gate delivery on the inspection verdict: a
    /// non-releasable verdict (`Incomplete`/`Block`/`Error`) withholds the
    /// body entirely; `Pass` delivers unmodified; `Warn` delivers with the
    /// verdict recorded on the inspection receipt (ADR-0013 semantics:
    /// warn is release-permitted-with-warning). `unscanned` grants deliver
    /// exactly what the transport bounded.
    fn resolve_egress_body_outcome(
        &self,
        fetch_grant: &arbitraitor_fetch::EgressGrant,
        response: &arbitraitor_fetch::EgressResponse,
        url: &str,
    ) -> Result<EgressBodyOutcome, EngineError> {
        match fetch_grant.body_treatment {
            arbitraitor_fetch::EgressBodyTreatment::InspectFirst => {
                let (inspection, _op) =
                    self.inspect_egress_body(&response.body, &response.content_type, url)?;
                if matches!(inspection.verdict, Verdict::Pass | Verdict::Warn) {
                    Ok((
                        "returned_inspected",
                        u64::try_from(response.body.len()).ok(),
                        Some(response.body.clone()),
                    ))
                } else {
                    Ok(("withheld", None, None))
                }
            }
            arbitraitor_fetch::EgressBodyTreatment::Unscanned => {
                if response.delivered {
                    Ok((
                        "returned_unscanned",
                        u64::try_from(response.body.len()).ok(),
                        Some(response.body.clone()),
                    ))
                } else {
                    // Unreachable while the transport fails closed on size
                    // (http_error_status_is_failure), but the label must
                    // not claim "returned" for a withheld body.
                    Ok(("withheld", None, None))
                }
            }
        }
    }

    /// Test-only passthrough to the real §11.6 body-outcome gate.
    #[doc(hidden)]
    #[cfg(test)]
    pub(crate) fn resolve_egress_body_outcome_for_test(
        &self,
        fetch_grant: &arbitraitor_fetch::EgressGrant,
        response: &arbitraitor_fetch::EgressResponse,
        url: &str,
    ) -> Result<EgressBodyOutcome, EngineError> {
        self.resolve_egress_body_outcome(fetch_grant, response, url)
    }

    /// §11.6 `inspect_first` body path: run the egress body through the
    /// inspection pipeline in-memory (no CAS write) and return the
    /// inspection result whose verdict gates delivery.
    fn inspect_egress_body(
        &self,
        body: &[u8],
        content_type: &str,
        source_url: &str,
    ) -> Result<(InspectionResult, PipelineOperation), EngineError> {
        let digest = Sha256Digest::new(Sha256::digest(body).into());
        let mut operation = PipelineOperation::new(OperationId::new(), ArtifactId(digest.clone()));
        operation = operation
            .transition_to(PipelineState::Retrieving)?
            .transition_to(PipelineState::Stored)?;
        let content_type = if content_type.is_empty() {
            None
        } else {
            Some(content_type.to_owned())
        };
        let (inspection, operation) = self.analyze_and_finalize(
            operation,
            body,
            &digest,
            source_url,
            Some(&synthetic_fetch_receipt(&digest, body.len() as u64)),
            content_type,
            false,
        )?;
        // The inspection receipt was persisted at the artifact-key path
        // ({sha256}.json) by analyze_and_finalize — the same namespace
        // lookup_verdict_for_release reads. Move it into the egress
        // namespace so it can never clobber an artifact receipt at the
        // same digest (gen-3 M1: an artifact re-served through an
        // inspect_first grant would otherwise replace the artifact's
        // verdict/findings/audit trail), and tag it operation_class =
        // 'egress' so audit consumers see the dual-receipt shape.
        let artifact_key_path = self
            .receipts_dir
            .join(format!("{}.json", inspection.sha256));
        let egress_key_path = self.receipts_dir.join(format!("egress-body-{digest}.json"));
        let mut tagged = None;
        if let Ok(data) = std::fs::read(&artifact_key_path)
            && let Ok(mut receipt) = serde_json::from_slice::<arbitraitor_receipt::Receipt>(&data)
        {
            receipt.policy.operation_class = Some("egress".to_owned());
            tagged = serde_json::to_vec_pretty(&receipt).ok();
        }
        match tagged {
            Some(json) => {
                // Write-to-temp + atomic rename (gen-4 LOW-2): a crash can
                // no longer leave an untagged receipt at the artifact key.
                // The temp file lives beside the destination (same
                // filesystem, atomic rename guarantee) with a unique name.
                let temp_path = self
                    .receipts_dir
                    .join(format!(".egress-body-tmp-{digest}-{}", std::process::id()));
                std::fs::write(&temp_path, json)
                    .map_err(|error| EngineError::Receipt(error.to_string()))?;
                std::fs::rename(&temp_path, &egress_key_path)
                    .map_err(|error| EngineError::Receipt(error.to_string()))?;
                // The artifact-namespace copy must not survive: leaving it
                // would reintroduce the clobber on the next lookup. Remove
                // only after the rename has landed.
                std::fs::remove_file(&artifact_key_path)
                    .map_err(|error| EngineError::Receipt(error.to_string()))?;
            }
            // Tagging failed (read/parse/serialize): fail loudly rather
            // than leave an untagged artifact-namespace receipt (gen-3 L3
            // — silent swallow was the original defect).
            None => {
                return Err(EngineError::Receipt(
                    "egress inspection receipt could not be read for egress tagging".to_owned(),
                ));
            }
        }
        Ok((inspection, operation))
    }

    /// Persists an egress receipt under its request-identity key.
    fn persist_egress_receipt(
        &self,
        receipt_key: &str,
        egress: arbitraitor_receipt::EgressInfo,
    ) -> Result<PathBuf, EngineError> {
        let now = crate::pipeline::receipt_timestamp();
        let receipt = arbitraitor_receipt::Receipt {
            schema_version: arbitraitor_receipt::CURRENT_SCHEMA_VERSION,
            request: arbitraitor_receipt::RequestInfo {
                arbitraitor_version: env!("CARGO_PKG_VERSION").to_owned(),
                config_digest: None,
            },
            artifact: arbitraitor_receipt::ArtifactInfo {
                sha256: receipt_key.to_owned(),
                size: egress.delivered_bytes.unwrap_or(0),
                artifact_type: Some("egress".to_owned()),
            },
            retrieval: None,
            egress: Some(egress),
            provenance: arbitraitor_receipt::ProvenanceInfo::default(),
            payload_graph: None,
            detectors: Vec::new(),
            findings: Vec::new(),
            policy: arbitraitor_receipt::PolicyInfo {
                policy_digest: None,
                operation_class: Some("egress".to_owned()),
                allow_rule_metadata: Vec::new(),
                audit_trail: Vec::new(),
            },
            verdict: arbitraitor_receipt::VerdictInfo {
                verdict: arbitraitor_model::verdict::Verdict::Pass,
                deciding_rule: None,
                policy_trace: vec!["egress operation: no artifact verdict (spec §11.6)".to_owned()],
            },
            release: None,
            timestamps: arbitraitor_receipt::ReceiptTimestamps {
                created: now.clone(),
                modified: now,
            },
        };
        let path = self.receipts_dir.join(format!("{receipt_key}.json"));
        let json = serde_json::to_vec_pretty(&receipt)
            .map_err(|error| EngineError::Receipt(error.to_string()))?;
        std::fs::write(&path, json)?;
        Ok(path)
    }
}
