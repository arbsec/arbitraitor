//! Programmatic API for Arbitraitor operations.
//!
//! This is the in-process equivalent of the daemon's socket protocol.
//! Consumers using Arbitraitor as a Rust dependency call [`ArbitraitorApi`]
//! instead of connecting to a Unix socket. All existing subsystems (fetcher,
//! store, analysis coordinator, policy engine, receipt builder) are composed
//! internally; no daemon process is required.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use arbitraitor_analysis::{AnalysisCoordinator, RetrievalInfo};
use arbitraitor_fetch::{
    FetchError, FetchPolicy, FetchRequest, FetchUrl, Fetcher, HttpFetcher, VecSink, redact_url,
};
use arbitraitor_model::finding::Finding;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::Verdict;
use arbitraitor_policy::{EvalContext, PolicyEngine};
use arbitraitor_receipt::{
    FindingSummary, Receipt, ReceiptBuilder, ReceiptTimestamps, RetrievalInfo as ReceiptRetrieval,
    VerdictInfo,
};
use arbitraitor_store::{ContentStore, MetadataEntry, RetentionMode};
use sha2::{Digest, Sha256};
use thiserror::Error;

const ARBITRAITOR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Minimal policy TOML used when no explicit policy is provided.
const DEFAULT_POLICY_TOML: &str = "\
version = 1\n\
[defaults]\n\
action = \"prompt\"\n\
non_interactive_prompt_action = \"block\"\n\
";

/// Programmatic API for Arbitraitor operations.
///
/// Composes fetcher, content store, analysis coordinator, policy engine,
/// and receipt builder into a single in-process interface. Instances are
/// cheap to clone internally (the store is backed by `Arc`) and safe to
/// share across tasks via `&self`.
pub struct ArbitraitorApi {
    store: ContentStore,
    fetcher: HttpFetcher,
    policy: PolicyEngine,
    coordinator: AnalysisCoordinator,
    fetch_policy: FetchPolicy,
    receipts_dir: PathBuf,
}

/// Tunable construction options for [`ArbitraitorApi`].
#[derive(Clone, Debug)]
pub struct Config {
    /// CAS root directory for content-addressed storage.
    pub store_path: PathBuf,
    /// Directory where inspection receipts are persisted as JSON files.
    pub receipts_path: PathBuf,
    /// Fetch policy controlling timeouts, schemes, and size limits.
    pub fetch_policy: FetchPolicy,
    /// Policy TOML for verdict evaluation. An empty string selects a
    /// safe default that prompts on every artifact.
    pub policy_toml: String,
}

/// Outcome of an [`ArbitraitorApi::inspect`] or [`ArbitraitorApi::scan`] call.
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
    pub findings: Vec<Finding>,
    /// Path to the persisted receipt JSON, when one was written.
    pub receipt_path: Option<PathBuf>,
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
}

/// Outcome of [`ArbitraitorApi::release`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseResult {
    /// Destination path where bytes were written.
    pub path: PathBuf,
    /// Whether the SHA-256 was re-verified immediately before writing.
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

/// Errors returned by the programmatic API.
#[derive(Debug, Error)]
pub enum ApiError {
    /// A retrieval or transport failure occurred.
    #[error("fetch failed: {0}")]
    Fetch(String),
    /// The referenced artifact digest is not present in the store.
    #[error("artifact not found: {0}")]
    NotFound(String),
    /// The store reported an error.
    #[error("store error: {0}")]
    Store(#[from] arbitraitor_store::StoreError),
    /// Configuration or policy compilation failed.
    #[error("config error: {0}")]
    Config(String),
    /// A receipt serialization or deserialization error occurred.
    #[error("receipt error: {0}")]
    Receipt(String),
    /// An I/O error occurred.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<FetchError> for ApiError {
    fn from(error: FetchError) -> Self {
        Self::Fetch(error.to_string())
    }
}

struct ReceiptInput<'a> {
    sha256: &'a str,
    size: u64,
    content_type: Option<&'a str>,
    final_url: Option<&'a str>,
    requested_url: &'a str,
    verdict: Verdict,
    findings: &'a [Finding],
}

impl ArbitraitorApi {
    /// Creates a new API instance from the supplied [`Config`].
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Store`] if the content store cannot be opened,
    /// or [`ApiError::Config`] if the policy TOML is invalid.
    pub fn new(config: Config) -> Result<Self, ApiError> {
        let store = ContentStore::open(&config.store_path)?;
        let policy_toml = if config.policy_toml.trim().is_empty() {
            DEFAULT_POLICY_TOML
        } else {
            &config.policy_toml
        };
        let policy =
            PolicyEngine::load(policy_toml).map_err(|error| ApiError::Config(error.to_string()))?;
        std::fs::create_dir_all(&config.receipts_path)?;
        Ok(Self {
            store,
            fetcher: HttpFetcher::new(),
            policy,
            coordinator: AnalysisCoordinator::new(),
            fetch_policy: config.fetch_policy,
            receipts_dir: config.receipts_path,
        })
    }

    /// Fetches a URL, stores the artifact in CAS, runs detectors, evaluates
    /// policy, persists a receipt, and returns findings plus verdict.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Fetch`] on transport failure, [`ApiError::Store`]
    /// on persistence failure, or [`ApiError::Io`] on receipt write failure.
    pub async fn inspect(&self, url: &str) -> Result<InspectionResult, ApiError> {
        let (digest, size, content_type, final_url, bytes) = self.fetch_and_store(url).await?;
        let retrieval = RetrievalInfo {
            requested_location: Some(redact_url(url)),
            final_location: final_url.as_deref().map(redact_url),
            content_type: content_type.clone(),
            byte_count: Some(size),
        };
        let result = self
            .coordinator
            .analyze_with_retrieval(&bytes, Some(retrieval));
        let verdict = self.policy.evaluate(
            &result.findings,
            &EvalContext::new(false).with_source_url(redact_url(url)),
        );
        let sha_hex = digest.to_string();
        let receipt_input = ReceiptInput {
            sha256: &sha_hex,
            size,
            content_type: content_type.as_deref(),
            final_url: final_url.as_deref(),
            requested_url: url,
            verdict,
            findings: &result.findings,
        };
        let receipt_path = self.persist_receipt(&receipt_input)?;
        Ok(InspectionResult {
            sha256: sha_hex,
            size_bytes: size,
            content_type,
            verdict,
            findings: result.findings,
            receipt_path: Some(receipt_path),
        })
    }

    /// Fetches and stores the raw artifact bytes without running analysis.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Fetch`] on transport failure or [`ApiError::Store`]
    /// on persistence failure.
    pub async fn fetch(&self, url: &str) -> Result<FetchResult, ApiError> {
        let (digest, size, _content_type, final_url, _bytes) = self.fetch_and_store(url).await?;
        Ok(FetchResult {
            sha256: digest.to_string(),
            size_bytes: size,
            final_url: final_url.unwrap_or_else(|| url.to_owned()),
        })
    }

    /// Scans an already-stored artifact by SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::NotFound`] when the digest is absent or invalid.
    pub fn scan(&self, sha256: &str) -> Result<InspectionResult, ApiError> {
        let digest = parse_digest(sha256)?;
        let handle = self
            .store
            .get(&digest)
            .map_err(not_found_if_missing(sha256))?;
        let mut reader = handle.read();
        let mut bytes = Vec::with_capacity(usize::try_from(handle.size()).unwrap_or(0));
        reader.read_to_end(&mut bytes)?;
        let entry = self.store.metadata_index().get(sha256)?;
        let retrieval = entry.as_ref().map(|metadata| RetrievalInfo {
            requested_location: metadata.source_url.as_deref().map(redact_url),
            final_location: None,
            content_type: metadata.content_type.clone(),
            byte_count: Some(metadata.size_bytes),
        });
        let result = self.coordinator.analyze_with_retrieval(&bytes, retrieval);
        let verdict = self.policy.evaluate(
            &result.findings,
            &EvalContext::new(false).with_source_url(
                entry
                    .as_ref()
                    .and_then(|m| m.source_url.clone())
                    .unwrap_or_default(),
            ),
        );
        Ok(InspectionResult {
            sha256: handle.digest().to_string(),
            size_bytes: handle.size(),
            content_type: entry.and_then(|m| m.content_type),
            verdict,
            findings: result.findings,
            receipt_path: None,
        })
    }

    /// Releases a stored artifact to `dest`, re-verifying the digest first.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::NotFound`] when the digest is absent, or
    /// [`ApiError::Io`] when the destination cannot be written.
    pub fn release(&self, sha256: &str, dest: &Path) -> Result<ReleaseResult, ApiError> {
        let digest = parse_digest(sha256)?;
        let handle = self
            .store
            .get(&digest)
            .map_err(not_found_if_missing(sha256))?;
        let mut reader = handle.read();
        let mut bytes = Vec::with_capacity(usize::try_from(handle.size()).unwrap_or(0));
        reader.read_to_end(&mut bytes)?;
        let actual = Sha256::digest(&bytes);
        let verified = actual.as_slice() == digest.as_bytes();
        if !verified {
            return Err(ApiError::NotFound(format!(
                "digest verification failed for {sha256}"
            )));
        }
        std::fs::write(dest, &bytes)?;
        Ok(ReleaseResult {
            path: dest.to_path_buf(),
            sha256_verified: true,
        })
    }

    /// Queries persisted receipts, optionally limited and filtered by time.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Receipt`] when a receipt file cannot be parsed.
    pub fn query_receipts(&self, filter: ReceiptFilter) -> Result<Vec<ReceiptSummary>, ApiError> {
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
                .map_err(|error| ApiError::Receipt(format!("{}: {error}", path.display())))?;
            let created_at = receipt.timestamps.created.parse::<u64>().unwrap_or(0);
            if filter.since.is_some_and(|since| created_at < since) {
                continue;
            }
            summaries.push(ReceiptSummary {
                sha256: receipt.artifact_sha256.clone(),
                verdict: receipt.verdict.verdict,
                size_bytes: receipt.artifact_size,
                created_at,
                findings_count: receipt.findings.len(),
            });
        }
        if let Some(limit) = filter.limit {
            summaries.truncate(limit);
        }
        Ok(summaries)
    }

    /// Lists metadata for all stored artifacts.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Store`] when the metadata index cannot be read.
    pub fn list_artifacts(&self) -> Result<Vec<ArtifactSummary>, ApiError> {
        let entries = self.store.metadata_index().list()?;
        Ok(entries
            .into_iter()
            .map(
                |MetadataEntry {
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

    /// Fetches a URL into a `VecSink`, stores the bytes in CAS with metadata,
    /// and returns the digest, size, content type, final URL, and raw bytes.
    async fn fetch_and_store(
        &self,
        url: &str,
    ) -> Result<(Sha256Digest, u64, Option<String>, Option<String>, Vec<u8>), ApiError> {
        let fetch_url = FetchUrl::parse(url)?;
        let request = FetchRequest::url(fetch_url, self.fetch_policy.clone());
        let mut sink = VecSink::new();
        let receipt = self.fetcher.fetch(request, &mut sink).await?;
        let bytes = sink.into_bytes();
        let content_type = receipt.metadata.content_type.clone();
        let final_url = receipt.metadata.final_url.as_ref().map(ToString::to_string);
        let size = receipt.bytes_written;
        let digest = receipt.sha256.clone();
        let source_url = redact_url(url);
        self.store.store_with_metadata(
            bytes.clone(),
            Some(source_url),
            content_type.clone(),
            RetentionMode::Cache,
        )?;
        Ok((digest, size, content_type, final_url, bytes))
    }

    /// Builds and persists a receipt as a JSON file in the receipts directory.
    fn persist_receipt(&self, input: &ReceiptInput<'_>) -> Result<PathBuf, ApiError> {
        let now = epoch_string();
        let timestamps = ReceiptTimestamps {
            created: now.clone(),
            modified: now,
        };
        let verdict_info = VerdictInfo {
            verdict: input.verdict,
            deciding_rule: None,
            policy_trace: Vec::new(),
        };
        let retrieval = ReceiptRetrieval::new(input.requested_url)
            .with_content_type(input.content_type.unwrap_or_default())
            .with_byte_count(input.size);
        let retrieval = if let Some(final_url) = input.final_url {
            retrieval.with_final_url(final_url)
        } else {
            retrieval
        };
        let receipt = ReceiptBuilder::new(
            ARBITRAITOR_VERSION,
            input.sha256,
            input.size,
            verdict_info,
            timestamps,
        )
        .retrieval(retrieval)
        .findings(input.findings.iter().map(FindingSummary::from))
        .build();
        let path = self.receipts_dir.join(format!("{}.json", input.sha256));
        let json = serde_json::to_vec_pretty(&receipt)
            .map_err(|error| ApiError::Receipt(error.to_string()))?;
        std::fs::write(&path, json)?;
        Ok(path)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            store_path: PathBuf::from(".arbitraitor").join("cas"),
            receipts_path: PathBuf::from(".arbitraitor").join("receipts"),
            fetch_policy: FetchPolicy::default(),
            policy_toml: String::new(),
        }
    }
}

fn parse_digest(sha256: &str) -> Result<Sha256Digest, ApiError> {
    Sha256Digest::from_str(sha256)
        .map_err(|_| ApiError::NotFound(format!("invalid sha256 digest: {sha256}")))
}

fn not_found_if_missing(sha256: &str) -> impl Fn(arbitraitor_store::StoreError) -> ApiError + '_ {
    move |error| match error {
        arbitraitor_store::StoreError::NotFound { .. } => ApiError::NotFound(sha256.to_owned()),
        other => ApiError::Store(other),
    }
}

fn epoch_string() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or_else(|_| "0".to_owned(), |d| d.as_secs().to_string())
}
