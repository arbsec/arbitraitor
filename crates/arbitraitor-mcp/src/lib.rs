//! MCP and AI agent gateway integration
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, ErrorKind as IoErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arbitraitor_analysis::{AnalysisCoordinator, DetectorStatus, RetrievalInfo};
use arbitraitor_artifact::{ArtifactType, ShellKind, classify};
use arbitraitor_exec::script::ScriptExecution;
use arbitraitor_fetch::{
    FetchPolicy, FetchRequest, FetchUrl, Fetcher, HttpFetcher, VecSink, redact_url,
};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_receipt::Receipt;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
mod explain;

pub use explain::sanitize_for_agent;
use explain::{
    error_response, explain_verdict, json_response, sanitize_json, sanitize_option, sanitized_agent,
};
use std::ops::Not;
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

/// HMAC-SHA256 type alias used for approval token signatures.
type HmacSha256 = Hmac<Sha256>;

pub(crate) const UNTRUSTED_START: &str = "<<ARBITRAITOR_UNTRUSTED_DATA_START>>";
pub(crate) const UNTRUSTED_END: &str = "<<ARBITRAITOR_UNTRUSTED_DATA_END>>";
pub(crate) const MAX_UNTRUSTED_CHARS: usize = 4096;
/// Length of the canonical plan digest prefix a human must retype when
/// approving a plan-bound execution token, per ADR-0013.
const PLAN_DIGEST_PREFIX_LEN: usize = 12;
/// Output length of HMAC-SHA256 in bytes (matches the approval token tag size).
const HMAC_OUTPUT_LEN: usize = 32;
/// Default maximum size of an artifact read by [`ScanArtifactTool`] (256 MiB).
///
/// The bound enforces the "bounded processing" security invariant from the
/// development conventions: every parser and scanner has explicit memory
/// limits. The coordinator pipeline operates on the bytes in memory.
pub const MAX_SCAN_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
/// Default approval token lifetime: five minutes.
pub const DEFAULT_APPROVAL_TOKEN_LIFETIME: Duration = Duration::from_mins(5);

/// MCP tool metadata advertised by this crate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpTool {
    /// Tool name used in MCP `call_tool` requests.
    pub name: String,
    /// Human-readable tool description.
    pub description: String,
    /// JSON Schema describing accepted input parameters.
    pub input_schema: Value,
}

/// Response returned by an MCP tool handler.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpToolResponse {
    /// Tool response content blocks.
    pub content: Vec<McpContent>,
    /// Whether this response represents a handled tool error.
    pub is_error: bool,
}

/// MCP content block emitted by tool handlers.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum McpContent {
    /// Plain text content.
    Text {
        /// Text payload.
        text: String,
    },
    /// Structured JSON content.
    Json {
        /// JSON payload.
        json: Value,
    },
}

/// Identity of the AI integration and agent invoking an MCP tool.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentity {
    /// Integration name, such as an MCP client or product identifier.
    pub integration: String,
    /// Calling agent name.
    pub agent_name: String,
    /// Calling agent session identifier.
    pub session_id: String,
    /// Optional workspace identifier supplied by the integration.
    pub workspace: Option<String>,
}

/// Security capability class exposed by a tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpCapability {
    /// Read-only inspection. This class never releases or executes artifacts.
    Inspect,
    /// Human approval request capability. This cannot execute artifacts.
    Approve,
    /// Execution capability that requires a pre-issued approval token.
    Execute,
}

/// Errors returned by MCP server dispatch.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum McpError {
    /// No registered tool matched the requested name.
    #[error("unknown MCP tool: {name}")]
    UnknownTool {
        /// Requested tool name.
        name: String,
    },
}

/// MCP tool implementation interface.
pub trait McpToolHandler: Send + Sync {
    /// Returns static tool metadata.
    fn metadata(&self) -> McpTool;

    /// Handles a tool call with caller identity for audit attribution.
    fn handle(&self, params: Value, agent: &AgentIdentity) -> McpToolResponse;

    /// Security capability class for this handler.
    fn capability(&self) -> McpCapability;
}

/// Registry and dispatcher for MCP tools.
#[derive(Default)]
pub struct McpServer {
    tools: Vec<Box<dyn McpToolHandler>>,
}

impl McpServer {
    /// Creates an empty MCP server registry.
    #[must_use]
    pub const fn new() -> Self {
        Self { tools: Vec::new() }
    }

    /// Registers a tool handler.
    pub fn register(&mut self, tool: Box<dyn McpToolHandler>) {
        self.tools.push(tool);
    }

    /// Lists registered tool metadata in registration order.
    #[must_use]
    pub fn list_tools(&self) -> Vec<McpTool> {
        self.tools.iter().map(|tool| tool.metadata()).collect()
    }

    /// Lists registered tool capability classes in registration order.
    #[must_use]
    pub fn list_capabilities(&self) -> Vec<(String, McpCapability)> {
        self.tools
            .iter()
            .map(|tool| (tool.metadata().name, tool.capability()))
            .collect()
    }

    /// Dispatches a tool call by name.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::UnknownTool`] when no handler is registered for `name`.
    pub fn call_tool(
        &self,
        name: &str,
        params: Value,
        agent: AgentIdentity,
    ) -> Result<McpToolResponse, McpError> {
        let tool = self
            .tools
            .iter()
            .find(|tool| tool.metadata().name == name)
            .ok_or_else(|| McpError::UnknownTool {
                name: name.to_owned(),
            })?;
        let response = tool.handle(params, &agent);
        drop(agent);
        Ok(response)
    }
}

/// Tool that retrieves an artifact URL and inspects the exact fetched bytes.
pub struct InspectUrlTool {
    coordinator: AnalysisCoordinator,
    fetch_policy: FetchPolicy,
}

impl InspectUrlTool {
    /// Creates an `inspect_url` tool with the default analysis coordinator and fetch policy.
    #[must_use]
    pub fn new(coordinator: AnalysisCoordinator) -> Self {
        Self {
            coordinator,
            fetch_policy: FetchPolicy::default(),
        }
    }

    /// Creates an `inspect_url` tool with an explicit fetch policy.
    #[must_use]
    pub fn with_fetch_policy(coordinator: AnalysisCoordinator, fetch_policy: FetchPolicy) -> Self {
        Self {
            coordinator,
            fetch_policy,
        }
    }
}

impl McpToolHandler for InspectUrlTool {
    fn metadata(&self) -> McpTool {
        McpTool {
            name: "inspect_url".to_owned(),
            description: "Fetch a URL once and inspect the exact artifact bytes without releasing or executing them.".to_owned(),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["url"],
                "properties": {
                    "url": { "type": "string" },
                    "sha256": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" }
                }
            }),
        }
    }

    fn handle(&self, params: Value, agent: &AgentIdentity) -> McpToolResponse {
        match self.inspect(params, agent) {
            Ok(json) => json_response(json),
            Err(error) => error_response(&error.to_string(), agent),
        }
    }

    fn capability(&self) -> McpCapability {
        McpCapability::Inspect
    }
}

impl InspectUrlTool {
    fn inspect(&self, params: Value, agent: &AgentIdentity) -> Result<Value, InspectUrlError> {
        let params: InspectUrlParams = serde_json::from_value(params)?;
        let fetch_url = FetchUrl::parse(&params.url).map_err(|error| InspectUrlError::Fetch {
            message: error.to_string(),
        })?;
        let mut request = FetchRequest::url(fetch_url, self.fetch_policy.clone());
        if let Some(sha256) = params.sha256 {
            let digest =
                sha256
                    .parse::<Sha256Digest>()
                    .map_err(|error| InspectUrlError::InvalidSha256 {
                        message: error.to_string(),
                    })?;
            request = request.with_expected_sha256(digest);
        }

        let fetched = fetch_url_once(request)?;
        let content_type = fetched.receipt.metadata.content_type.clone();
        let retrieval = RetrievalInfo {
            requested_location: Some(redact_url(&params.url)),
            final_location: fetched
                .receipt
                .metadata
                .final_url
                .as_ref()
                .map(ToString::to_string)
                .map(|url| redact_url(&url)),
            content_type: content_type.clone(),
            byte_count: Some(fetched.receipt.bytes_written),
        };
        let result = self
            .coordinator
            .analyze_with_retrieval(&fetched.bytes, Some(retrieval));

        Ok(json!({
            "capability": McpCapability::Inspect,
            "execution_performed": false,
            "release_performed": false,
            "agent_identity": sanitized_agent(agent),
            "artifact": {
                "sha256": fetched.receipt.sha256.to_string(),
                "byte_count": fetched.receipt.bytes_written,
                "content_type": sanitize_option(content_type.as_deref())
            },
            "classification": sanitize_json(json!(format!("{:?}", result.classification.artifact_type))),
            "verdict": result.verdict,
            "findings": sanitize_json(json!(result.findings)),
            "detector_results": sanitize_json(json!(
                result
                    .detector_results
                    .iter()
                    .map(detector_result_json)
                    .collect::<Vec<_>>()
            )),
        }))
    }
}

/// Tool that scans a local file by absolute path without releasing or executing it.
///
/// Reads bytes from disk once, runs the configured analysis coordinator, and
/// returns the same finding/verdict shape as [`InspectUrlTool`]. The path is
/// resolved by the host filesystem: symlinked files are rejected to avoid
/// trivial traversal of quarantine boundaries, and reads are bounded by
/// [`MAX_SCAN_ARTIFACT_BYTES`] so a single tool call cannot exhaust memory.
pub struct ScanArtifactTool {
    coordinator: AnalysisCoordinator,
    max_bytes: u64,
}

impl ScanArtifactTool {
    /// Creates a `scan_artifact` tool with the default coordinator and
    /// [`MAX_SCAN_ARTIFACT_BYTES`] size bound.
    #[must_use]
    pub fn new(coordinator: AnalysisCoordinator) -> Self {
        Self {
            coordinator,
            max_bytes: MAX_SCAN_ARTIFACT_BYTES,
        }
    }

    /// Creates a `scan_artifact` tool with an explicit maximum artifact size
    /// in bytes. The bound must be greater than zero.
    #[must_use]
    pub fn with_max_bytes(coordinator: AnalysisCoordinator, max_bytes: u64) -> Self {
        Self {
            coordinator,
            max_bytes: if max_bytes == 0 {
                MAX_SCAN_ARTIFACT_BYTES
            } else {
                max_bytes
            },
        }
    }

    fn scan(&self, params: Value, agent: &AgentIdentity) -> Result<Value, ScanArtifactError> {
        let params: ScanArtifactParams = serde_json::from_value(params)?;
        let path = PathBuf::from(&params.path);
        let (bytes, sha256) = read_bounded(&path, self.max_bytes)?;
        let result = self.coordinator.analyze(&bytes);
        Ok(json!({
            "capability": McpCapability::Inspect,
            "execution_performed": false,
            "release_performed": false,
            "agent_identity": sanitized_agent(agent),
            "artifact": {
                "path": sanitize_for_agent(&params.path),
                "sha256": sha256.to_string(),
                "byte_count": u64::try_from(bytes.len()).unwrap_or(0),
            },
            "classification": sanitize_json(json!(format!("{:?}", result.classification.artifact_type))),
            "verdict": result.verdict,
            "findings": sanitize_json(json!(result.findings)),
            "detector_results": sanitize_json(json!(
                result
                    .detector_results
                    .iter()
                    .map(detector_result_json)
                    .collect::<Vec<_>>()
            )),
        }))
    }
}

impl McpToolHandler for ScanArtifactTool {
    fn metadata(&self) -> McpTool {
        McpTool {
            name: "scan_artifact".to_owned(),
            description:
                "Read a local file once and inspect its bytes without releasing or executing them."
                    .to_owned(),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["path"],
                "properties": {
                    "path": { "type": "string" }
                }
            }),
        }
    }

    fn handle(&self, params: Value, agent: &AgentIdentity) -> McpToolResponse {
        match self.scan(params, agent) {
            Ok(json) => json_response(json),
            Err(error) => error_response(&error.to_string(), agent),
        }
    }

    fn capability(&self) -> McpCapability {
        McpCapability::Inspect
    }
}

/// Tool that retrieves a URL into the CAS without releasing or executing it.
///
/// Unlike [`InspectUrlTool`], this tool does not invoke the analysis pipeline:
/// it returns the identity (SHA-256, byte count, content type, final URL) of
/// the bytes recorded against the CAS. Callers can subsequently inspect the
/// artifact with [`ScanArtifactTool`] or scan with `inspect_url`. The tool
/// never writes bytes outside the CAS quarantine and never executes them,
/// so its capability class is [`McpCapability::Inspect`].
pub struct FetchArtifactTool {
    fetch_policy: FetchPolicy,
}

impl FetchArtifactTool {
    /// Creates a `fetch_artifact` tool with the default fetch policy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fetch_policy: FetchPolicy::default(),
        }
    }

    /// Creates a `fetch_artifact` tool with an explicit fetch policy.
    #[must_use]
    pub const fn with_fetch_policy(fetch_policy: FetchPolicy) -> Self {
        Self { fetch_policy }
    }
}

impl Default for FetchArtifactTool {
    fn default() -> Self {
        Self::new()
    }
}

impl McpToolHandler for FetchArtifactTool {
    fn metadata(&self) -> McpTool {
        McpTool {
            name: "fetch_artifact".to_owned(),
            description: "Fetch a URL once and record its CAS identity (SHA-256, byte count, content type) without releasing or executing the artifact.".to_owned(),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["url"],
                "properties": {
                    "url": { "type": "string" },
                    "sha256": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" }
                }
            }),
        }
    }

    fn handle(&self, params: Value, agent: &AgentIdentity) -> McpToolResponse {
        match self.fetch(params, agent) {
            Ok(json) => json_response(json),
            Err(error) => error_response(&error.to_string(), agent),
        }
    }

    fn capability(&self) -> McpCapability {
        McpCapability::Inspect
    }
}

impl FetchArtifactTool {
    fn fetch(&self, params: Value, agent: &AgentIdentity) -> Result<Value, FetchArtifactError> {
        let params: FetchArtifactParams = serde_json::from_value(params)?;
        let fetch_url =
            FetchUrl::parse(&params.url).map_err(|error| FetchArtifactError::Fetch {
                message: error.to_string(),
            })?;
        let mut request = FetchRequest::url(fetch_url, self.fetch_policy.clone());
        if let Some(sha256) = params.sha256 {
            let digest = sha256.parse::<Sha256Digest>().map_err(|error| {
                FetchArtifactError::InvalidSha256 {
                    message: error.to_string(),
                }
            })?;
            request = request.with_expected_sha256(digest);
        }

        let fetched = fetch_url_once(request).map_err(|error| FetchArtifactError::Fetch {
            message: error.to_string(),
        })?;
        let content_type = fetched.receipt.metadata.content_type.clone();
        let final_url = fetched
            .receipt
            .metadata
            .final_url
            .as_ref()
            .map(ToString::to_string)
            .map(|url| redact_url(&url));
        Ok(json!({
            "capability": McpCapability::Inspect,
            "execution_performed": false,
            "release_performed": false,
            "agent_identity": sanitized_agent(agent),
            "artifact": {
                "sha256": fetched.receipt.sha256.to_string(),
                "byte_count": fetched.receipt.bytes_written,
                "content_type": sanitize_option(content_type.as_deref())
            },
            "final_url": final_url.map(|url| sanitize_for_agent(&url))
        }))
    }
}

/// Read-only receipt lookup by artifact SHA-256.
///
/// Implementations are injected into [`QueryReceiptTool`]. The trait is
/// intentionally minimal so that filesystem, database, or in-memory backing
/// stores can be wired in without changing the MCP surface.
pub trait ReceiptLookup: Send + Sync {
    /// Returns the receipt recorded for `sha256`, if any.
    fn lookup(&self, sha256: &Sha256Digest) -> Option<Receipt>;
}

/// Simple in-memory [`ReceiptLookup`] used for tests and ephemeral sessions.
///
/// Receipts are indexed by the artifact digest recorded inside the receipt.
/// The store is bounded by the caller: receipts are only inserted through
/// [`Self::record`], never automatically.
#[derive(Default)]
pub struct InMemoryReceiptStore {
    receipts: Mutex<HashMap<Sha256Digest, Receipt>>,
}

impl InMemoryReceiptStore {
    /// Creates an empty in-memory receipt store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a receipt indexed by its `artifact_sha256` field.
    ///
    /// Returns the digest under which the receipt was recorded. Receipts whose
    /// `artifact_sha256` is not a valid 64-character hex string are rejected
    /// so the index cannot be silently poisoned.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptLookupError::InvalidDigest`] when the receipt's
    /// `artifact_sha256` is not a valid 64-character hex string, or
    /// [`ReceiptLookupError::Poisoned`] when the internal lock is poisoned.
    pub fn record(&self, receipt: Receipt) -> Result<Sha256Digest, ReceiptLookupError> {
        let digest: Sha256Digest = receipt.artifact_sha256.parse().map_err(
            |error: arbitraitor_model::ids::Sha256DigestParseError| {
                ReceiptLookupError::InvalidDigest(error.to_string())
            },
        )?;
        self.receipts
            .lock()
            .map_err(|_| ReceiptLookupError::Poisoned)?
            .insert(digest.clone(), receipt);
        Ok(digest)
    }
}

impl ReceiptLookup for InMemoryReceiptStore {
    fn lookup(&self, sha256: &Sha256Digest) -> Option<Receipt> {
        self.receipts
            .lock()
            .ok()
            .and_then(|guard| guard.get(sha256).cloned())
    }
}

/// Errors returned while inserting receipts into an [`InMemoryReceiptStore`].
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ReceiptLookupError {
    /// The receipt `artifact_sha256` was not a valid SHA-256 digest.
    #[error("invalid receipt artifact digest: {0}")]
    InvalidDigest(String),
    /// The internal index was poisoned by a panicking thread.
    #[error("receipt index is poisoned")]
    Poisoned,
}

/// Tool that returns a previously recorded receipt for an artifact digest.
///
/// The tool is read-only: it never releases or executes the artifact. Unknown
/// digests produce a structured `found: false` response rather than a tool
/// error, so callers can distinguish "no receipt exists" from "tool failed".
pub struct QueryReceiptTool {
    lookup: Arc<dyn ReceiptLookup>,
}

impl QueryReceiptTool {
    /// Creates a `query_receipt` tool backed by the supplied lookup.
    #[must_use]
    pub fn new(lookup: Arc<dyn ReceiptLookup>) -> Self {
        Self { lookup }
    }

    fn query(&self, params: Value, agent: &AgentIdentity) -> Result<Value, QueryReceiptError> {
        let params: QueryReceiptParams = serde_json::from_value(params)?;
        let digest: Sha256Digest = params.sha256.parse().map_err(
            |error: arbitraitor_model::ids::Sha256DigestParseError| {
                QueryReceiptError::InvalidSha256 {
                    message: error.to_string(),
                }
            },
        )?;
        Ok(match self.lookup.lookup(&digest) {
            Some(receipt) => json!({
                "capability": McpCapability::Inspect,
                "execution_performed": false,
                "release_performed": false,
                "agent_identity": sanitized_agent(agent),
                "found": true,
                "sha256": digest.to_string(),
                "receipt": sanitize_json(json!(receipt)),
            }),
            None => json!({
                "capability": McpCapability::Inspect,
                "execution_performed": false,
                "release_performed": false,
                "agent_identity": sanitized_agent(agent),
                "found": false,
                "sha256": digest.to_string(),
            }),
        })
    }
}

impl McpToolHandler for QueryReceiptTool {
    fn metadata(&self) -> McpTool {
        McpTool {
            name: "query_receipt".to_owned(),
            description: "Look up a previously recorded scan receipt by artifact SHA-256 without releasing or executing the artifact.".to_owned(),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["sha256"],
                "properties": {
                    "sha256": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" }
                }
            }),
        }
    }

    fn handle(&self, params: Value, agent: &AgentIdentity) -> McpToolResponse {
        match self.query(params, agent) {
            Ok(json) => json_response(json),
            Err(error) => error_response(&error.to_string(), agent),
        }
    }

    fn capability(&self) -> McpCapability {
        McpCapability::Inspect
    }
}

/// Execution context bound into an approval token per ADR-0013.
///
/// The plan digest is computed over `(artifact_sha256, plan_text, ctx)` so any
/// material change in the bound execution context — swapping the interpreter,
/// flipping the network policy, or replacing the policy snapshot — invalidates
/// a previously issued token. At validation time the caller supplies the
/// context that will actually be used for execution; if it does not match the
/// context baked into the token at issue time, validation fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanContext {
    /// Interpreter path that will be invoked (e.g. `/bin/bash`).
    pub interpreter: String,
    /// SHA-256 (hex) of the interpreter binary bytes at approval time, or an
    /// empty string when the operator has not pinned the interpreter digest.
    ///
    /// ADR-0013 calls for `path + digest or signer`. The digest is optional in
    /// the MVP because computing it requires reading `/bin/bash` (or the
    /// equivalent) at approval and execution time, which is platform-specific.
    /// When empty, binding is path-only; a deployment that wants stronger
    /// binding can populate this from the operator's policy.
    pub interpreter_digest: String,
    /// Whether the spawned interpreter will have its network namespace isolated.
    pub network_isolated: bool,
    /// SHA-256 (hex) of the policy TOML snapshot in effect at approval time,
    /// or an empty string when no policy is configured.
    pub policy_snapshot_digest: String,
    /// SHA-256 (hex) of the detector rule snapshot, or empty when none loaded.
    pub detector_snapshot_digest: String,
    /// SHA-256 (hex) of the intelligence feed snapshot, or empty when none loaded.
    pub intelligence_snapshot_digest: String,
}

impl PlanContext {
    /// Canonical mediated-bash context.
    ///
    /// Matches [`arbitraitor_exec::script::ScriptExecution::bash`] which hard
    /// codes `/bin/bash --noprofile --norc`. The interpreter string here is
    /// the bare binary path so the same value can be derived at issue and
    /// validation time without disagreements about argument vectors.
    ///
    /// Per ADR-0013 ("path + digest or signer") and Oracle R2 the returned
    /// context also pins the SHA-256 of `/bin/bash` (when the file is
    /// readable) so a token issued against one build cannot be replayed after
    /// the interpreter is replaced. On platforms where `/bin/bash` is absent
    /// the digest is left empty and binding is path-only.
    #[must_use]
    pub fn for_bash(network_isolated: bool, policy_snapshot_digest: impl Into<String>) -> Self {
        Self {
            interpreter: "/bin/bash".to_owned(),
            interpreter_digest: interpreter_digest_or_empty("/bin/bash"),
            network_isolated,
            policy_snapshot_digest: policy_snapshot_digest.into(),
            detector_snapshot_digest: String::new(),
            intelligence_snapshot_digest: String::new(),
        }
    }

    /// Pins the SHA-256 of the interpreter binary so a token issued for one
    /// `/bin/bash` build cannot be replayed against a different one.
    #[must_use]
    pub fn with_interpreter_digest(mut self, digest: impl Into<String>) -> Self {
        self.interpreter_digest = digest.into();
        self
    }

    /// Pins the SHA-256 of the detector rule snapshot in effect at approval time.
    #[must_use]
    pub fn with_detector_snapshot_digest(mut self, digest: impl Into<String>) -> Self {
        self.detector_snapshot_digest = digest.into();
        self
    }

    /// Pins the SHA-256 of the intelligence feed snapshot in effect at approval time.
    #[must_use]
    pub fn with_intelligence_snapshot_digest(mut self, digest: impl Into<String>) -> Self {
        self.intelligence_snapshot_digest = digest.into();
        self
    }
}

/// Human approval prompt used by [`RequestApprovalTool`].
pub trait ApprovalPrompt: Send + Sync {
    /// Shows the artifact and untrusted plan to a human approval channel.
    ///
    /// `ctx` carries the binding execution context per ADR-0013 so the prompt
    /// can render the interpreter, network policy, and policy snapshot digest
    /// alongside the artifact identity. The typed plan-digest prefix the
    /// operator must enter is derived from `(sha256, plan, ctx)`.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalPromptError`] when the approval channel cannot render
    /// the prompt or read the human response.
    fn request_confirmation(
        &self,
        sha256: &Sha256Digest,
        plan: &str,
        ctx: &PlanContext,
    ) -> Result<bool, ApprovalPromptError>;
}

/// Stdin/stderr approval prompt for MVP interactive use.
#[derive(Clone, Copy, Debug, Default)]
pub struct StdinApprovalPrompt;

impl ApprovalPrompt for StdinApprovalPrompt {
    fn request_confirmation(
        &self,
        sha256: &Sha256Digest,
        plan: &str,
        ctx: &PlanContext,
    ) -> Result<bool, ApprovalPromptError> {
        // ADR-0013: bind human attention to both the artifact identity and the
        // execution plan by requiring the operator to type a prefix of the
        // canonical plan digest instead of an easily-spoofed "yes" token.
        let plan_digest = canonical_plan_digest(sha256, plan, ctx)
            .map_err(|e| ApprovalPromptError::digest(&e))?;
        let digest_prefix = &plan_digest[..PLAN_DIGEST_PREFIX_LEN];

        let mut stderr = std::io::stderr().lock();
        writeln!(stderr, "APPROVAL REQUESTED for artifact {sha256}")
            .map_err(|error| ApprovalPromptError::write(&error))?;
        writeln!(stderr, "Plan (untrusted): {}", sanitize_for_agent(plan))
            .map_err(|error| ApprovalPromptError::write(&error))?;
        writeln!(
            stderr,
            "Interpreter: {} (args: {}, digest: {}, network isolated: {}, policy snapshot: {})",
            ctx.interpreter,
            CanonicalExecutionPlan::INTERPRETER_ARGUMENTS.join(" "),
            if ctx.interpreter_digest.is_empty() {
                "unpinned"
            } else {
                &ctx.interpreter_digest
            },
            ctx.network_isolated,
            if ctx.policy_snapshot_digest.is_empty() {
                "none"
            } else {
                &ctx.policy_snapshot_digest
            }
        )
        .map_err(|error| ApprovalPromptError::write(&error))?;
        writeln!(stderr, "Type this code to approve: {digest_prefix}")
            .map_err(|error| ApprovalPromptError::write(&error))?;
        write!(stderr, "> ").map_err(|error| ApprovalPromptError::write(&error))?;
        stderr
            .flush()
            .map_err(|error| ApprovalPromptError::write(&error))?;

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|error| ApprovalPromptError::read(&error))?;
        Ok(input.trim() == digest_prefix)
    }
}

/// Errors from a human approval prompt channel.
#[derive(Debug, Error)]
pub enum ApprovalPromptError {
    /// The approval prompt could not be written.
    #[error("approval prompt write failed during {stage}: {message}")]
    Write {
        /// I/O stage.
        stage: &'static str,
        /// Safe diagnostic message.
        message: String,
    },
    /// The approval response could not be read.
    #[error("approval prompt read failed during {stage}: {message}")]
    Read {
        /// I/O stage.
        stage: &'static str,
        /// Safe diagnostic message.
        message: String,
    },
    /// The canonical plan digest could not be computed for the prompt code.
    #[error("approval prompt digest computation failed: {message}")]
    Digest {
        /// Safe diagnostic message describing the serialization failure.
        message: String,
    },
}

impl ApprovalPromptError {
    fn write(error: &std::io::Error) -> Self {
        Self::Write {
            stage: "write-prompt",
            message: error.to_string(),
        }
    }

    fn read(error: &std::io::Error) -> Self {
        Self::Read {
            stage: "read-confirmation",
            message: error.to_string(),
        }
    }

    fn digest(error: &serde_json::Error) -> Self {
        Self::Digest {
            message: error.to_string(),
        }
    }
}

/// Issues and validates signed approval tokens.
///
/// Tokens are single-use: each token carries a unique nonce and the issuer
/// records every accepted nonce in an internally synchronised set so a
/// replayed token is rejected even before its signature is checked.
///
/// When constructed with [`Self::with_durable_store`], spent nonces are also
/// persisted to a redb-backed store so replay is rejected across process
/// restarts (ADR-0013, #388).
#[derive(Clone)]
pub struct ApprovalTokenIssuer {
    signing_secret: Arc<[u8]>,
    spent_nonces: Arc<Mutex<HashSet<String>>>,
    durable: Option<Arc<arbitraitor_store::SpentNonceStore>>,
}

impl ApprovalTokenIssuer {
    /// Creates an issuer with a process-local random signing secret.
    #[must_use]
    pub fn new() -> Self {
        let mut secret = Vec::with_capacity(32);
        secret.extend_from_slice(Uuid::new_v4().as_bytes());
        secret.extend_from_slice(Uuid::new_v4().as_bytes());
        Self {
            signing_secret: Arc::from(secret.into_boxed_slice()),
            spent_nonces: Arc::new(Mutex::new(HashSet::new())),
            durable: None,
        }
    }

    /// Creates an issuer with an explicit signing secret.
    #[must_use]
    pub fn with_secret(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            signing_secret: Arc::from(secret.into().into_boxed_slice()),
            spent_nonces: Arc::new(Mutex::new(HashSet::new())),
            durable: None,
        }
    }

    /// Creates an issuer backed by a durable spent-nonce store.
    ///
    /// On construction, all previously-spent nonces are loaded from `store`
    /// into the in-memory cache. Every subsequently spent nonce is persisted
    /// so a token used before a restart is rejected after restart (#388).
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalTokenError::NonceStorePoisoned`] when the durable
    /// store cannot be read.
    pub fn with_durable_store(
        store: arbitraitor_store::SpentNonceStore,
    ) -> Result<Self, ApprovalTokenError> {
        let nonces = store
            .load_all()
            .map_err(|_| ApprovalTokenError::NonceStorePoisoned)?;
        Ok(Self {
            signing_secret: Arc::from(
                {
                    let mut secret = Vec::with_capacity(32);
                    secret.extend_from_slice(Uuid::new_v4().as_bytes());
                    secret.extend_from_slice(Uuid::new_v4().as_bytes());
                    secret
                }
                .into_boxed_slice(),
            ),
            spent_nonces: Arc::new(Mutex::new(nonces)),
            durable: Some(Arc::new(store)),
        })
    }

    /// Creates an issuer with an explicit signing secret and durable nonce
    /// store. Intended for CI/automation where the signing secret is stable
    /// across restarts — in that scenario durable nonce persistence is what
    /// prevents replay of tokens issued before the restart (#388).
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalTokenError::NonceStorePoisoned`] when the durable
    /// store cannot be read.
    pub fn with_secret_and_durable_store(
        secret: impl Into<Vec<u8>>,
        store: arbitraitor_store::SpentNonceStore,
    ) -> Result<Self, ApprovalTokenError> {
        let nonces = store
            .load_all()
            .map_err(|_| ApprovalTokenError::NonceStorePoisoned)?;
        Ok(Self {
            signing_secret: Arc::from(secret.into().into_boxed_slice()),
            spent_nonces: Arc::new(Mutex::new(nonces)),
            durable: Some(Arc::new(store)),
        })
    }

    fn issue(
        &self,
        sha256: &Sha256Digest,
        plan: &str,
        ctx: &PlanContext,
        expires_at: SystemTime,
        agent: &AgentIdentity,
    ) -> Result<IssuedApprovalToken, ApprovalTokenError> {
        let expires_at_unix_seconds = unix_seconds(expires_at)?;
        let payload = ApprovalTokenPayload {
            schema_version: 3,
            sha256: sha256.to_string(),
            plan_digest: canonical_plan_digest(sha256, plan, ctx)?,
            interpreter: ctx.interpreter.clone(),
            interpreter_digest: ctx.interpreter_digest.clone(),
            interpreter_arguments: CanonicalExecutionPlan::INTERPRETER_ARGUMENTS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            network_isolated: ctx.network_isolated,
            policy_snapshot_digest: ctx.policy_snapshot_digest.clone(),
            detector_snapshot_digest: ctx.detector_snapshot_digest.clone(),
            intelligence_snapshot_digest: ctx.intelligence_snapshot_digest.clone(),
            operation: CanonicalExecutionPlan::OPERATION.to_owned(),
            release_mode: CanonicalExecutionPlan::RELEASE_MODE.to_owned(),
            environment_profile_digest: CanonicalExecutionPlan::ENVIRONMENT_PROFILE_DIGEST
                .to_owned(),
            working_directory_policy: CanonicalExecutionPlan::WORKING_DIRECTORY_POLICY.to_owned(),
            filesystem_grants: CanonicalExecutionPlan::FILESYSTEM_GRANTS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            sandbox_capabilities: CanonicalExecutionPlan::SANDBOX_CAPABILITIES.to_owned(),
            release_destination: CanonicalExecutionPlan::RELEASE_DESTINATION.to_owned(),
            expires_at_unix_seconds,
            nonce: Uuid::new_v4().to_string(),
            approval_method: "stdin-human-confirmation".to_owned(),
            requester_integration: agent.integration.clone(),
            requester_agent_name: agent.agent_name.clone(),
            requester_session_id: agent.session_id.clone(),
            human_approver_identity: std::env::var("USER").ok(),
        };
        let payload_bytes = serde_json::to_vec(&payload)?;
        let signature = self.sign(&payload_bytes)?;
        let token = format!(
            "v2.{}.{}",
            hex::encode(&payload_bytes),
            hex::encode(signature)
        );
        Ok(IssuedApprovalToken {
            token,
            expires_at_unix_seconds,
        })
    }

    fn validate(
        &self,
        token: &str,
        sha256: &Sha256Digest,
        ctx: &PlanContext,
        now: SystemTime,
    ) -> Result<ApprovalTokenPayload, ApprovalTokenError> {
        let (payload_bytes, signature) = Self::decode_token(token)?;

        // Constant-time comparison only holds for equal-length buffers; reject
        // malformed signatures up front so the comparison below is well-formed.
        if signature.len() != HMAC_OUTPUT_LEN {
            return Err(ApprovalTokenError::InvalidSignature);
        }
        // Defense-in-depth verification: recompute the HMAC over the canonical
        // inputs and let the HMAC implementation perform its own constant-time
        // tag comparison via `verify_slice`. This replaces the previous
        // short-circuit `Vec<u8>` equality which leaked timing information.
        let mut verify_mac = HmacSha256::new_from_slice(&self.signing_secret)
            .map_err(|_| ApprovalTokenError::KeyLength)?;
        verify_mac.update(b"arbitraitor-mcp-approval-token-v2");
        verify_mac.update(&payload_bytes);
        verify_mac
            .verify_slice(&signature)
            .map_err(|_| ApprovalTokenError::InvalidSignature)?;

        // Explicit constant-time equality against the recomputed tag. This is
        // redundant with `verify_slice` above but kept as a belt-and-suspenders
        // guarantee that the comparison never short-circuits on attacker input.
        let expected = self.sign(&payload_bytes)?;
        if bool::from(signature.ct_eq(&expected).not()) {
            return Err(ApprovalTokenError::InvalidSignature);
        }

        let payload: ApprovalTokenPayload = serde_json::from_slice(&payload_bytes)?;
        if payload.schema_version != 3 {
            return Err(ApprovalTokenError::UnsupportedSchema);
        }
        if payload.sha256 != sha256.to_string() {
            return Err(ApprovalTokenError::ArtifactMismatch);
        }
        if unix_seconds(now)? >= payload.expires_at_unix_seconds {
            return Err(ApprovalTokenError::Expired);
        }
        // ADR-0013 (#188): the bound execution context must match exactly.
        // The comparison covers interpreter identity (path + optional digest
        // per Oracle R2), the fixed interpreter argument vector, network
        // policy, policy snapshot, detector snapshot, intelligence snapshot,
        // and every fixed execution-profile dimension encoded in the token.
        // The comparison runs only after authenticity, artifact, and expiry
        // checks so an attacker cannot use a stolen or forged token to probe
        // the bound context.
        if payload.interpreter != ctx.interpreter
            || payload.interpreter_digest != ctx.interpreter_digest
            || payload.network_isolated != ctx.network_isolated
            || payload.policy_snapshot_digest != ctx.policy_snapshot_digest
            || payload.detector_snapshot_digest != ctx.detector_snapshot_digest
            || payload.intelligence_snapshot_digest != ctx.intelligence_snapshot_digest
            || payload.interpreter_arguments
                != CanonicalExecutionPlan::INTERPRETER_ARGUMENTS
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect::<Vec<_>>()
            || payload.operation != CanonicalExecutionPlan::OPERATION
            || payload.release_mode != CanonicalExecutionPlan::RELEASE_MODE
            || payload.environment_profile_digest
                != CanonicalExecutionPlan::ENVIRONMENT_PROFILE_DIGEST
            || payload.working_directory_policy != CanonicalExecutionPlan::WORKING_DIRECTORY_POLICY
            || payload.filesystem_grants
                != CanonicalExecutionPlan::FILESYSTEM_GRANTS
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect::<Vec<_>>()
            || payload.sandbox_capabilities != CanonicalExecutionPlan::SANDBOX_CAPABILITIES
            || payload.release_destination != CanonicalExecutionPlan::RELEASE_DESTINATION
        {
            return Err(ApprovalTokenError::ContextMismatch);
        }

        // Single-use enforcement (#187): a token's nonce may only be spent
        // once. The check runs after every other validation passes so that
        // a replay of an otherwise-valid token is the only path that consumes
        // the nonce, and a replay is rejected on its second presentation.
        //
        // When a durable store is configured (#388), the nonce is also
        // persisted to redb so replay is rejected across process restarts.
        let mut spent = self
            .spent_nonces
            .lock()
            .map_err(|_| ApprovalTokenError::NonceStorePoisoned)?;
        if !spent.insert(payload.nonce.clone()) {
            return Err(ApprovalTokenError::Reused);
        }
        if let Some(store) = &self.durable {
            match store.insert(&payload.nonce) {
                Ok(true) => {}
                Ok(false) => {
                    // Already spent in the durable store (cross-process replay
                    // or pre-restart spend). Roll back the in-memory insert.
                    spent.remove(&payload.nonce);
                    return Err(ApprovalTokenError::Reused);
                }
                Err(_) => {
                    spent.remove(&payload.nonce);
                    return Err(ApprovalTokenError::NonceStorePoisoned);
                }
            }
        }

        Ok(payload)
    }

    fn decode_token(token: &str) -> Result<(Vec<u8>, Vec<u8>), ApprovalTokenError> {
        let mut parts = token.split('.');
        let version = parts.next().ok_or(ApprovalTokenError::MalformedToken)?;
        let payload_hex = parts.next().ok_or(ApprovalTokenError::MalformedToken)?;
        let signature_hex = parts.next().ok_or(ApprovalTokenError::MalformedToken)?;
        if parts.next().is_some() || version != "v2" {
            return Err(ApprovalTokenError::MalformedToken);
        }
        Ok((hex::decode(payload_hex)?, hex::decode(signature_hex)?))
    }

    fn sign(&self, payload_bytes: &[u8]) -> Result<[u8; HMAC_OUTPUT_LEN], ApprovalTokenError> {
        // HMAC accepts any non-empty key length for SHA-256: short keys are
        // zero-padded to the block size and long keys are hashed first.
        // `InvalidKeyLength` is therefore unreachable for our `Arc<[u8]>`
        // secret, but we propagate it as a defensive error rather than
        // panicking, to honour `forbid(unsafe_code)` and the `expect_used` /
        // `panic` clippy lints.
        let mut mac = HmacSha256::new_from_slice(&self.signing_secret)
            .map_err(|_| ApprovalTokenError::KeyLength)?;
        mac.update(b"arbitraitor-mcp-approval-token-v2");
        mac.update(payload_bytes);
        let result = mac.finalize().into_bytes();
        let mut output = [0u8; HMAC_OUTPUT_LEN];
        output.copy_from_slice(&result);
        Ok(output)
    }
}

impl Default for ApprovalTokenIssuer {
    fn default() -> Self {
        Self::new()
    }
}

struct IssuedApprovalToken {
    token: String,
    expires_at_unix_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalTokenPayload {
    schema_version: u32,
    sha256: String,
    plan_digest: String,
    interpreter: String,
    interpreter_digest: String,
    interpreter_arguments: Vec<String>,
    network_isolated: bool,
    policy_snapshot_digest: String,
    detector_snapshot_digest: String,
    intelligence_snapshot_digest: String,
    operation: String,
    release_mode: String,
    environment_profile_digest: String,
    working_directory_policy: String,
    filesystem_grants: Vec<String>,
    sandbox_capabilities: String,
    release_destination: String,
    expires_at_unix_seconds: u64,
    nonce: String,
    approval_method: String,
    requester_integration: String,
    requester_agent_name: String,
    requester_session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    human_approver_identity: Option<String>,
}

/// Tool that requests human approval for a canonical artifact execution plan.
pub struct RequestApprovalTool {
    prompt: Arc<dyn ApprovalPrompt>,
    issuer: ApprovalTokenIssuer,
    token_lifetime: Duration,
    ctx: PlanContext,
}

impl RequestApprovalTool {
    /// Creates a `request_approval` tool using stdin/stderr confirmation with
    /// the default mediated-bash context (network isolated, no policy snapshot).
    #[must_use]
    pub fn new() -> Self {
        Self::with_prompt(
            Arc::new(StdinApprovalPrompt),
            ApprovalTokenIssuer::new(),
            PlanContext::for_bash(true, ""),
        )
    }

    /// Creates a `request_approval` tool with injected prompt, token issuer,
    /// and bound execution context.
    #[must_use]
    pub fn with_prompt(
        prompt: Arc<dyn ApprovalPrompt>,
        issuer: ApprovalTokenIssuer,
        ctx: PlanContext,
    ) -> Self {
        Self {
            prompt,
            issuer,
            token_lifetime: DEFAULT_APPROVAL_TOKEN_LIFETIME,
            ctx,
        }
    }

    /// Sets the token lifetime. A zero lifetime creates immediately expired tokens.
    #[must_use]
    pub const fn with_token_lifetime(mut self, token_lifetime: Duration) -> Self {
        self.token_lifetime = token_lifetime;
        self
    }

    fn request(&self, params: Value, agent: &AgentIdentity) -> Result<Value, RequestApprovalError> {
        let params: RequestApprovalParams = serde_json::from_value(params)?;
        let digest: Sha256Digest = params.sha256.parse().map_err(
            |error: arbitraitor_model::ids::Sha256DigestParseError| {
                RequestApprovalError::InvalidSha256 {
                    message: error.to_string(),
                }
            },
        )?;
        let approved = self
            .prompt
            .request_confirmation(&digest, &params.plan, &self.ctx)?;
        let expires_at = SystemTime::now()
            .checked_add(self.token_lifetime)
            .ok_or(RequestApprovalError::TimeOverflow)?;
        let issued = if approved {
            Some(
                self.issuer
                    .issue(&digest, &params.plan, &self.ctx, expires_at, agent)?,
            )
        } else {
            None
        };
        Ok(json!({
            "capability": McpCapability::Approve,
            "execution_performed": false,
            "release_performed": false,
            "agent_identity": sanitized_agent(agent),
            "approved": approved,
            "approval_token": issued.as_ref().map(|token| token.token.clone()),
            "expires_at": issued
                .as_ref()
                .map_or_else(|| unix_seconds_string(expires_at), |token| token.expires_at_unix_seconds.to_string()),
            "artifact": { "sha256": digest.to_string() },
            "plan_digest": canonical_plan_digest(&digest, &params.plan, &self.ctx)?,
        }))
    }
}

impl Default for RequestApprovalTool {
    fn default() -> Self {
        Self::new()
    }
}

impl McpToolHandler for RequestApprovalTool {
    fn metadata(&self) -> McpTool {
        McpTool {
            name: "request_approval".to_owned(),
            description: "Request human approval for a plan-bound artifact execution token without executing the artifact.".to_owned(),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["sha256", "plan"],
                "properties": {
                    "sha256": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" },
                    "plan": { "type": "string" }
                }
            }),
        }
    }

    fn handle(&self, params: Value, agent: &AgentIdentity) -> McpToolResponse {
        match self.request(params, agent) {
            Ok(json) => json_response(json),
            Err(error) => error_response(&error.to_string(), agent),
        }
    }

    fn capability(&self) -> McpCapability {
        McpCapability::Approve
    }
}

/// Byte lookup for approved artifacts.
pub trait ArtifactLookup: Send + Sync {
    /// Returns exact artifact bytes for `sha256`, if available.
    fn lookup_artifact(&self, sha256: &Sha256Digest) -> Option<Vec<u8>>;
}

/// In-memory artifact lookup for tests and ephemeral MCP sessions.
#[derive(Default)]
pub struct InMemoryArtifactStore {
    artifacts: Mutex<HashMap<Sha256Digest, Vec<u8>>>,
}

impl InMemoryArtifactStore {
    /// Creates an empty artifact store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records bytes by their SHA-256 digest and returns the digest.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactStoreError::Poisoned`] when the internal artifact
    /// store lock is poisoned.
    pub fn record(&self, bytes: Vec<u8>) -> Result<Sha256Digest, ArtifactStoreError> {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = Sha256Digest::new(hasher.finalize().into());
        self.artifacts
            .lock()
            .map_err(|_| ArtifactStoreError::Poisoned)?
            .insert(digest.clone(), bytes);
        Ok(digest)
    }
}

impl ArtifactLookup for InMemoryArtifactStore {
    fn lookup_artifact(&self, sha256: &Sha256Digest) -> Option<Vec<u8>> {
        self.artifacts
            .lock()
            .ok()
            .and_then(|guard| guard.get(sha256).cloned())
    }
}

/// Errors returned by [`InMemoryArtifactStore`].
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ArtifactStoreError {
    /// The artifact store lock was poisoned.
    #[error("artifact store is poisoned")]
    Poisoned,
}

/// Tool that executes an artifact only with a valid approval token.
pub struct RunApprovedArtifactTool {
    artifacts: Arc<dyn ArtifactLookup>,
    issuer: ApprovalTokenIssuer,
    ctx: PlanContext,
}

impl RunApprovedArtifactTool {
    /// Creates a `run_approved_artifact` tool backed by an artifact lookup,
    /// using the default mediated-bash context (network isolated, no policy).
    #[must_use]
    pub fn new(artifacts: Arc<dyn ArtifactLookup>, issuer: ApprovalTokenIssuer) -> Self {
        Self {
            artifacts,
            issuer,
            ctx: PlanContext::for_bash(true, ""),
        }
    }

    /// Controls network namespace isolation for tests and policy-granted callers.
    #[must_use]
    pub fn with_network_isolated(mut self, network_isolated: bool) -> Self {
        self.ctx.network_isolated = network_isolated;
        self
    }

    /// Sets the policy snapshot digest the executor will bind approval tokens
    /// against. Must match the digest configured on the issuing
    /// [`RequestApprovalTool`] or approval tokens will fail validation.
    #[must_use]
    pub fn with_policy_snapshot_digest(mut self, digest: impl Into<String>) -> Self {
        self.ctx.policy_snapshot_digest = digest.into();
        self
    }

    fn run(&self, params: Value, agent: &AgentIdentity) -> Result<Value, RunApprovedArtifactError> {
        let params: RunApprovedArtifactParams = serde_json::from_value(params)?;
        let digest: Sha256Digest = params.sha256.parse().map_err(
            |error: arbitraitor_model::ids::Sha256DigestParseError| {
                RunApprovedArtifactError::InvalidSha256 {
                    message: error.to_string(),
                }
            },
        )?;
        if params.args.as_ref().is_some_and(|args| !args.is_empty()) {
            return Err(RunApprovedArtifactError::UnapprovedArguments);
        }
        let token_payload = self.issuer.validate(
            &params.approval_token,
            &digest,
            &self.ctx,
            SystemTime::now(),
        )?;
        let bytes = self
            .artifacts
            .lookup_artifact(&digest)
            .ok_or(RunApprovedArtifactError::ArtifactNotFound)?;
        verify_bytes_digest(&bytes, &digest)?;
        // ADR-0036 / issue #612 (Blocker 4 from adversarial review): gate
        // the approved artifact by classified ArtifactType before piping bytes
        // to bash. The approval token binds the interpreter to bash, but an
        // agent (or a confused human operator driving the agent) could
        // approve an HTML / JSON / XML / archive / Unknown artifact for
        // execution. Piping such bytes to bash is unsafe (HTML etc. can
        // incidentally contain bash-parseable `$(...)`, redirections, pipes)
        // and incorrect (bash doesn't understand them). Only shell scripts
        // are runnable through this MCP path; native executables are gated
        // out as well because the MCP approval flow always binds to the
        // bash interpreter (see [`PlanContext::for_bash`]).
        let classification = classify(&bytes);
        if !matches!(
            classification.artifact_type,
            ArtifactType::ShellScript(ShellKind::Posix | ShellKind::Bash)
        ) {
            return Err(RunApprovedArtifactError::NotExecutable {
                artifact_type: classification.artifact_type,
            });
        }
        let execution = ScriptExecution::bash()?.with_network_isolated(self.ctx.network_isolated);
        let result = execution.execute(&bytes)?;
        Ok(json!({
            "capability": McpCapability::Execute,
            "execution_performed": true,
            "release_performed": false,
            "agent_identity": sanitized_agent(agent),
            "artifact": { "sha256": digest.to_string() },
            "approval": {
                "plan_digest": token_payload.plan_digest,
                "expires_at": token_payload.expires_at_unix_seconds.to_string(),
            },
            "result": {
                "exit_code": result.exit_code,
                "stdout": sanitize_for_agent(&String::from_utf8_lossy(&result.stdout)),
                "stderr": sanitize_for_agent(&String::from_utf8_lossy(&result.stderr)),
            }
        }))
    }
}

impl McpToolHandler for RunApprovedArtifactTool {
    fn metadata(&self) -> McpTool {
        McpTool {
            name: "run_approved_artifact".to_owned(),
            description: "Execute exact artifact bytes only when a valid plan-bound approval token is supplied.".to_owned(),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["sha256", "approval_token"],
                "properties": {
                    "sha256": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" },
                    "approval_token": { "type": "string" },
                    "args": { "type": "array", "items": { "type": "string" } }
                }
            }),
        }
    }

    fn handle(&self, params: Value, agent: &AgentIdentity) -> McpToolResponse {
        match self.run(params, agent) {
            Ok(json) => json_response(json),
            Err(error) => error_response(&error.to_string(), agent),
        }
    }

    fn capability(&self) -> McpCapability {
        McpCapability::Execute
    }
}

fn canonical_plan_digest(
    sha256: &Sha256Digest,
    plan: &str,
    ctx: &PlanContext,
) -> Result<String, serde_json::Error> {
    let canonical_plan = CanonicalExecutionPlan {
        schema_version: 3,
        artifact_sha256: sha256.to_string(),
        human_readable_plan: plan.to_owned(),
        approved_arguments: Vec::new(),
        interpreter: ctx.interpreter.clone(),
        interpreter_arguments: CanonicalExecutionPlan::INTERPRETER_ARGUMENTS
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        interpreter_digest: ctx.interpreter_digest.clone(),
        network_isolated: ctx.network_isolated,
        policy_snapshot_digest: ctx.policy_snapshot_digest.clone(),
        // ADR-0013 (#188): every dimension that affects execution is bound
        // here, even when its value is fixed for the MVP. Encoding the fixed
        // values (rather than omitting the fields) means any future change to
        // an implicit default invalidates outstanding tokens and forces fresh
        // approval. See `docs/adr/0013-plan-bound-approval-capability.md`.
        operation: CanonicalExecutionPlan::OPERATION.to_owned(),
        release_mode: CanonicalExecutionPlan::RELEASE_MODE.to_owned(),
        environment_profile_digest: CanonicalExecutionPlan::ENVIRONMENT_PROFILE_DIGEST.to_owned(),
        working_directory_policy: CanonicalExecutionPlan::WORKING_DIRECTORY_POLICY.to_owned(),
        filesystem_grants: CanonicalExecutionPlan::FILESYSTEM_GRANTS
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        sandbox_capabilities: CanonicalExecutionPlan::SANDBOX_CAPABILITIES.to_owned(),
        release_destination: CanonicalExecutionPlan::RELEASE_DESTINATION.to_owned(),
        detector_snapshot_digest: ctx.detector_snapshot_digest.clone(),
        intelligence_snapshot_digest: ctx.intelligence_snapshot_digest.clone(),
    };
    let encoded = serde_json::to_vec(&canonical_plan)?;
    let mut hasher = Sha256::new();
    hasher.update(encoded);
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Serialize)]
struct CanonicalExecutionPlan {
    schema_version: u32,
    artifact_sha256: String,
    human_readable_plan: String,
    approved_arguments: Vec<String>,
    interpreter: String,
    interpreter_arguments: Vec<String>,
    interpreter_digest: String,
    network_isolated: bool,
    policy_snapshot_digest: String,
    operation: String,
    release_mode: String,
    environment_profile_digest: String,
    working_directory_policy: String,
    filesystem_grants: Vec<String>,
    sandbox_capabilities: String,
    release_destination: String,
    detector_snapshot_digest: String,
    intelligence_snapshot_digest: String,
}

impl CanonicalExecutionPlan {
    // ADR-0013 fixed execution profile for the MVP mediated-bash path.
    //
    // Every constant here documents the *current* execution behaviour. If a
    // future change alters any of these values, outstanding approval tokens
    // are invalidated by construction (the canonical plan digest changes),
    // which is exactly the ADR-0013 invariant. Do not change these values
    // without bumping `schema_version` and forcing fresh approval.
    const OPERATION: &'static str = "execute";
    const RELEASE_MODE: &'static str = "execute";
    /// `bash --noprofile --norc`, matching
    /// [`arbitraitor_exec::script::ScriptExecution::bash`].
    const INTERPRETER_ARGUMENTS: &'static [&'static str] = &["--noprofile", "--norc"];
    /// Digest of the mediated environment profile produced by
    /// `arbitraitor_exec::ExecutionContext`. Empty until the profile is
    /// canonicalised; treated as a fixed value here so any future change to
    /// the allowlisted environment invalidates outstanding tokens.
    const ENVIRONMENT_PROFILE_DIGEST: &'static str = "mvp ExecutionContext allowlist v1";
    /// Workdir policy: scripts run with their bytes piped to stdin and no
    /// working directory grant beyond the sandbox root.
    const WORKING_DIRECTORY_POLICY: &'static str = "sandbox-root-stdin-fed";
    /// Filesystem grants are empty for the MVP; the interpreter sees only its
    /// own process image and the pipe delivering the script bytes.
    const FILESYSTEM_GRANTS: &'static [&'static str] = &[];
    /// Sandbox capabilities applied via `arbitraitor_sandbox::configure_command`.
    const SANDBOX_CAPABILITIES: &'static str = "prctl NoNewPrivs + close_range fd closure";
    /// No release destination; the MVP path executes inline.
    const RELEASE_DESTINATION: &'static str = "inline-execute";
}

/// Computes the SHA-256 hex digest of the interpreter binary at `path`, or
/// returns an empty string when the binary is unreadable.
///
/// Per ADR-0013 ("path + digest or signer") and Oracle R2, the default
/// [`PlanContext`] produced by [`PlanContext::for_bash`] should pin the actual
/// `/bin/bash` bytes in effect, so a token issued on one host cannot be
/// replayed after the interpreter is replaced. Failures (missing binary,
/// permission denied, non-Linux test sandbox) silently fall back to an empty
/// digest, preserving the path-only binding of the previous MVP. The fallback
/// is observable via tracing but never panics.
fn interpreter_digest_or_empty(path: &str) -> String {
    match std::fs::read(path) {
        Ok(bytes) => {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            hex::encode(hasher.finalize())
        }
        Err(_) => String::new(),
    }
}

fn verify_bytes_digest(
    bytes: &[u8],
    digest: &Sha256Digest,
) -> Result<(), RunApprovedArtifactError> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let actual = Sha256Digest::new(hasher.finalize().into());
    if &actual == digest {
        Ok(())
    } else {
        Err(RunApprovedArtifactError::ArtifactDigestMismatch)
    }
}

fn unix_seconds(time: SystemTime) -> Result<u64, ApprovalTokenError> {
    time.duration_since(UNIX_EPOCH)
        .map_err(|_| ApprovalTokenError::TimeBeforeEpoch)
        .map(|duration| duration.as_secs())
}

fn unix_seconds_string(time: SystemTime) -> String {
    time.duration_since(UNIX_EPOCH).map_or_else(
        |_| "0".to_owned(),
        |duration| duration.as_secs().to_string(),
    )
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<(Vec<u8>, Sha256Digest), ScanArtifactError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|source| ScanArtifactError::from_io("stat-path", &source))?;
    if metadata.file_type().is_symlink() {
        return Err(ScanArtifactError::SymlinkRejected);
    }
    if !metadata.is_file() {
        return Err(ScanArtifactError::NotAFile);
    }
    let size = metadata.len();
    if size > max_bytes {
        return Err(ScanArtifactError::SizeExceeded {
            attempted: size,
            max_bytes,
        });
    }

    let mut file =
        File::open(path).map_err(|source| ScanArtifactError::from_io("open-path", &source))?;
    let mut hasher = Sha256::new();
    let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| ScanArtifactError::from_io("read-bytes", &source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes.extend_from_slice(&buffer[..read]);
    }
    let digest = Sha256Digest::new(hasher.finalize().into());
    Ok((bytes, digest))
}

fn detector_result_json(result: &arbitraitor_analysis::DetectorResult) -> Value {
    json!({
        "detector": {
            "id": result.metadata.id,
            "version": result.metadata.version,
            "capabilities": result.metadata.capabilities,
            "is_local": result.metadata.is_local,
            "may_upload": result.metadata.may_upload,
            "is_deterministic": result.metadata.is_deterministic,
        },
        "status": detector_status_json(&result.status),
        "finding_count": result.finding_count,
    })
}

fn detector_status_json(status: &DetectorStatus) -> Value {
    match status {
        DetectorStatus::Ok => json!({"kind": "ok"}),
        DetectorStatus::Error(message) => json!({"kind": "error", "message": message}),
        DetectorStatus::Timeout => json!({"kind": "timeout"}),
    }
}

/// Tool that explains an existing verdict and finding set without reinterpreting untrusted text.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExplainVerdictTool;

impl McpToolHandler for ExplainVerdictTool {
    fn metadata(&self) -> McpTool {
        McpTool {
            name: "explain_verdict".to_owned(),
            description: "Explain a verdict from supplied findings while treating all finding data as untrusted.".to_owned(),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["findings", "verdict"],
                "properties": {
                    "findings": { "type": "array" },
                    "verdict": { "type": "string" }
                }
            }),
        }
    }

    fn handle(&self, params: Value, agent: &AgentIdentity) -> McpToolResponse {
        match explain_verdict(params, agent) {
            Ok(text) => McpToolResponse {
                content: vec![McpContent::Text { text }],
                is_error: false,
            },
            Err(error) => error_response(&error.to_string(), agent),
        }
    }

    fn capability(&self) -> McpCapability {
        McpCapability::Inspect
    }
}

fn fetch_url_once(request: FetchRequest) -> Result<FetchedArtifact, InspectUrlError> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = (|| {
            let runtime =
                tokio::runtime::Runtime::new().map_err(|error| InspectUrlError::Fetch {
                    message: error.to_string(),
                })?;
            runtime.block_on(async move {
                let mut sink = VecSink::new();
                let receipt =
                    HttpFetcher::new()
                        .fetch(request, &mut sink)
                        .await
                        .map_err(|error| InspectUrlError::Fetch {
                            message: error.to_string(),
                        })?;
                Ok(FetchedArtifact {
                    bytes: sink.into_bytes(),
                    receipt,
                })
            })
        })();
        let _ = tx.send(result);
    });
    rx.recv().map_err(|error| InspectUrlError::Fetch {
        message: error.to_string(),
    })?
}

struct FetchedArtifact {
    bytes: Vec<u8>,
    receipt: arbitraitor_fetch::FetchReceipt,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectUrlParams {
    url: String,
    sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchArtifactParams {
    url: String,
    sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanArtifactParams {
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryReceiptParams {
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestApprovalParams {
    sha256: String,
    plan: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunApprovedArtifactParams {
    sha256: String,
    approval_token: String,
    args: Option<Vec<String>>,
}

#[derive(Debug, Error)]
enum InspectUrlError {
    #[error("invalid inspect_url parameters: {0}")]
    Params(#[from] serde_json::Error),
    #[error("invalid sha256: {message}")]
    InvalidSha256 { message: String },
    #[error("fetch failed: {message}")]
    Fetch { message: String },
}

#[derive(Debug, Error)]
enum FetchArtifactError {
    #[error("invalid fetch_artifact parameters: {0}")]
    Params(#[from] serde_json::Error),
    #[error("invalid sha256: {message}")]
    InvalidSha256 { message: String },
    #[error("fetch failed: {message}")]
    Fetch { message: String },
}

#[derive(Debug, Error)]
enum ScanArtifactError {
    #[error("invalid scan_artifact parameters: {0}")]
    Params(#[from] serde_json::Error),
    #[error("scan_artifact path is a symlink, which is rejected")]
    SymlinkRejected,
    #[error("scan_artifact path is not a regular file")]
    NotAFile,
    #[error("scan_artifact size exceeded: attempted {attempted} bytes, maximum {max_bytes} bytes")]
    SizeExceeded { attempted: u64, max_bytes: u64 },
    #[error("scan_artifact I/O failure during {stage}: {message}")]
    Io {
        stage: &'static str,
        message: String,
    },
}

impl ScanArtifactError {
    fn from_io(stage: &'static str, error: &std::io::Error) -> Self {
        if error.kind() == IoErrorKind::NotFound {
            return Self::Io {
                stage,
                message: "path not found".to_owned(),
            };
        }
        Self::Io {
            stage,
            message: error.to_string(),
        }
    }
}

#[derive(Debug, Error)]
enum QueryReceiptError {
    #[error("invalid query_receipt parameters: {0}")]
    Params(#[from] serde_json::Error),
    #[error("invalid sha256: {message}")]
    InvalidSha256 { message: String },
}

#[derive(Debug, Error)]
enum RequestApprovalError {
    #[error("invalid request_approval parameters: {0}")]
    Params(#[from] serde_json::Error),
    #[error("invalid sha256: {message}")]
    InvalidSha256 { message: String },
    #[error("approval prompt failed: {0}")]
    Prompt(#[from] ApprovalPromptError),
    #[error("approval token failure: {0}")]
    Token(#[from] ApprovalTokenError),
    #[error("approval expiry overflowed system time")]
    TimeOverflow,
}

#[derive(Debug, Error)]
enum RunApprovedArtifactError {
    #[error("invalid run_approved_artifact parameters: {0}")]
    Params(#[from] serde_json::Error),
    #[error("invalid sha256: {message}")]
    InvalidSha256 { message: String },
    #[error("missing or invalid approval token: {0}")]
    Token(#[from] ApprovalTokenError),
    #[error("artifact was not found for approved digest")]
    ArtifactNotFound,
    #[error("artifact bytes do not match approved digest")]
    ArtifactDigestMismatch,
    #[error("runtime args are not part of the approved execution plan")]
    UnapprovedArguments,
    /// Artifact bytes were classified as a non-executable content type. The
    /// MCP-approved execution path gates the same way the CLI `run` pipeline
    /// does (ADR-0036, issue #612): only `ArtifactType::ShellScript(Posix | Bash)`
    /// can be approved for bash execution. Everything else — HTML, JSON, XML,
    /// archives, `GenericText`, `GenericBinary`, `PowerShellScript`,
    /// `PythonScript`, `JavaScript`, `ShellScript(Zsh)`, `Unknown` — fails
    /// closed with this error so an agent that approves an HTML artifact via
    /// HTML artifact via `request_approval` cannot then execute it via
    /// `run_approved_artifact` and have the bytes fed to `/bin/bash`.
    #[error(
        "artifact type {artifact_type:?} is not executable via the approved MCP run path; only shell scripts are runnable"
    )]
    NotExecutable {
        /// The classified [`ArtifactType`] that was rejected.
        artifact_type: ArtifactType,
    },
    #[error("script execution failed: {0}")]
    Exec(#[from] arbitraitor_exec::ExecError),
}

#[derive(Debug, Error)]
/// Errors returned while issuing or validating MCP approval tokens.
pub enum ApprovalTokenError {
    /// The token did not have the expected `v2.<payload>.<signature>` shape.
    #[error("token is malformed")]
    MalformedToken,
    /// The token HMAC signature did not verify.
    #[error("token signature is invalid")]
    InvalidSignature,
    /// The token was issued for a different artifact digest.
    #[error("token artifact digest does not match request")]
    ArtifactMismatch,
    /// The token was issued for a materially different execution context.
    #[error(
        "token execution context (interpreter, network policy, or policy snapshot) does not match the request"
    )]
    ContextMismatch,
    /// The token has expired.
    #[error("token is expired")]
    Expired,
    /// The token nonce has already been spent.
    #[error("token has already been used and cannot be replayed")]
    Reused,
    /// The HMAC signing key length was rejected.
    #[error("token signing key has an invalid length")]
    KeyLength,
    /// The nonce store lock or durable backing failed.
    #[error("token nonce store is poisoned")]
    NonceStorePoisoned,
    /// A system time was before the Unix epoch.
    #[error("token time is before Unix epoch")]
    TimeBeforeEpoch,
    /// The token schema version is unsupported.
    #[error("token schema version is unsupported")]
    UnsupportedSchema,
    /// Token payload JSON serialization or parsing failed.
    #[error("token serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    /// Token payload or signature hex decoding failed.
    #[error("token encoding failed: {0}")]
    Hex(#[from] hex::FromHexError),
}

/// Errors returned by [`run_stdio_server`].
#[derive(Debug, Error)]
pub enum StdioError {
    /// Standard I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization or deserialization failure.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

const JSONRPC_VERSION: &str = "2.0";
const MAX_LINE_LEN: usize = 1024 * 1024;

fn build_default_server() -> McpServer {
    let receipts = Arc::new(InMemoryReceiptStore::new()) as Arc<dyn ReceiptLookup>;

    let mut server = McpServer::new();
    server.register(Box::new(InspectUrlTool::new(AnalysisCoordinator::new())));
    server.register(Box::new(FetchArtifactTool::new()));
    server.register(Box::new(ScanArtifactTool::new(AnalysisCoordinator::new())));
    server.register(Box::new(QueryReceiptTool::new(receipts)));
    server.register(Box::new(ExplainVerdictTool));
    server
}

fn default_agent() -> AgentIdentity {
    AgentIdentity {
        integration: "stdio".to_owned(),
        agent_name: std::env::var("MCP_AGENT_NAME").unwrap_or_else(|_| "unknown".to_owned()),
        session_id: Uuid::new_v4().to_string(),
        workspace: std::env::current_dir()
            .ok()
            .map(|p| p.to_string_lossy().into_owned()),
    }
}

fn handle_request(server: &McpServer, request: &Value, agent: &AgentIdentity) -> Option<Value> {
    let id = request.get("id").cloned()?;
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let result = match method {
        "initialize" | "notifications/initialized" => json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": "arbitraitor",
                "version": env!("CARGO_PKG_VERSION")
            }
        }),
        "tools/list" => {
            let tools: Vec<Value> = server
                .list_tools()
                .iter()
                .map(|tool| {
                    json!({
                        "name": tool.name,
                        "description": tool.description,
                        "inputSchema": tool.input_schema
                    })
                })
                .collect();
            json!({ "tools": tools })
        }
        "tools/call" => {
            let name = request
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str);
            let params = request
                .get("params")
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(json!({}));

            match name {
                Some(tool_name) => match server.call_tool(tool_name, params, agent.clone()) {
                    Ok(response) => {
                        let content: Vec<Value> = response
                            .content
                            .iter()
                            .map(|c| match c {
                                McpContent::Text { text } => {
                                    json!({ "type": "text", "text": text })
                                }
                                McpContent::Json { json: val } => {
                                    json!({ "type": "text", "text": val.to_string() })
                                }
                            })
                            .collect();
                        json!({
                            "content": content,
                            "isError": response.is_error
                        })
                    }
                    Err(error) => {
                        return Some(json!({
                            "jsonrpc": JSONRPC_VERSION,
                            "id": id,
                            "error": { "code": -32602, "message": error.to_string() }
                        }));
                    }
                },
                None => {
                    return Some(json!({
                        "jsonrpc": JSONRPC_VERSION,
                        "id": id,
                        "error": { "code": -32602, "message": "missing 'name' in tools/call params" }
                    }));
                }
            }
        }
        _ => {
            return Some(json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": id,
                "error": { "code": -32601, "message": format!("unknown method: {method}") }
            }));
        }
    };

    Some(json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": id,
        "result": result
    }))
}

/// Runs the MCP server over stdio using JSON-RPC 2.0.
///
/// Reads line-delimited JSON requests from stdin and writes JSON-RPC
/// responses to stdout. Registers all built-in tools with default
/// configuration. Exits when stdin reaches EOF.
///
/// # Errors
///
/// Returns [`StdioError`] on I/O or JSON serialization failure.
pub fn run_stdio_server() -> Result<(), StdioError> {
    arbitraitor_core::privilege::refuse_root();
    let server = build_default_server();
    let agent = default_agent();
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();

    let mut reader = stdin.lock();
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line.len() > MAX_LINE_LEN {
            let response = json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": Value::Null,
                "error": { "code": -32600, "message": "request exceeds maximum line length" }
            });
            writeln!(stdout, "{response}")?;
            stdout.flush()?;
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(error) => {
                let response = json!({
                    "jsonrpc": JSONRPC_VERSION,
                    "id": Value::Null,
                    "error": { "code": -32700, "message": format!("parse error: {error}") }
                });
                writeln!(stdout, "{response}")?;
                stdout.flush()?;
                continue;
            }
        };
        if let Some(response) = handle_request(&server, &request, &agent) {
            writeln!(stdout, "{response}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic)]
#[path = "tests.rs"]
mod tests;
