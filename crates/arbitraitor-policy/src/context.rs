//! Evaluation context provided to the policy engine at decision time.

use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::origin::CallerOrigin;
use serde::{Deserialize, Serialize};

/// Ingress-envelope admission context attached to an evaluation.
///
/// Carries the fields of an external event envelope (e.g. a CI webhook
/// delivery) that policy admission rules reason about via `ingress.*` field
/// paths. Populated only when the operation arrived through an authenticated
/// ingress channel; every optional field that is absent resolves to
/// `FieldValue::Unavailable` at evaluation time, which triggers the
/// configured fail-closed behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressContext {
    /// Event type of the ingress envelope (e.g. `"push"`, `"pull_request"`).
    pub event_type: String,

    /// Repository the event targets, in `owner/name` form.
    pub repository: String,

    /// Head commit SHA referenced by the event, when the event carries one.
    pub head_sha: Option<String>,

    /// Unique delivery identifier assigned by the ingress transport.
    pub delivery_id: String,

    /// Run identifier for workflow-run style events, when present.
    pub run_id: Option<String>,

    /// Attempt counter for re-executed runs, when present.
    pub attempt: Option<u32>,

    /// Identity of the node that accepted the envelope, when attested.
    pub node_identity: Option<String>,

    /// Size of the ingress payload in bytes.
    pub payload_size: u64,
}

/// Operation mode requested for this policy evaluation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OperationMode {
    /// Inspect-only analysis; no execution mediation or containment requested.
    #[default]
    Inspect,
    /// Mediated operation where Arbitraitor brokers access to the artifact.
    Mediated,
    /// Contained execution in an Arbitraitor-controlled sandbox.
    Contained,
}

impl OperationMode {
    /// Returns the canonical policy-field representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Mediated => "mediated",
            Self::Contained => "contained",
        }
    }
}

/// Aggregate detector availability for this policy evaluation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DetectorHealth {
    /// Every detector required for this evaluation reported healthy.
    AllHealthy,
    /// At least one required detector reported unhealthy.
    SomeUnhealthy,
    /// No detector health signal was available.
    #[default]
    None,
}

impl DetectorHealth {
    /// Returns the canonical policy-field representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllHealthy => "all-healthy",
            Self::SomeUnhealthy => "some-unhealthy",
            Self::None => "none",
        }
    }
}

/// Runtime context describing the operation being evaluated.
///
/// The context carries information that is not part of any single finding —
/// transport properties, artifact metadata, and whether a human can be
/// prompted for a decision.
///
/// # Defaults (fail-closed)
///
/// The [`Default`](EvalContext::default) implementation assumes the safest
/// posture:
///
/// - `operation_mode = Inspect` — no execution privileges assumed.
/// - `is_interactive = false` — prompts are upgraded to blocks.
/// - `is_https = false` — HTTPS-requiring policies will block.
/// - `is_private_network = false` — no SSRF assumption.
/// - `provenance_verified = false` — unsigned/unverified until proven.
/// - `detector_health = None` — no detector health signal available.
/// - `recursive_graph_complete = false` — recursive dependency graph incomplete.
/// - `execution_network = false` — no execution-time network grant.
/// - `caller_origin = Unknown` — lowest trust class.
/// - `ingress = None` — no ingress envelope; `ingress.*` fields unavailable.
///
/// Callers **must** populate the fields accurately before evaluating.
#[derive(Debug, Clone, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "EvalContext mirrors policy input booleans for direct context.* field resolution"
)]
pub struct EvalContext {
    /// Operation mode being evaluated.
    pub operation_mode: OperationMode,

    /// Artifact SHA-256 digest, when identity is known.
    pub artifact_digest: Option<Sha256Digest>,

    /// Identified artifact type (e.g. `"shell-script"`, `"pe-executable"`).
    pub artifact_type: Option<String>,

    /// Source URL of the artifact.
    pub source_url: Option<String>,

    /// Redirect hop URLs observed while retrieving the artifact.
    pub redirect_chain: Vec<String>,

    /// Whether provenance verification succeeded.
    pub provenance_verified: bool,

    /// Verified provenance signer identity, when available.
    pub provenance_signer: Option<String>,

    /// Total detector findings available to policy evaluation.
    pub findings_count: usize,

    /// Number of detector findings with block-equivalent severity.
    pub block_findings_count: usize,

    /// Intelligence match identifiers associated with the artifact.
    pub intel_matches: Vec<String>,

    /// Aggregate detector health for the evaluation.
    pub detector_health: DetectorHealth,

    /// Whether recursive artifact/dependency graph analysis completed.
    pub recursive_graph_complete: bool,

    /// Interpreter path selected for execution, when applicable.
    pub execution_interpreter: Option<String>,

    /// Whether execution-time network access is granted.
    pub execution_network: bool,

    /// Whether a human is available to answer an interactive prompt.
    pub is_interactive: bool,

    /// Whether the transport used HTTPS (or equivalent secure transport).
    pub is_https: bool,

    /// Whether the resolved endpoint is on a private / loopback / link-local
    /// network.
    pub is_private_network: bool,

    /// Origin class of the operation request. Defaults to
    /// [`CallerOrigin::Unknown`] — the lowest trust class.
    pub caller_origin: CallerOrigin,

    /// Ingress-envelope admission context for externally delivered events.
    /// `None` means no authenticated ingress envelope is attached and every
    /// `ingress.*` field resolves to `FieldValue::Unavailable`, triggering
    /// the configured fail-closed behaviour.
    pub ingress: Option<IngressContext>,
}

impl EvalContext {
    /// Creates a context with `is_interactive` set and all other fields at
    /// their fail-closed defaults.
    #[must_use]
    pub fn new(is_interactive: bool) -> Self {
        Self {
            is_interactive,
            ..Self::default()
        }
    }

    /// Sets the artifact type.
    #[must_use]
    pub fn with_artifact_type(mut self, artifact_type: impl Into<String>) -> Self {
        self.artifact_type = Some(artifact_type.into());
        self
    }

    /// Sets the source URL.
    #[must_use]
    pub fn with_source_url(mut self, source_url: impl Into<String>) -> Self {
        self.source_url = Some(source_url.into());
        self
    }

    /// Sets whether HTTPS was used.
    #[must_use]
    pub fn with_https(mut self, is_https: bool) -> Self {
        self.is_https = is_https;
        self
    }

    /// Sets whether the endpoint is on a private network.
    #[must_use]
    pub fn with_private_network(mut self, is_private_network: bool) -> Self {
        self.is_private_network = is_private_network;
        self
    }

    /// Sets the caller-origin class.
    #[must_use]
    pub fn with_caller_origin(mut self, origin: CallerOrigin) -> Self {
        self.caller_origin = origin;
        self
    }

    /// Sets the ingress-envelope admission context.
    #[must_use]
    pub fn with_ingress(mut self, context: Option<IngressContext>) -> Self {
        self.ingress = context;
        self
    }
}
