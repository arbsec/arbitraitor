//! Evaluation context provided to the policy engine at decision time.

use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::origin::CallerOrigin;

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
///
/// Callers **must** populate the fields accurately before evaluating.
#[derive(Debug, Clone, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "EvalContext mirrors spec §23.1 policy input booleans for direct context.* field resolution"
)]
pub struct EvalContext {
    /// Operation mode being evaluated (spec §23.1.1).
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

    /// Origin class of the operation request (spec §23.1.1). Defaults to
    /// [`CallerOrigin::Unknown`] — the lowest trust class.
    pub caller_origin: CallerOrigin,
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

    /// Sets the caller-origin class (spec §23.1.1).
    #[must_use]
    pub fn with_caller_origin(mut self, origin: CallerOrigin) -> Self {
        self.caller_origin = origin;
        self
    }
}
