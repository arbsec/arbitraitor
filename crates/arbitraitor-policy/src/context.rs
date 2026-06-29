//! Evaluation context provided to the policy engine at decision time.

use arbitraitor_model::origin::CallerOrigin;

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
/// - `is_interactive = false` — prompts are upgraded to blocks.
/// - `is_https = false` — HTTPS-requiring policies will block.
/// - `is_private_network = false` — no SSRF assumption.
/// - `caller_origin = Unknown` — lowest trust class.
///
/// Callers **must** populate the fields accurately before evaluating.
#[derive(Debug, Clone, Default)]
pub struct EvalContext {
    /// Identified artifact type (e.g. `"shell-script"`, `"pe-executable"`).
    pub artifact_type: Option<String>,

    /// Source URL of the artifact.
    pub source_url: Option<String>,

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
