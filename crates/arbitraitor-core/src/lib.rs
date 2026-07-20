//! State machine and invariants for the Arbitraitor pipeline.
//!
//! This crate owns only core pipeline state, transition validation, and the
//! typed error model used by orchestration components. It does not perform I/O,
//! policy evaluation, presentation, artifact analysis, or release work.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod health;
pub mod metrics;
pub mod privilege;
pub mod renderer;
pub mod secret;

use arbitraitor_model::finding::Finding;
use arbitraitor_model::ids::{ArtifactId, OperationId};
use arbitraitor_model::operation::OperationPlan;
use arbitraitor_model::verdict::Verdict;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// A named component participating in a pipeline stage.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineComponent {
    /// Stable safe component name for diagnostics.
    pub name: String,
}

impl PipelineComponent {
    /// Creates a component identifier from a safe component name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Whether a failed operation can be retried without weakening policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Retryability {
    /// The failure may be transient and policy permits retrying the same stage.
    Retryable,
    /// The failure is deterministic or policy-prohibited and must not be retried blindly.
    NotRetryable,
}

impl Retryability {
    /// Returns `true` when retrying this failure is allowed.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Retryable)
    }
}

/// Security-relevant pipeline stage associated with a transition or error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PipelineStage {
    /// Operation was created but no artifact bytes have been retrieved.
    Created,
    /// Artifact retrieval is in progress.
    Retrieval,
    /// Immutable artifact storage is in progress or just completed.
    Storage,
    /// Artifact content identification is in progress or just completed.
    Identification,
    /// Artifact analysis is in progress.
    Analysis,
    /// Recursive payload expansion is in progress.
    Expansion,
    /// Policy evaluation is in progress.
    Evaluation,
    /// Plan-bound approval is required or being checked.
    Approval,
    /// Exact inspected bytes are being released.
    Release,
    /// Receipt completion is in progress.
    Receipt,
    /// The pipeline is in a terminal state.
    Terminal,
}

impl PipelineStage {
    /// Returns whether any error in this stage must prohibit later release.
    #[must_use]
    pub const fn release_prohibited_on_error(self) -> bool {
        matches!(
            self,
            Self::Retrieval
                | Self::Storage
                | Self::Identification
                | Self::Analysis
                | Self::Expansion
                | Self::Evaluation
                | Self::Approval
                | Self::Release
        )
    }
}

/// Durable state of an Arbitraitor pipeline operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PipelineState {
    /// Operation has been accepted but no retrieval has begun.
    Created,
    /// Primary artifact retrieval is running.
    Retrieving,
    /// Retrieved bytes have been stored immutably.
    Stored,
    /// Stored bytes have been identified.
    Identified,
    /// Required analysis is running.
    Analyzing,
    /// Recursive expansion is running.
    Expanding,
    /// Policy evaluation is running.
    Evaluating,
    /// Evaluation completed and plan-bound approval is required before release.
    AwaitingApproval,
    /// The evaluated plan has been approved.
    Approved,
    /// Exact inspected bytes have been released.
    Released,
    /// Release receipt has been completed.
    Completed,
    /// Policy blocked the operation and release is impossible.
    Blocked,
    /// A required stage failed and release is impossible.
    Failed,
    /// The operation was cancelled and release is impossible.
    Cancelled,
}

impl PipelineState {
    /// Returns `true` when this state cannot transition to any other state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Blocked | Self::Failed | Self::Cancelled | Self::Completed
        )
    }

    /// Returns `true` when this state irrevocably prevents release.
    #[must_use]
    pub const fn prohibits_release(self) -> bool {
        matches!(self, Self::Blocked | Self::Failed | Self::Cancelled)
    }

    /// Returns the diagnostic stage corresponding to this state.
    #[must_use]
    pub const fn stage(self) -> PipelineStage {
        match self {
            Self::Created => PipelineStage::Created,
            Self::Retrieving => PipelineStage::Retrieval,
            Self::Stored => PipelineStage::Storage,
            Self::Identified => PipelineStage::Identification,
            Self::Analyzing => PipelineStage::Analysis,
            Self::Expanding => PipelineStage::Expansion,
            Self::Evaluating => PipelineStage::Evaluation,
            Self::AwaitingApproval | Self::Approved => PipelineStage::Approval,
            Self::Released => PipelineStage::Release,
            Self::Blocked | Self::Failed | Self::Cancelled | Self::Completed => {
                PipelineStage::Terminal
            }
        }
    }
}

/// Reason a state-machine operation was rejected or failed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StateErrorKind {
    /// The requested transition is not allowed by the pipeline graph.
    InvalidTransition,
    /// A terminal state was asked to transition again.
    TerminalTransition,
    /// Release was requested before a verdict had been recorded.
    ReleaseBeforeVerdict,
    /// Verdict recording was requested before analysis was complete.
    VerdictBeforeAnalysisComplete,
    /// Analysis was requested before artifact storage and identification completed.
    AnalysisBeforeStorage,
    /// Completion was requested before release.
    CompletionBeforeRelease,
    /// A component reported a stage failure.
    ComponentFailure,
    /// Release was requested after an invariant made release impossible.
    ReleaseProhibited,
    /// Release was requested after a blocking verdict was recorded.
    BlockingVerdict,
}

impl core::fmt::Display for StateErrorKind {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTransition => "invalid pipeline transition",
            Self::TerminalTransition => "terminal pipeline state cannot transition",
            Self::ReleaseBeforeVerdict => "release requested before verdict",
            Self::VerdictBeforeAnalysisComplete => "verdict requested before analysis completed",
            Self::AnalysisBeforeStorage => "analysis requested before storage",
            Self::CompletionBeforeRelease => "completion requested before release",
            Self::ComponentFailure => "pipeline component failure",
            Self::ReleaseProhibited => "release prohibited by prior failure",
            Self::BlockingVerdict => "release prohibited by blocking verdict",
        })
    }
}

/// Typed state-machine error carrying security consequences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(deny_unknown_fields)]
#[error(
    "{kind} at {stage:?} in component {component:?} for artifact {artifact_id:?} \
     operation {operation_id:?}; retryable={retryability:?}; \
     release_prohibited={release_prohibited}"
)]
pub struct StateError {
    /// Machine-readable error kind.
    pub kind: StateErrorKind,
    /// Stage where the rejected operation or failure occurred.
    pub stage: PipelineStage,
    /// Component that requested the transition or reported failure.
    pub component: PipelineComponent,
    /// Whether the failed stage is retryable.
    pub retryability: Retryability,
    /// Artifact affected by this error.
    pub artifact_id: ArtifactId,
    /// Operation affected by this error.
    pub operation_id: OperationId,
    /// Whether this error irrevocably prohibits artifact release.
    pub release_prohibited: bool,
}

impl StateError {
    fn invalid_transition(
        operation: &PipelineOperation,
        from: PipelineState,
        to: PipelineState,
        kind: StateErrorKind,
    ) -> Self {
        let stage = from.stage();
        let error = Self {
            kind,
            stage,
            component: PipelineComponent::new("arbitraitor-core"),
            retryability: Retryability::NotRetryable,
            artifact_id: operation.artifact_id.clone(),
            operation_id: operation.operation_id,
            release_prohibited: stage.release_prohibited_on_error() || to.prohibits_release(),
        };
        tracing::warn!(?from, ?to, ?error, "pipeline transition rejected");
        error
    }

    /// Creates a component failure and enforces release-prohibition by stage.
    #[must_use]
    pub fn component_failure(
        stage: PipelineStage,
        component: PipelineComponent,
        retryability: Retryability,
        artifact_id: ArtifactId,
        operation_id: OperationId,
    ) -> Self {
        let error = Self {
            kind: StateErrorKind::ComponentFailure,
            stage,
            component,
            retryability,
            artifact_id,
            operation_id,
            release_prohibited: stage.release_prohibited_on_error(),
        };
        tracing::error!(?error, "pipeline component failure");
        error
    }
}

/// Serializable pipeline operation state and security-relevant context.
///
/// `PipelineOperation` is an immutable-by-value state machine: every transition
/// consumes the previous value and returns a new value. It contains no interior
/// mutability, does not spawn work, and derives thread-safety solely from its
/// fields. Callers that share an operation between threads must provide their
/// own synchronization and must serialize transitions so stale clones cannot be
/// released after a newer clone records a failure or blocking verdict.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineOperation {
    /// Operation identifier that binds approval and receipts.
    operation_id: OperationId,
    /// Artifact identity the pipeline protects.
    artifact_id: ArtifactId,
    /// Current pipeline state.
    state: PipelineState,
    /// Final policy verdict once evaluation has completed.
    verdict: Option<Verdict>,
    /// Findings accumulated by analysis components.
    findings: Vec<Finding>,
    /// Optional plan-bound operation context from the domain model.
    operation_plan: Option<OperationPlan>,
    /// Whether any failure has made release impossible.
    release_prohibited: bool,
    /// Whether a blocking verdict was ever recorded for this operation.
    has_blocking_verdict: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PipelineOperationWire {
    operation_id: OperationId,
    artifact_id: ArtifactId,
    state: PipelineState,
    verdict: Option<Verdict>,
    findings: Vec<Finding>,
    operation_plan: Option<OperationPlan>,
    release_prohibited: bool,
    #[serde(default)]
    has_blocking_verdict: bool,
}

impl<'de> Deserialize<'de> for PipelineOperation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PipelineOperationWire::deserialize(deserializer)?;
        let operation = Self {
            operation_id: wire.operation_id,
            artifact_id: wire.artifact_id,
            state: wire.state,
            verdict: wire.verdict,
            findings: wire.findings,
            operation_plan: wire.operation_plan,
            release_prohibited: wire.release_prohibited,
            has_blocking_verdict: wire.has_blocking_verdict
                || wire.verdict.is_some_and(verdict_prohibits_release),
        };
        operation
            .validate_invariants()
            .map_err(serde::de::Error::custom)?;
        Ok(operation)
    }
}

impl PipelineOperation {
    /// Creates a new operation in [`PipelineState::Created`].
    #[must_use]
    pub const fn new(operation_id: OperationId, artifact_id: ArtifactId) -> Self {
        Self {
            operation_id,
            artifact_id,
            state: PipelineState::Created,
            verdict: None,
            findings: Vec::new(),
            operation_plan: None,
            release_prohibited: false,
            has_blocking_verdict: false,
        }
    }

    /// Returns the operation identifier that binds approval and receipts.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the artifact identity the pipeline protects.
    #[must_use]
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Returns the current pipeline state.
    #[must_use]
    pub const fn state(&self) -> PipelineState {
        self.state
    }

    /// Returns the final policy verdict once evaluation has completed.
    #[must_use]
    pub const fn verdict(&self) -> Option<Verdict> {
        self.verdict
    }

    /// Returns accumulated analysis findings.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Returns the plan-bound operation context from the domain model.
    #[must_use]
    pub const fn operation_plan(&self) -> Option<&OperationPlan> {
        self.operation_plan.as_ref()
    }

    /// Returns whether any failure has made release impossible.
    #[must_use]
    pub const fn release_prohibited(&self) -> bool {
        self.release_prohibited
    }

    /// Returns whether a blocking verdict was ever recorded for this operation.
    #[must_use]
    pub const fn has_blocking_verdict(&self) -> bool {
        self.has_blocking_verdict
    }

    /// Attaches a plan-bound operation context.
    #[must_use]
    pub fn with_operation_plan(mut self, operation_plan: OperationPlan) -> Self {
        self.operation_plan = Some(operation_plan);
        self
    }

    /// Replaces accumulated analysis findings.
    #[must_use]
    pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = findings;
        self
    }

    /// Attempts a graph-only state transition.
    ///
    /// Use [`Self::record_verdict`] for `Evaluating -> AwaitingApproval`, because
    /// that edge must atomically attach the verdict that authorizes approval.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the transition violates pipeline invariants.
    pub fn transition_to(mut self, next: PipelineState) -> Result<Self, StateError> {
        self.validate_transition(next)?;
        let previous = self.state;
        self.state = next;
        self.release_prohibited |= next.prohibits_release();
        tracing::info!(?previous, ?next, operation_id = %self.operation_id, "pipeline transitioned");
        Ok(self)
    }

    /// Records a policy verdict after analysis and evaluation complete.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] unless the current state is [`PipelineState::Evaluating`].
    pub fn record_verdict(mut self, verdict: Verdict) -> Result<Self, StateError> {
        if self.state.is_terminal() {
            return Err(StateError::invalid_transition(
                &self,
                self.state,
                PipelineState::AwaitingApproval,
                StateErrorKind::TerminalTransition,
            ));
        }
        if self.state != PipelineState::Evaluating {
            return Err(StateError::invalid_transition(
                &self,
                self.state,
                PipelineState::AwaitingApproval,
                StateErrorKind::VerdictBeforeAnalysisComplete,
            ));
        }
        let previous = self.state;
        self.verdict = Some(verdict);
        if verdict_prohibits_release(verdict) {
            self.has_blocking_verdict = true;
            self.release_prohibited = true;
        }
        self.state = PipelineState::AwaitingApproval;
        tracing::info!(?previous, ?verdict, operation_id = %self.operation_id, "pipeline verdict recorded");
        Ok(self)
    }

    /// Approves an evaluated plan for release.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] unless the pipeline is awaiting approval with a verdict.
    pub fn approve(self) -> Result<Self, StateError> {
        if self.verdict.is_none() {
            return Err(StateError::invalid_transition(
                &self,
                self.state,
                PipelineState::Approved,
                StateErrorKind::ReleaseBeforeVerdict,
            ));
        }
        if self.has_blocking_verdict {
            return Err(StateError::invalid_transition(
                &self,
                self.state,
                PipelineState::Approved,
                StateErrorKind::BlockingVerdict,
            ));
        }
        self.transition_to(PipelineState::Approved)
    }

    /// Releases exact inspected bytes after approval.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when release is requested before a verdict and approval.
    pub fn release(self) -> Result<Self, StateError> {
        if self.verdict.is_none() {
            return Err(StateError::invalid_transition(
                &self,
                self.state,
                PipelineState::Released,
                StateErrorKind::ReleaseBeforeVerdict,
            ));
        }
        if self.has_blocking_verdict {
            return Err(StateError::invalid_transition(
                &self,
                self.state,
                PipelineState::Released,
                StateErrorKind::BlockingVerdict,
            ));
        }
        if self.release_prohibited {
            return Err(StateError::invalid_transition(
                &self,
                self.state,
                PipelineState::Released,
                StateErrorKind::ReleaseProhibited,
            ));
        }
        self.transition_to(PipelineState::Released)
    }

    /// Records a component failure and atomically updates operation state.
    #[must_use]
    pub fn component_failure(
        mut self,
        stage: PipelineStage,
        component: PipelineComponent,
        retryability: Retryability,
    ) -> (Self, StateError) {
        let error = StateError::component_failure(
            stage,
            component,
            retryability,
            self.artifact_id.clone(),
            self.operation_id,
        );
        self.release_prohibited |= error.release_prohibited;
        if error.release_prohibited && !self.state.is_terminal() {
            self.state = PipelineState::Failed;
        }
        (self, error)
    }

    /// Completes the operation receipt after release.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] unless the current state is [`PipelineState::Released`].
    pub fn complete(self) -> Result<Self, StateError> {
        self.transition_to(PipelineState::Completed)
    }

    /// Marks the operation blocked by policy from any non-terminal state.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the operation is already terminal.
    pub fn block(self) -> Result<Self, StateError> {
        self.transition_to(PipelineState::Blocked)
    }

    /// Marks the operation failed from any non-terminal state.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the operation is already terminal.
    pub fn fail(self) -> Result<Self, StateError> {
        self.transition_to(PipelineState::Failed)
    }

    /// Marks the operation cancelled from any non-terminal state.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the operation is already terminal.
    pub fn cancel(self) -> Result<Self, StateError> {
        self.transition_to(PipelineState::Cancelled)
    }

    fn validate_transition(&self, next: PipelineState) -> Result<(), StateError> {
        if self.state.is_terminal() {
            return Err(StateError::invalid_transition(
                self,
                self.state,
                next,
                StateErrorKind::TerminalTransition,
            ));
        }

        if matches!(
            next,
            PipelineState::Blocked | PipelineState::Failed | PipelineState::Cancelled
        ) {
            return Ok(());
        }

        let valid = matches!(
            (self.state, next),
            (PipelineState::Created, PipelineState::Retrieving)
                | (PipelineState::Retrieving, PipelineState::Stored)
                | (PipelineState::Stored, PipelineState::Identified)
                | (PipelineState::Identified, PipelineState::Analyzing)
                | (PipelineState::Analyzing, PipelineState::Expanding)
                | (PipelineState::Expanding, PipelineState::Evaluating)
                | (PipelineState::AwaitingApproval, PipelineState::Approved)
                | (PipelineState::Approved, PipelineState::Released)
                | (PipelineState::Released, PipelineState::Completed)
        );

        if valid {
            if self.state == PipelineState::Approved && next == PipelineState::Released {
                if self.verdict.is_none() {
                    return Err(StateError::invalid_transition(
                        self,
                        self.state,
                        next,
                        StateErrorKind::ReleaseBeforeVerdict,
                    ));
                }
                if self.has_blocking_verdict {
                    return Err(StateError::invalid_transition(
                        self,
                        self.state,
                        next,
                        StateErrorKind::BlockingVerdict,
                    ));
                }
                if self.release_prohibited {
                    return Err(StateError::invalid_transition(
                        self,
                        self.state,
                        next,
                        StateErrorKind::ReleaseProhibited,
                    ));
                }
            }
            return Ok(());
        }

        Err(StateError::invalid_transition(
            self,
            self.state,
            next,
            transition_error_kind(self.state, next),
        ))
    }

    fn validate_invariants(&self) -> Result<(), &'static str> {
        if self.state.prohibits_release() && !self.release_prohibited {
            return Err("release-prohibited terminal states must set release_prohibited");
        }
        if matches!(
            self.state,
            PipelineState::AwaitingApproval | PipelineState::Approved
        ) && self.verdict.is_none()
        {
            return Err("approval states require a recorded verdict");
        }
        if matches!(
            self.state,
            PipelineState::Released | PipelineState::Completed
        ) && self.verdict.is_none()
        {
            return Err("released states require a recorded verdict");
        }
        if matches!(
            self.state,
            PipelineState::Released | PipelineState::Completed
        ) && (self.release_prohibited || self.has_blocking_verdict)
        {
            return Err("released states cannot have release-prohibition markers");
        }
        if self.verdict.is_some_and(verdict_prohibits_release)
            && (!self.has_blocking_verdict || !self.release_prohibited)
        {
            return Err("blocking verdicts must persist release-prohibition markers");
        }
        Ok(())
    }
}

const fn verdict_prohibits_release(verdict: Verdict) -> bool {
    matches!(
        verdict,
        Verdict::Block | Verdict::Error | Verdict::Incomplete
    )
}

fn transition_error_kind(from: PipelineState, to: PipelineState) -> StateErrorKind {
    match (from, to) {
        (_, PipelineState::Released) => StateErrorKind::ReleaseBeforeVerdict,
        (_, PipelineState::AwaitingApproval) => StateErrorKind::VerdictBeforeAnalysisComplete,
        (_, PipelineState::Analyzing) => StateErrorKind::AnalysisBeforeStorage,
        (_, PipelineState::Completed) => StateErrorKind::CompletionBeforeRelease,
        _ => StateErrorKind::InvalidTransition,
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
