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
mod tests {
    use super::*;
    use arbitraitor_model::ids::Sha256Digest;
    use proptest::prelude::*;

    #[derive(Debug, Clone, Copy)]
    enum Action {
        Transition(PipelineState),
        RecordVerdict(Verdict),
        Approve,
        Release,
        Complete,
        Cancel,
        ComponentFailure(PipelineStage),
    }

    fn artifact_id() -> ArtifactId {
        ArtifactId(Sha256Digest::new([0x30; 32]))
    }

    fn operation() -> PipelineOperation {
        PipelineOperation::new(OperationId::new(), artifact_id())
    }

    fn evaluated_operation() -> Result<PipelineOperation, StateError> {
        operation()
            .transition_to(PipelineState::Retrieving)?
            .transition_to(PipelineState::Stored)?
            .transition_to(PipelineState::Identified)?
            .transition_to(PipelineState::Analyzing)?
            .transition_to(PipelineState::Expanding)?
            .transition_to(PipelineState::Evaluating)
    }

    fn released_operation() -> Result<PipelineOperation, StateError> {
        evaluated_operation()?
            .record_verdict(Verdict::Prompt)?
            .approve()?
            .release()
    }

    fn state_strategy() -> impl Strategy<Value = PipelineState> {
        prop_oneof![
            Just(PipelineState::Created),
            Just(PipelineState::Retrieving),
            Just(PipelineState::Stored),
            Just(PipelineState::Identified),
            Just(PipelineState::Analyzing),
            Just(PipelineState::Expanding),
            Just(PipelineState::Evaluating),
            Just(PipelineState::AwaitingApproval),
            Just(PipelineState::Approved),
            Just(PipelineState::Released),
            Just(PipelineState::Completed),
            Just(PipelineState::Blocked),
            Just(PipelineState::Failed),
            Just(PipelineState::Cancelled),
        ]
    }

    fn verdict_strategy() -> impl Strategy<Value = Verdict> {
        prop_oneof![
            Just(Verdict::Pass),
            Just(Verdict::Warn),
            Just(Verdict::Prompt),
            Just(Verdict::Block),
            Just(Verdict::Error),
            Just(Verdict::Incomplete),
        ]
    }

    fn stage_strategy() -> impl Strategy<Value = PipelineStage> {
        prop_oneof![
            Just(PipelineStage::Created),
            Just(PipelineStage::Retrieval),
            Just(PipelineStage::Storage),
            Just(PipelineStage::Identification),
            Just(PipelineStage::Analysis),
            Just(PipelineStage::Expansion),
            Just(PipelineStage::Evaluation),
            Just(PipelineStage::Approval),
            Just(PipelineStage::Release),
            Just(PipelineStage::Receipt),
            Just(PipelineStage::Terminal),
        ]
    }

    fn action_strategy() -> impl Strategy<Value = Action> {
        prop_oneof![
            state_strategy().prop_map(Action::Transition),
            verdict_strategy().prop_map(Action::RecordVerdict),
            Just(Action::Approve),
            Just(Action::Release),
            Just(Action::Complete),
            Just(Action::Cancel),
            stage_strategy().prop_map(Action::ComponentFailure),
        ]
    }

    const fn state_rank(state: PipelineState) -> u8 {
        match state {
            PipelineState::Created => 0,
            PipelineState::Retrieving => 1,
            PipelineState::Stored => 2,
            PipelineState::Identified => 3,
            PipelineState::Analyzing => 4,
            PipelineState::Expanding => 5,
            PipelineState::Evaluating => 6,
            PipelineState::AwaitingApproval => 7,
            PipelineState::Approved => 8,
            PipelineState::Released => 9,
            PipelineState::Completed
            | PipelineState::Blocked
            | PipelineState::Failed
            | PipelineState::Cancelled => 10,
        }
    }

    fn apply_action(current: PipelineOperation, action: Action) -> PipelineOperation {
        let attempted = match action {
            Action::Transition(next) => current.clone().transition_to(next),
            Action::RecordVerdict(verdict) => current.clone().record_verdict(verdict),
            Action::Approve => current.clone().approve(),
            Action::Release => current.clone().release(),
            Action::Complete => current.clone().complete(),
            Action::Cancel => current.clone().cancel(),
            Action::ComponentFailure(stage) => {
                let (next, _error) = current.clone().component_failure(
                    stage,
                    PipelineComponent::new("test"),
                    Retryability::NotRetryable,
                );
                return next;
            }
        };
        match attempted {
            Ok(next) => next,
            Err(_error) => current,
        }
    }

    #[test]
    fn happy_path_reaches_completed() -> Result<(), Box<dyn std::error::Error>> {
        let completed = released_operation()?.complete()?;
        assert_eq!(completed.state, PipelineState::Completed);
        assert_eq!(completed.verdict, Some(Verdict::Prompt));
        Ok(())
    }

    #[test]
    fn direct_release_before_verdict_is_rejected() {
        let error = operation().release().err().unwrap_or_else(|| {
            StateError::component_failure(
                PipelineStage::Release,
                PipelineComponent::new("test"),
                Retryability::NotRetryable,
                artifact_id(),
                OperationId::new(),
            )
        });
        assert_eq!(error.kind, StateErrorKind::ReleaseBeforeVerdict);
        assert!(!error.release_prohibited);
    }

    #[test]
    fn verdict_before_analysis_is_rejected() {
        let error = operation()
            .record_verdict(Verdict::Pass)
            .err()
            .unwrap_or_else(|| {
                StateError::component_failure(
                    PipelineStage::Evaluation,
                    PipelineComponent::new("test"),
                    Retryability::NotRetryable,
                    artifact_id(),
                    OperationId::new(),
                )
            });
        assert_eq!(error.kind, StateErrorKind::VerdictBeforeAnalysisComplete);
    }

    #[test]
    fn analysis_before_storage_is_rejected() {
        let error = operation()
            .transition_to(PipelineState::Analyzing)
            .err()
            .unwrap_or_else(|| {
                StateError::component_failure(
                    PipelineStage::Analysis,
                    PipelineComponent::new("test"),
                    Retryability::NotRetryable,
                    artifact_id(),
                    OperationId::new(),
                )
            });
        assert_eq!(error.kind, StateErrorKind::AnalysisBeforeStorage);
    }

    #[test]
    fn terminal_states_cannot_transition_out() -> Result<(), Box<dyn std::error::Error>> {
        for terminal in [
            PipelineState::Blocked,
            PipelineState::Failed,
            PipelineState::Cancelled,
            PipelineState::Completed,
        ] {
            let operation = operation()
                .transition_to(terminal)
                .or_else(|_error| released_operation()?.complete())?;
            let error = operation.transition_to(PipelineState::Retrieving).err();
            assert!(matches!(
                error.map(|value| value.kind),
                Some(StateErrorKind::TerminalTransition)
            ));
        }
        Ok(())
    }

    #[test]
    fn component_failure_sets_release_prohibited_for_critical_stages() {
        for stage in [
            PipelineStage::Retrieval,
            PipelineStage::Storage,
            PipelineStage::Identification,
            PipelineStage::Analysis,
            PipelineStage::Expansion,
            PipelineStage::Evaluation,
            PipelineStage::Approval,
            PipelineStage::Release,
        ] {
            let error = StateError::component_failure(
                stage,
                PipelineComponent::new("component"),
                Retryability::Retryable,
                artifact_id(),
                OperationId::new(),
            );
            assert!(error.release_prohibited);
        }
    }

    #[test]
    fn component_failure_does_not_overstate_other_stages() {
        let error = StateError::component_failure(
            PipelineStage::Created,
            PipelineComponent::new("component"),
            Retryability::NotRetryable,
            artifact_id(),
            OperationId::new(),
        );
        assert!(!error.release_prohibited);
    }

    #[test]
    fn blocking_verdict_permanently_prevents_release() -> Result<(), Box<dyn std::error::Error>> {
        for verdict in [Verdict::Block, Verdict::Error, Verdict::Incomplete] {
            let blocked = evaluated_operation()?.record_verdict(verdict)?;

            assert!(blocked.has_blocking_verdict);
            assert!(blocked.release_prohibited);
            assert_eq!(
                blocked.release().err().map(|error| error.kind),
                Some(StateErrorKind::BlockingVerdict)
            );
        }
        Ok(())
    }

    #[test]
    fn deserialized_released_state_requires_verdict_and_no_release_prohibition() {
        let invalid = PipelineOperation {
            operation_id: OperationId::new(),
            artifact_id: artifact_id(),
            state: PipelineState::Released,
            verdict: None,
            findings: Vec::new(),
            operation_plan: None,
            release_prohibited: false,
            has_blocking_verdict: false,
        };

        assert!(invalid.validate_invariants().is_err());

        let invalid = PipelineOperation {
            verdict: Some(Verdict::Block),
            release_prohibited: true,
            has_blocking_verdict: true,
            ..invalid
        };

        assert!(invalid.validate_invariants().is_err());
    }

    #[test]
    fn release_prohibited_flag_prevents_release() -> Result<(), Box<dyn std::error::Error>> {
        let mut operation = evaluated_operation()?
            .record_verdict(Verdict::Pass)?
            .approve()?;
        operation.release_prohibited = true;

        assert_eq!(
            operation.release().err().map(|error| error.kind),
            Some(StateErrorKind::ReleaseProhibited)
        );
        Ok(())
    }

    #[test]
    fn transition_to_released_rejects_blocking_verdict_bypass()
    -> Result<(), Box<dyn std::error::Error>> {
        // Exploit path: record a blocking verdict, then attempt to bypass
        // release() by calling transition_to(Released) directly.
        let awaiting_approval = evaluated_operation()?.record_verdict(Verdict::Block)?;
        assert!(awaiting_approval.has_blocking_verdict);
        assert!(awaiting_approval.release_prohibited);

        // approve() must reject a blocking verdict (defense in depth).
        assert_eq!(
            awaiting_approval
                .clone()
                .approve()
                .err()
                .map(|error| error.kind),
            Some(StateErrorKind::BlockingVerdict),
        );

        // Even if an Approved state with a blocking verdict is constructed
        // (simulating a bypass of approve()), transition_to(Released) must
        // still reject.
        let mut bypassed = awaiting_approval;
        bypassed.state = PipelineState::Approved;
        assert_eq!(
            bypassed
                .transition_to(PipelineState::Released)
                .err()
                .map(|error| error.kind),
            Some(StateErrorKind::BlockingVerdict),
        );
        Ok(())
    }

    #[test]
    fn transition_to_released_rejects_release_prohibited_bypass()
    -> Result<(), Box<dyn std::error::Error>> {
        // Simulate a component failure that sets release_prohibited without a
        // blocking verdict, then attempt to bypass release().
        let mut bypassed = evaluated_operation()?
            .record_verdict(Verdict::Pass)?
            .approve()?;
        bypassed.release_prohibited = true;
        assert_eq!(
            bypassed
                .transition_to(PipelineState::Released)
                .err()
                .map(|error| error.kind),
            Some(StateErrorKind::ReleaseProhibited),
        );
        Ok(())
    }

    #[test]
    fn component_failure_atomically_fails_operation_and_blocks_release()
    -> Result<(), Box<dyn std::error::Error>> {
        let approved = evaluated_operation()?
            .record_verdict(Verdict::Pass)?
            .approve()?;
        let (operation, error) = approved.component_failure(
            PipelineStage::Evaluation,
            PipelineComponent::new("policy-engine"),
            Retryability::NotRetryable,
        );

        assert_eq!(error.kind, StateErrorKind::ComponentFailure);
        assert!(error.release_prohibited);
        assert_eq!(operation.state, PipelineState::Failed);
        assert!(operation.release_prohibited);
        assert_eq!(
            operation.release().err().map(|error| error.kind),
            Some(StateErrorKind::ReleaseProhibited)
        );
        Ok(())
    }

    proptest! {
        #[test]
        fn no_release_before_verdict(actions in prop::collection::vec(action_strategy(), 0..128)) {
            let mut current = operation();
            let mut saw_awaiting_approval = false;
            let mut saw_approved_after_awaiting = false;
            let mut blocking_verdict_recorded = false;

            for action in actions {
                current = apply_action(current, action);
                blocking_verdict_recorded |= current.has_blocking_verdict;
                if current.state == PipelineState::AwaitingApproval && current.verdict.is_some() {
                    saw_awaiting_approval = true;
                }
                if saw_awaiting_approval && current.state == PipelineState::Approved {
                    saw_approved_after_awaiting = true;
                }
                if current.state == PipelineState::Released {
                    prop_assert!(current.verdict.is_some());
                    prop_assert!(saw_awaiting_approval);
                    prop_assert!(saw_approved_after_awaiting);
                    prop_assert!(!blocking_verdict_recorded);
                    prop_assert!(!current.release_prohibited);
                }
            }
        }

        #[test]
        fn receipt_safe_transitions(actions in prop::collection::vec(action_strategy(), 0..128)) {
            let mut current = operation();
            let mut saw_released = false;

            for action in actions {
                let previous = current.clone();
                current = apply_action(current, action);
                prop_assert!(state_rank(current.state) >= state_rank(previous.state));
                if previous.state == PipelineState::Released {
                    prop_assert!(matches!(current.state, PipelineState::Released | PipelineState::Completed));
                }
                saw_released |= current.state == PipelineState::Released;
                if current.state == PipelineState::Completed {
                    prop_assert!(saw_released);
                }
            }
        }

        #[test]
        fn invalid_transition_rejection(from in state_strategy(), to in state_strategy()) {
            let mut current = operation();
            current.state = from;
            current.verdict = if from == PipelineState::Approved {
                Some(Verdict::Pass)
            } else {
                None
            };
            current.release_prohibited = from.prohibits_release();
            current.has_blocking_verdict = false;

            let result = current.clone().transition_to(to);
            if result.is_err() {
                let error = result.err();
                prop_assert!(error.is_some());
            } else {
                let next = result.map(|value| value.state);
                prop_assert_eq!(next, Ok(to));
            }
        }

        #[test]
        fn cancelled_from_any_non_terminal_state(state in state_strategy()) {
            let mut current = operation();
            current.state = state;

            let result = current.cancel();
            if state.is_terminal() {
                prop_assert!(result.is_err());
            } else {
                prop_assert_eq!(result.map(|value| value.state), Ok(PipelineState::Cancelled));
            }
        }
    }
}
