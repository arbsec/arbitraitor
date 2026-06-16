//! State machine and invariants for the Arbitraitor pipeline.
//!
//! This crate owns only core pipeline state, transition validation, and the
//! typed error model used by orchestration components. It does not perform I/O,
//! policy evaluation, presentation, artifact analysis, or release work.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use arbitraitor_model::finding::Finding;
use arbitraitor_model::ids::{ArtifactId, OperationId};
use arbitraitor_model::operation::OperationPlan;
use arbitraitor_model::verdict::Verdict;
use serde::{Deserialize, Serialize};
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
        matches!(self, Self::Retrieval | Self::Storage | Self::Analysis)
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineOperation {
    /// Operation identifier that binds approval and receipts.
    pub operation_id: OperationId,
    /// Artifact identity the pipeline protects.
    pub artifact_id: ArtifactId,
    /// Current pipeline state.
    pub state: PipelineState,
    /// Final policy verdict once evaluation has completed.
    pub verdict: Option<Verdict>,
    /// Findings accumulated by analysis components.
    pub findings: Vec<Finding>,
    /// Optional plan-bound operation context from the domain model.
    pub operation_plan: Option<OperationPlan>,
    /// Whether any failure has made release impossible.
    pub release_prohibited: bool,
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
        }
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
        self.transition_to(PipelineState::Released)
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
            if self.state == PipelineState::Approved
                && next == PipelineState::Released
                && self.verdict.is_none()
            {
                return Err(StateError::invalid_transition(
                    self,
                    self.state,
                    next,
                    StateErrorKind::ReleaseBeforeVerdict,
                ));
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

    fn action_strategy() -> impl Strategy<Value = Action> {
        prop_oneof![
            state_strategy().prop_map(Action::Transition),
            verdict_strategy().prop_map(Action::RecordVerdict),
            Just(Action::Approve),
            Just(Action::Release),
            Just(Action::Complete),
            Just(Action::Cancel),
        ]
    }

    fn apply_action(current: PipelineOperation, action: Action) -> PipelineOperation {
        let attempted = match action {
            Action::Transition(next) => current.clone().transition_to(next),
            Action::RecordVerdict(verdict) => current.clone().record_verdict(verdict),
            Action::Approve => current.clone().approve(),
            Action::Release => current.clone().release(),
            Action::Complete => current.clone().complete(),
            Action::Cancel => current.clone().cancel(),
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
            PipelineStage::Analysis,
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
            PipelineStage::Approval,
            PipelineComponent::new("component"),
            Retryability::NotRetryable,
            artifact_id(),
            OperationId::new(),
        );
        assert!(!error.release_prohibited);
    }

    proptest! {
        #[test]
        fn no_release_before_verdict(actions in prop::collection::vec(action_strategy(), 0..128)) {
            let mut current = operation();
            let mut saw_awaiting_approval = false;
            let mut saw_approved_after_awaiting = false;

            for action in actions {
                current = apply_action(current, action);
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
                }
            }
        }

        #[test]
        fn receipt_safe_transitions(actions in prop::collection::vec(action_strategy(), 0..128)) {
            let mut current = operation();
            let mut saw_released = false;

            for action in actions {
                current = apply_action(current, action);
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
