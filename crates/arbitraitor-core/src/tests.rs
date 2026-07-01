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
fn transition_to_released_rejects_blocking_verdict_bypass() -> Result<(), Box<dyn std::error::Error>>
{
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
