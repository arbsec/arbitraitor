use super::*;
use arbitraitor_model::ids::Sha256Digest;

fn sample_digest() -> Sha256Digest {
    Sha256Digest::new([0xab; 32])
}

fn sample_inputs() -> ExecutionPlanInputs {
    ExecutionPlanInputs {
        artifact_sha256: sample_digest(),
        network_isolated: true,
        policy_snapshot_digest: "policy:abc".to_owned(),
        detector_snapshot_digest: "detector:def".to_owned(),
    }
}

fn valid_file() -> Result<ApprovalFile, ApprovalError> {
    ApprovalFile::for_bash_execution(&sample_inputs(), "human@terminal", 1_000, 9_999, "Prompt")
}

#[test]
fn valid_approval_passes_verification() -> Result<(), Box<dyn std::error::Error>> {
    let file = valid_file()?;
    file.verify(5_000)?;
    Ok(())
}

#[test]
fn schema_version_mismatch_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = valid_file()?;
    file.schema_version = 1;
    assert!(matches!(
        file.verify(5_000),
        Err(ApprovalError::UnsupportedSchema(1))
    ));
    Ok(())
}

#[test]
fn expired_approval_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let file = valid_file()?;
    assert!(matches!(file.verify(9_999), Err(ApprovalError::Expired)));
    assert!(matches!(file.verify(10_000), Err(ApprovalError::Expired)));
    Ok(())
}

#[test]
fn tampered_artifact_sha256_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = valid_file()?;
    file.artifact_sha256 = "0".repeat(64);
    assert!(matches!(
        file.verify(5_000),
        Err(ApprovalError::PlanDigestMismatch)
    ));
    Ok(())
}

#[test]
fn tampered_interpreter_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = valid_file()?;
    file.interpreter = "/bin/dash".to_owned();
    assert!(matches!(
        file.verify(5_000),
        Err(ApprovalError::PlanDigestMismatch)
    ));
    Ok(())
}

#[test]
fn tampered_interpreter_arguments_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = valid_file()?;
    file.interpreter_arguments = vec!["--norc".to_owned()];
    assert!(matches!(
        file.verify(5_000),
        Err(ApprovalError::PlanDigestMismatch)
    ));
    Ok(())
}

#[test]
fn tampered_environment_profile_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = valid_file()?;
    file.environment_profile_digest = "env:evil".to_owned();
    assert!(matches!(
        file.verify(5_000),
        Err(ApprovalError::PlanDigestMismatch)
    ));
    Ok(())
}

#[test]
fn tampered_network_isolated_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = valid_file()?;
    file.network_isolated = false;
    assert!(matches!(
        file.verify(5_000),
        Err(ApprovalError::PlanDigestMismatch)
    ));
    Ok(())
}

#[test]
fn tampered_policy_digest_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = valid_file()?;
    file.policy_snapshot_digest = "policy:evil".to_owned();
    assert!(matches!(
        file.verify(5_000),
        Err(ApprovalError::PlanDigestMismatch)
    ));
    Ok(())
}

#[test]
fn tampered_detector_digest_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = valid_file()?;
    file.detector_snapshot_digest = "detector:evil".to_owned();
    assert!(matches!(
        file.verify(5_000),
        Err(ApprovalError::PlanDigestMismatch)
    ));
    Ok(())
}

#[test]
fn tampered_plan_digest_itself_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = valid_file()?;
    file.plan_digest = "0".repeat(64);
    assert!(matches!(
        file.verify(5_000),
        Err(ApprovalError::PlanDigestMismatch)
    ));
    Ok(())
}

#[test]
fn tampered_nonce_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = valid_file()?;
    file.nonce = "different-nonce".to_owned();
    assert!(matches!(
        file.verify(5_000),
        Err(ApprovalError::PlanDigestMismatch)
    ));
    Ok(())
}

#[test]
fn changing_approver_does_not_invalidate_digest() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = valid_file()?;
    file.approver = "someone-else".to_owned();
    file.verify(5_000)?;
    Ok(())
}

#[test]
fn tampered_expiry_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = valid_file()?;
    file.expires_at = 99_999;
    assert!(matches!(
        file.verify(5_000),
        Err(ApprovalError::PlanDigestMismatch)
    ));
    Ok(())
}

#[test]
fn approval_round_trips_through_json() -> Result<(), Box<dyn std::error::Error>> {
    let file = valid_file()?;
    let json = serde_json::to_string_pretty(&file)?;
    let decoded: ApprovalFile = serde_json::from_str(&json)?;
    assert_eq!(decoded, file);
    Ok(())
}

#[test]
fn approval_rejects_unknown_json_fields() -> Result<(), Box<dyn std::error::Error>> {
    let file = valid_file()?;
    let mut json = serde_json::to_value(&file)?;
    json["rogue_field"] = serde_json::json!("evil");
    let result: Result<ApprovalFile, _> = serde_json::from_value(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn empty_approver_is_rejected() {
    let result = ApprovalFile::for_bash_execution(&sample_inputs(), "", 1, 2, "Pass");
    assert!(matches!(
        result,
        Err(ApprovalError::MissingField { field: "approver" })
    ));
}

#[test]
fn different_network_flag_produces_different_digest() -> Result<(), Box<dyn std::error::Error>> {
    let isolated = valid_file()?;
    let mut network_inputs = sample_inputs();
    network_inputs.network_isolated = false;
    let network = ApprovalFile::for_bash_execution(
        &network_inputs,
        "human@terminal",
        1_000,
        9_999,
        "Prompt",
    )?;
    assert_ne!(
        isolated.plan_digest, network.plan_digest,
        "network policy difference must produce a different digest"
    );
    Ok(())
}

#[test]
fn different_artifact_produces_different_digest() -> Result<(), Box<dyn std::error::Error>> {
    let a = valid_file()?;
    let mut inputs = sample_inputs();
    inputs.artifact_sha256 = Sha256Digest::new([0xcd; 32]);
    let b = ApprovalFile::for_bash_execution(&inputs, "human@terminal", 1_000, 9_999, "Prompt")?;
    assert_ne!(a.plan_digest, b.plan_digest);
    Ok(())
}
