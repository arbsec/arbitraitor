//! Integration tests for mediated execution contexts.

use std::ffi::OsString;
use std::fs::File;
use std::process::Command;

use arbitraitor_exec::{
    EnvAllowlist, ExecError, ExecutionContext, ExecutionContextBuilder, ExecutionPolicy,
};
use arbitraitor_model::ids::{ArtifactId, OperationId, Sha256Digest};
use arbitraitor_model::operation::{
    CapabilityGrant, GrantedCapabilities, OperationPlan, OperationType,
};

fn plan() -> OperationPlan {
    OperationPlan {
        operation_id: OperationId::new(),
        artifact_id: ArtifactId(Sha256Digest::new([8; 32])),
        operation_type: OperationType::Execute,
        interpreter: Some("/bin/sh".to_owned()),
        arguments: vec!["-c".to_owned(), "true".to_owned()],
        environment_allowlist: Vec::new(),
        network_allowed: false,
        sandbox_enabled: true,
        expiry: None,
    }
}

fn grants() -> GrantedCapabilities {
    GrantedCapabilities::new(
        CapabilityGrant(false),
        CapabilityGrant(false),
        CapabilityGrant(true),
        CapabilityGrant(false),
    )
}

fn command_for_context(context: &ExecutionContext) -> Command {
    let mut command = Command::new(&context.command);
    command.args(&context.arguments);
    command.env_clear();
    command.envs(context.environment_iter());
    command.current_dir(&context.working_dir);
    command
}

#[test]
fn child_environment_contains_only_allowlisted_variables() -> Result<(), Box<dyn std::error::Error>>
{
    let mut policy = ExecutionPolicy {
        deny_running_as_root: false,
        ..ExecutionPolicy::default()
    };
    policy.environment_allowlist = EnvAllowlist::new(["LANG", "TERM"])?;
    let context = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy)
        .arguments(["-c", "env | sort"])
        .source_environment([
            ("LANG", "C.UTF-8"),
            ("TERM", "xterm-256color"),
            ("AWS_ACCESS_KEY_ID", "secret"),
            ("UNLISTED", "hidden"),
        ])
        .build()?;
    let output = command_for_context(&context).output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("HOME="));
    assert!(stdout.contains("LANG=C.UTF-8"));
    assert!(stdout.contains("PATH="));
    assert!(stdout.contains("TERM=xterm-256color"));
    assert!(!stdout.contains("AWS_ACCESS_KEY_ID"));
    assert!(!stdout.contains("UNLISTED"));
    Ok(())
}

#[test]
fn child_does_not_observe_extra_inherited_file_descriptors()
-> Result<(), Box<dyn std::error::Error>> {
    let context = ExecutionContextBuilder::new(plan(), grants())
        .policy(ExecutionPolicy {
            deny_running_as_root: false,
            ..ExecutionPolicy::default()
        })
        .arguments(["-c", "ls /proc/self/fd | wc -l"])
        .source_environment([] as [(&str, &str); 0])
        .build()?;

    let baseline_output = command_for_context(&context).output()?;
    assert!(baseline_output.status.success());
    let baseline: usize = String::from_utf8(baseline_output.stdout)?.trim().parse()?;

    // Open a file descriptor — Rust sets CLOEXEC by default, so the child
    // should NOT inherit it and the fd count should remain unchanged.
    let _parent_file = File::open("/dev/null")?;

    let after_output = command_for_context(&context).output()?;
    assert!(after_output.status.success());
    let after: usize = String::from_utf8(after_output.stdout)?.trim().parse()?;

    assert_eq!(
        baseline, after,
        "CLOEXEC fd leaked to child: baseline={baseline}, after_opening={after}"
    );
    Ok(())
}

#[test]
fn privilege_elevation_is_blocked_before_spawn() {
    let policy = ExecutionPolicy {
        deny_running_as_root: false,
        ..ExecutionPolicy::default()
    };
    let error = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy)
        .arguments([OsString::from("-c"), OsString::from("sudo id")])
        .source_environment([] as [(&str, &str); 0])
        .build()
        .err();
    assert!(matches!(
        error,
        Some(ExecError::PrivilegeElevationAttempt { .. })
    ));
}
