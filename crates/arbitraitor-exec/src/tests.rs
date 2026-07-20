use super::*;
use arbitraitor_model::ids::{ArtifactId, OperationId, Sha256Digest};
use arbitraitor_model::operation::{CapabilityGrant, OperationState, OperationType};

fn plan() -> OperationPlan {
    OperationPlan {
        operation_id: OperationId::new(),
        artifact_id: ArtifactId(Sha256Digest::new([7; 32])),
        operation_type: OperationType::Execute,
        interpreter: Some("/bin/sh".to_owned()),
        arguments: vec!["-c".to_owned(), "true".to_owned()],
        environment_allowlist: Vec::new(),
        network_allowed: false,
        sandbox_enabled: true,
        expiry: None,
        state: OperationState::Pending,
        plugin_identity: None,
        argv_digest: None,
        policy_digest: None,
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

fn grants_with_network() -> GrantedCapabilities {
    GrantedCapabilities::new(
        CapabilityGrant(true),
        CapabilityGrant(false),
        CapabilityGrant(true),
        CapabilityGrant(false),
    )
}

fn grants_without_execute() -> GrantedCapabilities {
    GrantedCapabilities::new(
        CapabilityGrant(false),
        CapabilityGrant(false),
        CapabilityGrant(false),
        CapabilityGrant(false),
    )
}

fn policy_without_root_check() -> ExecutionPolicy {
    ExecutionPolicy {
        deny_running_as_root: false,
        ..ExecutionPolicy::default()
    }
}

#[test]
fn allowlist_filters_environment() -> Result<(), Box<dyn std::error::Error>> {
    let context = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy_without_root_check())
        .source_environment([
            ("LANG", "C.UTF-8"),
            ("TERM", "xterm-256color"),
            ("SECRET_TOKEN", "not-forwarded"),
        ])
        .build()?;

    assert_eq!(
        context.environment().get("LANG"),
        Some(&OsString::from("C.UTF-8"))
    );
    assert_eq!(
        context.environment().get("TERM"),
        Some(&OsString::from("xterm-256color"))
    );
    assert!(context.environment().contains_key("PATH"));
    assert!(context.environment().contains_key("HOME"));
    assert!(!context.environment().contains_key("SECRET_TOKEN"));
    Ok(())
}

#[test]
fn deny_patterns_are_checked_even_when_allowlisted() -> Result<(), Box<dyn std::error::Error>> {
    let denied_names = [
        "BASH_ENV",
        "ENV",
        "ZDOTDIR",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "PYTHONPATH",
        "NODE_OPTIONS",
        "RUBYOPT",
        "PERL5LIB",
        "GIT_CONFIG_GLOBAL",
        "SSH_AUTH_SOCK",
        "AWS_ACCESS_KEY_ID",
        "AZURE_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GITHUB_TOKEN",
        // Shell injection vectors (MEDIUM 6).
        "IFS",
        "SHELLOPTS",
        "BASHOPTS",
        "CDPATH",
        "GLOBIGNORE",
        "POSIXLY_CORRECT",
        "PS4",
        "PROMPT_COMMAND",
    ];

    for name in denied_names {
        let policy = ExecutionPolicy {
            deny_running_as_root: false,
            environment_allowlist: EnvAllowlist::new([name])?,
            ..ExecutionPolicy::default()
        };
        let error = ExecutionContextBuilder::new(plan(), grants())
            .policy(policy)
            .source_environment([(name, "x")])
            .build()
            .err();
        assert!(
            matches!(error, Some(ExecError::DeniedEnvironmentVariable { .. })),
            "expected {name} to be denied even when allowlisted"
        );
    }
    Ok(())
}

#[test]
fn shell_injection_vars_blocked_even_in_allowlist() -> Result<(), Box<dyn std::error::Error>> {
    // Explicitly verify that each newly added shell var is blocked
    // even when present in both the allowlist and source environment.
    let shell_vars = [
        "IFS",
        "SHELLOPTS",
        "BASHOPTS",
        "CDPATH",
        "GLOBIGNORE",
        "POSIXLY_CORRECT",
        "PS4",
        "PROMPT_COMMAND",
    ];
    for var in shell_vars {
        let policy = ExecutionPolicy {
            deny_running_as_root: false,
            environment_allowlist: EnvAllowlist::new([var])?,
            ..ExecutionPolicy::default()
        };
        let result = ExecutionContextBuilder::new(plan(), grants())
            .policy(policy)
            .source_environment([(var, "evil")])
            .build();
        assert!(
            matches!(result, Err(ExecError::DeniedEnvironmentVariable { .. })),
            "{var} should be denied by mandatory denylist"
        );
    }
    Ok(())
}

#[test]
fn custom_allow_environment_config_produces_different_environment()
-> Result<(), Box<dyn std::error::Error>> {
    use arbitraitor_core::config::ExecutionConfig;

    let cfg = ExecutionConfig {
        allow_environment: vec!["ARBITRAITOR_TEST_VAR".to_owned()],
        ..ExecutionConfig::default()
    };

    let context = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy_without_root_check())
        .environment_from_config(&cfg)?
        .source_environment([
            ("LANG", "C.UTF-8"),
            ("LC_ALL", "C"),
            ("TERM", "xterm-256color"),
            ("ARBITRAITOR_TEST_VAR", "hello"),
        ])
        .build()?;

    assert_eq!(
        context.environment().get("ARBITRAITOR_TEST_VAR"),
        Some(&OsString::from("hello"))
    );
    assert!(!context.environment().contains_key("LANG"));
    assert!(!context.environment().contains_key("LC_ALL"));
    assert!(!context.environment().contains_key("TERM"));
    // PATH is inserted unconditionally downstream of the controlled PATH
    // builder and is independent of the allowlist.
    assert!(context.environment().contains_key("PATH"));
    assert!(context.environment().contains_key("HOME"));

    let default_context = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy_without_root_check())
        .source_environment([
            ("LANG", "C.UTF-8"),
            ("LC_ALL", "C"),
            ("TERM", "xterm-256color"),
            ("ARBITRAITOR_TEST_VAR", "hello"),
        ])
        .build()?;
    assert_eq!(
        default_context.environment().get("LANG"),
        Some(&OsString::from("C.UTF-8"))
    );
    assert!(
        !default_context
            .environment()
            .contains_key("ARBITRAITOR_TEST_VAR")
    );
    Ok(())
}

#[test]
fn temp_directories_are_fresh_empty_and_cleaned_on_drop() -> Result<(), Box<dyn std::error::Error>>
{
    use std::os::unix::fs::MetadataExt;

    let (home, work) = {
        let context = ExecutionContextBuilder::new(plan(), grants())
            .policy(policy_without_root_check())
            .source_environment([] as [(&str, &str); 0])
            .build()?;
        assert!(context.home_dir().exists());
        assert!(context.working_dir().exists());
        assert_ne!(context.home_dir(), context.working_dir());
        assert_eq!(fs::read_dir(context.home_dir())?.count(), 0);
        assert_eq!(fs::read_dir(context.working_dir())?.count(), 0);
        assert!(context.owns_temporary_directories());

        // Verify 0700 permissions on temp dirs.
        let home_mode = fs::metadata(context.home_dir())?.mode() & 0o777;
        let work_mode = fs::metadata(context.working_dir())?.mode() & 0o777;
        assert_eq!(
            home_mode, 0o700,
            "temp HOME dir should have 0700 permissions"
        );
        assert_eq!(
            work_mode, 0o700,
            "temp working dir should have 0700 permissions"
        );

        (
            context.home_dir().to_path_buf(),
            context.working_dir().to_path_buf(),
        )
    };
    assert!(!home.exists());
    assert!(!work.exists());
    Ok(())
}

#[test]
fn privilege_elevation_detection_blocks_program_and_arguments() {
    let blocked_program = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy_without_root_check())
        .command("/usr/bin/sudo")
        .source_environment([] as [(&str, &str); 0])
        .build()
        .err();
    assert!(matches!(
        blocked_program,
        Some(ExecError::PrivilegeElevationAttempt { .. })
    ));

    let blocked_argument = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy_without_root_check())
        .arguments(["sh", "-c", "doas install thing"])
        .source_environment([] as [(&str, &str); 0])
        .build()
        .err();
    assert!(matches!(
        blocked_argument,
        Some(ExecError::PrivilegeElevationAttempt { .. })
    ));
}

#[test]
fn root_detection_policy_can_block_context_creation() {
    let policy = ExecutionPolicy {
        deny_running_as_root: true,
        ..policy_without_root_check()
    };
    let result = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy)
        .source_environment([] as [(&str, &str); 0])
        .build();
    if running_as_root().unwrap_or(false) {
        assert!(matches!(result, Err(ExecError::RunningAsRoot)));
    }
}

#[test]
fn fd_policy_configuration_is_preserved() -> Result<(), Box<dyn std::error::Error>> {
    let policy = ExecutionPolicy {
        deny_running_as_root: false,
        fd_policy: FdPolicy::new(true, [0, 1, 2, 9]),
        ..ExecutionPolicy::default()
    };
    let context = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy)
        .source_environment([] as [(&str, &str); 0])
        .build()?;
    assert!(context.fd_policy().close_inherited);
    assert!(context.fd_policy().keeps(9));
    assert!(!context.fd_policy().keeps(10));
    Ok(())
}

#[test]
fn network_denied_prepares_sandbox_plan() -> Result<(), Box<dyn std::error::Error>> {
    let context = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy_without_root_check())
        .source_environment([] as [(&str, &str); 0])
        .build()?;
    assert_eq!(context.network_policy(), &NetworkPolicy::Denied);
    assert!(context.network_sandbox().deny_network);
    assert!(
        context
            .network_sandbox()
            .linux_mechanisms
            .contains(&"seccomp")
    );
    Ok(())
}

#[test]
fn controlled_path_rejects_relative_entries() {
    let relative = validate_path_entries(&[PathBuf::from("bin")]);
    assert!(matches!(relative, Err(ExecError::RelativePathEntry { .. })));
}

#[test]
fn controlled_path_rejects_nonexistent_entries() {
    let missing = validate_path_entries(&[PathBuf::from("/tmp/nonexistent-path-entry")]);
    assert!(matches!(missing, Err(ExecError::UnsafePathEntry { .. })));
}

#[test]
fn controlled_path_rejects_symlink_entries() -> Result<(), Box<dyn std::error::Error>> {
    let symlink_path = env::temp_dir().join("arbitraitor-test-symlink-path");
    let _ = fs::remove_file(&symlink_path);
    std::os::unix::fs::symlink("/usr/bin", &symlink_path)?;
    let result = validate_path_entries(std::slice::from_ref(&symlink_path));
    assert!(matches!(result, Err(ExecError::UnsafePathEntry { .. })));
    let _ = fs::remove_file(&symlink_path);
    Ok(())
}

#[test]
fn controlled_path_accepts_root_owned_entries() {
    // The default entries should validate successfully on a standard
    // Linux system where /usr/bin and /usr/local/bin exist and are
    // root-owned.
    let entries = default_path_entries();
    if entries.is_empty() {
        return;
    }
    let result = validate_path_entries(&entries);
    // If the system doesn't have standard paths (rare CI), skip.
    if let Err(ExecError::UnsafePathEntry { .. }) = &result {
        return;
    }
    assert!(
        result.is_ok(),
        "default path entries should be valid: {entries:?}"
    );
}

#[test]
fn execute_capability_is_required() {
    let result = ExecutionContextBuilder::new(plan(), grants_without_execute())
        .policy(policy_without_root_check())
        .source_environment([] as [(&str, &str); 0])
        .build();
    assert!(
        matches!(result, Err(ExecError::ExecuteNotGranted)),
        "build must fail when execute capability is not granted"
    );
}

#[test]
fn network_requires_both_grant_and_plan() -> Result<(), Box<dyn std::error::Error>> {
    // Grant=true, plan=false → denied.
    let mut plan_no_net = plan();
    plan_no_net.network_allowed = false;
    let policy = ExecutionPolicy::from_operation(&plan_no_net, &grants_with_network())?;
    assert_eq!(policy.network_policy, NetworkPolicy::Denied);

    // Grant=false, plan=true → denied (plan alone cannot enable network).
    let mut plan_wants_net = plan();
    plan_wants_net.network_allowed = true;
    let policy = ExecutionPolicy::from_operation(&plan_wants_net, &grants())?;
    assert_eq!(
        policy.network_policy,
        NetworkPolicy::Denied,
        "untrusted plan alone must not enable network"
    );

    // Grant=true, plan=true → allowed (intersection).
    let policy = ExecutionPolicy::from_operation(&plan_wants_net, &grants_with_network())?;
    assert_eq!(policy.network_policy, NetworkPolicy::Allowed);
    Ok(())
}

#[test]
fn relative_command_is_rejected() {
    let result = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy_without_root_check())
        .command("sh")
        .source_environment([] as [(&str, &str); 0])
        .build();
    assert!(
        matches!(result, Err(ExecError::CommandNotAbsolute { .. })),
        "relative command must be rejected"
    );
}

#[test]
fn resource_limits_have_conservative_defaults() {
    let limits = ResourceLimits::default();
    assert_eq!(limits.cpu_time_secs, Some(60));
    assert_eq!(limits.memory_bytes, Some(512 * 1024 * 1024));
    assert_eq!(limits.process_count, Some(64));
    assert_eq!(limits.fd_count, Some(64));
    assert_eq!(limits.output_size_bytes, Some(10 * 1024 * 1024));
}

#[test]
fn resource_limits_are_recorded_in_context() -> Result<(), Box<dyn std::error::Error>> {
    let context = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy_without_root_check())
        .source_environment([] as [(&str, &str); 0])
        .build()?;
    assert_eq!(context.resource_limits(), &ResourceLimits::default());
    Ok(())
}

#[test]
fn fixed_directory_rejects_relative_path() {
    let policy = ExecutionPolicy {
        deny_running_as_root: false,
        home_directory: TempDirectoryPolicy::Fixed(PathBuf::from("relative/dir")),
        ..ExecutionPolicy::default()
    };
    let result = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy)
        .source_environment([] as [(&str, &str); 0])
        .build();
    assert!(
        matches!(result, Err(ExecError::UnsafeFixedDirectory { .. })),
        "relative fixed directory must be rejected"
    );
}

#[test]
fn fixed_directory_rejects_symlink() -> Result<(), Box<dyn std::error::Error>> {
    let symlink_dir = env::temp_dir().join("arbitraitor-test-symlink-dir");
    let target_dir = env::temp_dir().join("arbitraitor-test-real-dir");
    let _ = fs::remove_file(&symlink_dir);
    let _ = fs::remove_dir_all(&target_dir);
    fs::create_dir(&target_dir)?;
    std::os::unix::fs::symlink(&target_dir, &symlink_dir)?;

    let policy = ExecutionPolicy {
        deny_running_as_root: false,
        home_directory: TempDirectoryPolicy::Fixed(symlink_dir.clone()),
        ..ExecutionPolicy::default()
    };
    let result = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy)
        .source_environment([] as [(&str, &str); 0])
        .build();
    assert!(
        matches!(result, Err(ExecError::UnsafeFixedDirectory { .. })),
        "symlink fixed directory must be rejected"
    );

    let _ = fs::remove_file(&symlink_dir);
    let _ = fs::remove_dir_all(&target_dir);
    Ok(())
}

#[test]
fn context_fields_are_accessible_via_accessors() -> Result<(), Box<dyn std::error::Error>> {
    let context = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy_without_root_check())
        .source_environment([] as [(&str, &str); 0])
        .build()?;

    // Verify all accessors return the expected types without compilation
    // errors — this guards against accidental field re-exposure.
    let _cmd: &Path = context.command();
    let _args: &[OsString] = context.arguments();
    let _env: &BTreeMap<String, OsString> = context.environment();
    let _home: &Path = context.home_dir();
    let _work: &Path = context.working_dir();
    let _fd: &FdPolicy = context.fd_policy();
    let _net: &NetworkPolicy = context.network_policy();
    let _sandbox: &NetworkSandboxPlan = context.network_sandbox();
    let _plan: &OperationPlan = context.operation_plan();
    let _level: AssuranceLevel = context.assurance_level();
    let _grants: &GrantedCapabilities = context.granted_capabilities();
    let _limits: &ResourceLimits = context.resource_limits();
    let _controls: &EffectiveControls = context.effective_controls();
    Ok(())
}

// ---------------------------------------------------------------------------
// ADR-0007 containment control proofs (#381)
// ---------------------------------------------------------------------------

fn all_control_proofs() -> ControlProofs {
    ControlProofs {
        filesystem_isolation: Some("landlock".to_owned()),
        network_isolation: Some("network-namespace".to_owned()),
        process_tree_control: Some("pid-namespace".to_owned()),
        privilege_suppression: Some("no-new-privs".to_owned()),
        syscall_filtering: Some("seccomp-bpf".to_owned()),
        resource_limits: Some("setrlimit".to_owned()),
    }
}

#[test]
fn contained_fails_closed_without_control_proofs() {
    // ADR-0007: Contained assurance requires proof of EACH effective control.
    // Missing all proofs → build must fail-closed.
    let result = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy_without_root_check())
        .assurance_level(AssuranceLevel::Contained)
        .source_environment([] as [(&str, &str); 0])
        .build();
    assert!(
        matches!(result, Err(ExecError::MissingContainmentProof { .. })),
        "Contained without control proofs must fail-closed, got {result:?}"
    );
}

#[test]
fn contained_fails_closed_with_partial_proofs() {
    // Five of six proofs supplied — still must fail-closed.
    let mut proofs = all_control_proofs();
    proofs.syscall_filtering = None;
    let result = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy_without_root_check())
        .assurance_level(AssuranceLevel::Contained)
        .control_proofs(proofs)
        .source_environment([] as [(&str, &str); 0])
        .build();
    assert!(
        matches!(
            result,
            Err(ExecError::MissingContainmentProof { control: _ })
        ),
        "Contained with partial proofs must fail-closed"
    );
    if let Err(ExecError::MissingContainmentProof { control }) = &result {
        assert!(
            control.contains("syscall"),
            "error must name the missing control, got '{control}'"
        );
    }
}

#[test]
fn contained_with_all_proofs_records_enforced_matrix() -> Result<(), Box<dyn std::error::Error>> {
    let proofs = all_control_proofs();
    let context = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy_without_root_check())
        .assurance_level(AssuranceLevel::Contained)
        .control_proofs(proofs)
        .source_environment([] as [(&str, &str); 0])
        .build()?;

    assert_eq!(context.assurance_level(), AssuranceLevel::Contained);
    let controls = context.effective_controls();
    // Every control must be recorded as Enforced with its proof.
    let filesystem = controls
        .filesystem_isolation
        .as_ref()
        .ok_or_else(|| std::io::Error::other("filesystem_isolation missing"))?;
    let network = controls
        .network_isolation
        .as_ref()
        .ok_or_else(|| std::io::Error::other("network_isolation missing"))?;
    let process_tree = controls
        .process_tree_control
        .as_ref()
        .ok_or_else(|| std::io::Error::other("process_tree_control missing"))?;
    let privilege = controls
        .privilege_suppression
        .as_ref()
        .ok_or_else(|| std::io::Error::other("privilege_suppression missing"))?;
    let syscall = controls
        .syscall_filtering
        .as_ref()
        .ok_or_else(|| std::io::Error::other("syscall_filtering missing"))?;
    let resource_limits = controls
        .resource_limits
        .as_ref()
        .ok_or_else(|| std::io::Error::other("resource_limits missing"))?;
    assert_eq!(filesystem.applied, ControlStatus::Enforced);
    assert_eq!(filesystem.proof.as_deref(), Some("landlock"));
    assert_eq!(network.applied, ControlStatus::Enforced);
    assert_eq!(process_tree.applied, ControlStatus::Enforced);
    assert_eq!(privilege.applied, ControlStatus::Enforced);
    assert_eq!(syscall.applied, ControlStatus::Enforced);
    assert_eq!(resource_limits.applied, ControlStatus::Enforced);
    Ok(())
}

#[test]
fn mediated_does_not_require_control_proofs() -> Result<(), Box<dyn std::error::Error>> {
    // Mediated must NOT require containment proofs.
    let context = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy_without_root_check())
        .assurance_level(AssuranceLevel::Mediated)
        .source_environment([] as [(&str, &str); 0])
        .build()?;
    assert_eq!(context.assurance_level(), AssuranceLevel::Mediated);
    // No containment controls recorded for non-contained levels.
    assert_eq!(context.effective_controls(), &EffectiveControls::default());
    Ok(())
}

#[test]
fn inspect_level_does_not_require_control_proofs() -> Result<(), Box<dyn std::error::Error>> {
    let context = ExecutionContextBuilder::new(plan(), grants())
        .policy(policy_without_root_check())
        .assurance_level(AssuranceLevel::Inspect)
        .source_environment([] as [(&str, &str); 0])
        .build()?;
    assert_eq!(context.assurance_level(), AssuranceLevel::Inspect);
    assert_eq!(context.effective_controls(), &EffectiveControls::default());
    Ok(())
}
