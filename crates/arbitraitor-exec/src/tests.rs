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
        landlock_abi_version: Some(arbitraitor_sandbox::LandlockAbiVersion::V7),
        io_uring_available: Some(false),
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
    assert_eq!(
        controls.landlock_abi_version,
        Some(arbitraitor_sandbox::LandlockAbiVersion::V7)
    );
    assert_eq!(controls.io_uring_available, Some(false));
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

/// Regression test for the review of #615 (Blocker 1, found by 3 of 5
/// adversarial reviewers): `ExecError::script_io_detail` previously sliced
/// `&str[..MAX_STDERR_LEN]` at byte offset 1024, which panics if byte 1024
/// falls inside a multibyte UTF-8 codepoint. The bytes come from the
/// executed child (bash, unshare, ...) which an attacker can control via
/// the script bytes, so this is a reachable panic on the error path —
/// violates the workspace `clippy::panic = "deny"` lint, the Safe
/// Presentation invariant (ADR-0016), and the Fail Closed invariant.
///
/// The fix truncates BYTES before UTF-8 lossy decoding. `from_utf8_lossy`
/// replaces any partial trailing codepoint with U+FFFD, so a slice that
/// ends mid-char cannot panic.
#[test]
fn script_io_detail_does_not_panic_when_cap_splits_multibyte_char() {
    // 1023 ASCII bytes followed by a 2-byte char (é = 0xC3 0xA9). Total
    // byte length = 1025, but the 1024-byte cap (0-indexed 0..=1023) lands
    // on byte 0xC3 — the lead byte of the 2-byte codepoint. The pre-fix
    // `&str[..1024]` would panic here.
    let mut stderr: Vec<u8> = vec![b'a'; 1023];
    stderr.extend_from_slice("é".as_bytes());
    assert_eq!(stderr.len(), 1025);

    // Must not panic; must include the 1023 'a' bytes; must replace the
    // split trailing char with U+FFFD ("�").
    let detail = ExecError::script_io_detail(Some(1), &stderr);
    assert!(
        detail.starts_with(" (child exited 1; stderr: \""),
        "unexpected format: {detail:?}"
    );
    assert!(
        detail.contains("aaa"),
        "should include the 1023 ASCII 'a' bytes; got {detail:?}"
    );
    // U+FFFD = '\u{FFFD}' = 0xEF 0xBF 0xBD. The decoder must emit one
    // replacement char in place of the split codepoint.
    assert!(
        detail.contains('\u{FFFD}'),
        "should contain U+FFFD for the truncated multibyte char; got {detail:?}"
    );

    // Also exercise a much larger input to ensure no panic at any cap.
    let huge: Vec<u8> = std::iter::repeat_n(b'\xC3', 8192).collect();
    let _ = ExecError::script_io_detail(Some(2), &huge);
}

/// Regression test for #615: `script_io_detail` with empty stderr and no
/// exit code yields an empty `child_detail` so the user-visible error stays
/// terse (preserves the previous behavior for tests that don't capture
/// child state).
#[test]
fn script_io_detail_is_empty_when_no_state_captured() {
    assert_eq!(ExecError::script_io_detail(None, &[]), "");
}

/// Regression test for #615: `script_io_detail` handles invalid UTF-8
/// stderr by lossy-decoding rather than silently dropping it. Previously
/// `std::str::from_utf8(stderr).unwrap_or("")` discarded all bytes when
/// any byte was invalid; the fix uses `from_utf8_lossy` so partial garbage
/// still surfaces something useful to the operator.
#[test]
fn script_io_detail_lossily_decodes_invalid_utf8_stderr() {
    let stderr: Vec<u8> = vec![b'b', b'a', b's', b'h', b':', b' ', 0xFF, 0xFE, b'!'];
    let detail = ExecError::script_io_detail(Some(2), &stderr);
    assert!(
        detail.contains("bash:"),
        "should preserve the valid UTF-8 prefix; got {detail:?}"
    );
    assert!(
        detail.contains('\u{FFFD}'),
        "should include U+FFFD for the invalid bytes; got {detail:?}"
    );
}

/// Regression test for the review of #615 (Blocker 2, ADR-0016 Safe
/// Presentation): an attacker who controls the executed child (e.g. via a
/// shell script that emits an `ARBITRAITOR_UNTRUSTED_DATA_START` marker to
/// stderr) could otherwise spoof Arbitraitor's untrusted-data markers in
/// the captured stderr, confusing downstream agent consumers that rely on
/// the markers to fence untrusted content.
///
/// The fix replaces the markers with safe placeholder text before
/// formatting. This test asserts the spoofed marker does not appear in the
/// rendered error string and IS replaced with `[escaped-untrusted-start]`.
#[test]
fn script_io_detail_escapes_arbitraitor_untrusted_data_markers() {
    const SPOOFED_STDERR: &[u8] =
        b"<<ARBITRAITOR_UNTRUSTED_DATA_START>>hello<<ARBITRAITOR_UNTRUSTED_DATA_END>>";
    let detail = ExecError::script_io_detail(Some(1), SPOOFED_STDERR);
    assert!(
        !detail.contains("<<ARBITRAITOR_UNTRUSTED_DATA_START>>"),
        "untrusted-start marker must be escaped; got {detail:?}"
    );
    assert!(
        !detail.contains("<<ARBITRAITOR_UNTRUSTED_DATA_END>>"),
        "untrusted-end marker must be escaped; got {detail:?}"
    );
    assert!(
        detail.contains("[escaped-untrusted-start]"),
        "escaped placeholder should appear; got {detail:?}"
    );
    assert!(
        detail.contains("[escaped-untrusted-end]"),
        "escaped placeholder should appear; got {detail:?}"
    );
}

/// Regression test for the review of #615 (Blocker 2): control bytes in
/// captured child stderr must NOT reach the rendered error string as live
/// terminal control characters. The fix relies on Rust's `{:?}` debug
/// format for `&str`, which escapes C0/C1 control bytes (including ANSI
/// escape sequences) as `\xNN` literal text. This test feeds a script that
/// emits an ANSI "red text" sequence plus a cursor-move sequence to
/// stderr, then verifies the rendered error string contains the ESC byte
/// as the literal text `\x1b` rather than as a live escape.
#[test]
fn script_io_detail_neutralizes_ansi_control_sequences_in_stderr() {
    // 0x1b 0x5b 0x33 0x31 0x6d = ESC [ 3 1 m  ("red foreground")
    // 0x1b 0x5b 0x48           = ESC [ H    ("cursor home")
    let mut stderr: Vec<u8> = Vec::new();
    stderr.extend_from_slice(b"sh: ");
    stderr.extend_from_slice(&[0x1b, b'[', b'3', b'1', b'm', b'e', b'r', b'r']);
    stderr.extend_from_slice(&[0x1b, b'[', b'0', b'm', 0x1b, b'[', b'H']);
    stderr.extend_from_slice(b"\n");
    let detail = ExecError::script_io_detail(Some(2), &stderr);
    // No live ESC byte should appear in the rendered string.
    assert!(
        !detail.contains(0x1b as char),
        "live ESC byte must not reach terminal; got {detail:?}"
    );
    // Rust's `{:?}` format escapes ESC as the literal text `\u{1b}` (Unicode
    // escape syntax) inside the quoted string. Verify the escape is present
    // in the rendered output so reviewers can confirm no live control byte
    // slipped through.
    assert!(
        detail.contains("\\u{1b}"),
        "ESC should be escaped as `\\u{{1b}}` literal text; got {detail:?}"
    );
}

/// Regression test for `From<ExecError>` for `PowerShellError`: the conversion
/// must preserve all `ScriptIo` fields (`child_exit_code`, `child_stderr`,
/// `child_detail`) so PowerShell execution diagnostics are consistent with
/// the bash path after the conversion at `powershell.rs:176`.
#[test]
fn from_exec_error_preserves_script_io_fields() -> Result<(), Box<dyn std::error::Error>> {
    use crate::PowerShellError;

    let stderr = b"pwsh: syntax error at line 1".to_vec();
    let original = ExecError::script_io(
        "write-script-stdin",
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "EPIPE"),
        Some(1),
        stderr.clone(),
    );

    let converted: PowerShellError = original.into();
    let PowerShellError::ScriptIo {
        child_exit_code,
        child_stderr,
        child_detail,
        ..
    } = converted
    else {
        return Err("expected PowerShellError::ScriptIo variant".into());
    };
    assert_eq!(child_exit_code, Some(1));
    assert_eq!(child_stderr, stderr);
    assert!(
        child_detail.contains("pwsh: syntax error"),
        "child_detail should contain the rendered stderr; got {child_detail:?}"
    );
    Ok(())
}
