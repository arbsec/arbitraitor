#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use arbitraitor_artifact::{ArtifactType, ShellKind};
use arbitraitor_core::config::Config;
use arbitraitor_mcp::PlanContext;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::Verdict;
use clap::Parser;
use sha2::{Digest, Sha256};

use super::run_services::{build_run_receipt, map_exec_failure, validate_cli_policy_override};
use super::{
    DeprecatedRunAliases, EXIT_EXECUTION_FAILED, EXIT_SUCCESS, ExecutionMode, ExecutionOutput,
    InspectedArtifact, RunApprovalFlags, RunCommand, RunExecutionOptions, RunFailure, RunFuture,
    RunServices, run_with_services,
};
use arbitraitor_model::exit_code::ExitCode;
use arbitraitor_receipt::ApprovalInfo;

#[test]
fn run_parses_url_and_flags() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: a run command with every supported flag.
    let cli = crate::Cli::parse_from([
        "arbitraitor",
        "run",
        "https://example.com/install.sh",
        "--interpreter",
        "/usr/local/bin/bash",
        "--native",
        "--working-directory",
        "/tmp/arbitraitor-run",
        "--clean-environment",
        "--allow-env",
        "TERM",
        "--allow-env",
        "LANG",
        "--sandbox",
        "restricted",
        "--approve",
        "approval.json",
        "--non-interactive",
        "--network",
        "--policy",
        "policy.toml",
        "--audit-override",
    ]);

    // When: clap parses the subcommand.
    let command = match cli.command {
        crate::Command::Run(command) => command,
        crate::Command::Inspect(_)
        | crate::Command::Daemon(_)
        | crate::Command::Fetch(_)
        | crate::Command::Wrap(_)
        | crate::Command::Unpack(_)
        | crate::Command::Intel(_)
        | crate::Command::Status(_)
        | crate::Command::Wrappers(_)
        | crate::Command::Mcp
        | crate::Command::Scan(_)
        | crate::Command::Explain(_)
        | crate::Command::Store(_)
        | crate::Command::Policy(_)
        | crate::Command::Doctor(_)
        | crate::Command::Rules(_)
        | crate::Command::Update(_)
        | crate::Command::Plugin(_)
        | crate::Command::Hook(_)
        | crate::Command::Shim(_)
        | crate::Command::Graph(_)
        | crate::Command::Approve(_)
        | crate::Command::Execute(_)
        | crate::Command::Report(_)
        | crate::Command::Allow(_)
        | crate::Command::Pm(_)
        | crate::Command::Env(_)
        | crate::Command::Version => return Err("parsed wrong command".into()),
    };

    // Then: every field reflects the CLI input.
    assert_eq!(command.url, "https://example.com/install.sh");
    assert_eq!(
        command.interpreter,
        Some(PathBuf::from("/usr/local/bin/bash"))
    );
    assert!(command.approval.native);
    assert_eq!(
        command.working_directory,
        Some(PathBuf::from("/tmp/arbitraitor-run"))
    );
    assert!(command.approval.clean_environment);
    assert_eq!(command.allow_env, ["TERM", "LANG"]);
    assert_eq!(command.sandbox, Some("restricted".to_owned()));
    assert_eq!(command.approve, Some(PathBuf::from("approval.json")));
    assert!(command.approval.non_interactive);
    assert!(command.compatibility.network);
    assert_eq!(
        command.compatibility.policy,
        Some(PathBuf::from("policy.toml"))
    );
    assert!(command.compatibility.audit_override);
    Ok(())
}

#[test]
fn cli_policy_override_without_audit_override_is_rejected() {
    // Given: a command-line policy override without audit consent.
    let mut command = command(false, false);
    command.compatibility.policy = Some(PathBuf::from("policy.toml"));

    // When: the override gate is evaluated.
    let result = validate_cli_policy_override(&command);

    // Then: the override is rejected.
    assert!(
        matches!(result, Err(RunFailure::Blocked(message)) if message.contains("--audit-override"))
    );
}

#[test]
fn cli_policy_override_with_audit_override_is_allowed_and_audited()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: a command-line policy override with audit consent.
    let mut command = command(false, false);
    command.compatibility.policy = Some(PathBuf::from("policy.toml"));
    command.compatibility.audit_override = true;
    let mut artifact = fake_artifact(Verdict::Pass, false);
    artifact.audit_trail = vec!["CLI policy override applied from policy.toml".to_owned()];

    // When: the override gate and receipt audit path run.
    assert!(validate_cli_policy_override(&command).is_ok());
    let receipt = build_run_receipt(
        &artifact,
        &ExecutionOutput {
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            network_isolated: true,
        },
    )
    .map_err(|error| format!("receipt build failed: {error:?}"))?;

    // Then: the receipt records the override.
    assert_eq!(receipt.policy.audit_trail.len(), 1);
    assert_eq!(receipt.policy.audit_trail[0].kind, "cli-policy-override");
    assert!(
        receipt.policy.audit_trail[0]
            .detail
            .contains("CLI policy override")
    );
    Ok(())
}

#[tokio::test]
async fn run_binds_approval_context_to_requested_interpreter()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: a prompt verdict and a custom interpreter path.
    let mut command = command(false, false);
    command.interpreter = Some(PathBuf::from("/opt/arbitraitor/interpreters/bash"));
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Prompt, false));
    let mut output = Vec::new();

    // When: approval is requested.
    let code = run_with_services(&command, &Config::default(), &mut services, &mut output).await?;

    // Then: ADR-0013 binding uses the requested interpreter path.
    assert_eq!(code, EXIT_SUCCESS);
    let context = services
        .approval_context
        .ok_or("approval context was not captured")?;
    assert_eq!(context.interpreter, "/opt/arbitraitor/interpreters/bash");
    assert_ne!(context.interpreter, "/bin/bash");
    Ok(())
}

#[tokio::test]
async fn run_passes_spec_flags_to_execution_services()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: a script run with the spec-defined execution flags.
    let mut command = command(false, false);
    command.interpreter = Some(PathBuf::from("/usr/local/bin/zsh"));
    command.working_directory = Some(PathBuf::from("/tmp/arbitraitor-run"));
    command.approval.clean_environment = true;
    command.allow_env = vec!["TERM".to_owned(), "LANG".to_owned()];
    command.sandbox = Some("observe".to_owned());
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Pass, false));
    let mut output = Vec::new();

    // When: the artifact executes.
    let code = run_with_services(&command, &Config::default(), &mut services, &mut output).await?;

    // Then: the service boundary receives the full flag surface.
    assert_eq!(code, EXIT_SUCCESS);
    let options = services
        .execution_options
        .ok_or("execution options were not captured")?;
    assert_eq!(options.interpreter, PathBuf::from("/usr/local/bin/zsh"));
    assert_eq!(options.interpreter_args, [] as [std::string::String; 0]);
    assert_eq!(
        options.working_directory,
        Some(PathBuf::from("/tmp/arbitraitor-run"))
    );
    assert!(options.clean_environment);
    assert_eq!(options.allow_env, ["TERM", "LANG"]);
    assert_eq!(options.sandbox, Some("observe".to_owned()));
    Ok(())
}

#[tokio::test]
async fn run_native_auto_detects_and_prompts() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    let command = command(false, false);
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Pass, true));
    let mut output = Vec::new();

    let code = run_with_services(&command, &Config::default(), &mut services, &mut output).await?;

    assert_eq!(code, EXIT_SUCCESS);
    assert!(services.approval_requested);
    assert!(services.executed);
    Ok(())
}

#[tokio::test]
async fn run_native_non_interactive_blocked_without_flag()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let command = command(false, true);
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Pass, true));
    let mut output = Vec::new();

    let code = run_with_services(&command, &Config::default(), &mut services, &mut output).await?;

    assert_eq!(code, ExitCode::PromptInNonInteractive.as_i32());
    assert!(!services.approval_requested);
    assert!(!services.executed);
    let rendered = String::from_utf8(output)?;
    assert!(rendered.contains("native binary detected"));
    assert!(rendered.contains("--native"));
    Ok(())
}

#[tokio::test]
async fn run_native_with_flag_skips_prompt() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    let command = command(true, true);
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Pass, true));
    let mut output = Vec::new();

    let code = run_with_services(&command, &Config::default(), &mut services, &mut output).await?;

    assert_eq!(code, EXIT_SUCCESS);
    assert!(!services.approval_requested);
    assert!(services.executed);
    Ok(())
}

#[tokio::test]
async fn run_non_interactive_blocks_on_prompt_verdict()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: policy requires approval but non-interactive mode is set.
    let command = command(false, true);
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Prompt, false));
    let mut output = Vec::new();

    // When: the verdict is evaluated.
    let code = run_with_services(&command, &Config::default(), &mut services, &mut output).await?;

    // Then: the command exits with the prompt-in-non-interactive code (21).
    assert_eq!(code, ExitCode::PromptInNonInteractive.as_i32());
    assert!(!services.approval_requested);
    assert!(!services.executed);
    Ok(())
}

#[tokio::test]
async fn run_writes_receipt_on_success() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: a successful script execution and fake receipt path.
    let command = command(false, false);
    let receipt_path = PathBuf::from("/tmp/arbitraitor-receipt.json");
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Pass, false));
    services.receipt_path = receipt_path.clone();
    let mut output = Vec::new();

    // When: the pipeline completes.
    let code = run_with_services(&command, &Config::default(), &mut services, &mut output).await?;

    // Then: receipt writing is invoked and reported.
    assert_eq!(code, EXIT_SUCCESS);
    assert_eq!(services.written_receipt, Some(receipt_path.clone()));
    assert_eq!(services.receipt_approval, None);
    assert!(String::from_utf8(output)?.contains(&receipt_path.display().to_string()));
    Ok(())
}

#[tokio::test]
async fn run_writes_approval_binding_exit_status_to_receipt()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let command = command(false, false);
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Prompt, false));
    services.execution.exit_code = Some(7);
    let mut output = Vec::new();

    let code = run_with_services(&command, &Config::default(), &mut services, &mut output).await?;

    // The process exits 50 ("execution failed after approval", spec §29); the
    // child's own code is not propagated, only recorded on the receipt.
    assert_eq!(code, EXIT_EXECUTION_FAILED);
    assert_eq!(
        services
            .receipt_approval
            .as_ref()
            .and_then(|approval| approval.exit_status),
        Some(7)
    );
    Ok(())
}

/// Regression test for #612 (Fix A): `arbitraitor run` must refuse to execute
/// artifacts whose classified `ArtifactType` is not interpretable by the
/// `run` pipeline. HTML, JSON, XML, archives, compressed payloads,
/// `GenericText`, `GenericBinary`, `Unknown`, and the not-yet-wired script
/// types (PowerShell, Python, JavaScript) all fall in this category. Feeding
/// their bytes to `/bin/bash` is incorrect (bash can't parse them) and
/// unsafe (they may incidentally contain bash-parseable constructs). The
/// pipeline fails closed with `BlockedByPolicy` before reaching execution.
#[tokio::test]
async fn run_blocks_non_executable_artifact_types()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for artifact_type in [
        ArtifactType::HtmlDocument,
        ArtifactType::JsonDocument,
        ArtifactType::XmlDocument,
        ArtifactType::GenericText,
        ArtifactType::GenericBinary,
        ArtifactType::ZipArchive,
        ArtifactType::TarArchive,
        ArtifactType::GzipCompressed,
        ArtifactType::XzCompressed,
        ArtifactType::Bzip2Compressed,
        ArtifactType::ZstdCompressed,
        ArtifactType::PowerShellScript,
        ArtifactType::PythonScript,
        ArtifactType::JavaScript,
        ArtifactType::ShellScript(ShellKind::Zsh),
        ArtifactType::Unknown,
    ] {
        let command = command(false, false);
        let mut services =
            FakeServices::with_artifact(fake_artifact_with_type(Verdict::Pass, artifact_type));
        let mut output = Vec::new();

        let code =
            run_with_services(&command, &Config::default(), &mut services, &mut output).await?;

        // BlockedByPolicy exit code per ExitCode::BlockedByPolicy.
        assert_eq!(
            code,
            ExitCode::BlockedByPolicy.as_i32(),
            "artifact type {artifact_type:?} should be blocked, not executed"
        );
        assert!(
            !services.executed,
            "pipeline executed artifact type {artifact_type:?}; should have been blocked"
        );
        let rendered = String::from_utf8_lossy(&output);
        assert!(
            rendered.contains("blocked by policy"),
            "output for {artifact_type:?} should say 'blocked by policy'; got: {rendered}"
        );
        assert!(
            rendered.contains("is not executable"),
            "output for {artifact_type:?} should explain the artifact is not executable; got: {rendered}"
        );
        assert!(
            rendered.contains(&format!("{artifact_type:?}")),
            "output should name the specific artifact type {artifact_type:?}; got: {rendered}"
        );
    }
    Ok(())
}

/// Positive control for #612 (Fix A): classified `ShellScript(Posix)` and
/// `ShellScript(Bash)` must still pass through the gate. Guards against an
/// over-restrictive regression that would block legitimate shell-script
/// execution. `ShellScript(Zsh)` is intentionally NOT included here
/// because `/bin/bash` cannot safely interpret zsh syntax — see
/// `run_blocks_zsh_shell_script` below.
#[tokio::test]
async fn run_executes_shell_script_artifact_types()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for shell_kind in [ShellKind::Posix, ShellKind::Bash] {
        let command = command(false, false);
        let mut services = FakeServices::with_artifact(fake_artifact_with_type(
            Verdict::Pass,
            ArtifactType::ShellScript(shell_kind),
        ));
        let mut output = Vec::new();
        let code =
            run_with_services(&command, &Config::default(), &mut services, &mut output).await?;
        assert_eq!(
            code, EXIT_SUCCESS,
            "shell script ({shell_kind:?}) should execute"
        );
        assert!(
            services.executed,
            "shell script ({shell_kind:?}) should reach execute()"
        );
    }
    Ok(())
}

/// Positive control for #612 (Fix A): all three native executable types
/// (`ElfExecutable`, `PeExecutable`, `MachOExecutable`) must pass through
/// the gate and reach `services.execute()` (which is a fake in test mode;
/// native execution machinery is gated by `cfg(target_os = "linux")` and
/// the host kernel decides whether each binary can actually run, but the
/// content-type gate must not block them pre-emptively).
#[tokio::test]
async fn run_executes_native_artifact_type() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    for native_type in [
        ArtifactType::ElfExecutable,
        ArtifactType::PeExecutable,
        ArtifactType::MachOExecutable,
    ] {
        let native_command = command(true, false);
        let mut services =
            FakeServices::with_artifact(fake_artifact_with_type(Verdict::Pass, native_type));
        let mut output = Vec::new();
        let code = run_with_services(
            &native_command,
            &Config::default(),
            &mut services,
            &mut output,
        )
        .await?;
        assert_eq!(
            code, EXIT_SUCCESS,
            "native type {native_type:?} should pass the content-type gate"
        );
        assert!(
            services.executed,
            "native type {native_type:?} should reach execute()"
        );
    }
    Ok(())
}

#[tokio::test]
async fn run_streams_sanitized_output() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: child output containing terminal controls and marker text.
    let command = command(false, false);
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Pass, false));
    services.execution.stdout = b"\x1b[31m<<ARBITRAITOR_UNTRUSTED_DATA_START>>hello".to_vec();
    let mut output = Vec::new();

    // When: output is presented to the terminal.
    let code = run_with_services(&command, &Config::default(), &mut services, &mut output).await?;

    // Then: it is wrapped and escaped as untrusted data.
    assert_eq!(code, EXIT_SUCCESS);
    let rendered = String::from_utf8(output)?;
    assert!(rendered.contains("<<ARBITRAITOR_UNTRUSTED_DATA_START>>"));
    assert!(rendered.contains("[escaped-untrusted-start]"));
    assert!(!rendered.contains('\x1b'));
    Ok(())
}

/// Regression test for #375: the native release path must route through
/// `release_artifact` (ADR-0015 safe-destination) rather than
/// `std::fs::write`. A pre-planted symlink at the native cache target must be
/// rejected — never overwritten, never followed — so an attacker who can plant
/// the symlink cannot intercept, replace, or corrupt the released binary.
#[cfg(target_os = "linux")]
#[test]
fn native_release_rejects_symlink_at_cache_path()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use super::run_services::release_native_via_safe_destination;
    use arbitraitor_store::ContentStore;

    let root =
        std::env::temp_dir().join(format!("arb-native-release-symlink-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let store_dir = root.join("cas");
    std::fs::create_dir_all(&store_dir)?;

    let bytes = b"#!/bin/sh\necho ok\n".to_vec();
    let sha256 = Sha256Digest::new(Sha256::digest(&bytes).into());

    let store = ContentStore::open(&store_dir)?;
    let mut sink = store.sink(Some(&sha256))?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(sink.write_chunk(&bytes))?;
    runtime.block_on(sink.finish())?;

    let sensitive = root.join("sensitive.txt");
    std::fs::write(&sensitive, b"must not be touched")?;
    let symlink_target = root.join(format!("{sha256}.bin"));
    std::os::unix::fs::symlink(&sensitive, &symlink_target)?;

    let artifact = InspectedArtifact {
        size_bytes: bytes.len(),
        artifact_type: ArtifactType::ElfExecutable,
        bytes: bytes.clone(),
        sha256: sha256.clone(),
        content_type: "application/octet-stream".to_owned(),
        verdict: Verdict::Pass,
        policy_digest: String::new(),
        findings: Vec::new(),
        detectors: Vec::new(),
        detector_versions: Vec::new(),
        audit_trail: Vec::new(),
        requested_url: "https://example.test/native".to_owned(),
        final_url: "https://example.test/native".to_owned(),
        store_dir: store_dir.clone(),
    };

    let result = release_native_via_safe_destination(&artifact, &symlink_target);
    assert!(
        matches!(result, Err(RunFailure::Execution(_))),
        "release through symlink must fail (ADR-0015); got {result:?}"
    );
    // The symlink target must be untouched — no overwrite, no follow.
    assert_eq!(std::fs::read(&sensitive)?, b"must not be touched");
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

fn command(native: bool, non_interactive: bool) -> RunCommand {
    RunCommand {
        url: "https://example.test/install.sh".to_owned(),
        interpreter: None,
        approval: RunApprovalFlags {
            native,
            non_interactive,
            clean_environment: false,
        },
        working_directory: None,
        allow_env: Vec::new(),
        sandbox: None,
        approve: None,
        sign_receipt: None,
        compatibility: DeprecatedRunAliases {
            network: false,
            policy: None,
            audit_override: false,
        },
    }
}

fn fake_artifact(verdict: Verdict, is_native: bool) -> InspectedArtifact {
    let bytes = b"#!/bin/sh\necho test\n".to_vec();
    let sha256 = Sha256Digest::new(Sha256::digest(&bytes).into());
    let artifact_type = if is_native {
        ArtifactType::ElfExecutable
    } else {
        ArtifactType::ShellScript(ShellKind::Posix)
    };
    InspectedArtifact {
        size_bytes: bytes.len(),
        artifact_type,
        bytes,
        sha256,
        content_type: "text/x-shellscript".to_owned(),
        verdict,
        policy_digest: String::new(),
        findings: Vec::new(),
        detectors: Vec::new(),
        detector_versions: Vec::new(),
        audit_trail: Vec::new(),
        requested_url: "https://example.test/install.sh".to_owned(),
        final_url: "https://example.test/install.sh".to_owned(),
        store_dir: PathBuf::new(),
    }
}

fn fake_artifact_with_type(verdict: Verdict, artifact_type: ArtifactType) -> InspectedArtifact {
    let bytes = b"#!/bin/sh\necho test\n".to_vec();
    let sha256 = Sha256Digest::new(Sha256::digest(&bytes).into());
    InspectedArtifact {
        size_bytes: bytes.len(),
        artifact_type,
        bytes,
        sha256,
        content_type: "application/octet-stream".to_owned(),
        verdict,
        policy_digest: String::new(),
        findings: Vec::new(),
        detectors: Vec::new(),
        detector_versions: Vec::new(),
        audit_trail: Vec::new(),
        requested_url: "https://example.test/install.sh".to_owned(),
        final_url: "https://example.test/install.sh".to_owned(),
        store_dir: PathBuf::new(),
    }
}

fn fake_approval_info(sha256: &Sha256Digest, exit_status: Option<i32>) -> ApprovalInfo {
    ApprovalInfo {
        plan_digest: Sha256Digest::new([0x11; 32]),
        artifact_digest: sha256.clone(),
        expiry: Some(UNIX_EPOCH + Duration::from_mins(5)),
        nonce: "fake-approval-nonce".to_owned(),
        bound_capabilities: vec![
            "process:execute".to_owned(),
            "network:isolated".to_owned(),
            "filesystem:none".to_owned(),
        ],
        override_reason: Some("Prompt".to_owned()),
        override_scope: Some(format!("artifact:{sha256}")),
        exit_status,
    }
}

struct FakeServices {
    artifact: InspectedArtifact,
    preflight_failure: Option<RunFailure>,
    refuse_isolated_native_network: bool,
    approval_requested: bool,
    approval_context: Option<PlanContext>,
    executed: bool,
    execution_options: Option<RunExecutionOptions>,
    execution: ExecutionOutput,
    execution_failure: Option<RunFailure>,
    receipt_path: PathBuf,
    written_receipt: Option<PathBuf>,
    receipt_approval: Option<ApprovalInfo>,
}

impl FakeServices {
    fn with_artifact(artifact: InspectedArtifact) -> Self {
        Self {
            artifact,
            preflight_failure: None,
            refuse_isolated_native_network: false,
            approval_requested: false,
            approval_context: None,
            executed: false,
            execution_options: None,
            execution: ExecutionOutput {
                exit_code: Some(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
                network_isolated: true,
            },
            execution_failure: None,
            receipt_path: PathBuf::from("/tmp/arbitraitor-fake-receipt.json"),
            written_receipt: None,
            receipt_approval: None,
        }
    }
}

impl RunServices for FakeServices {
    fn preflight(
        &self,
        mode: ExecutionMode,
        network_isolated: bool,
    ) -> std::result::Result<(), RunFailure> {
        if let Some(failure) = &self.preflight_failure {
            return Err(failure.clone());
        }
        // Mirrors `DefaultRunServices`: a native execution whose plan denies
        // network is refused when the backend cannot install the control.
        if self.refuse_isolated_native_network && mode == ExecutionMode::Native && network_isolated
        {
            return Err(RunFailure::Blocked(
                arbitraitor_exec::ExecError::NetworkIsolationUnavailable {
                    reason: "fake host cannot create a network namespace".to_owned(),
                }
                .to_string(),
            ));
        }
        Ok(())
    }

    fn prepare<'a>(
        &'a mut self,
        _command: &'a RunCommand,
        _config: &'a Config,
    ) -> RunFuture<'a, std::result::Result<InspectedArtifact, RunFailure>> {
        let artifact = self.artifact.clone();
        Box::pin(async move { Ok(artifact) })
    }

    fn request_approval(
        &mut self,
        _artifact: &InspectedArtifact,
        _plan: &str,
        ctx: &PlanContext,
    ) -> std::result::Result<Option<ApprovalInfo>, RunFailure> {
        self.approval_requested = true;
        self.approval_context = Some(ctx.clone());
        Ok(Some(fake_approval_info(&self.artifact.sha256, None)))
    }

    fn execute(
        &mut self,
        _mode: ExecutionMode,
        _artifact: &InspectedArtifact,
        options: &RunExecutionOptions,
    ) -> std::result::Result<ExecutionOutput, RunFailure> {
        self.executed = true;
        self.execution_options = Some(options.clone());
        match &self.execution_failure {
            Some(failure) => Err(failure.clone()),
            None => Ok(self.execution.clone()),
        }
    }

    fn write_receipt(
        &mut self,
        _artifact: &InspectedArtifact,
        _output: &ExecutionOutput,
        approval: Option<&ApprovalInfo>,
    ) -> std::result::Result<PathBuf, RunFailure> {
        let path = self.receipt_path.clone();
        self.written_receipt = Some(path.clone());
        self.receipt_approval = approval.cloned();
        Ok(path)
    }
}

/// `run` must tell the backend whether the plan denies network, so a native
/// run under the mediated default (`network_allowed() == false`) is refused
/// before approval and dispatch when the host cannot install the
/// network-namespace wrapper (issue #842). `--network` lowers assurance
/// explicitly and must reach the backend as an unisolated plan.
#[tokio::test]
async fn run_refuses_unisolatable_native_network_before_approval_and_dispatch()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: a native artifact and a backend that cannot isolate the network.
    let isolated_command = command(true, false);
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Pass, true));
    services.refuse_isolated_native_network = true;
    let mut output = Vec::new();

    // When: the plan denies network (no `--network`).
    let code = run_with_services(
        &isolated_command,
        &Config::default(),
        &mut services,
        &mut output,
    )
    .await?;

    // Then: the run is blocked by policy before approval or dispatch.
    assert_eq!(code, ExitCode::BlockedByPolicy.as_i32());
    assert!(
        !services.approval_requested,
        "no approval for a refused run"
    );
    assert!(!services.executed, "no child may be dispatched");
    assert!(
        services.written_receipt.is_none(),
        "no receipt for a refusal"
    );
    let text = String::from_utf8(output)?;
    assert!(text.contains("blocked by policy"), "refusal text: {text}");
    assert!(
        text.contains("network isolation"),
        "refusal must name the missing control: {text}",
    );

    // When: the operator explicitly lowers assurance with `--network`.
    let mut permissive_command = command(true, false);
    permissive_command.compatibility.network = true;
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Pass, true));
    services.refuse_isolated_native_network = true;
    let mut output = Vec::new();

    let code = run_with_services(
        &permissive_command,
        &Config::default(),
        &mut services,
        &mut output,
    )
    .await?;

    // Then: the plan is not network-denied, so preflight passes and the run
    // reaches dispatch — which is the opt-down the refusal names.
    assert_eq!(code, EXIT_SUCCESS);
    assert!(services.executed);
    let options = services
        .execution_options
        .ok_or("execution options were not captured")?;
    assert!(
        options.network_allowed,
        "--network must reach the execution backend"
    );
    Ok(())
}

/// `run` must refuse a mode the backend reports as unenforceable before it
/// requests an approval, releases the artifact, or writes a receipt (issue
/// #839). The refusal is injected so the orchestrator contract is exercised on
/// every host, not only where the real backend refuses.
#[tokio::test]
async fn run_refuses_unenforceable_mode_before_approval_and_dispatch()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: a Prompt verdict, so approval would otherwise be requested.
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Prompt, false));
    services.preflight_failure = Some(RunFailure::Blocked(
        arbitraitor_exec::ExecError::MediatedContainmentUnavailable.to_string(),
    ));
    let command = command(false, false);
    let mut output = Vec::new();

    // When: the pipeline runs.
    let code = run_with_services(&command, &Config::default(), &mut services, &mut output).await?;

    // Then: it stops before approval, dispatch, or a receipt.
    assert_eq!(code, ExitCode::BlockedByPolicy.as_i32());
    assert!(
        !services.approval_requested,
        "no approval may be requested for a run that can never dispatch",
    );
    assert!(!services.executed, "no child may be dispatched");
    assert!(
        services.written_receipt.is_none(),
        "no receipt may be written for a refused run",
    );
    let text = String::from_utf8(output)?;
    assert!(
        text.contains("blocked by policy"),
        "refusal must be labelled as a policy block: {text}",
    );
    for control in [
        "network isolation",
        "filesystem isolation",
        "no-privilege-elevation",
        "inherited-descriptor closure",
    ] {
        assert!(
            text.contains(control),
            "refusal must name unavailable control {control:?}: {text}",
        );
    }
    Ok(())
}

/// The receipt must record the network-isolation control only when the
/// executor actually installed it and the target reported an exit status
/// (issue #827). The state comes from the executor, never from the CLI
/// flags, so the matrix describes the run that happened.
#[test]
fn receipt_records_the_network_isolation_control_when_the_executor_installed_it()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: an isolated run whose target exited cleanly.
    let artifact = fake_artifact(Verdict::Pass, false);

    // When: the receipt is built.
    let receipt = build_run_receipt(
        &artifact,
        &ExecutionOutput {
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            network_isolated: true,
        },
    )
    .map_err(|error| format!("receipt build failed: {error:?}"))?;

    // Then: the network-isolation control is recorded as enforced, with the
    // mechanism label as its proof.
    let controls = receipt
        .release
        .as_ref()
        .and_then(|release| release.effective_controls.as_ref())
        .ok_or("the receipt must carry the effective-controls matrix")?;
    let network = controls
        .network_isolation
        .as_ref()
        .ok_or("the network-isolation control must be recorded")?;
    assert!(network.requested);
    assert_eq!(network.applied, arbitraitor_exec::ControlStatus::Enforced);
    assert_eq!(network.proof.as_deref(), Some("unshare"));

    // And: no other control is claimed.
    assert!(controls.filesystem_isolation.is_none());
    assert!(controls.process_tree_control.is_none());
    assert!(controls.privilege_suppression.is_none());
    assert!(controls.syscall_filtering.is_none());
    assert!(controls.resource_limits.is_none());
    Ok(())
}

/// A target that died from a signal has no observable enforcement state, so
/// the matrix is omitted rather than claiming one. The receipt itself is
/// still written: the run happened, and the omission is the honest record
/// (issue #827).
#[test]
fn receipt_omits_effective_controls_when_the_target_died_from_a_signal()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: an isolated run whose target was killed by a signal.
    let artifact = fake_artifact(Verdict::Pass, false);

    // When: the receipt is built.
    let receipt = build_run_receipt(
        &artifact,
        &ExecutionOutput {
            exit_code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            network_isolated: true,
        },
    )
    .map_err(|error| format!("receipt build failed: {error:?}"))?;

    // Then: no control is claimed.
    assert!(
        receipt
            .release
            .as_ref()
            .and_then(|release| release.effective_controls.as_ref())
            .is_none(),
        "a signal death must not claim an enforced control",
    );

    // And: the serialized receipt omits the matrix entirely.
    let json = serde_json::to_value(&receipt)?;
    let release = json
        .get("release")
        .and_then(serde_json::Value::as_object)
        .ok_or("the receipt must carry a release section")?;
    assert!(
        !release.contains_key("effective_controls"),
        "the serialized receipt must omit effective_controls: {release:?}",
    );
    Ok(())
}

/// A run that was not isolated makes no isolation claim at all.
#[test]
fn receipt_omits_effective_controls_when_the_run_was_not_isolated()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: a run whose executor did not install network isolation.
    let artifact = fake_artifact(Verdict::Pass, false);

    // When: the receipt is built.
    let receipt = build_run_receipt(
        &artifact,
        &ExecutionOutput {
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            network_isolated: false,
        },
    )
    .map_err(|error| format!("receipt build failed: {error:?}"))?;

    // Then: no control is claimed.
    assert!(
        receipt
            .release
            .as_ref()
            .and_then(|release| release.effective_controls.as_ref())
            .is_none(),
        "an unisolated run must not claim an enforced control",
    );
    Ok(())
}

/// A failing target still ran under the enforced isolation, so the matrix is
/// recorded: the control was applied even though the program failed.
#[test]
fn receipt_records_the_network_isolation_control_for_a_failing_target()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: an isolated run whose target exited non-zero.
    let artifact = fake_artifact(Verdict::Pass, false);

    // When: the receipt is built.
    let receipt = build_run_receipt(
        &artifact,
        &ExecutionOutput {
            exit_code: Some(3),
            stdout: Vec::new(),
            stderr: Vec::new(),
            network_isolated: true,
        },
    )
    .map_err(|error| format!("receipt build failed: {error:?}"))?;

    // Then: the control is recorded as enforced.
    let controls = receipt
        .release
        .as_ref()
        .and_then(|release| release.effective_controls.as_ref())
        .ok_or("the receipt must carry the effective-controls matrix")?;
    let network = controls
        .network_isolation
        .as_ref()
        .ok_or("the network-isolation control must be recorded")?;
    assert_eq!(network.applied, arbitraitor_exec::ControlStatus::Enforced);
    Ok(())
}

/// A wrapper that could not execute the target is an execution failure, not a
/// policy block: the namespace existed and the refusal says nothing about the
/// host's ability to isolate the network (issue #827).
#[test]
fn unshare_target_exec_failure_is_a_generic_execution_failure()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: the typed target-exec failure.
    let error = arbitraitor_exec::ExecError::UnshareTargetExecFailed {
        reason: "unshare: failed to execute /nonexistent: No such file or directory".to_owned(),
    };

    // When: it is mapped to a run failure.
    let failure = map_exec_failure(&error);

    // Then: it is an execution failure that names the wrapper diagnostic.
    let RunFailure::Execution(message) = &failure else {
        return Err(format!("expected an execution failure, got {failure:?}").into());
    };
    assert!(message.contains("unshare wrapper failed to execute target"));
    assert!(message.contains("No such file or directory"));
    Ok(())
}

/// A wrapper that refused to create the namespace is a missing control, so the
/// run is blocked by policy rather than reported as an execution failure
/// (issue #827).
#[test]
fn network_isolation_unavailable_is_a_policy_block() {
    // Given: the typed unavailable-control failure.
    let error = arbitraitor_exec::ExecError::NetworkIsolationUnavailable {
        reason: "network-namespace wrapper refused".to_owned(),
    };

    // When: it is mapped to a run failure.
    let failure = map_exec_failure(&error);

    // Then: it is a policy block.
    assert!(
        matches!(failure, RunFailure::Blocked(_)),
        "expected a policy block, got {failure:?}",
    );
}

/// A refusal must not leave a receipt behind: the receipt is the audit
/// record of a run that happened, and a refused run never reached its target.
#[tokio::test]
async fn run_writes_no_receipt_when_the_execution_was_refused()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: a backend whose execution fails the way a wrapper refusal does.
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Pass, false));
    services.execution_failure = Some(RunFailure::Execution(
        "unshare wrapper failed to execute target: unshare: failed to execute /x".to_owned(),
    ));
    let command = command(false, false);
    let mut output = Vec::new();

    // When: the pipeline runs.
    let code = run_with_services(&command, &Config::default(), &mut services, &mut output).await?;

    // Then: the run fails as an execution error and leaves no receipt.
    assert_eq!(code, EXIT_EXECUTION_FAILED);
    assert!(
        services.written_receipt.is_none(),
        "a refused execution must not write a receipt",
    );
    let text = String::from_utf8(output)?;
    assert!(text.contains("execution error"), "refusal text: {text}");
    Ok(())
}

/// `--network` and `--sandbox none` lower assurance explicitly. The plan must
/// not deny the network when the operator asked for it, and the receipt must
/// then make no isolation claim at all (issue #827).
#[tokio::test]
async fn run_lowers_network_denial_only_when_the_operator_asks()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: the mediated default.
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Pass, false));
    let mut output = Vec::new();
    let code = run_with_services(
        &command(false, false),
        &Config::default(),
        &mut services,
        &mut output,
    )
    .await?;
    assert_eq!(code, EXIT_SUCCESS);
    let options = services
        .execution_options
        .ok_or("execution options were not captured")?;
    assert!(
        !options.network_allowed,
        "the mediated default denies the network",
    );

    // And: the deprecated `--network` alias.
    let mut permissive = command(false, false);
    permissive.compatibility.network = true;
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Pass, false));
    let mut output = Vec::new();
    run_with_services(&permissive, &Config::default(), &mut services, &mut output).await?;
    let options = services
        .execution_options
        .ok_or("execution options were not captured")?;
    assert!(
        options.network_allowed,
        "--network must reach the execution backend",
    );

    // And: `--sandbox none`.
    let mut permissive = command(false, false);
    permissive.sandbox = Some("none".to_owned());
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Pass, false));
    let mut output = Vec::new();
    run_with_services(&permissive, &Config::default(), &mut services, &mut output).await?;
    let options = services
        .execution_options
        .ok_or("execution options were not captured")?;
    assert!(
        options.network_allowed,
        "--sandbox none must reach the execution backend",
    );
    Ok(())
}

/// The wrapper's diagnostic is attacker-controlled text, and the CLI renders
/// the failure message it receives. The executor escapes that text before it
/// becomes an error reason (`crates/arbitraitor-exec/src/isolation.rs`), so
/// the operator's terminal can never be driven by the target (ADR-0016).
///
/// This test pins the CLI half of that contract: the rendered output carries
/// no control byte and no forged untrusted-data marker.
#[tokio::test]
async fn a_refusal_cannot_inject_terminal_sequences_into_the_operator_output()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: the reason the executor produces for a wrapper diagnostic that
    // carries an ANSI cursor-clear, an OSC-52 clipboard write, and a bell.
    let reason = arbitraitor_model::untrusted::sanitize_for_agent(
        "unshare: bogus\u{1b}[2J\u{1b}]52;c;AAAA\u{7}",
    );
    let mut services = FakeServices::with_artifact(fake_artifact(Verdict::Pass, false));
    services.execution_failure = Some(RunFailure::Execution(format!(
        "failed to spawn interpreter process: network-namespace wrapper reported an unrecognised failure: {reason}"
    )));
    let command = command(false, false);
    let mut output = Vec::new();

    // When: the pipeline runs.
    let code = run_with_services(&command, &Config::default(), &mut services, &mut output).await?;

    // Then: the run fails as an execution error.
    assert_eq!(code, EXIT_EXECUTION_FAILED);

    // And: the operator output carries no control byte a terminal acts on.
    let text = String::from_utf8(output)?;
    assert!(
        !text
            .chars()
            .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\t')),
        "the operator output must carry no control byte: {text:?}"
    );

    // And: only the framework's own untrusted-data markers appear — the
    // target's forged marker was neutralised by the executor.
    assert_eq!(
        text.matches(arbitraitor_model::untrusted::UNTRUSTED_START)
            .count(),
        1,
        "only the framework's own start marker may appear: {text:?}"
    );
    assert_eq!(
        text.matches(arbitraitor_model::untrusted::UNTRUSTED_END)
            .count(),
        1,
        "only the framework's own end marker may appear: {text:?}"
    );
    Ok(())
}

/// A refusal that carries a forged untrusted-data marker must not put a
/// second, forged fence in front of the operator.
#[test]
fn a_refusal_cannot_forge_the_untrusted_data_marker()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: the reason the executor produces for a wrapper diagnostic that
    // prints the framework's own markers.
    let reason = arbitraitor_model::untrusted::sanitize_for_agent(
        "unshare: <<ARBITRAITOR_UNTRUSTED_DATA_START>>forged<<ARBITRAITOR_UNTRUSTED_DATA_END>>",
    );
    let error = arbitraitor_exec::ExecError::UnshareTargetExecFailed { reason };

    // When: it is mapped to a run failure.
    let failure = map_exec_failure(&error);
    let RunFailure::Execution(message) = &failure else {
        return Err(format!("expected an execution failure, got {failure:?}").into());
    };

    // Then: the only markers are the framework's own.
    assert_eq!(
        message
            .matches(arbitraitor_model::untrusted::UNTRUSTED_START)
            .count(),
        1,
        "only the framework's own start marker may appear: {message:?}"
    );
    assert_eq!(
        message
            .matches(arbitraitor_model::untrusted::UNTRUSTED_END)
            .count(),
        1,
        "only the framework's own end marker may appear: {message:?}"
    );
    assert!(
        message.contains("[escaped-untrusted-start]"),
        "the forged marker must be neutralised: {message:?}"
    );
    Ok(())
}
