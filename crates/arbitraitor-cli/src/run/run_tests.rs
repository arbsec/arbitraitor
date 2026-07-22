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

use super::run_services::{build_run_receipt, validate_cli_policy_override};
use super::{
    DeprecatedRunAliases, EXIT_SUCCESS, ExecutionMode, ExecutionOutput, InspectedArtifact,
    RunApprovalFlags, RunCommand, RunExecutionOptions, RunFailure, RunFuture, RunServices,
    run_with_services,
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
        },
    )
    .map_err(|error| format!("receipt build failed: {error:?}"))?;

    // Then: the receipt records the override.
    assert_eq!(receipt.audit_trail.len(), 1);
    assert_eq!(receipt.audit_trail[0].kind, "cli-policy-override");
    assert!(
        receipt.audit_trail[0]
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
    assert!(options.interpreter_args.is_empty());
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

    assert_eq!(code, 7);
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
    approval_requested: bool,
    approval_context: Option<PlanContext>,
    executed: bool,
    execution_options: Option<RunExecutionOptions>,
    execution: ExecutionOutput,
    receipt_path: PathBuf,
    written_receipt: Option<PathBuf>,
    receipt_approval: Option<ApprovalInfo>,
}

impl FakeServices {
    fn with_artifact(artifact: InspectedArtifact) -> Self {
        Self {
            artifact,
            approval_requested: false,
            approval_context: None,
            executed: false,
            execution_options: None,
            execution: ExecutionOutput {
                exit_code: Some(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            receipt_path: PathBuf::from("/tmp/arbitraitor-fake-receipt.json"),
            written_receipt: None,
            receipt_approval: None,
        }
    }
}

impl RunServices for FakeServices {
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
        Ok(self.execution.clone())
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
