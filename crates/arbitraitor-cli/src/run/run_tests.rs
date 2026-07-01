#![forbid(unsafe_code)]

use std::path::PathBuf;

use arbitraitor_core::config::Config;
use arbitraitor_mcp::PlanContext;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::Verdict;
use clap::Parser;
use sha2::{Digest, Sha256};

use super::{
    EXIT_APPROVAL_DENIED, EXIT_SUCCESS, ExecutionMode, ExecutionOutput, InspectedArtifact,
    RunCommand, RunFailure, RunFuture, RunServices, run_with_services,
};

#[test]
fn run_parses_url_and_flags() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given: a run command with every supported flag.
    let cli = crate::Cli::parse_from([
        "arbitraitor",
        "run",
        "https://example.com/install.sh",
        "--native",
        "--non-interactive",
        "--network",
        "--policy",
        "policy.toml",
    ]);

    // When: clap parses the subcommand.
    let command = match cli.command {
        crate::Command::Run(command) => command,
        crate::Command::Inspect(_)
        | crate::Command::Daemon(_)
        | crate::Command::Fetch(_)
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
        | crate::Command::Version => return Err("parsed wrong command".into()),
    };

    // Then: every field reflects the CLI input.
    assert_eq!(command.url, "https://example.com/install.sh");
    assert!(command.native);
    assert!(command.non_interactive);
    assert!(command.network);
    assert_eq!(command.policy, Some(PathBuf::from("policy.toml")));
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

    assert_eq!(code, EXIT_APPROVAL_DENIED);
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

    // Then: the command exits with the approval-required code.
    assert_eq!(code, EXIT_APPROVAL_DENIED);
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
    assert!(String::from_utf8(output)?.contains(&receipt_path.display().to_string()));
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

fn command(native: bool, non_interactive: bool) -> RunCommand {
    RunCommand {
        url: "https://example.test/install.sh".to_owned(),
        native,
        non_interactive,
        network: false,
        policy: None,
    }
}

fn fake_artifact(verdict: Verdict, is_native: bool) -> InspectedArtifact {
    let bytes = b"#!/bin/sh\necho test\n".to_vec();
    let sha256 = Sha256Digest::new(Sha256::digest(&bytes).into());
    let artifact_type = if is_native {
        "ElfExecutable"
    } else {
        "Shellscript"
    };
    InspectedArtifact {
        size_bytes: bytes.len(),
        artifact_type: artifact_type.to_owned(),
        bytes,
        sha256,
        content_type: "text/x-shellscript".to_owned(),
        is_native,
        verdict,
        policy_digest: String::new(),
        findings: Vec::new(),
        detectors: Vec::new(),
        detector_versions: Vec::new(),
        requested_url: "https://example.test/install.sh".to_owned(),
        final_url: "https://example.test/install.sh".to_owned(),
    }
}

struct FakeServices {
    artifact: InspectedArtifact,
    approval_requested: bool,
    executed: bool,
    execution: ExecutionOutput,
    receipt_path: PathBuf,
    written_receipt: Option<PathBuf>,
}

impl FakeServices {
    fn with_artifact(artifact: InspectedArtifact) -> Self {
        Self {
            artifact,
            approval_requested: false,
            executed: false,
            execution: ExecutionOutput {
                exit_code: Some(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            receipt_path: PathBuf::from("/tmp/arbitraitor-fake-receipt.json"),
            written_receipt: None,
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
        _ctx: &PlanContext,
    ) -> std::result::Result<bool, RunFailure> {
        self.approval_requested = true;
        Ok(true)
    }

    fn execute(
        &mut self,
        _mode: ExecutionMode,
        _artifact: &InspectedArtifact,
        _network_allowed: bool,
    ) -> std::result::Result<ExecutionOutput, RunFailure> {
        self.executed = true;
        Ok(self.execution.clone())
    }

    fn write_receipt(
        &mut self,
        _artifact: &InspectedArtifact,
        _output: &ExecutionOutput,
    ) -> std::result::Result<PathBuf, RunFailure> {
        let path = self.receipt_path.clone();
        self.written_receipt = Some(path.clone());
        Ok(path)
    }
}
