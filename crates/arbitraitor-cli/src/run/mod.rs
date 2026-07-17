#![forbid(unsafe_code)]

mod run_services;
#[cfg(test)]
mod run_tests;

use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::pin::Pin;

use arbitraitor_core::config::Config;
use arbitraitor_mcp::{PlanContext, sanitize_for_agent};
use arbitraitor_model::finding::Finding;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::Verdict;
use arbitraitor_receipt::DetectorVersion;
use clap::Args;
use miette::{IntoDiagnostic, Result};

use self::run_services::DefaultRunServices;

const EXIT_SUCCESS: i32 = 0;
const EXIT_EXECUTION_FAILED: i32 = 33;
const EXIT_APPROVAL_DENIED: i32 = 21;
const EXIT_FETCH_ERROR: i32 = 33;
const EXIT_DETECTION_ERROR: i32 = 34;
const EXIT_INTERNAL_ERROR: i32 = 33;

type RunFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Run an artifact through the full inspection → approval → execution pipeline.
#[derive(Args, Clone, Debug)]
pub struct RunCommand {
    /// URL to fetch and execute.
    pub url: String,

    /// Pre-approve native binary execution without interactive prompt.
    #[arg(long)]
    pub native: bool,

    /// Skip interactive approval prompts.
    #[arg(long)]
    pub non_interactive: bool,

    /// Allow network access during execution (default: isolated).
    #[arg(long)]
    pub network: bool,

    /// Policy file path.
    #[arg(long)]
    pub policy: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub(super) struct DetectorSummary {
    name: String,
    findings: usize,
}

#[derive(Clone, Debug)]
pub(super) struct InspectedArtifact {
    bytes: Vec<u8>,
    sha256: Sha256Digest,
    size_bytes: usize,
    content_type: String,
    artifact_type: String,
    is_native: bool,
    verdict: Verdict,
    policy_digest: String,
    findings: Vec<Finding>,
    detectors: Vec<DetectorSummary>,
    detector_versions: Vec<DetectorVersion>,
    requested_url: String,
    final_url: String,
    store_dir: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ExecutionMode {
    Script,
    Native,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ExecutionOutput {
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RunFailure {
    Fetch(String),
    Detection(String),
    Approval(String),
    Execution(String),
    Internal(String),
}

pub(super) trait RunServices {
    fn prepare<'a>(
        &'a mut self,
        command: &'a RunCommand,
        config: &'a Config,
    ) -> RunFuture<'a, std::result::Result<InspectedArtifact, RunFailure>>;

    fn request_approval(
        &mut self,
        artifact: &InspectedArtifact,
        plan: &str,
        ctx: &PlanContext,
    ) -> std::result::Result<bool, RunFailure>;

    fn execute(
        &mut self,
        mode: ExecutionMode,
        artifact: &InspectedArtifact,
        network_allowed: bool,
    ) -> std::result::Result<ExecutionOutput, RunFailure>;

    fn write_receipt(
        &mut self,
        artifact: &InspectedArtifact,
        output: &ExecutionOutput,
    ) -> std::result::Result<PathBuf, RunFailure>;
}

pub async fn run(command: RunCommand, config: &Config) -> Result<i32> {
    let mut services = DefaultRunServices;
    run_with_services(
        &command,
        config,
        &mut services,
        &mut std::io::stderr().lock(),
    )
    .await
}

async fn run_with_services(
    command: &RunCommand,
    config: &Config,
    services: &mut impl RunServices,
    writer: &mut impl Write,
) -> Result<i32> {
    writeln!(writer, "Fetching {}...", command.url).into_diagnostic()?;
    let artifact = match services.prepare(command, config).await {
        Ok(artifact) => artifact,
        Err(error) => return write_failure(writer, error),
    };
    write_fetch_summary(writer, &artifact)?;
    write_detection_summary(writer, &artifact)?;

    let mode = if artifact.is_native {
        ExecutionMode::Native
    } else {
        ExecutionMode::Script
    };
    let network_isolated = !command.network;
    let plan = execution_plan(mode, network_isolated);
    let mut ctx = PlanContext::for_bash(network_isolated, artifact.policy_digest.clone());
    if mode == ExecutionMode::Native {
        ctx.interpreter = format!("native:{}", artifact.sha256);
    }
    writeln!(writer, "Plan: {plan}").into_diagnostic()?;

    if mode == ExecutionMode::Native && !command.native {
        if command.non_interactive {
            return write_failure(
                writer,
                RunFailure::Approval(
                    "native binary detected; pass --native to confirm native execution".to_owned(),
                ),
            );
        }
        let approved = match services.request_approval(&artifact, &plan, &ctx) {
            Ok(approved) => approved,
            Err(error) => return write_failure(writer, error),
        };
        if !approved {
            return write_failure(
                writer,
                RunFailure::Approval("native execution not approved".to_owned()),
            );
        }
        writeln!(writer, "Native execution approved.").into_diagnostic()?;
    }

    match artifact.verdict {
        Verdict::Pass | Verdict::Warn => {}
        Verdict::Prompt if command.non_interactive => {
            return write_failure(
                writer,
                RunFailure::Approval("approval required in non-interactive mode".to_owned()),
            );
        }
        Verdict::Prompt => {
            let approved = match services.request_approval(&artifact, &plan, &ctx) {
                Ok(approved) => approved,
                Err(error) => return write_failure(writer, error),
            };
            if !approved {
                return write_failure(writer, RunFailure::Approval("approval denied".to_owned()));
            }
            writeln!(writer, "Approved. Executing...").into_diagnostic()?;
        }
        Verdict::Block => {
            return write_failure(
                writer,
                RunFailure::Approval("policy blocked execution".to_owned()),
            );
        }
        Verdict::Error => {
            return write_failure(
                writer,
                RunFailure::Internal("fatal error during analysis".to_owned()),
            );
        }
        Verdict::Incomplete => {
            return write_failure(
                writer,
                RunFailure::Detection("required detection coverage not achieved".to_owned()),
            );
        }
    }

    let output = match services.execute(mode, &artifact, command.network) {
        Ok(output) => output,
        Err(error) => return write_failure(writer, error),
    };
    write_sanitized_output(writer, &output)?;
    let receipt_path = match services.write_receipt(&artifact, &output) {
        Ok(path) => path,
        Err(error) => return write_failure(writer, error),
    };
    let exit_code = output.exit_code.unwrap_or(EXIT_EXECUTION_FAILED);
    writeln!(writer, "Exit code: {exit_code}").into_diagnostic()?;
    writeln!(writer, "Receipt written to: {}", receipt_path.display()).into_diagnostic()?;
    if exit_code == 0 {
        Ok(EXIT_SUCCESS)
    } else {
        Ok(exit_code)
    }
}

fn execution_plan(mode: ExecutionMode, network_isolated: bool) -> String {
    let executor = match mode {
        ExecutionMode::Script => "execute via /bin/bash",
        ExecutionMode::Native => "execute as native binary",
    };
    let network = if network_isolated {
        "network isolated"
    } else {
        "network allowed"
    };
    format!("{executor} with {network}")
}

fn write_fetch_summary(writer: &mut impl Write, artifact: &InspectedArtifact) -> Result<()> {
    writeln!(writer, "  → sha256:{}", artifact.sha256).into_diagnostic()?;
    writeln!(
        writer,
        "  → {} bytes, {}",
        artifact.size_bytes, artifact.content_type
    )
    .into_diagnostic()?;
    Ok(())
}

fn write_detection_summary(writer: &mut impl Write, artifact: &InspectedArtifact) -> Result<()> {
    writeln!(writer).into_diagnostic()?;
    writeln!(writer, "Detecting threats...").into_diagnostic()?;
    for detector in &artifact.detectors {
        writeln!(
            writer,
            "  {}: {} findings",
            detector.name, detector.findings
        )
        .into_diagnostic()?;
    }
    writeln!(writer).into_diagnostic()?;
    writeln!(
        writer,
        "Verdict: {:?} ({} findings)",
        artifact.verdict,
        artifact.findings.len()
    )
    .into_diagnostic()?;
    for finding in &artifact.findings {
        writeln!(writer, "  - {}", finding.title).into_diagnostic()?;
    }
    Ok(())
}

fn write_sanitized_output(writer: &mut impl Write, output: &ExecutionOutput) -> Result<()> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.is_empty() {
        writeln!(writer, "{}", sanitize_for_agent(&stdout)).into_diagnostic()?;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        writeln!(writer, "{}", sanitize_for_agent(&stderr)).into_diagnostic()?;
    }
    Ok(())
}

fn write_failure(writer: &mut impl Write, failure: RunFailure) -> Result<i32> {
    let (code, label, message) = match failure {
        RunFailure::Fetch(message) => (EXIT_FETCH_ERROR, "fetch error", message),
        RunFailure::Detection(message) => (EXIT_DETECTION_ERROR, "detection error", message),
        RunFailure::Approval(message) => (EXIT_APPROVAL_DENIED, "approval denied", message),
        RunFailure::Execution(message) => (EXIT_EXECUTION_FAILED, "execution error", message),
        RunFailure::Internal(message) => (EXIT_INTERNAL_ERROR, "internal error", message),
    };
    writeln!(writer, "{label}: {message}").into_diagnostic()?;
    Ok(code)
}
