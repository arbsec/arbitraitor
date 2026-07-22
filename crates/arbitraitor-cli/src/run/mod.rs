#![forbid(unsafe_code)]

mod run_services;
#[cfg(test)]
mod run_tests;

use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, UNIX_EPOCH};

use arbitraitor_artifact::{ArtifactType, ShellKind};
use arbitraitor_core::config::Config;
use arbitraitor_mcp::{PlanContext, sanitize_for_agent};
use arbitraitor_model::exit_code::ExitCode;
use arbitraitor_model::finding::Finding;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::Verdict;
use arbitraitor_receipt::{ApprovalInfo, DetectorVersion};
use clap::Args;
use miette::{IntoDiagnostic, Result};
use sha2::{Digest, Sha256};

use self::run_services::DefaultRunServices;
use crate::approval::ApprovalFile;

// Spec §29 exit codes. The constants below are kept as private aliases so
// the historical `i32`-typed call sites in this module can switch to
// `ExitCode` incrementally without a wide-bore refactor in this PR.
const EXIT_SUCCESS: i32 = ExitCode::Success.as_i32();
const EXIT_EXECUTION_FAILED: i32 = ExitCode::ExecutionFailed.as_i32();
const EXIT_APPROVAL_DENIED: i32 = ExitCode::ApprovalDeclined.as_i32();
const EXIT_FETCH_ERROR: i32 = ExitCode::NetworkRetrievalFailure.as_i32();
const EXIT_DETECTION_ERROR: i32 = ExitCode::RequiredDetectorUnavailable.as_i32();
const EXIT_INTERNAL_ERROR: i32 = ExitCode::InternalInvariantFailure.as_i32();

type RunFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Run an artifact through the full inspection → approval → execution pipeline.
#[derive(Args, Clone, Debug)]
pub struct RunCommand {
    /// URL to fetch and execute.
    pub url: String,

    /// Interpreter path for script execution.
    #[arg(long, value_name = "PATH")]
    pub interpreter: Option<PathBuf>,

    #[command(flatten)]
    pub(super) approval: RunApprovalFlags,

    /// Working directory assigned to the child process.
    #[arg(long, value_name = "PATH")]
    pub working_directory: Option<PathBuf>,

    /// Environment variable copied when `--clean-environment` is set.
    #[arg(long, value_name = "VAR")]
    pub allow_env: Vec<String>,

    /// Sandbox mode override (`none`, `observe`, `restricted`, `disposable`).
    #[arg(long, value_name = "MODE")]
    pub sandbox: Option<String>,

    /// Pre-approved approval file path.
    #[arg(long, value_name = "PATH")]
    pub approve: Option<PathBuf>,

    #[command(flatten)]
    pub(super) compatibility: DeprecatedRunAliases,
}

#[derive(Args, Clone, Debug)]
pub(super) struct RunApprovalFlags {
    /// Pre-approve native binary execution without interactive prompt.
    #[arg(long)]
    pub native: bool,

    /// Skip interactive approval prompts.
    #[arg(long)]
    pub non_interactive: bool,

    /// Start the child with an empty environment allowlist.
    #[arg(long)]
    pub clean_environment: bool,
}

#[derive(Args, Clone, Debug)]
pub(super) struct DeprecatedRunAliases {
    /// Deprecated alias retained for compatibility; use `--sandbox none` for
    /// unrestricted execution instead.
    #[arg(long, hide = true)]
    pub network: bool,

    /// Deprecated policy file path alias retained for compatibility.
    #[arg(long, hide = true)]
    pub policy: Option<PathBuf>,

    /// Required to apply a command-line policy override.
    #[arg(long, hide = true)]
    pub audit_override: bool,
}

impl RunCommand {
    fn interpreter_path(&self) -> PathBuf {
        self.interpreter
            .clone()
            .unwrap_or_else(|| PathBuf::from("/bin/bash"))
    }

    fn interpreter_arguments(&self) -> Vec<String> {
        if self.interpreter.is_some() {
            Vec::new()
        } else {
            vec!["--noprofile".to_owned(), "--norc".to_owned()]
        }
    }

    fn network_allowed(&self) -> bool {
        self.compatibility.network || self.sandbox.as_deref() == Some("none")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RunExecutionOptions {
    interpreter: PathBuf,
    interpreter_args: Vec<String>,
    working_directory: Option<PathBuf>,
    clean_environment: bool,
    allow_env: Vec<String>,
    sandbox: Option<String>,
    network_allowed: bool,
}

impl RunExecutionOptions {
    fn from_command(command: &RunCommand) -> Self {
        Self {
            interpreter: command.interpreter_path(),
            interpreter_args: command.interpreter_arguments(),
            working_directory: command.working_directory.clone(),
            clean_environment: command.approval.clean_environment,
            allow_env: command.allow_env.clone(),
            sandbox: command.sandbox.clone(),
            network_allowed: command.network_allowed(),
        }
    }
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
    artifact_type: ArtifactType,
    verdict: Verdict,
    policy_digest: String,
    allow_rule_metadata: Vec<arbitraitor_receipt::AllowRuleMetadata>,
    findings: Vec<Finding>,
    detectors: Vec<DetectorSummary>,
    detector_versions: Vec<DetectorVersion>,
    audit_trail: Vec<String>,
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
    Blocked(String),
    PromptRequired(String),
    AnalysisIncomplete(String),
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
    ) -> std::result::Result<Option<ApprovalInfo>, RunFailure>;

    fn execute(
        &mut self,
        mode: ExecutionMode,
        artifact: &InspectedArtifact,
        options: &RunExecutionOptions,
    ) -> std::result::Result<ExecutionOutput, RunFailure>;

    fn write_receipt(
        &mut self,
        artifact: &InspectedArtifact,
        output: &ExecutionOutput,
        approval: Option<&ApprovalInfo>,
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
    write_deprecated_alias_warnings(writer, command)?;
    writeln!(writer, "Fetching {}...", command.url).into_diagnostic()?;
    let artifact = match services.prepare(command, config).await {
        Ok(artifact) => artifact,
        Err(error) => return write_failure(writer, error),
    };
    write_fetch_summary(writer, &artifact)?;
    write_detection_summary(writer, &artifact)?;

    let mode = match execution_mode_for_type(artifact.artifact_type) {
        Ok(mode) => mode,
        Err(message) => return write_failure(writer, RunFailure::Blocked(message)),
    };
    let options = RunExecutionOptions::from_command(command);
    let network_isolated = !options.network_allowed;
    let plan = execution_plan(mode, network_isolated);
    let mut ctx = plan_context(command, &artifact, network_isolated);
    if mode == ExecutionMode::Native {
        ctx.interpreter = format!("native:{}", artifact.sha256);
    }
    writeln!(writer, "Plan: {plan}").into_diagnostic()?;
    let mut approval_info = None;

    if mode == ExecutionMode::Native && !command.approval.native {
        if command.approval.non_interactive && command.approve.is_none() {
            return write_failure(
                writer,
                RunFailure::PromptRequired(
                    "native binary detected; pass --native to confirm native execution".to_owned(),
                ),
            );
        }
        let approval = match request_approval(command, services, &artifact, &plan, &ctx) {
            Ok(approval) => approval,
            Err(error) => return write_failure(writer, error),
        };
        if approval.is_none() {
            return write_failure(
                writer,
                RunFailure::Approval("native execution not approved".to_owned()),
            );
        }
        approval_info = approval;
        writeln!(writer, "Native execution approved.").into_diagnostic()?;
    }

    match artifact.verdict {
        Verdict::Pass | Verdict::Warn => {}
        Verdict::Prompt if command.approval.non_interactive && command.approve.is_none() => {
            return write_failure(
                writer,
                RunFailure::PromptRequired("approval required in non-interactive mode".to_owned()),
            );
        }
        Verdict::Prompt => {
            let approval = match request_approval(command, services, &artifact, &plan, &ctx) {
                Ok(approval) => approval,
                Err(error) => return write_failure(writer, error),
            };
            if approval.is_none() {
                return write_failure(writer, RunFailure::Approval("approval denied".to_owned()));
            }
            approval_info = approval;
            writeln!(writer, "Approved. Executing...").into_diagnostic()?;
        }
        Verdict::Block => {
            return write_failure(
                writer,
                RunFailure::Blocked("policy blocked execution".to_owned()),
            );
        }
        Verdict::Error => {
            return write_failure(
                writer,
                RunFailure::Detection("fatal error during analysis".to_owned()),
            );
        }
        Verdict::Incomplete => {
            return write_failure(
                writer,
                RunFailure::AnalysisIncomplete(
                    "required detection coverage not achieved".to_owned(),
                ),
            );
        }
    }

    let output = match services.execute(mode, &artifact, &options) {
        Ok(output) => output,
        Err(error) => return write_failure(writer, error),
    };
    if let Some(approval) = &mut approval_info {
        approval.exit_status = output.exit_code;
    }
    finish_run(services, writer, &artifact, &output, approval_info.as_ref())
}

fn finish_run(
    services: &mut impl RunServices,
    writer: &mut impl Write,
    artifact: &InspectedArtifact,
    output: &ExecutionOutput,
    approval_info: Option<&ApprovalInfo>,
) -> Result<i32> {
    write_sanitized_output(writer, output)?;
    let receipt_path = match services.write_receipt(artifact, output, approval_info) {
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

fn write_deprecated_alias_warnings(writer: &mut impl Write, command: &RunCommand) -> Result<()> {
    if command.compatibility.network {
        writeln!(
            writer,
            "warning: --network is deprecated; use --sandbox none"
        )
        .into_diagnostic()?;
    }
    if command.compatibility.policy.is_some() {
        writeln!(
            writer,
            "warning: --policy is deprecated and hidden from help"
        )
        .into_diagnostic()?;
    }
    Ok(())
}

fn plan_context(
    command: &RunCommand,
    artifact: &InspectedArtifact,
    network_isolated: bool,
) -> PlanContext {
    let interpreter = command.interpreter_path();
    PlanContext {
        interpreter: interpreter.display().to_string(),
        interpreter_digest: interpreter_digest_or_empty(&interpreter),
        network_isolated,
        policy_snapshot_digest: artifact.policy_digest.clone(),
        detector_snapshot_digest: detector_snapshot_digest(artifact),
        intelligence_snapshot_digest: String::new(),
    }
}

fn request_approval(
    command: &RunCommand,
    services: &mut impl RunServices,
    artifact: &InspectedArtifact,
    plan: &str,
    ctx: &PlanContext,
) -> std::result::Result<Option<ApprovalInfo>, RunFailure> {
    if let Some(path) = &command.approve {
        validate_approval_file(path, artifact, ctx).map(Some)
    } else {
        services.request_approval(artifact, plan, ctx)
    }
}

fn validate_approval_file(
    path: &Path,
    artifact: &InspectedArtifact,
    ctx: &PlanContext,
) -> std::result::Result<ApprovalInfo, RunFailure> {
    let bytes = std::fs::read(path).map_err(|error| RunFailure::Approval(error.to_string()))?;
    let approval: ApprovalFile = serde_json::from_slice(&bytes)
        .map_err(|error| RunFailure::Approval(format!("invalid approval file: {error}")))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    approval
        .verify(now)
        .map_err(|error| RunFailure::Approval(error.to_string()))?;
    if approval.artifact_sha256 != artifact.sha256.to_string() {
        return Err(RunFailure::Approval(
            "approval artifact digest does not match fetched artifact".to_owned(),
        ));
    }
    if approval.interpreter != ctx.interpreter {
        return Err(RunFailure::Approval(
            "approval interpreter does not match execution plan".to_owned(),
        ));
    }
    if approval.network_isolated != ctx.network_isolated {
        return Err(RunFailure::Approval(
            "approval network policy does not match execution plan".to_owned(),
        ));
    }
    if approval.policy_snapshot_digest != ctx.policy_snapshot_digest {
        return Err(RunFailure::Approval(
            "approval policy digest does not match execution plan".to_owned(),
        ));
    }
    approval_info_from_file(&approval, artifact, None)
}

pub(super) fn approval_info_from_file(
    approval: &ApprovalFile,
    artifact: &InspectedArtifact,
    exit_status: Option<i32>,
) -> std::result::Result<ApprovalInfo, RunFailure> {
    let plan_digest = approval.plan_digest.parse().map_err(
        |error: arbitraitor_model::ids::Sha256DigestParseError| {
            RunFailure::Approval(format!("approval plan digest is invalid: {error}"))
        },
    )?;
    let artifact_digest = approval.artifact_sha256.parse().map_err(
        |error: arbitraitor_model::ids::Sha256DigestParseError| {
            RunFailure::Approval(format!("approval artifact digest is invalid: {error}"))
        },
    )?;
    Ok(ApprovalInfo {
        plan_digest,
        artifact_digest,
        expiry: Some(UNIX_EPOCH + Duration::from_secs(approval.expires_at)),
        nonce: approval.nonce.clone(),
        bound_capabilities: approval_capabilities(
            approval.network_isolated,
            &approval.filesystem_grants,
        ),
        override_reason: Some(approval.verdict.clone()),
        override_scope: Some(format!("artifact:{}", artifact.sha256)),
        exit_status,
    })
}

pub(super) fn approval_capabilities(
    network_isolated: bool,
    filesystem_grants: &[String],
) -> Vec<String> {
    let mut capabilities = vec!["process:execute".to_owned()];
    if network_isolated {
        capabilities.push("network:isolated".to_owned());
    } else {
        capabilities.push("network:allowed".to_owned());
    }
    if filesystem_grants.is_empty() {
        capabilities.push("filesystem:none".to_owned());
    } else {
        capabilities.extend(
            filesystem_grants
                .iter()
                .map(|grant| format!("filesystem:{grant}")),
        );
    }
    capabilities
}

fn detector_snapshot_digest(artifact: &InspectedArtifact) -> String {
    artifact
        .detector_versions
        .iter()
        .map(|version| format!("{}:{}", version.id, version.version))
        .collect::<Vec<_>>()
        .join(",")
}

fn interpreter_digest_or_empty(path: &Path) -> String {
    std::fs::read(path)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .unwrap_or_default()
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

/// Maps an [`ArtifactType`] to the execution mode the `run` pipeline will
/// use to dispatch it.
///
/// Only shell scripts and native executables are runnable by the current
/// `run` pipeline. PowerShell, Python, and JavaScript artifacts would need
/// interpreter discovery + path canonicalization that is not yet wired into
/// `run_services`; attempting to execute them by piping their bytes to
/// `/bin/bash` is incorrect (the interpreter does not understand them) and
/// unsafe (the bytes may incidentally contain bash-parseable constructs).
/// Piping arbitrary text/markup (HTML, JSON, XML, `GenericText`,
/// `GenericBinary`, archives, compressed payloads, `Unknown`) to bash is
/// likewise a foot-gun: HTML can contain `$(...)` and redirections that
/// bash would happily run. We fail closed instead — see ADR-0036 for the
/// rationale.
fn execution_mode_for_type(artifact_type: ArtifactType) -> Result<ExecutionMode, String> {
    match artifact_type {
        ArtifactType::ShellScript(ShellKind::Posix | ShellKind::Bash) => Ok(ExecutionMode::Script),
        ArtifactType::PeExecutable
        | ArtifactType::ElfExecutable
        | ArtifactType::MachOExecutable => Ok(ExecutionMode::Native),
        other => Err(format!(
            "artifact type {other:?} is not executable via the run pipeline; \
             only shell scripts and native executables are runnable"
        )),
    }
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
        RunFailure::Blocked(message) => (
            ExitCode::BlockedByPolicy.as_i32(),
            "blocked by policy",
            message,
        ),
        RunFailure::PromptRequired(message) => (
            ExitCode::PromptInNonInteractive.as_i32(),
            "prompt required in non-interactive mode",
            message,
        ),
        RunFailure::AnalysisIncomplete(message) => (
            ExitCode::AnalysisIncomplete.as_i32(),
            "analysis incomplete",
            message,
        ),
    };
    writeln!(writer, "{label}: {message}").into_diagnostic()?;
    Ok(code)
}
