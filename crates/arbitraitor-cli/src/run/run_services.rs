// allow: SIZE_OK — single cohesive DefaultRunServices impl with private helpers
// (fetch/store/analyze, policy eval, native exec gate, receipt build). All
// functions serve the four RunServices trait methods; splitting would scatter
// one implementation across files without improving clarity.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arbitraitor_analysis::{AnalysisCoordinator, RetrievalInfo as AnalysisRetrievalInfo};
use arbitraitor_core::config::Config;
use arbitraitor_exec::script::{ExecutionResult, ScriptExecution};
use arbitraitor_exec::{EnvAllowlist, ExecutionPolicy, SandboxConfig, TempDirectoryPolicy};
#[cfg(target_os = "linux")]
use arbitraitor_exec::{NativeExecution, NativeExecutionGate};
use arbitraitor_fetch::{FetchPolicy, FetchRequest, FetchUrl, Fetcher, HttpFetcher, VecSink};
use arbitraitor_mcp::{
    AgentIdentity, ApprovalTokenIssuer, McpContent, McpToolHandler, PlanContext,
    RequestApprovalTool, StdinApprovalPrompt,
};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::Verdict;
use arbitraitor_policy::{EvalContext, PolicyEngine};
use arbitraitor_receipt::{
    ApprovalInfo, AuditEvent, DetectorVersion, FindingSummary, ReceiptBuilder, ReceiptTimestamps,
    RetrievalInfo, VerdictInfo,
};
use arbitraitor_store::ContentStore;
use sha2::{Digest, Sha256};

use crate::pipeline::{default_cas_dir, timestamp};

use super::{
    DetectorSummary, ExecutionMode, ExecutionOutput, InspectedArtifact, RunCommand,
    RunExecutionOptions, RunFailure, RunFuture, RunServices,
};

pub(super) struct DefaultRunServices;

impl RunServices for DefaultRunServices {
    fn prepare<'a>(
        &'a mut self,
        command: &'a RunCommand,
        config: &'a Config,
    ) -> RunFuture<'a, std::result::Result<InspectedArtifact, RunFailure>> {
        Box::pin(async move { prepare_artifact(command, config).await })
    }

    fn request_approval(
        &mut self,
        artifact: &InspectedArtifact,
        plan: &str,
        ctx: &PlanContext,
    ) -> std::result::Result<Option<ApprovalInfo>, RunFailure> {
        let tool = RequestApprovalTool::with_prompt(
            Arc::new(StdinApprovalPrompt),
            ApprovalTokenIssuer::new(),
            ctx.clone(),
        );
        let agent = AgentIdentity {
            integration: "arbitraitor-cli".to_owned(),
            agent_name: "human-operator".to_owned(),
            session_id: "stdin".to_owned(),
            workspace: None,
        };
        let response = tool.handle(
            serde_json::json!({ "sha256": artifact.sha256.to_string(), "plan": plan }),
            &agent,
        );
        if response.is_error {
            return Err(RunFailure::Approval("approval tool failed".to_owned()));
        }
        response
            .content
            .iter()
            .find_map(|content| match content {
                McpContent::Json { json } => {
                    json.get("approved").and_then(serde_json::Value::as_bool)
                }
                McpContent::Text { .. } => None,
            })
            .ok_or_else(|| RunFailure::Approval("approval response missing decision".to_owned()))
            .map(|approved| {
                if approved {
                    Some(ApprovalInfo {
                        plan_digest: artifact.sha256.clone(),
                        artifact_digest: artifact.sha256.clone(),
                        expiry: None,
                        nonce: format!("cli-{}", timestamp()),
                        bound_capabilities: Vec::new(),
                        override_reason: None,
                        override_scope: None,
                        exit_status: None,
                    })
                } else {
                    None
                }
            })
    }

    fn execute(
        &mut self,
        mode: ExecutionMode,
        artifact: &InspectedArtifact,
        options: &RunExecutionOptions,
    ) -> std::result::Result<ExecutionOutput, RunFailure> {
        match mode {
            ExecutionMode::Script => {
                let execution = script_execution(options)?;
                execution
                    .execute(&artifact.bytes)
                    .map(execution_output)
                    .map_err(|error| RunFailure::Execution(error.to_string()))
            }
            ExecutionMode::Native => execute_native_artifact(artifact),
        }
    }

    fn write_receipt(
        &mut self,
        artifact: &InspectedArtifact,
        output: &ExecutionOutput,
        _approval: Option<&ApprovalInfo>,
    ) -> std::result::Result<PathBuf, RunFailure> {
        let dir = arbitraitor_home()?.join("receipts");
        std::fs::create_dir_all(&dir).map_err(|error| RunFailure::Internal(error.to_string()))?;
        let digest_prefix: String = artifact.sha256.to_string().chars().take(12).collect();
        let path = dir.join(format!("{}-{digest_prefix}.json", timestamp()));
        let receipt = build_run_receipt(artifact, output)?;
        let json = serde_json::to_vec_pretty(&receipt)
            .map_err(|error| RunFailure::Internal(error.to_string()))?;
        std::fs::write(&path, json).map_err(|error| RunFailure::Internal(error.to_string()))?;
        Ok(path)
    }
}

fn script_execution(
    options: &RunExecutionOptions,
) -> std::result::Result<ScriptExecution, RunFailure> {
    let mut policy = ExecutionPolicy::default();
    if options.clean_environment {
        policy.environment_allowlist = EnvAllowlist::new(options.allow_env.clone())
            .map_err(|error| RunFailure::Execution(error.to_string()))?;
    } else {
        for name in &options.allow_env {
            policy
                .environment_allowlist
                .insert(name.clone())
                .map_err(|error| RunFailure::Execution(error.to_string()))?;
        }
    }
    if let Some(directory) = &options.working_directory {
        policy.working_directory = TempDirectoryPolicy::Fixed(directory.clone());
    }
    let execution = ScriptExecution::new(
        options.interpreter.clone(),
        options.interpreter_args.iter().map(String::as_str),
    )
    .map_err(|error| RunFailure::Execution(error.to_string()))?
    .with_environment_policy(
        policy,
        std::env::vars_os()
            .filter_map(|(name, value)| name.into_string().ok().map(|name| (name, value))),
    )
    .map_err(|error| RunFailure::Execution(error.to_string()))?
    .with_network_isolated(!options.network_allowed)
    .with_sandbox_config(sandbox_config(options.sandbox.as_deref())?);
    Ok(execution)
}

fn sandbox_config(mode: Option<&str>) -> std::result::Result<SandboxConfig, RunFailure> {
    match mode.map(str::to_ascii_lowercase).as_deref() {
        None | Some("restricted" | "disposable" | "observe") => Ok(SandboxConfig::default()),
        Some("none") => Ok(SandboxConfig {
            no_new_privs: false,
            dumpable: true,
            close_fds: false,
        }),
        Some(other) => Err(RunFailure::Execution(format!(
            "unsupported sandbox mode {other:?}; expected none, observe, restricted, or disposable"
        ))),
    }
}

async fn prepare_artifact(
    command: &RunCommand,
    config: &Config,
) -> std::result::Result<InspectedArtifact, RunFailure> {
    let fetch_url =
        FetchUrl::parse(&command.url).map_err(|error| RunFailure::Fetch(error.to_string()))?;
    let fetch_policy = FetchPolicy {
        total_timeout: Duration::from_secs(config.fetch.total_timeout_secs),
        max_compressed_size: config.fetch.max_bytes,
        max_uncompressed_size: config.fetch.max_bytes,
        max_redirects: usize::try_from(config.fetch.max_redirects)
            .map_err(|error| RunFailure::Internal(error.to_string()))?,
        require_digest: config.integrity.require_digest,
        allow_cross_origin_redirect: config.fetch.allow_cross_origin,
        forward_authorization_cross_origin: config.fetch.forward_authorization_cross_origin,
        ..FetchPolicy::default()
    };
    let request = FetchRequest::url(fetch_url.clone(), fetch_policy);
    let mut fetch_sink = VecSink::new();
    let fetch_receipt = HttpFetcher::new()
        .fetch(request, &mut fetch_sink)
        .await
        .map_err(|error| RunFailure::Fetch(error.to_string()))?;
    let bytes = fetch_sink.into_bytes();
    let sha256 = Sha256Digest::new(Sha256::digest(&bytes).into());
    if sha256 != fetch_receipt.sha256 {
        return Err(RunFailure::Fetch(
            "fetched bytes digest mismatch".to_owned(),
        ));
    }
    let cas_root = store_artifact(config, &sha256, &bytes).await?;
    let retrieval = AnalysisRetrievalInfo {
        requested_location: Some(command.url.clone()),
        final_location: fetch_receipt
            .metadata
            .final_url
            .as_ref()
            .map(ToString::to_string),
        content_type: fetch_receipt.metadata.content_type.clone(),
        byte_count: Some(fetch_receipt.bytes_written),
    };
    let result = AnalysisCoordinator::new().analyze_with_retrieval(&bytes, Some(retrieval));
    let policy_decision =
        policy_decision(command, &result, fetch_url.as_url().scheme() == "https")?;
    let detector_versions = result
        .detector_results
        .iter()
        .map(|detector| DetectorVersion {
            id: detector.metadata.id.clone(),
            version: detector.metadata.version.clone(),
        })
        .collect();
    let detectors = result
        .detector_results
        .iter()
        .map(|detector| DetectorSummary {
            name: detector.metadata.id.clone(),
            findings: detector.finding_count,
        })
        .collect();
    let content_type = fetch_receipt
        .metadata
        .content_type
        .clone()
        .unwrap_or_else(|| format!("{:?}", result.classification.artifact_type));
    Ok(InspectedArtifact {
        bytes,
        sha256,
        size_bytes: usize::try_from(fetch_receipt.bytes_written)
            .map_err(|error| RunFailure::Internal(error.to_string()))?,
        content_type,
        artifact_type: result.classification.artifact_type,
        verdict: policy_decision.verdict,
        policy_digest: policy_decision.digest,
        findings: result.findings,
        detectors,
        detector_versions,
        audit_trail: policy_decision.audit_trail,
        requested_url: command.url.clone(),
        final_url: fetch_receipt
            .metadata
            .final_url
            .as_ref()
            .map_or_else(|| command.url.clone(), ToString::to_string),
        store_dir: cas_root,
    })
}

async fn store_artifact(
    config: &Config,
    sha256: &Sha256Digest,
    bytes: &[u8],
) -> std::result::Result<PathBuf, RunFailure> {
    let cas_root = config.store.cas_dir.clone().unwrap_or_else(default_cas_dir);
    let store =
        ContentStore::open(&cas_root).map_err(|error| RunFailure::Internal(error.to_string()))?;
    let mut sink = store
        .sink(Some(sha256))
        .map_err(|error| RunFailure::Internal(error.to_string()))?;
    sink.write_chunk(bytes)
        .await
        .map_err(|error| RunFailure::Internal(error.to_string()))?;
    let stored = sink
        .finish()
        .await
        .map_err(|error| RunFailure::Internal(error.to_string()))?;
    if stored == *sha256 {
        Ok(cas_root)
    } else {
        Err(RunFailure::Internal("CAS digest mismatch".to_owned()))
    }
}

struct PolicyDecision {
    verdict: Verdict,
    digest: String,
    audit_trail: Vec<String>,
}

fn policy_decision(
    command: &RunCommand,
    result: &arbitraitor_analysis::AnalysisResult,
    is_https: bool,
) -> std::result::Result<PolicyDecision, RunFailure> {
    let Some(path) = &command.compatibility.policy else {
        return Ok(PolicyDecision {
            verdict: result.verdict,
            digest: String::new(),
            audit_trail: Vec::new(),
        });
    };
    validate_cli_policy_override(command)?;
    let policy_toml =
        std::fs::read_to_string(path).map_err(|error| RunFailure::Internal(error.to_string()))?;
    let engine = PolicyEngine::load(&policy_toml)
        .map_err(|error| RunFailure::Internal(error.to_string()))?;
    let context = EvalContext::new(!command.approval.non_interactive)
        .with_artifact_type(format!("{:?}", result.classification.artifact_type))
        .with_source_url(command.url.clone())
        .with_https(is_https)
        .with_private_network(false);
    let digest = engine.digest();
    Ok(PolicyDecision {
        verdict: engine.evaluate(&result.findings, &context),
        digest: digest.clone(),
        audit_trail: vec![format!(
            "CLI policy override applied from {} with --audit-override; digest={digest}",
            path.display()
        )],
    })
}

pub(super) fn validate_cli_policy_override(
    command: &RunCommand,
) -> std::result::Result<(), RunFailure> {
    if command.compatibility.policy.is_some() && !command.compatibility.audit_override {
        return Err(RunFailure::Blocked(
            "--policy is a CLI policy override and requires --audit-override".to_owned(),
        ));
    }
    Ok(())
}

fn execution_output(result: ExecutionResult) -> ExecutionOutput {
    ExecutionOutput {
        exit_code: result.exit_code,
        stdout: result.stdout,
        stderr: result.stderr,
    }
}

#[cfg(target_os = "linux")]
fn execute_native_artifact(
    artifact: &InspectedArtifact,
) -> std::result::Result<ExecutionOutput, RunFailure> {
    let _gate = NativeExecutionGate::new();
    let path = native_release_path(&artifact.sha256)?;
    release_native_via_safe_destination(artifact, &path)?;
    NativeExecution::new()
        .map_err(|error| RunFailure::Execution(error.to_string()))?
        .execute(&path)
        .map(execution_output)
        .map_err(|error| RunFailure::Execution(error.to_string()))
}

#[cfg(not(target_os = "linux"))]
fn execute_native_artifact(
    _artifact: &InspectedArtifact,
) -> std::result::Result<ExecutionOutput, RunFailure> {
    Err(RunFailure::Execution(
        "native execution is only wired on linux hosts".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
pub(super) fn release_native_via_safe_destination(
    artifact: &InspectedArtifact,
    destination: &Path,
) -> std::result::Result<(), RunFailure> {
    use arbitraitor_exec::release::{ReleasePolicy, release_artifact};

    let store = ContentStore::open(&artifact.store_dir)
        .map_err(|error| RunFailure::Execution(error.to_string()))?;
    let policy = ReleasePolicy {
        allow_overwrite: true,
        #[cfg(unix)]
        final_mode: Some(0o700),
        ..ReleasePolicy::default()
    };
    release_artifact(&store, &artifact.sha256, destination, &policy)
        .map_err(|error| RunFailure::Execution(error.to_string()))?;
    Ok(())
}

fn native_release_path(sha256: &Sha256Digest) -> std::result::Result<PathBuf, RunFailure> {
    let dir = arbitraitor_home()?.join("native");
    std::fs::create_dir_all(&dir).map_err(|error| RunFailure::Execution(error.to_string()))?;
    Ok(dir.join(format!("{sha256}.bin")))
}

pub(super) fn build_run_receipt(
    artifact: &InspectedArtifact,
    output: &ExecutionOutput,
) -> std::result::Result<arbitraitor_receipt::Receipt, RunFailure> {
    let now = timestamp();
    let artifact_size = u64::try_from(artifact.size_bytes)
        .map_err(|error| RunFailure::Internal(error.to_string()))?;
    let mut builder = ReceiptBuilder::new(
        env!("CARGO_PKG_VERSION"),
        artifact.sha256.to_string(),
        artifact_size,
        VerdictInfo {
            verdict: artifact.verdict,
            deciding_rule: None,
            policy_trace: vec!["arbitraitor-cli run pipeline".to_owned()],
        },
        ReceiptTimestamps {
            created: now.clone(),
            modified: now.clone(),
        },
    )
    .policy_digest(artifact.policy_digest.clone())
    .artifact_type(format!("{:?}", artifact.artifact_type))
    .retrieval(
        RetrievalInfo::new(artifact.requested_url.clone())
            .with_final_url(artifact.final_url.clone()),
    )
    .findings(artifact.findings.iter().map(FindingSummary::from))
    .release(arbitraitor_receipt::ReleaseInfo {
        method: arbitraitor_receipt::ReleaseMethod::Execute,
        destination: Some(format!("exit-code={:?}", output.exit_code)),
        sha256_verified: true,
        timestamp: now,
        approval: None,
        effective_controls: None,
    });
    for detector in &artifact.detector_versions {
        builder = builder.detector_version(detector.clone());
    }
    for event in &artifact.audit_trail {
        builder = builder.audit_event(AuditEvent {
            kind: "cli-policy-override".to_owned(),
            detail: event.clone(),
        });
    }
    Ok(builder.build())
}

fn arbitraitor_home() -> std::result::Result<PathBuf, RunFailure> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".arbitraitor"))
        .ok_or_else(|| RunFailure::Internal("HOME is not set".to_owned()))
}
