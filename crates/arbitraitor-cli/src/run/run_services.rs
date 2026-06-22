// allow: SIZE_OK — single cohesive DefaultRunServices impl with private helpers
// (fetch/store/analyze, policy eval, native exec gate, receipt build). All
// functions serve the four RunServices trait methods; splitting would scatter
// one implementation across files without improving clarity.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arbitraitor_analysis::{AnalysisCoordinator, RetrievalInfo as AnalysisRetrievalInfo};
use arbitraitor_artifact::ArtifactType;
use arbitraitor_core::config::Config;
use arbitraitor_exec::script::ExecutionResult;
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
    DetectorVersion, FindingSummary, ReceiptBuilder, ReceiptTimestamps, RetrievalInfo, VerdictInfo,
};
use arbitraitor_store::ContentStore;
use sha2::{Digest, Sha256};

use super::{
    DetectorSummary, ExecutionMode, ExecutionOutput, InspectedArtifact, RunCommand, RunFailure,
    RunFuture, RunServices,
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
    ) -> std::result::Result<bool, RunFailure> {
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
    }

    fn execute(
        &mut self,
        mode: ExecutionMode,
        artifact: &InspectedArtifact,
        network_allowed: bool,
    ) -> std::result::Result<ExecutionOutput, RunFailure> {
        match mode {
            ExecutionMode::Script => {
                let execution = arbitraitor_exec::script::ScriptExecution::bash()
                    .map_err(|error| RunFailure::Execution(error.to_string()))?
                    .with_network_isolated(!network_allowed);
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
    ) -> std::result::Result<PathBuf, RunFailure> {
        let dir = arbitraitor_home()?.join("receipts");
        std::fs::create_dir_all(&dir).map_err(|error| RunFailure::Internal(error.to_string()))?;
        let digest_prefix: String = artifact.sha256.to_string().chars().take(12).collect();
        let path = dir.join(format!("{}-{digest_prefix}.json", crate::timestamp()));
        let receipt = build_run_receipt(artifact, output)?;
        let json = serde_json::to_vec_pretty(&receipt)
            .map_err(|error| RunFailure::Internal(error.to_string()))?;
        std::fs::write(&path, json).map_err(|error| RunFailure::Internal(error.to_string()))?;
        Ok(path)
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
    store_artifact(config, &sha256, &bytes).await?;
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
    let verdict = policy_verdict(command, &result, fetch_url.as_url().scheme() == "https")?;
    let policy_digest = policy_digest(command)?;
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
        artifact_type: format!("{:?}", result.classification.artifact_type),
        is_native: is_native_artifact(result.classification.artifact_type),
        verdict,
        policy_digest,
        findings: result.findings,
        detectors,
        detector_versions,
        requested_url: command.url.clone(),
        final_url: fetch_receipt
            .metadata
            .final_url
            .as_ref()
            .map_or_else(|| command.url.clone(), ToString::to_string),
    })
}

async fn store_artifact(
    config: &Config,
    sha256: &Sha256Digest,
    bytes: &[u8],
) -> std::result::Result<(), RunFailure> {
    let cas_root = config
        .store
        .cas_dir
        .clone()
        .unwrap_or_else(crate::default_cas_dir);
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
        Ok(())
    } else {
        Err(RunFailure::Internal("CAS digest mismatch".to_owned()))
    }
}

fn policy_verdict(
    command: &RunCommand,
    result: &arbitraitor_analysis::AnalysisResult,
    is_https: bool,
) -> std::result::Result<Verdict, RunFailure> {
    let Some(path) = &command.policy else {
        return Ok(result.verdict);
    };
    let policy_toml =
        std::fs::read_to_string(path).map_err(|error| RunFailure::Internal(error.to_string()))?;
    let engine = PolicyEngine::load(&policy_toml)
        .map_err(|error| RunFailure::Internal(error.to_string()))?;
    let context = EvalContext::new(!command.non_interactive)
        .with_artifact_type(format!("{:?}", result.classification.artifact_type))
        .with_source_url(command.url.clone())
        .with_https(is_https)
        .with_private_network(false);
    Ok(engine.evaluate(&result.findings, &context))
}

fn policy_digest(command: &RunCommand) -> std::result::Result<String, RunFailure> {
    let Some(path) = &command.policy else {
        return Ok(String::new());
    };
    let policy_toml =
        std::fs::read_to_string(path).map_err(|error| RunFailure::Internal(error.to_string()))?;
    PolicyEngine::load(&policy_toml)
        .map(|engine| engine.digest())
        .map_err(|error| RunFailure::Internal(error.to_string()))
}

fn is_native_artifact(artifact_type: ArtifactType) -> bool {
    matches!(
        artifact_type,
        ArtifactType::PeExecutable | ArtifactType::ElfExecutable | ArtifactType::MachOExecutable
    )
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
    std::fs::write(&path, &artifact.bytes)
        .map_err(|error| RunFailure::Execution(error.to_string()))?;
    set_owner_execute_permissions(&path)?;
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

fn native_release_path(sha256: &Sha256Digest) -> std::result::Result<PathBuf, RunFailure> {
    let dir = arbitraitor_home()?.join("native");
    std::fs::create_dir_all(&dir).map_err(|error| RunFailure::Execution(error.to_string()))?;
    Ok(dir.join(format!("{sha256}.bin")))
}

#[cfg(unix)]
fn set_owner_execute_permissions(path: &Path) -> std::result::Result<(), RunFailure> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .map_err(|error| RunFailure::Execution(error.to_string()))?
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
        .map_err(|error| RunFailure::Execution(error.to_string()))
}

#[cfg(not(unix))]
fn set_owner_execute_permissions(_path: &Path) -> std::result::Result<(), RunFailure> {
    Ok(())
}

fn build_run_receipt(
    artifact: &InspectedArtifact,
    output: &ExecutionOutput,
) -> std::result::Result<arbitraitor_receipt::Receipt, RunFailure> {
    let now = crate::timestamp();
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
    .artifact_type(artifact.artifact_type.clone())
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
    });
    for detector in &artifact.detector_versions {
        builder = builder.detector_version(detector.clone());
    }
    Ok(builder.build())
}

fn arbitraitor_home() -> std::result::Result<PathBuf, RunFailure> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".arbitraitor"))
        .ok_or_else(|| RunFailure::Internal("HOME is not set".to_owned()))
}
