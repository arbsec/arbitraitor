//! CLI subcommand handlers added in v0.6 to close the spec §28.1 surface gap.
//!
//! Each function corresponds to a top-level subcommand. Functions are
//! intentionally stateless: they receive parsed clap args, perform I/O
//! against the appropriate crate APIs, and write to stdout/stderr.

use std::io::{Read, Write};
use std::path::PathBuf;

use arbitraitor_core::config::Config;
use arbitraitor_core::health::HealthChecker;
use arbitraitor_policy::PolicyEngine;
use arbitraitor_store::ContentStore;
use clap::{Args, Subcommand};
use miette::{IntoDiagnostic, Result};
use sha2::{Digest, Sha256};

use crate::{ExplainFormat, default_cas_dir, write_explainability, write_report};

#[derive(Args)]
pub struct ScanCommand {
    pub path: Option<PathBuf>,
    #[arg(long)]
    pub stdin: bool,
    #[arg(long, value_name = "DIR")]
    pub rules: Option<PathBuf>,
    #[arg(long)]
    pub explain: bool,
    #[arg(long, value_enum)]
    pub format: Option<ExplainFormat>,
}

#[derive(Args)]
pub struct ExplainCommand {
    pub receipt_path: PathBuf,
}

#[derive(Args)]
pub struct StoreCommand {
    #[arg(long, value_name = "DIR")]
    pub cas_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub subcommand: StoreSubcommand,
}

#[derive(Subcommand)]
pub enum StoreSubcommand {
    List,
    Inspect {
        sha256: String,
    },
    Gc {
        #[arg(long, value_name = "DAYS")]
        max_age_days: Option<u64>,
    },
}

#[derive(Args)]
pub struct PolicyCommand {
    pub policy_path: PathBuf,
}

#[derive(Args)]
pub struct DoctorCommand {
    #[arg(long, value_name = "DIR")]
    pub cas_dir: Option<PathBuf>,
    #[arg(long, value_name = "DIR")]
    pub rules: Option<PathBuf>,
}

#[allow(clippy::too_many_lines)]
pub(crate) fn scan(command: &ScanCommand, config: &Config) -> Result<()> {
    let bytes = if command.stdin {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf).into_diagnostic()?;
        buf
    } else {
        let path = command
            .path
            .as_deref()
            .ok_or_else(|| miette::miette!("no file path provided and --stdin not set"))?;
        std::fs::read(path).into_diagnostic()?
    };

    let artifact_sha256 = arbitraitor_model::ids::Sha256Digest::new(Sha256::digest(&bytes).into());

    let (coordinator, _rule_pack_versions) = crate::analysis_coordinator(command.rules.as_deref())?;
    let result = coordinator.analyze(&bytes);

    let cas_root = config.store.cas_dir.clone().unwrap_or_else(default_cas_dir);

    write_report(
        &mut std::io::stderr().lock(),
        &result,
        &artifact_sha256,
        &cas_root,
        &[],
    )?;

    if let Some(format) = command.format {
        write_explainability(&result.findings, "scan", format)?;
    }

    if result.verdict == arbitraitor_model::verdict::Verdict::Block {
        std::process::exit(30);
    }
    Ok(())
}

pub(crate) fn explain(command: &ExplainCommand) -> Result<()> {
    let receipt_bytes = std::fs::read(&command.receipt_path).into_diagnostic()?;
    let receipt: serde_json::Value = serde_json::from_slice(&receipt_bytes).into_diagnostic()?;

    let verdict = receipt
        .get("verdict")
        .and_then(|v| v.get("verdict"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");

    let findings = receipt
        .get("findings")
        .cloned()
        .unwrap_or(serde_json::Value::Array(vec![]));

    let artifact_sha = receipt
        .get("artifact_sha256")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<unknown>");

    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "Artifact: {artifact_sha}").into_diagnostic()?;
    writeln!(stdout, "Verdict: {verdict}").into_diagnostic()?;
    writeln!(stdout).into_diagnostic()?;

    if let Some(findings_arr) = findings.as_array() {
        writeln!(stdout, "Findings ({})", findings_arr.len()).into_diagnostic()?;
        for (i, finding) in findings_arr.iter().enumerate() {
            let title = finding
                .get("title")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<no title>");
            let severity = finding
                .get("severity")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            writeln!(stdout, "  {}. [{severity}] {title}", i + 1).into_diagnostic()?;
        }
    }

    if let Some(retrieval) = receipt.get("retrieval") {
        writeln!(stdout).into_diagnostic()?;
        writeln!(stdout, "Retrieval:").into_diagnostic()?;
        if let Some(url) = retrieval
            .get("requested_url")
            .and_then(serde_json::Value::as_str)
        {
            writeln!(stdout, "  URL: {url}").into_diagnostic()?;
        }
        if let Some(size) = retrieval
            .get("byte_count")
            .and_then(serde_json::Value::as_u64)
        {
            writeln!(stdout, "  Size: {size} bytes").into_diagnostic()?;
        }
    }

    Ok(())
}

pub(crate) fn store(command: &StoreCommand, config: &Config) -> Result<()> {
    let cas_root = command
        .cas_dir
        .clone()
        .or_else(|| config.store.cas_dir.clone())
        .unwrap_or_else(default_cas_dir);

    let store = ContentStore::open(&cas_root).into_diagnostic()?;
    let index = store.metadata_index();

    match &command.subcommand {
        StoreSubcommand::List => {
            let entries = index.list().into_diagnostic()?;
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "Stored artifacts: {}", entries.len()).into_diagnostic()?;
            for entry in &entries {
                writeln!(
                    stdout,
                    "  {} ({} bytes, {})",
                    &entry.sha256[..12],
                    entry.size_bytes,
                    if entry.locked { "locked" } else { "unlocked" }
                )
                .into_diagnostic()?;
            }
        }
        StoreSubcommand::Inspect { sha256 } => {
            let entry = index
                .get(sha256)
                .into_diagnostic()?
                .ok_or_else(|| miette::miette!("artifact {sha256} not found in store"))?;
            let json = serde_json::to_string_pretty(&entry).into_diagnostic()?;
            writeln!(std::io::stdout().lock(), "{json}").into_diagnostic()?;
        }
        StoreSubcommand::Gc { max_age_days } => {
            let mut gc = arbitraitor_store::GarbageCollector::new();
            if let Some(days) = *max_age_days {
                gc = gc.with_max_age(std::time::Duration::from_secs(days * 86_400));
            }
            let stats = gc.run(&store, index).into_diagnostic()?;
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "Garbage collection complete:").into_diagnostic()?;
            writeln!(stdout, "  Examined: {}", stats.examined).into_diagnostic()?;
            writeln!(stdout, "  Collected: {}", stats.collected).into_diagnostic()?;
            writeln!(stdout, "  Retained (locked): {}", stats.retained_locked).into_diagnostic()?;
            writeln!(stdout, "  Retained (forensic): {}", stats.retained_forensic)
                .into_diagnostic()?;
            writeln!(stdout, "  Freed: {} bytes", stats.freed_bytes).into_diagnostic()?;
        }
    }
    Ok(())
}

pub(crate) fn policy(command: &PolicyCommand) -> Result<()> {
    let toml_str = std::fs::read_to_string(&command.policy_path).into_diagnostic()?;
    let engine = PolicyEngine::load(&toml_str)
        .map_err(|e| miette::miette!("policy validation failed: {e}"))?;
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "Policy valid").into_diagnostic()?;
    writeln!(stdout, "  Version: {}", engine.policy().version).into_diagnostic()?;
    writeln!(stdout, "  Rules: {}", engine.policy().rules.len()).into_diagnostic()?;
    writeln!(stdout, "  Digest: {}", engine.digest()).into_diagnostic()?;
    Ok(())
}

pub(crate) fn doctor(command: &DoctorCommand, config: &Config) -> Result<()> {
    let cas_dir = command
        .cas_dir
        .clone()
        .or_else(|| config.store.cas_dir.clone())
        .unwrap_or_else(default_cas_dir);
    let mut checker = HealthChecker::new().with_store(cas_dir);
    if let Some(rules_dir) = command.rules.as_deref() {
        let versions = crate::rule_pack_versions(rules_dir)?;
        if let Some(first) = versions.first() {
            checker = checker.with_rule_pack(first.clone());
        }
        checker = checker.with_detector_versions(versions);
    }
    let report = checker.check();
    let json = serde_json::to_vec_pretty(&report).into_diagnostic()?;
    std::io::stdout()
        .lock()
        .write_all(&json)
        .into_diagnostic()?;
    Ok(())
}

pub(crate) fn version() -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "arbitraitor {}", env!("CARGO_PKG_VERSION")).into_diagnostic()?;
    writeln!(stdout, "license: {}", env!("CARGO_PKG_LICENSE")).into_diagnostic()?;
    writeln!(stdout, "repository: {}", env!("CARGO_PKG_REPOSITORY")).into_diagnostic()?;
    Ok(())
}
