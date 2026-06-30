//! CLI subcommand handlers added in v0.6 to close the spec §28.1 surface gap.

use std::io::{Read, Write};
use std::path::PathBuf;

use arbitraitor_core::config::Config;
use arbitraitor_core::health::HealthChecker;
use arbitraitor_mcp::sanitize_for_agent;
use arbitraitor_model::verdict::Verdict;
use arbitraitor_policy::PolicyEngine;
use arbitraitor_receipt::Receipt;
use arbitraitor_store::ContentStore;
use arbitraitor_update::verifier::UpdateVerifier;
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

#[derive(Args)]
pub struct RulesCommand {
    #[arg(long, value_name = "DIR")]
    pub rules_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub subcommand: RulesSubcommand,
}

#[derive(Subcommand)]
pub enum RulesSubcommand {
    List,
    Validate { file: PathBuf },
}

#[derive(Args)]
pub struct UpdateCommand {
    #[command(subcommand)]
    pub subcommand: UpdateSubcommand,
}

#[derive(Subcommand)]
pub enum UpdateSubcommand {
    Verify {
        manifest_file: PathBuf,
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
        #[arg(long, value_name = "FILE")]
        signature: Option<PathBuf>,
    },
}

#[allow(clippy::too_many_lines)]
pub(crate) fn scan(command: &ScanCommand, config: &Config) -> Result<()> {
    let max_bytes = config.store.max_bytes;
    let bytes = if command.stdin {
        let mut buf = Vec::new();
        let mut stdin = std::io::stdin().lock();
        let mut chunk = [0_u8; 8192];
        loop {
            let n = stdin.read(&mut chunk).into_diagnostic()?;
            if n == 0 {
                break;
            }
            if buf.len() + n > usize::try_from(max_bytes).unwrap_or(usize::MAX) {
                miette::bail!(
                    "input exceeds configured store limit: bytes={}, limit={}",
                    buf.len() + n,
                    max_bytes
                );
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        buf
    } else {
        let path = command
            .path
            .as_deref()
            .ok_or_else(|| miette::miette!("no file path provided and --stdin not set"))?;
        let metadata = std::fs::metadata(path).into_diagnostic()?;
        let file_size = metadata.len();
        if file_size > max_bytes {
            miette::bail!(
                "file exceeds configured store limit: bytes={}, limit={}",
                file_size,
                max_bytes
            );
        }
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

    let format = match (command.explain, command.format) {
        (_, Some(f)) => Some(f),
        (true, None) => Some(ExplainFormat::Text),
        (false, None) => None,
    };
    if let Some(fmt) = format {
        write_explainability(&result.findings, "scan", fmt)?;
    }

    let exit_code = match result.verdict {
        Verdict::Pass => 0,
        Verdict::Warn => 10,
        Verdict::Block => 30,
        Verdict::Prompt => 21,
        Verdict::Error => 33,
        Verdict::Incomplete => 34,
    };
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

pub(crate) fn explain(command: &ExplainCommand) -> Result<()> {
    let receipt_bytes = std::fs::read(&command.receipt_path).into_diagnostic()?;
    let receipt: Receipt = serde_json::from_slice(&receipt_bytes)
        .map_err(|e| miette::miette!("invalid receipt file: {e}"))?;

    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "Artifact: {}",
        sanitize_for_agent(&receipt.artifact_sha256)
    )
    .into_diagnostic()?;
    writeln!(stdout, "Verdict: {:?}", receipt.verdict.verdict).into_diagnostic()?;
    writeln!(stdout).into_diagnostic()?;

    writeln!(stdout, "Findings ({})", receipt.findings.len()).into_diagnostic()?;
    for (i, finding) in receipt.findings.iter().enumerate() {
        writeln!(
            stdout,
            "  {}. [{:?}] {}",
            i + 1,
            finding.severity,
            sanitize_for_agent(&finding.title)
        )
        .into_diagnostic()?;
    }

    if let Some(retrieval) = &receipt.retrieval {
        writeln!(stdout).into_diagnostic()?;
        writeln!(stdout, "Retrieval:").into_diagnostic()?;
        let url = retrieval.requested_url();
        if !url.is_empty() {
            writeln!(stdout, "  URL: {}", sanitize_for_agent(url)).into_diagnostic()?;
        }
        if let Some(final_url) = retrieval.final_url() {
            writeln!(stdout, "  Final URL: {}", sanitize_for_agent(final_url)).into_diagnostic()?;
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
                let prefix: String = entry.sha256.chars().take(12).collect();
                writeln!(
                    stdout,
                    "  {} ({} bytes, {})",
                    prefix,
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
            if let Some(days) = max_age_days {
                let secs = days
                    .checked_mul(86_400)
                    .ok_or_else(|| miette::miette!("max-age-days overflow: {days} is too large"))?;
                gc = gc.with_max_age(std::time::Duration::from_secs(secs));
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

pub(crate) fn rules(command: &RulesCommand) -> Result<()> {
    let mut manager = arbitraitor_yarax::RulePackManager::with_built_in().into_diagnostic()?;
    if let Some(dir) = command.rules_dir.as_deref() {
        manager
            .load_directory(
                dir,
                arbitraitor_yarax::RuleSource::FileSystem(dir.to_path_buf()),
            )
            .into_diagnostic()?;
    }

    match &command.subcommand {
        RulesSubcommand::List => {
            let mut stdout = std::io::stdout().lock();
            let packs = manager.packs();
            writeln!(stdout, "Rule packs: {}", packs.len()).into_diagnostic()?;
            for pack in packs {
                let source = match pack.source {
                    arbitraitor_yarax::RuleSource::BuiltIn => "built-in",
                    arbitraitor_yarax::RuleSource::FileSystem(_) => "filesystem",
                    arbitraitor_yarax::RuleSource::Enterprise => "enterprise",
                    arbitraitor_yarax::RuleSource::Community => "community",
                    arbitraitor_yarax::RuleSource::UserLocal => "user-local",
                };
                let auth = match &pack.auth {
                    arbitraitor_yarax::RulePackAuth::Signed { key_id } => {
                        format!("signed ({key_id})")
                    }
                    arbitraitor_yarax::RulePackAuth::Unsigned { reason: _ } => {
                        "unsigned".to_owned()
                    }
                };
                let digest_short: String = pack.digest.to_string().chars().take(12).collect();
                writeln!(
                    stdout,
                    "  {source:10} {ns:20} {ver:20} {auth:20} sha256:{digest_short}",
                    ns = pack.namespace,
                    ver = pack.version,
                )
                .into_diagnostic()?;
            }
        }
        RulesSubcommand::Validate { file } => {
            let rules_text = std::fs::read_to_string(file).into_diagnostic()?;
            let scanner = arbitraitor_yarax::YaraScanner::empty().into_diagnostic()?;
            let mut scanner = scanner;
            scanner.add_rules(&rules_text).into_diagnostic()?;
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "valid: {}", file.display()).into_diagnostic()?;
            writeln!(stdout, "  rules compiled successfully").into_diagnostic()?;
        }
    }
    Ok(())
}

pub(crate) fn update(command: &UpdateCommand) -> Result<()> {
    match &command.subcommand {
        UpdateSubcommand::Verify {
            manifest_file,
            key,
            signature,
        } => {
            let key_bytes = std::fs::read(key).into_diagnostic()?;
            let verifier = arbitraitor_update::verifier::MinisignVerifier::new(&key_bytes)
                .map_err(|e| miette::miette!("invalid public key: {e}"))?;

            let manifest_bytes = std::fs::read(manifest_file).into_diagnostic()?;
            let sig_path = signature.clone().unwrap_or_else(|| {
                let mut p = manifest_file.clone();
                p.set_extension("minisig");
                p
            });
            let sig_bytes = std::fs::read(&sig_path).into_diagnostic()?;

            let manifest = verifier
                .verify_manifest(&manifest_bytes, &sig_bytes)
                .map_err(|e| miette::miette!("manifest verification failed: {e}"))?;
            manifest
                .validate_manifest()
                .map_err(|e| miette::miette!("manifest validation failed: {e}"))?;

            let channel = match manifest.channel {
                arbitraitor_update::manifest::UpdateChannel::RulePacks => "rule_packs",
                arbitraitor_update::manifest::UpdateChannel::IntelFeeds => "intel_feeds",
                arbitraitor_update::manifest::UpdateChannel::TrustRoot => "trust_root",
                arbitraitor_update::manifest::UpdateChannel::PluginRegistry => "plugin_registry",
            };

            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "verified: {}", manifest_file.display()).into_diagnostic()?;
            writeln!(stdout, "  channel:          {channel}").into_diagnostic()?;
            writeln!(stdout, "  manifest version: {}", manifest.manifest_version)
                .into_diagnostic()?;
            writeln!(stdout, "  schema version:   {}", manifest.schema_version)
                .into_diagnostic()?;
            writeln!(stdout, "  publisher:        {}", manifest.publisher).into_diagnostic()?;
            writeln!(stdout, "  published at:     {}", manifest.published_at).into_diagnostic()?;
            writeln!(stdout, "  expires at:       {}", manifest.expires_at).into_diagnostic()?;
            writeln!(stdout, "  targets:          {}", manifest.targets.len()).into_diagnostic()?;
            for target in &manifest.targets {
                let sha_prefix: String = target.sha256.to_string().chars().take(12).collect();
                writeln!(
                    stdout,
                    "    {} v{} ({} bytes, sha256:{sha_prefix})",
                    target.path, target.target_version, target.size
                )
                .into_diagnostic()?;
            }
        }
    }
    Ok(())
}
