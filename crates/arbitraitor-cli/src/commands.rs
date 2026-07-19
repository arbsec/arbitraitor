//! CLI subcommand handlers added in v0.6 to close the spec §28.1 surface gap.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

use arbitraitor_core::config::Config;
use arbitraitor_core::health::{HealthChecker, HealthStatus};
use arbitraitor_mcp::sanitize_for_agent;
use arbitraitor_model::exit_code::ExitCode;
use arbitraitor_policy::PolicyEngine;
use arbitraitor_receipt::Receipt;
use arbitraitor_store::ContentStore;
use arbitraitor_update::verifier::UpdateVerifier;
use arbitraitor_wrapper::init as shell_init;
use arbitraitor_wrapper::shim::{ShimConfig, ShimState, WrapperTarget, check_shims};
use clap::{Args, Subcommand};
use miette::{IntoDiagnostic, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::{ExplainFormat, pipeline::default_cas_dir, write_explainability, write_report};

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
    /// Output JSON instead of human-readable format.
    #[arg(long)]
    pub json: bool,
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

#[derive(Args)]
pub struct PluginCommand {
    #[command(subcommand)]
    pub subcommand: PluginSubcommand,
}

#[derive(Subcommand)]
pub enum PluginSubcommand {
    List,
    Info { id: String },
    Discover,
    Remove { id: String },
}

#[derive(Args)]
pub struct HookCommand {
    #[command(subcommand)]
    pub subcommand: HookSubcommand,
}

#[derive(Subcommand)]
pub enum HookSubcommand {
    /// Print a shell hook that intercepts curl|sh patterns.
    Init {
        #[arg(long, value_name = "PATH")]
        binary: Option<PathBuf>,
    },
}

#[derive(Args)]
pub struct ShimCommand {
    #[command(subcommand)]
    pub subcommand: ShimSubcommand,
}

#[derive(Subcommand)]
pub enum ShimSubcommand {
    /// List installed compatibility shims.
    List,
    /// Install a compatibility shim for a package manager tool.
    Install { tool: String },
    /// Remove a compatibility shim.
    Uninstall { tool: String },
}

#[derive(Args)]
pub struct GraphCommand {
    /// Local file to analyze.
    pub file: PathBuf,
}

#[derive(Args)]
pub struct ApproveCommand {
    /// Receipt file from a prior inspection.
    pub receipt: PathBuf,
}

#[derive(Args)]
pub struct ExecuteCommand {
    /// Approval file from 'arbitraitor approve'.
    pub approval: PathBuf,
    /// Allow network access during execution.
    #[arg(long)]
    pub network: bool,
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

    let (coordinator, _rule_pack_versions) =
        crate::pipeline::analysis_coordinator(command.rules.as_deref())?;
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

    let exit_code = ExitCode::from(result.verdict);
    if exit_code != ExitCode::Success {
        std::process::exit(exit_code.as_i32());
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

fn print_health_row(
    stdout: &mut std::io::StdoutLock<'_>,
    name: &str,
    value: &str,
    ok: bool,
) -> Result<()> {
    let mark = if ok { "✓" } else { "✗" };
    writeln!(stdout, "  {name:<12} {value}  {mark}").into_diagnostic()
}

#[allow(clippy::too_many_lines)]
pub(crate) fn doctor(command: &DoctorCommand, config: &Config) -> Result<()> {
    let cas_dir = command
        .cas_dir
        .clone()
        .or_else(|| config.store.cas_dir.clone())
        .unwrap_or_else(default_cas_dir);
    let mut checker = HealthChecker::new().with_store(cas_dir.clone());
    if let Some(rules_dir) = command.rules.as_deref() {
        let versions = crate::rule_pack_versions(rules_dir)?;
        if let Some(first) = versions.first() {
            checker = checker.with_rule_pack(first.clone());
        }
        checker = checker.with_detector_versions(versions);
    }
    let report = checker.check();

    if command.json {
        let json = serde_json::to_vec_pretty(&report).into_diagnostic()?;
        std::io::stdout()
            .lock()
            .write_all(&json)
            .into_diagnostic()?;
        return Ok(());
    }

    let mut stdout = std::io::stdout().lock();
    let mut all_healthy = true;

    let store_healthy = report
        .checks
        .get("store")
        .is_some_and(|c| c.status == HealthStatus::Healthy);

    let shell_info = shell_init::detect_shell();
    let shell_ok = shell_info.is_some();

    let shim_dir = std::env::var_os("HOME").map_or_else(
        || PathBuf::from("/dev/null"),
        |h| PathBuf::from(h).join(".arbitraitor").join("shims"),
    );
    let shim_config = ShimConfig {
        shim_dir: shim_dir.clone(),
        use_symlinks: false,
    };
    let shim_results = check_shims(&shim_config, WrapperTarget::ALL);
    let shims_ok = shim_results
        .iter()
        .any(|s| matches!(s.state, ShimState::Script | ShimState::Symlink));

    let path_str = std::env::var("PATH").unwrap_or_default();
    let path_has_shim = path_str
        .split(if cfg!(windows) { ';' } else { ':' })
        .any(|p| Path::new(p) == shim_dir.as_path());

    let rcfile_ok = shell_info
        .as_ref()
        .and_then(|d| shell_init::target_rcfile(d.shell))
        .and_then(|p| std::fs::read_to_string(&p).ok())
        .is_some_and(|content| content.contains(shell_init::MARKER_BEGIN));

    writeln!(stdout, "Arbitraitor health:").into_diagnostic()?;
    print_health_row(&mut stdout, "version", &report.version, true)?;
    print_health_row(
        &mut stdout,
        "store",
        &cas_dir.display().to_string(),
        store_healthy,
    )?;

    let check_count = report.checks.len();
    let healthy_count = report
        .checks
        .values()
        .filter(|c| c.status == HealthStatus::Healthy)
        .count();
    print_health_row(
        &mut stdout,
        "checks",
        &format!("{healthy_count}/{check_count} healthy"),
        check_count > 0,
    )?;

    let shell_label = match &shell_info {
        Some(d) => format!(
            "{} (via {})",
            d.shell.as_str(),
            match d.source {
                shell_init::DetectionSource::EnvShell => "$SHELL",
                shell_init::DetectionSource::ParentProcess => "parent process",
            }
        ),
        None => "not detected".to_owned(),
    };
    print_health_row(&mut stdout, "shell", &shell_label, shell_ok)?;

    let shims_label = {
        let installed: Vec<&str> = shim_results
            .iter()
            .filter(|s| matches!(s.state, ShimState::Script | ShimState::Symlink))
            .map(|s| s.target.binary_name())
            .collect();
        if installed.is_empty() {
            "none installed".to_owned()
        } else {
            installed.join(", ")
        }
    };
    print_health_row(&mut stdout, "shims", &shims_label, shims_ok)?;
    print_health_row(
        &mut stdout,
        "PATH",
        &shim_dir.display().to_string(),
        path_has_shim,
    )?;

    let rcfile_label = shell_info
        .as_ref()
        .and_then(|d| shell_init::target_rcfile(d.shell))
        .map_or_else(|| "n/a".to_owned(), |p| p.display().to_string());
    print_health_row(&mut stdout, "rcfile", &rcfile_label, rcfile_ok)?;

    all_healthy = all_healthy && shims_ok && path_has_shim && rcfile_ok;

    if !all_healthy {
        writeln!(stdout).into_diagnostic()?;
        writeln!(stdout, "Fix shell integration:").into_diagnostic()?;
        if !shims_ok {
            writeln!(stdout, "  arbitraitor wrappers install").into_diagnostic()?;
        }
        if !path_has_shim || !rcfile_ok {
            writeln!(stdout, "  arbitraitor wrappers init --install").into_diagnostic()?;
        }
    }

    if all_healthy {
        Ok(())
    } else {
        // Spec §29 code 33: Required detector unavailable or stale. doctor
        // is responsible for surfacing detector and configuration health;
        // an unhealthy doctor result is the canonical 33 trigger.
        std::process::exit(33);
    }
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

pub(crate) fn plugin(command: &PluginCommand) -> Result<()> {
    let mut registry = arbitraitor_plugin_host::registry::PluginRegistry::new(
        arbitraitor_plugin_host::registry::PluginRegistry::default_dirs(),
    );
    registry
        .discover()
        .map_err(|e| miette::miette!("plugin discovery failed: {e}"))?;

    match &command.subcommand {
        PluginSubcommand::List => {
            let mut stdout = std::io::stdout().lock();
            let plugins = registry.list();
            writeln!(stdout, "Registered plugins: {}", plugins.len()).into_diagnostic()?;
            for p in plugins {
                writeln!(
                    stdout,
                    "  {} v{} [{:?}] {:?}",
                    p.manifest.identity.id,
                    p.manifest.identity.version,
                    p.manifest.plugin_type,
                    p.manifest.identity.trust_class,
                )
                .into_diagnostic()?;
            }
        }
        PluginSubcommand::Info { id } => {
            let plugin = registry
                .get(id)
                .ok_or_else(|| miette::miette!("plugin '{id}' not found"))?;
            let json = serde_json::to_string_pretty(&plugin.manifest).into_diagnostic()?;
            writeln!(std::io::stdout().lock(), "{json}").into_diagnostic()?;
        }
        PluginSubcommand::Discover => {
            let count = registry
                .discover()
                .map_err(|e| miette::miette!("discovery failed: {e}"))?;
            writeln!(std::io::stdout().lock(), "Discovered {count} plugins").into_diagnostic()?;
        }
        PluginSubcommand::Remove { id } => {
            registry
                .unregister(id)
                .ok_or_else(|| miette::miette!("plugin '{id}' not found"))?;
            writeln!(std::io::stdout().lock(), "Removed plugin {id}").into_diagnostic()?;
        }
    }
    Ok(())
}

pub(crate) fn hook(command: &HookCommand) -> Result<()> {
    match &command.subcommand {
        HookSubcommand::Init { binary } => {
            let mut stderr = std::io::stderr().lock();
            writeln!(
                stderr,
                "[arbitraitor] warning: 'hook init' is deprecated. The bash DEBUG trap has\n\
                 performance overhead on every command and only supports bash. Use\n\
                 'arbitraitor wrappers install' + 'arbitraitor wrappers init --install'\n\
                 for a robust, shell-agnostic alternative.\n"
            )
            .into_diagnostic()?;
            let arb = match binary.as_ref() {
                Some(p) => p.display().to_string(),
                None => std::env::current_exe()
                    .map_or_else(|_| "arbitraitor".to_owned(), |p| p.display().to_string()),
            };
            let snippet = format!(
                "# >>> arbitraitor hook (deprecated — use 'wrappers install' instead) >>>\n\
                 _arbitraitor_guard() {{\n\
                 \x20   local cmd=\"$BASH_COMMAND\"\n\
                 \x20   case \"$cmd\" in\n\
                 \x20       *'curl'*'|'*'sh'*|*'curl'*'|'*'bash'*|*'wget'*'|'*'sh'*)\n\
                 \x20           if [ -z \"$ARBITRAITOR_HOOK_DISABLE\" ]; then\n\
                 \x20               echo \"[arbitraitor] intercepted: $cmd\" >&2\n\
                 \x20               echo \"[arbitraitor] use '{arb} run <url>' for safe execution\" >&2\n\
                 \x20               echo \"[arbitraitor] set ARBITRAITOR_HOOK_DISABLE=1 to bypass\" >&2\n\
                 \x20               return 1\n\
                 \x20           fi\n\
                 \x20           ;;\n\
                 \x20   esac\n\
                 }}\n\
                 trap '_arbitraitor_guard' DEBUG\n\
                 # <<< arbitraitor hook <<<\n"
            );
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(snippet.as_bytes()).into_diagnostic()?;
        }
    }
    Ok(())
}

const SUPPORTED_SHIMS: &[&str] = &["npm"];

pub(crate) fn shim(command: &ShimCommand) -> Result<()> {
    match &command.subcommand {
        ShimSubcommand::List => {
            let mut stdout = std::io::stdout().lock();
            if SUPPORTED_SHIMS.is_empty() {
                writeln!(stdout, "No package-manager shims are currently supported.")
                    .into_diagnostic()?;
                writeln!(
                    stdout,
                    "\nFor curl/wget wrapper support, use:\n  arbitraitor wrappers install"
                )
                .into_diagnostic()?;
                return Ok(());
            }
            writeln!(stdout, "Supported shims: {}", SUPPORTED_SHIMS.join(", "))
                .into_diagnostic()?;
            writeln!(stdout).into_diagnostic()?;
            let shim_dir = std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join(".arbitraitor").join("shims"))
                .ok_or_else(|| miette::miette!("HOME not set"))?;
            if !shim_dir.exists() {
                writeln!(stdout, "No shims installed.").into_diagnostic()?;
                return Ok(());
            }
            for entry in std::fs::read_dir(&shim_dir).into_diagnostic()? {
                let entry = entry.into_diagnostic()?;
                let name = entry.file_name().to_string_lossy().to_string();
                writeln!(stdout, "  {name}").into_diagnostic()?;
            }
        }
        ShimSubcommand::Install { tool } => {
            if !SUPPORTED_SHIMS.contains(&tool.as_str()) {
                miette::bail!(
                    "package-manager shims are not yet implemented; \
                     use 'arbitraitor wrappers install' for curl/wget support"
                );
            }
            let arb = std::env::current_exe()
                .map_or_else(|_| "arbitraitor".to_owned(), |p| p.display().to_string());
            let shim_dir = std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join(".arbitraitor").join("shims"))
                .ok_or_else(|| miette::miette!("HOME not set"))?;
            std::fs::create_dir_all(&shim_dir).into_diagnostic()?;
            let shim_path = shim_dir.join(tool);
            let content = format!(
                "#!/bin/sh\n# Arbitraitor shim for {tool}\nexec {arb} pm run --tool {tool} -- \"$@\"\n"
            );
            std::fs::write(&shim_path, content).into_diagnostic()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&shim_path, std::fs::Permissions::from_mode(0o755))
                    .into_diagnostic()?;
            }
            writeln!(
                std::io::stdout().lock(),
                "installed: {}",
                shim_path.display()
            )
            .into_diagnostic()?;
        }
        ShimSubcommand::Uninstall { tool } => {
            let shim_dir = std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join(".arbitraitor").join("shims"))
                .ok_or_else(|| miette::miette!("HOME not set"))?;
            let shim_path = shim_dir.join(tool);
            if shim_path.exists() {
                std::fs::remove_file(&shim_path).into_diagnostic()?;
                writeln!(std::io::stdout().lock(), "removed: {}", shim_path.display())
                    .into_diagnostic()?;
            } else {
                writeln!(std::io::stdout().lock(), "not installed: {tool}").into_diagnostic()?;
            }
        }
    }
    Ok(())
}

pub(crate) fn graph(command: &GraphCommand) -> Result<()> {
    let bytes = std::fs::read(&command.file).into_diagnostic()?;
    let coordinator = arbitraitor_analysis::AnalysisCoordinator::new();
    let (node, findings) = arbitraitor_analysis::analyze_recursive(&coordinator, &bytes, 10);
    let mut stdout = std::io::stdout().lock();
    let sha: String = node.sha256.to_string().chars().take(12).collect();
    writeln!(stdout, "{:?} {sha}", node.kind).into_diagnostic()?;
    render_node(&mut stdout, &node, 1)?;
    if !findings.is_empty() {
        writeln!(stdout).into_diagnostic()?;
        writeln!(stdout, "Findings: {}", findings.len()).into_diagnostic()?;
        for f in &findings {
            writeln!(stdout, "  - {}", f.title).into_diagnostic()?;
        }
    }
    Ok(())
}

fn render_node(
    writer: &mut impl std::io::Write,
    node: &arbitraitor_archive::ArtifactNode,
    depth: usize,
) -> Result<()> {
    for child in &node.contained {
        let prefix = "  ".repeat(depth);
        let sha: String = child.sha256.to_string().chars().take(12).collect();
        let name = match &child.origin {
            arbitraitor_archive::ArtifactOrigin::ArchiveEntry { entry_name, .. } => {
                entry_name.as_str()
            }
            arbitraitor_archive::ArtifactOrigin::Root => "(root)",
        };
        writeln!(
            writer,
            "{prefix}├─ {sha} {kind:?} [{name}]",
            kind = child.kind,
            name = name
        )
        .into_diagnostic()?;
        render_node(writer, child, depth + 1)?;
    }
    Ok(())
}

pub(crate) fn approve(command: &ApproveCommand, _config: &Config) -> Result<()> {
    let receipt_bytes = std::fs::read(&command.receipt).into_diagnostic()?;
    let receipt: Receipt = serde_json::from_slice(&receipt_bytes)
        .map_err(|e| miette::miette!("invalid receipt file: {e}"))?;
    let sha = &receipt.artifact_sha256;
    let verdict = receipt.verdict.verdict;

    let mut stderr = std::io::stderr().lock();
    writeln!(stderr, "Artifact: {sha}").into_diagnostic()?;
    writeln!(stderr, "Verdict:  {verdict:?}").into_diagnostic()?;
    writeln!(stderr, "Findings: {}", receipt.findings.len()).into_diagnostic()?;
    for f in &receipt.findings {
        writeln!(stderr, "  - {}", f.title).into_diagnostic()?;
    }
    writeln!(stderr).into_diagnostic()?;
    writeln!(stderr, "Approve execution? [y/N] ").into_diagnostic()?;
    drop(stderr);

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).into_diagnostic()?;
    if !input.trim().eq_ignore_ascii_case("y") {
        miette::bail!("approval denied");
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let expiry = now + 300;

    let artifact_sha256 = arbitraitor_model::ids::Sha256Digest::from_str(sha)
        .map_err(|e| miette::miette!("invalid SHA-256 in receipt: {e}"))?;
    let plan_inputs = crate::approval::ExecutionPlanInputs {
        artifact_sha256,
        network_isolated: true,
        policy_snapshot_digest: receipt
            .policy_digest
            .clone()
            .unwrap_or_else(|| "unset".to_owned()),
        detector_snapshot_digest: receipt
            .detector_versions
            .iter()
            .map(|d| format!("{}:{}", d.id, d.version))
            .collect::<Vec<_>>()
            .join(","),
    };
    let approval = crate::approval::ApprovalFile::for_bash_execution(
        &plan_inputs,
        "stdin-human-confirmation",
        now,
        expiry,
        &format!("{verdict:?}"),
    )
    .map_err(|e| miette::miette!("failed to build approval: {e}"))?;

    let approval_path = command.receipt.with_extension("approval.json");
    let json = serde_json::to_vec_pretty(&approval).into_diagnostic()?;
    std::fs::write(&approval_path, json).into_diagnostic()?;
    writeln!(
        std::io::stdout().lock(),
        "approval written to: {}",
        approval_path.display()
    )
    .into_diagnostic()?;
    Ok(())
}

pub(crate) fn execute(command: &ExecuteCommand, config: &Config) -> Result<()> {
    let approval_bytes = std::fs::read(&command.approval).into_diagnostic()?;
    let approval: crate::approval::ApprovalFile = serde_json::from_slice(&approval_bytes)
        .map_err(|e| miette::miette!("invalid approval file: {e}"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    approval
        .verify(now)
        .map_err(|e| miette::miette!("approval verification failed: {e}"))?;

    // The to-be-executed plan must match the approved plan. Recompute the
    // plan digest from the actual execution inputs and compare.
    let expected_network_isolated = !command.network;
    if approval.network_isolated != expected_network_isolated {
        miette::bail!(
            "approval was issued for network_isolated={} but execute requested network_isolated={}",
            approval.network_isolated,
            expected_network_isolated
        );
    }

    let sha = arbitraitor_model::ids::Sha256Digest::from_str(&approval.artifact_sha256)
        .map_err(|e| miette::miette!("invalid SHA-256 in approval: {e}"))?;

    let cas_dir = config.store.cas_dir.clone().unwrap_or_else(default_cas_dir);
    let store = ContentStore::open(&cas_dir).into_diagnostic()?;
    let handle = store.get(&sha).into_diagnostic()?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut handle.read(), &mut bytes).into_diagnostic()?;

    let execution = arbitraitor_exec::script::ScriptExecution::bash()
        .map_err(|e| miette::miette!("exec setup failed: {e}"))?
        .with_network_isolated(!command.network);
    let result = execution
        .execute(&bytes)
        .map_err(|e| miette::miette!("execution failed: {e}"))?;

    let mut stdout = std::io::stdout().lock();
    if !result.stdout.is_empty() {
        stdout.write_all(&result.stdout).into_diagnostic()?;
    }
    if !result.stderr.is_empty() {
        std::io::stderr()
            .lock()
            .write_all(&result.stderr)
            .into_diagnostic()?;
    }
    writeln!(stdout, "exit code: {:?}", result.exit_code.unwrap_or(50)).into_diagnostic()?;
    Ok(())
}
