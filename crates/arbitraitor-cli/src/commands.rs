//! CLI subcommand handlers added in v0.6 to close the spec §28.1 surface gap.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

use arbitraitor_artifact::{ArtifactType, classify};
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
    /// Receipt file path or `sha256:<hex>` to look up the most recent
    /// receipt for an artifact from the Arbitraitor receipts directory
    /// (spec §28.6).
    pub target: String,
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
pub struct ReportCommand {
    #[command(subcommand)]
    pub subcommand: ReportSubcommand,
}

/// Subcommands of `arbitraitor report` (spec §21.7).
#[derive(Subcommand)]
pub enum ReportSubcommand {
    /// Mark a finding as a false positive so future inspections do not
    /// re-surface it. Scoped and auditable per spec §21.7.
    FalsePositive {
        /// Identifier of the finding (matches `Finding.id` from a receipt).
        finding_id: String,
    },
}

/// `arbitraitor allow` — record a scoped allow exception for an artifact
/// digest (spec §21.7). All exceptions are auditable; expiry is mandatory.
#[derive(Args)]
pub struct AllowCommand {
    /// Artifact SHA-256 in `sha256:<hex>` form.
    #[arg(value_name = "sha256:<HEX>", value_parser = parse_sha256_arg)]
    pub hash: String,
    /// Exception scope: user, project, or org.
    #[arg(long, value_enum)]
    pub scope: AllowScope,
    /// Time until the exception expires (e.g. `7d`, `24h`, `30m`).
    #[arg(long, value_name = "DURATION")]
    pub expires: String,
    /// Free-form justification recorded with the exception for auditing.
    #[arg(long, value_name = "TEXT")]
    pub reason: String,
}

/// Allowed scopes for an `allow` exception (spec §21.7).
#[derive(Clone, Copy, Debug, clap::ValueEnum, Eq, PartialEq)]
pub enum AllowScope {
    User,
    Project,
    Org,
}

fn parse_sha256_arg(raw: &str) -> std::result::Result<String, String> {
    parse_sha256_allow_target(raw).map_err(|e| e.to_string())
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
    let receipt_bytes = if let Some(hash) = command.target.strip_prefix("sha256:") {
        resolve_receipt_by_hash(hash)?
    } else {
        std::fs::read(&command.target).into_diagnostic()?
    };
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

/// Locates the most recent receipt for an artifact by its SHA-256 hash
/// (spec §28.6). Receipts are stored as `~/.arbitraitor/receipts/*-<prefix>.json`
/// where `<prefix>` is the first 12 chars of the artifact's sha256 hex.
/// Returns the newest matching file's bytes.
fn resolve_receipt_by_hash(hash_hex: &str) -> Result<Vec<u8>> {
    let hash_lower = hash_hex.to_lowercase();
    if hash_lower.len() != 64 || !hash_lower.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(miette::miette!(
            "invalid sha256 hash: expected 64 hex characters, got '{}'",
            hash_hex
        ));
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(".arbitraitor").join("receipts"))
        .ok_or_else(|| miette::miette!("HOME environment variable is not set"))?;
    let prefix: String = hash_lower.chars().take(12).collect();
    let mut entries: Vec<_> = std::fs::read_dir(&home)
        .into_diagnostic()?
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(&format!("-{prefix}.json")) {
                Some(entry)
            } else {
                None
            }
        })
        .collect();
    entries.sort_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()));
    let newest = entries
        .last()
        .ok_or_else(|| miette::miette!("no receipt found for sha256:{hash_hex}"))?;
    std::fs::read(newest.path()).into_diagnostic()
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

const MIN_SAFE_TAR_RS_VERSION: &str = "0.4.46";
const WORKSPACE_LOCK: &str = include_str!("../../../Cargo.lock");

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

    let tar_rs_version = locked_crate_version(WORKSPACE_LOCK, "tar");
    let tar_rs_ok = tar_rs_version
        .as_deref()
        .is_some_and(|version| semver_at_least(version, MIN_SAFE_TAR_RS_VERSION));

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
    print_health_row(
        &mut stdout,
        "tar-rs",
        tar_rs_version.as_deref().unwrap_or("not locked"),
        tar_rs_ok,
    )?;

    all_healthy = all_healthy && shims_ok && path_has_shim && rcfile_ok && tar_rs_ok;

    if !all_healthy {
        writeln!(stdout).into_diagnostic()?;
        writeln!(stdout, "Fix shell integration:").into_diagnostic()?;
        if !shims_ok {
            writeln!(stdout, "  arbitraitor wrappers install").into_diagnostic()?;
        }
        if !path_has_shim || !rcfile_ok {
            writeln!(stdout, "  arbitraitor wrappers init --install").into_diagnostic()?;
        }
        if !tar_rs_ok {
            writeln!(
                stdout,
                "  update tar-rs to at least {MIN_SAFE_TAR_RS_VERSION} (GHSA-3pv8-6f4r-ffg2)"
            )
            .into_diagnostic()?;
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

fn locked_crate_version(lock: &str, crate_name: &str) -> Option<String> {
    let mut in_matching_package = false;
    for line in lock.lines() {
        match line {
            "[[package]]" => in_matching_package = false,
            line if line == format!("name = \"{crate_name}\"") => in_matching_package = true,
            line if in_matching_package && line.starts_with("version = ") => {
                return line
                    .strip_prefix("version = \"")
                    .and_then(|value| value.strip_suffix('"'))
                    .map(str::to_owned);
            }
            _ => {}
        }
    }
    None
}

fn semver_at_least(version: &str, minimum: &str) -> bool {
    parse_semver_triplet(version) >= parse_semver_triplet(minimum)
}

fn parse_semver_triplet(version: &str) -> Option<(u64, u64, u64)> {
    let core = version.split_once('-').map_or(version, |(core, _)| core);
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

pub(crate) fn version() -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "arbitraitor {}", env!("CARGO_PKG_VERSION")).into_diagnostic()?;
    writeln!(stdout, "license: {}", env!("CARGO_PKG_LICENSE")).into_diagnostic()?;
    writeln!(stdout, "repository: {}", env!("CARGO_PKG_REPOSITORY")).into_diagnostic()?;
    writeln!(stdout, "target: {}", std::env::consts::ARCH).into_diagnostic()?;
    writeln!(
        stdout,
        "min-rust-version: {}",
        env!("CARGO_PKG_RUST_VERSION")
    )
    .into_diagnostic()?;
    if let Some(commit) = option_env!("ARBITRAITOR_BUILD_COMMIT")
        && !commit.is_empty()
    {
        writeln!(stdout, "commit: {commit}").into_diagnostic()?;
    }
    if let Some(date) = option_env!("ARBITRAITOR_BUILD_DATE")
        && !date.is_empty()
    {
        writeln!(stdout, "build-date: {date}").into_diagnostic()?;
    }
    writeln!(stdout, "profile: {}", profile_name()).into_diagnostic()?;
    Ok(())
}

fn profile_name() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
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
                arbitraitor_update::manifest::UpdateChannel::BinaryRelease => "binary_release",
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

    // ADR-0031 / issue #612 (Blocker 4 from the round-1 adversarial review,
    // extended to the `arbitraitor execute` command in round 2 of the
    // review): gate the approved artifact by classified ArtifactType before
    // piping bytes to bash. The approval file pins the interpreter to bash,
    // but a user (or automation) could approve an HTML / JSON / XML /
    // archive / Unknown artifact via `arbitraitor approve` and execute it
    // via `arbitraitor execute`, bypassing the content-type gate at the
    // `run` pipeline layer. Piping such bytes to bash is unsafe (HTML etc.
    // can incidentally contain bash-parseable `$(...)`, redirections, pipes)
    // — the same rationale as ADR-0031 applies here. Only
    // `ArtifactType::ShellScript(_)` is runnable through this execute
    // path; everything else fails closed. (Native executables are gated
    // out as well because the approval flow always binds to the bash
    // interpreter; native execution uses a separate release path.)
    let classification = classify(&bytes);
    if !matches!(classification.artifact_type, ArtifactType::ShellScript(_)) {
        miette::bail!(
            "artifact type {:?} is not executable via the approved execute path; \
             only shell scripts are runnable (ADR-0031, issue #612)",
            classification.artifact_type
        );
    }

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

/// Stub handler for `arbitraitor report <subcommand>` (spec §21.7).
///
/// The intel-store backed implementation lands in a follow-up PR. For now
/// we validate inputs and describe what would be recorded, so users can
/// wire the CLI surface end-to-end without it silently no-op'ing.
pub(crate) fn report(command: &ReportCommand) -> Result<()> {
    match &command.subcommand {
        ReportSubcommand::FalsePositive { finding_id } => {
            if finding_id.trim().is_empty() {
                miette::bail!("finding_id must not be empty");
            }
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "would_record_false_positive: true").into_diagnostic()?;
            writeln!(stdout, "finding_id: {finding_id}").into_diagnostic()?;
            writeln!(
                stdout,
                "note: intel-store persistence will be enabled in a follow-up PR"
            )
            .into_diagnostic()?;
        }
    }
    Ok(())
}

/// Stub handler for `arbitraitor allow sha256:<hash> ...` (spec §21.7).
///
/// All exceptions must be scoped, time-bounded, and have a justification;
/// we validate those invariants up front so a follow-up PR only needs to
/// persist them, not change the CLI surface.
pub(crate) fn allow(command: &AllowCommand) -> Result<()> {
    let hash = parse_sha256_allow_target(&command.hash)?;
    let duration = parse_duration_to_seconds(&command.expires)
        .map_err(|e| miette::miette!("invalid --expires '{}': {e}", command.expires))?;
    if duration == 0 {
        miette::bail!("--expires must be greater than zero");
    }
    if command.reason.trim().is_empty() {
        miette::bail!("--reason must not be empty");
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let expires_at = now.saturating_add(duration);
    let scope = match command.scope {
        AllowScope::User => "user",
        AllowScope::Project => "project",
        AllowScope::Org => "org",
    };

    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "would_record_allow_exception: true").into_diagnostic()?;
    writeln!(stdout, "hash: {hash}").into_diagnostic()?;
    writeln!(stdout, "scope: {scope}").into_diagnostic()?;
    writeln!(stdout, "expires_in_seconds: {duration}").into_diagnostic()?;
    writeln!(stdout, "expires_at_unix: {expires_at}").into_diagnostic()?;
    writeln!(stdout, "reason: {}", command.reason).into_diagnostic()?;
    writeln!(
        stdout,
        "note: intel-store persistence will be enabled in a follow-up PR"
    )
    .into_diagnostic()?;
    Ok(())
}

/// Strip the `sha256:` prefix and validate the remaining 64 hex chars.
fn parse_sha256_allow_target(raw: &str) -> Result<String> {
    let hex = raw
        .strip_prefix("sha256:")
        .ok_or_else(|| miette::miette!("hash must be prefixed with 'sha256:'"))?;
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(miette::miette!(
            "hash must be 64 hex characters after the 'sha256:' prefix"
        ));
    }
    Ok(hex.to_ascii_lowercase())
}

/// Parse a compact duration like `7d`, `24h`, `30m`, `60s` into seconds.
/// Compound forms (`1d12h`) and bare integers are not accepted in the stub
/// to keep the surface small; the follow-up PR can extend the grammar.
fn parse_duration_to_seconds(raw: &str) -> Result<u64, String> {
    if raw.is_empty() {
        return Err("empty duration".to_owned());
    }
    let (num_part, unit) = raw.split_at(raw.len() - 1);
    let value: u64 = num_part
        .parse()
        .map_err(|_| format!("expected a non-negative integer before unit '{unit}'"))?;
    if value == 0 {
        return Err("duration must be greater than zero".to_owned());
    }
    let multiplier = match unit {
        "s" => 1_u64,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 60 * 60 * 24,
        other => return Err(format!("unknown duration unit '{other}'")),
    };
    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration '{raw}' overflows u64 seconds"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::ExecutionPlanInputs;
    use arbitraitor_model::ids::Sha256Digest;
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};

    const APPROVER: &str = "round-2-test";
    const VERDICT: &str = "pass";
    const TTL_SECONDS: u64 = 3600;

    /// Build an `ApprovalFile` for the bash-execution path with the given
    /// artifact digest, pinned to network-isolated. Far-future timestamps
    /// so the expiry check always passes.
    fn build_approval(
        sha256: Sha256Digest,
    ) -> Result<crate::approval::ApprovalFile, Box<dyn std::error::Error>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let inputs = ExecutionPlanInputs {
            artifact_sha256: sha256,
            network_isolated: true,
            policy_snapshot_digest: String::new(),
            detector_snapshot_digest: String::new(),
        };
        Ok(crate::approval::ApprovalFile::for_bash_execution(
            &inputs,
            APPROVER,
            now,
            now + TTL_SECONDS,
            VERDICT,
        )?)
    }

    /// Store the given bytes under a fresh CAS root and return the digest.
    fn store_bytes_under_cas(
        cas_root: &Path,
        bytes: &[u8],
    ) -> Result<Sha256Digest, Box<dyn std::error::Error>> {
        let sha256 = Sha256Digest::new(Sha256::digest(bytes).into());
        let store = ContentStore::open(cas_root)?;
        let mut sink = store.sink(Some(&sha256))?;
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(sink.write_chunk(bytes))?;
        runtime.block_on(sink.finish())?;
        Ok(sha256)
    }

    /// Regression test for the round-2 adversarial review of PR #615
    /// (Blocker 4 extended scope): `arbitraitor execute` must gate the
    /// approved artifact by classified `ArtifactType` before piping bytes
    /// to bash. An HTML artifact (verifiably `ArtifactType::HtmlDocument`)
    /// is approved via the bash-execution approval flow and then passed
    /// through `execute(&command, &config)`. Without the gate the bytes
    /// would be piped to `/bin/bash` (unsafe per ADR-0031: HTML can
    /// incidentally contain bash-parseable `$(...)`, redirections, pipes).
    /// With the gate, the function must bail with "is not executable via
    /// the approved execute path" and name the artifact type.
    #[test]
    fn execute_command_rejects_html_artifact_via_content_type_gate()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = b"<!DOCTYPE html>\n<html><body>not bash</body></html>\n".to_vec();
        let cas_root =
            std::env::temp_dir().join(format!("arb-execute-gate-html-{}", std::process::id()));
        std::fs::remove_dir_all(&cas_root).ok();
        let sha256 = store_bytes_under_cas(&cas_root, &bytes)?;
        let approval = build_approval(sha256.clone())?;
        let approval_path = std::env::temp_dir().join(format!(
            "arb-execute-gate-approval-html-{}-{sha256}.json",
            std::process::id()
        ));
        std::fs::write(&approval_path, serde_json::to_vec_pretty(&approval)?)?;

        let mut config = Config::default();
        config.store.cas_dir = Some(cas_root.clone());

        let command = ExecuteCommand {
            approval: approval_path.clone(),
            network: false,
        };

        let result = execute(&command, &config);

        std::fs::remove_dir_all(&cas_root).ok();
        std::fs::remove_file(&approval_path).ok();

        let Err(err) = result else {
            return Err(
                "execute() should have rejected HTML artifact via the gate, but it succeeded"
                    .into(),
            );
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("is not executable via the approved execute path"),
            "expected is-not-executable error; got: {msg}"
        );
        assert!(
            msg.contains("HtmlDocument"),
            "expected the artifact type name in the error; got: {msg}"
        );
        Ok(())
    }

    /// Positive control for the round-2 review (Blocker 4 extended scope):
    /// a shebang-tagged shell script artifact must pass through the
    /// `arbitraitor execute` content-type gate and reach
    /// `ScriptExecution::bash().execute()`. Verifies the gate does not
    /// over-tighten on legitimate script artifacts (i.e. it permits
    /// `ArtifactType::ShellScript(Posix)` through).
    #[test]
    #[cfg(target_os = "linux")]
    fn execute_command_accepts_shell_script_artifact_through_gate()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = b"#!/bin/sh\necho 'posix shell through execute gate'\n".to_vec();
        let cas_root =
            std::env::temp_dir().join(format!("arb-execute-gate-script-{}", std::process::id()));
        std::fs::remove_dir_all(&cas_root).ok();
        let sha256 = store_bytes_under_cas(&cas_root, &bytes)?;
        let approval = build_approval(sha256.clone())?;
        let approval_path = std::env::temp_dir().join(format!(
            "arb-execute-gate-approval-script-{}-{sha256}.json",
            std::process::id()
        ));
        std::fs::write(&approval_path, serde_json::to_vec_pretty(&approval)?)?;

        let mut config = Config::default();
        config.store.cas_dir = Some(cas_root.clone());

        let command = ExecuteCommand {
            approval: approval_path.clone(),
            network: false,
        };

        let result = execute(&command, &config);

        std::fs::remove_dir_all(&cas_root).ok();
        std::fs::remove_file(&approval_path).ok();

        // We don't assert exit-code because the bash sandbox may reject the
        // script via unshare/Landlock/network policy independent of the
        // content-type gate. What we DO assert is that the gate did NOT
        // bail with "is not executable" — i.e. it permitted the
        // ShellScript artifact to proceed to ScriptExecution::execute().
        match result {
            Ok(()) => Ok(()),
            Err(err) => {
                let msg = format!("{err}");
                assert!(
                    !msg.contains("is not executable via the approved execute path"),
                    "execute() must NOT reject a shell script artifact via the gate; got: {msg}"
                );
                Ok(())
            }
        }
    }

    #[test]
    fn parse_duration_to_seconds_handles_basic_units() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(parse_duration_to_seconds("60s")?, 60);
        assert_eq!(parse_duration_to_seconds("30m")?, 1800);
        assert_eq!(parse_duration_to_seconds("24h")?, 86_400);
        assert_eq!(parse_duration_to_seconds("7d")?, 604_800);
        assert!(parse_duration_to_seconds("").is_err());
        assert!(parse_duration_to_seconds("0s").is_err());
        assert!(parse_duration_to_seconds("12x").is_err());
        Ok(())
    }
}
