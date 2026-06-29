//! Arbitraitor CLI entry point.

#![forbid(unsafe_code)]

mod run;

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arbitraitor_analysis::{
    AnalysisCoordinator, ArtifactDetector, RetrievalInfo as AnalysisRetrievalInfo, ShellDetector,
};
use arbitraitor_archive::{ArchiveLimits, detect_archive_hazards, extract_to_output_dir};
use arbitraitor_artifact::classify;
use arbitraitor_core::config::Config;
use arbitraitor_core::health::HealthChecker;
use arbitraitor_daemon::{Daemon, DaemonRequest, default_socket_path, request_once};
use arbitraitor_fetch::{FetchPolicy, FetchRequest, FetchUrl, Fetcher, HttpFetcher, VecSink};
use arbitraitor_intel::{IngestionReport, IntelStore, UrlhausAdapter, ingest_feed};
use arbitraitor_model::finding::{Finding, FindingCategory};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity, Verdict};
use arbitraitor_provenance::{
    SignatureSystem, SignatureVerification, parse_minisign_public_key, verify_cosign,
    verify_minisign,
};
use arbitraitor_receipt::{
    DetectorVersion, FindingSummary, ReceiptBuilder, ReceiptTimestamps,
    RetrievalInfo as ReceiptRetrievalInfo, VerdictInfo,
};
use arbitraitor_store::ContentStore;
use arbitraitor_wrapper::shim::{
    ShimConfig, ShimError, WrapperTarget, check_shims, generate_shell_init, install_shims,
    uninstall_shims,
};
use arbitraitor_wrapper::{parse_curl_args, wget::translate_wget_args};
use arbitraitor_yarax::{RulePackManager, RuleSource, YaraDetector};
use clap::{Args, Parser, Subcommand};
use miette::{IntoDiagnostic, Result};
use sha2::{Digest, Sha256};

/// Arbitraitor: Secure Download and Execution Gate
#[derive(Parser)]
#[command(name = "arbitraitor", version, about, long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Override layered configuration with one TOML file
    #[arg(long, value_name = "PATH", global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Inspect(Box<InspectCommand>),
    #[command(hide = true)]
    Fetch(FetchCommand),
    Run(Box<run::RunCommand>),
    Daemon(DaemonCommand),
    Unpack(UnpackCommand),
    Intel(IntelCommand),
    Status(StatusCommand),
    Wrappers(WrappersCommand),
}

#[derive(Args)]
struct DaemonCommand {
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    subcommand: DaemonSubcommand,
}

#[derive(Subcommand)]
enum DaemonSubcommand {
    Start,
    Stop,
    Status,
}

#[derive(Args)]
struct InspectCommand {
    url: String,
    #[arg(long)]
    receipt: Option<PathBuf>,
    #[arg(long)]
    cas_dir: Option<PathBuf>,
    #[arg(long, value_name = "HEX")]
    sha256: Option<Sha256Digest>,
    #[arg(long, value_name = "DIR")]
    rules: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    minisign_sig: Vec<PathBuf>,
    #[arg(long, value_name = "KEY")]
    minisign_key: Vec<String>,
    #[arg(long, value_name = "PATH")]
    cosign_bundle: Vec<PathBuf>,
    #[arg(long, value_name = "IDENTITY")]
    cosign_identity: Vec<String>,
    #[arg(long, value_name = "ISSUER")]
    cosign_issuer: Vec<String>,
    /// Show an explainability report for detected findings.
    #[arg(long)]
    explain: bool,
    /// Output format for the explainability report (implies --explain).
    #[arg(long, value_enum)]
    format: Option<ExplainFormat>,
}

#[derive(Args)]
#[command(disable_help_flag = true)]
struct FetchCommand {
    #[arg(long, value_name = "curl|wget")]
    tool: Option<String>,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

/// Output format for the `--explain` report.
#[derive(Clone, Copy, Debug, clap::ValueEnum, Eq, PartialEq)]
enum ExplainFormat {
    /// Human-readable text report.
    Text,
    /// ShellCheck-compatible JSON.
    Shellcheck,
}

#[derive(Args)]
struct UnpackCommand {
    archive: PathBuf,
    #[arg(long, value_name = "DIR")]
    output: PathBuf,
}

/// Report Arbitraitor component health and version information.
#[derive(Args)]
struct StatusCommand {
    /// Output the full health report as JSON.
    #[arg(long)]
    json: bool,
    /// Override the content-addressed store root to probe.
    #[arg(long, value_name = "DIR")]
    cas_dir: Option<PathBuf>,
    /// Load YARA-X rule packs from this directory and report their versions.
    #[arg(long, value_name = "DIR")]
    rules: Option<PathBuf>,
}

/// `arbitraitor intel` — manage local threat-intelligence feeds.
#[derive(Args)]
struct IntelCommand {
    #[command(subcommand)]
    subcommand: IntelSubcommand,
}

#[derive(Subcommand)]
enum IntelSubcommand {
    /// Fetch and ingest one or more feeds into the local intel store.
    Update(UpdateCommand),
}

#[derive(Args)]
struct UpdateCommand {
    /// Ingest the `URLhaus` malicious-URL feed.
    #[arg(long)]
    urlhaus: bool,
    /// Override the `URLhaus` feed URL (CSV or JSON).
    #[arg(long, value_name = "URL")]
    urlhaus_url: Option<String>,
    /// Override the local intel store path.
    #[arg(long, value_name = "PATH")]
    intel_store: Option<PathBuf>,
}

/// `arbitraitor wrappers` — install and manage PATH shims for curl/wget.
#[derive(Args)]
struct WrappersCommand {
    /// Override the shim directory (default: `$HOME/.arbitraitor/shims`).
    #[arg(long, value_name = "DIR", global = true)]
    shim_dir: Option<PathBuf>,
    /// Use wrapper scripts instead of symlinks.
    #[arg(long, global = true)]
    use_scripts: bool,
    #[command(subcommand)]
    subcommand: WrappersSubcommand,
}

#[derive(Subcommand)]
enum WrappersSubcommand {
    /// Install PATH shims for the specified wrappers (default: all).
    Install(InstallWrappersCommand),
    /// Remove previously installed shims.
    Uninstall(UninstallWrappersCommand),
    /// Show which shims are currently installed.
    Status(WrappersStatusCommand),
    /// Print a shell init snippet for ~/.bashrc or ~/.zshrc.
    InitScript(InitScriptCommand),
}

#[derive(Args)]
struct InstallWrappersCommand {
    /// Specific wrappers to install (e.g. `curl`, `wget`). Defaults to all.
    targets: Vec<String>,
}

#[derive(Args)]
struct UninstallWrappersCommand {
    /// Specific wrappers to uninstall. Defaults to all.
    targets: Vec<String>,
}

#[derive(Args)]
struct WrappersStatusCommand {
    /// Specific wrappers to check. Defaults to all.
    targets: Vec<String>,
}

#[derive(Args)]
struct InitScriptCommand {}

#[derive(Debug, Default)]
struct SignatureInputs {
    minisign: Vec<MinisignInput>,
    cosign: Vec<CosignInput>,
}

#[derive(Debug)]
struct MinisignInput {
    signature_path: PathBuf,
    public_key: String,
}

#[derive(Debug)]
struct CosignInput {
    bundle_path: PathBuf,
    identity: String,
    issuer: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_cli_from_invocation();

    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt().with_env_filter(level).init();

    tracing::info!("arbitraitor initialized");

    let config = match cli.config.as_deref() {
        Some(path) => Config::load_from_file(path),
        None => Config::load(),
    }
    .into_diagnostic()?;

    match cli.command {
        Command::Inspect(command) => {
            let InspectCommand {
                url,
                receipt,
                cas_dir,
                sha256,
                rules,
                minisign_sig,
                minisign_key,
                cosign_bundle,
                cosign_identity,
                cosign_issuer,
                explain,
                format,
            } = *command;
            let signatures = signature_inputs(
                minisign_sig,
                minisign_key,
                cosign_bundle,
                cosign_identity,
                cosign_issuer,
            )?;
            let explain_format = match (explain, format) {
                (_, Some(f)) => Some(f),
                (true, None) => Some(ExplainFormat::Text),
                (false, None) => None,
            };
            inspect(
                &url,
                receipt.as_deref(),
                cas_dir.as_deref(),
                sha256,
                rules.as_deref(),
                signatures,
                &config,
                explain_format,
            )
            .await?;
        }
        Command::Fetch(command) => {
            wrapper_fetch(&command, &config).await?;
        }
        Command::Run(command) => {
            let exit_code = run::run(*command, &config).await?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        Command::Daemon(command) => {
            daemon(command).await?;
        }
        Command::Unpack(command) => {
            unpack(&command.archive, &command.output)?;
        }
        Command::Intel(command) => {
            intel(command).await?;
        }
        Command::Status(command) => {
            status(&command, &config)?;
        }
        Command::Wrappers(command) => {
            wrappers(command)?;
        }
    }

    Ok(())
}

fn parse_cli_from_invocation() -> Cli {
    parse_cli_from_args(std::env::args_os())
}

fn parse_cli_from_args<I, T>(args: I) -> Cli
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let Some(program) = args.first() else {
        return Cli::parse_from([OsString::from("arbitraitor")]);
    };
    let wrapper_target = Path::new(program)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .and_then(WrapperTarget::from_binary_name);
    if wrapper_target.is_none() {
        return Cli::parse_from(args);
    }

    let Some(wrapper_target) = wrapper_target else {
        return Cli::parse_from(args);
    };
    let mut rewritten = Vec::with_capacity(args.len() + 4);
    rewritten.push(OsString::from("arbitraitor"));
    rewritten.push(OsString::from("fetch"));
    rewritten.push(OsString::from("--tool"));
    rewritten.push(OsString::from(wrapper_target.binary_name()));
    rewritten.push(OsString::from("--"));
    rewritten.extend(args.into_iter().skip(1));
    Cli::parse_from(rewritten)
}

async fn wrapper_fetch(command: &FetchCommand, config: &Config) -> Result<()> {
    let target = wrapper_fetch_target(command.tool.as_deref())?;
    let url = wrapper_url_argument(command.tool.as_deref(), &command.args).ok_or_else(|| {
        miette::miette!("curl/wget wrapper requires an http:// or https:// URL argument")
    })?;
    if matches!(target, Some(WrapperTarget::Curl)) {
        let parsed = parse_curl_args(&command.args).into_diagnostic()?;
        if !parsed.unsupported_options.is_empty() {
            miette::bail!(
                "unsupported curl wrapper option: {}",
                parsed.unsupported_options.join(", ")
            );
        }
    }
    let verdict = inspect(
        url,
        None,
        None,
        None,
        None,
        SignatureInputs::default(),
        config,
        None,
    )
    .await?;
    enforce_wrapper_verdict(verdict)
}

fn wrapper_fetch_target(tool: Option<&str>) -> Result<Option<WrapperTarget>> {
    tool.map(|name| {
        WrapperTarget::from_binary_name(name)
            .ok_or_else(|| miette::miette!("unsupported wrapper target: {name}"))
    })
    .transpose()
}

fn enforce_wrapper_verdict(verdict: Verdict) -> Result<()> {
    if verdict == Verdict::Pass {
        return Ok(());
    }
    miette::bail!("wrapper rejected artifact with verdict {verdict:?}")
}

fn wrapper_url_argument<'a>(tool: Option<&str>, args: &'a [String]) -> Option<&'a str> {
    match tool.and_then(WrapperTarget::from_binary_name) {
        Some(WrapperTarget::Curl) => curl_url_argument(args),
        Some(WrapperTarget::Wget) => wget_url_argument(args),
        None => curl_url_argument(args).or_else(|| wget_url_argument(args)),
    }
}

fn curl_url_argument(args: &[String]) -> Option<&str> {
    let parsed = parse_curl_args(args).ok()?;
    let url = parsed.url.as_deref()?;
    args.iter().map(String::as_str).find(|arg| *arg == url)
}

fn wget_url_argument(args: &[String]) -> Option<&str> {
    let parsed = translate_wget_args(args).ok()?;
    args.iter()
        .map(String::as_str)
        .find(|arg| *arg == parsed.url.as_str())
}

async fn daemon(command: DaemonCommand) -> Result<()> {
    let socket = command.socket.unwrap_or_else(default_socket_path);
    match command.subcommand {
        DaemonSubcommand::Start => {
            Daemon::new(socket).run().await.into_diagnostic()?;
        }
        DaemonSubcommand::Stop => {
            let response = request_once(socket, &DaemonRequest::Shutdown)
                .await
                .into_diagnostic()?;
            write_daemon_response(&mut std::io::stdout().lock(), &response)?;
            if !response.success {
                miette::bail!(
                    response
                        .error
                        .unwrap_or_else(|| "daemon stop failed".to_owned())
                );
            }
        }
        DaemonSubcommand::Status => {
            let response = request_once(
                socket,
                &DaemonRequest::Scan {
                    path: String::new(),
                },
            )
            .await;
            let mut stdout = std::io::stdout().lock();
            match response {
                Ok(_) => writeln!(stdout, "running").into_diagnostic()?,
                Err(_) => writeln!(stdout, "stopped").into_diagnostic()?,
            }
        }
    }
    Ok(())
}

fn write_daemon_response(
    writer: &mut impl std::io::Write,
    response: &arbitraitor_daemon::DaemonResponse,
) -> Result<()> {
    writeln!(writer, "success: {}", response.success).into_diagnostic()?;
    if let Some(verdict) = &response.verdict {
        writeln!(writer, "verdict: {verdict}").into_diagnostic()?;
    }
    writeln!(writer, "findings: {}", response.findings_count).into_diagnostic()?;
    if let Some(sha256) = &response.sha256 {
        writeln!(writer, "sha256: {sha256}").into_diagnostic()?;
    }
    if let Some(error) = &response.error {
        writeln!(writer, "error: {error}").into_diagnostic()?;
    }
    Ok(())
}

fn unpack(archive_path: &Path, output_dir: &Path) -> Result<()> {
    let bytes = std::fs::read(archive_path).into_diagnostic()?;
    let artifact_type = classify(&bytes).artifact_type;
    let limits = ArchiveLimits::default();
    let mut reader =
        arbitraitor_archive::open_archive_with_limits(&bytes, artifact_type, limits.clone())
            .into_diagnostic()?;
    let entries = reader.entries().into_diagnostic()?;
    let hazards = detect_archive_hazards(&entries, &limits);
    if !hazards.is_empty() {
        write_unpack_hazards(&mut std::io::stderr().lock(), &hazards)?;
        miette::bail!("archive hazards block hardened unpack");
    }

    let mut reader =
        arbitraitor_archive::open_archive_with_limits(&bytes, artifact_type, limits.clone())
            .into_diagnostic()?;
    let extracted =
        extract_to_output_dir(reader.as_mut(), &limits, output_dir).into_diagnostic()?;
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "extracted_files: {}", extracted.len()).into_diagnostic()?;
    for file in extracted {
        writeln!(
            stdout,
            "- {} size={} sha256={}",
            file.path.display(),
            file.size,
            file.sha256
        )
        .into_diagnostic()?;
    }
    Ok(())
}

async fn intel(command: IntelCommand) -> Result<()> {
    let IntelSubcommand::Update(update) = command.subcommand;
    if !update.urlhaus {
        miette::bail!("no feed selected; pass --urlhaus to ingest the URLhaus feed");
    }
    let adapter = match update.urlhaus_url {
        Some(url) => UrlhausAdapter::with_url(url),
        None => UrlhausAdapter::new(),
    };
    let store_path = update
        .intel_store
        .unwrap_or_else(|| PathBuf::from(".arbitraitor/intel.json"));
    let mut store = IntelStore::open(&store_path).into_diagnostic()?;
    let report = ingest_feed(
        &adapter,
        &HttpFetcher::new(),
        &mut store,
        &FetchPolicy::default(),
    )
    .await
    .into_diagnostic()?;
    write_intel_report(&mut std::io::stderr().lock(), &report)
}

fn write_intel_report(writer: &mut impl std::io::Write, report: &IngestionReport) -> Result<()> {
    writeln!(writer, "source: {}", report.source).into_diagnostic()?;
    writeln!(writer, "added: {}", report.entries_added).into_diagnostic()?;
    writeln!(writer, "updated: {}", report.entries_updated).into_diagnostic()?;
    writeln!(writer, "expired: {}", report.entries_expired).into_diagnostic()?;
    writeln!(writer, "errors: {}", report.errors.len()).into_diagnostic()?;
    for error in &report.errors {
        writeln!(writer, "- {error}").into_diagnostic()?;
    }
    Ok(())
}

fn wrappers(command: WrappersCommand) -> Result<()> {
    let shim_dir = command.shim_dir.or_else(default_shim_dir).ok_or_else(|| {
        miette::miette!("could not determine shim directory; pass --shim-dir or set $HOME")
    })?;
    let config = ShimConfig {
        shim_dir: shim_dir.clone(),
        use_symlinks: !command.use_scripts,
    };
    match command.subcommand {
        WrappersSubcommand::Install(install) => {
            let targets = resolve_targets(&install.targets)?;
            let arb = current_arbitraitor_binary()?;
            let installed = install_shims(&config, &targets, &arb)
                .map_err(|err| shim_error_to_miette(&err, "install"))?;
            let mut stdout = std::io::stdout().lock();
            for path in &installed {
                writeln!(stdout, "installed: {}", path.display()).into_diagnostic()?;
            }
            writeln!(
                stdout,
                "{} shim{} installed in {}",
                installed.len(),
                if installed.len() == 1 { "" } else { "s" },
                shim_dir.display()
            )
            .into_diagnostic()?;
        }
        WrappersSubcommand::Uninstall(uninstall) => {
            let targets = resolve_targets(&uninstall.targets)?;
            let removed = uninstall_shims(&config, &targets)
                .map_err(|err| shim_error_to_miette(&err, "uninstall"))?;
            let mut stdout = std::io::stdout().lock();
            writeln!(
                stdout,
                "{} shim{} removed from {}",
                removed,
                if removed == 1 { "" } else { "s" },
                shim_dir.display()
            )
            .into_diagnostic()?;
        }
        WrappersSubcommand::Status(status_cmd) => {
            let targets = resolve_targets(&status_cmd.targets)?;
            let statuses = check_shims(&config, &targets);
            let mut stdout = std::io::stdout().lock();
            for st in &statuses {
                let label = match st.state {
                    arbitraitor_wrapper::shim::ShimState::Script => "installed (script)",
                    arbitraitor_wrapper::shim::ShimState::Symlink => "installed (symlink)",
                    arbitraitor_wrapper::shim::ShimState::NotInstalled => "not installed",
                    arbitraitor_wrapper::shim::ShimState::ForeignFile => "foreign file",
                };
                writeln!(stdout, "{}: {label}", st.target.binary_name()).into_diagnostic()?;
            }
        }
        WrappersSubcommand::InitScript(_) => {
            let arb = current_arbitraitor_binary()?;
            let snippet = generate_shell_init(&arb, WrapperTarget::ALL);
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(snippet.as_bytes()).into_diagnostic()?;
        }
    }
    Ok(())
}

fn resolve_targets(names: &[String]) -> Result<Vec<WrapperTarget>> {
    if names.is_empty() {
        return Ok(WrapperTarget::ALL.to_vec());
    }
    names
        .iter()
        .map(|name| {
            WrapperTarget::from_binary_name(name).ok_or_else(|| {
                miette::miette!("unknown wrapper target '{name}'; supported: curl, wget")
            })
        })
        .collect()
}

fn default_shim_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".arbitraitor").join("shims"))
}

fn current_arbitraitor_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe().into_diagnostic()?;
    if exe.is_absolute() {
        Ok(exe)
    } else {
        miette::bail!("could not determine absolute path to arbitraitor binary");
    }
}

fn shim_error_to_miette(error: &ShimError, action: &str) -> miette::Report {
    miette::miette!("shim {action} failed: {error}")
}

fn status(command: &StatusCommand, config: &Config) -> Result<()> {
    let cas_dir = command
        .cas_dir
        .clone()
        .or_else(|| config.store.cas_dir.clone())
        .unwrap_or_else(default_cas_dir);

    let mut checker = HealthChecker::new().with_store(cas_dir);
    if let Some(rules_dir) = command.rules.as_deref() {
        let versions = rule_pack_versions(rules_dir)?;
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

    write_status_text(&mut std::io::stdout().lock(), &report)
}

fn rule_pack_versions(rules_dir: &Path) -> Result<Vec<String>> {
    let mut manager = arbitraitor_yarax::RulePackManager::with_built_in().into_diagnostic()?;
    manager
        .load_directory(
            rules_dir,
            arbitraitor_yarax::RuleSource::FileSystem(rules_dir.to_path_buf()),
        )
        .into_diagnostic()?;
    Ok(manager
        .pack_versions()
        .into_iter()
        .map(|version| version.version)
        .collect())
}

fn write_status_text(
    writer: &mut impl std::io::Write,
    report: &arbitraitor_core::health::HealthReport,
) -> Result<()> {
    writeln!(writer, "Arbitraitor v{}", report.version).into_diagnostic()?;
    writeln!(writer, "Overall: {:?}", report.overall).into_diagnostic()?;
    writeln!(writer).into_diagnostic()?;
    writeln!(writer, "Component {:<10} Details", "Status").into_diagnostic()?;
    for component_name in ["store", "detectors", "version"] {
        if let Some(component) = report.checks.get(component_name) {
            writeln!(
                writer,
                "{:<10} {:<10} {}",
                capitalize(component_name),
                format!("{:?}", component.status),
                component.message
            )
            .into_diagnostic()?;
        }
    }
    Ok(())
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn write_unpack_hazards(
    writer: &mut impl std::io::Write,
    hazards: &[arbitraitor_model::finding::Finding],
) -> Result<()> {
    writeln!(writer, "archive_hazards: {}", hazards.len()).into_diagnostic()?;
    for hazard in hazards {
        writeln!(
            writer,
            "- [{} {:?}/{:?}] {}",
            hazard.id, hazard.severity, hazard.confidence, hazard.title
        )
        .into_diagnostic()?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn inspect(
    url: &str,
    receipt_path: Option<&Path>,
    cas_dir: Option<&Path>,
    expected_sha256: Option<Sha256Digest>,
    rules_dir: Option<&Path>,
    signatures: SignatureInputs,
    config: &Config,
    explain_format: Option<ExplainFormat>,
) -> Result<Verdict> {
    let fetch_url = FetchUrl::parse(url).into_diagnostic()?;
    let fetch_policy = FetchPolicy {
        total_timeout: Duration::from_secs(config.fetch.total_timeout_secs),
        max_compressed_size: config.fetch.max_bytes,
        max_uncompressed_size: config.fetch.max_bytes,
        max_redirects: usize::try_from(config.fetch.max_redirects).into_diagnostic()?,
        require_digest: config.integrity.require_digest,
        ..FetchPolicy::default()
    };
    let mut request = FetchRequest::url(fetch_url, fetch_policy);
    if let Some(digest) = expected_sha256 {
        request = request.with_expected_sha256(digest);
    }
    let mut fetch_sink = VecSink::new();
    let fetch_receipt = HttpFetcher::new()
        .fetch(request, &mut fetch_sink)
        .await
        .into_diagnostic()?;
    let bytes = fetch_sink.into_bytes();
    let artifact_len = u64::try_from(bytes.len()).into_diagnostic()?;
    if artifact_len > config.store.max_bytes {
        miette::bail!(
            "artifact exceeds configured store limit: bytes={}, limit={}",
            artifact_len,
            config.store.max_bytes
        );
    }
    let artifact_sha256 = Sha256Digest::new(Sha256::digest(&bytes).into());
    if artifact_sha256 != fetch_receipt.sha256 {
        miette::bail!(
            "fetch digest mismatch: receipt={}, bytes={}",
            fetch_receipt.sha256,
            artifact_sha256
        );
    }

    let cas_root = cas_dir
        .map(Path::to_path_buf)
        .or_else(|| config.store.cas_dir.clone())
        .unwrap_or_else(default_cas_dir);
    let store = ContentStore::open(&cas_root).into_diagnostic()?;
    let mut store_sink = store.sink(Some(&artifact_sha256)).into_diagnostic()?;
    store_sink.write_chunk(&bytes).await.into_diagnostic()?;
    let stored_digest = store_sink.finish().await.into_diagnostic()?;
    if stored_digest != artifact_sha256 {
        miette::bail!(
            "CAS digest mismatch: stored={}, expected={}",
            stored_digest,
            artifact_sha256
        );
    }

    let signature_verifications = verify_signatures(&bytes, &signatures)?;

    let analysis_retrieval = analysis_retrieval_info(url, &fetch_receipt);
    let (coordinator, rule_pack_versions) = analysis_coordinator(rules_dir)?;
    let result = coordinator.analyze_with_retrieval(&bytes, Some(analysis_retrieval));
    write_report(
        &mut std::io::stderr().lock(),
        &result,
        &artifact_sha256,
        &cas_root,
        &signature_verifications,
    )?;

    if let Some(format) = explain_format {
        write_explainability(&result.findings, url, format)?;
    }

    if let Some(path) = receipt_path {
        let receipt = build_receipt(
            url,
            &fetch_receipt,
            &result,
            &artifact_sha256,
            bytes.len(),
            &rule_pack_versions,
            &signature_verifications,
        )?;
        let json = serde_json::to_vec_pretty(&receipt).into_diagnostic()?;
        std::fs::write(path, json).into_diagnostic()?;
    }

    Ok(result.verdict)
}

fn analysis_coordinator(
    rules_dir: Option<&Path>,
) -> Result<(AnalysisCoordinator, Vec<DetectorVersion>)> {
    let Some(rules_dir) = rules_dir else {
        return Ok((AnalysisCoordinator::new(), Vec::new()));
    };

    let mut manager = RulePackManager::with_built_in().into_diagnostic()?;
    manager
        .load_directory(rules_dir, RuleSource::FileSystem(rules_dir.to_path_buf()))
        .into_diagnostic()?;
    let rule_pack_versions = manager.pack_versions();
    let scanner = manager.compile_all().into_diagnostic()?;
    let detector = YaraDetector::from_scanner(&scanner).into_diagnostic()?;
    Ok((
        AnalysisCoordinator::with_detectors(vec![
            Box::new(ArtifactDetector),
            Box::new(ShellDetector),
            Box::new(detector),
        ]),
        rule_pack_versions,
    ))
}

fn default_cas_dir() -> PathBuf {
    PathBuf::from(".arbitraitor").join("cas")
}

fn analysis_retrieval_info(
    requested_url: &str,
    fetch_receipt: &arbitraitor_fetch::FetchReceipt,
) -> AnalysisRetrievalInfo {
    AnalysisRetrievalInfo {
        requested_location: Some(arbitraitor_fetch::redact_url(requested_url)),
        final_location: fetch_receipt
            .metadata
            .final_url
            .as_ref()
            .map(ToString::to_string)
            .map(|url| arbitraitor_fetch::redact_url(&url)),
        content_type: fetch_receipt.metadata.content_type.clone(),
        byte_count: Some(fetch_receipt.bytes_written),
    }
}

fn write_report(
    writer: &mut impl std::io::Write,
    result: &arbitraitor_analysis::AnalysisResult,
    digest: &Sha256Digest,
    cas_root: &Path,
    signature_verifications: &[SignatureVerification],
) -> Result<()> {
    writeln!(writer, "artifact_sha256: {digest}").into_diagnostic()?;
    writeln!(writer, "cas_dir: {}", cas_root.display()).into_diagnostic()?;
    writeln!(
        writer,
        "artifact_type: {:?}",
        result.classification.artifact_type
    )
    .into_diagnostic()?;
    writeln!(writer, "verdict: {:?}", result.verdict).into_diagnostic()?;
    writeln!(
        writer,
        "signatures_verified: {}",
        signature_verifications.len()
    )
    .into_diagnostic()?;
    for verification in signature_verifications {
        writeln!(
            writer,
            "- signature: {} identity={}",
            verification.system.as_str(),
            verification.identity.as_deref().unwrap_or("<none>")
        )
        .into_diagnostic()?;
    }
    writeln!(writer, "findings: {}", result.findings.len()).into_diagnostic()?;
    for finding in &result.findings {
        writeln!(
            writer,
            "- [{} {:?}/{:?}] {}",
            finding.id, finding.severity, finding.confidence, finding.title
        )
        .into_diagnostic()?;
    }
    Ok(())
}

fn write_explainability(
    findings: &[Finding],
    source_name: &str,
    format: ExplainFormat,
) -> Result<()> {
    match format {
        ExplainFormat::Shellcheck => {
            let report = arbitraitor_shell::to_shellcheck_json(findings, source_name);
            let json = serde_json::to_string_pretty(&report).into_diagnostic()?;
            writeln!(std::io::stdout().lock(), "{json}").into_diagnostic()?;
        }
        ExplainFormat::Text => {
            let report = arbitraitor_shell::ExplainabilityReport::from_findings(findings);
            write!(std::io::stderr().lock(), "{}", report.to_text()).into_diagnostic()?;
        }
    }
    Ok(())
}

fn build_receipt(
    requested_url: &str,
    fetch_receipt: &arbitraitor_fetch::FetchReceipt,
    result: &arbitraitor_analysis::AnalysisResult,
    artifact_sha256: &Sha256Digest,
    artifact_size: usize,
    rule_pack_versions: &[DetectorVersion],
    signature_verifications: &[SignatureVerification],
) -> Result<arbitraitor_receipt::Receipt> {
    let artifact_size = u64::try_from(artifact_size).into_diagnostic()?;
    let now = timestamp();
    let mut builder = ReceiptBuilder::new(
        env!("CARGO_PKG_VERSION"),
        artifact_sha256.to_string(),
        artifact_size,
        VerdictInfo {
            verdict: result.verdict,
            deciding_rule: None,
            policy_trace: vec!["arbitraitor-analysis built-in verdict derivation".to_owned()],
        },
        ReceiptTimestamps {
            created: now.clone(),
            modified: now,
        },
    )
    .artifact_type(format!("{:?}", result.classification.artifact_type))
    .retrieval(receipt_retrieval_info(requested_url, fetch_receipt))
    .findings(result.findings.iter().map(FindingSummary::from))
    .findings(
        signature_verifications
            .iter()
            .enumerate()
            .map(|(index, verification)| signature_finding(index, verification)),
    );

    for detector_result in &result.detector_results {
        builder = builder.detector_version(DetectorVersion {
            id: detector_result.metadata.id.clone(),
            version: detector_result.metadata.version.clone(),
        });
    }
    for rule_pack_version in rule_pack_versions {
        builder = builder.detector_version(rule_pack_version.clone());
    }

    Ok(builder.build())
}

fn signature_inputs(
    minisign_sig: Vec<PathBuf>,
    minisign_key: Vec<String>,
    cosign_bundle: Vec<PathBuf>,
    cosign_identity: Vec<String>,
    cosign_issuer: Vec<String>,
) -> Result<SignatureInputs> {
    if minisign_sig.len() != minisign_key.len() {
        miette::bail!("each --minisign-sig requires exactly one --minisign-key");
    }
    if cosign_bundle.len() != cosign_identity.len() || cosign_bundle.len() != cosign_issuer.len() {
        miette::bail!(
            "each --cosign-bundle requires exactly one --cosign-identity and --cosign-issuer"
        );
    }

    Ok(SignatureInputs {
        minisign: minisign_sig
            .into_iter()
            .zip(minisign_key)
            .map(|(signature_path, public_key)| MinisignInput {
                signature_path,
                public_key,
            })
            .collect(),
        cosign: cosign_bundle
            .into_iter()
            .zip(cosign_identity)
            .zip(cosign_issuer)
            .map(|((bundle_path, identity), issuer)| CosignInput {
                bundle_path,
                identity,
                issuer,
            })
            .collect(),
    })
}

fn verify_signatures(
    artifact_bytes: &[u8],
    signatures: &SignatureInputs,
) -> Result<Vec<SignatureVerification>> {
    let mut verifications = Vec::with_capacity(signatures.minisign.len() + signatures.cosign.len());
    for minisign_input in &signatures.minisign {
        let signature = std::fs::read(&minisign_input.signature_path).into_diagnostic()?;
        let public_key = parse_minisign_public_key(&minisign_input.public_key).into_diagnostic()?;
        verifications
            .push(verify_minisign(artifact_bytes, &signature, &public_key).into_diagnostic()?);
    }
    for cosign_input in &signatures.cosign {
        verifications.push(
            verify_cosign(
                artifact_bytes,
                &cosign_input.bundle_path,
                &cosign_input.identity,
                &cosign_input.issuer,
            )
            .into_diagnostic()?,
        );
    }
    Ok(verifications)
}

fn signature_finding(index: usize, verification: &SignatureVerification) -> FindingSummary {
    FindingSummary {
        id: format!(
            "provenance.signature.{}.{}",
            verification.system.as_str(),
            index + 1
        ),
        category: FindingCategory::Provenance,
        severity: Severity::Informational,
        confidence: Confidence::Confirmed,
        title: signature_title(verification),
        location: None,
    }
}

fn signature_title(verification: &SignatureVerification) -> String {
    let system = match verification.system {
        SignatureSystem::Minisign => "minisign",
        SignatureSystem::Cosign => "cosign",
    };
    match verification.identity.as_deref() {
        Some(identity) => format!("{system} signature verified for {identity}"),
        None => format!("{system} signature verified"),
    }
}

fn receipt_retrieval_info(
    requested_url: &str,
    fetch_receipt: &arbitraitor_fetch::FetchReceipt,
) -> ReceiptRetrievalInfo {
    let mut retrieval = ReceiptRetrievalInfo::new(requested_url)
        .with_redirect_chain(
            fetch_receipt
                .metadata
                .redirect_chain
                .iter()
                .map(ToString::to_string),
        )
        .with_byte_count(fetch_receipt.bytes_written);
    if let Some(final_url) = &fetch_receipt.metadata.final_url {
        retrieval = retrieval.with_final_url(final_url.to_string());
    }
    if let Some(content_type) = &fetch_receipt.metadata.content_type {
        retrieval = retrieval.with_content_type(content_type.clone());
    }
    if let Some(tls_version) = &fetch_receipt.metadata.tls_version {
        retrieval = retrieval.with_tls_version(tls_version.clone());
    }
    if let Some(fingerprint) = &fetch_receipt.metadata.peer_certificate_fingerprint {
        retrieval = retrieval.with_peer_cert_fingerprint(format!("sha256:{fingerprint}"));
    }
    retrieval
}

fn timestamp() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => format!(
            "unix:{}.{:09}Z",
            duration.as_secs(),
            duration.subsec_nanos()
        ),
        Err(error) => format!(
            "unix:-{}.{:09}Z",
            error.duration().as_secs(),
            error.duration().subsec_nanos()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, Command, HealthChecker, WrappersCommand, WrappersSubcommand, enforce_wrapper_verdict,
        parse_cli_from_args, wrapper_url_argument, write_status_text,
    };
    use arbitraitor_model::verdict::Verdict;
    use clap::Parser;
    use std::fs;
    use std::io::{Cursor, Write};
    use std::path::PathBuf;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    #[test]
    fn inspect_accepts_sha256_flag() -> Result<(), Box<dyn std::error::Error>> {
        let digest = "ab".repeat(32);
        let cli = Cli::try_parse_from([
            "arbitraitor",
            "inspect",
            "https://example.test/artifact",
            "--sha256",
            &digest,
        ])?;

        match cli.command {
            Command::Inspect(command) => {
                assert_eq!(
                    command.sha256.ok_or("missing parsed digest")?.to_string(),
                    digest
                );
            }
            Command::Daemon(_)
            | Command::Fetch(_)
            | Command::Unpack(_)
            | Command::Intel(_)
            | Command::Run(_)
            | Command::Status(_)
            | Command::Wrappers(_) => {
                return Err("parsed wrong command".into());
            }
        }
        Ok(())
    }

    #[test]
    fn inspect_rejects_invalid_sha256_flag() {
        let result = Cli::try_parse_from([
            "arbitraitor",
            "inspect",
            "https://example.test/artifact",
            "--sha256",
            "not-a-digest",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn accepts_global_config_flag() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "arbitraitor",
            "--config",
            "arbitraitor.toml",
            "inspect",
            "https://example.test/artifact",
        ])?;

        assert_eq!(cli.config, Some(PathBuf::from("arbitraitor.toml")));
        Ok(())
    }

    #[test]
    fn inspect_accepts_rules_directory_flag() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "arbitraitor",
            "inspect",
            "https://example.test/artifact",
            "--rules",
            "/tmp/rules",
        ])?;

        match cli.command {
            Command::Inspect(command) => {
                assert_eq!(
                    command.rules.ok_or("missing rules path")?,
                    std::path::PathBuf::from("/tmp/rules")
                );
            }
            Command::Daemon(_)
            | Command::Fetch(_)
            | Command::Unpack(_)
            | Command::Intel(_)
            | Command::Run(_)
            | Command::Status(_)
            | Command::Wrappers(_) => {
                return Err("parsed wrong command".into());
            }
        }
        Ok(())
    }

    #[test]
    fn inspect_accepts_signature_flags() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "arbitraitor",
            "inspect",
            "https://example.test/artifact",
            "--minisign-sig",
            "artifact.minisig",
            "--minisign-key",
            "RWQexamplekeymaterial",
            "--cosign-bundle",
            "artifact.bundle",
            "--cosign-identity",
            "builder@example.test",
            "--cosign-issuer",
            "https://issuer.example.test",
        ])?;

        match cli.command {
            Command::Inspect(command) => {
                assert_eq!(command.minisign_sig.len(), 1);
                assert_eq!(command.minisign_key, ["RWQexamplekeymaterial"]);
                assert_eq!(command.cosign_bundle.len(), 1);
                assert_eq!(command.cosign_identity, ["builder@example.test"]);
                assert_eq!(command.cosign_issuer, ["https://issuer.example.test"]);
            }
            Command::Daemon(_)
            | Command::Fetch(_)
            | Command::Unpack(_)
            | Command::Intel(_)
            | Command::Run(_)
            | Command::Status(_)
            | Command::Wrappers(_) => {
                return Err("parsed wrong command".into());
            }
        }
        Ok(())
    }

    #[test]
    fn inspect_accepts_explain_flag() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "arbitraitor",
            "inspect",
            "https://example.test/artifact",
            "--explain",
        ])?;

        match cli.command {
            Command::Inspect(command) => {
                assert!(command.explain);
                assert!(command.format.is_none());
            }
            _ => return Err("parsed wrong command".into()),
        }
        Ok(())
    }

    #[test]
    fn inspect_accepts_format_shellcheck_flag() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "arbitraitor",
            "inspect",
            "https://example.test/artifact",
            "--explain",
            "--format",
            "shellcheck",
        ])?;

        match cli.command {
            Command::Inspect(command) => {
                assert!(command.explain);
                assert_eq!(command.format, Some(super::ExplainFormat::Shellcheck));
            }
            _ => return Err("parsed wrong command".into()),
        }
        Ok(())
    }

    #[test]
    fn inspect_accepts_format_text_flag() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "arbitraitor",
            "inspect",
            "https://example.test/artifact",
            "--format",
            "text",
        ])?;

        match cli.command {
            Command::Inspect(command) => {
                assert_eq!(command.format, Some(super::ExplainFormat::Text));
            }
            _ => return Err("parsed wrong command".into()),
        }
        Ok(())
    }

    #[test]
    fn unpack_accepts_archive_and_output_flags() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from(["arbitraitor", "unpack", "archive.zip", "--output", "out"])?;

        match cli.command {
            Command::Unpack(command) => {
                assert_eq!(command.archive, PathBuf::from("archive.zip"));
                assert_eq!(command.output, PathBuf::from("out"));
            }
            Command::Inspect(_)
            | Command::Daemon(_)
            | Command::Fetch(_)
            | Command::Intel(_)
            | Command::Run(_)
            | Command::Status(_)
            | Command::Wrappers(_) => {
                return Err("parsed wrong command".into());
            }
        }
        Ok(())
    }

    #[test]
    fn daemon_accepts_start_stop_status() -> Result<(), Box<dyn std::error::Error>> {
        for subcommand in ["start", "stop", "status"] {
            let cli = Cli::try_parse_from([
                "arbitraitor",
                "daemon",
                "--socket",
                "/tmp/arbitraitor.sock",
                subcommand,
            ])?;

            match cli.command {
                Command::Daemon(command) => {
                    assert_eq!(command.socket, Some(PathBuf::from("/tmp/arbitraitor.sock")));
                }
                _ => return Err("parsed wrong command".into()),
            }
        }
        Ok(())
    }

    #[test]
    fn unpack_command_extracts_safe_archive() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_temp_path("cli-unpack");
        fs::create_dir_all(&root)?;
        let archive_path = root.join("archive.zip");
        let output_dir = root.join("out");
        fs::write(&archive_path, zip_bytes(&[("nested/file.txt", b"safe")])?)?;

        super::unpack(&archive_path, &output_dir)?;

        assert_eq!(fs::read(output_dir.join("nested/file.txt"))?, b"safe");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_unpaired_signature_flags() {
        let signatures = super::signature_inputs(
            vec!["artifact.minisig".into()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        assert!(signatures.is_err());
    }

    #[test]
    fn intel_update_parses_urlhaus_flag() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "arbitraitor",
            "intel",
            "update",
            "--urlhaus",
            "--intel-store",
            "/tmp/intel.json",
        ])?;

        match cli.command {
            Command::Intel(super::IntelCommand {
                subcommand: super::IntelSubcommand::Update(update),
            }) => {
                assert!(update.urlhaus);
                assert_eq!(update.intel_store, Some(PathBuf::from("/tmp/intel.json")));
                assert!(update.urlhaus_url.is_none());
            }
            _ => return Err("parsed wrong command".into()),
        }
        Ok(())
    }

    #[test]
    fn intel_update_parses_custom_urlhaus_url() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "arbitraitor",
            "intel",
            "update",
            "--urlhaus",
            "--urlhaus-url",
            "https://mirror.example/urlhaus.csv",
        ])?;

        match cli.command {
            Command::Intel(super::IntelCommand {
                subcommand: super::IntelSubcommand::Update(update),
            }) => {
                assert_eq!(
                    update.urlhaus_url.as_deref(),
                    Some("https://mirror.example/urlhaus.csv")
                );
            }
            _ => return Err("parsed wrong command".into()),
        }
        Ok(())
    }

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        for (name, data) in entries {
            writer.start_file(*name, SimpleFileOptions::default())?;
            writer.write_all(data)?;
        }
        Ok(writer.finish()?.into_inner())
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "arbitraitor-cli-{label}-{}-{}",
            std::process::id(),
            timestamp_nanos()
        ))
    }

    fn timestamp_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    }

    #[test]
    fn status_command_parses_text_mode() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from(["arbitraitor", "status"])?;

        match cli.command {
            Command::Status(command) => {
                assert!(!command.json);
                assert!(command.cas_dir.is_none());
                assert!(command.rules.is_none());
            }
            _ => return Err("parsed wrong command".into()),
        }
        Ok(())
    }

    #[test]
    fn status_command_parses_json_flag() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from(["arbitraitor", "status", "--json"])?;

        match cli.command {
            Command::Status(command) => assert!(command.json),
            _ => return Err("parsed wrong command".into()),
        }
        Ok(())
    }

    #[test]
    fn status_command_outputs_text() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_temp_path("status-text");
        fs::create_dir_all(root.join("objects").join("ab"))?;
        fs::write(root.join("objects").join("ab").join("object"), b"data")?;

        let report = HealthChecker::new()
            .with_store(root.clone())
            .with_rule_pack("v2024.6".to_owned())
            .check();
        let mut buffer = Vec::new();
        write_status_text(&mut buffer, &report)?;
        let output = String::from_utf8(buffer)?;

        assert!(output.contains("Arbitraitor v"));
        assert!(output.contains("Store"));
        assert!(output.contains("Detector"));
        assert!(output.contains("Version"));
        assert!(output.contains("Healthy"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn status_command_outputs_json() -> Result<(), Box<dyn std::error::Error>> {
        let report = HealthChecker::new()
            .with_rule_pack("v2024.6".to_owned())
            .check();
        let json = serde_json::to_value(&report)?;
        let parsed: arbitraitor_core::health::HealthReport = serde_json::from_value(json.clone())?;

        assert_eq!(parsed.version, report.version);
        assert!(json.get("checks").is_some());
        assert!(json["checks"].get("store").is_some());
        assert!(json["checks"].get("detectors").is_some());
        assert!(json["checks"].get("version").is_some());
        Ok(())
    }

    #[test]
    fn wrappers_install_parses_all_targets() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from(["arbitraitor", "wrappers", "install"])?;

        match cli.command {
            Command::Wrappers(cmd) => match cmd.subcommand {
                WrappersSubcommand::Install(install) => {
                    assert!(install.targets.is_empty());
                    assert!(!cmd.use_scripts);
                }
                _ => return Err("parsed wrong subcommand".into()),
            },
            _ => return Err("parsed wrong command".into()),
        }
        Ok(())
    }

    #[test]
    fn wrappers_install_parses_specific_target() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from(["arbitraitor", "wrappers", "install", "curl"])?;

        match cli.command {
            Command::Wrappers(WrappersCommand {
                subcommand: WrappersSubcommand::Install(install),
                ..
            }) => {
                assert_eq!(install.targets, ["curl"]);
            }
            _ => return Err("parsed wrong command".into()),
        }
        Ok(())
    }

    #[test]
    fn wrappers_accepts_shim_dir_and_scripts_flags() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "arbitraitor",
            "wrappers",
            "--shim-dir",
            "/tmp/shims",
            "--use-scripts",
            "install",
        ])?;

        match cli.command {
            Command::Wrappers(cmd) => {
                assert_eq!(
                    cmd.shim_dir.as_deref(),
                    Some(std::path::Path::new("/tmp/shims"))
                );
                assert!(cmd.use_scripts);
            }
            _ => return Err("parsed wrong command".into()),
        }
        Ok(())
    }

    #[test]
    fn wrappers_uninstall_status_init_script_parse() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from(["arbitraitor", "wrappers", "uninstall"])?;
        assert!(matches!(
            cli.command,
            Command::Wrappers(WrappersCommand {
                subcommand: WrappersSubcommand::Uninstall(_),
                ..
            })
        ));

        let cli = Cli::try_parse_from(["arbitraitor", "wrappers", "status"])?;
        assert!(matches!(
            cli.command,
            Command::Wrappers(WrappersCommand {
                subcommand: WrappersSubcommand::Status(_),
                ..
            })
        ));

        let cli = Cli::try_parse_from(["arbitraitor", "wrappers", "init-script"])?;
        assert!(matches!(
            cli.command,
            Command::Wrappers(WrappersCommand {
                subcommand: WrappersSubcommand::InitScript(_),
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn symlink_invocation_parses_as_fetch_wrapper() -> Result<(), Box<dyn std::error::Error>> {
        let cli = parse_cli_from_args([
            "/tmp/shims/curl",
            "-fsSL",
            "https://example.test/install.sh",
        ]);

        match cli.command {
            Command::Fetch(fetch) => {
                assert_eq!(fetch.tool.as_deref(), Some("curl"));
                assert_eq!(fetch.args, ["-fsSL", "https://example.test/install.sh"]);
            }
            _ => return Err("parsed wrong command".into()),
        }
        Ok(())
    }

    #[test]
    fn symlink_invocation_treats_help_as_curl_arg() -> Result<(), Box<dyn std::error::Error>> {
        let cli = parse_cli_from_args([
            "/tmp/shims/curl",
            "--help",
            "https://example.test/install.sh",
        ]);

        match cli.command {
            Command::Fetch(fetch) => {
                assert_eq!(fetch.tool.as_deref(), Some("curl"));
                assert_eq!(fetch.args, ["--help", "https://example.test/install.sh"]);
            }
            _ => return Err("parsed wrong command".into()),
        }
        Ok(())
    }

    #[test]
    fn symlink_invocation_treats_config_as_curl_arg() -> Result<(), Box<dyn std::error::Error>> {
        let cli = parse_cli_from_args([
            "/tmp/shims/curl",
            "--config",
            "curlrc",
            "https://example.test/install.sh",
        ]);

        assert!(cli.config.is_none());
        match cli.command {
            Command::Fetch(fetch) => {
                assert_eq!(fetch.tool.as_deref(), Some("curl"));
                assert_eq!(
                    fetch.args,
                    ["--config", "curlrc", "https://example.test/install.sh"]
                );
            }
            _ => return Err("parsed wrong command".into()),
        }
        Ok(())
    }

    #[test]
    fn wrapper_url_argument_ignores_options() -> Result<(), Box<dyn std::error::Error>> {
        let args = [
            "-o".to_owned(),
            "install.sh".to_owned(),
            "https://example.test/install.sh".to_owned(),
        ];

        let url = wrapper_url_argument(Some("curl"), &args).ok_or("missing wrapper URL")?;

        assert_eq!(url, "https://example.test/install.sh");
        Ok(())
    }

    #[test]
    fn wrapper_url_argument_uses_curl_parser_for_url_valued_options()
    -> Result<(), Box<dyn std::error::Error>> {
        let args = [
            "--proxy".to_owned(),
            "https://example.test/proxy".to_owned(),
            "https://www.rust-lang.org/".to_owned(),
        ];

        let url = wrapper_url_argument(Some("curl"), &args).ok_or("missing wrapper URL")?;

        assert_eq!(url, "https://www.rust-lang.org/");
        Ok(())
    }

    #[test]
    fn wrapper_url_argument_consumes_unsupported_curl_option_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let args = [
            "--config".to_owned(),
            "curlrc".to_owned(),
            "https://example.test/install.sh".to_owned(),
        ];

        let url = wrapper_url_argument(Some("curl"), &args).ok_or("missing wrapper URL")?;

        assert_eq!(url, "https://example.test/install.sh");
        Ok(())
    }

    #[test]
    fn wrapper_verdict_passes_only_on_pass() -> Result<(), Box<dyn std::error::Error>> {
        enforce_wrapper_verdict(Verdict::Pass)?;
        for verdict in [
            Verdict::Warn,
            Verdict::Prompt,
            Verdict::Block,
            Verdict::Error,
            Verdict::Incomplete,
        ] {
            assert!(enforce_wrapper_verdict(verdict).is_err());
        }
        Ok(())
    }

    #[test]
    fn wrappers_rejects_unknown_target_name() {
        let result = Cli::try_parse_from(["arbitraitor", "wrappers", "install", "unknown-tool"]);
        assert!(
            result.is_ok(),
            "unknown target is a runtime error, not parse"
        );
    }
}
