//! Arbitraitor CLI entry point.

#![forbid(unsafe_code)]

mod approval;
mod commands;
mod pm;
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
use arbitraitor_fetch::{
    FetchPolicy, FetchRequest, FetchSource, FetchUrl, Fetcher, FileFetcher, HttpFetcher, VecSink,
};
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
use arbitraitor_wrapper::init as shell_init;
use arbitraitor_wrapper::shim::{
    ShimConfig, ShimError, WrapperTarget, check_shims, generate_shell_init, install_shims,
    uninstall_shims,
};
use arbitraitor_wrapper::{parse_curl_args, remote_name_from_url, wget::translate_wget_args};
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

    /// Allow running as root (diagnostic mode only, ADR-0009).
    ///
    /// Bypasses the no-root guard for the `doctor` command and integration
    /// test harnesses. Prints a warning to stderr. Never use for fetch,
    /// inspect, run, or any path that touches untrusted content.
    #[arg(long, global = true)]
    allow_root: bool,

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
    Mcp,
    Scan(commands::ScanCommand),
    Explain(commands::ExplainCommand),
    Store(commands::StoreCommand),
    Policy(commands::PolicyCommand),
    Doctor(commands::DoctorCommand),
    Rules(commands::RulesCommand),
    Update(commands::UpdateCommand),
    Plugin(commands::PluginCommand),
    Hook(commands::HookCommand),
    Shim(commands::ShimCommand),
    Graph(commands::GraphCommand),
    Approve(commands::ApproveCommand),
    Execute(commands::ExecuteCommand),
    Pm(pm::PmCommand),
    /// Hidden alias of `wrappers init` for discoverability.
    #[command(hide = true)]
    Env(EnvCommand),
    Version,
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
    /// Print or install a shell init snippet for PATH configuration.
    Init(InitCommand),
    #[command(hide = true)]
    /// Legacy alias for `init` (prints a generic POSIX snippet).
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
#[allow(clippy::struct_excessive_bools)]
struct InitCommand {
    /// Target shell (auto-detected from $SHELL if omitted).
    shell: Option<String>,
    /// Write to shell rcfile (instead of printing to stdout).
    #[arg(long)]
    install: bool,
    /// Remove previously installed lines from rcfile.
    #[arg(long)]
    uninstall: bool,
    /// Print detected shell and target rcfile, then exit.
    #[arg(long)]
    detect_shell: bool,
    /// Show what would change without writing to rcfile (use with --install).
    #[arg(long, requires = "install")]
    dry_run: bool,
    /// Skip backup file creation (default: backup is created).
    #[arg(long, requires = "install")]
    no_backup: bool,
}

/// Hidden `env` alias of `wrappers init`.
#[derive(Args)]
#[allow(clippy::struct_excessive_bools)]
struct EnvCommand {
    /// Target shell (auto-detected from $SHELL if omitted).
    shell: Option<String>,
    /// Write to shell rcfile (instead of printing to stdout).
    #[arg(long)]
    install: bool,
    /// Remove previously installed lines from rcfile.
    #[arg(long)]
    uninstall: bool,
    /// Print detected shell and target rcfile, then exit.
    #[arg(long)]
    detect_shell: bool,
    /// Show what would change without writing to rcfile (use with --install).
    #[arg(long, requires = "install")]
    dry_run: bool,
    /// Skip backup file creation (default: backup is created).
    #[arg(long, requires = "install")]
    no_backup: bool,
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

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() {
    if let Err(error) = run_main().await {
        let _ = writeln!(std::io::stderr().lock(), "{error:?}");
        std::process::exit(33);
    }
}

#[allow(clippy::too_many_lines)]
async fn run_main() -> Result<()> {
    let cli = parse_cli_from_invocation();

    let is_diagnostic = matches!(
        cli.command,
        Command::Doctor(_) | Command::Version | Command::Status(_)
    );
    if is_diagnostic {
        arbitraitor_core::privilege::refuse_root_unless(cli.allow_root);
    } else {
        arbitraitor_core::privilege::refuse_root();
    }

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
            .await
            .map(|outcome| {
                tracing::info!(
                    sha256 = %outcome.sha256,
                    verdict = ?outcome.verdict,
                    "inspection complete"
                );
            })?;
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
        Command::Mcp => {
            arbitraitor_mcp::run_stdio_server().into_diagnostic()?;
        }
        Command::Scan(command) => {
            commands::scan(&command, &config)?;
        }
        Command::Explain(command) => {
            commands::explain(&command)?;
        }
        Command::Store(command) => {
            commands::store(&command, &config)?;
        }
        Command::Policy(command) => {
            commands::policy(&command)?;
        }
        Command::Doctor(command) => {
            commands::doctor(&command, &config)?;
        }
        Command::Rules(command) => {
            commands::rules(&command)?;
        }
        Command::Update(command) => {
            commands::update(&command)?;
        }
        Command::Plugin(command) => {
            commands::plugin(&command)?;
        }
        Command::Hook(command) => {
            commands::hook(&command)?;
        }
        Command::Shim(command) => {
            commands::shim(&command)?;
        }
        Command::Graph(command) => {
            commands::graph(&command)?;
        }
        Command::Approve(command) => {
            commands::approve(&command, &config)?;
        }
        Command::Execute(command) => {
            commands::execute(&command, &config)?;
        }
        Command::Pm(command) => {
            pm::run(&command)?;
        }
        Command::Env(env_cmd) => {
            let shim_dir = default_shim_dir().ok_or_else(|| {
                miette::miette!("could not determine home directory for shim path")
            })?;
            let init_cmd = InitCommand {
                shell: env_cmd.shell,
                install: env_cmd.install,
                uninstall: env_cmd.uninstall,
                detect_shell: env_cmd.detect_shell,
                dry_run: env_cmd.dry_run,
                no_backup: env_cmd.no_backup,
            };
            handle_init(&init_cmd, &shim_dir)?;
        }
        Command::Version => {
            commands::version()?;
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

    let (output_path, remote_name) =
        wrapper_output_destination(command.tool.as_deref(), &command.args);

    if matches!(target, Some(WrapperTarget::Curl)) {
        let parsed = parse_curl_args(&command.args).into_diagnostic()?;
        if !parsed.unsupported_options.is_empty() {
            miette::bail!(
                "unsupported curl wrapper option: {}",
                parsed.unsupported_options.join(", ")
            );
        }
    }

    let outcome = inspect(
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

    if outcome.verdict != Verdict::Pass {
        miette::bail!(
            "wrapper rejected artifact with verdict {:?}",
            outcome.verdict
        );
    }

    let recomputed = Sha256Digest::new(Sha256::digest(&outcome.bytes).into());
    if recomputed != outcome.sha256 {
        miette::bail!(
            "pre-release digest mismatch: stored={}, recomputed={}",
            outcome.sha256,
            recomputed
        );
    }

    emit_wrapper_output(&outcome.bytes, output_path.as_deref(), remote_name, url)?;
    Ok(())
}

fn emit_wrapper_output(
    bytes: &[u8],
    output_path: Option<&str>,
    remote_name: bool,
    url: &str,
) -> Result<()> {
    match output_path {
        Some(path) => {
            std::fs::write(path, bytes).into_diagnostic()?;
        }
        None if remote_name => {
            let filename = remote_name_from_url(url).into_diagnostic()?;
            std::fs::write(&filename, bytes).into_diagnostic()?;
        }
        None => {
            std::io::stdout().write_all(bytes).into_diagnostic()?;
        }
    }
    Ok(())
}

fn wrapper_fetch_target(tool: Option<&str>) -> Result<Option<WrapperTarget>> {
    tool.map(|name| {
        WrapperTarget::from_binary_name(name)
            .ok_or_else(|| miette::miette!("unsupported wrapper target: {name}"))
    })
    .transpose()
}

fn wrapper_output_destination(tool: Option<&str>, args: &[String]) -> (Option<String>, bool) {
    match tool.and_then(WrapperTarget::from_binary_name) {
        Some(WrapperTarget::Curl) => match parse_curl_args(args) {
            Ok(parsed) => (parsed.output, parsed.remote_name),
            Err(_) => (None, false),
        },
        Some(WrapperTarget::Wget) => match translate_wget_args(args) {
            Ok(parsed) => (
                parsed.output_path.map(|p| p.to_string_lossy().into_owned()),
                false,
            ),
            Err(_) => (None, false),
        },
        None => (None, false),
    }
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
            writeln!(stdout).into_diagnostic()?;
            writeln!(stdout, "To activate, add the shim directory to your PATH:")
                .into_diagnostic()?;
            writeln!(
                stdout,
                "  eval \"$(arbitraitor wrappers init)\"    # print mode"
            )
            .into_diagnostic()?;
            writeln!(
                stdout,
                "  arbitraitor wrappers init --install      # auto-install to rcfile"
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
        WrappersSubcommand::Init(init_cmd) => {
            handle_init(&init_cmd, &shim_dir)?;
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

fn handle_init(cmd: &InitCommand, shim_dir: &Path) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    if cmd.detect_shell {
        match shell_init::detect_shell() {
            Some(detected) => {
                let rc_str = shell_init::target_rcfile(detected.shell)
                    .map_or_else(|| "<none>".to_owned(), |p| p.display().to_string());
                writeln!(
                    stdout,
                    "{} (detected via {})",
                    detected.shell.as_str(),
                    match detected.source {
                        shell_init::DetectionSource::EnvShell => "$SHELL",
                        shell_init::DetectionSource::ParentProcess => "parent process",
                    }
                )
                .into_diagnostic()?;
                writeln!(stdout, "rcfile: {rc_str}").into_diagnostic()?;
                return Ok(());
            }
            None => {
                miette::bail!(
                    "could not detect shell; specify one explicitly: {}",
                    supported_shells_list()
                );
            }
        }
    }

    let shell = match &cmd.shell {
        Some(name) => shell_init::Shell::from_name(name).ok_or_else(|| {
            miette::miette!(
                "unknown shell '{name}'; supported: {}",
                supported_shells_list()
            )
        })?,
        None => match shell_init::detect_shell() {
            Some(detected) => detected.shell,
            None => miette::bail!(
                "could not detect shell; specify one explicitly: {}",
                supported_shells_list()
            ),
        },
    };

    if cmd.uninstall {
        let rcfile =
            shell_init::uninstall_from_rcfile(shell).map_err(|e| miette::miette!("{e}"))?;
        writeln!(stdout, "removed init block from {}", rcfile.display()).into_diagnostic()?;
        return Ok(());
    }

    if cmd.install {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| miette::miette!("HOME not set"))?;
        let rcfile_target = shell_init::target_rcfile(shell)
            .ok_or_else(|| miette::miette!("no rcfile known for shell '{}'", shell.as_str()))?;
        if cmd.dry_run {
            let snippet =
                shell_init::render_snippet(shell, shim_dir).map_err(|e| miette::miette!("{e}"))?;
            let existing = std::fs::read_to_string(&rcfile_target).unwrap_or_default();
            let updated = if existing.is_empty() {
                format!("[new file] {snippet}")
            } else {
                snippet
            };
            writeln!(
                stdout,
                "Dry-run: would write to {}\n{updated}",
                rcfile_target.display()
            )
            .into_diagnostic()?;
            return Ok(());
        }
        let options = shell_init::InstallOptions {
            dry_run: false,
            backup: !cmd.no_backup,
        };
        let rcfile = shell_init::install_to_rcfile_in(shell, shim_dir, &home, &options)
            .map_err(|e| miette::miette!("{e}"))?;
        if cmd.no_backup {
            writeln!(stdout, "installed init snippet to {}", rcfile.display()).into_diagnostic()?;
        } else {
            let backup = format!("{}.arbitraitor.bak", rcfile.display());
            writeln!(
                stdout,
                "installed init snippet to {} (backup: {backup})",
                rcfile.display()
            )
            .into_diagnostic()?;
        }
        return Ok(());
    }

    let snippet =
        shell_init::render_snippet(shell, shim_dir).map_err(|e| miette::miette!("{e}"))?;
    stdout.write_all(snippet.as_bytes()).into_diagnostic()?;
    Ok(())
}

fn supported_shells_list() -> String {
    shell_init::Shell::ALL
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(", ")
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
struct InspectOutcome {
    verdict: Verdict,
    bytes: Vec<u8>,
    sha256: Sha256Digest,
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
) -> Result<InspectOutcome> {
    let fetch_policy = FetchPolicy {
        total_timeout: Duration::from_secs(config.fetch.total_timeout_secs),
        max_compressed_size: config.fetch.max_bytes,
        max_uncompressed_size: config.fetch.max_bytes,
        max_redirects: usize::try_from(config.fetch.max_redirects).into_diagnostic()?,
        require_digest: config.integrity.require_digest,
        ..FetchPolicy::default()
    };
    let source = parse_fetch_source(url)?;
    let request = FetchRequest {
        source,
        policy: fetch_policy,
        expected_sha256,
    };
    let mut fetch_sink = VecSink::new();
    let fetch_receipt = match &request.source {
        FetchSource::File(_) => FileFetcher::new().fetch(request, &mut fetch_sink).await,
        FetchSource::Url(_) => HttpFetcher::new().fetch(request, &mut fetch_sink).await,
        FetchSource::Stdin => {
            miette::bail!(
                "stdin source is not supported by inspect; use 'arbitraitor scan --stdin'"
            );
        }
    }
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

    Ok(InspectOutcome {
        verdict: result.verdict,
        bytes,
        sha256: artifact_sha256,
    })
}

fn parse_fetch_source(input: &str) -> Result<FetchSource> {
    if input == "-" || input == "stdin://" {
        return Ok(FetchSource::Stdin);
    }
    if input.starts_with("http://") || input.starts_with("https://") {
        return Ok(FetchSource::Url(
            FetchUrl::parse(input).map_err(|e| miette::miette!("invalid URL: {e}"))?,
        ));
    }
    if input.starts_with("file://") {
        let parsed =
            FetchUrl::parse(input).map_err(|e| miette::miette!("invalid file:// URL: {e}"))?;
        let path = parsed
            .as_url()
            .to_file_path()
            .map_err(|()| miette::miette!("file:// URL does not resolve to a local path"))?;
        return Ok(FetchSource::File(path));
    }
    if let Some(colon) = input.find(':') {
        let scheme = &input[..colon];
        if !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        {
            miette::bail!(
                "unsupported URI scheme '{scheme}'; only http, https, and file are accepted"
            );
        }
    }
    Ok(FetchSource::File(PathBuf::from(input)))
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
        evidence: None,
        remediation: None,
        references: Vec::new(),
        taxonomies: Vec::new(),
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
#[path = "tests.rs"]
mod tests;
