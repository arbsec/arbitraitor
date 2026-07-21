//! Arbitraitor CLI entry point.

#![forbid(unsafe_code)]

mod approval;
mod commands;
mod pipeline;
mod pm;
mod run;

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use arbitraitor_archive::{
    ArchiveLimits, detect_archive_hazards, detect_tar_parser_differentials, extract_to_output_dir,
};
use arbitraitor_artifact::classify;
use arbitraitor_core::config::Config;
use arbitraitor_core::health::HealthChecker;
use arbitraitor_daemon::{Daemon, DaemonRequest, default_socket_path, request_once};
use arbitraitor_fetch::{FetchPolicy, HttpFetcher};
use arbitraitor_intel::{
    IngestionReport, IntelStore, OssfMaliciousPackagesAdapter, UrlhausAdapter, ingest_feed,
};
use arbitraitor_model::finding::Finding;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::origin::CallerOrigin;
use arbitraitor_model::verdict::Verdict;
use arbitraitor_provenance::SignatureVerification;
use arbitraitor_wrapper::init as shell_init;
use arbitraitor_wrapper::shim::{
    ShimConfig, ShimError, WrapperTarget, check_shims, generate_shell_init, install_shims,
    uninstall_shims,
};
use arbitraitor_wrapper::{parse_curl_args, remote_name_from_url, wget::translate_wget_args};
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
    /// Fetch an artifact with provenance verification (spec §28.2).
    Fetch(Box<FetchCommand>),
    /// Wrap an existing tool invocation through Arbitraitor (spec §28.1).
    Wrap(WrapCommand),
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
    /// Report user feedback on findings (spec §21.7).
    Report(commands::ReportCommand),
    /// Record a scoped allow exception for an artifact digest (spec §21.7).
    Allow(commands::AllowCommand),
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

/// Fetch an artifact from a URL with provenance verification (spec §28.2).
///
/// When invoked via a wrapper symlink (`curl`/`wget`), `--tool` is set
/// automatically and `args` carries the passthrough arguments. In
/// first-class mode the URL is the first positional argument and the
/// spec-defined flags are parsed normally.
#[derive(Args)]
#[allow(clippy::struct_excessive_bools)] // spec §28.2 mandates these boolean flags
struct FetchCommand {
    /// Wrapper tool name (set automatically by symlink invocation).
    #[arg(long, value_name = "curl|wget")]
    tool: Option<String>,
    /// URL to fetch, or passthrough args when invoked via wrapper symlink.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
    /// Write the fetched artifact to this path instead of stdout.
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Expected SHA-256 digest for provenance verification.
    #[arg(long, value_name = "HEX")]
    sha256: Option<Sha256Digest>,
    /// minisign signature file path (repeatable; requires key via config).
    #[arg(long, value_name = "PATH")]
    signature: Vec<PathBuf>,
    /// cosign bundle file path (repeatable).
    #[arg(long, value_name = "PATH")]
    cosign_bundle: Vec<PathBuf>,
    /// cosign identity (repeatable).
    #[arg(long, value_name = "IDENTITY")]
    identity: Vec<String>,
    /// cosign certificate issuer (repeatable).
    #[arg(long, value_name = "ISSUER")]
    issuer: Vec<String>,
    /// Expected artifact type (e.g., `shell`, `elf`, `archive`).
    #[arg(long, value_name = "TYPE")]
    expected_type: Option<String>,
    /// Expected content type (e.g., `application/x-sh`).
    #[arg(long, value_name = "TYPE")]
    expected_content_type: Option<String>,
    /// Maximum bytes to fetch.
    #[arg(long, value_name = "BYTES")]
    max_bytes: Option<u64>,
    /// HTTP header to send (repeatable, format: `Key: Value`).
    #[arg(long, value_name = "HEADER")]
    header: Vec<String>,
    /// Policy file path.
    #[arg(long, value_name = "PATH")]
    policy: Option<PathBuf>,
    /// Recursively fetch and inspect referenced payloads.
    #[arg(long)]
    recursive: bool,
    /// Sandbox execution after fetch.
    #[arg(long)]
    sandbox: bool,
    /// Skip interactive approval prompts.
    #[arg(long)]
    non_interactive: bool,
    /// Output results as JSON.
    #[arg(long)]
    json: bool,
    /// Output results as SARIF.
    #[arg(long)]
    sarif: bool,
    /// Write a JSON receipt to this path.
    #[arg(long, value_name = "PATH")]
    receipt: Option<PathBuf>,
    /// Skip cache and force a fresh fetch.
    #[arg(long)]
    no_cache: bool,
}

/// Wrap an existing tool invocation and submit useful artifacts to Arbitraitor.
#[derive(Args)]
struct WrapCommand {
    /// Tool to wrap, such as `curl`, `wget`, `bash`, or `brew`.
    tool: String,
    /// Original tool arguments after `--`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

/// Output format for the `--explain` report.
#[derive(Clone, Copy, Debug, clap::ValueEnum, Eq, PartialEq)]
pub(crate) enum ExplainFormat {
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
    /// Ingest `OpenSSF` malicious-packages `MAL-` IDs from an OSV querybatch response.
    #[arg(long)]
    ossf_malicious_packages: bool,
    /// Override the `OpenSSF` malicious-packages OSV querybatch URL or signed mirror.
    #[arg(long, value_name = "URL")]
    ossf_malicious_packages_url: Option<String>,
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

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() {
    if let Err(error) = run_main().await {
        let _ = writeln!(std::io::stderr().lock(), "{error:?}");
        // Spec §29 code 1: General operational error. Distinct from
        // `RequiredDetectorUnavailable` (33, previously used here) which is
        // reserved for cases where a detector marked `required = true` was
        // unavailable or stale at analysis time.
        std::process::exit(1);
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
            let signatures = pipeline::signature_inputs(
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
            pipeline::inspect(
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
        Command::Wrap(command) => {
            wrap(command, &config).await?;
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
        Command::Report(command) => {
            commands::report(&command)?;
        }
        Command::Allow(command) => {
            commands::allow(&command)?;
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
    let (url, output_path, remote_name) = if command.tool.is_some() {
        let target = wrapper_fetch_target(command.tool.as_deref())?;
        let url =
            wrapper_url_argument(command.tool.as_deref(), &command.args).ok_or_else(|| {
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
        (url.to_string(), output_path, remote_name)
    } else {
        let url = command
            .args
            .first()
            .ok_or_else(|| miette::miette!("fetch requires a URL argument"))?;
        let output_path = command
            .output
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned());
        (url.clone(), output_path, false)
    };

    let signatures = pipeline::signature_inputs(
        command.signature.clone(),
        Vec::new(),
        command.cosign_bundle.clone(),
        command.identity.clone(),
        command.issuer.clone(),
    )?;

    let outcome = pipeline::inspect(
        &url,
        command.receipt.as_deref(),
        None,
        command.sha256.clone(),
        None,
        signatures,
        config,
        None,
    )
    .await?;

    if outcome.verdict != Verdict::Pass {
        miette::bail!("fetch rejected artifact with verdict {:?}", outcome.verdict);
    }

    let recomputed = Sha256Digest::new(Sha256::digest(&outcome.bytes).into());
    if recomputed != outcome.sha256 {
        miette::bail!(
            "pre-release digest mismatch: stored={}, recomputed={}",
            outcome.sha256,
            recomputed
        );
    }

    emit_wrapper_output(&outcome.bytes, output_path.as_deref(), remote_name, &url)?;
    Ok(())
}

async fn wrap(command: WrapCommand, config: &Config) -> Result<()> {
    match WrapperTarget::from_binary_name(&command.tool) {
        Some(WrapperTarget::Curl | WrapperTarget::Wget) => {
            let fetch = FetchCommand {
                tool: Some(command.tool),
                args: command.args,
                output: None,
                sha256: None,
                signature: Vec::new(),
                cosign_bundle: Vec::new(),
                identity: Vec::new(),
                issuer: Vec::new(),
                expected_type: None,
                expected_content_type: None,
                max_bytes: None,
                header: Vec::new(),
                policy: None,
                recursive: false,
                sandbox: false,
                non_interactive: false,
                json: false,
                sarif: false,
                receipt: None,
                no_cache: false,
            };
            wrapper_fetch(&fetch, config).await?;
        }
        None if command.tool == "bash" => {
            wrap_bash(&command, config).await?;
        }
        None => {
            writeln!(
                std::io::stderr().lock(),
                "warning: wrap support for `{}` is not implemented; no content was released",
                command.tool
            )
            .into_diagnostic()?;
        }
    }
    Ok(())
}

async fn wrap_bash(command: &WrapCommand, config: &Config) -> Result<()> {
    let Some(script) = bash_script_argument(&command.args) else {
        writeln!(
            std::io::stderr().lock(),
            "warning: wrap bash could not identify a script path; no content was released"
        )
        .into_diagnostic()?;
        return Ok(());
    };
    let outcome = pipeline::inspect(
        script,
        None,
        None,
        None,
        None,
        pipeline::signature_inputs(Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new())?,
        config,
        None,
    )
    .await?;
    if outcome.verdict != Verdict::Pass {
        miette::bail!(
            "wrap rejected bash script with verdict {:?}",
            outcome.verdict
        );
    }
    writeln!(
        std::io::stderr().lock(),
        "warning: wrap bash inspected {script}; execution is not implemented and no content was released"
    )
    .into_diagnostic()?;
    Ok(())
}

fn bash_script_argument(args: &[String]) -> Option<&str> {
    args.iter()
        .map(String::as_str)
        .find(|arg| !arg.starts_with('-'))
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
            let response = request_once(
                socket,
                &DaemonRequest::Shutdown {
                    caller_origin: CallerOrigin::HumanTty,
                    capability_token: None,
                },
            )
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
                    caller_origin: CallerOrigin::HumanTty,
                    capability_token: None,
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
    let mut hazards = detect_archive_hazards(&entries, &limits);
    if artifact_type == arbitraitor_artifact::ArtifactType::TarArchive {
        hazards.extend(detect_tar_parser_differentials(&bytes, &entries, &limits));
    }
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
    if !update.urlhaus && !update.ossf_malicious_packages {
        miette::bail!(
            "no feed selected; pass --urlhaus or --ossf-malicious-packages to ingest a feed"
        );
    }
    let store_path = update
        .intel_store
        .unwrap_or_else(|| PathBuf::from(".arbitraitor/intel.json"));
    let mut store = IntelStore::open(&store_path).into_diagnostic()?;
    let fetcher = HttpFetcher::new();
    let policy = FetchPolicy::default();
    let mut writer = std::io::stderr().lock();

    if update.urlhaus {
        let adapter = match update.urlhaus_url {
            Some(url) => UrlhausAdapter::with_url(url),
            None => UrlhausAdapter::new(),
        };
        let report = ingest_feed(&adapter, &fetcher, &mut store, &policy)
            .await
            .into_diagnostic()?;
        write_intel_report(&mut writer, &report)?;
    }

    if update.ossf_malicious_packages {
        let adapter = match update.ossf_malicious_packages_url {
            Some(url) => OssfMaliciousPackagesAdapter::with_url(url),
            None => OssfMaliciousPackagesAdapter::new(),
        };
        let report = ingest_feed(&adapter, &fetcher, &mut store, &policy)
            .await
            .into_diagnostic()?;
        write_intel_report(&mut writer, &report)?;
    }

    Ok(())
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
        .unwrap_or_else(pipeline::default_cas_dir);

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

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
