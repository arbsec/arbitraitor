//! Mediated PowerShell script execution.
//!
//! [`PowerShellExecution`] is the PowerShell analogue of
//! [`crate::ScriptExecution`]: it wraps a fully built [`ExecutionContext`] with
//! a discovered PowerShell interpreter and PowerShell-specific hardening flags.
//! The script bytes are streamed to the interpreter through its standard input
//! via `pwsh -Command -`, so no temporary `.ps1` file is ever materialized on
//! disk. This closes the same TOCTOU and stale-permissions attack surface that
//! [`crate::ScriptExecution`] closes for bash.
//!
//! # Hardening flags
//!
//! Every invocation supplies:
//!
//! - `-NoProfile` — do not load the user or system PowerShell profile.
//! - `-NonInteractive` — never prompt; fail closed on any interactive prompt.
//! - `-NoLogo` — suppress the startup banner (clean stdout).
//! - `-ExecutionPolicy <policy>` — defaults to `Restricted`; see
//!   [`PowerShellPolicy`].
//! - `-InputFormat Text` — read stdin as plain text, never serialized objects.
//! - `-OutputFormat Text` — emit plain text, never serialized objects.
//! - `-Command -` — read the script from stdin. The `-EncodedCommand` and
//!   `-File` parameters are never used: `-EncodedCommand` defeats static
//!   inspection and `-File` would require writing the script to disk.
//!
//! The mediated execution profile (allowlisted environment, controlled `PATH`,
//! temporary `HOME` and working directories, privilege-elevation rejection,
//! network denied by default, `no_new_privs`, `close_range`, fenced resource
//! limits, and output capping) is identical to [`crate::ScriptExecution`].
//! See ADR 0008 (`docs/adr/0008-execution-context-security-profile.md`).

// The public types deliberately carry the "PowerShell" prefix for clarity at
// call sites that also handle bash and native execution; the module-name
// repetition is intentional and matches the convention in `arbitraitor-intel`.
#![allow(clippy::module_name_repetitions)]
// allow: SIZE_OK — implementation-only LOC is marginally over 250 because this
// module hosts three tightly-coupled types (PowerShellPolicy, PowerShellError,
// PowerShellExecution) plus the binary discovery helpers, all of which exist
// solely to serve PowerShellExecution. Splitting would create artificial
// fragmentation inconsistent with the sibling `script.rs` pattern.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use arbitraitor_model::ids::{ArtifactId, OperationId, Sha256Digest};
use arbitraitor_model::operation::{
    CapabilityGrant, GrantedCapabilities, OperationPlan, OperationState, OperationType,
};
use arbitraitor_model::verdict::AssuranceLevel;
use thiserror::Error;
use tracing::debug;

use crate::script::ExecutionResult;
use crate::{ExecError, ExecutionContext, ExecutionContextBuilder, ResourceLimits};

#[cfg(target_os = "linux")]
const UNSHARE_PATH: &str = "/usr/bin/unshare";

#[cfg(target_os = "linux")]
const UNSHARE_NETWORK_ARGS: [&str; 4] = ["--user", "--map-current-user", "--net", "--"];

/// PowerShell-specific execution policy controls passed via
/// `-ExecutionPolicy`.
///
/// The default is [`PowerShellPolicy::Restricted`]. [`PowerShellPolicy::Bypass`]
/// is accepted only for sandboxed testing and must not be used for production
/// execution of untrusted scripts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PowerShellPolicy {
    /// `-ExecutionPolicy Restricted`. No scripts may run via `-File`; only
    /// commands read from stdin are accepted. This is the default and the only
    /// policy recommended for untrusted content.
    #[default]
    Restricted,
    /// `-ExecutionPolicy AllSigned`. Only publisher-trusted signed scripts may
    /// run via `-File`. Appropriate when the executed pipeline legitimately
    /// invokes signed helper modules.
    AllSigned,
    /// `-ExecutionPolicy Bypass`. Suppresses execution-policy checks entirely.
    /// **Not for production use** — exists for test harnesses that need to
    /// exercise PowerShell under a permissive policy.
    Bypass,
}

impl PowerShellPolicy {
    /// Returns the literal policy token passed to `-ExecutionPolicy`.
    const fn policy_token(self) -> &'static str {
        match self {
            Self::Restricted => "Restricted",
            Self::AllSigned => "AllSigned",
            Self::Bypass => "Bypass",
        }
    }
}

/// Errors returned while constructing or running a [`PowerShellExecution`].
///
/// The [`PowerShellError::Execution`] variant is a catch-all for failures
/// surfaced by the shared mediated-execution machinery (root detection,
/// privilege-elevation rejection, output overflow, resource-limit application,
/// child reap failures, ...). The structured detail for those lives on
/// [`ExecError`]; PowerShell call sites only need to distinguish "the binary
/// was missing", "spawn or stdin piping failed", and "something else went
/// wrong".
#[derive(Debug, Error)]
pub enum PowerShellError {
    /// Neither `pwsh` nor `powershell` was discovered on `PATH`.
    #[error("PowerShell binary not found at expected path")]
    BinaryNotFound,
    /// A mediated execution-context, resource-limit, or output-cap failure.
    /// The stringified [`ExecError`] message preserves the underlying detail.
    #[error("PowerShell execution failed: {message}")]
    Execution {
        /// Human-readable description of the underlying failure.
        message: String,
    },
    /// The interpreter process could not be spawned.
    #[error("spawn failed: {source}")]
    Spawn {
        /// Source I/O error from `Command::spawn`.
        #[source]
        source: std::io::Error,
    },
    /// Piping the script bytes to the interpreter's standard input failed.
    ///
    /// Mirrors [`ExecError::ScriptIo`]: when `write_all` or `flush` fails
    /// because the PowerShell interpreter exited early (syntax error,
    /// `-ExecutionPolicy` rejection, pre-exec sandbox failure), the variant
    /// also carries whatever the child printed to its stderr and the exit
    /// code it died with, captured best-effort after the failed write.
    #[error("script I/O failed during {stage}: {source}{child_detail}")]
    ScriptIo {
        /// Operation stage identifier (e.g. `"write-script-stdin"`).
        stage: &'static str,
        /// Source I/O error.
        #[source]
        source: std::io::Error,
        /// Exit code the child reported before the write failed, when the
        /// child could be reaped. `None` when the child was still running,
        /// was killed by a signal, or could not be waited on.
        child_exit_code: Option<i32>,
        /// Best-effort capture of the child's stderr stream after the failed
        /// write. May be empty when the child produced no stderr, when output
        /// exceeded the cap and the child was killed, or when reaping failed
        /// before any bytes could be drained.
        child_stderr: Vec<u8>,
        /// Pre-rendered human-readable detail derived from
        /// `child_exit_code` / `child_stderr`, built once at construction.
        child_detail: String,
    },
}

impl PowerShellError {
    /// Constructs a [`PowerShellError::ScriptIo`] with the supplied stage,
    /// source, and best-effort child state. Mirrors
    /// [`ExecError::script_io`].
    #[must_use]
    pub fn script_io(
        stage: &'static str,
        source: std::io::Error,
        child_exit_code: Option<i32>,
        child_stderr: Vec<u8>,
    ) -> Self {
        let child_detail = ExecError::script_io_detail(child_exit_code, child_stderr.as_slice());
        Self::ScriptIo {
            stage,
            source,
            child_exit_code,
            child_stderr,
            child_detail,
        }
    }
}

impl From<ExecError> for PowerShellError {
    fn from(error: ExecError) -> Self {
        match error {
            ExecError::Spawn { source } => Self::Spawn { source },
            ExecError::ScriptIo {
                stage,
                source,
                child_exit_code,
                child_stderr,
                child_detail,
            } => Self::ScriptIo {
                stage,
                source,
                child_exit_code,
                child_stderr,
                child_detail,
            },
            other => Self::Execution {
                message: other.to_string(),
            },
        }
    }
}

/// Mediated PowerShell execution wrapping a controlled [`ExecutionContext`].
///
/// Structurally mirrors [`crate::ScriptExecution`]: the discovered interpreter
/// (`pwsh`, or `powershell` on Windows) is spawned inside the mediated
/// environment produced by [`ExecutionContextBuilder`], with PowerShell-specific
/// hardening flags (see the module docs for the full flag table). The script
/// bytes are streamed to the interpreter's standard input; no temporary script
/// file is written to disk.
#[derive(Debug)]
pub struct PowerShellExecution {
    interpreter: PathBuf,
    interpreter_args: Vec<String>,
    environment: ExecutionContext,
    network_isolated: bool,
    sandbox_config: arbitraitor_sandbox::SandboxConfig,
    execution_policy: PowerShellPolicy,
    #[cfg(target_os = "linux")]
    resource_limits: ResourceLimits,
}

impl PowerShellExecution {
    /// Creates a restricted-policy PowerShell executor.
    ///
    /// Discovers `pwsh` on `PATH` (PowerShell 7+, cross-platform); on Windows
    /// it additionally falls back to `powershell` (Windows PowerShell 5.x).
    /// Returns [`PowerShellError::BinaryNotFound`] when neither is present.
    ///
    /// The default [`PowerShellPolicy::Restricted`] flags are applied and the
    /// full mediated [`ExecutionContext`] is built: allowlisted environment
    /// only, controlled `PATH`, temporary `HOME` and working directories,
    /// privilege-elevation rejection, and network denied by default.
    ///
    /// # Errors
    ///
    /// Returns [`PowerShellError::BinaryNotFound`] when no PowerShell binary is
    /// discovered, or [`PowerShellError::Execution`] when the mediated context
    /// cannot be built (e.g. the caller is running as root).
    pub fn new() -> Result<Self, PowerShellError> {
        let interpreter = discover_powershell_binary().ok_or(PowerShellError::BinaryNotFound)?;
        Self::with_interpreter(interpreter, PowerShellPolicy::default())
    }

    /// Builds a fully wired executor for an already-resolved interpreter path
    /// and policy. The mediated [`ExecutionContext`] is constructed once and
    /// stored; the flag vector is derived from `policy`.
    fn with_interpreter(
        interpreter: PathBuf,
        policy: PowerShellPolicy,
    ) -> Result<Self, PowerShellError> {
        let interpreter_args = powershell_args(policy);
        let plan = operation_plan(&interpreter, &interpreter_args);
        // Same capability posture as ScriptExecution: execute only. No network,
        // no file-write outside the working tree, no environment mutation.
        let grants = GrantedCapabilities::new(
            CapabilityGrant(false),
            CapabilityGrant(false),
            CapabilityGrant(true),
            CapabilityGrant(false),
        );
        let environment = ExecutionContextBuilder::new(plan, grants)
            .assurance_level(AssuranceLevel::Mediated)
            .command(interpreter.clone())
            .arguments(interpreter_args.iter().map(String::as_str))
            .build()?;
        Ok(Self {
            interpreter,
            interpreter_args,
            environment,
            network_isolated: true,
            sandbox_config: arbitraitor_sandbox::SandboxConfig::default(),
            execution_policy: policy,
            #[cfg(target_os = "linux")]
            resource_limits: ResourceLimits::default(),
        })
    }

    /// Controls whether the interpreter is launched inside an isolated Linux
    /// network namespace. Enabled by default.
    ///
    /// Disabling is intended only for policy-granted execution paths and tests
    /// that validate the contrast between denied and explicitly allowed network
    /// access.
    #[must_use]
    pub fn with_network_isolated(mut self, isolated: bool) -> Self {
        self.network_isolated = isolated;
        self
    }

    /// Sets the execution policy level. Default: [`PowerShellPolicy::Restricted`].
    ///
    /// The interpreter arguments are recomputed immediately so that
    /// [`Self::interpreter_args`] and the spawned command stay consistent with
    /// the recorded policy.
    #[must_use]
    pub fn with_execution_policy(mut self, policy: PowerShellPolicy) -> Self {
        self.execution_policy = policy;
        self.interpreter_args = powershell_args(policy);
        self
    }

    /// Sets the resource limits applied to the child process.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn with_resource_limits(mut self, limits: ResourceLimits) -> Self {
        self.resource_limits = limits;
        self
    }

    /// Sets the sandbox hardening applied in the child before `exec`.
    ///
    /// The default already enables `no_new_privs`, clears the dumpable flag,
    /// and closes inherited file descriptors. Callers may loosen or tighten
    /// these via this builder, but doing so for untrusted scripts is rarely
    /// appropriate.
    #[must_use]
    pub fn with_sandbox_config(mut self, config: arbitraitor_sandbox::SandboxConfig) -> Self {
        self.sandbox_config = config;
        self
    }

    /// Returns the discovered interpreter executable path.
    #[must_use]
    pub fn interpreter(&self) -> &Path {
        &self.interpreter
    }

    /// Returns the configured interpreter arguments (the PowerShell hardening
    /// flags derived from the current [`PowerShellPolicy`]).
    #[must_use]
    pub fn interpreter_args(&self) -> &[String] {
        &self.interpreter_args
    }

    /// Returns the mediated execution environment prepared for the interpreter.
    #[must_use]
    pub fn environment(&self) -> &ExecutionContext {
        &self.environment
    }

    /// Returns true when this execution will request network namespace
    /// isolation before running the interpreter.
    #[must_use]
    pub fn network_isolated(&self) -> bool {
        self.network_isolated
    }

    /// Returns the configured execution policy.
    #[must_use]
    pub fn execution_policy(&self) -> PowerShellPolicy {
        self.execution_policy
    }

    /// Returns the configured sandbox hardening.
    #[must_use]
    pub fn sandbox_config(&self) -> arbitraitor_sandbox::SandboxConfig {
        self.sandbox_config
    }

    /// Returns the combined stdout/stderr cap that will be enforced.
    fn output_limit(&self) -> u64 {
        #[cfg(target_os = "linux")]
        {
            self.resource_limits
                .output_size_bytes
                .unwrap_or(crate::spawn::DEFAULT_OUTPUT_LIMIT)
        }
        #[cfg(not(target_os = "linux"))]
        {
            crate::spawn::DEFAULT_OUTPUT_LIMIT
        }
    }

    /// Executes the script bytes through the configured PowerShell interpreter.
    ///
    /// The interpreter is invoked with the controlled environment prepared by
    /// the underlying [`ExecutionContext`]: the parent environment is cleared
    /// and replaced with only the allowlisted variables, the working directory
    /// is set to the policy-materialized temporary directory, and the script
    /// bytes are written to the interpreter's standard input before being
    /// closed so the interpreter observes EOF.
    ///
    /// # Errors
    ///
    /// Returns [`PowerShellError::Spawn`] when the interpreter cannot be
    /// spawned, [`PowerShellError::ScriptIo`] when piping the script bytes
    /// fails, or [`PowerShellError::Execution`] when resource-limit application
    /// or output collection fails (including output-cap overflow).
    pub fn execute(&self, script_bytes: &[u8]) -> Result<ExecutionResult, PowerShellError> {
        let mut command = self.build_command();
        debug!(
            interpreter = %self.interpreter.display(),
            network_isolated = self.network_isolated,
            policy = ?self.execution_policy,
            "spawning PowerShell interpreter"
        );
        let mut child = command
            .spawn()
            .map_err(|source| PowerShellError::Spawn { source })?;

        // SIGSTOP the child, apply prlimit while frozen, then SIGCONT. If the
        // limits cannot be applied the child is killed and reaped (see
        // apply_limits_fenced) so it can never run unbounded.
        #[cfg(target_os = "linux")]
        crate::spawn::apply_limits_fenced(&mut child, &self.resource_limits)?;

        // Drop our write end of the stdin pipe as soon as the script bytes are
        // written so the interpreter observes EOF and completes any pending
        // read-driven control flow before we wait for it. The child has been
        // resumed by this point so it can drain the pipe without deadlock.
        if let Some(mut stdin) = child.stdin.take() {
            if let Err(source) = stdin.write_all(script_bytes) {
                drop(stdin);
                let (child_exit_code, _, child_stderr) =
                    crate::spawn::best_effort_capture(&mut child, self.output_limit());
                return Err(PowerShellError::script_io(
                    "write-script-stdin",
                    source,
                    child_exit_code,
                    child_stderr,
                ));
            }
            if let Err(source) = stdin.flush() {
                drop(stdin);
                let (child_exit_code, _, child_stderr) =
                    crate::spawn::best_effort_capture(&mut child, self.output_limit());
                return Err(PowerShellError::script_io(
                    "flush-script-stdin",
                    source,
                    child_exit_code,
                    child_stderr,
                ));
            }
        }

        let (exit_code, stdout, stderr) =
            crate::spawn::read_with_limit(&mut child, self.output_limit())?;

        Ok(ExecutionResult {
            exit_code,
            stdout,
            stderr,
        })
    }

    fn build_command(&self) -> Command {
        let mut command = self.build_program_command();
        // Fail closed on environment: clear the parent environment entirely
        // and re-establish only the mediated, allowlisted variables produced
        // by the ExecutionContext.
        command.env_clear();
        command.envs(self.environment.environment_iter());
        command.current_dir(self.environment.working_dir());
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        // Apply privilege hardening (no_new_privs, dumpable=0, fd closure) in
        // the child before exec. The unsafe pre_exec boundary stays inside the
        // sandbox crate, preserving forbid(unsafe_code) here.
        arbitraitor_sandbox::configure_command(&mut command, self.sandbox_config);
        command
    }

    #[cfg(target_os = "linux")]
    fn build_program_command(&self) -> Command {
        if self.network_isolated {
            // Use util-linux `unshare` rather than an in-process pre_exec hook:
            // CommandExt::pre_exec and libc::unshare both require unsafe code,
            // while this crate forbids unsafe. The absolute helper path avoids
            // PATH lookup; failure to create the namespace prevents the script
            // from running, preserving fail-closed network denial.
            let mut command = Command::new(UNSHARE_PATH);
            command.args(UNSHARE_NETWORK_ARGS);
            command.arg(&self.interpreter);
            command.args(&self.interpreter_args);
            command
        } else {
            let mut command = Command::new(&self.interpreter);
            command.args(&self.interpreter_args);
            command
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn build_program_command(&self) -> Command {
        let mut command = Command::new(&self.interpreter);
        command.args(&self.interpreter_args);
        command
    }
}

/// Builds the canonical PowerShell hardening flag vector for a policy.
///
/// The flags are documented in the module-level docs. The script is always
/// delivered via stdin (`-Command -`); `-File` and `-EncodedCommand` are never
/// emitted.
fn powershell_args(policy: PowerShellPolicy) -> Vec<String> {
    vec![
        "-NoProfile".to_owned(),
        "-NonInteractive".to_owned(),
        "-NoLogo".to_owned(),
        "-ExecutionPolicy".to_owned(),
        policy.policy_token().to_owned(),
        "-InputFormat".to_owned(),
        "Text".to_owned(),
        "-OutputFormat".to_owned(),
        "Text".to_owned(),
        "-Command".to_owned(),
        "-".to_owned(),
    ]
}

/// Builds a placeholder [`OperationPlan`] for context construction.
///
/// Mirrors [`crate::script`]'s private `operation_plan`: the artifact identity
/// is bound at `execute` time by the caller; the plan's `artifact_id` uses a
/// zero digest until operation dispatch records the real one.
fn operation_plan(interpreter: &Path, args: &[String]) -> OperationPlan {
    OperationPlan {
        operation_id: OperationId::new(),
        artifact_id: ArtifactId(Sha256Digest::new([0; 32])),
        operation_type: OperationType::Execute,
        interpreter: Some(interpreter.to_string_lossy().into_owned()),
        arguments: args.to_vec(),
        environment_allowlist: Vec::new(),
        network_allowed: false,
        sandbox_enabled: true,
        expiry: None,
        state: OperationState::Pending,
        plugin_identity: None,
        argv_digest: None,
        policy_digest: None,
    }
}

/// Discovers the PowerShell interpreter binary on `PATH`.
///
/// On non-Windows only `pwsh` (PowerShell 7+) is considered. On Windows the
/// `powershell` (Windows PowerShell 5.x) fallback is also probed. The exec
/// crate is Unix-only today, so the Windows branch is inert but documents the
/// intended fallback for a future Windows port.
fn discover_powershell_binary() -> Option<PathBuf> {
    let pwsh = find_in_path("pwsh");
    if pwsh.is_some() {
        return pwsh;
    }
    #[cfg(target_os = "windows")]
    {
        find_in_path("powershell")
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

/// Searches `PATH` for an executable named `name`, returning the first
/// absolute, executable, regular-file match.
fn find_in_path(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        // Skip relative entries — only absolute directories are considered to
        // avoid depending on the parent process's current working directory.
        if !dir.is_absolute() {
            continue;
        }
        let candidate = dir.join(name);
        let Ok(meta) = std::fs::metadata(&candidate) else {
            continue;
        };
        if meta.is_file() && (meta.permissions().mode() & 0o111 != 0) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::process::Command as StdCommand;

    /// Returns a [`PowerShellExecution`] with resource limits relaxed so the
    /// .NET runtime can start, or `None` when PowerShell is not installed.
    fn pwsh_or_skip() -> Option<PowerShellExecution> {
        let exec = PowerShellExecution::new().ok()?;
        Some(exec.with_resource_limits(ResourceLimits {
            cpu_time_secs: None,
            memory_bytes: None,
            process_count: None,
            fd_count: None,
            output_size_bytes: None,
        }))
    }

    /// Returns true when util-linux `unshare` can create a user+net namespace.
    fn network_namespace_supported() -> bool {
        Path::new(UNSHARE_PATH).exists()
            && StdCommand::new(UNSHARE_PATH)
                .args(UNSHARE_NETWORK_ARGS)
                .arg("/bin/sh")
                .arg("-c")
                .arg("true")
                .status()
                .is_ok_and(|status| status.success())
    }

    #[test]
    fn new_finds_pwsh_or_powershell() {
        // Binary discovery: skip silently when no PowerShell is installed.
        let Some(exec) = PowerShellExecution::new().ok() else {
            return;
        };
        let name = exec
            .interpreter()
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        assert!(
            matches!(name, "pwsh" | "powershell"),
            "unexpected interpreter binary: {name}"
        );
    }

    #[test]
    #[ignore = "requires pwsh and sandbox support unavailable in CI containers"]
    fn execute_restricted_policy() -> Result<(), Box<dyn std::error::Error>> {
        let Some(exec) = pwsh_or_skip() else {
            return Ok(());
        };
        assert_eq!(exec.execution_policy(), PowerShellPolicy::Restricted);
        let result = exec.execute(b"Write-Output 'hello'\r\n")?;
        let stdout = String::from_utf8(result.stdout)?;
        assert!(
            stdout.trim() == "hello",
            "expected stdout 'hello', got: {stdout:?}"
        );
        assert_eq!(result.exit_code, Some(0));
        Ok(())
    }

    #[test]
    #[ignore = "requires pwsh and sandbox support unavailable in CI containers"]
    fn execute_pipes_script_via_stdin() -> Result<(), Box<dyn std::error::Error>> {
        // Structural verification that the invocation reads the script from
        // stdin (`-Command -`) and never uses `-File` or `-EncodedCommand`.
        let Some(exec) = pwsh_or_skip() else {
            return Ok(());
        };
        let args = exec.interpreter_args();
        assert!(
            args.windows(2).any(|w| w[0] == "-Command" && w[1] == "-"),
            "missing `-Command -` stdin invocation: {args:?}"
        );
        assert!(
            !args.iter().any(|a| a == "-File" || a == "-EncodedCommand"),
            "forbidden flag present: {args:?}"
        );

        // Functional verification: no .ps1 file is materialized in the
        // temporary directories during execution (the stdin-only contract).
        let home = exec.environment().home_dir().to_path_buf();
        let work = exec.environment().working_dir().to_path_buf();
        let before = count_ps1_under(&home)? + count_ps1_under(&work)?;
        let result = exec.execute(b"Write-Output 'runs'\r\n")?;
        assert_eq!(result.exit_code, Some(0));
        let after = count_ps1_under(&home)? + count_ps1_under(&work)?;
        assert_eq!(
            before, after,
            "a .ps1 file was created during execution; the stdin-only contract is broken"
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires pwsh and sandbox support unavailable in CI containers"]
    fn network_isolated_prevents_network() -> Result<(), Box<dyn std::error::Error>> {
        let Some(exec) = pwsh_or_skip() else {
            return Ok(());
        };
        if !network_namespace_supported() {
            return Ok(());
        }
        // Bind a loopback listener on the host. The isolated child lives in a
        // separate network namespace whose loopback has no listener on this
        // port, so the connect must fail (non-zero exit). If isolation is
        // broken the child connects to the host listener and exits 0.
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let script = format!(
            "try {{ (New-Object System.Net.Sockets.TcpClient('127.0.0.1', {port})).Close(); exit 0 }} catch {{ exit 7 }}\r\n"
        );
        let result = exec.execute(script.as_bytes())?;
        assert_ne!(
            result.exit_code,
            Some(0),
            "isolated PowerShell unexpectedly connected to host loopback listener"
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires pwsh and sandbox support unavailable in CI containers"]
    fn output_capped_at_limit() {
        let Some(exec) = pwsh_or_skip() else {
            return;
        };
        let capped = exec.with_resource_limits(ResourceLimits {
            cpu_time_secs: None,
            memory_bytes: None,
            process_count: None,
            fd_count: None,
            output_size_bytes: Some(128),
        });
        // Generate far more than 128 bytes of stdout so the cap must trip.
        let result = capped.execute(b"1..10000 | ForEach-Object { 'x' * 128 }\r\n");
        assert!(
            matches!(result, Err(PowerShellError::Execution { .. })),
            "expected output-cap error, got: {result:?}"
        );
    }

    #[test]
    fn non_interactive_flag_set() {
        let Some(exec) = pwsh_or_skip() else {
            return;
        };
        assert!(
            exec.interpreter_args()
                .iter()
                .any(|a| a == "-NonInteractive"),
            "missing -NonInteractive flag"
        );
    }

    #[test]
    fn no_profile_flag_set() {
        let Some(exec) = pwsh_or_skip() else {
            return;
        };
        assert!(
            exec.interpreter_args().iter().any(|a| a == "-NoProfile"),
            "missing -NoProfile flag"
        );
    }

    #[test]
    fn execution_policy_all_signed_updates_args() -> Result<(), Box<dyn std::error::Error>> {
        // Construct with an absolute interpreter path (the mediated context
        // builder records but never executes it). This isolates the
        // flag-derivation logic from binary availability.
        let exec = PowerShellExecution::with_interpreter(
            PathBuf::from("/usr/bin/pwsh"),
            PowerShellPolicy::Restricted,
        )?
        .with_execution_policy(PowerShellPolicy::AllSigned);
        assert!(exec.interpreter_args().contains(&"AllSigned".to_owned()));
        Ok(())
    }

    #[test]
    fn execution_policy_bypass_updates_args() -> Result<(), Box<dyn std::error::Error>> {
        let exec = PowerShellExecution::with_interpreter(
            PathBuf::from("/usr/bin/pwsh"),
            PowerShellPolicy::Restricted,
        )?
        .with_execution_policy(PowerShellPolicy::Bypass);
        assert!(exec.interpreter_args().contains(&"Bypass".to_owned()));
        Ok(())
    }

    #[test]
    fn new_returns_binary_not_found_when_missing() {
        // If pwsh IS installed this test is a no-op (cannot force discovery to
        // fail); when it is absent the constructor must report BinaryNotFound.
        if discover_powershell_binary().is_some() {
            return;
        }
        let result = PowerShellExecution::new();
        assert!(
            matches!(result, Err(PowerShellError::BinaryNotFound)),
            "expected BinaryNotFound, got: {result:?}"
        );
    }

    fn count_ps1_under(root: &Path) -> Result<usize, Box<dyn std::error::Error>> {
        if !root.exists() {
            return Ok(0);
        }
        let mut count = 0;
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if entry.path().extension().and_then(|e| e.to_str()) == Some("ps1") {
                count += 1;
            }
        }
        Ok(count)
    }
}
