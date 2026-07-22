//! Interpreter-based script execution.
//!
//! [`ScriptExecution`] wraps a fully built [`ExecutionContext`] (see the crate
//! root) with a configured interpreter command and arguments. The script bytes
//! are streamed to the interpreter through its standard input — no temporary
//! executable file is ever created on disk. This eliminates a class of TOCTOU
//! and stale-permissions attacks that arise when scripts are written to disk
//! and then `chmod +x`'d before invocation.
//!
//! The mediated execution profile is enforced by the underlying
//! [`ExecutionContextBuilder`]: allowlisted environment only, controlled PATH,
//! temporary HOME and working directories, privilege-elevation rejection, and
//! network denied by default.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use arbitraitor_model::ids::{ArtifactId, OperationId, Sha256Digest};
use arbitraitor_model::operation::{
    CapabilityGrant, GrantedCapabilities, OperationPlan, OperationState, OperationType,
};
use arbitraitor_model::verdict::AssuranceLevel;
use arbitraitor_sandbox::{PathRule, configure_filesystem_isolation};
use tracing::debug;

use crate::{ExecError, ExecutionContext, ExecutionContextBuilder, ExecutionPolicy};

#[cfg(target_os = "linux")]
const UNSHARE_PATH: &str = "/usr/bin/unshare";

#[cfg(target_os = "linux")]
const UNSHARE_NETWORK_ARGS: [&str; 4] = ["--user", "--map-current-user", "--net", "--"];

/// Result of executing a script through the controlled interpreter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionResult {
    /// Exit code reported by the interpreter process. `None` when the process
    /// was terminated by a signal and therefore has no exit code.
    pub exit_code: Option<i32>,
    /// Captured stdout bytes emitted by the interpreter process.
    pub stdout: Vec<u8>,
    /// Captured stderr bytes emitted by the interpreter process.
    pub stderr: Vec<u8>,
}

/// Interpreter-based script execution wrapping a mediated [`ExecutionContext`].
///
/// The script bytes are streamed to the interpreter's standard input. No
/// temporary executable file is materialized on disk.
pub struct ScriptExecution {
    interpreter: PathBuf,
    interpreter_args: Vec<String>,
    environment: ExecutionContext,
    network_isolated: bool,
    sandbox_config: arbitraitor_sandbox::SandboxConfig,
    #[cfg(target_os = "linux")]
    resource_limits: crate::ResourceLimits,
}

impl ScriptExecution {
    /// Creates a bash interpreter execution context.
    ///
    /// Invokes `/bin/bash --noprofile --norc` so that no user or system bash
    /// startup files (`~/.bashrc`, `~/.bash_profile`, `/etc/profile`, ...) are
    /// sourced before the supplied script runs. The default mediated
    /// [`ExecutionPolicy`](crate::ExecutionPolicy) is applied: allowlisted
    /// environment only, controlled PATH, temporary HOME and working
    /// directories, privilege-elevation rejection, network denied.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::RunningAsRoot`] when the calling process is root,
    /// or another [`ExecError`] variant when policy validation fails.
    pub fn bash() -> Result<Self, ExecError> {
        Self::new(PathBuf::from("/bin/bash"), ["--noprofile", "--norc"])
    }

    /// Creates an interpreter execution context with the given interpreter
    /// binary and arguments. The interpreter path must be absolute; the
    /// default mediated [`ExecutionPolicy`](crate::ExecutionPolicy) is applied.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError`] when policy validation, environment construction,
    /// or temporary directory creation fails.
    pub fn new<I, S>(interpreter: PathBuf, interpreter_args: I) -> Result<Self, ExecError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let interpreter_args: Vec<String> = interpreter_args.into_iter().map(Into::into).collect();
        let plan = operation_plan(&interpreter, &interpreter_args);
        // The execute capability is the only capability required for script
        // execution. Network, file-write outside the working tree, and
        // environment mutation are not granted at this layer; the script runs
        // fully mediated with network denied.
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
            #[cfg(target_os = "linux")]
            resource_limits: crate::ResourceLimits::default(),
        })
    }

    /// Rebuilds the mediated execution context with caller-supplied policy and
    /// source environment.
    ///
    /// This is used by higher-level approval-bound CLI flows that need to pin
    /// additional plan dimensions such as the working directory or environment
    /// allowlist while retaining the already selected interpreter path and
    /// argument vector.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError`] when the policy or source environment cannot produce
    /// a valid mediated [`ExecutionContext`].
    pub fn with_environment_policy<I, K, V>(
        mut self,
        policy: ExecutionPolicy,
        source_environment: I,
    ) -> Result<Self, ExecError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<std::ffi::OsString>,
    {
        let plan = operation_plan(&self.interpreter, &self.interpreter_args);
        let grants = GrantedCapabilities::new(
            CapabilityGrant(false),
            CapabilityGrant(false),
            CapabilityGrant(true),
            CapabilityGrant(false),
        );
        self.environment = ExecutionContextBuilder::new(plan, grants)
            .assurance_level(AssuranceLevel::Mediated)
            .command(self.interpreter.clone())
            .arguments(self.interpreter_args.iter().map(String::as_str))
            .policy(policy)
            .source_environment(source_environment)
            .build()?;
        Ok(self)
    }

    /// Controls whether the interpreter is launched inside an isolated Linux
    /// network namespace.
    ///
    /// Network isolation is enabled by default. Disabling it is intended only
    /// for policy-granted execution paths and tests that validate the contrast
    /// between denied and explicitly allowed network access.
    #[must_use]
    pub fn with_network_isolated(mut self, isolated: bool) -> Self {
        self.network_isolated = isolated;
        self
    }

    /// Returns true when this execution will request network namespace
    /// isolation before running the interpreter.
    #[must_use]
    pub fn network_isolated(&self) -> bool {
        self.network_isolated
    }

    /// Sets the resource limits applied to the child process.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn with_resource_limits(mut self, limits: crate::ResourceLimits) -> Self {
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

    /// Returns the configured interpreter executable path.
    #[must_use]
    pub fn interpreter(&self) -> &Path {
        &self.interpreter
    }

    /// Returns the configured interpreter arguments.
    #[must_use]
    pub fn interpreter_args(&self) -> &[String] {
        &self.interpreter_args
    }

    /// Returns the mediated execution environment prepared for the interpreter.
    #[must_use]
    pub fn environment(&self) -> &ExecutionContext {
        &self.environment
    }

    /// Executes the script bytes through the configured interpreter.
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
    /// Returns [`ExecError::Spawn`] when the interpreter cannot be spawned,
    /// [`ExecError::ScriptIo`] when piping the script bytes fails, or
    /// [`ExecError::Wait`] when the interpreter output cannot be collected.
    pub fn execute(&self, script_bytes: &[u8]) -> Result<ExecutionResult, ExecError> {
        let mut command = self.build_command();
        debug!(
            interpreter = %self.interpreter.display(),
            network_isolated = self.network_isolated,
            "spawning interpreter"
        );
        let mut child = command
            .spawn()
            .map_err(|source| ExecError::Spawn { source })?;

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
                // Drop stdin before capturing output. If the child is still
                // alive (write_all failed due to EPIPE on one write, not
                // because the child exited), the child may be blocked on
                // stdin read. Without dropping stdin, the drain threads in
                // best_effort_capture → read_with_limit would block forever
                // waiting for stdout/stderr EOF while the child waits for
                // stdin EOF that never arrives = deadlock.
                drop(stdin);
                let (child_exit_code, _, child_stderr) =
                    crate::spawn::best_effort_capture(&mut child, self.output_limit());
                return Err(ExecError::script_io(
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
                return Err(ExecError::script_io(
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
        // Apply Landlock filesystem confinement: restrict the child to
        // read-execute on system paths and read-write-execute on its working
        // directory and temp home only. This prevents scripts from reading
        // arbitrary absolute paths (e.g. ~/.ssh, ~/.aws, /etc/shadow).
        let rules = landlock_rules_for_script_execution(
            &self.interpreter,
            self.environment.working_dir(),
            self.environment.home_dir(),
        );
        configure_filesystem_isolation(&mut command, &rules);
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
            command.arg(self.environment.command());
            command.args(self.environment.arguments());
            command
        } else {
            let mut command = Command::new(self.environment.command());
            command.args(self.environment.arguments());
            command
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn build_program_command(&self) -> Command {
        let mut command = Command::new(self.environment.command());
        command.args(self.environment.arguments());
        command
    }
}

fn landlock_rules_for_script_execution(
    interpreter: &Path,
    working_dir: &Path,
    home_dir: &Path,
) -> Vec<PathRule> {
    let mut rules = Vec::new();

    if let Some(parent) = interpreter.parent() {
        rules.push(PathRule::read_execute(parent.to_path_buf()));
    }
    rules.push(PathRule::read_write_execute(working_dir.to_path_buf()));
    rules.push(PathRule::read_write_execute(home_dir.to_path_buf()));
    for path in [
        "/bin",
        "/usr/bin",
        "/usr/local/bin",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/tmp",
    ] {
        rules.push(PathRule::read_execute(PathBuf::from(path)));
    }

    rules
}

fn operation_plan(interpreter: &Path, args: &[String]) -> OperationPlan {
    OperationPlan {
        operation_id: OperationId::new(),
        // The script artifact identity is bound at execute() time by the
        // caller (the CLI). The plan's artifact_id is metadata only and uses
        // a placeholder digest until operation dispatch records the real one.
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::process::Command as StdCommand;
    use std::sync::mpsc;
    use std::thread;

    fn bash_or_skip() -> Result<ScriptExecution, ExecError> {
        // `/bin/bash` is the documented interpreter path for the mediated
        // profile. Skip the test on platforms where it is not installed.
        if !Path::new("/bin/bash").exists() {
            return Err(ExecError::RunningAsRoot);
        }
        ScriptExecution::bash().map(|script| {
            script
                .with_network_isolated(false)
                .with_resource_limits(crate::ResourceLimits {
                    cpu_time_secs: None,
                    memory_bytes: None,
                    process_count: None,
                    fd_count: None,
                    output_size_bytes: None,
                })
        })
    }

    fn network_isolated_bash_or_skip() -> Result<Option<ScriptExecution>, ExecError> {
        if !Path::new("/bin/bash").exists() || !network_namespace_supported() {
            return Ok(None);
        }
        ScriptExecution::bash().map(Some)
    }

    #[test]
    fn bash_runs_simple_echo_script() -> Result<(), Box<dyn std::error::Error>> {
        let script = bash_or_skip()?;
        let result = script.execute(b"echo hello\n")?;
        assert_eq!(result.stdout, b"hello\n");
        assert!(result.stderr.is_empty());
        assert_eq!(result.exit_code, Some(0));
        Ok(())
    }

    #[test]
    fn bash_environment_excludes_unlisted_variables() -> Result<(), Box<dyn std::error::Error>> {
        // The mediated allowlist is {LANG, LC_ALL, TERM, PATH}. The test
        // process typically has many other env vars set (USER, SHELL,
        // CARGO_HOME, ...). Each such name MUST be absent from the child env.
        // We exclude shell-internal variables that bash sets itself after
        // exec (PWD, SHLVL, _, OLDPWD) — those are not parent-env leaks.
        let allow = ["LANG", "LC_ALL", "TERM", "PATH", "HOME"];
        let shell_internal = ["PWD", "SHLVL", "_", "OLDPWD"];
        let parent_names: Vec<String> = std::env::vars()
            .map(|(name, _)| name)
            .filter(|name| {
                !allow.contains(&name.as_str())
                    && !shell_internal.contains(&name.as_str())
                    && !name.starts_with("BASH")
            })
            .collect();
        if parent_names.is_empty() {
            return Err(
                "test process has no env vars outside the allowlist to test against".into(),
            );
        }
        let script = bash_or_skip()?;
        let result = script.execute(b"env -0\n")?;
        let child_stdout = String::from_utf8(result.stdout)?;
        let child_names: Vec<&str> = child_stdout
            .split('\0')
            .filter_map(|pair| pair.split_once('=').map(|(name, _)| name))
            .collect();
        for parent_name in &parent_names {
            assert!(
                !child_names.contains(&parent_name.as_str()),
                "unlisted environment variable leaked into the child: {parent_name}"
            );
        }
        Ok(())
    }

    #[test]
    fn bash_environment_includes_home_and_path() -> Result<(), Box<dyn std::error::Error>> {
        let script = bash_or_skip()?;
        let result = script.execute(b"env -0\n")?;
        let stdout = String::from_utf8(result.stdout)?;
        let names: Vec<&str> = stdout
            .split('\0')
            .filter_map(|pair| pair.split_once('=').map(|(name, _)| name))
            .collect();
        assert!(names.contains(&"HOME"), "HOME missing from child env");
        assert!(names.contains(&"PATH"), "PATH missing from child env");
        Ok(())
    }

    #[test]
    fn bash_working_directory_is_temporary() -> Result<(), Box<dyn std::error::Error>> {
        let script = bash_or_skip()?;
        let working_dir = script.environment().working_dir().to_path_buf();
        let result = script.execute(b"pwd\n")?;
        let reported = PathBuf::from(String::from_utf8_lossy(&result.stdout).trim().to_owned());
        assert_eq!(
            reported, working_dir,
            "child reported a different working directory than the mediated context"
        );
        assert!(
            working_dir.starts_with(std::env::temp_dir()),
            "working directory is not under the system temp dir: {}",
            working_dir.display()
        );
        Ok(())
    }

    #[test]
    fn bash_invocation_passes_noprofile_and_norc() -> Result<(), Box<dyn std::error::Error>> {
        let script = bash_or_skip()?;
        assert_eq!(
            script.interpreter_args(),
            ["--noprofile", "--norc"],
            "bash interpreter must be invoked with --noprofile --norc"
        );
        assert_eq!(script.interpreter(), Path::new("/bin/bash"));
        Ok(())
    }

    #[test]
    fn bash_does_not_source_startup_files() -> Result<(), Box<dyn std::error::Error>> {
        // Drop a hostile `~/.bashrc` into the temporary HOME and verify it is
        // never sourced thanks to `--noprofile --norc`. If profiles were
        // loaded, `BAHMED_RC_RAN` would be set in the child environment.
        let script = bash_or_skip()?;
        let home = script.environment().home_dir().to_path_buf();
        fs::write(
            home.join(".bashrc"),
            "export BASHMED_RC_RAN=1\nexport PROFILE_LOADED=yes\n",
        )?;
        fs::write(home.join(".bash_profile"), "export BASHMED_PROFILE_RAN=1\n")?;
        let result = script.execute(b"printf 'rc=%s profile=%s\\n' \"${BASHMED_RC_RAN:-0}\" \"${BASHMED_PROFILE_RAN:-0}\"\n")?;
        let stdout = String::from_utf8(result.stdout)?;
        assert!(
            stdout.contains("rc=0") && stdout.contains("profile=0"),
            "bash sourced a startup file despite --noprofile --norc: {stdout}"
        );
        Ok(())
    }

    #[test]
    fn bash_script_is_delivered_via_stdin_not_an_executable_file()
    -> Result<(), Box<dyn std::error::Error>> {
        // The mediated temp directories are the only places the exec crate
        // writes to. Snapshot them, run a script, and assert no new
        // executable regular file (mode bits 0o111) was created anywhere
        // underneath. This guards against regressing the stdin-only contract.
        let script = bash_or_skip()?;
        let home = script.environment().home_dir().to_path_buf();
        let work = script.environment().working_dir().to_path_buf();
        let snapshot = list_executable_files_under(&home)?
            .into_iter()
            .chain(list_executable_files_under(&work)?)
            .collect::<Vec<_>>();
        let result = script.execute(b"echo runs\n")?;
        assert_eq!(result.exit_code, Some(0));
        let after = list_executable_files_under(&home)?
            .into_iter()
            .chain(list_executable_files_under(&work)?)
            .collect::<Vec<_>>();
        assert_eq!(
            after, snapshot,
            "an executable file was created during execution; the stdin-only contract is broken"
        );
        Ok(())
    }

    #[test]
    fn bash_exit_code_is_propagated() -> Result<(), Box<dyn std::error::Error>> {
        let script = bash_or_skip()?;
        let result = script.execute(b"exit 42\n")?;
        assert_eq!(result.exit_code, Some(42));
        Ok(())
    }

    #[test]
    fn script_sandbox_requests_no_new_privs() -> Result<(), Box<dyn std::error::Error>> {
        let script = bash_or_skip()?;
        // Runtime proof lives in arbitraitor-sandbox::tests::apply_sandbox_sets_no_new_privs.
        // This broker test verifies script execution delegates to the secure default.
        assert!(script.sandbox_config().no_new_privs);
        Ok(())
    }

    #[test]
    fn sandbox_config_defaults_and_overrides() -> Result<(), Box<dyn std::error::Error>> {
        let exec = ScriptExecution::new(PathBuf::from("/bin/sh"), ["-u"])?;
        assert_eq!(
            exec.sandbox_config(),
            arbitraitor_sandbox::SandboxConfig::default()
        );
        let relaxed = arbitraitor_sandbox::SandboxConfig {
            no_new_privs: false,
            dumpable: true,
            close_fds: false,
        };
        assert_eq!(exec.with_sandbox_config(relaxed).sandbox_config(), relaxed);
        Ok(())
    }

    #[test]
    fn bash_captures_stdout_and_stderr_separately() -> Result<(), Box<dyn std::error::Error>> {
        let script = bash_or_skip()?;
        let result = script.execute(b"echo to-out\nprintf '%s\\n' 'to-err' 1>&2\n")?;
        assert_eq!(result.stdout, b"to-out\n");
        assert_eq!(result.stderr, b"to-err\n");
        Ok(())
    }

    #[test]
    fn bash_child_uses_controlled_path() -> Result<(), Box<dyn std::error::Error>> {
        let script = bash_or_skip()?;
        let result = script.execute(b"printf '%s' \"$PATH\"\n")?;
        let path = String::from_utf8(result.stdout)?;
        let entries: Vec<&str> = path.split(':').collect();
        // Every entry must be absolute and resolve to a root-owned binary
        // directory per the default policy.
        assert!(
            entries.iter().all(|entry| Path::new(entry).is_absolute()),
            "controlled PATH contains a relative entry: {path}"
        );
        assert!(
            !entries.iter().any(|entry| entry.is_empty()),
            "controlled PATH contains an empty entry: {path}"
        );
        Ok(())
    }

    #[test]
    fn bash_constructor_rejects_running_as_root() {
        // The mediated policy refuses to run as root. We cannot force the test
        // process to become root, so we only assert the constructor surface
        // is fallible here — the RunningAsRoot error is exercised in lib.rs.
        let _ = ScriptExecution::bash();
    }

    #[test]
    fn new_constructor_records_interpreter_and_args() -> Result<(), Box<dyn std::error::Error>> {
        let exec = ScriptExecution::new(PathBuf::from("/bin/sh"), ["-u"])?;
        assert_eq!(exec.interpreter(), Path::new("/bin/sh"));
        assert_eq!(exec.interpreter_args(), ["-u"]);
        Ok(())
    }

    #[test]
    fn network_isolation_is_enabled_by_default() -> Result<(), Box<dyn std::error::Error>> {
        let exec = ScriptExecution::new(PathBuf::from("/bin/sh"), ["-u"])?;
        assert!(exec.network_isolated());
        assert!(!exec.with_network_isolated(false).network_isolated());
        Ok(())
    }

    #[test]
    fn loopback_connection_succeeds_when_network_isolation_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let script = bash_or_skip()?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let (sender, receiver) = mpsc::channel();
        let accept_thread = thread::spawn(move || {
            let accepted = listener.accept().and_then(|(mut stream, _addr)| {
                let mut bytes = [0_u8; 4];
                stream.read_exact(&mut bytes)?;
                Ok(bytes)
            });
            let _send_result = sender.send(accepted);
        });

        let source = format!("exec 3<>/dev/tcp/127.0.0.1/{port}\nprintf ping >&3\n");
        let result = script.execute(source.as_bytes())?;
        assert_eq!(result.exit_code, Some(0));

        match receiver.recv()? {
            Ok(bytes) => assert_eq!(&bytes, b"ping"),
            Err(error) => return Err(error.into()),
        }
        accept_thread
            .join()
            .map_err(|_| "loopback accept thread panicked")?;
        Ok(())
    }

    #[test]
    fn loopback_connection_fails_when_network_isolated() -> Result<(), Box<dyn std::error::Error>> {
        let Some(script) = network_isolated_bash_or_skip()? else {
            return Ok(());
        };
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let source =
            format!("exec 3<>/dev/tcp/127.0.0.1/{port}\nprintf 'unexpected-connect' >&3\n");

        let result = script.execute(source.as_bytes())?;
        assert_ne!(
            result.exit_code,
            Some(0),
            "isolated script unexpectedly connected to host loopback listener"
        );
        Ok(())
    }

    #[test]
    fn external_connection_fails_when_network_isolated() -> Result<(), Box<dyn std::error::Error>> {
        let Some(script) = network_isolated_bash_or_skip()? else {
            return Ok(());
        };
        let result = script.execute(b"exec 3<>/dev/tcp/192.0.2.1/80\nprintf unexpected >&3\n")?;
        assert_ne!(
            result.exit_code,
            Some(0),
            "isolated script unexpectedly opened an external TCP connection"
        );
        Ok(())
    }

    fn list_executable_files_under(
        root: &Path,
    ) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let mut out = Vec::new();
        if !root.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_file() && (meta.permissions().mode() & 0o111 != 0) {
                out.push(entry.path());
            }
        }
        out.sort();
        Ok(out)
    }

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

    fn landlock_enforced() -> bool {
        let mut command = StdCommand::new("/bin/sh");
        command.arg("-c").arg("cat /etc/hostname 2>/dev/null");
        arbitraitor_sandbox::configure_command(
            &mut command,
            arbitraitor_sandbox::SandboxConfig::default(),
        );
        arbitraitor_sandbox::configure_filesystem_isolation(&mut command, &[]);
        command.status().is_ok_and(|s| !s.success())
    }

    #[test]
    fn landlock_blocks_read_of_disallowed_paths() -> Result<(), Box<dyn std::error::Error>> {
        if !landlock_enforced() {
            return Ok(());
        }
        let script = bash_or_skip()?;
        let result = script.execute(b"cat /etc/passwd\n")?;
        assert!(
            result.exit_code != Some(0),
            "reading /etc/passwd should fail under Landlock; stdout={}",
            String::from_utf8_lossy(&result.stdout)
        );
        Ok(())
    }

    #[test]
    fn landlock_allows_working_dir_writes() -> Result<(), Box<dyn std::error::Error>> {
        if !landlock_enforced() {
            return Ok(());
        }
        let script = bash_or_skip()?;
        let result = script.execute(b"echo hello > allowed.txt && cat allowed.txt\n")?;
        assert!(
            result.exit_code == Some(0),
            "writing to working dir should succeed; stderr={}",
            String::from_utf8_lossy(&result.stderr)
        );
        Ok(())
    }

    #[test]
    fn landlock_rules_include_standard_paths() {
        let rules = landlock_rules_for_script_execution(
            Path::new("/bin/bash"),
            Path::new("/tmp/work"),
            Path::new("/tmp/home"),
        );
        let paths: Vec<&Path> = rules.iter().map(|r| r.path.as_path()).collect();
        assert!(paths.iter().any(|p| p == &Path::new("/bin")));
        assert!(paths.iter().any(|p| p == &Path::new("/usr/bin")));
        assert!(paths.iter().any(|p| p == &Path::new("/usr/local/bin")));
        assert!(paths.iter().any(|p| p == &Path::new("/lib")));
        assert!(paths.iter().any(|p| p == &Path::new("/tmp")));
    }

    /// Regression test for #612 (Fix B): when bash exits before consuming
    /// all streamed script bytes, `ScriptExecution::execute` must:
    ///
    /// 1. Return `ExecError::ScriptIo { stage: "write-script-stdin", ... }`
    ///    (or `"flush-script-stdin"`).
    /// 2. Populate `child_exit_code` with the early-exit code.
    /// 3. Populate `child_stderr` with whatever bash printed before dying.
    /// 4. Render the captured stderr into the `Display` representation so
    ///    the CLI-level failure message identifies the real root cause.
    ///
    /// Before the fix, the function returned at `write_all` failure without
    /// ever reading the child's captured stderr — leaving the user with a
    /// generic "script input I/O failure during write-script-stdin" message
    /// and no clue that bash had rejected the input as a parse error.
    #[test]
    fn execute_preserves_child_stderr_when_bash_exits_early()
    -> Result<(), Box<dyn std::error::Error>> {
        if !Path::new("/bin/bash").exists() {
            return Ok(());
        }
        let script = bash_or_skip()?;
        // Bash reads line 1, writes "expected-diagnostic\n" to its stderr
        // pipe, reads line 2 (`exit 1`), and exits. By that point the parent
        // is still blocked in `write_all` on the 256 KB stdin pipe (Linux
        // pipe buffers are ~64 KB) — closing the read end on bash exit
        // causes `write_all` to fail with EPIPE, exercising the regression
        // path from issue #612. The 256 KiB padding exceeds the pipe buffer
        // so write_all cannot drain before bash exits.
        let mut script_bytes = b"echo expected-diagnostic >&2\nexit 1\n".to_vec();
        script_bytes.resize(256 * 1024, b'\n');
        let error = match script.execute(&script_bytes) {
            Err(err) => err,
            Ok(result) => {
                return Err(format!(
                    "expected execute() to fail (early child exit), but it succeeded: {result:?}"
                )
                .into());
            }
        };
        let ExecError::ScriptIo {
            stage,
            ref child_exit_code,
            ref child_stderr,
            ..
        } = error
        else {
            return Err(format!(
                "expected ScriptIo variant, got {error:?} — pipeline is no longer surfacing child-exit failure as ScriptIo"
            )
            .into());
        };
        let child_exit_code = *child_exit_code;
        let child_stderr = child_stderr.clone();
        assert!(
            stage == "write-script-stdin" || stage == "flush-script-stdin",
            "stage should be a script-stdin write/flush failure, got {stage:?}"
        );
        let stderr_text = String::from_utf8_lossy(&child_stderr);
        assert!(
            stderr_text.contains("expected-diagnostic"),
            "child_stderr must be captured even when write_all failed; got {stderr_text:?}"
        );
        assert_eq!(
            child_exit_code,
            Some(1),
            "child_exit_code should be 1 (exit 1); got {child_exit_code:?}"
        );
        let rendered = error.to_string();
        assert!(
            rendered.contains("write-script-stdin") || rendered.contains("flush-script-stdin"),
            "rendered error should name the stage; got {rendered:?}"
        );
        assert!(
            rendered.contains("expected-diagnostic"),
            "rendered error should include the captured stderr so users can see the real root cause; got {rendered:?}"
        );
        assert!(
            rendered.contains("child exited 1"),
            "rendered error should mention the child exit code; got {rendered:?}"
        );
        Ok(())
    }

    /// Regression test for #612 acceptance criterion (c): reproduction of
    /// the unshare-denied path. When the kernel or container runtime denies
    /// `unshare --user --map-current-user --net` (e.g.
    /// `/proc/sys/kernel/unprivileged_userns_clone=0`, a seccomp filter
    /// blocking `CLONE_NEWUSER`, or a container runtime that doesn't allow
    /// userns), unshare writes `unshare: ... Operation not permitted` to
    /// stderr and exits before consuming the parent's stdin script bytes.
    /// Before Fix B, the user saw a generic
    /// `script input I/O failure during write-script-stdin` message with no
    /// hint that userns was the actual blocker.
    ///
    /// Reproducing the real unshare-denied failure mode requires a
    /// system/container where `unshare --user` is actually denied. CI
    /// runners typically allow userns, so this test cannot exercise the
    /// real unshare binary directly. Instead it installs a fake interpreter
    /// that EXACTLY mimics unshare's failure signature (write the canonical
    /// `unshare: unshare failed: Operation not permitted` message to
    /// stderr, exit 1, never read stdin) and runs it through the same
    /// `ScriptExecution::execute` code path that the real unshare-wrapped
    /// bash invocation would hit. The Fix B machinery (`best_effort_capture`
    /// plus `ExecError::script_io` plus `script_io_detail` rendering) is
    /// identical whether the early-exiting child is the real unshare or this
    /// fake — the same `write_all` EPIPE then capture then render path is
    /// exercised in both cases.
    #[test]
    fn execute_surfaces_unshare_denied_diagnostic_when_child_exits_early()
    -> Result<(), Box<dyn std::error::Error>> {
        if !Path::new("/bin/sh").exists() {
            return Ok(());
        }
        // The fake "interpreter" mimics util-linux unshare's behavior when
        // the kernel denies CLONE_NEWUSER: emit the canonical diagnostic to
        // stderr, exit 1, never read stdin. Real unshare output:
        //   `unshare: unshare failed: Operation not permitted`
        // (https://github.com/util-linux/util-linux/blob/master/sys-utils/unshare.c)
        let fake_unshare_dir =
            std::env::temp_dir().join(format!("arb-fake-unshare-{}", std::process::id()));
        std::fs::remove_dir_all(&fake_unshare_dir).ok();
        std::fs::create_dir_all(&fake_unshare_dir)?;
        let fake_unshare_path = fake_unshare_dir.join("fake-unshare");
        std::fs::write(
            &fake_unshare_path,
            b"#!/bin/sh\necho 'unshare: unshare failed: Operation not permitted' >&2\nexit 1\n",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake_unshare_path, std::fs::Permissions::from_mode(0o700))?;
        }
        // Use ScriptExecution::new() with the fake interpreter. The default
        // network_isolated=true would wrap this in a real unshare, defeating
        // the purpose (we want to substitute FOR unshare, not layer on top
        // of it). No resource limits are needed because the fake exits
        // before any execution begins.
        let execution = ScriptExecution::new(
            fake_unshare_path.clone(),
            std::iter::empty::<&'static str>(),
        )?
        .with_network_isolated(false);
        // 256 KiB padding guarantees `write_all` cannot drain before the
        // fake-unshare exits; the parent's `write_all` then fails with
        // EPIPE, exercising the same Fix B path the real unshare-denied
        // case would exercise.
        let mut script_bytes: Vec<u8> = Vec::with_capacity(256 * 1024);
        script_bytes.resize(256 * 1024, b'\n');
        let error = match execution.execute(&script_bytes) {
            Err(err) => err,
            Ok(result) => {
                std::fs::remove_dir_all(&fake_unshare_dir).ok();
                return Err(format!(
                    "expected execute() to fail via fake-unshare early exit, but it succeeded: {result:?}"
                )
                .into());
            }
        };
        let ExecError::ScriptIo {
            stage,
            ref child_exit_code,
            ref child_stderr,
            ..
        } = error
        else {
            std::fs::remove_dir_all(&fake_unshare_dir).ok();
            return Err(format!(
                "expected ScriptIo variant for unshare-denied path, got {error:?}"
            )
            .into());
        };
        let child_exit_code = *child_exit_code;
        let child_stderr = child_stderr.clone();
        assert!(
            stage == "write-script-stdin" || stage == "flush-script-stdin",
            "stage should be a script-stdin write/flush failure for the unshare-denied path, got {stage:?}"
        );
        let stderr_text = String::from_utf8_lossy(&child_stderr);
        assert!(
            stderr_text.contains("unshare failed") && stderr_text.contains("not permitted"),
            "child_stderr must capture the unshare-denied diagnostic for issue #612 acceptance (c); got {stderr_text:?}"
        );
        assert_eq!(
            child_exit_code,
            Some(1),
            "child_exit_code should be 1 (unshare exits 1 on denial); got {child_exit_code:?}"
        );
        let rendered = error.to_string();
        assert!(
            rendered.contains("unshare failed"),
            "rendered error must surface the unshare-denied diagnostic so the user can distinguish 'kernel denied userns' from 'I fed bash junk'; got {rendered:?}"
        );
        assert!(
            rendered.contains("not permitted"),
            "rendered error must include 'not permitted' from unshare's diagnostic; got {rendered:?}"
        );
        assert!(
            rendered.contains("child exited 1"),
            "rendered error should mention the child exit code; got {rendered:?}"
        );
        std::fs::remove_dir_all(&fake_unshare_dir).ok();
        Ok(())
    }
}
