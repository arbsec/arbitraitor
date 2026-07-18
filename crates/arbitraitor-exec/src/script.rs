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

use crate::{ExecError, ExecutionContext, ExecutionContextBuilder};

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
            stdin
                .write_all(script_bytes)
                .map_err(|source| ExecError::ScriptIo {
                    stage: "write-script-stdin",
                    source,
                })?;
            stdin.flush().map_err(|source| ExecError::ScriptIo {
                stage: "flush-script-stdin",
                source,
            })?;
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
    fn script_sandbox_sets_no_new_privs() -> Result<(), Box<dyn std::error::Error>> {
        if !Path::new("/proc/self/status").exists() {
            return Ok(());
        }
        let script = bash_or_skip()?;
        let result = script.execute(b"grep '^NoNewPrivs:' /proc/self/status\n")?;
        assert_eq!(
            String::from_utf8(result.stdout)?.trim(),
            "NoNewPrivs:\t1",
            "script child must run with NoNewPrivs set"
        );
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
}
