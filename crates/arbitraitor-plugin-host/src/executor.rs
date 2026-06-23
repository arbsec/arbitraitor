//! Sandboxed subprocess executor for framed JSON plugins.

#![forbid(unsafe_code)]

use std::env;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use arbitraitor_exec::EnvDenyList;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_sandbox::{
    ProcessResourceLimits, SandboxConfig, configure_command, configure_resource_limits,
};

use crate::error::ProtocolError;

mod message;
mod plugin;
mod process;

pub use plugin::SubprocessPlugin;
use process::{BoundedReader, configure_process_group, hash_file, plugin_resource_limits};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Errors returned by subprocess plugin spawning and lifecycle operations.
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    /// The configured plugin executable path does not exist.
    #[error("plugin binary not found: {0}")]
    BinaryNotFound(PathBuf),
    /// An allowlisted environment variable is blocked by the mandatory denylist.
    ///
    /// Variables such as `LD_PRELOAD`, `BASH_ENV`, and `PYTHONPATH` can hijack a
    /// dynamically-linked plugin binary before `main()` runs, defeating the
    /// on-disk digest check. They are refused even when the caller allowlists
    /// them.
    #[error("environment variable denied by mandatory sandbox policy: {name}")]
    DeniedEnvironmentVariable {
        /// The denied variable name.
        name: String,
    },
    /// The configured plugin executable path is not absolute.
    #[error("plugin binary path must be absolute: {0}")]
    BinaryPathNotAbsolute(PathBuf),
    /// The configured binary digest did not match the bytes on disk.
    #[error("plugin binary digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch {
        /// Expected SHA-256 digest as lowercase hexadecimal.
        expected: String,
        /// Actual SHA-256 digest as lowercase hexadecimal.
        actual: String,
    },
    /// Process spawning or process I/O failed.
    #[error("plugin spawn failed: {0}")]
    Spawn(#[from] std::io::Error),
    /// Plugin handshake failed or returned an unexpected response.
    #[error("plugin handshake failed: {0}")]
    Handshake(String),
    /// Plugin did not respond or exit before the configured deadline.
    #[error("plugin timed out after {0:?}")]
    Timeout(Duration),
    /// Plugin exited before completing the requested operation.
    #[error("plugin exited unexpectedly with code {0:?}")]
    UnexpectedExit(Option<i32>),
    /// Framed JSON protocol error.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
}

/// Builder and spawner for sandboxed subprocess plugins.
#[derive(Clone, Debug)]
pub struct SubprocessExecutor {
    binary_path: PathBuf,
    expected_digest: Option<Sha256Digest>,
    timeout: Duration,
    env_allowlist: Vec<String>,
    working_directory: Option<PathBuf>,
}

impl SubprocessExecutor {
    /// Creates an executor for an absolute plugin binary path.
    #[must_use]
    pub fn new(binary_path: PathBuf) -> Self {
        Self {
            binary_path,
            expected_digest: None,
            timeout: DEFAULT_TIMEOUT,
            env_allowlist: Vec::new(),
            working_directory: None,
        }
    }

    /// Requires the executable bytes to match `digest` before spawning.
    #[must_use]
    pub fn with_expected_digest(mut self, digest: Sha256Digest) -> Self {
        self.expected_digest = Some(digest);
        self
    }

    /// Sets the lifecycle and request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets environment variable names copied from the host environment.
    #[must_use]
    pub fn with_env_allowlist(mut self, vars: Vec<String>) -> Self {
        self.env_allowlist = vars;
        self
    }

    /// Sets the child working directory.
    #[must_use]
    pub fn with_working_directory(mut self, dir: PathBuf) -> Self {
        self.working_directory = Some(dir);
        self
    }

    /// Spawns the plugin process with sandbox hardening and framed I/O pipes.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError`] when the binary is absent, digest verification
    /// fails, the environment allowlist contains a mandatory-denied variable,
    /// sandbox setup fails, resource limits cannot be applied, or the child
    /// cannot be spawned with piped stdin/stdout.
    pub fn spawn(&self) -> Result<SubprocessPlugin, ExecutorError> {
        self.verify_binary()?;
        self.verify_env_allowlist()?;

        let mut command = Command::new(&self.binary_path);
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for name in &self.env_allowlist {
            if let Some(value) = env::var_os(name) {
                command.env(name, value);
            }
        }
        if let Some(directory) = &self.working_directory {
            command.current_dir(directory);
        }
        configure_process_group(&mut command);
        // Security: limits are applied in-child via `setrlimit` in `pre_exec`
        // (inherited across `execve`), not parent-side `prlimit` after spawn.
        // This closes the #210 TOCTOU race where a plugin could fork unbounded
        // grandchildren before limits applied. Must be registered before
        // `configure_command` so limits hold during sandbox hardening too.
        let policy_limits = plugin_resource_limits();
        let child_limits = ProcessResourceLimits {
            cpu_time_secs: policy_limits.cpu_time_secs,
            memory_bytes: policy_limits.memory_bytes,
            process_count: policy_limits.process_count.map(u64::from),
            fd_count: policy_limits.fd_count.map(u64::from),
        };
        configure_resource_limits(&mut command, &child_limits);
        configure_command(&mut command, SandboxConfig::default());

        let mut child = command.spawn()?;
        // Limits are already applied in-child before execve — no race window.

        let stdin = child.stdin.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "plugin stdin pipe unavailable")
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "plugin stdout pipe unavailable")
        })?;
        let (responses_tx, responses) = mpsc::channel();
        let reader_thread = thread::spawn(move || {
            let mut frame_reader =
                crate::frame::FrameReader::new(BoundedReader::with_default_limit(stdout));
            loop {
                match frame_reader.read_frame() {
                    Ok(message) => {
                        if responses_tx.send(Ok(message)).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _send_result = responses_tx.send(Err(error));
                        break;
                    }
                }
            }
        });

        Ok(SubprocessPlugin::new(
            child,
            stdin,
            responses,
            reader_thread,
            self.timeout,
        ))
    }

    fn verify_binary(&self) -> Result<(), ExecutorError> {
        if !self.binary_path.is_absolute() {
            return Err(ExecutorError::BinaryPathNotAbsolute(
                self.binary_path.clone(),
            ));
        }
        if !self.binary_path.is_file() {
            return Err(ExecutorError::BinaryNotFound(self.binary_path.clone()));
        }
        if let Some(expected) = &self.expected_digest {
            let actual = hash_file(&self.binary_path)?;
            if &actual != expected {
                return Err(ExecutorError::DigestMismatch {
                    expected: expected.to_string(),
                    actual: actual.to_string(),
                });
            }
        }
        Ok(())
    }

    fn verify_env_allowlist(&self) -> Result<(), ExecutorError> {
        let denylist = EnvDenyList::mandatory();
        for name in &self.env_allowlist {
            if denylist.denies(name) {
                return Err(ExecutorError::DeniedEnvironmentVariable { name: name.clone() });
            }
        }
        Ok(())
    }
}
