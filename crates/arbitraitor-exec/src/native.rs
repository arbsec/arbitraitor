//! Native executable launch support.
//!
//! Native execution is an explicit opt-in path for already released binaries.
//! The caller remains responsible for using the safe release machinery first;
//! this module fail-closes unless platform quarantine/provenance metadata is
//! present on the released inode immediately before spawn.

use std::ffi::{CString, OsStr};
use std::fs;
use std::os::fd::AsFd;
use std::path::Path;
use std::process::{Command, Stdio};

use arbitraitor_artifact::executable::{ExecutableInfo, is_compatible};
use arbitraitor_model::ids::{ArtifactId, OperationId, Sha256Digest};
use arbitraitor_model::operation::{
    CapabilityGrant, GrantedCapabilities, OperationPlan, OperationState, OperationType,
};
use arbitraitor_model::verdict::AssuranceLevel;
use arbitraitor_sandbox::SandboxConfig;
use arbitraitor_sandbox::{ProcessResourceLimits, configure_resource_limits};
use rustix::fs::{XattrFlags, fgetxattr, fsetxattr};
use tracing::debug;

use crate::release::ReleasePolicy;
use crate::{ExecError, ExecutionContext, ExecutionContextBuilder, ResourceLimits};

const LINUX_ORIGIN_XATTR: &str = "user.xdg.origin.url";
const LINUX_ORIGIN_VALUE: &[u8] = b"arbitraitor://native-execution";

/// Capability token proving the caller explicitly opted into native execution.
#[derive(Debug, Clone)]
pub struct NativeExecutionGate(());

impl NativeExecutionGate {
    /// Construct the gate. Only call this from code that verified the `--native` flag.
    #[must_use]
    pub fn new() -> Self {
        Self(())
    }
}

impl Default for NativeExecutionGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Native binary execution wrapping a mediated [`ExecutionContext`].
pub struct NativeExecution {
    args: Vec<String>,
    environment: ExecutionContext,
    #[cfg(target_os = "linux")]
    resource_limits: ResourceLimits,
    #[cfg(target_os = "linux")]
    sandbox: SandboxConfig,
}

impl NativeExecution {
    /// Creates a native execution context with no extra argv entries.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError`] when mediated environment construction fails.
    pub fn new() -> Result<Self, ExecError> {
        Self::with_args_checked(Vec::new())
    }

    /// Replaces the argv entries passed to the released binary.
    #[must_use]
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Sets resource limits applied to the child process.
    #[must_use]
    pub fn with_resource_limits(mut self, limits: ResourceLimits) -> Self {
        self.resource_limits = limits;
        self
    }

    /// Sets sandbox hardening applied in the child before `exec`.
    #[must_use]
    pub fn with_sandbox(mut self, sandbox: SandboxConfig) -> Self {
        self.sandbox = sandbox;
        self
    }

    /// Returns the controlled execution environment.
    #[must_use]
    pub fn environment(&self) -> &ExecutionContext {
        &self.environment
    }

    /// Executes a released native binary after quarantine verification.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError`] when the binary path is invalid, quarantine cannot
    /// be applied and verified, spawning fails, resource limits cannot be
    /// applied, or output collection fails.
    pub fn execute(&self, binary_path: &Path) -> Result<crate::ExecutionResult, ExecError> {
        if !binary_path.is_absolute() {
            return Err(ExecError::NativePathNotAbsolute {
                path: binary_path.to_path_buf(),
            });
        }
        reject_privilege_elevation(binary_path, &self.args)?;
        apply_platform_quarantine(binary_path)?;
        verify_platform_quarantine(binary_path)?;

        let mut command = Command::new(binary_path);
        command.args(&self.args);
        command.env_clear();
        command.envs(self.environment.environment_iter());
        command.current_dir(self.environment.working_dir());
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        // Security: limits are applied in-child via `setrlimit` in `pre_exec`
        // (inherited across `execve`), not parent-side `prlimit` after spawn.
        // This closes the #375 fork-before-prlimit race where a native binary
        // could fork unbounded grandchildren before limits applied. Must be
        // registered before `configure_command` so limits hold during sandbox
        // hardening too. Mirrors plugin-host/src/executor.rs:172-185.
        let process_limits = process_resource_limits(&self.resource_limits);
        configure_resource_limits(&mut command, &process_limits);
        arbitraitor_sandbox::configure_command(&mut command, self.sandbox);

        debug!(binary = %binary_path.display(), "spawning native binary");
        let child = command
            .spawn()
            .map_err(|source| ExecError::Spawn { source })?;
        // Limits were applied in pre_exec before execve — no race window.
        let output = child
            .wait_with_output()
            .map_err(|source| ExecError::Wait { source })?;
        Ok(crate::ExecutionResult {
            exit_code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    fn with_args_checked(args: Vec<String>) -> Result<Self, ExecError> {
        let environment = ExecutionContextBuilder::new(operation_plan(&args), execute_grants())
            .assurance_level(AssuranceLevel::Contained)
            .command("/bin/true")
            .arguments(args.iter().map(String::as_str))
            .build()?;
        Ok(Self {
            args,
            environment,
            resource_limits: ResourceLimits::default(),
            sandbox: SandboxConfig::default(),
        })
    }
}

/// Explicit native opt-in helper for released binaries.
///
/// Call this only when the CLI/user supplied the explicit native execution gate
/// (for example `--native`). The function verifies executable host
/// compatibility, applies and verifies quarantine/provenance attributes, and
/// runs the binary with controlled environment, sandbox hardening, and resource
/// limits.
///
/// # Errors
///
/// Returns [`ExecError::IncompatibleNativeExecutable`] when `exec_info` is not
/// compatible with the current host, or another [`ExecError`] from context
/// construction or execution.
pub fn execute_native(
    binary_path: &Path,
    args: &[String],
    exec_info: &ExecutableInfo,
    _policy: &ReleasePolicy,
) -> Result<crate::ExecutionResult, ExecError> {
    if !is_compatible(exec_info) {
        return Err(ExecError::IncompatibleNativeExecutable);
    }
    NativeExecution::new()?
        .with_args(args.to_vec())
        .execute(binary_path)
}

fn process_resource_limits(limits: &ResourceLimits) -> ProcessResourceLimits {
    ProcessResourceLimits {
        cpu_time_secs: limits.cpu_time_secs,
        memory_bytes: limits.memory_bytes,
        process_count: limits.process_count.map(u64::from),
        fd_count: limits.fd_count.map(u64::from),
    }
}

fn operation_plan(args: &[String]) -> OperationPlan {
    OperationPlan {
        operation_id: OperationId::new(),
        artifact_id: ArtifactId(Sha256Digest::new([0; 32])),
        operation_type: OperationType::Execute,
        interpreter: Some("/bin/true".to_owned()),
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

fn execute_grants() -> GrantedCapabilities {
    GrantedCapabilities::new(
        CapabilityGrant(false),
        CapabilityGrant(false),
        CapabilityGrant(true),
        CapabilityGrant(false),
    )
}

fn reject_privilege_elevation(binary_path: &Path, args: &[String]) -> Result<(), ExecError> {
    if let Some(name) = binary_path.file_name().and_then(OsStr::to_str) {
        reject_privilege_elevation_token(name)?;
    }
    for arg in args {
        for token in split_command_tokens(arg) {
            reject_privilege_elevation_token(token)?;
        }
    }
    Ok(())
}

fn split_command_tokens(command: &str) -> impl Iterator<Item = &str> {
    command
        .split(|character: char| !matches!(character, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | '/' | '.'))
        .filter(|token| !token.is_empty())
}

fn reject_privilege_elevation_token(value: &str) -> Result<(), ExecError> {
    let name = Path::new(value)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(value);
    if matches!(name, "sudo" | "su" | "doas" | "pkexec") {
        Err(ExecError::PrivilegeElevationAttempt {
            program: value.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn apply_platform_quarantine(binary_path: &Path) -> Result<(), ExecError> {
    let file = fs::File::options()
        .read(true)
        .write(true)
        .open(binary_path)
        .map_err(|source| ExecError::NativeQuarantine {
            stage: "open-native-for-quarantine",
            source,
        })?;
    let name = xattr_name(LINUX_ORIGIN_XATTR, "prepare-linux-origin-xattr")?;
    fsetxattr(
        file.as_fd(),
        name.as_c_str(),
        LINUX_ORIGIN_VALUE,
        XattrFlags::empty(),
    )
    .map_err(|source| ExecError::NativeQuarantine {
        stage: "set-linux-origin-xattr",
        source: rustix_to_io(source),
    })
}

fn verify_platform_quarantine(binary_path: &Path) -> Result<(), ExecError> {
    let file = fs::File::open(binary_path).map_err(|source| ExecError::NativeQuarantine {
        stage: "open-native-for-quarantine-verify",
        source,
    })?;
    let name = xattr_name(LINUX_ORIGIN_XATTR, "prepare-linux-origin-xattr-verify")?;
    let mut empty = [0_u8; 0];
    let size = match fgetxattr(file.as_fd(), name.as_c_str(), &mut empty) {
        Ok(size) => size,
        Err(error) if is_missing_xattr(error) => {
            return Err(ExecError::NativeQuarantineMissing {
                path: binary_path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(ExecError::NativeQuarantine {
                stage: "read-linux-origin-xattr-size",
                source: rustix_to_io(source),
            });
        }
    };
    if size == 0 {
        return Err(ExecError::NativeQuarantineMissing {
            path: binary_path.to_path_buf(),
        });
    }
    let mut value = vec![0_u8; size];
    let len = fgetxattr(file.as_fd(), name.as_c_str(), &mut value).map_err(|source| {
        ExecError::NativeQuarantine {
            stage: "read-linux-origin-xattr",
            source: rustix_to_io(source),
        }
    })?;
    value.truncate(len);
    if value.is_empty() {
        return Err(ExecError::NativeQuarantineMissing {
            path: binary_path.to_path_buf(),
        });
    }
    Ok(())
}

fn xattr_name(name: &str, stage: &'static str) -> Result<CString, ExecError> {
    CString::new(name).map_err(|source| ExecError::NativeQuarantine {
        stage,
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, source),
    })
}

fn is_missing_xattr(error: rustix::io::Errno) -> bool {
    matches!(error.raw_os_error(), libc::ENODATA | libc::EOPNOTSUPP)
}

fn rustix_to_io(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use arbitraitor_artifact::executable::{Architecture, Bitness, ExecutableFormat, Linking};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_root(label: &str) -> io::Result<PathBuf> {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "arbitraitor-native-{label}-{}-{id}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn copy_executable(source: &str, root: &Path, name: &str) -> io::Result<Option<PathBuf>> {
        let source = Path::new(source);
        if !source.exists() {
            return Ok(None);
        }
        let destination = root.join(name);
        fs::copy(source, &destination)?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;
        Ok(Some(destination))
    }

    fn xattrs_supported(root: &Path) -> Result<bool, ExecError> {
        let probe = root.join("probe");
        fs::write(&probe, b"probe").map_err(|source| ExecError::NativeQuarantine {
            stage: "write-xattr-probe",
            source,
        })?;
        match apply_platform_quarantine(&probe) {
            Ok(()) => Ok(true),
            Err(ExecError::NativeQuarantine { source, .. })
                if matches!(source.raw_os_error(), Some(libc::EOPNOTSUPP | libc::EPERM)) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn shell_copy(root: &Path) -> io::Result<Option<PathBuf>> {
        copy_executable("/bin/sh", root, "native-sh")
    }

    #[test]
    fn executes_simple_native_binary() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("echo")?;
        if !xattrs_supported(&root)? {
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let Some(binary) = copy_executable("/bin/echo", &root, "native-echo")? else {
            fs::remove_dir_all(root)?;
            return Ok(());
        };
        let result = NativeExecution::new()?
            .with_args(vec!["hello".to_owned()])
            .execute(&binary)?;
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout, b"hello\n");
        assert!(result.stderr.is_empty());
        verify_platform_quarantine(&binary)?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[ignore = "requires shell binary in CI"]
    fn native_environment_is_controlled() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("env")?;
        if !xattrs_supported(&root)? {
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let Some(binary) = shell_copy(&root)? else {
            fs::remove_dir_all(root)?;
            return Ok(());
        };
        let result = NativeExecution::new()?
            .with_args(vec!["-c".to_owned(), "env -0".to_owned()])
            .execute(&binary)?;
        let stdout = String::from_utf8(result.stdout)?;
        assert!(stdout.contains("PATH="));
        assert!(stdout.contains("HOME="));
        assert!(!stdout.contains("CARGO="));
        assert!(!stdout.contains("LD_PRELOAD="));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "requires process spawning in CI"]
    fn native_resource_limits_are_applied() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("limits")?;
        if !xattrs_supported(&root)? {
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let Some(binary) = shell_copy(&root)? else {
            fs::remove_dir_all(root)?;
            return Ok(());
        };
        let limits = ResourceLimits {
            cpu_time_secs: None,
            memory_bytes: None,
            process_count: None,
            fd_count: Some(32),
            output_size_bytes: None,
        };
        let result = NativeExecution::new()?
            .with_resource_limits(limits)
            .with_args(vec!["-c".to_owned(), "sleep 0.1; ulimit -n".to_owned()])
            .execute(&binary)?;
        assert_eq!(String::from_utf8(result.stdout)?.trim(), "32");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    /// Regression test for the #375 fork-before-prlimit race: the limits
    /// configured via `with_resource_limits` must be observable *inside the
    /// child's first instruction*, proving they were applied in `pre_exec`
    /// (inherited across `execve`) rather than parent-side `prlimit` after
    /// spawn. Reads `ulimit -t`/`-n` immediately — no `sleep` that would mask
    /// a post-spawn apply window.
    ///
    /// Fast and deterministic, so it runs in CI (not `#[ignore]`).
    #[test]
    #[cfg(target_os = "linux")]
    fn native_pre_exec_limits_hold_before_first_instruction()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("pre-exec-limits")?;
        if !xattrs_supported(&root)? {
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let Some(binary) = shell_copy(&root)? else {
            fs::remove_dir_all(root)?;
            return Ok(());
        };
        // Distinct values unlikely to match a host default.
        let limits = ResourceLimits {
            cpu_time_secs: Some(7),
            memory_bytes: None,
            process_count: None,
            fd_count: Some(64),
            output_size_bytes: None,
        };
        let result = NativeExecution::new()?
            .with_resource_limits(limits)
            .with_args(vec![
                "-c".to_owned(),
                // Read soft limits at once, before any other work; if the
                // limits were applied post-spawn there would be a window
                // where these would still show the inherited parent values.
                "echo cpu=$(ulimit -t); echo nofile=$(ulimit -n)".to_owned(),
            ])
            .execute(&binary)?;
        let stdout = String::from_utf8(result.stdout)?;
        assert!(
            stdout.contains("cpu=7"),
            "RLIMIT_CPU not applied in pre_exec; stdout was: {stdout:?}"
        );
        assert!(
            stdout.contains("nofile=64"),
            "RLIMIT_NOFILE not applied in pre_exec; stdout was: {stdout:?}"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[cfg(target_os = "linux")]
    #[ignore = "requires user namespace support unavailable in CI"]
    fn native_sandbox_sets_no_new_privs() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("sandbox")?;
        if !Path::new("/proc/self/status").exists() || !xattrs_supported(&root)? {
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let Some(binary) = shell_copy(&root)? else {
            fs::remove_dir_all(root)?;
            return Ok(());
        };
        let result = NativeExecution::new()?
            .with_args(vec![
                "-c".to_owned(),
                "grep '^NoNewPrivs:' /proc/self/status".to_owned(),
            ])
            .execute(&binary)?;
        assert_eq!(String::from_utf8(result.stdout)?.trim(), "NoNewPrivs:\t1");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn missing_quarantine_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("missing-quarantine")?;
        let binary = root.join("native");
        fs::write(&binary, b"not executed")?;
        let result = verify_platform_quarantine(&binary);
        assert!(matches!(
            result,
            Err(ExecError::NativeQuarantineMissing { .. } | ExecError::NativeQuarantine { .. })
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn incompatible_architecture_is_refused() {
        let info = ExecutableInfo {
            format: ExecutableFormat::Pe,
            architecture: Architecture::X86_64,
            bits: Bitness::Bits64,
            linking: Linking::Dynamic,
            interpreter: None,
            dependencies: Vec::new(),
            signed: false,
        };
        let result = execute_native(
            Path::new("/no/such/binary"),
            &[],
            &info,
            &ReleasePolicy::default(),
        );
        assert!(matches!(
            result,
            Err(ExecError::IncompatibleNativeExecutable)
        ));
    }
}
