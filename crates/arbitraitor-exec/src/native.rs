//! Native executable launch support.
//!
//! Native execution is an explicit opt-in path for already released binaries.
//! The caller remains responsible for using the safe release machinery first;
//! this module fail-closes unless platform quarantine/provenance metadata is
//! present on the released inode immediately before spawn.

use std::ffi::{CString, OsStr};
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use arbitraitor_artifact::executable::{ExecutableInfo, is_compatible};
use arbitraitor_model::ids::{ArtifactId, OperationId, Sha256Digest};
use arbitraitor_model::operation::{
    CapabilityGrant, GrantedCapabilities, OperationPlan, OperationState, OperationType,
};
use arbitraitor_model::verdict::AssuranceLevel;
use arbitraitor_sandbox::SandboxConfig;
use arbitraitor_store::ContentStore;
use rustix::fs::{XattrFlags, fgetxattr, fsetxattr};
use tracing::debug;

use crate::release::ReleasePolicy;
use crate::{ExecError, ExecutionContext, ExecutionContextBuilder, ResourceLimits};

const LINUX_ORIGIN_XATTR: &str = "user.xdg.origin.url";
const LINUX_ORIGIN_VALUE: &[u8] = b"arbitraitor://native-execution";
/// Mode for the materialized binary while quarantine xattrs are applied: owner
/// read + write so the provenance attribute can be set.
const MATERIALIZE_WRITABLE_MODE: u32 = 0o600;
/// Final mode for the materialized binary: owner read + execute, no write, so
/// the child cannot modify its own binary.
const EXECUTABLE_MODE: u32 = 0o500;

/// Capability marker that must be presented to execute a native binary.
///
/// Constructing this value is the explicit opt-in to native execution. The CLI
/// builds one only after confirming a user-supplied `--native` flag. Passing it
/// to [`execute_native`] documents, at the type level, that the caller has
/// authorized running an untrusted binary directly rather than through the
/// mediated interpreter path. Accidental native execution is impossible without
/// a `NativeExecutionGate::new()` call site, which is trivially auditable.
#[derive(Clone, Copy, Debug)]
pub struct NativeExecutionGate(());

impl NativeExecutionGate {
    /// Constructs the native-execution opt-in marker.
    ///
    /// Only call this after verifying an explicit user/CLI opt-in (for example
    /// `--native`). There is intentionally no `Default` impl so that every
    /// opt-in site is a visible `NativeExecutionGate::new()` call.
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self(())
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

    /// Executes a native binary bound to a verified content-addressed artifact.
    ///
    /// The binary is sourced exclusively from `store`: `digest` is re-verified
    /// against the stored bytes, then the verified bytes are materialized to a
    /// private executable temporary file (CAS objects are stored `0600` and are
    /// not executable; `fexecve` would require `unsafe` which this crate
    /// forbids). Quarantine/provenance attributes are applied and verified on
    /// the materialized inode immediately before spawn, and sandbox hardening,
    /// fenced resource limits, and a capped output read are applied to the
    /// child.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError`] when CAS verification fails, materialization
    /// fails, quarantine cannot be applied and verified, spawning fails,
    /// resource limits cannot be applied, or output collection fails.
    pub fn execute(
        &self,
        store: &ContentStore,
        digest: &Sha256Digest,
    ) -> Result<crate::ExecutionResult, ExecError> {
        let handle = store.get(digest).map_err(|source| ExecError::Store {
            reason: source.to_string(),
        })?;
        let (dir, binary_path) = materialize_executable(&handle)?;

        reject_privilege_elevation(&binary_path, &self.args)?;
        apply_platform_quarantine(&binary_path)?;
        verify_platform_quarantine(&binary_path)?;
        make_executable(&binary_path)?;

        let mut command = Command::new(&binary_path);
        command.args(&self.args);
        command.env_clear();
        command.envs(self.environment.environment_iter());
        command.current_dir(self.environment.working_dir());
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        arbitraitor_sandbox::configure_command(&mut command, self.sandbox);

        debug!(binary = %binary_path.display(), "spawning native binary");
        let mut child = command
            .spawn()
            .map_err(|source| ExecError::Spawn { source })?;
        crate::spawn::apply_limits_fenced(&mut child, &self.resource_limits)?;
        let limit = self
            .resource_limits
            .output_size_bytes
            .unwrap_or(crate::spawn::DEFAULT_OUTPUT_LIMIT);
        let (exit_code, stdout, stderr) = crate::spawn::read_with_limit(&mut child, limit)?;
        // The materialized binary is cleaned up when `dir` drops here; the
        // child has already been reaped by read_with_limit.
        drop(dir);
        Ok(crate::ExecutionResult {
            exit_code,
            stdout,
            stderr,
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
/// (for example `--native`). The [`NativeExecutionGate`] parameter makes the
/// opt-in audible at the type level: there is no path to native execution
/// without a `NativeExecutionGate::new()` call site. The function verifies
/// executable host compatibility, binds the binary to the content-addressed
/// store via `digest`, and runs it with controlled environment, sandbox
/// hardening, fenced resource limits, and capped output.
///
/// # Errors
///
/// Returns [`ExecError::IncompatibleNativeExecutable`] when `exec_info` is not
/// compatible with the current host, or another [`ExecError`] from CAS
/// verification, context construction, or execution.
pub fn execute_native(
    _gate: &NativeExecutionGate,
    store: &ContentStore,
    digest: &Sha256Digest,
    args: &[String],
    exec_info: &ExecutableInfo,
    _policy: &ReleasePolicy,
) -> Result<crate::ExecutionResult, ExecError> {
    if !is_compatible(exec_info) {
        return Err(ExecError::IncompatibleNativeExecutable);
    }
    NativeExecution::new()?
        .with_args(args.to_vec())
        .execute(store, digest)
}

/// Materializes verified CAS bytes into a private executable temporary file.
///
/// Returns the temporary directory guard (which removes the file on drop) and
/// the path to the executable. The mode is `0500`: owner read + execute, no
/// write, so the child cannot modify its own binary.
fn materialize_executable(
    handle: &arbitraitor_store::ArtifactHandle,
) -> Result<(crate::OwnedTempDir, PathBuf), ExecError> {
    use std::os::unix::fs::PermissionsExt as StdPermissionsExt;
    let dir = crate::create_temporary_directory()?;
    let path = dir.path().join("native-binary");
    let mut output = fs::File::create(&path).map_err(|source| ExecError::NativeQuarantine {
        stage: "create-native-materialize",
        source,
    })?;
    let mut reader = handle
        .read()
        .try_clone()
        .map_err(|source| ExecError::NativeQuarantine {
            stage: "clone-cas-handle",
            source,
        })?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|source| ExecError::NativeQuarantine {
            stage: "rewind-cas-handle",
            source,
        })?;
    let copied =
        std::io::copy(&mut reader, &mut output).map_err(|source| ExecError::NativeQuarantine {
            stage: "copy-cas-to-materialize",
            source,
        })?;
    if copied != handle.size() {
        return Err(ExecError::NativeQuarantine {
            stage: "short-read-cas-handle",
            source: std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "materialized bytes do not match the verified artifact size",
            ),
        });
    }
    output
        .flush()
        .map_err(|source| ExecError::NativeQuarantine {
            stage: "flush-materialize",
            source,
        })?;
    // Writable while quarantine/provenance xattrs are applied; execute bit is
    // added in `execute` after verification.
    fs::set_permissions(&path, fs::Permissions::from_mode(MATERIALIZE_WRITABLE_MODE)).map_err(
        |source| ExecError::NativeQuarantine {
            stage: "chmod-materialize-writable",
            source,
        },
    )?;
    Ok((dir, path))
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

fn make_executable(path: &Path) -> Result<(), ExecError> {
    use std::os::unix::fs::PermissionsExt as StdPermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(EXECUTABLE_MODE)).map_err(|source| {
        ExecError::NativeQuarantine {
            stage: "chmod-materialize-executable",
            source,
        }
    })
}

fn rustix_to_io(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
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

    async fn store_binary(
        store: &ContentStore,
        source: &str,
    ) -> Result<Option<Sha256Digest>, Box<dyn std::error::Error>> {
        let path = Path::new(source);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path)?;
        let mut sink = store.sink(None)?;
        sink.write_chunk(&bytes).await?;
        Ok(Some(sink.finish().await?))
    }

    #[tokio::test]
    async fn executes_simple_native_binary() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("echo")?;
        if !xattrs_supported(&root)? {
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let store = ContentStore::open(&root.join("store"))?;
        let Some(digest) = store_binary(&store, "/bin/echo").await? else {
            fs::remove_dir_all(root)?;
            return Ok(());
        };
        let result = NativeExecution::new()?
            .with_args(vec!["hello".to_owned()])
            .execute(&store, &digest)?;
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout, b"hello\n");
        assert!(result.stderr.is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn native_environment_is_controlled() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("env")?;
        if !xattrs_supported(&root)? {
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let store = ContentStore::open(&root.join("store"))?;
        let Some(digest) = store_binary(&store, "/bin/sh").await? else {
            fs::remove_dir_all(root)?;
            return Ok(());
        };
        let result = NativeExecution::new()?
            .with_args(vec!["-c".to_owned(), "env -0".to_owned()])
            .execute(&store, &digest)?;
        let stdout = String::from_utf8(result.stdout)?;
        assert!(stdout.contains("PATH="));
        assert!(stdout.contains("HOME="));
        assert!(!stdout.contains("CARGO="));
        assert!(!stdout.contains("LD_PRELOAD="));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn native_resource_limits_are_applied() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("limits")?;
        if !xattrs_supported(&root)? {
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let store = ContentStore::open(&root.join("store"))?;
        let Some(digest) = store_binary(&store, "/bin/sh").await? else {
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
            .execute(&store, &digest)?;
        assert_eq!(String::from_utf8(result.stdout)?.trim(), "32");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn native_sandbox_sets_no_new_privs() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("sandbox")?;
        if !Path::new("/proc/self/status").exists() || !xattrs_supported(&root)? {
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let store = ContentStore::open(&root.join("store"))?;
        let Some(digest) = store_binary(&store, "/bin/sh").await? else {
            fs::remove_dir_all(root)?;
            return Ok(());
        };
        let result = NativeExecution::new()?
            .with_args(vec![
                "-c".to_owned(),
                "grep '^NoNewPrivs:' /proc/self/status".to_owned(),
            ])
            .execute(&store, &digest)?;
        assert_eq!(String::from_utf8(result.stdout)?.trim(), "NoNewPrivs:\t1");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn native_execute_refuses_absent_digest() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("absent")?;
        let store = ContentStore::open(&root.join("store"))?;
        let absent = Sha256Digest::new([0xaa; 32]);
        let result = NativeExecution::new()?.execute(&store, &absent);
        assert!(
            matches!(result, Err(ExecError::Store { .. })),
            "absent digest must be rejected, got {result:?}"
        );
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

    #[tokio::test]
    async fn incompatible_architecture_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("incompatible")?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = Sha256Digest::new([0xbb; 32]);
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
            &NativeExecutionGate::new(),
            &store,
            &digest,
            &[],
            &info,
            &ReleasePolicy::default(),
        );
        assert!(matches!(
            result,
            Err(ExecError::IncompatibleNativeExecutable)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
