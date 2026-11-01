//! Native executable launch support.
//!
//! Native execution is an explicit opt-in path for already released binaries.
//! The caller remains responsible for using the safe release machinery first;
//! this module fail-closes unless platform quarantine/provenance metadata is
//! present on the released inode immediately before spawn.

use std::ffi::{CString, OsStr};
use std::fs;
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use arbitraitor_artifact::executable::{ExecutableInfo, is_compatible};
use arbitraitor_model::ids::{ArtifactId, OperationId, Sha256Digest};
use arbitraitor_model::operation::{
    CapabilityGrant, GrantedCapabilities, OperationPlan, OperationState, OperationType,
};
use arbitraitor_model::verdict::AssuranceLevel;
use arbitraitor_sandbox::SandboxConfig;
use arbitraitor_sandbox::{
    PathRule, ProcessResourceLimits, configure_filesystem_isolation, configure_resource_limits,
};
use rustix::fs::{XattrFlags, fgetxattr, fgetxattr_query, fsetxattr};
use tracing::debug;

use crate::script::{UNSHARE_NETWORK_ARGS, UNSHARE_PATH, unshare_wrapper_proc_rules};
use crate::{
    ExecError, ExecutionContext, ExecutionContextBuilder, ExecutionPolicy, ResourceLimits,
};

const LINUX_ORIGIN_XATTR: &str = "user.xdg.origin.url";
const LINUX_ORIGIN_VALUE: &[u8] = b"arbitraitor://native-execution";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const MACOS_QUARANTINE_XATTR: &str = "com.apple.quarantine";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const MACOS_QUARANTINE_VALUE: &[u8] = b"0081;5f123456;arbitraitor;";

/// Platform provenance preservation result (ADR-0010).
///
/// Records which platform-native provenance attributes were applied
/// during release. On Linux this is xattr; on macOS it's quarantine;
/// on Windows it's Mark of the Web (Zone.Identifier).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PlatformProvenance {
    /// Linux xattr was applied (Linux only).
    pub linux_xattr_applied: bool,
    /// macOS quarantine was applied (macOS only).
    pub macos_quarantine_applied: bool,
    /// Windows MOTW was applied (Windows only).
    pub windows_motw_applied: bool,
}

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
    /// Whether the child's network must be denied (the mediated default).
    ///
    /// Defaults to `true`, matching the `network_allowed: false` the operation
    /// plan and the derived [`ExecutionContext`] declare. Enforced on Linux by
    /// re-executing the binary inside `unshare --user --map-current-user
    /// --net` (see [`NativeExecution::program_command`]); there is no state in
    /// which the plan claims denial and the child keeps an interface.
    network_isolated: bool,
    /// Absolute path of the `unshare` wrapper.
    ///
    /// A field rather than a bare constant so tests can prove the fail-closed
    /// path (missing wrapper, wrapper that refuses) without an environment
    /// override that would double as an isolation bypass.
    unshare_path: PathBuf,
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

    /// Selects whether the child's network is denied (default: denied).
    ///
    /// Passing `false` explicitly lowers assurance: the operation plan this
    /// execution builds still declares `network_allowed: false`, so callers may
    /// only do this when the user has explicitly opted into network access
    /// (`arbitraitor run --network`, i.e. `--sandbox none`).
    #[must_use]
    pub fn with_network_isolated(mut self, isolated: bool) -> Self {
        self.network_isolated = isolated;
        self
    }

    /// Returns whether the child's network is denied.
    #[must_use]
    pub fn network_isolated(&self) -> bool {
        self.network_isolated
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

        let mut command = self.program_command(binary_path)?;
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
        let fs_rules = landlock_rules_for_native(
            binary_path,
            self.environment.working_dir(),
            self.environment.home_dir(),
            self.network_isolated,
        );
        configure_filesystem_isolation(&mut command, &fs_rules);

        // Put the child in its own process group so the wall-clock watchdog
        // can kill the binary and any children it spawns with a single
        // group kill (mirrors the script/PowerShell paths; spec §9).
        command.process_group(0);

        debug!(
            binary = %binary_path.display(),
            network_isolated = self.network_isolated,
            "spawning native binary"
        );
        let mut child = command
            .spawn()
            .map_err(|source| self.spawn_failure(source))?;
        // Arm the wall-clock watchdog so the deadline covers the whole
        // child lifetime (the same fence the script/PowerShell paths
        // enforce; RLIMIT_CPU cannot bound a child that sleeps or blocks
        // on I/O).
        let watchdog = crate::spawn::arm_wall_clock(
            rustix::process::Pid::from_child(&child),
            self.resource_limits.wall_clock_secs,
        );
        // Collect output through the same deadline-aware, output-capped
        // collector the script path uses: `wait_with_output` would wait for
        // EOF on the inherited pipes, so a setsid descendant holding a
        // write-end could keep this parent blocked past the deadline and
        // `WallClockExpired` could never be produced. The output cap is
        // still enforced by the collector.
        let output_limit = self
            .resource_limits
            .output_size_bytes
            .unwrap_or(crate::spawn::DEFAULT_OUTPUT_LIMIT);
        let (exit_code, stdout, stderr) =
            crate::spawn::read_with_limit(&mut child, output_limit, watchdog)?;
        Ok(crate::ExecutionResult {
            exit_code,
            stdout,
            stderr,
        })
    }

    fn with_args_checked(args: Vec<String>) -> Result<Self, ExecError> {
        let environment = ExecutionContextBuilder::new(operation_plan(&args), execute_grants())
            .assurance_level(AssuranceLevel::Mediated)
            .command("/bin/true")
            .arguments(args.iter().map(String::as_str))
            .build()?;
        Ok(Self {
            args,
            environment,
            resource_limits: ResourceLimits::default(),
            sandbox: SandboxConfig::default(),
            network_isolated: true,
            unshare_path: PathBuf::from(UNSHARE_PATH),
        })
    }

    /// Builds the command that spawns the released binary.
    ///
    /// When network denial is in force the binary is re-executed through
    /// `unshare --user --map-current-user --net --`, the same wrapper the
    /// mediated script path has used since #754. The wrapper is a child of the
    /// hooks registered on this `Command`, so every other control still holds
    /// across its `execve`: `pre_exec` resource limits, `no_new_privs`,
    /// `dumpable=0`, inherited-descriptor closure and the Landlock domain are
    /// all inherited, the wrapper then creates an empty network namespace, and
    /// it `exec`s the binary in the same process (no `--fork`, so the pid,
    /// process group, stdio pipes and exit status are the binary's own).
    ///
    /// There is deliberately no fallback: if the wrapper is missing or cannot
    /// create the namespaces, it exits non-zero without ever `exec`ing the
    /// binary, and the run reports that failure instead of an uncontained
    /// success (issue #842).
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::NetworkIsolationUnavailable`] when network denial is
    /// in force and the wrapper is not installed, *before* anything is forked.
    /// The check cannot be left to spawn failure alone: the sandbox's fd-closure
    /// hook ([`SandboxConfig::close_fds`]) closes the error pipe `std` uses to
    /// report a failed `execve`, so a missing program looks to the parent like a
    /// child that started and then died from `SIGABRT`. That is still
    /// fail-closed (the binary never runs and the run is reported as failed),
    /// but an untyped signal is not an actionable refusal. A wrapper that exists
    /// but cannot be executed falls through to that same fail-closed signal.
    fn program_command(&self, binary_path: &Path) -> Result<Command, ExecError> {
        if self.network_isolated {
            if !self.unshare_path.is_file() {
                return Err(ExecError::NetworkIsolationUnavailable {
                    reason: format!(
                        "network-namespace wrapper {} is not installed",
                        self.unshare_path.display()
                    ),
                });
            }
            let mut command = Command::new(&self.unshare_path);
            command.args(UNSHARE_NETWORK_ARGS);
            command.arg(binary_path);
            command.args(&self.args);
            Ok(command)
        } else {
            let mut command = Command::new(binary_path);
            command.args(&self.args);
            Ok(command)
        }
    }

    /// Maps a spawn failure to the error the caller must see.
    ///
    /// A failed `unshare` spawn is a containment refusal, not an ordinary
    /// execution error: the binary was never started, and the caller's plan
    /// promised network denial. Naming the wrapper keeps the refusal
    /// actionable.
    ///
    /// Best-effort by nature: the fd-closure hook closes the pipe `std` reports
    /// a failed `execve` through, so most exec failures surface as a
    /// signal-death result instead of reaching here. The missing-wrapper case —
    /// the one that matters for #842 — is caught earlier and typed by
    /// [`NativeExecution::program_command`].
    fn spawn_failure(&self, source: std::io::Error) -> ExecError {
        if self.network_isolated {
            ExecError::NetworkIsolationUnavailable {
                reason: format!(
                    "network-namespace wrapper {} could not be executed: {source}",
                    self.unshare_path.display()
                ),
            }
        } else {
            ExecError::Spawn { source }
        }
    }
}

/// Returns the typed refusal when native network isolation cannot be enforced
/// on this host, or `None` when the wrapper works.
///
/// This is the capability probe a caller should run *before* requesting
/// approval or releasing the binary (spec §27.7, ADR-0007's "capability probe"
/// row): it spawns `/bin/true` through the exact wrapper arguments used at
/// execution time. A wrapper that is not installed, cannot be executed, or
/// cannot create the user+network namespaces (unprivileged user namespaces
/// disabled, kernel or LSM restriction) is reported as unavailable instead of
/// being discovered after the approval record already bound
/// `network:isolated`.
///
/// The probe is deliberately advisory: [`NativeExecution::execute`] still
/// fails closed on its own, so a probe that passes on a host that then refuses
/// the namespace cannot produce an unconfined run.
#[must_use]
pub fn native_network_isolation_refusal() -> Option<ExecError> {
    if !Path::new(UNSHARE_PATH).is_file() {
        return Some(ExecError::NetworkIsolationUnavailable {
            reason: format!("network-namespace wrapper {UNSHARE_PATH} is not installed"),
        });
    }
    let probe = Command::new(UNSHARE_PATH)
        .args(UNSHARE_NETWORK_ARGS)
        .arg("/bin/true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match probe {
        Ok(status) if status.success() => None,
        Ok(status) => Some(ExecError::NetworkIsolationUnavailable {
            reason: format!(
                "{UNSHARE_PATH} could not create a user and network namespace \
                 (probe exited {status})"
            ),
        }),
        Err(source) => Some(ExecError::NetworkIsolationUnavailable {
            reason: format!("{UNSHARE_PATH} could not be executed: {source}"),
        }),
    }
}

/// Enforces explicit approval before native execution.
///
/// # Errors
///
/// Returns [`ExecError::NativeExecutionNotApproved`] unless either the caller
/// supplies verified native approval or trusted policy allows native execution.
pub fn require_native_approval(
    native_approved: bool,
    policy: &ExecutionPolicy,
) -> Result<(), ExecError> {
    if native_approved || policy.allow_native_execution {
        Ok(())
    } else {
        Err(ExecError::NativeExecutionNotApproved)
    }
}

/// Explicit native opt-in helper for released binaries.
///
/// The caller must supply verified native approval (for example, from the
/// `--native` flag or a plan-bound approval capability), or trusted execution
/// policy must explicitly allow native execution. The function then verifies
/// executable host compatibility, applies and verifies quarantine/provenance
/// attributes, and runs the binary with controlled environment, sandbox
/// hardening, resource limits, and network denial ([`NativeExecution`]'s
/// default; use it directly with
/// [`NativeExecution::with_network_isolated`] to lower that assurance).
///
/// # Errors
///
/// Returns [`ExecError::NativeExecutionNotApproved`] when neither the caller nor
/// trusted policy approves native execution,
/// [`ExecError::IncompatibleNativeExecutable`] when `exec_info` is not compatible
/// with the current host,
/// [`ExecError::NetworkIsolationUnavailable`] when network denial cannot be
/// enforced on this host, or another [`ExecError`] from context construction or
/// execution.
pub fn execute_native(
    binary_path: &Path,
    args: &[String],
    exec_info: &ExecutableInfo,
    native_approved: bool,
    policy: &ExecutionPolicy,
) -> Result<crate::ExecutionResult, ExecError> {
    require_native_approval(native_approved, policy)?;
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
    })?;
    #[cfg(target_os = "macos")]
    {
        apply_macos_quarantine(binary_path)?;
    }
    #[cfg(target_os = "windows")]
    {
        apply_windows_motw(binary_path)?;
    }
    Ok(())
}

/// Applies macOS quarantine xattr (ADR-0010).
///
/// On macOS, downloaded files receive `com.apple.quarantine` to trigger
/// Gatekeeper checks. Arbitraitor sets this so files released through it
/// are treated with the same scrutiny as browser-downloaded files.
#[cfg(target_os = "macos")]
fn apply_macos_quarantine(binary_path: &Path) -> Result<(), ExecError> {
    let file = fs::File::options()
        .read(true)
        .write(true)
        .open(binary_path)
        .map_err(|source| ExecError::NativeQuarantine {
            stage: "open-macos-quarantine",
            source,
        })?;
    let name = xattr_name(MACOS_QUARANTINE_XATTR, "prepare-macos-quarantine")?;
    fsetxattr(
        file.as_fd(),
        name.as_c_str(),
        MACOS_QUARANTINE_VALUE,
        XattrFlags::empty(),
    )
    .map_err(|source| ExecError::NativeQuarantine {
        stage: "set-macos-quarantine",
        source: rustix_to_io(source),
    })
}

/// Applies Windows Mark of the Web (ADR-0010).
///
/// On Windows, downloaded files receive a Zone.Identifier alternate data
/// stream marking them as from the internet (Zone 3). This triggers
/// SmartScreen checks. The implementation uses NTFS ADS via the Windows API.
#[cfg(target_os = "windows")]
fn apply_windows_motw(binary_path: &Path) -> Result<(), ExecError> {
    // Windows MOTW is implemented via NTFS alternate data streams.
    // The Zone.Identifier ADS contains INI-format zone data.
    // Zone 3 = Internet (downloaded from the internet).
    let motw_path = binary_path.join(":Zone.Identifier");
    fs::write(&motw_path, "[ZoneTransfer]\nZoneId=3\n").map_err(|source| {
        ExecError::NativeQuarantine {
            stage: "set-windows-motw",
            source,
        }
    })
}

fn verify_platform_quarantine(binary_path: &Path) -> Result<(), ExecError> {
    let file = fs::File::open(binary_path).map_err(|source| ExecError::NativeQuarantine {
        stage: "open-native-for-quarantine-verify",
        source,
    })?;
    let name = xattr_name(LINUX_ORIGIN_XATTR, "prepare-linux-origin-xattr-verify")?;
    // rustix 1.1.6 stopped treating a zero-length buffer as a size query, so the
    // size has to be asked for explicitly. An empty value is still treated as a
    // missing quarantine marker below, which keeps this check fail-closed.
    let size = match fgetxattr_query(file.as_fd(), name.as_c_str()) {
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

fn landlock_rules_for_native(
    binary_path: &Path,
    working_dir: &Path,
    home_dir: &Path,
    network_isolated: bool,
) -> Vec<PathRule> {
    let mut rules = Vec::new();

    if let Some(parent) = binary_path.parent() {
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

    // The `unshare --map-current-user` wrapper writes its user-namespace
    // identity mapping through `/proc/self` before executing the binary. The
    // grant is per-file, write-only, and gated on the same condition that
    // selects the wrapper, so a non-isolated run receives no `/proc` access
    // (mirrors the mediated script path, #754).
    if network_isolated {
        rules.extend(unshare_wrapper_proc_rules());
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use arbitraitor_artifact::executable::{Architecture, Bitness, ExecutableFormat, Linking};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    /// Probe configuration file, written by the parent into the mediated
    /// working directory and read by the re-executed probe from its cwd. The
    /// mediated environment carries no custom variables, so argv/env cannot
    /// deliver the port.
    const PROBE_CONFIG: &str = "native-net-probe.config";
    /// libtest path of the probe inside this crate's unit-test binary.
    const PROBE_NAME: &str = "native::tests::native_network_probe";
    /// Negative-assertion window: how long a listener is watched for a
    /// connection that must never arrive.
    const SILENCE_WINDOW: Duration = Duration::from_millis(500);
    /// Budget for a positive event (an accepted control-arm connection).
    const CONNECT_WINDOW: Duration = Duration::from_secs(5);
    /// Poll interval for deadline-bounded waits. Never used as a bare sleep.
    const POLL_INTERVAL: Duration = Duration::from_millis(5);

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

    fn copy_executable(source: &Path, root: &Path, name: &str) -> io::Result<Option<PathBuf>> {
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
        copy_executable(Path::new("/bin/sh"), root, "native-sh")
    }

    #[test]
    fn executes_simple_native_binary() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("echo")?;
        if !xattrs_supported(&root)? {
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let Some(binary) = copy_executable(Path::new("/bin/echo"), &root, "native-echo")? else {
            fs::remove_dir_all(root)?;
            return Ok(());
        };
        // These controls are independent of network denial; opt out of the
        // wrapper so the assertion does not depend on host user-namespace
        // support. The network arms live in the `native_network_*` tests.
        let result = NativeExecution::new()?
            .with_network_isolated(false)
            .with_args(vec!["hello".to_owned()])
            .execute(&binary)?;
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout, b"hello\n");
        assert_eq!(result.stderr, [] as [u8; 0]);
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
            .with_network_isolated(false)
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
            wall_clock_secs: None,
        };
        let result = NativeExecution::new()?
            .with_network_isolated(false)
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
            wall_clock_secs: None,
        };
        let result = NativeExecution::new()?
            .with_network_isolated(false)
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
            .with_network_isolated(false)
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

    /// Writes an explicit skip marker for a host-dependent branch.
    ///
    /// A bare early return would be a silent pass (spec §43.8: "skip with an
    /// explicit marker — never a silent pass"). `clippy::print_stderr` is
    /// denied workspace-wide, so the marker is written directly.
    fn skip_marker(reason: &str) {
        use std::io::Write as _;
        let _ = writeln!(io::stderr(), "NATIVE-NET SKIP: {reason}");
    }

    fn probe_args() -> Vec<String> {
        vec![
            "--ignored".to_owned(),
            "--exact".to_owned(),
            PROBE_NAME.to_owned(),
            "--nocapture".to_owned(),
            "--test-threads=1".to_owned(),
        ]
    }

    /// Copies this unit-test binary into `root` so it can be released and
    /// executed through the native path like any other artifact.
    fn copy_current_exe(root: &Path) -> io::Result<PathBuf> {
        let source = std::env::current_exe()?;
        let destination = root.join("native-net-probe");
        fs::copy(&source, &destination)?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;
        Ok(destination)
    }

    /// Writes the probe's port into the mediated working directory (the probe's
    /// cwd, and the only channel available: the mediated environment carries no
    /// custom variables and argv belongs to libtest).
    fn write_probe_config(working_dir: &Path, port: u16) -> io::Result<()> {
        fs::write(working_dir.join(PROBE_CONFIG), format!("port={port}\n"))
    }

    /// Parses the probe's `KEY=value` evidence out of the captured stderr.
    ///
    /// Stderr, not a file in the mediated working directory: that directory is
    /// owned by the `ExecutionContext` and removed when it drops, which happens
    /// as soon as the `NativeExecution` temporary returned by `with_args` goes
    /// out of scope. The captured pipe is read before that and survives it.
    fn probe_report(stderr: &[u8]) -> BTreeMap<String, String> {
        let mut values = BTreeMap::new();
        for line in String::from_utf8_lossy(stderr).lines() {
            if let Some((key, value)) = line.split_once('=') {
                let _previous = values.insert(key.trim().to_owned(), value.trim().to_owned());
            }
        }
        values
    }

    /// True when the payload ran: the probe always records this before the
    /// connect attempt, so its absence means the binary never started.
    fn probe_ran(stderr: &[u8]) -> bool {
        probe_report(stderr).contains_key("PROBE_ALIVE")
    }

    fn report_int(
        report: &BTreeMap<String, String>,
        key: &str,
    ) -> Result<i32, Box<dyn std::error::Error>> {
        let raw = report
            .get(key)
            .ok_or_else(|| format!("probe report is missing `{key}`: {report:?}"))?;
        raw.parse::<i32>().map_err(|error| {
            format!("probe report key `{key}` is not an integer: {raw:?} ({error})").into()
        })
    }

    /// Asserts the host listener never accepted a connection within
    /// [`SILENCE_WINDOW`]. The forbidden *effect* is what is pinned here, not
    /// the child's exit status.
    fn assert_no_connection(
        listener: &TcpListener,
        label: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + SILENCE_WINDOW;
        loop {
            match listener.accept() {
                Ok(_) => {
                    return Err(format!(
                        "{label}: a network-isolated native child reached the host listener"
                    )
                    .into());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Ok(());
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Waits until the listener accepts one connection and returns the bytes
    /// the child sent, or fails after [`CONNECT_WINDOW`].
    fn accept_payload(
        listener: &TcpListener,
        label: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use std::io::Read as _;

        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + CONNECT_WINDOW;
        loop {
            match listener.accept() {
                Ok((mut stream, _address)) => {
                    let mut bytes = Vec::new();
                    let _read = stream.read_to_end(&mut bytes)?;
                    return Ok(bytes);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "{label}: the control arm never connected within {CONNECT_WINDOW:?}"
                        )
                        .into());
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Probe entry point: dials the loopback listener named in
    /// [`PROBE_CONFIG`] from inside a released native binary and records what
    /// happened.
    ///
    /// `#[ignore]`d on purpose: it is only meaningful under the hooks the
    /// `native_network_*` parents install. Run standalone it has no config and
    /// fails, which is why no runner executes it.
    #[test]
    #[ignore = "probe entry point; re-executed by the native network isolation tests"]
    fn native_network_probe() -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;
        use std::net::SocketAddr;

        let config = fs::read_to_string(std::env::current_dir()?.join(PROBE_CONFIG))?;
        let port: u16 = config
            .lines()
            .find_map(|line| line.strip_prefix("port="))
            .ok_or("probe config has no `port=` line")?
            .parse()?;

        let mut report = io::stderr();
        // Recorded before the connect attempt: the parent treats
        // `PROBE_ALIVE` as proof that the probe process itself ran, so a
        // denial can never be mistaken for a broken payload.
        writeln!(report, "PROBE_ALIVE=1")?;

        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        match TcpStream::connect_timeout(&address, Duration::from_secs(2)) {
            Ok(mut stream) => {
                writeln!(report, "PROBE_CONNECT=0")?;
                let _written = stream.write_all(b"ping");
            }
            Err(error) => {
                writeln!(
                    report,
                    "PROBE_CONNECT_ERRNO={}",
                    error.raw_os_error().unwrap_or(-1)
                )?;
            }
        }
        Ok(())
    }

    /// Denial arm (issue #842): a native execution whose plan denies network
    /// must not reach a loopback listener on the host, while the same binary
    /// demonstrably runs and writes.
    ///
    /// The assertion is on the *effect*: the probe's `connect(2)` errno and the
    /// host listener receiving nothing. Exit status alone is never the
    /// evidence. On a host where unprivileged user namespaces are unavailable
    /// the wrapper cannot exist at all, so the test asserts the fail-closed
    /// outcome instead of skipping silently — and says so with a marker.
    #[test]
    fn native_network_isolation_denies_loopback_connect() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = temp_root("net-deny")?;
        if !xattrs_supported(&root)? {
            skip_marker("host filesystem cannot hold the quarantine xattr; no execution possible");
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let binary = copy_current_exe(&root)?;
        let execution = NativeExecution::new()?.with_network_isolated(true);
        let working_dir = execution.environment().working_dir().to_path_buf();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        write_probe_config(&working_dir, port)?;

        let result = execution.with_args(probe_args()).execute(&binary);

        if native_network_isolation_refusal().is_some() {
            // Explicit marker: the denial assertion needs a host that can
            // create the namespace. The available assertion is that the
            // requested control failing closed never runs the binary.
            skip_marker(
                "unprivileged user namespaces are unavailable; asserting fail-closed refusal",
            );
            let fail_closed = match &result {
                Err(_) => true,
                Ok(output) => output.exit_code != Some(0),
            };
            assert!(
                fail_closed,
                "native execution reported success although the network wrapper cannot run: {result:?}"
            );
            if let Ok(output) = &result {
                assert!(
                    !probe_ran(&output.stderr),
                    "the probe ran although network isolation could not be installed: stderr {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            assert_no_connection(&listener, "denial (wrapper unavailable)")?;
            fs::remove_dir_all(root)?;
            return Ok(());
        }

        let output = match result {
            Ok(output) => output,
            Err(error) => {
                return Err(format!(
                    "network-isolated native execution failed instead of denying the connect: {error}"
                )
                .into());
            }
        };
        let report = probe_report(&output.stderr);
        assert_eq!(
            report.get("PROBE_ALIVE").map(String::as_str),
            Some("1"),
            "the probe never recorded that it ran; stdout {:?} stderr {:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let errno = report_int(&report, "PROBE_CONNECT_ERRNO")?;
        assert!(
            matches!(
                errno,
                libc::ENETUNREACH
                    | libc::EHOSTUNREACH
                    | libc::ENETDOWN
                    | libc::EADDRNOTAVAIL
                    | libc::ECONNREFUSED
                    | libc::EACCES
                    | libc::EPERM
            ),
            "isolated native child connected or failed for a non-network reason: errno {errno}"
        );
        assert_no_connection(&listener, "denial")?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    /// Control arm (mandatory non-vacuity proof): the *same* probe binary, with
    /// network denial explicitly lowered, connects to the same listener and
    /// delivers the payload.
    ///
    /// Without this arm the denial test could pass because the probe is broken.
    #[test]
    fn native_network_allowed_loopback_connect_succeeds() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = temp_root("net-allow")?;
        if !xattrs_supported(&root)? {
            skip_marker("host filesystem cannot hold the quarantine xattr; no execution possible");
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let binary = copy_current_exe(&root)?;
        let execution = NativeExecution::new()?.with_network_isolated(false);
        let working_dir = execution.environment().working_dir().to_path_buf();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        write_probe_config(&working_dir, port)?;

        let result = execution.with_args(probe_args()).execute(&binary)?;
        assert_eq!(
            result.exit_code,
            Some(0),
            "the probe harness failed; stderr: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report = probe_report(&result.stderr);
        assert_eq!(
            report_int(&report, "PROBE_CONNECT")?,
            0,
            "the probe could not connect even with network access allowed: {report:?}"
        );
        assert_eq!(
            accept_payload(&listener, "control")?,
            b"ping",
            "the control arm connected but delivered no payload"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    /// Failure path (issue #842): a missing `unshare` wrapper must refuse the
    /// run instead of executing the binary unconfined.
    #[test]
    fn native_network_isolation_refuses_when_wrapper_is_missing()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("net-no-wrapper")?;
        if !xattrs_supported(&root)? {
            skip_marker("host filesystem cannot hold the quarantine xattr; no execution possible");
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let binary = copy_current_exe(&root)?;
        let mut execution = NativeExecution::new()?.with_network_isolated(true);
        execution.unshare_path = root.join("absent-unshare");
        let working_dir = execution.environment().working_dir().to_path_buf();
        write_probe_config(&working_dir, 1)?;

        let result = execution.with_args(probe_args()).execute(&binary);

        assert!(
            matches!(result, Err(ExecError::NetworkIsolationUnavailable { .. })),
            "a missing network-namespace wrapper must be a containment refusal: {result:?}"
        );
        if let Ok(output) = &result {
            assert!(
                !probe_ran(&output.stderr),
                "the binary ran although the network-namespace wrapper was missing"
            );
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    /// Failure path (issue #842): a wrapper that runs but cannot create the
    /// namespace (the shape of a host with user namespaces disabled) must exit
    /// non-zero without ever `exec`ing the binary.
    #[test]
    fn native_network_isolation_refuses_when_wrapper_cannot_isolate()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("net-wrapper-fails")?;
        if !xattrs_supported(&root)? {
            skip_marker("host filesystem cannot hold the quarantine xattr; no execution possible");
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let binary = copy_current_exe(&root)?;
        // Stands in for `unshare` on a host where the namespace cannot be
        // created: it exits non-zero without executing its arguments.
        let failing_wrapper = root.join("unshare-that-fails");
        fs::write(&failing_wrapper, b"#!/bin/sh\nexit 1\n")?;
        fs::set_permissions(&failing_wrapper, fs::Permissions::from_mode(0o700))?;
        let mut execution = NativeExecution::new()?.with_network_isolated(true);
        execution.unshare_path = failing_wrapper;
        let working_dir = execution.environment().working_dir().to_path_buf();
        write_probe_config(&working_dir, 1)?;

        let result = execution.with_args(probe_args()).execute(&binary)?;

        assert_ne!(
            result.exit_code,
            Some(0),
            "a failing network-namespace wrapper must not report success"
        );
        assert!(
            !probe_ran(&result.stderr),
            "the binary ran although its network-namespace wrapper failed: stderr {}",
            String::from_utf8_lossy(&result.stderr)
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    /// The wrapper's procfs identity-mapping grants follow the wrapper: a
    /// non-isolated native run must receive no `/proc` access at all.
    #[test]
    fn landlock_rules_grant_wrapper_proc_writes_only_when_isolated() {
        let isolated = landlock_rules_for_native(
            Path::new("/tmp/bin/tool"),
            Path::new("/tmp/work"),
            Path::new("/tmp/home"),
            true,
        );
        let mut missing = Vec::new();
        for path in crate::script::UNSHARE_ID_MAP_FILES {
            match isolated.iter().find(|rule| rule.path == *path) {
                Some(rule) => assert_eq!(
                    rule.access,
                    arbitraitor_sandbox::access_fs::WRITE_FILE,
                    "grant for {path} must be WRITE_FILE-only"
                ),
                None => missing.push(path),
            }
        }
        assert!(
            missing.is_empty(),
            "wrapper procfs write rules missing: {missing:?}"
        );
        let unconfined = landlock_rules_for_native(
            Path::new("/tmp/bin/tool"),
            Path::new("/tmp/work"),
            Path::new("/tmp/home"),
            false,
        );
        assert!(
            unconfined
                .iter()
                .all(|rule| !rule.path.starts_with("/proc")),
            "a non-isolated native run must not receive /proc grants: {unconfined:?}"
        );
    }

    /// The capability probe must agree with reality: it reports unavailable
    /// exactly when the wrapper cannot create a namespace on this host.
    #[test]
    fn network_isolation_probe_reports_a_named_control() {
        match native_network_isolation_refusal() {
            None => assert!(
                unshare_directly_supported(),
                "the probe accepted the wrapper but a direct unshare(1) invocation fails"
            ),
            Some(error) => {
                let message = error.to_string();
                assert!(
                    message.contains("network isolation"),
                    "refusal must name the missing control: {message}"
                );
                assert!(
                    message.contains(UNSHARE_PATH),
                    "refusal must name the wrapper: {message}"
                );
            }
        }
    }

    /// Direct `unshare(1)` check used to cross-check the probe.
    fn unshare_directly_supported() -> bool {
        Command::new(UNSHARE_PATH)
            .args(UNSHARE_NETWORK_ARGS)
            .arg("/bin/true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    #[test]
    fn native_execution_without_approval_is_refused() {
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
            false,
            &crate::ExecutionPolicy::default(),
        );
        assert!(matches!(result, Err(ExecError::NativeExecutionNotApproved)));
    }

    /// Resolves when the `setsid` helper binary is installed, else `Err`
    /// (callers skip the test).
    fn setsid_or_skip() -> Result<&'static str, &'static str> {
        if Path::new("/usr/bin/setsid").exists() {
            Ok("/usr/bin/setsid")
        } else if Path::new("/bin/setsid").exists() {
            Ok("/bin/setsid")
        } else {
            Err("setsid not installed")
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn native_deadline_bounds_setsid_descendant_holding_stdout()
    -> Result<(), Box<dyn std::error::Error>> {
        // Regression test for the CodeRabbit finding: `wait_with_output`
        // waits for pipe EOF, so a setsid descendant inheriting the pipe
        // write-ends would keep `execute` blocked past the deadline and
        // `WallClockExpired` could never be produced. The shared
        // deadline-aware collector must bound the parent.
        let root = temp_root("setsid-deadline")?;
        if !xattrs_supported(&root)? {
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let setsid = setsid_or_skip();
        let Some(binary) = copy_executable(Path::new("/bin/bash"), &root, "native-bash")? else {
            fs::remove_dir_all(root)?;
            return Ok(());
        };
        let Ok(setsid) = setsid
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "setsid not installed"))
        else {
            fs::remove_dir_all(root)?;
            return Ok(());
        };
        let limits = ResourceLimits {
            wall_clock_secs: Some(1),
            ..ResourceLimits::default()
        };
        let started = std::time::Instant::now();
        let result = NativeExecution::new()?
            .with_network_isolated(false)
            .with_resource_limits(limits)
            .with_args(vec![
                "-c".to_owned(),
                format!(
                    // A grandchild in a new session (the group kill cannot
                    // reach it) that inherits and holds the pipe write-ends
                    // forever — no redirect — so only the deadline-aware
                    // drain can bound the parent.
                    "{setsid} sleep 30 &\necho started\nexec sleep 30\n"
                ),
            ])
            .execute(&binary);
        let elapsed = started.elapsed();
        fs::remove_dir_all(root)?;
        match result {
            Err(ExecError::WallClockExpired { limit_secs: 1 }) => {}
            other => {
                return Err(
                    format!("expected WallClockExpired{{limit_secs: 1}}, got {other:?}").into(),
                );
            }
        }
        assert!(
            elapsed < Duration::from_secs(10),
            "native deadline must bound the parent even with an out-of-group pipe holder: {elapsed:?}"
        );
        Ok(())
    }

    #[test]
    fn trusted_policy_native_approval_is_accepted() {
        let policy = crate::ExecutionPolicy {
            allow_native_execution: true,
            ..crate::ExecutionPolicy::default()
        };

        assert!(require_native_approval(false, &policy).is_ok());
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
            true,
            &crate::ExecutionPolicy::default(),
        );
        assert!(matches!(
            result,
            Err(ExecError::IncompatibleNativeExecutable)
        ));
    }
}
