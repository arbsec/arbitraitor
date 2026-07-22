//! Execution broker for approved artifacts.
//!
//! This crate builds mediated execution contexts. It does not spawn child
//! processes and does not apply kernel sandboxing; downstream execution and
//! sandbox crates consume the context produced here.

#![cfg(unix)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use arbitraitor_core::config::ExecutionConfig;
use arbitraitor_model::operation::{GrantedCapabilities, OperationPlan};
use arbitraitor_model::verdict::AssuranceLevel;
use arbitraitor_sandbox::LandlockAbiVersion;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::debug;

pub use arbitraitor_sandbox::SandboxConfig;

#[cfg(target_os = "linux")]
pub mod native;
pub mod powershell;
pub mod release;
pub mod script;
mod spawn;
#[cfg(target_os = "linux")]
pub use native::{NativeExecution, NativeExecutionGate, execute_native, require_native_approval};
#[cfg(target_os = "linux")]
pub use powershell::{PowerShellError, PowerShellExecution, PowerShellPolicy};
#[cfg(target_os = "linux")]
pub use script::{ExecutionResult, ScriptExecution};

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Default `PATH` entries used when policy does not provide a stricter value.
///
/// At runtime, [`ExecutionPolicy::default`] canonicalizes these entries to
/// resolve any system-level symlinks (e.g. `/bin` → `/usr/bin`).
pub const DEFAULT_CONTROLLED_PATH: &str = "/usr/local/bin:/usr/bin";

/// File descriptors inherited by default: stdin, stdout, and stderr.
pub const DEFAULT_KEEP_FDS: [i32; 3] = [0, 1, 2];

/// Errors returned while constructing a mediated execution context.
#[derive(Debug, Error)]
pub enum ExecError {
    /// The current Arbitraitor process is running with elevated privileges.
    #[error("refusing to build execution context while running as root")]
    RunningAsRoot,
    /// Trusted policy did not grant the execute capability.
    #[error("execute capability not granted by trusted policy")]
    ExecuteNotGranted,
    /// Trusted policy did not grant network access requested by execution policy.
    #[error("network capability not granted by trusted policy")]
    NetworkNotGranted,
    /// The command executable is not an absolute path.
    #[error("command must be an absolute path: {command}")]
    CommandNotAbsolute {
        /// Rejected command path.
        command: PathBuf,
    },
    /// The command or one of its arguments attempts privilege elevation.
    #[error("privilege elevation command blocked: {program}")]
    PrivilegeElevationAttempt {
        /// Program or argument that matched a privilege-elevation vector.
        program: String,
    },
    /// An environment variable name is syntactically invalid.
    #[error("invalid environment variable name: {name}")]
    InvalidEnvironmentName {
        /// Invalid variable name.
        name: String,
    },
    /// An allowlisted variable also matched a mandatory deny pattern.
    #[error("environment variable denied by mandatory pattern: {name}")]
    DeniedEnvironmentVariable {
        /// Denied variable name.
        name: String,
    },
    /// The configured PATH is empty.
    #[error("controlled PATH must contain at least one directory")]
    EmptyPath,
    /// A configured PATH entry is relative.
    #[error("controlled PATH entry is not absolute: {path}")]
    RelativePathEntry {
        /// Rejected PATH entry.
        path: PathBuf,
    },
    /// A configured PATH entry is a symlink, not root-owned, world/group-writable, or could not be verified.
    #[error("controlled PATH entry is unsafe or unverified: {path}")]
    UnsafePathEntry {
        /// Rejected PATH entry.
        path: PathBuf,
    },
    /// A fixed execution directory is relative, a symlink, or could not be verified.
    #[error("fixed execution directory is invalid or unsafe: {path}")]
    UnsafeFixedDirectory {
        /// Rejected directory path.
        path: PathBuf,
    },
    /// Temporary HOME or working directory creation failed.
    #[error("failed to create temporary execution directory")]
    TemporaryDirectory {
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
    /// Root detection failed.
    #[error("failed to determine current uid")]
    RootDetection {
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
    /// The interpreter process could not be spawned.
    #[error("failed to spawn interpreter process")]
    Spawn {
        /// Source I/O error from `Command::spawn`.
        #[source]
        source: io::Error,
    },
    /// The interpreter process exit status or captured output could not be collected.
    #[error("failed to collect interpreter process output")]
    Wait {
        /// Source I/O error from `Child::wait_with_output`.
        #[source]
        source: io::Error,
    },
    /// Piping the script bytes to the interpreter's standard input failed.
    ///
    /// When `write_all` or `flush` fails it is usually because the interpreter
    /// process exited before consuming the script bytes (`EPIPE`) — for example
    /// because the script bytes were not valid syntax for the interpreter, or
    /// because a pre-exec sandbox step (such as `unshare --user`) was denied
    /// by the kernel or container runtime. To preserve the actual root cause,
    /// the variant also carries whatever the child printed to its stderr and
    /// the exit code it died with, captured best-effort after the failed
    /// write. Callers SHOULD surface `child_stderr` in user-facing diagnostics
    /// when it is non-empty; absent a captured stderr, the `source` I/O error
    /// is the only available signal.
    #[error("script input I/O failure during {stage}{child_detail}")]
    ScriptIo {
        /// Operation stage identifier (e.g. `"write-script-stdin"`).
        stage: &'static str,
        /// Source I/O error.
        #[source]
        source: io::Error,
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
        /// `child_exit_code` / `child_stderr` so thiserror's `Display` impl
        /// can append it without a custom `fmt::Display` override. Built once
        /// at construction by [`ExecError::script_io`]. Callers MUST use
        /// that constructor rather than building the struct literal directly
        /// so the `child_detail` field stays consistent with the
        /// `child_exit_code` / `child_stderr` fields.
        child_detail: String,
    },
    /// Native execution lacks both explicit CLI approval and trusted policy approval.
    #[error("native execution requires explicit --native or trusted policy approval")]
    NativeExecutionNotApproved,
    /// Native execution is not supported for this executable on the current host.
    #[error("native executable is incompatible with the current host")]
    IncompatibleNativeExecutable,
    /// The released native binary path is not absolute.
    #[error("native binary path must be absolute: {path}")]
    NativePathNotAbsolute {
        /// Rejected native binary path.
        path: PathBuf,
    },
    /// Applying or verifying native quarantine/provenance metadata failed.
    #[error("native quarantine failure during {stage}")]
    NativeQuarantine {
        /// Operation stage identifier.
        stage: &'static str,
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
    /// Required native quarantine/provenance metadata is absent.
    #[error("native quarantine metadata missing: {path}")]
    NativeQuarantineMissing {
        /// Released binary path missing required quarantine metadata.
        path: PathBuf,
    },
    /// Applying resource limits to the child process failed.
    ///
    /// The child has been killed and reaped before this error is returned; it
    /// never runs without its limits and cannot become an orphan.
    #[error("failed to apply resource limits to child: {reason}")]
    ResourceLimit {
        /// Human-readable description of the `prlimit` failure.
        reason: String,
    },
    /// Combined stdout/stderr output exceeded the configured cap.
    ///
    /// The child was killed when the limit was exceeded and has been reaped.
    #[error("child output exceeded cap: {actual} bytes > {limit} byte limit")]
    OutputExceeded {
        /// Configured maximum combined output size in bytes.
        limit: u64,
        /// Actual combined bytes read before the child was killed.
        actual: u64,
    },
    /// The content-addressed store rejected the requested artifact.
    ///
    /// This typically means the digest is absent from the CAS or the stored
    /// bytes no longer hash to the path digest (tampering).
    #[error("content store rejected artifact: {reason}")]
    Store {
        /// Human-readable store error.
        reason: String,
    },
    /// ADR-0007 fail-closed: `AssuranceLevel::Contained` was requested but
    /// proof of a mandatory containment control was not supplied. The builder
    /// refuses to emit a `Contained` context without proof of every effective
    /// control so a receipt never carries an unearned containment claim.
    #[error("contained assurance requires proof of {control}")]
    MissingContainmentProof {
        /// Name of the control lacking a proof.
        control: &'static str,
    },
}

impl ExecError {
    /// Constructs a [`ExecError::ScriptIo`] with the supplied stage, source,
    /// and best-effort child state. Renders a stable, human-readable
    /// `child_detail` suffix so the [`Display`](std::fmt::Display)
    /// representation surfaces the actual root cause (e.g. `bash: !DOCTYPE:
    /// event not found`, `unshare: operation not permitted`) when one was
    /// captured.
    ///
    /// Empty `child_stderr` and `None` exit code yield an empty
    /// `child_detail`, leaving the existing message form unchanged. Callers
    /// MUST use this constructor rather than building the variant struct
    /// directly so the `child_detail` field stays consistent with the
    /// `child_exit_code` / `child_stderr` fields.
    #[must_use]
    pub fn script_io(
        stage: &'static str,
        source: io::Error,
        child_exit_code: Option<i32>,
        child_stderr: Vec<u8>,
    ) -> Self {
        let child_detail = Self::script_io_detail(child_exit_code, child_stderr.as_slice());
        Self::ScriptIo {
            stage,
            source,
            child_exit_code,
            child_stderr,
            child_detail,
        }
    }

    /// Renders the suffix appended after `script input I/O failure during
    /// {stage}` for [`ExecError::ScriptIo`]. Exposed publicly so sibling
    /// executors (e.g. [`PowerShellError::ScriptIo`](crate::PowerShellError::ScriptIo))
    /// can share the same rendering rule without re-implementing it.
    /// Returns an empty string when no child state was captured so the
    /// message stays as terse as before.
    ///
    /// The captured stderr is byte-truncated to 1 KiB before UTF-8 lossy
    /// decoding: `String::from_utf8_lossy` replaces any partial trailing
    /// codepoint with U+FFFD, so this is panic-safe even when the
    /// attacker-controlled child stderr ends mid-multibyte-char right at the
    /// cap. This matters because the bytes come from the executed child
    /// (bash, unshare, pwsh, ...) whose output the parent does not control.
    ///
    /// ADR-0016 (Safe Presentation) requires untrusted text to be escaped
    /// and bounded before display. Because `arbitraitor-exec` sits BELOW
    /// the `arbitraitor-mcp::sanitize_for_agent` renderer in the dependency
    /// stack, we apply the two crucial defenses inline: (1) the `{:?}`
    /// debug-format at the call site quotes the preview and escapes all C0
    /// control bytes including ANSI sequences, preventing terminal injection;
    /// (2) this function replaces Arbitraitor's untrusted-data markers
    /// (`<<ARBITRAITOR_UNTRUSTED_DATA_START>>` / `<<ARBITRAITOR_UNTRUSTED_DATA_END>>`)
    /// with placeholder text so an attacker who controls the child stderr
    /// cannot spoof the markers and confuse downstream agent consumers that
    /// rely on them to fence untrusted content.
    #[must_use]
    pub fn script_io_detail(child_exit_code: Option<i32>, child_stderr: &[u8]) -> String {
        // Cap rendered stderr to keep failure messages and receipts bounded.
        // 1 KiB is ample for the "bash: parse error" / "unshare: not permitted"
        // class of diagnostics and holds even multi-line shell errors.
        const MAX_STDERR_LEN: usize = 1024;
        // Escape Arbitraitor untrusted-data markers per ADR-0016 so an
        // attacker who controls the child stderr cannot spoof markers and
        // confuse downstream agent consumers (See Safe Presentation
        // invariant in docs/conventions.md). The literals are duplicated
        // here rather than imported from `arbitraitor-mcp` because
        // `arbitraitor-exec` sits below `arbitraitor-mcp` in the dependency
        // stack.
        const ARBITRAITOR_UNTRUSTED_START: &str = "<<ARBITRAITOR_UNTRUSTED_DATA_START>>";
        const ARBITRAITOR_UNTRUSTED_END: &str = "<<ARBITRAITOR_UNTRUSTED_DATA_END>>";
        // Truncate bytes FIRST, then lossy-decode. `from_utf8_lossy` replaces
        // any partial trailing codepoint with U+FFFD, so a slice that ends mid
        // multibyte char cannot panic (the previous `&str[..usize]` form
        // would panic in the same position).
        let truncated_bytes: &[u8] = if child_stderr.len() > MAX_STDERR_LEN {
            &child_stderr[..MAX_STDERR_LEN]
        } else {
            child_stderr
        };
        let decoded = String::from_utf8_lossy(truncated_bytes);
        let sanitized = decoded
            .replace(ARBITRAITOR_UNTRUSTED_START, "[escaped-untrusted-start]")
            .replace(ARBITRAITOR_UNTRUSTED_END, "[escaped-untrusted-end]");
        let trimmed = sanitized.trim_end_matches(['\n', '\r', ' ']);
        match (child_exit_code, trimmed.is_empty()) {
            (None, true) => String::new(),
            (Some(code), true) => format!(" (child exited with code {code})"),
            (Some(code), false) => format!(" (child exited {code}; stderr: {trimmed:?})"),
            (None, false) => {
                format!(" (child produced stderr without an exit code; stderr: {trimmed:?})")
            }
        }
    }
}

/// Network access policy prepared for downstream sandbox enforcement.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum NetworkPolicy {
    /// Deny runtime network access. This is the default mediated posture.
    #[default]
    Denied,
    /// Allow only explicitly granted destinations or brokered egress.
    Restricted {
        /// Human-readable policy labels or destination identifiers.
        grants: Vec<String>,
    },
    /// Permit runtime network access as a policy exception.
    Allowed,
}

/// Sandbox preparation metadata for network-denied execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkSandboxPlan {
    /// Whether network-denial configuration must be applied by the sandbox crate.
    pub deny_network: bool,
    /// Linux enforcement mechanisms the sandbox crate may use.
    pub linux_mechanisms: Vec<&'static str>,
}

impl NetworkSandboxPlan {
    /// Returns the sandbox plan implied by a network policy.
    #[must_use]
    pub fn for_policy(policy: &NetworkPolicy) -> Self {
        match policy {
            NetworkPolicy::Denied => Self {
                deny_network: true,
                linux_mechanisms: vec!["seccomp", "landlock", "network-namespace"],
            },
            NetworkPolicy::Restricted { .. } | NetworkPolicy::Allowed => Self {
                deny_network: false,
                linux_mechanisms: Vec::new(),
            },
        }
    }
}

/// Policy controlling which environment variables may reach the child.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvAllowlist {
    names: BTreeSet<String>,
}

impl EnvAllowlist {
    /// Creates an allowlist from variable names.
    ///
    /// Variable names must be non-empty and may contain only ASCII letters,
    /// digits, and underscores. Names may not start with a digit.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::InvalidEnvironmentName`] when any supplied name is invalid.
    pub fn new<I, S>(names: I) -> Result<Self, ExecError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut allowed = BTreeSet::new();
        for name in names {
            let name = name.into();
            validate_env_name(&name)?;
            allowed.insert(name);
        }
        Ok(Self { names: allowed })
    }

    /// Returns the default mediated execution allowlist.
    pub fn default_names() -> Self {
        Self {
            names: ["LANG", "LC_ALL", "TERM", "PATH"]
                .into_iter()
                .map(ToOwned::to_owned)
                .collect(),
        }
    }

    /// Adds a variable name to the allowlist.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::InvalidEnvironmentName`] when `name` is invalid.
    pub fn insert<S>(&mut self, name: S) -> Result<(), ExecError>
    where
        S: Into<String>,
    {
        let name = name.into();
        validate_env_name(&name)?;
        self.names.insert(name);
        Ok(())
    }

    /// Returns true when `name` is explicitly allowlisted.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// Returns allowlisted variable names in deterministic order.
    #[must_use]
    pub fn names(&self) -> &BTreeSet<String> {
        &self.names
    }
}

impl Default for EnvAllowlist {
    fn default() -> Self {
        Self::default_names()
    }
}

/// Mandatory environment deny patterns checked after allowlist filtering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvDenyList {
    exact: BTreeSet<String>,
    prefixes: BTreeSet<String>,
}

impl EnvDenyList {
    /// Creates a denylist from exact names and prefixes.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::InvalidEnvironmentName`] when any supplied name or prefix is invalid.
    pub fn new<I, S, J, T>(exact: I, prefixes: J) -> Result<Self, ExecError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
        J: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let mut exact_names = BTreeSet::new();
        for name in exact {
            let name = name.into();
            validate_env_name(&name)?;
            exact_names.insert(name);
        }
        let mut prefix_names = BTreeSet::new();
        for prefix in prefixes {
            let prefix = prefix.into();
            validate_env_prefix(&prefix)?;
            prefix_names.insert(prefix);
        }
        Ok(Self {
            exact: exact_names,
            prefixes: prefix_names,
        })
    }

    /// Returns the mandatory defense-in-depth denylist.
    #[must_use]
    pub fn mandatory() -> Self {
        let exact = [
            "BASH_ENV",
            "ENV",
            "ZDOTDIR",
            "NODE_OPTIONS",
            "SSH_AUTH_SOCK",
            // Shell injection vectors — must be blocked even when allowlisted.
            "IFS",
            "SHELLOPTS",
            "BASHOPTS",
            "CDPATH",
            "GLOBIGNORE",
            "POSIXLY_CORRECT",
            "PS4",
            "PROMPT_COMMAND",
        ];
        let prefixes = [
            "LD_",
            "DYLD_",
            "PYTHON",
            "RUBY",
            "PERL5",
            "GIT_CONFIG_",
            "AWS_",
            "AZURE_",
            "GOOGLE_",
            "GITHUB_",
        ];
        Self {
            exact: exact.into_iter().map(ToOwned::to_owned).collect(),
            prefixes: prefixes.into_iter().map(ToOwned::to_owned).collect(),
        }
    }

    /// Returns true when `name` matches an exact deny name or denied prefix.
    #[must_use]
    pub fn denies(&self, name: &str) -> bool {
        self.exact.contains(name) || self.prefixes.iter().any(|prefix| name.starts_with(prefix))
    }
}

impl Default for EnvDenyList {
    fn default() -> Self {
        Self::mandatory()
    }
}

/// File descriptor inheritance policy for child process creation.
///
/// This is **declarative metadata** consumed by the downstream sandbox and
/// spawn layer. This crate records the policy but does not itself enforce fd
/// closure — the actual `close_range` / `O_CLOEXEC` application happens when
/// the child process is spawned. Callers that ignore `close_inherited` will
/// leak descriptors to untrusted children.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FdPolicy {
    /// Whether descriptors outside `keep_fds` must be closed before exec.
    pub close_inherited: bool,
    /// Descriptor numbers allowed to remain inherited.
    pub keep_fds: BTreeSet<i32>,
}

impl FdPolicy {
    /// Creates a file descriptor policy.
    #[must_use]
    pub fn new<I>(close_inherited: bool, keep_fds: I) -> Self
    where
        I: IntoIterator<Item = i32>,
    {
        Self {
            close_inherited,
            keep_fds: keep_fds.into_iter().collect(),
        }
    }

    /// Returns true if `fd` may be inherited.
    #[must_use]
    pub fn keeps(&self, fd: i32) -> bool {
        self.keep_fds.contains(&fd)
    }
}

impl Default for FdPolicy {
    fn default() -> Self {
        Self::new(true, DEFAULT_KEEP_FDS)
    }
}

/// Conservative resource limits for execution contexts.
///
/// These limits are declared by policy and recorded in the execution context.
/// Downstream spawn and sandbox code is **required** to actually enforce them
/// (e.g. via `setrlimit`, cgroups, or equivalent platform mechanisms). If
/// downstream enforcement cannot be applied, the operation must fail closed —
/// the limits must never be silently ignored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    /// Maximum CPU time in seconds.
    pub cpu_time_secs: Option<u64>,
    /// Maximum virtual memory in bytes.
    pub memory_bytes: Option<u64>,
    /// Maximum number of processes or threads.
    pub process_count: Option<u32>,
    /// Maximum number of open file descriptors.
    pub fd_count: Option<u32>,
    /// Maximum combined stdout/stderr output size in bytes.
    pub output_size_bytes: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_time_secs: Some(60),
            memory_bytes: Some(512 * 1024 * 1024), // 512 MB
            process_count: Some(64),
            fd_count: Some(64),
            output_size_bytes: Some(10 * 1024 * 1024), // 10 MB
        }
    }
}

#[cfg(target_os = "linux")]
impl ResourceLimits {
    /// Apply all configured limits to a child process via `prlimit`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the kernel rejects a limit.
    pub fn apply_to(&self, pid: u32) -> std::io::Result<()> {
        use rustix::process::{Pid, Resource, Rlimit, prlimit};
        let pid = Pid::from_raw(pid.try_into().unwrap_or(i32::MAX));
        let apply = |resource: Resource, limit: Option<u64>| -> std::io::Result<()> {
            if let Some(v) = limit {
                let rlim = Rlimit {
                    current: Some(v),
                    maximum: Some(v),
                };
                prlimit(pid, resource, rlim)
                    .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))?;
            }
            Ok(())
        };
        apply(Resource::Cpu, self.cpu_time_secs)?;
        apply(Resource::As, self.memory_bytes)?;
        apply(Resource::Nproc, self.process_count.map(u64::from))?;
        apply(Resource::Nofile, self.fd_count.map(u64::from))?;
        Ok(())
    }
}

/// Policy for execution temporary directories.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum TempDirectoryPolicy {
    /// Create a fresh empty temporary HOME directory.
    #[default]
    Temporary,
    /// Use a policy-approved fixed directory.
    Fixed(PathBuf),
}

/// Policy-driven controls used to build an execution context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionPolicy {
    /// Environment variables allowed to pass after validation.
    pub environment_allowlist: EnvAllowlist,
    /// Mandatory and policy-specified denied variables.
    pub environment_denylist: EnvDenyList,
    /// Controlled PATH entries.
    pub path_entries: Vec<PathBuf>,
    /// Runtime network policy.
    pub network_policy: NetworkPolicy,
    /// File descriptor inheritance policy (declarative — see [`FdPolicy`]).
    pub fd_policy: FdPolicy,
    /// HOME directory policy.
    pub home_directory: TempDirectoryPolicy,
    /// Working directory policy.
    pub working_directory: TempDirectoryPolicy,
    /// Whether privilege elevation attempts are blocked.
    pub deny_privilege_elevation: bool,
    /// Whether running Arbitraitor as root is blocked.
    pub deny_running_as_root: bool,
    /// Whether trusted policy explicitly approves native binary execution.
    pub allow_native_execution: bool,
    /// Resource limits to be enforced by downstream spawn/sandbox code.
    pub resource_limits: ResourceLimits,
}

/// Builds an [`EnvAllowlist`] from an execution configuration's
/// `allow_environment` list (spec §26.5).
///
/// Each entry is matched as an exact variable name. Pre-existing
/// [`EnvAllowlist::default_names`] behavior is preserved when the
/// configuration is built from its serde defaults.
///
/// # Errors
///
/// Returns [`ExecError::InvalidEnvironmentName`] when any configured name
/// is malformed.
pub fn env_allowlist_from_config(cfg: &ExecutionConfig) -> Result<EnvAllowlist, ExecError> {
    EnvAllowlist::new(cfg.allow_environment.iter().cloned())
}

/// Builds an [`EnvDenyList`] from an execution configuration's
/// `deny_environment_patterns` list (spec §26.5).
///
/// Each entry is treated as a prefix that matches any variable name
/// starting with that string. Defaults are the union of the historic
/// exact-match denylist and the historic prefix denylist; treating the
/// exact-match entries as prefixes is strictly tighter than exact match
/// and is the safe direction.
///
/// # Errors
///
/// Returns [`ExecError::InvalidEnvironmentName`] when any configured
/// pattern is malformed.
pub fn env_denylist_from_config(cfg: &ExecutionConfig) -> Result<EnvDenyList, ExecError> {
    EnvDenyList::new(
        std::iter::empty::<String>(),
        cfg.deny_environment_patterns.iter().cloned(),
    )
}

impl ExecutionPolicy {
    /// Returns the controlled PATH string for this policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured PATH is empty, relative, or unsafe.
    pub fn controlled_path(&self) -> Result<OsString, ExecError> {
        let canonical_entries = validate_path_entries(&self.path_entries)?;
        let joined = env::join_paths(&canonical_entries).map_err(|_| ExecError::EmptyPath)?;
        Ok(joined)
    }

    /// Builds a policy from an operation plan and granted capabilities.
    ///
    /// The trusted `granted_capabilities` are **authoritative**. Network access
    /// requires *both* `granted_capabilities.network()` and
    /// `plan.network_allowed` (intersection). The untrusted plan alone can
    /// never enable network access.
    ///
    /// # Errors
    ///
    /// Returns an error when operation-provided environment allowlist entries are invalid.
    pub fn from_operation(
        plan: &OperationPlan,
        granted_capabilities: &GrantedCapabilities,
    ) -> Result<Self, ExecError> {
        let mut policy = Self {
            network_policy: if granted_capabilities.network() && plan.network_allowed {
                NetworkPolicy::Allowed
            } else {
                NetworkPolicy::Denied
            },
            ..Self::default()
        };
        for name in &plan.environment_allowlist {
            policy.environment_allowlist.insert(name.clone())?;
        }
        Ok(policy)
    }
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            environment_allowlist: EnvAllowlist::default(),
            environment_denylist: EnvDenyList::default(),
            path_entries: default_path_entries(),
            network_policy: NetworkPolicy::default(),
            fd_policy: FdPolicy::default(),
            home_directory: TempDirectoryPolicy::default(),
            working_directory: TempDirectoryPolicy::default(),
            deny_privilege_elevation: true,
            deny_running_as_root: true,
            allow_native_execution: false,
            resource_limits: ResourceLimits::default(),
        }
    }
}

/// Status of a single containment control (ADR-0007 platform capability matrix).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlStatus {
    /// Control is enforced and proven active.
    Enforced,
    /// Control is partially enforced (degraded coverage).
    Partial,
    /// Control is unavailable on this platform or configuration.
    Unavailable,
}

/// One entry in the per-control effective-controls matrix recorded in receipts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EffectiveControl {
    /// Whether the control was requested by policy.
    pub requested: bool,
    /// Whether the control was applied, partially applied, or unavailable.
    pub applied: ControlStatus,
    /// Proof or mechanism name attesting the control is active
    /// (e.g. `"landlock"`, `"no-new-privs"`). `None` when not requested.
    pub proof: Option<String>,
}

/// Per-control capability matrix emitted in receipts per ADR-0007.
///
/// Every field is `Option` so that non-contained contexts serialize compactly
/// (all `None`) and contained contexts carry exactly one entry per mandatory
/// control.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EffectiveControls {
    /// Filesystem isolation (chroot, namespace, `AppContainer`, `Landlock`, ...).
    pub filesystem_isolation: Option<EffectiveControl>,
    /// Network isolation (namespace, filter, broker).
    pub network_isolation: Option<EffectiveControl>,
    /// Process-tree containment (pid namespace, job object).
    pub process_tree_control: Option<EffectiveControl>,
    /// Privilege suppression (`no-new-privileges` or platform equivalent).
    pub privilege_suppression: Option<EffectiveControl>,
    /// System-call filtering (seccomp-bpf, ...).
    pub syscall_filtering: Option<EffectiveControl>,
    /// Resource limits (CPU, memory, FDs, processes).
    pub resource_limits: Option<EffectiveControl>,
    /// Effective Landlock ABI version observed when filesystem isolation uses Landlock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landlock_abi_version: Option<LandlockAbiVersion>,
    /// Whether `io_uring` is available on the host kernel (spec §27.3).
    ///
    /// `Some(true)` signals that `io_uring` bypasses seccomp; receipt
    /// consumers should recommend `sysctl kernel.io_uring_disabled=1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_uring_available: Option<bool>,
    /// Whether unprivileged user namespaces are available without host restriction.
    ///
    /// `Some(true)` signals an expanded kernel attack surface and receipt
    /// consumers should recommend `sysctl kernel.unprivileged_userns_clone=0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userns_available: Option<bool>,
}

/// Proofs supplied to the builder that each containment control is active.
///
/// Required when [`AssuranceLevel::Contained`] is requested. Each `Option`
/// holds a mechanism or attestation name (e.g. `"landlock"`). A `None` entry
/// for any mandatory control causes [`ExecError::MissingContainmentProof`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ControlProofs {
    /// Proof of filesystem isolation.
    pub filesystem_isolation: Option<String>,
    /// Proof of network isolation.
    pub network_isolation: Option<String>,
    /// Proof of process-tree containment.
    pub process_tree_control: Option<String>,
    /// Proof of privilege suppression.
    pub privilege_suppression: Option<String>,
    /// Proof of syscall filtering.
    pub syscall_filtering: Option<String>,
    /// Proof of resource-limit enforcement.
    pub resource_limits: Option<String>,
    /// Effective Landlock ABI version backing the filesystem-isolation proof.
    pub landlock_abi_version: Option<LandlockAbiVersion>,
    /// Whether `io_uring` is available on the host kernel (spec §27.3).
    pub io_uring_available: Option<bool>,
    /// Whether unprivileged user namespaces are available without host restriction.
    pub userns_available: Option<bool>,
}

impl ControlProofs {
    fn require(
        proof: Option<String>,
        control: &'static str,
    ) -> Result<EffectiveControl, ExecError> {
        let proof = proof.ok_or(ExecError::MissingContainmentProof { control })?;
        Ok(EffectiveControl {
            requested: true,
            applied: ControlStatus::Enforced,
            proof: Some(proof),
        })
    }

    fn into_effective_controls(self) -> Result<EffectiveControls, ExecError> {
        if self.io_uring_available == Some(true) {
            tracing::warn!(
                "io_uring is available on this host; it bypasses seccomp. \
                 Recommend: sysctl kernel.io_uring_disabled=1 (or =2 for full disable)"
            );
        }
        if self.userns_available == Some(true) {
            tracing::warn!(
                "unprivileged user namespaces are available without AppArmor restriction; \
                 recommend: sysctl kernel.unprivileged_userns_clone=0"
            );
        }
        Ok(EffectiveControls {
            filesystem_isolation: Some(Self::require(
                self.filesystem_isolation,
                "filesystem isolation",
            )?),
            network_isolation: Some(Self::require(self.network_isolation, "network isolation")?),
            process_tree_control: Some(Self::require(
                self.process_tree_control,
                "process-tree control",
            )?),
            privilege_suppression: Some(Self::require(
                self.privilege_suppression,
                "privilege suppression",
            )?),
            syscall_filtering: Some(Self::require(self.syscall_filtering, "syscall filtering")?),
            resource_limits: Some(Self::require(self.resource_limits, "resource limits")?),
            landlock_abi_version: self.landlock_abi_version,
            io_uring_available: self.io_uring_available,
            userns_available: self.userns_available,
        })
    }
}

/// A built mediated execution context for a safe child process environment.
///
/// All fields are private. Use the provided read-only accessors to inspect
/// the context. No mutation is possible after validation — the context is
/// immutable for its entire lifetime.
pub struct ExecutionContext {
    operation_plan: OperationPlan,
    assurance_level: AssuranceLevel,
    granted_capabilities: GrantedCapabilities,
    command: PathBuf,
    arguments: Vec<OsString>,
    environment: BTreeMap<String, OsString>,
    home_dir: PathBuf,
    working_dir: PathBuf,
    fd_policy: FdPolicy,
    network_policy: NetworkPolicy,
    network_sandbox: NetworkSandboxPlan,
    resource_limits: ResourceLimits,
    effective_controls: EffectiveControls,
    home_tempdir: Option<OwnedTempDir>,
    working_tempdir: Option<OwnedTempDir>,
}

pub(crate) struct OwnedTempDir {
    path: PathBuf,
}

impl OwnedTempDir {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for OwnedTempDir {
    fn drop(&mut self) {
        let _cleanup_result = fs::remove_dir_all(&self.path);
    }
}

impl std::fmt::Debug for ExecutionContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionContext")
            .field("operation_plan", &self.operation_plan)
            .field("assurance_level", &self.assurance_level)
            .field("granted_capabilities", &self.granted_capabilities)
            .field("command", &self.command)
            .field("arguments", &self.arguments)
            .field("environment", &self.environment)
            .field("home_dir", &self.home_dir)
            .field("working_dir", &self.working_dir)
            .field("fd_policy", &self.fd_policy)
            .field("network_policy", &self.network_policy)
            .field("network_sandbox", &self.network_sandbox)
            .field("resource_limits", &self.resource_limits)
            .field("effective_controls", &self.effective_controls)
            .finish_non_exhaustive()
    }
}

impl ExecutionContext {
    /// Returns true when HOME and working directory are backed by temporary
    /// directories that will be removed on drop.
    #[must_use]
    pub fn owns_temporary_directories(&self) -> bool {
        self.home_tempdir.is_some() || self.working_tempdir.is_some()
    }

    /// Returns the environment as an iterator suitable for `std::process::Command`.
    pub fn environment_iter(&self) -> impl Iterator<Item = (&str, &OsStr)> {
        self.environment
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_os_str()))
    }

    /// Returns the command executable path.
    #[must_use]
    pub fn command(&self) -> &Path {
        &self.command
    }

    /// Returns the command arguments.
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    /// Returns the fully constructed child environment map.
    #[must_use]
    pub fn environment(&self) -> &BTreeMap<String, OsString> {
        &self.environment
    }

    /// Returns the HOME directory assigned to the child.
    #[must_use]
    pub fn home_dir(&self) -> &Path {
        &self.home_dir
    }

    /// Returns the working directory assigned to the child.
    #[must_use]
    pub fn working_dir(&self) -> &Path {
        &self.working_dir
    }

    /// Returns the file descriptor inheritance policy.
    #[must_use]
    pub fn fd_policy(&self) -> &FdPolicy {
        &self.fd_policy
    }

    /// Returns the network policy to enforce in the sandbox crate.
    #[must_use]
    pub fn network_policy(&self) -> &NetworkPolicy {
        &self.network_policy
    }

    /// Returns the prepared sandbox configuration for the network policy.
    #[must_use]
    pub fn network_sandbox(&self) -> &NetworkSandboxPlan {
        &self.network_sandbox
    }

    /// Returns the operation plan bound to this context.
    #[must_use]
    pub fn operation_plan(&self) -> &OperationPlan {
        &self.operation_plan
    }

    /// Returns the effective assurance level for this context.
    #[must_use]
    pub fn assurance_level(&self) -> AssuranceLevel {
        self.assurance_level
    }

    /// Returns the policy-granted capabilities used while building the context.
    #[must_use]
    pub fn granted_capabilities(&self) -> &GrantedCapabilities {
        &self.granted_capabilities
    }

    /// Returns the resource limits to be enforced by downstream code.
    #[must_use]
    pub fn resource_limits(&self) -> &ResourceLimits {
        &self.resource_limits
    }

    /// Returns the per-control effective-controls matrix (ADR-0007).
    ///
    /// For [`AssuranceLevel::Contained`] contexts this carries one enforced
    /// entry per mandatory control. For lower assurance levels all entries
    /// are `None`.
    #[must_use]
    pub fn effective_controls(&self) -> &EffectiveControls {
        &self.effective_controls
    }
}

/// Fluent builder for [`ExecutionContext`].
pub struct ExecutionContextBuilder {
    operation_plan: OperationPlan,
    granted_capabilities: GrantedCapabilities,
    assurance_level: AssuranceLevel,
    command: Option<PathBuf>,
    arguments: Vec<OsString>,
    policy: ExecutionPolicy,
    source_environment: BTreeMap<String, OsString>,
    control_proofs: ControlProofs,
}

impl ExecutionContextBuilder {
    /// Creates a builder for a policy-resolved operation.
    #[must_use]
    pub fn new(operation_plan: OperationPlan, granted_capabilities: GrantedCapabilities) -> Self {
        let arguments = operation_plan
            .arguments
            .iter()
            .map(OsString::from)
            .collect();
        let command = operation_plan.interpreter.as_ref().map(PathBuf::from);
        Self {
            operation_plan,
            granted_capabilities,
            assurance_level: AssuranceLevel::Mediated,
            command,
            arguments,
            policy: ExecutionPolicy::default(),
            source_environment: env::vars_os()
                .filter_map(|(name, value)| name.into_string().ok().map(|name| (name, value)))
                .collect(),
            control_proofs: ControlProofs::default(),
        }
    }

    /// Creates a builder and seeds policy from an operation plan.
    ///
    /// # Errors
    ///
    /// Returns an error when policy derivation from the operation plan fails.
    pub fn from_operation(
        operation_plan: OperationPlan,
        granted_capabilities: GrantedCapabilities,
    ) -> Result<Self, ExecError> {
        let policy = ExecutionPolicy::from_operation(&operation_plan, &granted_capabilities)?;
        Ok(Self::new(operation_plan, granted_capabilities).policy(policy))
    }

    /// Replaces the effective assurance level recorded in the context.
    #[must_use]
    pub fn assurance_level(mut self, assurance_level: AssuranceLevel) -> Self {
        self.assurance_level = assurance_level;
        self
    }

    /// Replaces the command executable.
    #[must_use]
    pub fn command<P>(mut self, command: P) -> Self
    where
        P: Into<PathBuf>,
    {
        self.command = Some(command.into());
        self
    }

    /// Replaces command arguments.
    #[must_use]
    pub fn arguments<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.arguments = arguments.into_iter().map(Into::into).collect();
        self
    }

    /// Replaces execution policy.
    #[must_use]
    pub fn policy(mut self, policy: ExecutionPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Replaces the source environment used for allowlist filtering.
    #[must_use]
    pub fn source_environment<I, K, V>(mut self, variables: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<OsString>,
    {
        self.source_environment = variables
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect();
        self
    }

    /// Supplies containment control proofs (ADR-0007).
    ///
    /// Required when the assurance level is set to
    /// [`AssuranceLevel::Contained`]; ignored otherwise.
    #[must_use]
    pub fn control_proofs(mut self, proofs: ControlProofs) -> Self {
        self.control_proofs = proofs;
        self
    }

    /// Replaces the environment allowlist and denylist with values derived
    /// from the supplied execution configuration (spec §26.5).
    ///
    /// `cfg.allow_environment` entries are matched as exact variable names.
    /// `cfg.deny_environment_patterns` entries are matched as prefixes
    /// (any variable name starting with the pattern is denied). When the
    /// configuration is built from its serde defaults, the resulting lists
    /// match the historical `EnvAllowlist::default_names()` and
    /// `EnvDenyList::mandatory()` constants.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::InvalidEnvironmentName`] when any configured
    /// name or pattern is malformed.
    pub fn environment_from_config(mut self, cfg: &ExecutionConfig) -> Result<Self, ExecError> {
        self.policy.environment_allowlist = env_allowlist_from_config(cfg)?;
        self.policy.environment_denylist = env_denylist_from_config(cfg)?;
        Ok(self)
    }

    /// Builds the execution context without spawning any child process.
    ///
    /// # Errors
    ///
    /// Returns an error when root execution, capability checks, privilege
    /// elevation, environment, PATH, command resolution, or temporary
    /// directory checks fail.
    pub fn build(self) -> Result<ExecutionContext, ExecError> {
        if self.policy.deny_running_as_root && running_as_root()? {
            return Err(ExecError::RunningAsRoot);
        }

        // Fail closed: the execute capability must be explicitly granted by
        // trusted policy. The untrusted operation plan cannot bypass this.
        if !self.granted_capabilities.execute() {
            return Err(ExecError::ExecuteNotGranted);
        }
        if !self.granted_capabilities.network()
            && self.policy.network_policy != NetworkPolicy::Denied
        {
            return Err(ExecError::NetworkNotGranted);
        }

        let command = self.command.unwrap_or_else(|| PathBuf::from("/bin/sh"));
        // Commands must be absolute — no PATH lookup, no relative resolution.
        if !command.is_absolute() {
            return Err(ExecError::CommandNotAbsolute { command });
        }
        if self.policy.deny_privilege_elevation {
            detect_privilege_elevation_path(&command)?;
            for argument in &self.arguments {
                detect_privilege_elevation_os(argument)?;
            }
        }

        let canonical_path_entries = validate_path_entries(&self.policy.path_entries)?;
        let mut environment = filter_environment(
            &self.source_environment,
            &self.policy.environment_allowlist,
            &self.policy.environment_denylist,
        )?;
        let controlled_path =
            env::join_paths(&canonical_path_entries).map_err(|_| ExecError::EmptyPath)?;
        environment.insert("PATH".to_owned(), controlled_path);

        let (home_dir, home_tempdir) = materialize_directory(&self.policy.home_directory)?;
        let (working_dir, working_tempdir) = materialize_directory(&self.policy.working_directory)?;
        environment.insert("HOME".to_owned(), home_dir.as_os_str().to_owned());

        let network_sandbox = NetworkSandboxPlan::for_policy(&self.policy.network_policy);
        debug!(
            operation_id = %self.operation_plan.operation_id,
            fd_close_inherited = self.policy.fd_policy.close_inherited,
            network_denied = network_sandbox.deny_network,
            "built mediated execution context"
        );

        let effective_controls = match self.assurance_level {
            AssuranceLevel::Inspect | AssuranceLevel::Mediated => EffectiveControls::default(),
            AssuranceLevel::Contained => self.control_proofs.into_effective_controls()?,
        };

        Ok(ExecutionContext {
            operation_plan: self.operation_plan,
            assurance_level: self.assurance_level,
            granted_capabilities: self.granted_capabilities,
            command,
            arguments: self.arguments,
            environment,
            home_dir,
            working_dir,
            fd_policy: self.policy.fd_policy,
            network_policy: self.policy.network_policy,
            network_sandbox,
            resource_limits: self.policy.resource_limits,
            effective_controls,
            home_tempdir,
            working_tempdir,
        })
    }
}

fn filter_environment(
    source: &BTreeMap<String, OsString>,
    allowlist: &EnvAllowlist,
    denylist: &EnvDenyList,
) -> Result<BTreeMap<String, OsString>, ExecError> {
    let mut filtered = BTreeMap::new();
    for (name, value) in source {
        validate_env_name(name)?;
        if allowlist.contains(name) {
            if denylist.denies(name) {
                return Err(ExecError::DeniedEnvironmentVariable { name: name.clone() });
            }
            filtered.insert(name.clone(), value.clone());
        }
    }
    Ok(filtered)
}

fn validate_env_name(name: &str) -> Result<(), ExecError> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if valid {
        Ok(())
    } else {
        Err(ExecError::InvalidEnvironmentName {
            name: name.to_owned(),
        })
    }
}

fn validate_env_prefix(prefix: &str) -> Result<(), ExecError> {
    if prefix.is_empty()
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(ExecError::InvalidEnvironmentName {
            name: prefix.to_owned(),
        });
    }
    Ok(())
}

/// Returns canonical, verified-safe default PATH entries.
///
/// Each candidate is canonicalized at runtime so that system-level symlinks
/// (e.g. `/bin` → `/usr/bin`) are resolved before validation. Entries that
/// do not exist, are not root-owned, or are group-/world-writable are silently
/// skipped; duplicates after canonicalization are removed.
fn default_path_entries() -> Vec<PathBuf> {
    let candidates = ["/usr/local/bin", "/usr/bin", "/bin"];
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for candidate in candidates {
        let Ok(canonical) = fs::canonicalize(candidate) else {
            continue;
        };
        if !seen.insert(canonical.clone()) {
            continue;
        }
        // Verify the entry passes the same safety checks as validate_path_entries:
        // root-owned (uid 0) and not group-/world-writable.
        let Ok(meta) = fs::metadata(&canonical) else {
            continue;
        };
        if meta.uid() != 0 || (meta.permissions().mode() & 0o022 != 0) {
            continue;
        }
        entries.push(canonical);
    }
    entries
}

/// Validates that every PATH entry is absolute, not a symlink, canonicalizable,
/// owned by root (uid 0), and not group- or world-writable.
fn validate_path_entries(entries: &[PathBuf]) -> Result<Vec<PathBuf>, ExecError> {
    if entries.is_empty() {
        return Err(ExecError::EmptyPath);
    }
    let mut canonical_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        if !entry.is_absolute() {
            return Err(ExecError::RelativePathEntry {
                path: entry.clone(),
            });
        }
        // Reject symlink entries — PATH must point at real directories only.
        let symlink_meta = fs::symlink_metadata(entry).map_err(|_| ExecError::UnsafePathEntry {
            path: entry.clone(),
        })?;
        if symlink_meta.file_type().is_symlink() {
            return Err(ExecError::UnsafePathEntry {
                path: entry.clone(),
            });
        }
        // Canonicalize to resolve any remaining indirection, then verify
        // ownership and permissions on the resolved target.
        let canonical = fs::canonicalize(entry).map_err(|_| ExecError::UnsafePathEntry {
            path: entry.clone(),
        })?;
        let meta = fs::metadata(&canonical).map_err(|_| ExecError::UnsafePathEntry {
            path: entry.clone(),
        })?;
        if meta.uid() != 0 {
            return Err(ExecError::UnsafePathEntry {
                path: entry.clone(),
            });
        }
        let mode = meta.permissions().mode();
        // Reject group-writable (0o020) or world-writable (0o002).
        if mode & 0o022 != 0 {
            return Err(ExecError::UnsafePathEntry {
                path: entry.clone(),
            });
        }
        canonical_entries.push(canonical);
    }
    Ok(canonical_entries)
}

/// Validates a fixed execution directory: must be absolute, not a symlink,
/// and canonicalizable to a real directory.
fn validate_fixed_directory(path: &Path) -> Result<PathBuf, ExecError> {
    if !path.is_absolute() {
        return Err(ExecError::UnsafeFixedDirectory {
            path: path.to_path_buf(),
        });
    }
    let symlink_meta = fs::symlink_metadata(path).map_err(|_| ExecError::UnsafeFixedDirectory {
        path: path.to_path_buf(),
    })?;
    if symlink_meta.file_type().is_symlink() {
        return Err(ExecError::UnsafeFixedDirectory {
            path: path.to_path_buf(),
        });
    }
    let canonical = fs::canonicalize(path).map_err(|_| ExecError::UnsafeFixedDirectory {
        path: path.to_path_buf(),
    })?;
    let meta = fs::metadata(&canonical).map_err(|_| ExecError::UnsafeFixedDirectory {
        path: path.to_path_buf(),
    })?;
    if !meta.is_dir() {
        return Err(ExecError::UnsafeFixedDirectory {
            path: path.to_path_buf(),
        });
    }
    Ok(canonical)
}

fn materialize_directory(
    policy: &TempDirectoryPolicy,
) -> Result<(PathBuf, Option<OwnedTempDir>), ExecError> {
    match policy {
        TempDirectoryPolicy::Temporary => {
            let directory = create_temporary_directory()?;
            Ok((directory.path().to_path_buf(), Some(directory)))
        }
        TempDirectoryPolicy::Fixed(path) => {
            let canonical = validate_fixed_directory(path)?;
            Ok((canonical, None))
        }
    }
}

pub(crate) fn create_temporary_directory() -> Result<OwnedTempDir, ExecError> {
    let base = env::temp_dir();
    for _attempt in 0..128 {
        let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = base.join(format!("arbitraitor-exec-{}-{counter}", std::process::id()));
        match fs::DirBuilder::new().mode(0o700).create(&candidate) {
            Ok(()) => return Ok(OwnedTempDir { path: candidate }),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
            Err(source) => return Err(ExecError::TemporaryDirectory { source }),
        }
    }
    Err(ExecError::TemporaryDirectory {
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "unable to create unique temporary execution directory",
        ),
    })
}

fn detect_privilege_elevation_path(path: &Path) -> Result<(), ExecError> {
    if let Some(name) = path.file_name().and_then(OsStr::to_str) {
        detect_privilege_elevation_str(name)?;
    }
    Ok(())
}

fn detect_privilege_elevation_os(value: &OsStr) -> Result<(), ExecError> {
    if let Some(value) = value.to_str() {
        for token in split_command_tokens(value) {
            detect_privilege_elevation_str(&token)?;
        }
    }
    Ok(())
}

fn split_command_tokens(command: &str) -> Vec<String> {
    command
        .split(|character: char| !matches!(character, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | '/' | '.'))
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn detect_privilege_elevation_str(value: &str) -> Result<(), ExecError> {
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

fn running_as_root() -> Result<bool, ExecError> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|source| ExecError::RootDetection { source })?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let effective_uid =
                rest.split_whitespace()
                    .nth(1)
                    .ok_or_else(|| ExecError::RootDetection {
                        source: io::Error::new(io::ErrorKind::InvalidData, "missing effective uid"),
                    })?;
            return Ok(effective_uid == "0");
        }
    }
    Err(ExecError::RootDetection {
        source: io::Error::new(io::ErrorKind::InvalidData, "missing uid line"),
    })
}

#[cfg(all(test, target_os = "linux"))]
#[path = "tests.rs"]
mod tests;
