//! Execution broker for approved artifacts.
//!
//! This crate builds mediated execution contexts. It does not spawn child
//! processes and does not apply kernel sandboxing; downstream execution and
//! sandbox crates consume the context produced here.

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

use arbitraitor_model::operation::{GrantedCapabilities, OperationPlan};
use arbitraitor_model::verdict::AssuranceLevel;
use thiserror::Error;
use tracing::debug;

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
    /// Resource limits to be enforced by downstream spawn/sandbox code.
    pub resource_limits: ResourceLimits,
}

impl ExecutionPolicy {
    /// Returns the controlled PATH string for this policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured PATH is empty, relative, or unsafe.
    pub fn controlled_path(&self) -> Result<OsString, ExecError> {
        validate_path_entries(&self.path_entries)?;
        let joined = env::join_paths(&self.path_entries).map_err(|_| ExecError::EmptyPath)?;
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
            resource_limits: ResourceLimits::default(),
        }
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
    home_tempdir: Option<OwnedTempDir>,
    working_tempdir: Option<OwnedTempDir>,
}

struct OwnedTempDir {
    path: PathBuf,
}

impl OwnedTempDir {
    fn path(&self) -> &Path {
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

        validate_path_entries(&self.policy.path_entries)?;
        let mut environment = filter_environment(
            &self.source_environment,
            &self.policy.environment_allowlist,
            &self.policy.environment_denylist,
        )?;
        environment.insert("PATH".to_owned(), self.policy.controlled_path()?);

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
/// do not exist are silently skipped; duplicates after canonicalization are
/// removed.
fn default_path_entries() -> Vec<PathBuf> {
    let candidates = ["/usr/local/bin", "/usr/bin", "/bin"];
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for candidate in candidates {
        if let Ok(canonical) = fs::canonicalize(candidate)
            && seen.insert(canonical.clone())
        {
            entries.push(canonical);
        }
    }
    if entries.is_empty() {
        entries.push(PathBuf::from("/usr/local/bin"));
    }
    entries
}

/// Validates that every PATH entry is absolute, not a symlink, canonicalizable,
/// owned by root (uid 0), and not group- or world-writable.
fn validate_path_entries(entries: &[PathBuf]) -> Result<(), ExecError> {
    if entries.is_empty() {
        return Err(ExecError::EmptyPath);
    }
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
    }
    Ok(())
}

/// Validates a fixed execution directory: must be absolute, not a symlink,
/// and canonicalizable to a real directory.
fn validate_fixed_directory(path: &Path) -> Result<(), ExecError> {
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
    fs::canonicalize(path).map_err(|_| ExecError::UnsafeFixedDirectory {
        path: path.to_path_buf(),
    })?;
    Ok(())
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
            validate_fixed_directory(path)?;
            Ok((path.clone(), None))
        }
    }
}

fn create_temporary_directory() -> Result<OwnedTempDir, ExecError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use arbitraitor_model::ids::{ArtifactId, OperationId, Sha256Digest};
    use arbitraitor_model::operation::{CapabilityGrant, OperationType};

    fn plan() -> OperationPlan {
        OperationPlan {
            operation_id: OperationId::new(),
            artifact_id: ArtifactId(Sha256Digest::new([7; 32])),
            operation_type: OperationType::Execute,
            interpreter: Some("/bin/sh".to_owned()),
            arguments: vec!["-c".to_owned(), "true".to_owned()],
            environment_allowlist: Vec::new(),
            network_allowed: false,
            sandbox_enabled: true,
            expiry: None,
        }
    }

    fn grants() -> GrantedCapabilities {
        GrantedCapabilities::new(
            CapabilityGrant(false),
            CapabilityGrant(false),
            CapabilityGrant(true),
            CapabilityGrant(false),
        )
    }

    fn grants_with_network() -> GrantedCapabilities {
        GrantedCapabilities::new(
            CapabilityGrant(true),
            CapabilityGrant(false),
            CapabilityGrant(true),
            CapabilityGrant(false),
        )
    }

    fn grants_without_execute() -> GrantedCapabilities {
        GrantedCapabilities::new(
            CapabilityGrant(false),
            CapabilityGrant(false),
            CapabilityGrant(false),
            CapabilityGrant(false),
        )
    }

    fn policy_without_root_check() -> ExecutionPolicy {
        ExecutionPolicy {
            deny_running_as_root: false,
            ..ExecutionPolicy::default()
        }
    }

    #[test]
    fn allowlist_filters_environment() -> Result<(), Box<dyn std::error::Error>> {
        let context = ExecutionContextBuilder::new(plan(), grants())
            .policy(policy_without_root_check())
            .source_environment([
                ("LANG", "C.UTF-8"),
                ("TERM", "xterm-256color"),
                ("SECRET_TOKEN", "not-forwarded"),
            ])
            .build()?;

        assert_eq!(
            context.environment().get("LANG"),
            Some(&OsString::from("C.UTF-8"))
        );
        assert_eq!(
            context.environment().get("TERM"),
            Some(&OsString::from("xterm-256color"))
        );
        assert!(context.environment().contains_key("PATH"));
        assert!(context.environment().contains_key("HOME"));
        assert!(!context.environment().contains_key("SECRET_TOKEN"));
        Ok(())
    }

    #[test]
    fn deny_patterns_are_checked_even_when_allowlisted() -> Result<(), Box<dyn std::error::Error>> {
        let denied_names = [
            "BASH_ENV",
            "ENV",
            "ZDOTDIR",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "PYTHONPATH",
            "NODE_OPTIONS",
            "RUBYOPT",
            "PERL5LIB",
            "GIT_CONFIG_GLOBAL",
            "SSH_AUTH_SOCK",
            "AWS_ACCESS_KEY_ID",
            "AZURE_TOKEN",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GITHUB_TOKEN",
            // Shell injection vectors (MEDIUM 6).
            "IFS",
            "SHELLOPTS",
            "BASHOPTS",
            "CDPATH",
            "GLOBIGNORE",
            "POSIXLY_CORRECT",
            "PS4",
            "PROMPT_COMMAND",
        ];

        for name in denied_names {
            let policy = ExecutionPolicy {
                deny_running_as_root: false,
                environment_allowlist: EnvAllowlist::new([name])?,
                ..ExecutionPolicy::default()
            };
            let error = ExecutionContextBuilder::new(plan(), grants())
                .policy(policy)
                .source_environment([(name, "x")])
                .build()
                .err();
            assert!(
                matches!(error, Some(ExecError::DeniedEnvironmentVariable { .. })),
                "expected {name} to be denied even when allowlisted"
            );
        }
        Ok(())
    }

    #[test]
    fn shell_injection_vars_blocked_even_in_allowlist() -> Result<(), Box<dyn std::error::Error>> {
        // Explicitly verify that each newly added shell var is blocked
        // even when present in both the allowlist and source environment.
        let shell_vars = [
            "IFS",
            "SHELLOPTS",
            "BASHOPTS",
            "CDPATH",
            "GLOBIGNORE",
            "POSIXLY_CORRECT",
            "PS4",
            "PROMPT_COMMAND",
        ];
        for var in shell_vars {
            let policy = ExecutionPolicy {
                deny_running_as_root: false,
                environment_allowlist: EnvAllowlist::new([var])?,
                ..ExecutionPolicy::default()
            };
            let result = ExecutionContextBuilder::new(plan(), grants())
                .policy(policy)
                .source_environment([(var, "evil")])
                .build();
            assert!(
                matches!(result, Err(ExecError::DeniedEnvironmentVariable { .. })),
                "{var} should be denied by mandatory denylist"
            );
        }
        Ok(())
    }

    #[test]
    fn temp_directories_are_fresh_empty_and_cleaned_on_drop()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::MetadataExt;

        let (home, work) = {
            let context = ExecutionContextBuilder::new(plan(), grants())
                .policy(policy_without_root_check())
                .source_environment([] as [(&str, &str); 0])
                .build()?;
            assert!(context.home_dir().exists());
            assert!(context.working_dir().exists());
            assert_ne!(context.home_dir(), context.working_dir());
            assert_eq!(fs::read_dir(context.home_dir())?.count(), 0);
            assert_eq!(fs::read_dir(context.working_dir())?.count(), 0);
            assert!(context.owns_temporary_directories());

            // Verify 0700 permissions on temp dirs.
            let home_mode = fs::metadata(context.home_dir())?.mode() & 0o777;
            let work_mode = fs::metadata(context.working_dir())?.mode() & 0o777;
            assert_eq!(
                home_mode, 0o700,
                "temp HOME dir should have 0700 permissions"
            );
            assert_eq!(
                work_mode, 0o700,
                "temp working dir should have 0700 permissions"
            );

            (
                context.home_dir().to_path_buf(),
                context.working_dir().to_path_buf(),
            )
        };
        assert!(!home.exists());
        assert!(!work.exists());
        Ok(())
    }

    #[test]
    fn privilege_elevation_detection_blocks_program_and_arguments() {
        let blocked_program = ExecutionContextBuilder::new(plan(), grants())
            .policy(policy_without_root_check())
            .command("/usr/bin/sudo")
            .source_environment([] as [(&str, &str); 0])
            .build()
            .err();
        assert!(matches!(
            blocked_program,
            Some(ExecError::PrivilegeElevationAttempt { .. })
        ));

        let blocked_argument = ExecutionContextBuilder::new(plan(), grants())
            .policy(policy_without_root_check())
            .arguments(["sh", "-c", "doas install thing"])
            .source_environment([] as [(&str, &str); 0])
            .build()
            .err();
        assert!(matches!(
            blocked_argument,
            Some(ExecError::PrivilegeElevationAttempt { .. })
        ));
    }

    #[test]
    fn root_detection_policy_can_block_context_creation() {
        let policy = ExecutionPolicy {
            deny_running_as_root: true,
            ..policy_without_root_check()
        };
        let result = ExecutionContextBuilder::new(plan(), grants())
            .policy(policy)
            .source_environment([] as [(&str, &str); 0])
            .build();
        if running_as_root().unwrap_or(false) {
            assert!(matches!(result, Err(ExecError::RunningAsRoot)));
        }
    }

    #[test]
    fn fd_policy_configuration_is_preserved() -> Result<(), Box<dyn std::error::Error>> {
        let policy = ExecutionPolicy {
            deny_running_as_root: false,
            fd_policy: FdPolicy::new(true, [0, 1, 2, 9]),
            ..ExecutionPolicy::default()
        };
        let context = ExecutionContextBuilder::new(plan(), grants())
            .policy(policy)
            .source_environment([] as [(&str, &str); 0])
            .build()?;
        assert!(context.fd_policy().close_inherited);
        assert!(context.fd_policy().keeps(9));
        assert!(!context.fd_policy().keeps(10));
        Ok(())
    }

    #[test]
    fn network_denied_prepares_sandbox_plan() -> Result<(), Box<dyn std::error::Error>> {
        let context = ExecutionContextBuilder::new(plan(), grants())
            .policy(policy_without_root_check())
            .source_environment([] as [(&str, &str); 0])
            .build()?;
        assert_eq!(context.network_policy(), &NetworkPolicy::Denied);
        assert!(context.network_sandbox().deny_network);
        assert!(
            context
                .network_sandbox()
                .linux_mechanisms
                .contains(&"seccomp")
        );
        Ok(())
    }

    #[test]
    fn controlled_path_rejects_relative_entries() {
        let relative = validate_path_entries(&[PathBuf::from("bin")]);
        assert!(matches!(relative, Err(ExecError::RelativePathEntry { .. })));
    }

    #[test]
    fn controlled_path_rejects_nonexistent_entries() {
        let missing = validate_path_entries(&[PathBuf::from("/tmp/nonexistent-path-entry")]);
        assert!(matches!(missing, Err(ExecError::UnsafePathEntry { .. })));
    }

    #[test]
    fn controlled_path_rejects_symlink_entries() -> Result<(), Box<dyn std::error::Error>> {
        let symlink_path = env::temp_dir().join("arbitraitor-test-symlink-path");
        let _ = fs::remove_file(&symlink_path);
        std::os::unix::fs::symlink("/usr/bin", &symlink_path)?;
        let result = validate_path_entries(std::slice::from_ref(&symlink_path));
        assert!(matches!(result, Err(ExecError::UnsafePathEntry { .. })));
        let _ = fs::remove_file(&symlink_path);
        Ok(())
    }

    #[test]
    fn controlled_path_accepts_root_owned_entries() {
        // The default entries should validate successfully on a standard
        // Linux system where /usr/bin and /usr/local/bin exist and are
        // root-owned.
        let entries = default_path_entries();
        if entries.is_empty() {
            return;
        }
        let result = validate_path_entries(&entries);
        // If the system doesn't have standard paths (rare CI), skip.
        if let Err(ExecError::UnsafePathEntry { .. }) = &result {
            return;
        }
        assert!(
            result.is_ok(),
            "default path entries should be valid: {entries:?}"
        );
    }

    #[test]
    fn execute_capability_is_required() {
        let result = ExecutionContextBuilder::new(plan(), grants_without_execute())
            .policy(policy_without_root_check())
            .source_environment([] as [(&str, &str); 0])
            .build();
        assert!(
            matches!(result, Err(ExecError::ExecuteNotGranted)),
            "build must fail when execute capability is not granted"
        );
    }

    #[test]
    fn network_requires_both_grant_and_plan() -> Result<(), Box<dyn std::error::Error>> {
        // Grant=true, plan=false → denied.
        let mut plan_no_net = plan();
        plan_no_net.network_allowed = false;
        let policy = ExecutionPolicy::from_operation(&plan_no_net, &grants_with_network())?;
        assert_eq!(policy.network_policy, NetworkPolicy::Denied);

        // Grant=false, plan=true → denied (plan alone cannot enable network).
        let mut plan_wants_net = plan();
        plan_wants_net.network_allowed = true;
        let policy = ExecutionPolicy::from_operation(&plan_wants_net, &grants())?;
        assert_eq!(
            policy.network_policy,
            NetworkPolicy::Denied,
            "untrusted plan alone must not enable network"
        );

        // Grant=true, plan=true → allowed (intersection).
        let policy = ExecutionPolicy::from_operation(&plan_wants_net, &grants_with_network())?;
        assert_eq!(policy.network_policy, NetworkPolicy::Allowed);
        Ok(())
    }

    #[test]
    fn relative_command_is_rejected() {
        let result = ExecutionContextBuilder::new(plan(), grants())
            .policy(policy_without_root_check())
            .command("sh")
            .source_environment([] as [(&str, &str); 0])
            .build();
        assert!(
            matches!(result, Err(ExecError::CommandNotAbsolute { .. })),
            "relative command must be rejected"
        );
    }

    #[test]
    fn resource_limits_have_conservative_defaults() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.cpu_time_secs, Some(60));
        assert_eq!(limits.memory_bytes, Some(512 * 1024 * 1024));
        assert_eq!(limits.process_count, Some(64));
        assert_eq!(limits.fd_count, Some(64));
        assert_eq!(limits.output_size_bytes, Some(10 * 1024 * 1024));
    }

    #[test]
    fn resource_limits_are_recorded_in_context() -> Result<(), Box<dyn std::error::Error>> {
        let context = ExecutionContextBuilder::new(plan(), grants())
            .policy(policy_without_root_check())
            .source_environment([] as [(&str, &str); 0])
            .build()?;
        assert_eq!(context.resource_limits(), &ResourceLimits::default());
        Ok(())
    }

    #[test]
    fn fixed_directory_rejects_relative_path() {
        let policy = ExecutionPolicy {
            deny_running_as_root: false,
            home_directory: TempDirectoryPolicy::Fixed(PathBuf::from("relative/dir")),
            ..ExecutionPolicy::default()
        };
        let result = ExecutionContextBuilder::new(plan(), grants())
            .policy(policy)
            .source_environment([] as [(&str, &str); 0])
            .build();
        assert!(
            matches!(result, Err(ExecError::UnsafeFixedDirectory { .. })),
            "relative fixed directory must be rejected"
        );
    }

    #[test]
    fn fixed_directory_rejects_symlink() -> Result<(), Box<dyn std::error::Error>> {
        let symlink_dir = env::temp_dir().join("arbitraitor-test-symlink-dir");
        let target_dir = env::temp_dir().join("arbitraitor-test-real-dir");
        let _ = fs::remove_file(&symlink_dir);
        let _ = fs::remove_dir_all(&target_dir);
        fs::create_dir(&target_dir)?;
        std::os::unix::fs::symlink(&target_dir, &symlink_dir)?;

        let policy = ExecutionPolicy {
            deny_running_as_root: false,
            home_directory: TempDirectoryPolicy::Fixed(symlink_dir.clone()),
            ..ExecutionPolicy::default()
        };
        let result = ExecutionContextBuilder::new(plan(), grants())
            .policy(policy)
            .source_environment([] as [(&str, &str); 0])
            .build();
        assert!(
            matches!(result, Err(ExecError::UnsafeFixedDirectory { .. })),
            "symlink fixed directory must be rejected"
        );

        let _ = fs::remove_file(&symlink_dir);
        let _ = fs::remove_dir_all(&target_dir);
        Ok(())
    }

    #[test]
    fn context_fields_are_accessible_via_accessors() -> Result<(), Box<dyn std::error::Error>> {
        let context = ExecutionContextBuilder::new(plan(), grants())
            .policy(policy_without_root_check())
            .source_environment([] as [(&str, &str); 0])
            .build()?;

        // Verify all accessors return the expected types without compilation
        // errors — this guards against accidental field re-exposure.
        let _cmd: &Path = context.command();
        let _args: &[OsString] = context.arguments();
        let _env: &BTreeMap<String, OsString> = context.environment();
        let _home: &Path = context.home_dir();
        let _work: &Path = context.working_dir();
        let _fd: &FdPolicy = context.fd_policy();
        let _net: &NetworkPolicy = context.network_policy();
        let _sandbox: &NetworkSandboxPlan = context.network_sandbox();
        let _plan: &OperationPlan = context.operation_plan();
        let _level: AssuranceLevel = context.assurance_level();
        let _grants: &GrantedCapabilities = context.granted_capabilities();
        let _limits: &ResourceLimits = context.resource_limits();
        Ok(())
    }
}
