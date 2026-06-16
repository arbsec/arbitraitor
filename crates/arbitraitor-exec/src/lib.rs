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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use arbitraitor_model::operation::{GrantedCapabilities, OperationPlan};
use arbitraitor_model::verdict::AssuranceLevel;
use thiserror::Error;
use tracing::debug;

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Default `PATH` used when policy does not provide a stricter value.
pub const DEFAULT_CONTROLLED_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// File descriptors inherited by default: stdin, stdout, and stderr.
pub const DEFAULT_KEEP_FDS: [i32; 3] = [0, 1, 2];

/// Errors returned while constructing a mediated execution context.
#[derive(Debug, Error)]
pub enum ExecError {
    /// The current Arbitraitor process is running with elevated privileges.
    #[error("refusing to build execution context while running as root")]
    RunningAsRoot,
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
    /// A configured PATH entry is user-writable or otherwise unsafe.
    #[error("controlled PATH entry is user writable or unsafe: {path}")]
    UnsafePathEntry {
        /// Rejected PATH entry.
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
    /// File descriptor inheritance policy.
    pub fd_policy: FdPolicy,
    /// HOME directory policy.
    pub home_directory: TempDirectoryPolicy,
    /// Working directory policy.
    pub working_directory: TempDirectoryPolicy,
    /// Whether privilege elevation attempts are blocked.
    pub deny_privilege_elevation: bool,
    /// Whether running Arbitraitor as root is blocked.
    pub deny_running_as_root: bool,
}

impl ExecutionPolicy {
    /// Returns the controlled PATH string for this policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured PATH is empty, relative, or user-writable.
    pub fn controlled_path(&self) -> Result<OsString, ExecError> {
        validate_path_entries(&self.path_entries)?;
        let joined = env::join_paths(&self.path_entries).map_err(|_| ExecError::EmptyPath)?;
        Ok(joined)
    }

    /// Builds a policy from an operation plan and granted capabilities.
    ///
    /// # Errors
    ///
    /// Returns an error when operation-provided environment allowlist entries are invalid.
    pub fn from_operation(
        plan: &OperationPlan,
        granted_capabilities: &GrantedCapabilities,
    ) -> Result<Self, ExecError> {
        let mut policy = Self {
            network_policy: if granted_capabilities.network() || plan.network_allowed {
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
        }
    }
}

/// A built mediated execution context for a safe child process environment.
pub struct ExecutionContext {
    /// Operation plan bound to this execution context.
    pub operation_plan: OperationPlan,
    /// Effective assurance level for this context.
    pub assurance_level: AssuranceLevel,
    /// Policy-granted capabilities used while building the context.
    pub granted_capabilities: GrantedCapabilities,
    /// Command executable selected by policy and plan.
    pub command: PathBuf,
    /// Command arguments after privilege-elevation validation.
    pub arguments: Vec<OsString>,
    /// Fully constructed child environment.
    pub environment: BTreeMap<String, OsString>,
    /// HOME directory assigned to the child.
    pub home_dir: PathBuf,
    /// Working directory assigned to the child.
    pub working_dir: PathBuf,
    /// File descriptor inheritance policy to apply at spawn time.
    pub fd_policy: FdPolicy,
    /// Network policy to enforce in the sandbox crate.
    pub network_policy: NetworkPolicy,
    /// Prepared sandbox configuration for the network policy.
    pub network_sandbox: NetworkSandboxPlan,
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
    /// Returns an error when root execution, privilege elevation, environment,
    /// PATH, or temporary directory checks fail.
    pub fn build(self) -> Result<ExecutionContext, ExecError> {
        if self.policy.deny_running_as_root && running_as_root()? {
            return Err(ExecError::RunningAsRoot);
        }

        let command = self.command.unwrap_or_else(|| PathBuf::from("/bin/sh"));
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

fn default_path_entries() -> Vec<PathBuf> {
    ["/usr/local/bin", "/usr/bin", "/bin"]
        .into_iter()
        .map(PathBuf::from)
        .collect()
}

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
        if is_user_writable_path(entry) {
            return Err(ExecError::UnsafePathEntry {
                path: entry.clone(),
            });
        }
    }
    Ok(())
}

fn is_user_writable_path(path: &Path) -> bool {
    path.starts_with("/tmp")
        || path.starts_with("/var/tmp")
        || path.starts_with("/dev/shm")
        || env::var_os("HOME").is_some_and(|home| path.starts_with(home))
}

fn materialize_directory(
    policy: &TempDirectoryPolicy,
) -> Result<(PathBuf, Option<OwnedTempDir>), ExecError> {
    match policy {
        TempDirectoryPolicy::Temporary => {
            let directory = create_temporary_directory()?;
            Ok((directory.path().to_path_buf(), Some(directory)))
        }
        TempDirectoryPolicy::Fixed(path) => Ok((path.clone(), None)),
    }
}

fn create_temporary_directory() -> Result<OwnedTempDir, ExecError> {
    let base = env::temp_dir();
    for _attempt in 0..128 {
        let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = base.join(format!("arbitraitor-exec-{}-{counter}", std::process::id()));
        match fs::create_dir(&candidate) {
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
            context.environment.get("LANG"),
            Some(&OsString::from("C.UTF-8"))
        );
        assert_eq!(
            context.environment.get("TERM"),
            Some(&OsString::from("xterm-256color"))
        );
        assert!(context.environment.contains_key("PATH"));
        assert!(context.environment.contains_key("HOME"));
        assert!(!context.environment.contains_key("SECRET_TOKEN"));
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
            assert!(matches!(
                error,
                Some(ExecError::DeniedEnvironmentVariable { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn temp_directories_are_fresh_empty_and_cleaned_on_drop()
    -> Result<(), Box<dyn std::error::Error>> {
        let (home, work) = {
            let context = ExecutionContextBuilder::new(plan(), grants())
                .policy(policy_without_root_check())
                .source_environment([] as [(&str, &str); 0])
                .build()?;
            assert!(context.home_dir.exists());
            assert!(context.working_dir.exists());
            assert_ne!(context.home_dir, context.working_dir);
            assert_eq!(fs::read_dir(&context.home_dir)?.count(), 0);
            assert_eq!(fs::read_dir(&context.working_dir)?.count(), 0);
            assert!(context.owns_temporary_directories());
            (context.home_dir.clone(), context.working_dir.clone())
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
        assert!(context.fd_policy.close_inherited);
        assert!(context.fd_policy.keeps(9));
        assert!(!context.fd_policy.keeps(10));
        Ok(())
    }

    #[test]
    fn network_denied_prepares_sandbox_plan() -> Result<(), Box<dyn std::error::Error>> {
        let context = ExecutionContextBuilder::new(plan(), grants())
            .policy(policy_without_root_check())
            .source_environment([] as [(&str, &str); 0])
            .build()?;
        assert_eq!(context.network_policy, NetworkPolicy::Denied);
        assert!(context.network_sandbox.deny_network);
        assert!(
            context
                .network_sandbox
                .linux_mechanisms
                .contains(&"seccomp")
        );
        Ok(())
    }

    #[test]
    fn controlled_path_rejects_relative_or_user_writable_entries() {
        let relative = validate_path_entries(&[PathBuf::from("bin")]);
        assert!(matches!(relative, Err(ExecError::RelativePathEntry { .. })));

        let writable = validate_path_entries(&[PathBuf::from("/tmp/bin")]);
        assert!(matches!(writable, Err(ExecError::UnsafePathEntry { .. })));
    }
}
