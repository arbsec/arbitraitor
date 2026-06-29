//! Receipt fields for registry-based package-manager operations
//! per spec §39.14.5.

/// Lifecycle script execution status recorded in the receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleScriptStatus {
    /// Scripts were denied (`--ignore-scripts` enforced).
    Denied,
    /// Scripts ran for trust-listed packages only.
    AllowedWithTrustlist,
    /// Scripts ran inside a sandbox.
    Sandboxed,
    /// The tool does not support lifecycle scripts (no build.rs, no
    /// postinstall model).
    NotApplicable,
}

/// The proxy mode used during inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyMode {
    /// Arbitraitor acted as the registry proxy.
    RegistryProxy,
    /// No proxy; lockfile pre-scan only.
    LockfilePrescan,
    /// No proxy; post-install scan only.
    PostInstallScan,
}

/// Receipt data recorded for each registry-mediated operation
/// (spec §39.14.5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageManagerReceipt {
    /// The wrapped tool name.
    pub tool: String,
    /// The wrapped tool version.
    pub tool_version: String,
    /// SHA-256 of the inspected lockfile.
    pub lockfile_digest: String,
    /// Number of packages inspected.
    pub packages_inspected: usize,
    /// Number of packages blocked by policy.
    pub packages_blocked: usize,
    /// Number of packages with incomplete coverage.
    pub packages_incomplete: usize,
    /// Lifecycle script enforcement status.
    pub lifecycle_scripts: LifecycleScriptStatus,
    /// Sandbox used for build-script execution, if any.
    pub build_sandbox: Option<String>,
    /// The proxy mode used.
    pub proxy_mode: ProxyMode,
}
