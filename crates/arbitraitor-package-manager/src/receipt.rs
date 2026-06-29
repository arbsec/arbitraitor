//! Receipt fields for registry-based package-manager operations
//! per spec §39.14.5.

use arbitraitor_model::ids::Sha256Digest;

/// Lifecycle script execution status recorded in the receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleScriptStatus {
    /// Scripts were denied (`--ignore-scripts` enforced).
    Denied,
    /// Scripts ran for policy-approved packages only (§39.14.3).
    PolicyApproved,
    /// Scripts ran inside a sandbox.
    Sandboxed,
    /// Some packages have uninspected lifecycle scripts (e.g. cargo
    /// `build.rs` that was neither approved nor sandboxed). The verdict
    /// must reflect `incomplete` coverage.
    IncompleteCoverage,
    /// The tool does not support lifecycle scripts.
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

/// Capability grant recorded per spec §39.14.4.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityGrant {
    /// Capability name (e.g. `parse_argv`, `read_lockfile`, `spawn_tool`).
    pub name: String,
    /// Whether the capability was granted or denied.
    pub granted: bool,
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
    pub lockfile_digest: Sha256Digest,
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
    /// Capability grants exercised by the adapter (§39.14.4).
    pub capabilities: Vec<CapabilityGrant>,
}
