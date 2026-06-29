//! Adapter trait and recipe types per spec §39.14.

use std::fmt::Debug;

/// The registry-based package manager being wrapped.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RegistryTool {
    /// Rust crates via cargo.
    Cargo,
    /// Python packages via uv.
    Uv,
    /// Python tools via uvx (`uv tool run`).
    Uvx,
    /// JavaScript packages via npm.
    Npm,
    /// JavaScript packages via pnpm.
    Pnpm,
    /// JavaScript packages via yarn classic (v1).
    YarnClassic,
    /// JavaScript packages via yarn berry (v2+).
    YarnBerry,
    /// JavaScript packages via bun.
    Bun,
}

impl RegistryTool {
    /// Returns the human-readable name used in receipts and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Uv => "uv",
            Self::Uvx => "uvx",
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::YarnClassic => "yarn-classic",
            Self::YarnBerry => "yarn-berry",
            Self::Bun => "bun",
        }
    }
}

/// The lockfile format associated with a registry tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockfileFormat {
    /// `Cargo.lock` (TOML, V1–V4).
    CargoLock,
    /// `uv.lock` (TOML, v1).
    UvLock,
    /// `package-lock.json` (JSON, v1–v3).
    PackageLockJson,
    /// `pnpm-lock.yaml` (YAML, v5–v9).
    PnpmLockYaml,
    /// `yarn.lock` (YAML-like text or YAML v6+).
    YarnLock,
    /// `bun.lock` (text YAML since bun 1.2).
    BunLock,
}

/// The hybrid integration patterns from spec §39.14.1.
///
/// Each adapter combines multiple patterns because no single pattern
/// covers every tool's threat surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionPattern {
    /// Arbitraitor acts as the configured registry URL, intercepting
    /// all tarball downloads.
    RegistryProxy,
    /// Arbitraitor inspects the committed lockfile before the tool runs.
    LockfilePrescan,
    /// Arbitraitor scans the populated cache or install directory after
    /// the tool completes.
    PostInstallScan,
    /// Arbitraitor isolates `build.rs`, PEP 517 builds, or postinstall
    /// scripts in a sandbox.
    BuildScriptSandbox,
}

/// The per-tool recipe mapping a tool to its primary and secondary
/// inspection patterns (spec §39.14.1 recipe table).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterRecipe {
    /// The primary inspection pattern (highest-coverage, binding).
    pub primary: InspectionPattern,
    /// Secondary patterns applied as defense-in-depth.
    pub secondary: Vec<InspectionPattern>,
}

/// Lifecycle-script enforcement policy per spec §39.14.3.
///
/// All adapters enforce `--ignore-scripts` by default. Selective
/// re-enabling requires explicit policy approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleScriptPolicy {
    /// Lifecycle scripts are denied entirely (`--ignore-scripts`).
    DeniedByDefault,
    /// Scripts run only for packages on the trust list; all others denied.
    AllowedWithTrustlist(Vec<String>),
    /// Scripts may run but only inside an isolated sandbox (e.g. gVisor
    /// for cargo `build.rs`, `arbitraitor-exec` for postinstall).
    SandboxRequired,
}

/// Trait implemented by each per-tool registry adapter.
///
/// Implementations live in first-party plugins (spec §39.14.2). This
/// trait defines the metadata contract — actual fetching, parsing, and
/// scanning happen in the adapter's plugin runtime.
pub trait RegistryAdapter: Send + Sync + Debug {
    /// Returns the tool this adapter wraps.
    fn tool(&self) -> RegistryTool;

    /// Returns the inspection recipe (primary + secondary patterns).
    fn recipe(&self) -> AdapterRecipe;

    /// Returns the lockfile format this adapter parses.
    fn lockfile_format(&self) -> LockfileFormat;

    /// Returns the lifecycle-script enforcement policy.
    fn lifecycle_script_policy(&self) -> LifecycleScriptPolicy;
}
