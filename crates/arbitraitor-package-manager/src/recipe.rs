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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionPattern {
    /// Arbitraitor acts as the configured registry URL.
    RegistryProxy,
    /// Arbitraitor inspects the committed lockfile before the tool runs.
    LockfilePrescan,
    /// Arbitraitor scans the populated cache after the tool completes.
    PostInstallScan,
    /// Arbitraitor isolates build scripts in a sandbox.
    BuildScriptSandbox,
}

/// The per-tool recipe mapping a tool to its primary and secondary
/// inspection patterns (spec §39.14.1). Every adapter MUST combine
/// multiple patterns — no single pattern covers all threat surfaces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterRecipe {
    primary: InspectionPattern,
    secondary: Vec<InspectionPattern>,
}

impl AdapterRecipe {
    /// Creates a new recipe. The secondary list must be non-empty
    /// per spec §39.14.1 (\"each adapter MUST combine multiple patterns\").
    ///
    /// # Panics
    ///
    /// Panics if `secondary` is empty.
    #[must_use]
    pub fn new(primary: InspectionPattern, secondary: Vec<InspectionPattern>) -> Self {
        assert!(
            !secondary.is_empty(),
            "AdapterRecipe secondary must be non-empty per spec §39.14.1"
        );
        Self { primary, secondary }
    }

    /// Returns the primary inspection pattern.
    #[must_use]
    pub const fn primary(&self) -> InspectionPattern {
        self.primary
    }

    /// Returns the secondary inspection patterns.
    #[must_use]
    pub fn secondary(&self) -> &[InspectionPattern] {
        &self.secondary
    }
}

/// Lifecycle-script enforcement policy per spec §39.14.3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleScriptPolicy {
    /// Scripts denied entirely (`--ignore-scripts`).
    DeniedByDefault,
    /// Scripts run only for policy-approved packages.
    AllowedWithTrustlist(Vec<String>),
    /// Scripts may run inside a sandbox (gVisor, arbitraitor-exec).
    SandboxRequired,
    /// Scripts approved per-package by explicit policy; uninspected
    /// packages produce incomplete coverage (cargo `build.rs` model).
    PolicyApprovedOrIncomplete,
}

/// Trait implemented by each per-tool registry adapter.
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
