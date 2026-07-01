//! Bun adapter — JavaScript runtime and package manager.
//!
//! Implements spec §39.14.1 bun row. Bun ships a Security Scanner API
//! and a `bun.lock` format (YAML since v1.2). Arbitraitor integrates via
//! registry proxy and post-install scanning.

#![forbid(unsafe_code)]

use crate::recipe::{
    AdapterRecipe, InspectionPattern, LifecycleScriptPolicy, LockfileFormat, RegistryAdapter,
    RegistryTool,
};

/// Bun registry adapter (spec §39.14.1).
#[derive(Clone, Debug)]
pub struct BunAdapter;

impl RegistryAdapter for BunAdapter {
    fn tool(&self) -> RegistryTool {
        RegistryTool::Bun
    }

    fn recipe(&self) -> AdapterRecipe {
        AdapterRecipe::new(
            InspectionPattern::RegistryProxy,
            vec![
                InspectionPattern::LockfilePrescan,
                InspectionPattern::PostInstallScan,
            ],
        )
    }

    fn lockfile_format(&self) -> LockfileFormat {
        LockfileFormat::BunLock
    }

    fn lifecycle_script_policy(&self) -> LifecycleScriptPolicy {
        LifecycleScriptPolicy::SandboxRequired
    }
}
