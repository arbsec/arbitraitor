//! pnpm adapter — JavaScript package manager integration via pnpm.
//!
//! Implements spec §39.14.1 pnpm row. pnpm has built-in supply-chain features
//! (`pnpm audit`, `pnpm install --ignore-scripts`) and a structured lockfile
//! (`pnpm-lock.yaml`). Arbitraitor extends these with artifact-level inspection.

#![forbid(unsafe_code)]

use crate::recipe::{
    AdapterRecipe, InspectionPattern, LifecycleScriptPolicy, LockfileFormat, RegistryAdapter,
    RegistryTool,
};

/// pnpm registry adapter (spec §39.14.1).
#[derive(Clone, Debug)]
pub struct PnpmAdapter;

impl RegistryAdapter for PnpmAdapter {
    fn tool(&self) -> RegistryTool {
        RegistryTool::Pnpm
    }

    fn recipe(&self) -> AdapterRecipe {
        AdapterRecipe::new(
            InspectionPattern::LockfilePrescan,
            vec![
                InspectionPattern::PostInstallScan,
                InspectionPattern::RegistryProxy,
            ],
        )
    }

    fn lockfile_format(&self) -> LockfileFormat {
        LockfileFormat::PnpmLockYaml
    }

    fn lifecycle_script_policy(&self) -> LifecycleScriptPolicy {
        LifecycleScriptPolicy::DeniedByDefault
    }
}
