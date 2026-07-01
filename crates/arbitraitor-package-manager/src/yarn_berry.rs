//! Yarn Berry adapter — JavaScript package manager (yarn v2+).
//!
//! Implements spec §39.14.1 yarn berry row. Yarn Berry has
//! `enableHardenedMode` and `npmMinimalAgeGate` settings. Arbitraitor
//! extends via registry proxy and post-install scanning.

#![forbid(unsafe_code)]

use crate::recipe::{
    AdapterRecipe, InspectionPattern, LifecycleScriptPolicy, LockfileFormat, RegistryAdapter,
    RegistryTool,
};

/// Yarn Berry (v2+) registry adapter (spec §39.14.1).
#[derive(Clone, Debug)]
pub struct YarnBerryAdapter;

impl RegistryAdapter for YarnBerryAdapter {
    fn tool(&self) -> RegistryTool {
        RegistryTool::YarnBerry
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
        LockfileFormat::YarnLock
    }

    fn lifecycle_script_policy(&self) -> LifecycleScriptPolicy {
        LifecycleScriptPolicy::AllowedWithTrustlist(Vec::new())
    }
}
