//! Yarn Classic adapter — JavaScript package manager (yarn v1).
//!
//! Implements spec §39.14.1 yarn classic row. Yarn Classic (v1) is a
//! community plugin candidate — it lacks hardened mode and has a simpler
//! `yarn.lock` format. Arbitraitor provides registry proxy and lockfile
//! pre-scan.

#![forbid(unsafe_code)]

use crate::recipe::{
    AdapterRecipe, InspectionPattern, LifecycleScriptPolicy, LockfileFormat, RegistryAdapter,
    RegistryTool,
};

/// Yarn Classic (v1) registry adapter (spec §39.14.1).
#[derive(Clone, Debug)]
pub struct YarnClassicAdapter;

impl RegistryAdapter for YarnClassicAdapter {
    fn tool(&self) -> RegistryTool {
        RegistryTool::YarnClassic
    }

    fn recipe(&self) -> AdapterRecipe {
        AdapterRecipe::new(
            InspectionPattern::RegistryProxy,
            vec![InspectionPattern::LockfilePrescan],
        )
    }

    fn lockfile_format(&self) -> LockfileFormat {
        LockfileFormat::YarnLock
    }

    fn lifecycle_script_policy(&self) -> LifecycleScriptPolicy {
        LifecycleScriptPolicy::DeniedByDefault
    }
}
