//! Package manager lifecycle adapters.
//!
//! Defines the shared trait, types, and error model that per-tool
//! registry-based package-manager adapters (cargo, uv/uvx, npm, pnpm,
//! yarn, bun) implement. See spec §39.14 for the binding requirements.
//!
//! Per-tool adapter implementations live in separate first-party plugins
//! (spec §39.14.2). This crate provides the foundation they build on.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod receipt;
pub mod recipe;

pub use error::AdapterManagerError;
pub use receipt::{CapabilityGrant, LifecycleScriptStatus, PackageManagerReceipt, ProxyMode};
pub use recipe::{
    AdapterRecipe, InspectionPattern, LifecycleScriptPolicy, LockfileFormat, RegistryAdapter,
    RegistryTool,
};
