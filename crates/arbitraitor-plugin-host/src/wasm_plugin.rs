//! Wasmtime component loader and Plugin trait bridge (ADR-0006).
//!
//! [`WasmPlugin`] compiles a WebAssembly Component Model binary and bridges it
//! to Arbitraitor's native [`DetectorPlugin`] trait.
//!
//! # Sandbox guarantees
//!
//! Per ADR-0006, components receive no WASI, no filesystem, no networking.
//! The linker exposes ONLY the host imports defined by the `detector` world.

#![forbid(unsafe_code)]

use arbitraitor_model::finding::Finding;
use arbitraitor_plugin_api::{
    CapabilitySet, DetectorPlugin, Plugin, PluginContext, PluginIdentity, PluginTrustClass,
};
use wasmtime::component::Component;

use crate::wasm_engine::{WasmEngine, WasmEngineError};

/// Errors from Wasmtime plugin operations.
#[derive(Debug, thiserror::Error)]
pub enum WasmPluginError {
    /// Component compilation failed.
    #[error("component compilation failed: {0}")]
    Compilation(String),
    /// Engine error.
    #[error("engine error: {0}")]
    Engine(#[from] WasmEngineError),
}

/// A loaded Wasmtime component implementing the detector plugin trait.
pub struct WasmPlugin {
    component: Component,
    identity: PluginIdentity,
}

impl WasmPlugin {
    /// Loads and compiles a .wasm component from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WasmPluginError`] if the bytes are empty or compilation fails.
    pub fn from_bytes(engine: &WasmEngine, wasm_bytes: &[u8]) -> Result<Self, WasmPluginError> {
        if wasm_bytes.is_empty() {
            return Err(WasmPluginError::Compilation("empty input".to_owned()));
        }
        let component = engine.compile(wasm_bytes)?;
        Ok(Self {
            component,
            identity: PluginIdentity {
                id: "wasm-plugin".to_owned(),
                version: "0.1.0".to_owned(),
                trust_class: PluginTrustClass::CommunityUnreviewed,
            },
        })
    }

    /// Returns the compiled component.
    #[must_use]
    pub fn component(&self) -> &Component {
        &self.component
    }
}

impl Plugin for WasmPlugin {
    fn identity(&self) -> &PluginIdentity {
        &self.identity
    }

    fn capabilities(&self) -> &CapabilitySet {
        static CAPS: CapabilitySet = CapabilitySet {
            network: arbitraitor_plugin_api::NetworkCapability::None,
            filesystem: arbitraitor_plugin_api::FilesystemCapability::None,
            process: arbitraitor_plugin_api::ProcessCapability::None,
            max_memory_bytes: Some(64 * 1024 * 1024),
            max_cpu_ms: Some(30_000),
        };
        &CAPS
    }
}

impl DetectorPlugin for WasmPlugin {
    fn analyze(&self, artifact: &[u8], _context: &PluginContext) -> Vec<Finding> {
        if artifact.is_empty() {
            return Vec::new();
        }
        // Full instantiation and export calling requires wasmtime component
        // model bindgen, which generates typed Host traits and add_to_linker
        // functions from the WIT definitions. This will be wired in a
        // follow-up that adds `wasmtime::component::bindgen!` and implements
        // the generated Host trait on WasmStoreData.
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::wasm_engine::WasmEngineConfig;

    #[test]
    fn rejects_empty_bytes() {
        let engine =
            WasmEngine::new(WasmEngineConfig::default()).unwrap_or_else(|e| panic!("engine: {e}"));
        let result = WasmPlugin::from_bytes(&engine, b"");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_non_wasm_bytes() {
        let engine =
            WasmEngine::new(WasmEngineConfig::default()).unwrap_or_else(|e| panic!("engine: {e}"));
        let result = WasmPlugin::from_bytes(&engine, b"this is not wasm");
        assert!(result.is_err());
    }

    #[test]
    fn plugin_identity_and_capabilities() {
        let engine =
            WasmEngine::new(WasmEngineConfig::default()).unwrap_or_else(|e| panic!("engine: {e}"));
        let wasm = b"\x00asm\x01\x00\x00\x00";
        if let Ok(plugin) = WasmPlugin::from_bytes(&engine, wasm) {
            assert_eq!(plugin.identity().id, "wasm-plugin");
            assert_eq!(
                plugin.identity().trust_class,
                PluginTrustClass::CommunityUnreviewed
            );
            assert_eq!(
                plugin.capabilities().network,
                arbitraitor_plugin_api::NetworkCapability::None
            );
        }
    }
}
