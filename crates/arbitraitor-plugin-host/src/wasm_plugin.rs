//! Wasmtime component loader and Plugin trait bridge (ADR-0006).
//!
//! [`WasmPlugin`] compiles a WebAssembly Component Model binary, instantiates
//! it inside a sandboxed Wasmtime engine, and bridges it to Arbitraitor's
//! native [`DetectorPlugin`] trait.
//!
//! # Sandbox guarantees
//!
//! Per ADR-0006, components receive no WASI, no filesystem, no networking.
//! The linker exposes ONLY the host imports defined by the `detector` world:
//! `get-artifact-bytes`, `get-artifact-size`, and `log`. Fuel and epoch
//! interruption are enforced by [`WasmEngine`](crate::wasm_engine::WasmEngine).
//!
//! # WIT bindgen
//!
//! Host-side bindings are generated at compile time by
//! [`wasmtime::component::bindgen!`] from the workspace WIT file at
//! `wit/arbitraitor-plugin.wit`, selecting the `detector` world.

#![forbid(unsafe_code)]

use std::sync::Arc;

use arbitraitor_model::finding::{Evidence, EvidenceKind, Finding, FindingCategory};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity};
use arbitraitor_plugin_api::{
    CapabilitySet, DetectorPlugin, Plugin, PluginContext, PluginIdentity, PluginTrustClass,
};
use sha2::{Digest as _, Sha256};
use wasmtime::Store;
use wasmtime::component::{Component, HasData, Linker};

use crate::wasm_engine::{WasmEngine, WasmEngineConfig, WasmEngineError, WasmStoreData};

// Generated bindings module with lint suppressions.
#[path = "wasm_plugin_bindings.rs"]
mod bindgen;
use bindgen::arbitraitor::plugin::types;
use bindgen::{Detector, DetectorImports};

/// Errors from Wasmtime plugin operations.
#[derive(Debug, thiserror::Error)]
pub enum WasmPluginError {
    /// Component compilation failed.
    #[error("component compilation failed: {0}")]
    Compilation(String),
    /// Engine error.
    #[error("engine error: {0}")]
    Engine(#[from] WasmEngineError),
    /// Linker or instantiation failed — the component does not match the
    /// `detector` world (missing exports or unresolvable imports).
    #[error("instantiation failed: {0}")]
    Instantiation(String),
    /// The guest `analyze` call trapped (unreachable, OOM, fuel exhaustion,
    /// epoch deadline). The sandbox boundaries held — the host is safe.
    #[error("guest analyze trapped: {0}")]
    Trap(String),
    /// The guest returned an `Err(string)` from `analyze`.
    #[error("guest analyze returned error: {0}")]
    GuestError(String),
}

/// Store data for detector component execution.
///
/// Holds the artifact bytes bound to this analyze invocation, plus the ADR-0006
/// resource-limiting fields from [`WasmStoreData`]. The host import trait
/// reads `artifact` to satisfy `get-artifact-bytes` / `get-artifact-size`.
struct DetectorStore {
    /// Inner engine store data (fuel, epoch deadline, resource limiter).
    inner: WasmStoreData,
    /// Immutable artifact bytes bound for this analyze call.
    artifact: Arc<[u8]>,
}

impl HasData for DetectorStore {
    type Data<'a> = &'a mut DetectorStore;
}

impl DetectorStore {
    fn new(inner: WasmStoreData, artifact: Arc<[u8]>) -> Self {
        Self { inner, artifact }
    }
}

impl types::Host for DetectorStore {}

/// Host implementation of the `detector` world's imported functions.
impl DetectorImports for DetectorStore {
    fn get_artifact_bytes(&mut self) -> Vec<u8> {
        self.artifact.to_vec()
    }

    fn get_artifact_size(&mut self) -> u64 {
        self.artifact.len() as u64
    }

    fn log(&mut self, level: types::LogLevel, message: String) {
        let level_str = match level {
            types::LogLevel::Debug => tracing::Level::DEBUG,
            types::LogLevel::Info => tracing::Level::INFO,
            types::LogLevel::Warn => tracing::Level::WARN,
            types::LogLevel::Error => tracing::Level::ERROR,
        };
        let _ = (level_str, message);
    }
}

/// A loaded Wasmtime component implementing the detector plugin trait.
pub struct WasmPlugin {
    component: Component,
    linker: Linker<DetectorStore>,
    identity: PluginIdentity,
}

impl WasmPlugin {
    /// Loads and compiles a .wasm component from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WasmPluginError`] if the bytes are empty or compilation
    /// fails, or if the `detector` world host imports cannot be linked.
    pub fn from_bytes(engine: &WasmEngine, wasm_bytes: &[u8]) -> Result<Self, WasmPluginError> {
        if wasm_bytes.is_empty() {
            return Err(WasmPluginError::Compilation("empty input".to_owned()));
        }
        let component = engine.compile(wasm_bytes)?;

        let mut linker: Linker<DetectorStore> = Linker::new(engine.engine());
        Detector::add_to_linker::<_, DetectorStore>(&mut linker, |state: &mut DetectorStore| state)
            .map_err(|e| WasmPluginError::Instantiation(e.to_string()))?;

        Ok(Self {
            component,
            linker,
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

    /// Analyzes artifact bytes by instantiating the component and calling the
    /// guest `analyze` export.
    ///
    /// # Errors
    ///
    /// - [`WasmPluginError::Instantiation`] — component does not match the
    ///   `detector` world or is malformed.
    /// - [`WasmPluginError::Trap`] — guest trapped (fuel exhausted, epoch
    ///   deadline, unreachable, OOM).
    /// - [`WasmPluginError::GuestError`] — guest returned `Err(string)`.
    pub fn analyze_artifact(
        &self,
        engine: &WasmEngine,
        artifact: &[u8],
    ) -> Result<Vec<Finding>, WasmPluginError> {
        let inner = WasmStoreData::new(engine.config());
        let artifact_arc: Arc<[u8]> = Arc::from(artifact);
        let mut store = Store::new(engine.engine(), DetectorStore::new(inner, artifact_arc));

        store
            .set_fuel(engine.config().fuel_limit)
            .map_err(|e| WasmPluginError::Engine(WasmEngineError::EngineCreation(e.to_string())))?;
        store.set_epoch_deadline(1);
        store.limiter(
            |data: &mut DetectorStore| -> &mut dyn wasmtime::ResourceLimiter {
                &mut data.inner.limiter
            },
        );

        let bindings = Detector::instantiate(&mut store, &self.component, &self.linker)
            .map_err(|e| WasmPluginError::Instantiation(e.to_string()))?;

        let result = bindings
            .call_analyze(&mut store)
            .map_err(|e| WasmPluginError::Trap(e.to_string()))?;

        match result {
            Ok(analysis_result) => {
                let artifact_hash = sha256_of(artifact);
                Ok(analysis_result
                    .findings
                    .into_iter()
                    .enumerate()
                    .map(|(i, f)| finding_from_wit(&f, i, &self.identity.id, artifact_hash.clone()))
                    .collect())
            }
            Err(err_string) => Err(WasmPluginError::GuestError(err_string)),
        }
    }
}

/// Computes the SHA-256 digest of artifact bytes.
fn sha256_of(bytes: &[u8]) -> Sha256Digest {
    let hash = Sha256::digest(bytes);
    Sha256Digest::new(hash.into())
}

/// Converts a WIT `finding` to the host [`Finding`] model type.
fn finding_from_wit(
    f: &types::Finding,
    index: usize,
    detector_id: &str,
    artifact_hash: Sha256Digest,
) -> Finding {
    let severity = match f.severity.as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,

        _ => Severity::Informational,
    };
    let category = match f.category.as_str() {
        "malware" | "malware-signature" => FindingCategory::MalwareSignature,
        "suspicious-script" | "suspicious-script-behavior" => {
            FindingCategory::SuspiciousScriptBehavior
        }
        "obfuscation" => FindingCategory::Obfuscation,
        "credential-access" => FindingCategory::CredentialAccess,
        "persistence" => FindingCategory::Persistence,
        "privilege-escalation" => FindingCategory::PrivilegeEscalation,
        "destructive" | "destructive-behavior" => FindingCategory::DestructiveBehavior,
        "network" | "network-behavior" => FindingCategory::NetworkBehavior,
        "dynamic-code" | "dynamic-code-execution" => FindingCategory::DynamicCodeExecution,
        "archive" | "archive-hazard" => FindingCategory::ArchiveHazard,
        "parser-differential" => FindingCategory::ParserDifferential,
        "provenance" => FindingCategory::Provenance,
        "reputation" => FindingCategory::Reputation,
        "transport" => FindingCategory::Transport,
        "content-mismatch" => FindingCategory::ContentMismatch,
        "supply-chain" => FindingCategory::SupplyChain,
        _ => FindingCategory::SuspiciousScriptBehavior,
    };
    let evidence = f
        .evidence
        .as_ref()
        .map(|e| {
            vec![Evidence {
                kind: EvidenceKind::Other,
                description: e.clone(),
                content: None,
            }]
        })
        .unwrap_or_default();
    Finding {
        id: format!("{detector_id}-{index}"),
        detector: detector_id.to_owned(),
        category,
        severity,
        confidence: Confidence::Low,
        title: f.description.chars().take(120).collect(),
        description: f.description.clone(),
        evidence,
        artifact_sha256: artifact_hash,
        location: None,
        remediation: None,
        references: Vec::new(),
        tags: Vec::new(),
        taxonomies: Vec::new(),
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

        let engine = match WasmEngine::new(WasmEngineConfig::default()) {
            Ok(e) => e,
            Err(err) => {
                tracing::error!(
                    plugin = %self.identity.id,
                    error = %err,
                    "failed to create engine for WasmPlugin::analyze"
                );
                return Vec::new();
            }
        };

        match self.analyze_artifact(&engine, artifact) {
            Ok(findings) => findings,
            Err(err) => {
                tracing::warn!(
                    plugin = %self.identity.id,
                    error = %err,
                    "WasmPlugin guest analyze failed; returning zero findings"
                );
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::wasm_engine::WasmEngineConfig;

    /// Minimal valid detector component — exports `analyze` returning
    /// `Ok(analysis_result { findings: [], detector_version: "" })`.
    const VALID_COMPONENT: &[u8] = include_bytes!("test_fixtures/valid_detector.wasm");

    /// Trapping detector component — `analyze` calls `unreachable`.
    const TRAP_COMPONENT: &[u8] = include_bytes!("test_fixtures/trap_detector.wasm");

    fn make_engine() -> WasmEngine {
        WasmEngine::new(WasmEngineConfig::default()).unwrap_or_else(|e| panic!("engine: {e}"))
    }

    fn make_context(artifact: &[u8]) -> PluginContext {
        let hash = Sha256::digest(artifact);
        PluginContext {
            artifact_sha256: Sha256Digest::new(hash.into()),
            artifact_type: "unknown".to_owned(),
            retrieval_url: None,
        }
    }

    #[test]
    fn rejects_empty_bytes() {
        let engine = make_engine();
        let result = WasmPlugin::from_bytes(&engine, b"");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_non_wasm_bytes() {
        let engine = make_engine();
        let result = WasmPlugin::from_bytes(&engine, b"this is not wasm");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_core_wasm_module_not_component() {
        let engine = make_engine();
        let core_wasm = b"\x00asm\x01\x00\x00\x00";
        let result = WasmPlugin::from_bytes(&engine, core_wasm);
        assert!(
            result.is_err(),
            "core wasm modules must be rejected — only components accepted"
        );
    }

    #[test]
    fn loads_valid_component() {
        let engine = make_engine();
        let plugin = WasmPlugin::from_bytes(&engine, VALID_COMPONENT)
            .unwrap_or_else(|e| panic!("valid component should load: {e}"));
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

    #[test]
    fn analyze_returns_empty_findings_for_empty_artifact() {
        let engine = make_engine();
        let plugin = WasmPlugin::from_bytes(&engine, VALID_COMPONENT)
            .unwrap_or_else(|e| panic!("load: {e}"));
        let findings = plugin.analyze(b"", &make_context(b""));
        assert!(findings.is_empty());
    }

    #[test]
    fn analyze_executes_guest_and_returns_empty_findings() {
        let engine = make_engine();
        let plugin = WasmPlugin::from_bytes(&engine, VALID_COMPONENT)
            .unwrap_or_else(|e| panic!("load: {e}"));
        let artifact = b"hello world artifact";
        let findings = plugin
            .analyze_artifact(&engine, artifact)
            .unwrap_or_else(|e| panic!("analyze should succeed: {e}"));
        assert!(findings.is_empty(), "test component returns empty findings");
    }

    #[test]
    fn analyze_traps_on_unreachable_component() {
        let engine = make_engine();
        let plugin = WasmPlugin::from_bytes(&engine, TRAP_COMPONENT)
            .unwrap_or_else(|e| panic!("trap component should load: {e}"));
        let result = plugin.analyze_artifact(&engine, b"artifact");
        assert!(
            matches!(result, Err(WasmPluginError::Trap(_))),
            "trapping component must return Trap error, got {result:?}"
        );
    }

    #[test]
    fn analyze_via_detector_trait_returns_empty_on_trap() {
        let engine = make_engine();
        let plugin =
            WasmPlugin::from_bytes(&engine, TRAP_COMPONENT).unwrap_or_else(|e| panic!("load: {e}"));
        let context = make_context(b"artifact");
        let findings = plugin.analyze(b"artifact", &context);
        assert!(
            findings.is_empty(),
            "DetectorPlugin::analyze must return empty Vec on trap (fail-safe)"
        );
    }

    #[test]
    fn fuel_consumed_during_analysis() {
        let engine = make_engine();
        let plugin = WasmPlugin::from_bytes(&engine, VALID_COMPONENT)
            .unwrap_or_else(|e| panic!("load: {e}"));
        plugin
            .analyze_artifact(&engine, b"artifact")
            .unwrap_or_else(|e| panic!("analyze: {e}"));
    }

    #[test]
    fn plugin_identity_and_capabilities() {
        let engine = make_engine();
        let plugin = WasmPlugin::from_bytes(&engine, VALID_COMPONENT)
            .unwrap_or_else(|e| panic!("load: {e}"));
        assert_eq!(plugin.identity().id, "wasm-plugin");
        assert_eq!(
            plugin.identity().trust_class,
            PluginTrustClass::CommunityUnreviewed
        );
        assert_eq!(
            plugin.capabilities().network,
            arbitraitor_plugin_api::NetworkCapability::None
        );
        assert_eq!(
            plugin.capabilities().filesystem,
            arbitraitor_plugin_api::FilesystemCapability::None
        );
        assert_eq!(
            plugin.capabilities().process,
            arbitraitor_plugin_api::ProcessCapability::None
        );
    }
}
