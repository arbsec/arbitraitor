//! Typed error surface for the pipeline engine.

use arbitraitor_model::verdict::Verdict;
use thiserror::Error;

/// Errors returned by the pipeline engine.
///
/// Store failures are reported as safe diagnostic strings rather than the
/// internal `arbitraitor_store::StoreError` type so the public surface does
/// not leak internal crate types (ADR-0038 decision 7).
#[derive(Debug, Error)]
pub enum EngineError {
    /// A retrieval or transport failure occurred.
    #[error("fetch failed: {0}")]
    Fetch(String),
    /// The referenced artifact digest is not present in the store.
    #[error("artifact not found: {0}")]
    NotFound(String),
    /// The store reported an error.
    #[error("store error: {0}")]
    Store(String),
    /// Configuration, source parsing, or policy compilation failed.
    #[error("config error: {0}")]
    Config(String),
    /// Detector configuration or rule compilation failed.
    #[error("detector error: {0}")]
    Detector(String),
    /// A receipt serialization or deserialization error occurred.
    #[error("receipt error: {0}")]
    Receipt(String),
    /// Provenance verification (minisign/cosign) failed.
    ///
    /// Fail-closed per spec §18.3: a requested signature verification that
    /// cannot be completed blocks the inspection rather than degrading to
    /// "not verified".
    #[error("provenance verification failed: {0}")]
    Provenance(String),
    /// The pipeline state machine rejected a transition (spec §38.3).
    #[error("pipeline state error: {0}")]
    State(String),
    /// No inspection receipt exists for the artifact; release requires prior analysis.
    #[error("no inspection receipt for {0}; release requires prior inspect() or scan()")]
    NoReceipt(String),
    /// The policy verdict recorded for the artifact blocks release.
    #[error("policy verdict blocks release: {0:?}")]
    PolicyBlocked(Verdict),
    /// The safe-release primitive (ADR-0015) rejected the destination or failed.
    #[error("release failed: {0}")]
    Release(String),
    /// An I/O error occurred.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<arbitraitor_store::StoreError> for EngineError {
    fn from(error: arbitraitor_store::StoreError) -> Self {
        Self::Store(error.to_string())
    }
}

impl From<arbitraitor_fetch::FetchError> for EngineError {
    fn from(error: arbitraitor_fetch::FetchError) -> Self {
        Self::Fetch(error.to_string())
    }
}

impl From<arbitraitor_exec::release::ReleaseError> for EngineError {
    fn from(error: arbitraitor_exec::release::ReleaseError) -> Self {
        Self::Release(error.to_string())
    }
}

impl From<arbitraitor_provenance::ProvenanceError> for EngineError {
    fn from(error: arbitraitor_provenance::ProvenanceError) -> Self {
        Self::Provenance(error.to_string())
    }
}

impl From<arbitraitor_yarax::YaraError> for EngineError {
    fn from(error: arbitraitor_yarax::YaraError) -> Self {
        Self::Detector(error.to_string())
    }
}

impl From<arbitraitor_core::StateError> for EngineError {
    fn from(error: arbitraitor_core::StateError) -> Self {
        Self::State(error.to_string())
    }
}
