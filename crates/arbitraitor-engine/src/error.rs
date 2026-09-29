//! Typed error surface for the pipeline engine.

use arbitraitor_fetch::FetchError;
use arbitraitor_model::verdict::Verdict;
use thiserror::Error;

/// Transport failure classes that map directly to real `curl` exit codes.
///
/// The mapping is the subset of `curl(1)`'s exit-code table that the fetch
/// layer can actually distinguish. Everything else (protocol errors,
/// malformed responses, truncated bodies) stays a generic transport failure
/// and maps to the tool's generic transport exit code at the caller.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum FetchFailureKind {
    /// HTTP 4xx/5xx status aborted the transfer (curl exit 22, with `-f`).
    #[error("HTTP error status {status}")]
    HttpErrorStatus {
        /// HTTP status code returned by the server.
        status: u16,
    },
    /// Host could not be resolved (curl exit 6).
    #[error("could not resolve host")]
    DnsResolution,
    /// Connection was refused (curl exit 7).
    #[error("connection refused")]
    ConnectionRefused,
    /// Transfer timed out (curl exit 28).
    #[error("operation timed out")]
    Timeout,
    /// TLS certificate validation failed (curl exit 60).
    #[error("TLS certificate validation failed")]
    TlsCertificate,
}

impl FetchFailureKind {
    /// Returns the `curl(1)` exit code for this failure class.
    #[must_use]
    pub const fn curl_exit_code(&self) -> i32 {
        match self {
            Self::HttpErrorStatus { .. } => 22,
            Self::DnsResolution => 6,
            Self::ConnectionRefused => 7,
            Self::Timeout => 28,
            Self::TlsCertificate => 60,
        }
    }

    /// Classifies a [`FetchError`] when it has a direct `curl` exit-code
    /// equivalent. Returns `None` for failures outside the mappable subset
    /// (redirect policy, SSRF, size limits, digest mismatch, generic
    /// transport errors); callers map those to the tool's fallback exit
    /// code instead of guessing a specific one.
    #[must_use]
    pub fn classify(error: &FetchError) -> Option<Self> {
        match error {
            FetchError::HttpStatus { status } => Some(Self::HttpErrorStatus { status: *status }),
            FetchError::Io {
                stage: "resolve", ..
            } => Some(Self::DnsResolution),
            FetchError::ConnectionRefused => Some(Self::ConnectionRefused),
            FetchError::Timeout { .. } => Some(Self::Timeout),
            FetchError::TlsFailure => Some(Self::TlsCertificate),
            _ => None,
        }
    }
}

/// A fetch failure carrying its classified [`FetchFailureKind`].
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{kind}: {message}")]
pub struct FetchTransportError {
    /// Classified failure kind.
    pub kind: FetchFailureKind,
    /// Safe diagnostic message from the underlying [`FetchError`].
    pub message: String,
}

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
    /// A classified transport failure with a machine-readable kind.
    ///
    /// Produced when a fetch aborts with a [`FetchError`] that maps to a
    /// real `curl`/`wget` exit-code class (HTTP error status under `-f`,
    /// DNS failure, connection refused, timeout, TLS failure). Callers that
    /// emulate tool exit-code semantics match on [`FetchTransportError`]
    /// instead of parsing diagnostic strings.
    #[error("fetch transport failure: {}", _0.kind)]
    FetchTransport(#[from] FetchTransportError),
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::{EngineError, FetchFailureKind, FetchTransportError};
    use arbitraitor_fetch::FetchError;

    #[test]
    fn classifies_curl_mappable_transport_failures() {
        assert_eq!(
            FetchFailureKind::classify(&FetchError::HttpStatus { status: 404 }),
            Some(FetchFailureKind::HttpErrorStatus { status: 404 })
        );
        assert_eq!(
            FetchFailureKind::classify(&FetchError::ConnectionRefused),
            Some(FetchFailureKind::ConnectionRefused)
        );
        assert_eq!(
            FetchFailureKind::classify(&FetchError::Timeout { stage: "request" }),
            Some(FetchFailureKind::Timeout)
        );
        assert_eq!(
            FetchFailureKind::classify(&FetchError::TlsFailure),
            Some(FetchFailureKind::TlsCertificate)
        );
        assert!(matches!(
            FetchFailureKind::classify(&FetchError::Io {
                stage: "resolve",
                source: std::io::Error::other("dns down"),
            }),
            Some(FetchFailureKind::DnsResolution)
        ));
    }

    #[test]
    fn non_mappable_failures_classify_to_none() {
        assert_eq!(
            FetchFailureKind::classify(&FetchError::RedirectLoop),
            None,
            "redirect policy violations have no curl exit-code equivalent"
        );
        assert_eq!(
            FetchFailureKind::classify(&FetchError::ProhibitedAddress {
                address: "10.0.0.1".parse().unwrap()
            }),
            None,
            "SSRF violations have no curl exit-code equivalent"
        );
    }

    #[test]
    fn curl_exit_codes_match_real_curl_table() {
        // curl(1): 22 HTTP error with -f, 6 DNS, 7 refused, 28 timeout,
        // 60 TLS certificate failure.
        assert_eq!(
            FetchFailureKind::HttpErrorStatus { status: 500 }.curl_exit_code(),
            22
        );
        assert_eq!(FetchFailureKind::DnsResolution.curl_exit_code(), 6);
        assert_eq!(FetchFailureKind::ConnectionRefused.curl_exit_code(), 7);
        assert_eq!(FetchFailureKind::Timeout.curl_exit_code(), 28);
        assert_eq!(FetchFailureKind::TlsCertificate.curl_exit_code(), 60);
    }

    #[test]
    fn engine_error_preserves_transport_kind_in_display() {
        let error = EngineError::FetchTransport(FetchTransportError {
            kind: FetchFailureKind::HttpErrorStatus { status: 404 },
            message: "HTTP error status 404".to_owned(),
        });
        assert!(
            error.to_string().contains("HTTP error status 404"),
            "diagnostic must stay visible: {error}"
        );
    }
}
