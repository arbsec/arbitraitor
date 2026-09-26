//! Programmatic API for Arbitraitor operations.
//!
//! The pipeline engine moved to the `arbitraitor-engine` crate (ADR-0038);
//! this module re-exports its public surface so existing
//! `arbitraitor_daemon::api` consumers keep compiling. New consumers should
//! depend on `arbitraitor-engine` directly.
//!
//! The in-process API is the equivalent of the daemon's socket protocol.
//! Consumers using Arbitraitor as a Rust dependency start with
//! [`Arbitraitor::builder`] or call [`ArbitraitorApi::new`] directly instead
//! of connecting to a Unix socket. All pipeline stages (fetcher, store,
//! analysis coordinator, provenance verification, policy engine, receipt
//! builder) are composed inside the engine; no daemon process is required.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use arbitraitor_engine::Config;
pub use arbitraitor_engine::EngineError as ApiError;
pub use arbitraitor_engine::{
    Arbitraitor, ArbitraitorApi, ArbitraitorBuilder, ArtifactSummary, FetchResult,
    InspectionResult, InspectionResultReceipt, ReceiptFilter, ReceiptSummary, ReleaseResult,
};
