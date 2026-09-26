//! Pipeline engine for Arbitraitor (ADR-0038).
//!
//! This crate is the single consolidated composition of the
//! fetch → store → analyze → provenance → receipt → verdict → release pipeline.
//! Every integration surface — CLI, MCP gateway, Unix-socket daemon, and
//! third-party embedders — routes through [`ArbitraitorApi`]. Independent
//! re-composition of pipeline stages in a consumer is a silent coverage hole
//! and is forbidden by the single-pipeline principle (spec §40.0).
//!
//! # Stability contract (ADR-0038 decision 5)
//!
//! Before `1.0` the crate publishes under `SemVer 0.x`. The public surface is
//! deliberately narrow: [`Arbitraitor`], [`ArbitraitorBuilder`],
//! [`ArbitraitorApi`], [`Config`], [`InspectionResult`],
//! [`InspectionResultReceipt`], and the [`EngineError`] type. Consumers must
//! not depend on the internal adapter crates (`arbitraitor-fetch`,
//! `arbitraitor-store`, `arbitraitor-analysis`, `arbitraitor-receipt`,
//! `arbitraitor-provenance`, `arbitraitor-exec`) — the engine wraps them.
//! Wrapping of the remaining leaked types (`FetchPolicy`, `ReleaseMethod`,
//! `PolicyEngine`) is sequenced as stage 6 of the ADR-0038 rollout, before
//! the crate publishes to crates.io.
//!
//! # Verdict derivation
//!
//! When [`Config::policy_toml`] is empty (or no compiled policy is supplied
//! through [`ArbitraitorBuilder::policy`]), the engine applies its built-in
//! verdict derivation over the analysis findings: any detector failure
//! produces [`Verdict::Incomplete`] (fail-closed, spec §18.3), a critical
//! finding blocks, a high finding prompts, no findings pass, and anything
//! else warns. Non-interactive surfaces that need a stricter default pass
//! [`FAIL_CLOSED_POLICY_TOML`] instead.
//!
//! # State machine
//!
//! The engine drives the `arbitraitor-core` value-type state machine
//! ([`arbitraitor_core::PipelineOperation`]) through every inspection and
//! release: retrieval → storage → identification → analysis → expansion →
//! evaluation, with the verdict recorded before approval, and
//! approval → release → completion enforced on the release path. Consumers
//! never transition the state machine themselves.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod api;
mod error;
mod pipeline;
mod signatures;

pub use api::{
    Arbitraitor, ArbitraitorApi, ArbitraitorBuilder, ArtifactSummary, Config,
    DEFAULT_SCAN_MAX_BYTES, DetectorStatusSummary, DetectorSummary, FAIL_CLOSED_POLICY_TOML,
    FetchResult, InspectionResult, InspectionResultReceipt, ReceiptFilter, ReceiptSummary,
    ReleaseResult, SignatureVerificationSummary,
};
pub use error::EngineError;
pub use pipeline::{default_cas_dir, default_receipts_dir, parse_fetch_source, receipt_timestamp};
pub use signatures::{CosignBundleInput, MinisignSignatureInput, SignatureInputs};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "tests.rs"]
mod tests;
