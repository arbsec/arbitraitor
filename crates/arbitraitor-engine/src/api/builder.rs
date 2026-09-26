//! Fluent construction for the pipeline engine.

use std::path::PathBuf;

use arbitraitor_fetch::HttpFetcher;
use arbitraitor_policy::PolicyEngine;
use arbitraitor_store::ContentStore;

use super::ArbitraitorApi;
use crate::pipeline::analysis_coordinator;
use crate::signatures::SignatureInputs;
use crate::{Config, EngineError};

/// Entry point for constructing a pipeline engine API.
#[derive(Clone, Copy, Debug, Default)]
pub struct Arbitraitor;

impl Arbitraitor {
    /// Starts a fluent API builder with safe default configuration.
    pub fn builder() -> ArbitraitorBuilder {
        ArbitraitorBuilder::default()
    }
}

/// Fluent construction options for [`ArbitraitorApi`].
///
/// An explicitly supplied [`PolicyEngine`] takes precedence over the policy
/// TOML stored in [`Config`]. Signature inputs and YARA rule directories
/// configure the provenance and detector stages of the pipeline.
#[derive(Clone, Debug, Default)]
#[must_use]
pub struct ArbitraitorBuilder {
    config: Config,
    policy: Option<PolicyEngine>,
    signatures: SignatureInputs,
    yara_rules: Option<PathBuf>,
}

impl ArbitraitorBuilder {
    /// Replaces the complete engine configuration.
    pub fn config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    /// Uses an already compiled policy instead of `Config::policy_toml`.
    ///
    /// Wrapping this input in an engine-owned type is sequenced as stage 6
    /// of the ADR-0038 rollout, before the crate publishes to crates.io.
    pub fn policy(mut self, policy: PolicyEngine) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Sets the provenance verification inputs (minisign signatures and
    /// Sigstore/cosign bundles) verified on every inspection.
    pub fn signatures(mut self, signatures: SignatureInputs) -> Self {
        self.signatures = signatures;
        self
    }

    /// Loads YARA rule packs from a directory, preserving the built-in
    /// detectors alongside the compiled rules.
    pub fn yara_rules(mut self, rules_dir: impl Into<PathBuf>) -> Self {
        self.yara_rules = Some(rules_dir.into());
        self
    }

    /// Constructs the configured [`ArbitraitorApi`].
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Store`] if the content store cannot be opened,
    /// [`EngineError::Config`] if the configured policy TOML is invalid and
    /// no compiled policy was supplied, or [`EngineError::Io`] if the
    /// receipts directory cannot be created.
    pub fn build(self) -> Result<ArbitraitorApi, EngineError> {
        let Config {
            store_path,
            receipts_path,
            fetch_policy,
            store_max_bytes,
            policy_toml,
            emit_partial_receipt_on_cancel,
        } = self.config;
        let store = ContentStore::open(&store_path)?;
        let policy = if let Some(policy) = self.policy {
            Some(policy)
        } else if policy_toml.trim().is_empty() {
            // Empty policy TOML selects the built-in verdict derivation.
            None
        } else {
            Some(
                PolicyEngine::load(&policy_toml)
                    .map_err(|error| EngineError::Config(error.to_string()))?,
            )
        };
        let (coordinator, rule_pack_versions) = analysis_coordinator(self.yara_rules.as_deref())?;
        std::fs::create_dir_all(&receipts_path)?;
        Ok(ArbitraitorApi {
            store,
            fetcher: HttpFetcher::new(),
            policy,
            coordinator: std::sync::Arc::new(coordinator),
            rule_pack_versions,
            fetch_policy,
            receipts_dir: receipts_path,
            emit_partial_receipt_on_cancel,
            signatures: self.signatures,
            store_max_bytes,
        })
    }
}
