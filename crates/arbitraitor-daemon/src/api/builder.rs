//! Fluent construction for the in-process Arbitraitor API.

use arbitraitor_analysis::AnalysisCoordinator;
use arbitraitor_fetch::HttpFetcher;
use arbitraitor_policy::PolicyEngine;
use arbitraitor_store::ContentStore;

use super::{ApiError, ArbitraitorApi, Config, DEFAULT_POLICY_TOML};

/// Entry point for constructing an in-process Arbitraitor API.
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
/// TOML stored in [`Config`].
#[derive(Clone, Debug, Default)]
#[must_use]
pub struct ArbitraitorBuilder {
    config: Config,
    policy: Option<PolicyEngine>,
}

impl ArbitraitorBuilder {
    /// Replaces the complete API configuration.
    pub fn config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    /// Uses an already compiled policy instead of `Config::policy_toml`.
    pub fn policy(mut self, policy: PolicyEngine) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Constructs the configured [`ArbitraitorApi`].
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Store`] if the content store cannot be opened,
    /// [`ApiError::Config`] if the configured policy TOML is invalid and no
    /// compiled policy was supplied, or [`ApiError::Io`] if the receipts
    /// directory cannot be created.
    pub fn build(self) -> Result<ArbitraitorApi, ApiError> {
        let Config {
            store_path,
            receipts_path,
            fetch_policy,
            policy_toml,
        } = self.config;
        let store = ContentStore::open(&store_path)?;
        let policy = if let Some(policy) = self.policy {
            policy
        } else {
            let policy_toml = if policy_toml.trim().is_empty() {
                DEFAULT_POLICY_TOML
            } else {
                &policy_toml
            };
            PolicyEngine::load(policy_toml).map_err(|error| ApiError::Config(error.to_string()))?
        };
        std::fs::create_dir_all(&receipts_path)?;
        Ok(ArbitraitorApi {
            store,
            fetcher: HttpFetcher::new(),
            policy,
            coordinator: AnalysisCoordinator::new(),
            fetch_policy,
            receipts_dir: receipts_path,
        })
    }
}
