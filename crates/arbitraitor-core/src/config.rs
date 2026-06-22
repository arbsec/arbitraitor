//! Layered TOML configuration for Arbitraitor.

use std::path::{Path, PathBuf};

use arbitraitor_policy::PolicyEngine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::secret::{SecretError, SecretResolver};

const DEFAULT_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Errors produced while loading Arbitraitor configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// A configuration file could not be read.
    #[error("failed to read configuration file {path}: {source}")]
    Read {
        /// Path that failed to load.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },

    /// A configuration file contained invalid TOML or an invalid schema.
    #[error("failed to parse configuration file {path}: {source}")]
    Parse {
        /// Path that failed to parse.
        path: PathBuf,
        /// Underlying TOML deserialization error.
        #[source]
        source: toml::de::Error,
    },

    /// A `secret://` reference in the configuration could not be resolved.
    #[error("failed to resolve secret reference: {0}")]
    SecretResolution(#[from] SecretError),

    /// A configured policy file could not be read.
    #[error("failed to read policy file {path}: {source}")]
    PolicyRead {
        /// Policy path that failed to load.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },

    /// Inline policy configuration could not be serialized to policy TOML.
    #[error("failed to serialize inline policy configuration: {source}")]
    PolicySerialize {
        /// Underlying TOML serialization error.
        #[source]
        source: toml::ser::Error,
    },

    /// Policy configuration could not be compiled by the policy engine.
    #[error("failed to compile policy configuration: {source}")]
    PolicyCompile {
        /// Underlying policy error.
        #[source]
        source: arbitraitor_policy::PolicyError,
    },
}

/// Convenient result alias for configuration loading.
pub type ConfigResult<T> = Result<T, ConfigError>;

/// Top-level Arbitraitor configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Retrieval limits and transport behavior.
    pub fetch: FetchConfig,
    /// Content-addressed storage settings.
    pub store: StoreConfig,
    /// Analysis resource limits.
    pub analysis: AnalysisConfig,
    /// Policy loading and enforcement defaults.
    pub policy: PolicyConfig,
    /// Detector selection and detector-specific limits.
    pub detectors: DetectorConfig,
    /// Execution broker defaults.
    pub execution: ExecutionConfig,
    /// Artifact integrity requirements.
    pub integrity: IntegrityConfig,
    /// Metrics collection and structured operation logging settings.
    pub metrics: MetricsConfig,
}

/// Fetcher configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct FetchConfig {
    /// Maximum followed redirects.
    pub max_redirects: u32,
    /// Whole-operation timeout in seconds.
    pub total_timeout_secs: u64,
    /// Maximum bytes accepted from transport.
    pub max_bytes: u64,
}

/// Content store configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct StoreConfig {
    /// Maximum bytes accepted into storage.
    pub max_bytes: u64,
    /// CAS root directory. When unset, callers use `.arbitraitor/cas`.
    pub cas_dir: Option<PathBuf>,
}

/// Artifact analysis configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct AnalysisConfig {
    /// Maximum analysis wall-clock time in seconds.
    pub max_time_secs: u64,
    /// Maximum recursive inspection depth.
    pub max_depth: u32,
    /// Maximum files inspected from archives or trees.
    pub max_files: u64,
}

/// Policy configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct PolicyConfig {
    /// Path to a standalone policy TOML file. If set, takes precedence over inline policy.
    pub policy_file: Option<PathBuf>,
    /// Default action when no rule matches.
    #[serde(default = "default_action")]
    pub default_action: String,
    /// Action when non-interactive and verdict is Prompt.
    #[serde(default = "default_non_interactive_action")]
    pub non_interactive_prompt_action: String,
    /// Inline rules used when [`Self::policy_file`] is unset.
    #[serde(default)]
    pub rules: Vec<InlineRule>,
}

/// Inline policy rule embedded in the main configuration file.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InlineRule {
    /// Human-readable rule identifier used in policy traces and diagnostics.
    pub id: String,
    /// Policy action for this rule: `pass`, `warn`, `prompt`, or `block`.
    pub action: String,
    /// Finding condition that must match for this rule to apply.
    #[serde(default)]
    pub when: RuleCondition,
}

/// Constrained inline rule condition for common finding fields.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct RuleCondition {
    /// Required finding category, when set.
    pub category: Option<String>,
    /// Required finding confidence, when set.
    pub confidence: Option<String>,
    /// Required finding severity, when set.
    pub severity: Option<String>,
}

/// Detector selection and detector resource limits.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "detector config intentionally exposes independent TOML booleans"
)]
pub struct DetectorConfig {
    /// Paths to YARA-X rule pack directories.
    #[serde(default)]
    pub yara_rule_packs: Vec<PathBuf>,
    /// Enable shell analysis detector.
    #[serde(default = "default_true")]
    pub shell_analysis: bool,
    /// Enable PowerShell analysis detector.
    #[serde(default = "default_true")]
    pub powershell_analysis: bool,
    /// Enable archive inspection detector.
    #[serde(default = "default_true")]
    pub archive_inspection: bool,
    /// Enable provenance verification detector.
    #[serde(default = "default_true")]
    pub provenance_verification: bool,
    /// Maximum nested archive depth.
    #[serde(default = "default_depth")]
    pub max_archive_depth: u32,
    /// Maximum total extraction size in bytes.
    #[serde(default = "default_max_size")]
    pub max_extraction_bytes: u64,
}

/// Effective detector settings selected from configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "detector set mirrors independent configured detector toggles"
)]
pub struct DetectorSet {
    /// Whether shell analysis is enabled.
    pub shell_analysis: bool,
    /// Whether PowerShell analysis is enabled.
    pub powershell_analysis: bool,
    /// Whether archive inspection is enabled.
    pub archive_inspection: bool,
    /// Whether provenance verification is enabled.
    pub provenance_verification: bool,
    /// YARA-X rule pack directories to load.
    pub yara_rule_packs: Vec<PathBuf>,
    /// Maximum nested archive depth.
    pub max_archive_depth: u32,
    /// Maximum total extraction size in bytes.
    pub max_extraction_bytes: u64,
}

/// Execution configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct ExecutionConfig {
    /// Whether execution is enabled by default.
    pub enabled: bool,
    /// Default execution timeout in seconds.
    pub timeout_secs: u64,
}

/// Integrity configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct IntegrityConfig {
    /// Require callers to provide an expected artifact digest before retrieval.
    pub require_digest: bool,
    /// Require supported provenance evidence before approval.
    pub require_provenance: bool,
}

/// Metrics and operation logging configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct MetricsConfig {
    /// Whether operation metrics collection and completion logs are enabled.
    pub enabled: bool,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            max_redirects: 10,
            total_timeout_secs: 120,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            cas_dir: None,
        }
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_time_secs: 300,
            max_depth: 8,
            max_files: 10_000,
        }
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            policy_file: None,
            default_action: default_action(),
            non_interactive_prompt_action: default_non_interactive_action(),
            rules: Vec::new(),
        }
    }
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            yara_rule_packs: Vec::new(),
            shell_analysis: true,
            powershell_analysis: true,
            archive_inspection: true,
            provenance_verification: true,
            max_archive_depth: default_depth(),
            max_extraction_bytes: default_max_size(),
        }
    }
}

fn default_action() -> String {
    "prompt".to_owned()
}

fn default_non_interactive_action() -> String {
    "block".to_owned()
}

fn default_true() -> bool {
    true
}

fn default_depth() -> u32 {
    8
}

fn default_max_size() -> u64 {
    DEFAULT_MAX_BYTES
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_secs: 60,
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Config {
    /// Loads default, system, user, and project configuration layers.
    ///
    /// # Errors
    ///
    /// Returns an error when a selected configuration file cannot be read or parsed.
    pub fn load() -> ConfigResult<Self> {
        let system_path = std::env::var_os("ARBITRAITOR_SYSTEM_CONFIG").map(PathBuf::from);
        let home = std::env::var_os("HOME").map(PathBuf::from);
        Self::load_from_layers(system_path.as_deref(), home.as_deref(), Path::new("."))
    }

    /// Loads defaults plus one explicit configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or parsed.
    pub fn load_from_file(path: impl AsRef<Path>) -> ConfigResult<Self> {
        Config::default().merge_file(path.as_ref())
    }

    /// Loads defaults plus optional system, user, and project layers.
    ///
    /// # Errors
    ///
    /// Returns an error when any selected configuration layer cannot be read or parsed.
    pub fn load_from_layers(
        system_config: Option<&Path>,
        home_dir: Option<&Path>,
        project_dir: &Path,
    ) -> ConfigResult<Self> {
        let mut config = Config::default();
        if let Some(path) = system_config {
            config = config.merge_file(path)?;
        } else {
            let path = Path::new("/etc/arbitraitor/config.toml");
            if path.exists() {
                config = config.merge_file(path)?;
            }
        }

        if let Some(home) = home_dir {
            let path = home.join(".config/arbitraitor/config.toml");
            if path.exists() {
                config = config.merge_file(&path)?;
            }
        }

        let project = project_dir.join(".arbitraitor/config.toml");
        if project.exists() {
            config = config.merge_file(&project)?;
        }

        Ok(config)
    }

    fn merge_file(self, path: &Path) -> ConfigResult<Self> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let overlay =
            toml::from_str::<ConfigOverlay>(&contents).map_err(|source| ConfigError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        Ok(self.merge(overlay))
    }

    /// Resolves all `secret://` references in string-valued configuration fields.
    ///
    /// After loading TOML layers, call this to replace secret references with
    /// their resolved values. Fields that do not contain secret references are
    /// left unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::SecretResolution`] if any reference cannot be resolved.
    pub fn resolve_secrets(&mut self, resolver: &SecretResolver) -> ConfigResult<()> {
        resolve_optional_path(&mut self.store.cas_dir, resolver)?;
        resolve_optional_path(&mut self.policy.policy_file, resolver)?;
        resolve_path_vec(&mut self.detectors.yara_rule_packs, resolver)?;
        Ok(())
    }

    /// Builds a [`PolicyEngine`] from the configured policy section.
    ///
    /// When [`PolicyConfig::policy_file`] is set, it takes precedence over any
    /// inline defaults or rules in the main configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error when a configured policy file cannot be read, inline
    /// policy serialization fails, or the policy engine rejects the policy.
    pub fn build_policy_engine(&self) -> ConfigResult<PolicyEngine> {
        let policy_toml = if let Some(path) = self.policy.policy_file.as_ref() {
            std::fs::read_to_string(path).map_err(|source| ConfigError::PolicyRead {
                path: path.clone(),
                source,
            })?
        } else {
            inline_policy_toml(&self.policy)?
        };

        PolicyEngine::load(&policy_toml).map_err(|source| ConfigError::PolicyCompile { source })
    }

    /// Returns the set of detector types to enable based on configuration.
    #[must_use]
    pub fn enabled_detectors(&self) -> DetectorSet {
        DetectorSet {
            shell_analysis: self.detectors.shell_analysis,
            powershell_analysis: self.detectors.powershell_analysis,
            archive_inspection: self.detectors.archive_inspection,
            provenance_verification: self.detectors.provenance_verification,
            yara_rule_packs: self.detectors.yara_rule_packs.clone(),
            max_archive_depth: self.detectors.max_archive_depth,
            max_extraction_bytes: self.detectors.max_extraction_bytes,
        }
    }

    fn merge(self, overlay: ConfigOverlay) -> Self {
        Self {
            fetch: self.fetch.merge(overlay.fetch),
            store: self.store.merge(overlay.store),
            analysis: self.analysis.merge(overlay.analysis),
            policy: self.policy.merge(overlay.policy),
            detectors: self.detectors.merge(overlay.detectors),
            execution: self.execution.merge(overlay.execution),
            integrity: self.integrity.merge(overlay.integrity),
            metrics: self.metrics.merge(overlay.metrics),
        }
    }
}

/// Resolves a `secret://` reference in an optional path field, if present.
fn resolve_optional_path(
    field: &mut Option<PathBuf>,
    resolver: &SecretResolver,
) -> ConfigResult<()> {
    if let Some(path) = field {
        let value = path.to_string_lossy();
        if SecretResolver::is_secret_ref(&value) {
            *field = Some(PathBuf::from(resolver.resolve(&value)?));
        }
    }
    Ok(())
}

fn resolve_path_vec(paths: &mut [PathBuf], resolver: &SecretResolver) -> ConfigResult<()> {
    for path in paths {
        let value = path.to_string_lossy();
        if SecretResolver::is_secret_ref(&value) {
            *path = PathBuf::from(resolver.resolve(&value)?);
        }
    }
    Ok(())
}

fn inline_policy_toml(policy: &PolicyConfig) -> ConfigResult<String> {
    let mut root = toml::value::Table::new();
    root.insert("version".to_owned(), toml::Value::Integer(1));

    let mut defaults = toml::value::Table::new();
    defaults.insert(
        "action".to_owned(),
        toml::Value::String(policy.default_action.clone()),
    );
    defaults.insert(
        "non_interactive_prompt_action".to_owned(),
        toml::Value::String(policy.non_interactive_prompt_action.clone()),
    );
    root.insert("defaults".to_owned(), toml::Value::Table(defaults));

    let rules = policy
        .rules
        .iter()
        .map(inline_rule_to_toml)
        .collect::<Vec<_>>();
    root.insert("rules".to_owned(), toml::Value::Array(rules));

    toml::to_string(&toml::Value::Table(root))
        .map_err(|source| ConfigError::PolicySerialize { source })
}

fn inline_rule_to_toml(rule: &InlineRule) -> toml::Value {
    let mut rule_table = toml::value::Table::new();
    rule_table.insert("id".to_owned(), toml::Value::String(rule.id.clone()));
    rule_table.insert(
        "action".to_owned(),
        toml::Value::String(rule.action.clone()),
    );

    let mut finding = toml::value::Table::new();
    insert_optional_string(&mut finding, "category", rule.when.category.as_ref());
    insert_optional_string(&mut finding, "confidence", rule.when.confidence.as_ref());
    insert_optional_string(&mut finding, "severity", rule.when.severity.as_ref());

    let mut when = toml::value::Table::new();
    when.insert("finding".to_owned(), toml::Value::Table(finding));
    rule_table.insert("when".to_owned(), toml::Value::Table(when));

    toml::Value::Table(rule_table)
}

fn insert_optional_string(table: &mut toml::value::Table, key: &str, value: Option<&String>) {
    if let Some(value) = value {
        table.insert(key.to_owned(), toml::Value::String(value.clone()));
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigOverlay {
    fetch: Option<FetchOverlay>,
    store: Option<StoreOverlay>,
    analysis: Option<AnalysisOverlay>,
    policy: Option<PolicyOverlay>,
    detectors: Option<DetectorOverlay>,
    execution: Option<ExecutionOverlay>,
    integrity: Option<IntegrityOverlay>,
    metrics: Option<MetricsOverlay>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchOverlay {
    max_redirects: Option<u32>,
    total_timeout_secs: Option<u64>,
    max_bytes: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreOverlay {
    max_bytes: Option<u64>,
    cas_dir: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalysisOverlay {
    #[serde(rename = "max_time_secs")]
    time_secs: Option<u64>,
    #[serde(rename = "max_depth")]
    depth: Option<u32>,
    #[serde(rename = "max_files")]
    files: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyOverlay {
    policy_file: Option<PathBuf>,
    default_action: Option<String>,
    non_interactive_prompt_action: Option<String>,
    rules: Option<Vec<InlineRule>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectorOverlay {
    yara_rule_packs: Option<Vec<PathBuf>>,
    shell_analysis: Option<bool>,
    powershell_analysis: Option<bool>,
    archive_inspection: Option<bool>,
    provenance_verification: Option<bool>,
    max_archive_depth: Option<u32>,
    max_extraction_bytes: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionOverlay {
    enabled: Option<bool>,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntegrityOverlay {
    require_digest: Option<bool>,
    require_provenance: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricsOverlay {
    enabled: Option<bool>,
}

impl FetchConfig {
    fn merge(self, overlay: Option<FetchOverlay>) -> Self {
        let Some(overlay) = overlay else {
            return self;
        };
        Self {
            max_redirects: overlay.max_redirects.unwrap_or(self.max_redirects),
            total_timeout_secs: overlay
                .total_timeout_secs
                .unwrap_or(self.total_timeout_secs),
            max_bytes: overlay.max_bytes.unwrap_or(self.max_bytes),
        }
    }
}

impl StoreConfig {
    fn merge(self, overlay: Option<StoreOverlay>) -> Self {
        let Some(overlay) = overlay else {
            return self;
        };
        Self {
            max_bytes: overlay.max_bytes.unwrap_or(self.max_bytes),
            cas_dir: overlay.cas_dir.or(self.cas_dir),
        }
    }
}

impl AnalysisConfig {
    fn merge(self, overlay: Option<AnalysisOverlay>) -> Self {
        let Some(overlay) = overlay else {
            return self;
        };
        Self {
            max_time_secs: overlay.time_secs.unwrap_or(self.max_time_secs),
            max_depth: overlay.depth.unwrap_or(self.max_depth),
            max_files: overlay.files.unwrap_or(self.max_files),
        }
    }
}

impl PolicyConfig {
    fn merge(self, overlay: Option<PolicyOverlay>) -> Self {
        let Some(overlay) = overlay else {
            return self;
        };
        Self {
            policy_file: overlay.policy_file.or(self.policy_file),
            default_action: overlay.default_action.unwrap_or(self.default_action),
            non_interactive_prompt_action: overlay
                .non_interactive_prompt_action
                .unwrap_or(self.non_interactive_prompt_action),
            rules: overlay.rules.unwrap_or(self.rules),
        }
    }
}

impl DetectorConfig {
    fn merge(self, overlay: Option<DetectorOverlay>) -> Self {
        let Some(overlay) = overlay else {
            return self;
        };
        Self {
            yara_rule_packs: overlay.yara_rule_packs.unwrap_or(self.yara_rule_packs),
            shell_analysis: overlay.shell_analysis.unwrap_or(self.shell_analysis),
            powershell_analysis: overlay
                .powershell_analysis
                .unwrap_or(self.powershell_analysis),
            archive_inspection: overlay
                .archive_inspection
                .unwrap_or(self.archive_inspection),
            provenance_verification: overlay
                .provenance_verification
                .unwrap_or(self.provenance_verification),
            max_archive_depth: overlay.max_archive_depth.unwrap_or(self.max_archive_depth),
            max_extraction_bytes: overlay
                .max_extraction_bytes
                .unwrap_or(self.max_extraction_bytes),
        }
    }
}

impl ExecutionConfig {
    fn merge(self, overlay: Option<ExecutionOverlay>) -> Self {
        let Some(overlay) = overlay else {
            return self;
        };
        Self {
            enabled: overlay.enabled.unwrap_or(self.enabled),
            timeout_secs: overlay.timeout_secs.unwrap_or(self.timeout_secs),
        }
    }
}

impl IntegrityConfig {
    fn merge(self, overlay: Option<IntegrityOverlay>) -> Self {
        let Some(overlay) = overlay else {
            return self;
        };
        Self {
            require_digest: overlay.require_digest.unwrap_or(self.require_digest),
            require_provenance: overlay
                .require_provenance
                .unwrap_or(self.require_provenance),
        }
    }
}

impl MetricsConfig {
    fn merge(self, overlay: Option<MetricsOverlay>) -> Self {
        let Some(overlay) = overlay else {
            return self;
        };
        Self {
            enabled: overlay.enabled.unwrap_or(self.enabled),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use arbitraitor_model::finding::{Finding, FindingCategory};
    use arbitraitor_model::ids::Sha256Digest;
    use arbitraitor_model::verdict::{Confidence, Severity, Verdict};
    use arbitraitor_policy::EvalContext;

    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    fn temp_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "arbitraitor-config-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn write_config(path: &Path, contents: &str) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)
    }

    #[test]
    fn default_config_has_expected_values() {
        let config = Config::default();

        assert_eq!(config.fetch.max_redirects, 10);
        assert_eq!(config.fetch.total_timeout_secs, 120);
        assert_eq!(config.fetch.max_bytes, DEFAULT_MAX_BYTES);
        assert_eq!(config.store.max_bytes, DEFAULT_MAX_BYTES);
        assert_eq!(config.store.cas_dir, None);
        assert_eq!(config.analysis.max_time_secs, 300);
        assert_eq!(config.analysis.max_depth, 8);
        assert_eq!(config.analysis.max_files, 10_000);
        assert_eq!(config.policy.default_action, "prompt");
        assert_eq!(config.policy.non_interactive_prompt_action, "block");
        assert!(config.policy.policy_file.is_none());
        assert!(config.policy.rules.is_empty());
        assert!(config.detectors.shell_analysis);
        assert!(config.detectors.powershell_analysis);
        assert!(config.detectors.archive_inspection);
        assert!(config.detectors.provenance_verification);
        assert_eq!(config.detectors.max_archive_depth, 8);
        assert_eq!(config.detectors.max_extraction_bytes, DEFAULT_MAX_BYTES);
        assert!(!config.execution.enabled);
        assert_eq!(config.execution.timeout_secs, 60);
        assert!(!config.integrity.require_digest);
        assert!(!config.integrity.require_provenance);
        assert!(config.metrics.enabled);
    }

    #[test]
    fn loading_toml_file_overrides_defaults() -> TestResult {
        let dir = temp_dir("single")?;
        let path = dir.join("config.toml");
        write_config(
            &path,
            r#"
[fetch]
max_redirects = 3
max_bytes = 4096

[store]
cas_dir = "custom-cas"

[integrity]
require_digest = true

[metrics]
enabled = false
"#,
        )?;

        let config = Config::load_from_file(&path)?;

        assert_eq!(config.fetch.max_redirects, 3);
        assert_eq!(config.fetch.total_timeout_secs, 120);
        assert_eq!(config.fetch.max_bytes, 4096);
        assert_eq!(config.store.cas_dir, Some(PathBuf::from("custom-cas")));
        assert!(config.integrity.require_digest);
        assert!(!config.metrics.enabled);
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn layered_loading_applies_user_then_project_config() -> TestResult {
        let root = temp_dir("layers")?;
        let home = root.join("home");
        let project = root.join("project");

        write_config(
            &home.join(".config/arbitraitor/config.toml"),
            r"
[fetch]
max_redirects = 4
total_timeout_secs = 45

[execution]
timeout_secs = 10
",
        )?;
        write_config(
            &project.join(".arbitraitor/config.toml"),
            r"
[fetch]
max_redirects = 8

[execution]
enabled = true
",
        )?;

        let config = Config::load_from_layers(None, Some(&home), &project)?;

        assert_eq!(config.fetch.max_redirects, 8);
        assert_eq!(config.fetch.total_timeout_secs, 45);
        assert!(config.execution.enabled);
        assert_eq!(config.execution.timeout_secs, 10);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn invalid_toml_returns_error() -> TestResult {
        let dir = temp_dir("invalid")?;
        let path = dir.join("config.toml");
        write_config(&path, "[fetch\nmax_redirects = 2")?;

        let result = Config::load_from_file(&path);

        assert!(matches!(result, Err(ConfigError::Parse { .. })));
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn unknown_fields_are_rejected() -> TestResult {
        let dir = temp_dir("unknown")?;
        let path = dir.join("config.toml");
        write_config(
            &path,
            r"
[fetch]
max_redirekts = 2
",
        )?;

        let result = Config::load_from_file(&path);

        assert!(matches!(result, Err(ConfigError::Parse { .. })));
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn config_resolve_secrets_replaces_all_refs() -> TestResult {
        let root = temp_dir("config_secrets")?;
        fs::write(root.join("cas_path.txt"), "/resolved/cas")?;
        fs::write(root.join("rules_path.txt"), "/resolved/rules")?;

        let mut config = Config::default();
        config.store.cas_dir = Some(PathBuf::from("secret://file/cas_path.txt"));
        config.policy.policy_file = Some(PathBuf::from("not-a-secret-ref"));
        config.detectors.yara_rule_packs = vec![PathBuf::from("secret://file/rules_path.txt")];

        let resolver = SecretResolver::new().with_files(true, Some(root.clone()));
        config.resolve_secrets(&resolver)?;

        assert_eq!(config.store.cas_dir, Some(PathBuf::from("/resolved/cas")));
        assert_eq!(
            config.policy.policy_file,
            Some(PathBuf::from("not-a-secret-ref"))
        );
        assert_eq!(
            config.detectors.yara_rule_packs,
            vec![PathBuf::from("/resolved/rules")]
        );

        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn policy_from_inline_rules() -> TestResult {
        let mut config = Config::default();
        config.policy.default_action = "pass".to_owned();
        config.policy.rules = vec![InlineRule {
            id: "block-confirmed-malware".to_owned(),
            action: "block".to_owned(),
            when: RuleCondition {
                category: Some("malware-signature".to_owned()),
                confidence: Some("confirmed".to_owned()),
                severity: None,
            },
        }];

        let engine = config.build_policy_engine()?;
        let finding = malware_finding();
        let verdict = engine.evaluate(&[finding], &EvalContext::new(true).with_https(true));

        assert_eq!(verdict, Verdict::Block);
        assert_eq!(engine.policy().rules.len(), 1);
        Ok(())
    }

    #[test]
    fn policy_from_file_overrides_inline() -> TestResult {
        let dir = temp_dir("policy_file")?;
        let policy_path = dir.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
version = 1

[defaults]
action = "warn"
non_interactive_prompt_action = "block"
"#,
        )?;
        let mut config = Config::default();
        config.policy.policy_file = Some(policy_path);
        config.policy.default_action = "block".to_owned();

        let engine = config.build_policy_engine()?;
        let verdict = engine.evaluate(&[], &EvalContext::new(true).with_https(true));

        assert_eq!(verdict, Verdict::Warn);
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn default_policy_when_unset() -> TestResult {
        let config = Config::default();

        let engine = config.build_policy_engine()?;

        assert_eq!(engine.policy().version, 1);
        assert!(engine.policy().rules.is_empty());
        Ok(())
    }

    #[test]
    fn detector_defaults_all_enabled() {
        let detectors = Config::default().enabled_detectors();

        assert!(detectors.shell_analysis);
        assert!(detectors.powershell_analysis);
        assert!(detectors.archive_inspection);
        assert!(detectors.provenance_verification);
        assert!(detectors.yara_rule_packs.is_empty());
    }

    #[test]
    fn detector_selective_disable() -> TestResult {
        let dir = temp_dir("detector_disable")?;
        let path = dir.join("config.toml");
        write_config(
            &path,
            r"
[detectors]
shell_analysis = false
",
        )?;

        let detectors = Config::load_from_file(&path)?.enabled_detectors();

        assert!(!detectors.shell_analysis);
        assert!(detectors.powershell_analysis);
        assert!(detectors.archive_inspection);
        assert!(detectors.provenance_verification);
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn detector_limits() -> TestResult {
        let dir = temp_dir("detector_limits")?;
        let path = dir.join("config.toml");
        write_config(
            &path,
            r#"
[detectors]
max_archive_depth = 3
max_extraction_bytes = 1048576
yara_rule_packs = ["rules/core", "rules/local"]
"#,
        )?;

        let detectors = Config::load_from_file(&path)?.enabled_detectors();

        assert_eq!(detectors.max_archive_depth, 3);
        assert_eq!(detectors.max_extraction_bytes, 1_048_576);
        assert_eq!(
            detectors.yara_rule_packs,
            vec![PathBuf::from("rules/core"), PathBuf::from("rules/local")]
        );
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn full_config_round_trips() -> TestResult {
        let mut config = Config::default();
        config.policy.default_action = "warn".to_owned();
        config.policy.non_interactive_prompt_action = "block".to_owned();
        config.policy.rules = vec![InlineRule {
            id: "warn-high-confidence".to_owned(),
            action: "warn".to_owned(),
            when: RuleCondition {
                category: Some("network-behavior".to_owned()),
                confidence: Some("high".to_owned()),
                severity: Some("medium".to_owned()),
            },
        }];
        config.detectors.yara_rule_packs = vec![PathBuf::from("rules")];
        config.detectors.shell_analysis = false;
        config.detectors.max_archive_depth = 4;
        config.detectors.max_extraction_bytes = 2_048;

        let encoded = toml::to_string(&config)?;
        let decoded: Config = toml::from_str(&encoded)?;

        assert_eq!(decoded, config);
        Ok(())
    }

    fn malware_finding() -> Finding {
        Finding {
            id: "malware.test".to_owned(),
            detector: "test".to_owned(),
            category: FindingCategory::MalwareSignature,
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            title: "Test malware".to_owned(),
            description: "Synthetic test finding".to_owned(),
            evidence: Vec::new(),
            artifact_sha256: Sha256Digest::new([0x42; 32]),
            location: None,
            remediation: None,
            references: Vec::new(),
            tags: Vec::new(),
        }
    }
}
