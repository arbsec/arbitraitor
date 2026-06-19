//! Layered TOML configuration for Arbitraitor.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    /// Optional default policy file path.
    pub path: Option<PathBuf>,
    /// Fail closed when policy or required evidence is unavailable.
    pub fail_closed: bool,
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
            path: None,
            fail_closed: true,
        }
    }
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

    fn merge(self, overlay: ConfigOverlay) -> Self {
        Self {
            fetch: self.fetch.merge(overlay.fetch),
            store: self.store.merge(overlay.store),
            analysis: self.analysis.merge(overlay.analysis),
            policy: self.policy.merge(overlay.policy),
            execution: self.execution.merge(overlay.execution),
            integrity: self.integrity.merge(overlay.integrity),
            metrics: self.metrics.merge(overlay.metrics),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigOverlay {
    fetch: Option<FetchOverlay>,
    store: Option<StoreOverlay>,
    analysis: Option<AnalysisOverlay>,
    policy: Option<PolicyOverlay>,
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
    path: Option<PathBuf>,
    fail_closed: Option<bool>,
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
            path: overlay.path.or(self.path),
            fail_closed: overlay.fail_closed.unwrap_or(self.fail_closed),
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
        assert!(config.policy.fail_closed);
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
            r#"
[fetch]
max_redirects = 4
total_timeout_secs = 45

[execution]
timeout_secs = 10
"#,
        )?;
        write_config(
            &project.join(".arbitraitor/config.toml"),
            r#"
[fetch]
max_redirects = 8

[execution]
enabled = true
"#,
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
            r#"
[fetch]
max_redirekts = 2
"#,
        )?;

        let result = Config::load_from_file(&path);

        assert!(matches!(result, Err(ConfigError::Parse { .. })));
        fs::remove_dir_all(dir)?;
        Ok(())
    }
}
