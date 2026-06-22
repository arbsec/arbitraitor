//! Health checks and status reporting for Arbitraitor components.
//!
//! The [`HealthChecker`] runs bounded, side-effect-free probes against the
//! content-addressed store, configured detectors, and build identity, then
//! aggregates the results into a [`HealthReport`] that callers can serialize
//! to JSON or render as text. Health checks never authorize release, modify
//! store contents durably, or perform network I/O — they are strictly
//! observability diagnostics layered on top of the existing security boundary.

mod store_probe;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use store_probe::{count_objects, format_bytes, measure_store_bytes, probe_writable};

/// Aggregated health report for all Arbitraitor components.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthReport {
    /// Arbitraitor build version (`CARGO_PKG_VERSION`).
    pub version: String,
    /// Unix epoch seconds at which the report was produced.
    pub timestamp: u64,
    /// Worst-case status across all component checks.
    pub overall: HealthStatus,
    /// Per-component health keyed by stable component name.
    pub checks: HashMap<String, ComponentHealth>,
}

/// Coarse-grained component health used for dashboards and routing decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// The component is operating within its expected envelope.
    Healthy,
    /// The component is usable but degraded; operators should investigate.
    Degraded,
    /// The component cannot fulfil its security contract.
    Unhealthy,
}

impl HealthStatus {
    /// Returns the worst of two statuses (`Healthy < Degraded < Unhealthy`).
    #[must_use]
    pub const fn worst(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unhealthy, _) | (_, Self::Unhealthy) => Self::Unhealthy,
            (Self::Degraded, _) | (_, Self::Degraded) => Self::Degraded,
            (Self::Healthy, Self::Healthy) => Self::Healthy,
        }
    }
}

/// Health result for one named component.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentHealth {
    /// Component health status.
    pub status: HealthStatus,
    /// Safe, bounded human-readable diagnostic message.
    pub message: String,
    /// Optional structured detail payload (counts, versions, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ComponentHealth {
    /// Creates a component health entry with the given status and message.
    #[must_use]
    pub fn new(status: HealthStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            details: None,
        }
    }

    /// Attaches a structured detail payload.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Builder that probes Arbitraitor components and aggregates a [`HealthReport`].
#[derive(Debug, Clone, Default)]
pub struct HealthChecker {
    store_path: Option<PathBuf>,
    rule_pack_version: Option<String>,
    detector_versions: Vec<String>,
}

impl HealthChecker {
    /// Creates a checker with no configured components.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configures the content-addressed store root to probe.
    #[must_use]
    pub fn with_store(mut self, path: PathBuf) -> Self {
        self.store_path = Some(path);
        self
    }

    /// Configures the YARA-X rule pack version to report.
    #[must_use]
    pub fn with_rule_pack(mut self, version: String) -> Self {
        self.rule_pack_version = Some(version);
        self
    }

    /// Configures the detector version strings reported by the analysis layer.
    #[must_use]
    pub fn with_detector_versions(mut self, versions: Vec<String>) -> Self {
        self.detector_versions = versions;
        self
    }

    /// Runs all configured checks and aggregates the results.
    #[must_use]
    pub fn check(&self) -> HealthReport {
        let store = self.check_store();
        let detectors = self.check_detectors();
        let version = self.check_version();
        let overall = store.status.worst(detectors.status).worst(version.status);
        let mut checks = HashMap::with_capacity(3);
        checks.insert("store".to_owned(), store);
        checks.insert("detectors".to_owned(), detectors);
        checks.insert("version".to_owned(), version);
        HealthReport {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            timestamp: store_probe::epoch_seconds(),
            overall,
            checks,
        }
    }

    /// Probes the CAS root directory for existence, writability, and object count.
    fn check_store(&self) -> ComponentHealth {
        let Some(path) = &self.store_path else {
            return ComponentHealth::new(
                HealthStatus::Degraded,
                "no content-addressed store configured",
            );
        };

        let meta = match fs::metadata(path) {
            Ok(meta) => meta,
            Err(error) => {
                return ComponentHealth::new(
                    HealthStatus::Unhealthy,
                    format!("store root {} is missing: {error}", path.display()),
                );
            }
        };
        if !meta.is_dir() {
            return ComponentHealth::new(
                HealthStatus::Unhealthy,
                format!("store root {} is not a directory", path.display()),
            );
        }
        if let Err(error) = probe_writable(path) {
            return ComponentHealth::new(
                HealthStatus::Unhealthy,
                format!("store root {} is not writable: {error}", path.display()),
            );
        }

        let object_count = count_objects(path);
        let total_bytes = measure_store_bytes(path);
        if object_count == 0 {
            return ComponentHealth::new(
                HealthStatus::Degraded,
                "store root is healthy but contains zero objects".to_owned(),
            )
            .with_details(serde_json::json!({
                "object_count": 0u64,
                "total_bytes": total_bytes,
            }));
        }

        ComponentHealth::new(
            HealthStatus::Healthy,
            format!("{object_count} objects, {}", format_bytes(total_bytes)),
        )
        .with_details(serde_json::json!({
            "object_count": object_count,
            "total_bytes": total_bytes,
        }))
    }

    /// Reports whether any detector (rule pack) is configured.
    fn check_detectors(&self) -> ComponentHealth {
        if self.rule_pack_version.is_some() || !self.detector_versions.is_empty() {
            let versions = self
                .detector_versions
                .iter()
                .cloned()
                .chain(self.rule_pack_version.iter().cloned())
                .collect::<Vec<_>>()
                .join(", ");
            return ComponentHealth::new(
                HealthStatus::Healthy,
                format!("detectors configured: {versions}"),
            );
        }
        ComponentHealth::new(
            HealthStatus::Degraded,
            "no detectors configured; analysis coverage is unavailable",
        )
    }

    /// Reports build and rule-pack version information (always healthy).
    fn check_version(&self) -> ComponentHealth {
        let arbitraitor_version = env!("CARGO_PKG_VERSION");
        let rule_pack = self
            .rule_pack_version
            .clone()
            .unwrap_or_else(|| "unknown".to_owned());
        ComponentHealth::new(
            HealthStatus::Healthy,
            format!("arbitraitor v{arbitraitor_version}, rules {rule_pack}"),
        )
    }
}
