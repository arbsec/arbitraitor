//! Health checks and status reporting for Arbitraitor components.
//!
//! The [`HealthChecker`] runs bounded, side-effect-free probes against local
//! configuration, stores, detector assets, wrapper state, and signing material.
//! Health checks never authorize release, modify store contents durably, or
//! perform network I/O — they are strictly observability diagnostics layered on
//! top of the existing security boundary.

mod store_probe;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arbitraitor_policy::PolicyEngine;
use serde::{Deserialize, Serialize};

use store_probe::{count_objects, format_bytes, measure_store_bytes, probe_writable};

const FRESHNESS_WINDOW: Duration = Duration::from_hours(168);
const MIN_CLOCK_EPOCH: u64 = 1_704_067_200;

/// Minimum cosign version that addresses CVE-2026-22703 and CVE-2026-24122
/// (issue #457). CVE-2026-22703 was patched in v2.6.2 and v3.0.4;
/// CVE-2026-24122 was patched in v3.0.5. v3.0.5 is the floor that addresses
/// both CVEs.
const MIN_COSIGN_VERSION: (u32, u32, u32) = (3, 0, 5);

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

/// Doctor health status serialized in spec §28.8 form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Check passed.
    Pass,
    /// Check failed and security posture is not acceptable.
    Fail,
    /// Check is usable but degraded; operators should investigate.
    Warn,
    /// Check is not configured or does not apply on this platform.
    Skipped,
}

impl HealthStatus {
    /// Returns the worst of two statuses (`Pass < Skipped < Warn < Fail`).
    #[must_use]
    pub const fn worst(self, other: Self) -> Self {
        match (self, other) {
            (Self::Fail, _) | (_, Self::Fail) => Self::Fail,
            (Self::Warn, _) | (_, Self::Warn) => Self::Warn,
            (Self::Skipped, _) | (_, Self::Skipped) => Self::Skipped,
            (Self::Pass, Self::Pass) => Self::Pass,
        }
    }

    /// Returns whether the check represents a passing condition.
    #[must_use]
    pub const fn is_pass(self) -> bool {
        matches!(self, Self::Pass)
    }
}

/// Health result returned by one focused doctor probe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckResult {
    /// Stable check name used in JSON reports.
    pub name: String,
    /// Check status.
    pub status: HealthStatus,
    /// Safe, bounded human-readable diagnostic message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Optional structured detail payload (counts, versions, paths, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl HealthCheckResult {
    /// Creates a named health-check result.
    #[must_use]
    pub fn new(name: impl Into<String>, status: HealthStatus, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status,
            message: Some(message.into()),
            details: None,
        }
    }

    /// Creates a skipped health-check result.
    #[must_use]
    pub fn skipped(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(name, HealthStatus::Skipped, message)
    }

    /// Attaches a structured detail payload.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    fn into_component(self) -> ComponentHealth {
        ComponentHealth {
            status: self.status,
            message: self.message.unwrap_or_default(),
            details: self.details,
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

/// Result of pre-parsing a YARA-X rule directory in the CLI layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraRulesProbe {
    /// Rule directory path.
    pub path: PathBuf,
    /// Parsed rule-pack versions discovered in the directory.
    pub versions: Vec<String>,
    /// Safe parse error if parsing failed.
    pub parse_error: Option<String>,
}

impl YaraRulesProbe {
    /// Creates a successful YARA-X rule-directory probe.
    #[must_use]
    pub fn parsed(path: PathBuf, versions: Vec<String>) -> Self {
        Self {
            path,
            versions,
            parse_error: None,
        }
    }

    /// Creates a failed YARA-X rule-directory probe.
    #[must_use]
    pub fn failed(path: PathBuf, error: impl Into<String>) -> Self {
        Self {
            path,
            versions: Vec::new(),
            parse_error: Some(error.into()),
        }
    }
}

/// Builder that probes Arbitraitor components and aggregates a [`HealthReport`].
#[derive(Debug, Clone, Default)]
pub struct HealthChecker {
    store_path: Option<PathBuf>,
    rule_pack_version: Option<String>,
    detector_versions: Vec<String>,
    policy_path: Option<PathBuf>,
    yara_rules: Vec<YaraRulesProbe>,
    scanner_signature_paths: Vec<PathBuf>,
    feed_signature_paths: Vec<PathBuf>,
    update_trust_root: Option<PathBuf>,
    plugin_dirs: Vec<PathBuf>,
    receipt_signing_key: Option<PathBuf>,
    shim_dir: Option<PathBuf>,
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

    /// Configures a standalone policy file to validate.
    #[must_use]
    pub fn with_policy_file(mut self, path: PathBuf) -> Self {
        self.policy_path = Some(path);
        self
    }

    /// Configures a pre-parsed YARA-X rule-directory probe.
    #[must_use]
    pub fn with_yara_rules(mut self, probe: YaraRulesProbe) -> Self {
        self.yara_rules.push(probe);
        self
    }

    /// Configures scanner signature/database paths for freshness checks.
    #[must_use]
    pub fn with_scanner_signature_path(mut self, path: PathBuf) -> Self {
        self.scanner_signature_paths.push(path);
        self
    }

    /// Configures intel feed signature paths to verify for presence/readability.
    #[must_use]
    pub fn with_feed_signature_path(mut self, path: PathBuf) -> Self {
        self.feed_signature_paths.push(path);
        self
    }

    /// Configures the pinned update trust-root key path.
    #[must_use]
    pub fn with_update_trust_root(mut self, path: PathBuf) -> Self {
        self.update_trust_root = Some(path);
        self
    }

    /// Configures a plugin directory to inspect for manifests and protocol metadata.
    #[must_use]
    pub fn with_plugin_dir(mut self, path: PathBuf) -> Self {
        self.plugin_dirs.push(path);
        self
    }

    /// Configures the receipt signing key path.
    #[must_use]
    pub fn with_receipt_signing_key(mut self, path: PathBuf) -> Self {
        self.receipt_signing_key = Some(path);
        self
    }

    /// Configures the wrapper shim directory for PATH-order checks.
    #[must_use]
    pub fn with_shim_dir(mut self, path: PathBuf) -> Self {
        self.shim_dir = Some(path);
        self
    }

    /// Runs all configured checks and aggregates the results.
    #[must_use]
    pub fn check(&self) -> HealthReport {
        let results = [
            self.check_store(),
            self.check_detectors(),
            self.check_version(),
            self.check_policy_validity(),
            self.check_yara_rules(),
            self.check_av_adapters(),
            self.check_scanner_freshness(),
            self.check_feed_signatures(),
            self.check_update_trust_root(),
            self.check_sandbox_adapters(),
            self.check_plugin_manifests(),
            self.check_plugin_protocol(),
            self.check_wrapper_coverage(),
            self.check_shim_path_order(),
            self.check_clock_skew(),
            self.check_proxy_settings(),
            self.check_receipt_signing_key(),
            self.check_sigstore_version(),
        ];
        let overall = results.iter().fold(HealthStatus::Pass, |status, result| {
            status.worst(result.status)
        });
        let mut checks = HashMap::with_capacity(results.len());
        for result in results {
            let name = result.name.clone();
            checks.insert(name, result.into_component());
        }
        HealthReport {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            timestamp: store_probe::epoch_seconds(),
            overall,
            checks,
        }
    }

    /// Probes the CAS root directory for existence, writability, and object count.
    #[must_use]
    pub fn check_store(&self) -> HealthCheckResult {
        let Some(path) = &self.store_path else {
            return HealthCheckResult::new(
                "store",
                HealthStatus::Warn,
                "no content-addressed store configured",
            );
        };

        let meta = match fs::metadata(path) {
            Ok(meta) => meta,
            Err(error) => {
                return HealthCheckResult::new(
                    "store",
                    HealthStatus::Fail,
                    format!("store root {} is missing: {error}", path.display()),
                );
            }
        };
        if !meta.is_dir() {
            return HealthCheckResult::new(
                "store",
                HealthStatus::Fail,
                format!("store root {} is not a directory", path.display()),
            );
        }
        if let Err(error) = probe_writable(path) {
            return HealthCheckResult::new(
                "store",
                HealthStatus::Fail,
                format!("store root {} is not writable: {error}", path.display()),
            );
        }

        let object_count = count_objects(path);
        let total_bytes = measure_store_bytes(path);
        if object_count == 0 {
            return HealthCheckResult::new(
                "store",
                HealthStatus::Warn,
                "store root is healthy but contains zero objects".to_owned(),
            )
            .with_details(serde_json::json!({
                "object_count": 0u64,
                "total_bytes": total_bytes,
            }));
        }

        HealthCheckResult::new(
            "store",
            HealthStatus::Pass,
            format!("{object_count} objects, {}", format_bytes(total_bytes)),
        )
        .with_details(serde_json::json!({
            "object_count": object_count,
            "total_bytes": total_bytes,
        }))
    }

    /// Reports whether any detector (rule pack) is configured.
    #[must_use]
    pub fn check_detectors(&self) -> HealthCheckResult {
        if self.rule_pack_version.is_some() || !self.detector_versions.is_empty() {
            let versions = self
                .detector_versions
                .iter()
                .cloned()
                .chain(self.rule_pack_version.iter().cloned())
                .collect::<Vec<_>>()
                .join(", ");
            return HealthCheckResult::new(
                "detectors",
                HealthStatus::Pass,
                format!("detectors configured: {versions}"),
            );
        }
        HealthCheckResult::new(
            "detectors",
            HealthStatus::Warn,
            "no detectors configured; analysis coverage is unavailable",
        )
    }

    /// Reports build and rule-pack version information.
    #[must_use]
    pub fn check_version(&self) -> HealthCheckResult {
        let arbitraitor_version = env!("CARGO_PKG_VERSION");
        let rule_pack = self
            .rule_pack_version
            .clone()
            .unwrap_or_else(|| "unknown".to_owned());
        HealthCheckResult::new(
            "version",
            HealthStatus::Pass,
            format!("arbitraitor v{arbitraitor_version}, rules {rule_pack}"),
        )
    }

    /// Validates the configured standalone policy TOML file.
    #[must_use]
    pub fn check_policy_validity(&self) -> HealthCheckResult {
        let Some(path) = &self.policy_path else {
            return HealthCheckResult::skipped(
                "policy_validity",
                "no standalone policy file configured",
            );
        };
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) => {
                return HealthCheckResult::new(
                    "policy_validity",
                    HealthStatus::Fail,
                    format!("policy file {} is unreadable: {error}", path.display()),
                );
            }
        };
        match PolicyEngine::load(&content) {
            Ok(engine) => HealthCheckResult::new(
                "policy_validity",
                HealthStatus::Pass,
                format!("policy {} is valid", path.display()),
            )
            .with_details(serde_json::json!({ "digest": engine.digest().clone() })),
            Err(error) => HealthCheckResult::new(
                "policy_validity",
                HealthStatus::Fail,
                format!("policy file {} is invalid: {error}", path.display()),
            ),
        }
    }

    /// Verifies configured YARA-X rule directories exist and were parsed.
    #[must_use]
    pub fn check_yara_rules(&self) -> HealthCheckResult {
        if self.yara_rules.is_empty() {
            return HealthCheckResult::skipped("yara_rules", "no YARA-X rule directory configured");
        }
        let mut rule_files = 0usize;
        let mut versions = Vec::new();
        for probe in &self.yara_rules {
            if let Some(error) = &probe.parse_error {
                return HealthCheckResult::new(
                    "yara_rules",
                    HealthStatus::Fail,
                    format!(
                        "YARA-X rules in {} failed to parse: {error}",
                        probe.path.display()
                    ),
                );
            }
            let count = count_rule_files(&probe.path);
            if count == 0 {
                return HealthCheckResult::new(
                    "yara_rules",
                    HealthStatus::Warn,
                    format!(
                        "YARA-X rules directory {} contains no .yar files",
                        probe.path.display()
                    ),
                );
            }
            rule_files += count;
            versions.extend(probe.versions.clone());
        }
        HealthCheckResult::new(
            "yara_rules",
            HealthStatus::Pass,
            format!("{rule_files} YARA-X rule files parsed"),
        )
        .with_details(serde_json::json!({ "rule_files": rule_files, "versions": versions }))
    }

    /// Checks local antivirus adapter availability for `ClamAV` or Defender.
    #[must_use]
    pub fn check_av_adapters(&self) -> HealthCheckResult {
        let clamav = command_exists("clamdscan") || command_exists("clamscan");
        let defender = defender_available();
        if clamav || defender {
            return HealthCheckResult::new(
                "av_adapters",
                HealthStatus::Pass,
                format!("antivirus adapter available: clamav={clamav}, defender={defender}"),
            );
        }
        HealthCheckResult::new(
            "av_adapters",
            HealthStatus::Warn,
            "no ClamAV or Microsoft Defender adapter command found in PATH",
        )
    }

    /// Checks scanner signature/database files are fresh enough for online posture.
    #[must_use]
    pub fn check_scanner_freshness(&self) -> HealthCheckResult {
        if self.scanner_signature_paths.is_empty() {
            return HealthCheckResult::skipped(
                "scanner_freshness",
                "no scanner signature path configured",
            );
        }
        newest_mtime_result("scanner_freshness", &self.scanner_signature_paths)
    }

    /// Verifies configured intel feed signature files exist and are readable.
    #[must_use]
    pub fn check_feed_signatures(&self) -> HealthCheckResult {
        if self.feed_signature_paths.is_empty() {
            return HealthCheckResult::skipped(
                "feed_signatures",
                "no signed intel feeds configured",
            );
        }
        for path in &self.feed_signature_paths {
            if let Err(error) = fs::read(path) {
                return HealthCheckResult::new(
                    "feed_signatures",
                    HealthStatus::Fail,
                    format!("feed signature {} is unreadable: {error}", path.display()),
                );
            }
        }
        HealthCheckResult::new(
            "feed_signatures",
            HealthStatus::Pass,
            format!(
                "{} feed signature files readable",
                self.feed_signature_paths.len()
            ),
        )
    }

    /// Verifies the configured update trust-root public key exists.
    #[must_use]
    pub fn check_update_trust_root(&self) -> HealthCheckResult {
        readable_key_check(
            "update_trust_root",
            self.update_trust_root.as_deref(),
            "no update trust-root key configured",
        )
    }

    /// Checks platform sandbox adapter availability.
    #[must_use]
    pub fn check_sandbox_adapters(&self) -> HealthCheckResult {
        sandbox_adapter_status()
    }

    /// Verifies configured plugin directories contain readable plugin manifests.
    #[must_use]
    pub fn check_plugin_manifests(&self) -> HealthCheckResult {
        if self.plugin_dirs.is_empty() {
            return HealthCheckResult::skipped(
                "plugin_manifests",
                "no plugin directories configured",
            );
        }
        let mut manifests = 0usize;
        for dir in &self.plugin_dirs {
            let entries = match fs::read_dir(dir) {
                Ok(entries) => entries,
                Err(error) => {
                    return HealthCheckResult::new(
                        "plugin_manifests",
                        HealthStatus::Fail,
                        format!("plugin directory {} is unreadable: {error}", dir.display()),
                    );
                }
            };
            for entry in entries.flatten() {
                let path = entry.path().join("manifest.toml");
                if path.is_file() {
                    manifests += 1;
                    if let Err(error) = fs::read_to_string(&path) {
                        return HealthCheckResult::new(
                            "plugin_manifests",
                            HealthStatus::Fail,
                            format!("plugin manifest {} is unreadable: {error}", path.display()),
                        );
                    }
                }
            }
        }
        if manifests == 0 {
            return HealthCheckResult::skipped("plugin_manifests", "no plugin manifests installed");
        }
        HealthCheckResult::new(
            "plugin_manifests",
            HealthStatus::Pass,
            format!("{manifests} plugin manifests readable"),
        )
    }

    /// Checks installed plugin manifests advertise a compatible protocol version when declared.
    #[must_use]
    pub fn check_plugin_protocol(&self) -> HealthCheckResult {
        if self.plugin_dirs.is_empty() {
            return HealthCheckResult::skipped(
                "plugin_protocol",
                "no plugin directories configured",
            );
        }
        let Some((checked, incompatible)) = plugin_protocol_counts(&self.plugin_dirs) else {
            return HealthCheckResult::skipped("plugin_protocol", "no plugin manifests installed");
        };
        if incompatible > 0 {
            return HealthCheckResult::new(
                "plugin_protocol",
                HealthStatus::Fail,
                format!(
                    "{incompatible}/{checked} plugin manifests advertise incompatible protocol"
                ),
            );
        }
        HealthCheckResult::new(
            "plugin_protocol",
            HealthStatus::Pass,
            format!("{checked} plugin manifests protocol-compatible"),
        )
    }

    /// Checks wrapper semantic coverage for installed curl and wget commands.
    #[must_use]
    pub fn check_wrapper_coverage(&self) -> HealthCheckResult {
        let curl = command_exists("curl");
        let wget = command_exists("wget");
        match (curl, wget) {
            (true, true) => HealthCheckResult::new(
                "wrapper_coverage",
                HealthStatus::Pass,
                "curl and wget are installed; wrapper coverage available",
            ),
            (true, false) | (false, true) => HealthCheckResult::new(
                "wrapper_coverage",
                HealthStatus::Warn,
                format!("partial wrapper coverage: curl={curl}, wget={wget}"),
            ),
            (false, false) => HealthCheckResult::skipped(
                "wrapper_coverage",
                "curl and wget are not installed on PATH",
            ),
        }
    }

    /// Verifies the configured shim directory precedes original tools in PATH.
    #[must_use]
    pub fn check_shim_path_order(&self) -> HealthCheckResult {
        let Some(shim_dir) = &self.shim_dir else {
            return HealthCheckResult::skipped("shim_path_order", "no shim directory configured");
        };
        let Some(path) = std::env::var_os("PATH") else {
            return HealthCheckResult::new("shim_path_order", HealthStatus::Warn, "PATH is unset");
        };
        let entries = std::env::split_paths(&path).collect::<Vec<_>>();
        let Some(shim_index) = entries.iter().position(|entry| entry == shim_dir) else {
            return HealthCheckResult::new(
                "shim_path_order",
                HealthStatus::Warn,
                format!("shim directory {} is not on PATH", shim_dir.display()),
            );
        };
        let first_tool = entries
            .iter()
            .position(|entry| entry.join("curl").is_file() || entry.join("wget").is_file());
        if first_tool.is_some_and(|index| index < shim_index) {
            return HealthCheckResult::new(
                "shim_path_order",
                HealthStatus::Fail,
                "an original curl/wget appears before the shim directory in PATH",
            );
        }
        HealthCheckResult::new(
            "shim_path_order",
            HealthStatus::Pass,
            format!(
                "shim directory {} precedes original tools",
                shim_dir.display()
            ),
        )
    }

    /// Checks the local clock is plausible without performing network I/O.
    #[must_use]
    pub fn check_clock_skew(&self) -> HealthCheckResult {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) if duration.as_secs() >= MIN_CLOCK_EPOCH => HealthCheckResult::new(
                "clock_skew",
                HealthStatus::Pass,
                "system clock is plausible",
            ),
            Ok(duration) => HealthCheckResult::new(
                "clock_skew",
                HealthStatus::Warn,
                format!(
                    "system clock epoch {} is implausibly old",
                    duration.as_secs()
                ),
            ),
            Err(error) => HealthCheckResult::new(
                "clock_skew",
                HealthStatus::Fail,
                format!("system clock is before Unix epoch: {error}"),
            ),
        }
    }

    /// Verifies configured proxy environment variables are syntactically plausible.
    #[must_use]
    pub fn check_proxy_settings(&self) -> HealthCheckResult {
        let proxies = [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ]
        .into_iter()
        .filter_map(|name| std::env::var(name).ok().map(|value| (name, value)))
        .collect::<Vec<_>>();
        if proxies.is_empty() {
            return HealthCheckResult::skipped(
                "proxy_settings",
                "no proxy environment variables set",
            );
        }
        for (name, value) in &proxies {
            if !valid_proxy_value(value) {
                return HealthCheckResult::new(
                    "proxy_settings",
                    HealthStatus::Fail,
                    format!("{name} has unsupported proxy URL scheme"),
                );
            }
        }
        HealthCheckResult::new(
            "proxy_settings",
            HealthStatus::Pass,
            format!("{} proxy variables configured", proxies.len()),
        )
    }

    /// Verifies the configured receipt signing key exists and is readable.
    #[must_use]
    pub fn check_receipt_signing_key(&self) -> HealthCheckResult {
        readable_key_check(
            "receipt_signing_key",
            self.receipt_signing_key.as_deref(),
            "no receipt signing key configured",
        )
    }

    /// Checks the cosign version on PATH against the minimum that addresses
    /// CVE-2026-22703 and CVE-2026-24122 (issue #457).
    ///
    /// Returns `Skipped` when cosign is not installed (Sigstore verification
    /// is optional), `Pass` when the version is >= v3.0.5, `Fail` when below
    /// the floor, and `Warn` when the version cannot be determined.
    #[must_use]
    pub fn check_sigstore_version(&self) -> HealthCheckResult {
        if !command_exists("cosign") {
            return HealthCheckResult::skipped(
                "sigstore_version",
                "cosign is not installed; Sigstore verification unavailable",
            );
        }
        let output = match Command::new("cosign")
            .arg("version")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                return HealthCheckResult::new(
                    "sigstore_version",
                    HealthStatus::Warn,
                    format!("cosign version probe failed: {error}"),
                );
            }
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let Some(version) = parse_cosign_version(&text) else {
            return HealthCheckResult::new(
                "sigstore_version",
                HealthStatus::Warn,
                "cosign is installed but version could not be determined",
            );
        };
        let Some(parsed) = parse_version_tuple(&version) else {
            return HealthCheckResult::new(
                "sigstore_version",
                HealthStatus::Warn,
                format!("cosign version '{version}' is not a recognized semver"),
            );
        };
        if parsed >= MIN_COSIGN_VERSION {
            HealthCheckResult::new(
                "sigstore_version",
                HealthStatus::Pass,
                format!(
                    "cosign v{version} meets minimum v{}",
                    version_tuple_str(MIN_COSIGN_VERSION)
                ),
            )
            .with_details(serde_json::json!({
                "version": version,
                "minimum": version_tuple_str(MIN_COSIGN_VERSION),
            }))
        } else {
            HealthCheckResult::new(
                "sigstore_version",
                HealthStatus::Fail,
                format!(
                    "cosign v{version} is below minimum v{} (CVE-2026-22703, CVE-2026-24122)",
                    version_tuple_str(MIN_COSIGN_VERSION)
                ),
            )
            .with_details(serde_json::json!({
                "version": version,
                "minimum": version_tuple_str(MIN_COSIGN_VERSION),
            }))
        }
    }
}

fn readable_key_check(name: &str, path: Option<&Path>, skipped: &str) -> HealthCheckResult {
    let Some(path) = path else {
        return HealthCheckResult::skipped(name, skipped);
    };
    match fs::read(path) {
        Ok(bytes) if !bytes.is_empty() => HealthCheckResult::new(
            name,
            HealthStatus::Pass,
            format!("key {} is readable", path.display()),
        ),
        Ok(_) => HealthCheckResult::new(
            name,
            HealthStatus::Fail,
            format!("key {} is empty", path.display()),
        ),
        Err(error) => HealthCheckResult::new(
            name,
            HealthStatus::Fail,
            format!("key {} is unreadable: {error}", path.display()),
        ),
    }
}

fn newest_mtime_result(name: &str, paths: &[PathBuf]) -> HealthCheckResult {
    let now = SystemTime::now();
    let mut newest = None;
    for path in paths {
        let modified = match fs::metadata(path).and_then(|meta| meta.modified()) {
            Ok(modified) => modified,
            Err(error) => {
                return HealthCheckResult::new(
                    name,
                    HealthStatus::Fail,
                    format!(
                        "scanner signature {} is unreadable: {error}",
                        path.display()
                    ),
                );
            }
        };
        newest = Some(newest.map_or(modified, |current: SystemTime| current.max(modified)));
    }
    let Some(modified) = newest else {
        return HealthCheckResult::skipped(name, "no scanner signature path configured");
    };
    match now.duration_since(modified) {
        Ok(age) if age <= FRESHNESS_WINDOW => HealthCheckResult::new(
            name,
            HealthStatus::Pass,
            format!("scanner signatures updated {} seconds ago", age.as_secs()),
        ),
        Ok(age) => HealthCheckResult::new(
            name,
            HealthStatus::Warn,
            format!(
                "scanner signatures are stale: {} seconds old",
                age.as_secs()
            ),
        ),
        Err(_) => HealthCheckResult::new(
            name,
            HealthStatus::Warn,
            "scanner signature timestamp is in the future",
        ),
    }
}

fn count_rule_files(path: &Path) -> usize {
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            matches!(
                entry.path().extension().and_then(OsStr::to_str),
                Some("yar" | "yara")
            )
        })
        .count()
}

fn command_exists(command: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| {
            let candidate = dir.join(command);
            candidate.is_file() || cfg!(windows) && dir.join(format!("{command}.exe")).is_file()
        })
    })
}

fn defender_available() -> bool {
    command_exists("MpCmdRun") || command_exists("mdatp")
}

fn sandbox_adapter_status() -> HealthCheckResult {
    if cfg!(target_os = "linux") {
        let landlock = Path::new("/proc/self/status").is_file();
        return if landlock {
            HealthCheckResult::new(
                "sandbox_adapters",
                HealthStatus::Pass,
                "Linux sandbox probes are available",
            )
        } else {
            HealthCheckResult::new(
                "sandbox_adapters",
                HealthStatus::Warn,
                "Linux procfs unavailable; sandbox adapter probing degraded",
            )
        };
    }
    HealthCheckResult::skipped(
        "sandbox_adapters",
        "restricted sandbox adapters are Linux-only in this build",
    )
}

fn plugin_protocol_counts(dirs: &[PathBuf]) -> Option<(usize, usize)> {
    let mut checked = 0usize;
    let mut incompatible = 0usize;
    for dir in dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let manifest = entry.path().join("manifest.toml");
            let Ok(content) = fs::read_to_string(&manifest) else {
                continue;
            };
            checked += 1;
            if content.contains("protocol_version") && !content.contains("protocol_version = 1") {
                incompatible += 1;
            }
        }
    }
    (checked > 0).then_some((checked, incompatible))
}

fn valid_proxy_value(value: &str) -> bool {
    value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("socks5://")
        || value.starts_with("socks5h://")
}

fn parse_cosign_version(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        let candidate = trimmed
            .strip_prefix("GitVersion:")
            .map_or(trimmed, str::trim);
        let candidate = candidate.strip_prefix('v').unwrap_or(candidate);
        let parts: Vec<&str> = candidate.split('.').collect();
        if parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        {
            return Some(candidate.to_owned());
        }
    }
    None
}

fn parse_version_tuple(version: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = version.trim_start_matches('v').split('.').collect();
    if parts.len() == 3 {
        Some((
            parts[0].parse().ok()?,
            parts[1].parse().ok()?,
            parts[2].parse().ok()?,
        ))
    } else {
        None
    }
}

fn version_tuple_str(tuple: (u32, u32, u32)) -> String {
    format!("{}.{}.{}", tuple.0, tuple.1, tuple.2)
}
