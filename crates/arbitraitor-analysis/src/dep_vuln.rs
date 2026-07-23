//! Dependency vulnerability detector (spec §18.5).
//!
//! Scans artifacts that contain package manifests or lockfiles against a
//! local OSV/KEV snapshot. Offline-first: the snapshot is passed via the
//! constructor. Live queries to OSV.dev, deps.dev, or CISA are policy-gated
//! and not performed by this detector.
//!
//! Findings, not verdicts — the detector does not block release on its own.
//! Policy interprets the findings per §18.5.

// allow: SIZE_OK — the detector, snapshot types, config, and lockfile parsers
// form a single cohesive module for spec §18.5. Splitting would scatter
// tightly-coupled types across files without reducing cognitive load.
use crate::{AnalysisContext, Detector, DetectorError};
use arbitraitor_model::artifact::ArtifactKind;
use arbitraitor_model::finding::{
    DetectorMetadata, DetectorProvenance, Evidence, EvidenceKind, Finding, FindingCategory,
};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::taxonomy::{TaxonomyName, TaxonomyRef};
use arbitraitor_model::verdict::{Confidence, Severity};
use arbitraitor_model::vex::{VexStatement, VexStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Maximum lockfile artifact size accepted (10 MiB).
const MAX_LOCKFILE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of packages to extract before stopping.
const MAX_PACKAGES: usize = 10_000;

/// Maximum number of advisories in a single OSV snapshot.
const MAX_ADVISORIES: usize = 50_000;

/// Maximum number of entries in a single KEV snapshot.
const MAX_KEV_ENTRIES: usize = 10_000;

/// Maximum snapshot file size accepted (50 MiB).
const MAX_SNAPSHOT_FILE_SIZE: usize = 50 * 1024 * 1024;

/// A single vulnerability advisory in the local OSV/KEV snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advisory {
    /// Advisory identifier (e.g. `GHSA-xxxx-xxxx-xxxx`, `CVE-2026-1234`).
    pub id: String,
    /// Package ecosystem (e.g. `crates.io`, `npm`, `PyPI`, `Go`).
    pub ecosystem: String,
    /// Package name affected by this advisory.
    pub package: String,
    /// Affected version range (e.g. `>=1.0.0,<2.0.0` or `*`).
    pub affected_range: String,
    /// Severity of the vulnerability.
    pub severity: String,
    /// Whether the advisory is from CISA KEV (known exploited).
    pub is_kev: bool,
}

/// A parsed package coordinate from a lockfile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageCoordinate {
    /// Package ecosystem.
    pub ecosystem: String,
    /// Package name.
    pub name: String,
    /// Resolved version.
    pub version: String,
}

/// The lockfile format that was detected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockfileFormat {
    /// `Cargo.lock` (TOML).
    CargoLock,
    /// `package-lock.json` (JSON, npm).
    NpmLock,
    /// `uv.lock` (JSON, uv).
    UvLock,
    /// Recognized but not yet fully parsed.
    Other,
}

/// Advisory entry in an OSV snapshot. Alias for [`Advisory`].
pub type OsvAdvisory = Advisory;

/// A single CISA KEV (Known Exploited Vulnerabilities) catalog entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KevEntry {
    /// CVE identifier (e.g. `CVE-2026-1234`).
    pub cve_id: String,
    /// Vendor name.
    pub vendor: String,
    /// Product name.
    pub product: String,
    /// Vulnerability name or short description.
    pub vulnerability_name: String,
    /// Date the entry was added to the KEV catalog (ISO 8601).
    pub date_added: Option<String>,
    /// Whether this vulnerability is known to be used in ransomware campaigns.
    pub known_ransomware_use: bool,
}

impl KevEntry {
    /// Converts this KEV entry into an [`Advisory`] with `is_kev = true`.
    #[must_use]
    pub fn to_advisory(&self, ecosystem: &str, package: &str, range: &str) -> Advisory {
        Advisory {
            id: self.cve_id.clone(),
            ecosystem: ecosystem.to_owned(),
            package: package.to_owned(),
            affected_range: range.to_owned(),
            severity: "critical".to_owned(),
            is_kev: true,
        }
    }
}

/// Offline OSV advisory snapshot loaded from disk.
#[derive(Clone, Debug)]
pub struct OsvSnapshot {
    /// SHA-256 digest of the raw snapshot file bytes.
    pub digest: Sha256Digest,
    /// Advisory entries parsed from the snapshot.
    pub advisories: Vec<OsvAdvisory>,
}

impl OsvSnapshot {
    /// Loads an OSV snapshot from a JSON file on disk.
    ///
    /// The file digest is computed over the raw bytes so the receipt can
    /// record provenance without re-reading the file.
    ///
    /// # Errors
    ///
    /// Returns [`DetectorError::Resource`] if the file cannot be read or
    /// parsed, or [`DetectorError::Other`] if the advisory count exceeds
    /// [`MAX_ADVISORIES`].
    pub fn load_from_path(path: &Path) -> Result<Self, DetectorError> {
        let bytes = read_snapshot_file(path)?;
        let digest = Sha256Digest::new(Sha256::digest(&bytes).into());
        let advisories: Vec<OsvAdvisory> = serde_json::from_slice(&bytes).map_err(|error| {
            DetectorError::ParseError(format!("osv snapshot parse error: {error}"))
        })?;
        if advisories.len() > MAX_ADVISORIES {
            return Err(DetectorError::Other(format!(
                "osv snapshot has {} advisories, limit is {MAX_ADVISORIES}",
                advisories.len()
            )));
        }
        Ok(Self { digest, advisories })
    }

    /// Creates a snapshot from pre-parsed advisories with a computed digest.
    #[must_use]
    pub fn from_advisories(advisories: Vec<OsvAdvisory>) -> Self {
        let serialized = serde_json::to_vec(&advisories).unwrap_or_default();
        let digest = Sha256Digest::new(Sha256::digest(&serialized).into());
        Self { digest, advisories }
    }
}

/// Offline CISA KEV snapshot loaded from disk.
#[derive(Clone, Debug)]
pub struct KevSnapshot {
    /// SHA-256 digest of the raw snapshot file bytes.
    pub digest: Sha256Digest,
    /// KEV entries parsed from the snapshot.
    pub entries: Vec<KevEntry>,
}

impl KevSnapshot {
    /// Loads a KEV snapshot from a JSON file on disk.
    ///
    /// # Errors
    ///
    /// Returns [`DetectorError::Resource`] if the file cannot be read or
    /// parsed, or [`DetectorError::Other`] if the entry count exceeds
    /// [`MAX_KEV_ENTRIES`].
    pub fn load_from_path(path: &Path) -> Result<Self, DetectorError> {
        let bytes = read_snapshot_file(path)?;
        let digest = Sha256Digest::new(Sha256::digest(&bytes).into());
        let entries: Vec<KevEntry> = serde_json::from_slice(&bytes).map_err(|error| {
            DetectorError::ParseError(format!("kev snapshot parse error: {error}"))
        })?;
        if entries.len() > MAX_KEV_ENTRIES {
            return Err(DetectorError::Other(format!(
                "kev snapshot has {} entries, limit is {MAX_KEV_ENTRIES}",
                entries.len()
            )));
        }
        Ok(Self { digest, entries })
    }

    /// Creates a snapshot from pre-parsed entries with a computed digest.
    #[must_use]
    pub fn from_entries(entries: Vec<KevEntry>) -> Self {
        let serialized = serde_json::to_vec(&entries).unwrap_or_default();
        let digest = Sha256Digest::new(Sha256::digest(&serialized).into());
        Self { digest, entries }
    }
}

/// Update mode for the dependency-vulnerability detector (spec §18.5).
///
/// Controls whether the detector may reach the network for advisory
/// refresh. The default and safest mode is [`OfflineOnly`].
///
/// [`OfflineOnly`]: DepVulnUpdateMode::OfflineOnly
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepVulnUpdateMode {
    /// Use only the local snapshot; no network access (default).
    #[default]
    OfflineOnly,
    /// Fetch a hash of the remote database and compare to the local snapshot
    /// digest; refresh only if the hash differs.
    HashOnly,
    /// Fetch the full remote database with redaction of PII and source URLs
    /// before local storage.
    OnlineWithRedaction,
}

/// Configuration for the dependency-vulnerability detector (spec §18.5).
///
/// Per spec: `enabled = "auto"` is forbidden. The detector must be
/// explicitly enabled with `enabled = true`. The default is `disabled`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DepVulnConfig {
    /// Whether the detector is enabled. Must be explicitly `true` to run.
    /// Defaults to `false` (disabled) per spec §18.5.
    #[serde(default)]
    pub enabled: bool,
    /// Advisory update mode. Defaults to [`DepVulnUpdateMode::OfflineOnly`].
    #[serde(default)]
    pub update_mode: DepVulnUpdateMode,
    /// Path to the OSV snapshot JSON file on disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub osv_snapshot_path: Option<PathBuf>,
    /// Path to the CISA KEV snapshot JSON file on disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kev_snapshot_path: Option<PathBuf>,
}

/// Full dependency-vulnerability detector with config, OSV/KEV snapshots,
/// and VEX interaction (spec §18.5).
///
/// This detector wraps the lower-level [`DepVulnDetector`] with:
/// - Explicit enable/disable (spec: `enabled = "auto"` is forbidden).
/// - Offline snapshot loading from disk paths in [`DepVulnConfig`].
/// - VEX-based severity downgrade when a trusted VEX statement asserts
///   `fixed` or `not_affected` for a matched advisory.
/// - Snapshot digest exposure for receipt recording.
pub struct DependencyVulnerabilityDetector {
    config: DepVulnConfig,
    inner: DepVulnDetector,
    vex_statements: Vec<VexStatement>,
}

impl DependencyVulnerabilityDetector {
    /// Creates a detector from configuration, loading snapshots from disk.
    ///
    /// If `config.enabled` is `false`, the detector is created but will
    /// return no findings when analyzed (spec: default is disabled).
    ///
    /// # Errors
    ///
    /// Returns [`DetectorError::Resource`] if a configured snapshot path
    /// cannot be read or parsed.
    pub fn from_config(config: DepVulnConfig) -> Result<Self, DetectorError> {
        let mut advisories = Vec::new();
        let mut digests = Vec::new();

        if let Some(ref path) = config.osv_snapshot_path {
            let snapshot = OsvSnapshot::load_from_path(path)?;
            advisories.extend(snapshot.advisories);
            digests.push(snapshot.digest);
        }

        if let Some(ref path) = config.kev_snapshot_path {
            let snapshot = KevSnapshot::load_from_path(path)?;
            for entry in &snapshot.entries {
                advisories.push(Advisory {
                    id: entry.cve_id.clone(),
                    ecosystem: String::new(),
                    package: String::new(),
                    affected_range: "*".to_owned(),
                    severity: "critical".to_owned(),
                    is_kev: true,
                });
            }
            digests.push(snapshot.digest);
        }

        let snapshot_digest = compute_combined_digest(&digests);
        let inner = DepVulnDetector::new(advisories, snapshot_digest);

        Ok(Self {
            config,
            inner,
            vex_statements: Vec::new(),
        })
    }

    /// Creates a detector from pre-loaded snapshots and config.
    #[must_use]
    pub fn with_snapshots(
        config: DepVulnConfig,
        osv: Option<OsvSnapshot>,
        kev: Option<KevSnapshot>,
    ) -> Self {
        let mut advisories = Vec::new();
        let mut digests = Vec::new();

        if let Some(snapshot) = osv {
            digests.push(snapshot.digest.clone());
            advisories.extend(snapshot.advisories);
        }

        if let Some(snapshot) = kev {
            digests.push(snapshot.digest.clone());
            for entry in &snapshot.entries {
                advisories.push(Advisory {
                    id: entry.cve_id.clone(),
                    ecosystem: String::new(),
                    package: String::new(),
                    affected_range: "*".to_owned(),
                    severity: "critical".to_owned(),
                    is_kev: true,
                });
            }
        }

        let snapshot_digest = compute_combined_digest(&digests);
        let inner = DepVulnDetector::new(advisories, snapshot_digest);

        Self {
            config,
            inner,
            vex_statements: Vec::new(),
        }
    }

    /// Attaches VEX statements for severity downgrade evaluation.
    #[must_use]
    pub fn with_vex_statements(mut self, statements: Vec<VexStatement>) -> Self {
        self.vex_statements = statements;
        self
    }

    /// Returns the combined snapshot digest for receipt recording.
    #[must_use]
    pub fn snapshot_digest(&self) -> Sha256Digest {
        self.inner.snapshot_digest()
    }

    /// Returns `true` if the detector is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Returns the VEX status for a given vulnerability ID, if any.
    fn vex_status_for(&self, vulnerability_id: &str) -> Option<VexStatus> {
        self.vex_statements
            .iter()
            .find(|stmt| {
                stmt.vulnerability
                    .as_str()
                    .eq_ignore_ascii_case(vulnerability_id)
            })
            .map(|stmt| stmt.status)
    }

    /// Downgrades severity by one level if a VEX statement asserts
    /// `fixed` or `not_affected` for the advisory.
    fn apply_vex_downgrade(&self, advisory_id: &str, severity: Severity) -> Severity {
        match self.vex_status_for(advisory_id) {
            Some(VexStatus::Fixed | VexStatus::NotAffected) => match severity {
                Severity::Critical => Severity::High,
                Severity::High => Severity::Medium,
                Severity::Medium => Severity::Low,
                Severity::Low | Severity::Informational => Severity::Informational,
            },
            _ => severity,
        }
    }
}

impl Detector for DependencyVulnerabilityDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: "dep-vuln".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            supported_artifact_kinds: vec![ArtifactKind::Json, ArtifactKind::GenericText],
            capabilities: vec!["offline-scan".to_owned(), "vex-aware".to_owned()],
            is_local: true,
            may_upload: false,
            default_timeout_ms: 10_000,
            is_deterministic: true,
        }
    }

    fn provenance(&self) -> Option<DetectorProvenance> {
        Some(DetectorProvenance {
            binary_sha256: None,
            binary_version: None,
            ruleset_digest: Some(self.snapshot_digest().to_string()),
        })
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        if !self.config.enabled {
            tracing::debug!("dep-vuln: detector disabled, skipping");
            return Ok(Vec::new());
        }

        let findings = self.inner.analyze(ctx)?;
        if self.vex_statements.is_empty() {
            return Ok(findings);
        }

        Ok(findings
            .into_iter()
            .map(|finding| {
                let advisory_id = finding
                    .references
                    .iter()
                    .find_map(|r| r.strip_prefix("https://osv.dev/vulnerability/"))
                    .unwrap_or(&finding.id);
                let downgraded = self.apply_vex_downgrade(advisory_id, finding.severity);
                Finding {
                    severity: downgraded,
                    ..finding
                }
            })
            .collect())
    }
}

/// Reads a snapshot file from disk with size validation.
fn read_snapshot_file(path: &Path) -> Result<Vec<u8>, DetectorError> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        DetectorError::Resource(format!("snapshot file metadata error: {error}"))
    })?;
    let file_size = usize::try_from(metadata.len()).map_err(|_| {
        DetectorError::Resource(format!(
            "snapshot file size {} exceeds usize on this platform",
            metadata.len()
        ))
    })?;
    if file_size > MAX_SNAPSHOT_FILE_SIZE {
        return Err(DetectorError::Resource(format!(
            "snapshot file size {file_size} exceeds limit {MAX_SNAPSHOT_FILE_SIZE}"
        )));
    }
    std::fs::read(path)
        .map_err(|error| DetectorError::Resource(format!("snapshot file read error: {error}")))
}

/// Computes a combined digest from multiple snapshot digests.
fn compute_combined_digest(digests: &[Sha256Digest]) -> Sha256Digest {
    if digests.is_empty() {
        return Sha256Digest::new([0; 32]);
    }
    if digests.len() == 1 {
        return digests[0].clone();
    }
    let mut hasher = Sha256::new();
    for digest in digests {
        hasher.update(digest.as_bytes());
    }
    Sha256Digest::new(hasher.finalize().into())
}

/// Dependency vulnerability detector with an offline OSV/KEV snapshot.
pub struct DepVulnDetector {
    advisories: Vec<Advisory>,
    snapshot_digest: Sha256Digest,
}

impl DepVulnDetector {
    /// Creates a detector with the given advisory snapshot.
    #[must_use]
    pub fn new(advisories: Vec<Advisory>, snapshot_digest: Sha256Digest) -> Self {
        Self {
            advisories,
            snapshot_digest,
        }
    }

    /// Creates a detector with an empty advisory snapshot.
    #[must_use]
    pub fn empty(snapshot_digest: Sha256Digest) -> Self {
        Self::new(Vec::new(), snapshot_digest)
    }

    /// Returns the snapshot digest for receipt recording.
    #[must_use]
    pub fn snapshot_digest(&self) -> Sha256Digest {
        self.snapshot_digest.clone()
    }

    /// Detects the lockfile format from artifact bytes.
    #[must_use]
    pub fn detect_format(bytes: &[u8]) -> Option<LockfileFormat> {
        if bytes.len() > MAX_LOCKFILE_SIZE {
            return None;
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return None;
        };

        if text.contains("[[package]]") && text.contains("version =") {
            return Some(LockfileFormat::CargoLock);
        }

        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(bytes) {
            if json.get("lockfileVersion").is_some()
                || json.get("packages").is_some()
                || json.get("dependencies").is_some()
            {
                return Some(LockfileFormat::NpmLock);
            }
            if json.get("version").is_some()
                && json.get("package").is_some()
                && json.get("lockfileVersion").is_none()
            {
                return Some(LockfileFormat::UvLock);
            }
        }

        if text.contains("lockfileVersion:") && text.contains("dependencies:") {
            return Some(LockfileFormat::Other);
        }

        None
    }

    /// Parses package coordinates from the lockfile.
    #[must_use]
    pub fn parse_packages(bytes: &[u8], format: LockfileFormat) -> Vec<PackageCoordinate> {
        match format {
            LockfileFormat::CargoLock => Self::parse_cargo_lock(bytes),
            LockfileFormat::NpmLock => Self::parse_npm_lock(bytes),
            LockfileFormat::UvLock => Self::parse_uv_lock(bytes),
            LockfileFormat::Other => Vec::new(),
        }
    }

    fn parse_cargo_lock(bytes: &[u8]) -> Vec<PackageCoordinate> {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Vec::new();
        };
        let mut packages = Vec::new();
        let mut in_package_table = false;
        let mut current_name: Option<String> = None;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed == "[[package]]" {
                in_package_table = true;
                continue;
            }
            if trimmed.starts_with('[') {
                in_package_table = false;
                continue;
            }
            if !in_package_table {
                continue;
            }
            if packages.len() >= MAX_PACKAGES {
                break;
            }
            if let Some(name) = trimmed
                .strip_prefix("name = \"")
                .and_then(|n| n.strip_suffix('"'))
            {
                current_name = Some(name.to_owned());
            } else if let Some(version) = trimmed
                .strip_prefix("version = \"")
                .and_then(|v| v.strip_suffix('"'))
                && let Some(name) = current_name.take()
            {
                packages.push(PackageCoordinate {
                    ecosystem: "crates.io".to_owned(),
                    name,
                    version: version.to_owned(),
                });
            }
        }

        packages
    }

    fn parse_npm_lock(bytes: &[u8]) -> Vec<PackageCoordinate> {
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return Vec::new();
        };
        let mut packages = Vec::new();
        if packages.len() >= MAX_PACKAGES {
            return packages;
        }

        if let Some(packages_obj) = json.get("packages").and_then(|p| p.as_object()) {
            for (path, info) in packages_obj {
                if packages.len() >= MAX_PACKAGES {
                    break;
                }
                if path.is_empty() {
                    continue;
                }
                let name = path.rsplit("node_modules/").next().unwrap_or(path);
                if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                    packages.push(PackageCoordinate {
                        ecosystem: "npm".to_owned(),
                        name: name.to_owned(),
                        version: version.to_owned(),
                    });
                }
            }
        }

        if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
            for (name, info) in deps {
                if !packages.iter().any(|p| p.name == *name)
                    && let Some(version) = info.get("version").and_then(|v| v.as_str())
                {
                    packages.push(PackageCoordinate {
                        ecosystem: "npm".to_owned(),
                        name: name.clone(),
                        version: version.to_owned(),
                    });
                }
            }
        }

        packages
    }

    fn parse_uv_lock(bytes: &[u8]) -> Vec<PackageCoordinate> {
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return Vec::new();
        };
        let mut packages = Vec::new();

        if let Some(pkgs) = json.get("package").and_then(|p| p.as_array()) {
            for pkg in pkgs {
                let name = pkg.get("name").and_then(|n| n.as_str()).unwrap_or_default();
                let version = pkg
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if !name.is_empty() {
                    packages.push(PackageCoordinate {
                        ecosystem: "PyPI".to_owned(),
                        name: name.to_owned(),
                        version: version.to_owned(),
                    });
                }
            }
        }

        packages
    }

    /// Looks up package coordinates against the advisory snapshot.
    fn lookup_advisories(
        &self,
        packages: &[PackageCoordinate],
    ) -> Vec<(PackageCoordinate, Advisory)> {
        let mut matches = Vec::new();
        for pkg in packages {
            for advisory in &self.advisories {
                if advisory.ecosystem.eq_ignore_ascii_case(&pkg.ecosystem)
                    && advisory.package.eq_ignore_ascii_case(&pkg.name)
                    && Self::version_matches(&pkg.version, &advisory.affected_range)
                {
                    matches.push((pkg.clone(), advisory.clone()));
                }
            }
        }
        matches
    }

    /// Simple version range check (supports `*`, `==X`, `>=X`).
    ///
    /// Does NOT use lexicographic substring matching. For `>=`, uses
    /// lexicographic comparison (not semver-awware) — sufficient for
    /// the simplified advisory model but not for complex ranges.
    #[must_use]
    pub fn version_matches(version: &str, range: &str) -> bool {
        if range == "*" {
            return true;
        }
        if let Some(exact) = range.strip_prefix("==") {
            let exact = exact.trim();
            return version == exact;
        }
        if let Some(prefix) = range.strip_prefix(">=") {
            let rest = prefix.split(',').next().unwrap_or(prefix).trim();
            return version >= rest;
        }
        false
    }

    fn advisory_to_finding(
        coordinate: &PackageCoordinate,
        advisory: &Advisory,
        artifact_sha256: &Sha256Digest,
    ) -> Finding {
        let severity = match advisory.severity.to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "low" => Severity::Low,
            _ => Severity::Medium,
        };

        Finding {
            id: format!(
                "dep-vuln.{}.{}-{}",
                coordinate.ecosystem, coordinate.name, advisory.id
            ),
            detector: "dep-vuln".to_owned(),
            category: FindingCategory::PackageRisk,
            severity,
            confidence: if advisory.is_kev {
                Confidence::Confirmed
            } else {
                Confidence::High
            },
            title: format!(
                "{} {} in {} is affected by {}",
                coordinate.name, coordinate.version, coordinate.ecosystem, advisory.id
            ),
            description: format!(
                "Package {} version {} in ecosystem {} matches advisory {} (affected range: {}).{}",
                coordinate.name,
                coordinate.version,
                coordinate.ecosystem,
                advisory.id,
                advisory.affected_range,
                if advisory.is_kev {
                    " This advisory is in the CISA KEV catalog (known exploited)."
                } else {
                    ""
                }
            ),
            evidence: vec![Evidence {
                kind: EvidenceKind::Other,
                description: format!(
                    "Advisory {} for {} {} ({})",
                    advisory.id, coordinate.name, coordinate.version, coordinate.ecosystem
                ),
                content: None,
            }],
            artifact_sha256: artifact_sha256.clone(),
            location: None,
            remediation: Some(format!(
                "Upgrade {} to a version outside the affected range ({}).",
                coordinate.name, advisory.affected_range
            )),
            references: vec![format!("https://osv.dev/vulnerability/{}", advisory.id)],
            tags: vec![
                "dependency-vulnerability".to_owned(),
                coordinate.ecosystem.to_ascii_lowercase(),
            ],
            taxonomies: vec![TaxonomyRef {
                name: TaxonomyName::Cwe,
                id: "CWE-1395".to_owned(),
                confidence: Confidence::Medium,
                url: None,
            }],
        }
    }
}

impl Detector for DepVulnDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: "dep-vuln".to_owned(),
            version: "0.1.0".to_owned(),
            supported_artifact_kinds: vec![ArtifactKind::Json, ArtifactKind::GenericText],
            capabilities: vec!["offline-scan".to_owned()],
            is_local: true,
            may_upload: false,
            default_timeout_ms: 10_000,
            is_deterministic: true,
        }
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        let Some(format) = Self::detect_format(ctx.artifact_bytes) else {
            tracing::debug!("dep-vuln: artifact is not a recognized lockfile format");
            return Ok(Vec::new());
        };

        let packages = Self::parse_packages(ctx.artifact_bytes, format);
        if packages.is_empty() {
            tracing::debug!("dep-vuln: no packages found in lockfile");
            return Ok(Vec::new());
        }

        let matches = self.lookup_advisories(&packages);
        Ok(matches
            .iter()
            .map(|(coordinate, advisory)| {
                Self::advisory_to_finding(coordinate, advisory, &ctx.artifact_sha256)
            })
            .collect())
    }
}
