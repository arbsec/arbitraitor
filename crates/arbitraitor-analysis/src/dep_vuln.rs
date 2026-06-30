//! Dependency vulnerability detector (spec §18.5).
//!
//! Scans artifacts that contain package manifests or lockfiles against a
//! local OSV/KEV snapshot. Offline-first: the snapshot is passed via the
//! constructor. Live queries to OSV.dev, deps.dev, or CISA are policy-gated
//! and not performed by this detector.
//!
//! Findings, not verdicts — the detector does not block release on its own.
//! Policy interprets the findings per §18.5.

use crate::{AnalysisContext, Detector};
use arbitraitor_model::artifact::ArtifactKind;
use arbitraitor_model::finding::{
    DetectorMetadata, Evidence, EvidenceKind, Finding, FindingCategory,
};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::taxonomy::{TaxonomyName, TaxonomyRef};
use arbitraitor_model::verdict::{Confidence, Severity};
use serde::{Deserialize, Serialize};

/// Maximum lockfile artifact size accepted (10 MiB).
const MAX_LOCKFILE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of packages to extract before stopping.
const MAX_PACKAGES: usize = 10_000;

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

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Vec<Finding> {
        let Some(format) = Self::detect_format(ctx.artifact_bytes) else {
            tracing::debug!("dep-vuln: artifact is not a recognized lockfile format");
            return Vec::new();
        };

        let packages = Self::parse_packages(ctx.artifact_bytes, format);
        if packages.is_empty() {
            tracing::debug!("dep-vuln: no packages found in lockfile");
            return Vec::new();
        }

        let matches = self.lookup_advisories(&packages);
        matches
            .iter()
            .map(|(coordinate, advisory)| {
                Self::advisory_to_finding(coordinate, advisory, &ctx.artifact_sha256)
            })
            .collect()
    }
}
