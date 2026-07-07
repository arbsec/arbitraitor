//! Advisory scan analysis for npm (spec §39.14, Phase 1 — advisory mode).
//!
//! Pure analysis — no I/O, no subprocess. The caller reads the lockfile and
//! root `package.json`, parses them, and passes the structured inputs here.
//! This module derives findings, a verdict, and the
//! [`PackageManagerReceipt`] per spec §39.14.5.
//!
//! Phase 1 scope (advisory): lockfile pre-scan + lifecycle detection.
//! Registry-proxy interception (Phase 2) and tarball byte scanning are
//! intentionally deferred — see task #422.

#![forbid(unsafe_code)]

use arbitraitor_model::ids::Sha256Digest;

use crate::lifecycle::LifecycleScript;
use crate::npm::PackageLock;
use crate::receipt::{CapabilityGrant, LifecycleScriptStatus, PackageManagerReceipt, ProxyMode};

/// Severity of a package finding, mapped to the advisory verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingSeverity {
    /// Informational; does not affect the verdict.
    Information,
    /// Review recommended; downgrades Pass → Warn.
    Warning,
    /// Execution must not proceed.
    Block,
}

/// A finding produced by advisory scanning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageFinding {
    /// Stable finding identifier (e.g. `npm.lifecycle.postinstall.root`).
    pub id: String,
    /// Package name the finding applies to; `(root)` for the project itself.
    pub package: String,
    /// Package version; empty for the root package.
    pub version: String,
    /// Finding severity.
    pub severity: FindingSeverity,
    /// Human-readable summary.
    pub title: String,
    /// Optional supporting detail (e.g. the script command, the URL).
    pub detail: Option<String>,
}

/// Verdict derived from the set of findings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdvisoryVerdict {
    /// No findings; safe to proceed.
    Pass,
    /// Findings present but none blocking; proceed with review.
    Warn,
    /// A blocking finding was raised; do not execute.
    Block,
}

impl AdvisoryVerdict {
    /// Returns `true` when execution may proceed (Pass or Warn).
    #[must_use]
    pub const fn allows_execution(self) -> bool {
        matches!(self, Self::Pass | Self::Warn)
    }
}

/// Outcome of an advisory scan.
#[derive(Clone, Debug)]
pub struct NpmAdvisoryOutcome {
    /// The receipt recorded per spec §39.14.5.
    pub receipt: PackageManagerReceipt,
    /// Findings raised during the scan.
    pub findings: Vec<PackageFinding>,
    /// Derived verdict.
    pub verdict: AdvisoryVerdict,
    /// Exit code of the real `npm install`, if it was executed.
    pub install_exit_code: Option<i32>,
}

/// Derives findings, verdict, and receipt from parsed lockfile inputs.
///
/// This is the pure core of the advisory scanner. The caller is responsible
/// for reading files, parsing the lockfile ([`crate::npm::parse_package_lock`]),
/// extracting root lifecycle scripts ([`crate::lifecycle::parse_lifecycle_scripts`]),
/// computing the lockfile SHA-256, and detecting the npm version.
///
/// # Arguments
///
/// * `lock` - Parsed `package-lock.json`.
/// * `root_scripts` - Lifecycle scripts declared in the root `package.json`.
/// * `npm_version` - Output of `npm --version`.
/// * `lockfile_digest` - SHA-256 of the raw lockfile bytes.
#[must_use]
pub fn analyze(
    lock: &PackageLock,
    root_scripts: &[LifecycleScript],
    npm_version: &str,
    lockfile_digest: Sha256Digest,
) -> NpmAdvisoryOutcome {
    let mut findings = Vec::new();
    let mut packages_incomplete = 0_usize;

    for script in root_scripts {
        findings.push(PackageFinding {
            id: format!("npm.lifecycle.{}.root", script.phase),
            package: "(root)".to_owned(),
            version: String::new(),
            severity: FindingSeverity::Warning,
            title: format!("root package declares '{}' lifecycle script", script.phase),
            detail: Some(script.command.clone()),
        });
    }
    if !root_scripts.is_empty() {
        packages_incomplete = packages_incomplete.saturating_add(1);
    }

    let mut any_dep_scripts = false;
    for pkg in &lock.packages {
        if pkg.has_scripts {
            any_dep_scripts = true;
            packages_incomplete = packages_incomplete.saturating_add(1);
            findings.push(PackageFinding {
                id: "npm.lifecycle.dependency".to_owned(),
                package: pkg.name.clone(),
                version: pkg.version.clone(),
                severity: FindingSeverity::Warning,
                title: format!(
                    "dependency '{}' declares install lifecycle scripts",
                    pkg.name
                ),
                detail: None,
            });
        }
        if let Some(resolved) = pkg.resolved.as_ref()
            && is_non_registry_url(resolved)
        {
            findings.push(PackageFinding {
                id: "npm.provenance.non_registry".to_owned(),
                package: pkg.name.clone(),
                version: pkg.version.clone(),
                severity: FindingSeverity::Block,
                title: format!(
                    "dependency '{}' resolved from non-registry source",
                    pkg.name
                ),
                detail: Some(resolved.clone()),
            });
        }
    }

    let packages_blocked = findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Block)
        .count();

    let verdict = if findings
        .iter()
        .any(|f| f.severity == FindingSeverity::Block)
    {
        AdvisoryVerdict::Block
    } else if findings.is_empty() {
        AdvisoryVerdict::Pass
    } else {
        AdvisoryVerdict::Warn
    };

    let lifecycle_status = if root_scripts.is_empty() && !any_dep_scripts {
        LifecycleScriptStatus::NotApplicable
    } else {
        LifecycleScriptStatus::IncompleteCoverage
    };

    let receipt = PackageManagerReceipt {
        tool: "npm".to_owned(),
        tool_version: npm_version.to_owned(),
        lockfile_digest,
        packages_inspected: lock.packages.len(),
        packages_blocked,
        packages_incomplete,
        lifecycle_scripts: lifecycle_status,
        build_sandbox: None,
        proxy_mode: ProxyMode::LockfilePrescan,
        capabilities: vec![
            CapabilityGrant {
                name: "read_lockfile".to_owned(),
                granted: true,
            },
            CapabilityGrant {
                name: "parse_argv".to_owned(),
                granted: true,
            },
        ],
    };

    NpmAdvisoryOutcome {
        receipt,
        findings,
        verdict,
        install_exit_code: None,
    }
}

/// Returns `true` when a resolved URL is outside the canonical npm registry.
///
/// `https://registry.npmjs.org/` and scoped fallbacks are accepted; anything
/// else (git URLs, tarball URLs from other hosts, `file:` links) is flagged.
fn is_non_registry_url(resolved: &str) -> bool {
    if resolved.starts_with("https://registry.npmjs.org/") {
        return false;
    }
    if resolved.starts_with("http://registry.npmjs.org/") {
        return false;
    }
    !resolved.starts_with("https://") && !resolved.starts_with("http://")
}

#[cfg(test)]
mod tests;
