//! npm adapter — JavaScript package manager integration.
//!
//! Implements spec §39.14.1 npm row. npm ships `--ignore-scripts` and
//! `npm audit` — Arbitraitor extends, not duplicates. This adapter combines:
//!
//! - **Lockfile pre-scan** (primary): parse `package-lock.json` (v1-v3)
//! - **Post-install scan** (secondary): scan `node_modules` after install

#![forbid(unsafe_code)]

use std::path::Path;

use serde::Deserialize;

use crate::recipe::{
    AdapterRecipe, InspectionPattern, LifecycleScriptPolicy, LockfileFormat, RegistryAdapter,
    RegistryTool,
};

/// npm registry adapter (spec §39.14.1).
#[derive(Clone, Debug)]
pub struct NpmAdapter;

impl RegistryAdapter for NpmAdapter {
    fn tool(&self) -> RegistryTool {
        RegistryTool::Npm
    }

    fn recipe(&self) -> AdapterRecipe {
        AdapterRecipe::new(
            InspectionPattern::LockfilePrescan,
            vec![
                InspectionPattern::PostInstallScan,
                InspectionPattern::RegistryProxy,
            ],
        )
    }

    fn lockfile_format(&self) -> LockfileFormat {
        LockfileFormat::PackageLockJson
    }

    fn lifecycle_script_policy(&self) -> LifecycleScriptPolicy {
        LifecycleScriptPolicy::DeniedByDefault
    }
}

/// A single package entry from `package-lock.json`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NpmPackage {
    /// Package name (e.g. `"express"`).
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Resolved tarball URL.
    pub resolved: Option<String>,
    /// Integrity hash (e.g. `"sha512-..."`).
    pub integrity: Option<String>,
    /// Whether lifecycle scripts are declared.
    pub has_scripts: bool,
}

/// Parsed `package-lock.json` contents.
#[derive(Clone, Debug)]
pub struct PackageLock {
    /// Lockfile version (1, 2, or 3).
    pub lockfile_version: u32,
    /// All package entries.
    pub packages: Vec<NpmPackage>,
}

/// Errors produced while parsing `package-lock.json`.
#[derive(Debug, thiserror::Error)]
pub enum NpmLockError {
    /// The file could not be read.
    #[error("failed to read file: {0}")]
    Io(#[from] std::io::Error),
    /// The JSON could not be parsed.
    #[error("failed to parse JSON: {0}")]
    Parse(#[from] serde_json::Error),
    /// Unsupported lockfile version.
    #[error("unsupported lockfile version: {0}")]
    InvalidVersion(u32),
    /// Too many packages in lockfile.
    #[error("too many packages in lockfile: {0}")]
    TooManyPackages(usize),
    /// A field exceeds the maximum length.
    #[error("field '{field}' too long: {len} bytes")]
    FieldTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        len: usize,
    },
    /// File is a symlink (rejected for security).
    #[error("symlink rejected")]
    SymlinkRejected,
    /// Path is not a regular file.
    #[error("not a regular file")]
    NotRegularFile,
    /// File exceeds maximum size.
    #[error("file too large: {size} bytes (max {max})")]
    FileTooLarge {
        /// Actual file size.
        size: u64,
        /// Maximum allowed size.
        max: u64,
    },
}

const MAX_LOCKFILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_PACKAGES: usize = 100_000;
const MAX_FIELD_LEN: usize = 1024;

#[derive(Deserialize)]
struct RawLock {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: u32,
    #[serde(default)]
    packages: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    dependencies: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPackage {
    version: Option<String>,
    resolved: Option<String>,
    integrity: Option<String>,
    has_install_script: Option<bool>,
}

/// Parses a `package-lock.json` file from raw bytes.
///
/// Supports format versions 1, 2, and 3.
///
/// # Errors
///
/// Returns [`NpmLockError`] if the file cannot be parsed or fails validation.
pub fn parse_package_lock(data: &[u8]) -> Result<PackageLock, NpmLockError> {
    let raw: RawLock = serde_json::from_slice(data)?;
    if !(1..=3).contains(&raw.lockfile_version) {
        return Err(NpmLockError::InvalidVersion(raw.lockfile_version));
    }

    let total_packages = raw.packages.len() + raw.dependencies.len();
    if total_packages > MAX_PACKAGES {
        return Err(NpmLockError::TooManyPackages(total_packages));
    }

    let mut packages = Vec::new();

    for (path, info) in &raw.packages {
        if path.is_empty() {
            continue;
        }
        let name = path.rsplit("node_modules/").next().unwrap_or(path);
        if let Ok(pkg) = deserialize_package(name, info) {
            packages.push(pkg);
        }
    }

    if raw.packages.is_empty() {
        for (name, info) in &raw.dependencies {
            if let Ok(pkg) = deserialize_package(name, info) {
                packages.push(pkg);
            }
        }
    }

    Ok(PackageLock {
        lockfile_version: raw.lockfile_version,
        packages,
    })
}

fn deserialize_package(name: &str, info: &serde_json::Value) -> Result<NpmPackage, NpmLockError> {
    let pkg: RawPackage = serde_json::from_value(info.clone())?;
    let name = name.to_owned();
    let version = pkg.version.unwrap_or_default();
    let resolved = pkg.resolved;
    let integrity = pkg.integrity;
    let has_scripts = pkg.has_install_script.unwrap_or(false);

    validate_field_len("name", &name)?;
    validate_field_len("version", &version)?;
    if let Some(ref r) = resolved {
        validate_field_len("resolved", r)?;
    }
    if let Some(ref i) = integrity {
        validate_field_len("integrity", i)?;
    }

    Ok(NpmPackage {
        name,
        version,
        resolved,
        integrity,
        has_scripts,
    })
}

fn validate_field_len(field: &'static str, value: &str) -> Result<(), NpmLockError> {
    if value.len() > MAX_FIELD_LEN {
        return Err(NpmLockError::FieldTooLong {
            field,
            len: value.len(),
        });
    }
    Ok(())
}

/// Reads and parses a `package-lock.json` file from disk with security checks.
///
/// # Errors
///
/// Returns [`NpmLockError`] if the file cannot be read or parsed.
pub fn read_package_lock(path: &Path) -> Result<PackageLock, NpmLockError> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(NpmLockError::SymlinkRejected);
    }
    if !meta.is_file() {
        return Err(NpmLockError::NotRegularFile);
    }
    if meta.len() > MAX_LOCKFILE_BYTES {
        return Err(NpmLockError::FileTooLarge {
            size: meta.len(),
            max: MAX_LOCKFILE_BYTES,
        });
    }
    let data = std::fs::read(path)?;
    parse_package_lock(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const V3_LOCK: &str = r#"{
  "name": "my-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": { "version": "1.0.0" },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-abc123"
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-def456",
      "hasInstallScript": true
    }
  }
}"#;

    const V1_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "dependencies": {
    "express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-abc123"
    }
  }
}"#;

    #[test]
    fn npm_adapter_trait() {
        let adapter = NpmAdapter;
        assert_eq!(adapter.tool(), RegistryTool::Npm);
        assert_eq!(adapter.lockfile_format(), LockfileFormat::PackageLockJson);
        assert_eq!(
            adapter.lifecycle_script_policy(),
            LifecycleScriptPolicy::DeniedByDefault
        );
        let recipe = adapter.recipe();
        assert_eq!(recipe.primary(), InspectionPattern::LockfilePrescan);
        assert!(
            recipe
                .secondary()
                .contains(&InspectionPattern::PostInstallScan)
        );
    }

    #[test]
    fn parse_v3_lockfile() -> TestResult {
        let lock = parse_package_lock(V3_LOCK.as_bytes())?;
        assert_eq!(lock.lockfile_version, 3);
        assert_eq!(lock.packages.len(), 2);
        assert_eq!(lock.packages[0].name, "express");
        assert_eq!(lock.packages[0].version, "4.18.2");
        assert!(
            lock.packages[0]
                .resolved
                .as_ref()
                .is_some_and(|r| r.contains("registry.npmjs.org"))
        );
        assert!(lock.packages[0].integrity.is_some());
        assert!(!lock.packages[0].has_scripts);
        assert_eq!(lock.packages[1].name, "lodash");
        assert!(lock.packages[1].has_scripts);
        Ok(())
    }

    #[test]
    fn parse_v1_lockfile_uses_dependencies() -> TestResult {
        let lock = parse_package_lock(V1_LOCK.as_bytes())?;
        assert_eq!(lock.lockfile_version, 1);
        assert_eq!(lock.packages.len(), 1);
        assert_eq!(lock.packages[0].name, "express");
        Ok(())
    }

    #[test]
    fn parse_empty_lockfile() -> TestResult {
        let lock = parse_package_lock(br#"{"lockfileVersion": 3, "packages": {}}"#)?;
        assert!(lock.packages.is_empty());
        Ok(())
    }

    #[test]
    fn parse_rejects_invalid_version() {
        let result = parse_package_lock(br#"{"lockfileVersion": 99}"#);
        assert!(matches!(result, Err(NpmLockError::InvalidVersion(99))));
    }

    #[test]
    fn parse_invalid_json_errors() {
        let result = parse_package_lock(b"not json");
        assert!(result.is_err());
    }

    #[test]
    fn parse_v3_excludes_root_package() -> TestResult {
        let lock = parse_package_lock(
            br#"{"lockfileVersion": 3, "packages": {"": {"version": "1.0.0"}, "node_modules/foo": {"version": "1.0"}}}"#,
        )?;
        assert_eq!(lock.packages.len(), 1);
        assert_eq!(lock.packages[0].name, "foo");
        Ok(())
    }
}
