//! uv/uvx adapter — Python package manager integration.
//!
//! Implements spec §39.14.1 uv row. uv ships `UV_MALWARE_CHECK=1`
//! (OSV-backed) — Arbitraitor extends, not duplicates. This adapter combines:
//!
//! - **Lockfile pre-scan** (primary): parse `uv.lock` (TOML v1), verify hashes
//! - **Post-install scan** (secondary): scan `.venv` after installation
//! - **Build-script sandbox** (secondary): PEP 517 build isolation

#![forbid(unsafe_code)]

use std::path::Path;

use serde::Deserialize;

use crate::recipe::{
    AdapterRecipe, InspectionPattern, LifecycleScriptPolicy, LockfileFormat, RegistryAdapter,
    RegistryTool,
};

/// uv registry adapter (spec §39.14.1).
#[derive(Clone, Debug)]
pub struct UvAdapter;

impl RegistryAdapter for UvAdapter {
    fn tool(&self) -> RegistryTool {
        RegistryTool::Uv
    }

    fn recipe(&self) -> AdapterRecipe {
        AdapterRecipe::new(
            InspectionPattern::LockfilePrescan,
            vec![
                InspectionPattern::PostInstallScan,
                InspectionPattern::BuildScriptSandbox,
            ],
        )
    }

    fn lockfile_format(&self) -> LockfileFormat {
        LockfileFormat::UvLock
    }

    fn lifecycle_script_policy(&self) -> LifecycleScriptPolicy {
        LifecycleScriptPolicy::SandboxRequired
    }
}

/// A single package entry from `uv.lock`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UvPackage {
    /// Package name (e.g. `"requests"`).
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Source type (registry URL, git, virtual).
    pub source: Option<String>,
    /// SHA-256 hash of the sdist, if present.
    pub sdist_hash: Option<String>,
    /// SHA-256 hashes of wheels, if present.
    pub wheel_hashes: Vec<String>,
}

/// Parsed `uv.lock` contents.
#[derive(Clone, Debug)]
pub struct UvLock {
    /// Lockfile format version.
    pub version: u32,
    /// All package entries.
    pub packages: Vec<UvPackage>,
}

/// Errors produced while parsing `uv.lock`.
#[derive(Debug, thiserror::Error)]
pub enum UvLockError {
    /// The file could not be read.
    #[error("failed to read file: {0}")]
    Io(#[from] std::io::Error),
    /// The TOML could not be parsed.
    #[error("failed to parse TOML: {0}")]
    Parse(#[from] toml::de::Error),
    /// Unsupported lockfile version.
    #[error("unsupported lockfile version: {0}")]
    InvalidVersion(u32),
    /// Too many packages in lockfile (possible `DoS`).
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
    /// Hash format is not `sha256:` followed by 64 hex chars.
    #[error("invalid hash format")]
    InvalidHash,
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

const MAX_LOCKFILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PACKAGES: usize = 100_000;
const MAX_FIELD_LEN: usize = 512;

#[derive(Deserialize)]
struct LockFile {
    version: u32,
    #[serde(default)]
    package: Vec<LockPackage>,
}

#[derive(Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    source: Option<toml::Value>,
    sdist: Option<toml::Value>,
    #[serde(default)]
    wheels: Vec<toml::Value>,
}

/// Parses a `uv.lock` file from its raw text.
///
/// # Errors
///
/// Returns [`UvLockError`] if the file cannot be parsed or fails validation.
pub fn parse_uv_lock(data: &str) -> Result<UvLock, UvLockError> {
    let lock: LockFile = toml::from_str(data)?;
    if lock.version != 1 {
        return Err(UvLockError::InvalidVersion(lock.version));
    }
    if lock.package.len() > MAX_PACKAGES {
        return Err(UvLockError::TooManyPackages(lock.package.len()));
    }
    let packages = lock
        .package
        .into_iter()
        .map(|p| {
            validate_field_len("name", &p.name)?;
            validate_field_len("version", &p.version)?;
            let source = p.source.as_ref().and_then(extract_source_string);
            let sdist_hash = p.sdist.as_ref().and_then(extract_hash);
            let mut wheel_hashes = Vec::new();
            for wheel in &p.wheels {
                if let Some(h) = extract_hash(wheel) {
                    validate_hash(&h)?;
                    wheel_hashes.push(h);
                }
            }
            if let Some(ref h) = sdist_hash {
                validate_hash(h)?;
            }
            Ok::<_, UvLockError>(UvPackage {
                name: p.name,
                version: p.version,
                source,
                sdist_hash,
                wheel_hashes,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(UvLock {
        version: lock.version,
        packages,
    })
}

fn validate_field_len(field: &'static str, value: &str) -> Result<(), UvLockError> {
    if value.len() > MAX_FIELD_LEN {
        return Err(UvLockError::FieldTooLong {
            field,
            len: value.len(),
        });
    }
    Ok(())
}

fn validate_hash(hash: &str) -> Result<(), UvLockError> {
    if let Some(hex) = hash.strip_prefix("sha256:")
        && hex.len() == 64
        && hex.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Ok(());
    }
    Err(UvLockError::InvalidHash)
}

fn extract_source_string(value: &toml::Value) -> Option<String> {
    if let Some(table) = value.as_table() {
        if let Some(registry) = table.get("registry").and_then(|v| v.as_str()) {
            return Some(format!("registry:{registry}"));
        }
        if let Some(git) = table.get("git").and_then(|v| v.as_str()) {
            return Some(format!("git:{git}"));
        }
        if let Some(virtual_) = table.get("virtual").and_then(|v| v.as_str()) {
            return Some(format!("virtual:{virtual_}"));
        }
    }
    None
}

fn extract_hash(value: &toml::Value) -> Option<String> {
    let table = value.as_table()?;
    let hash = table.get("hash")?.as_str()?;
    Some(hash.to_owned())
}

/// Reads and parses a `uv.lock` file from disk with security checks.
///
/// # Errors
///
/// Returns [`UvLockError`] if the file cannot be read or parsed.
pub fn read_uv_lock(path: &Path) -> Result<UvLock, UvLockError> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(UvLockError::SymlinkRejected);
    }
    if !meta.is_file() {
        return Err(UvLockError::NotRegularFile);
    }
    if meta.len() > MAX_LOCKFILE_BYTES {
        return Err(UvLockError::FileTooLarge {
            size: meta.len(),
            max: MAX_LOCKFILE_BYTES,
        });
    }
    let data = std::fs::read_to_string(path)?;
    parse_uv_lock(&data)
}

/// Checks whether a `pyproject.toml` declares a uv workspace.
///
/// Returns `true` if the `[tool.uv.workspace]` table is present.
///
/// # Errors
///
/// Returns [`UvLockError`] if the file cannot be read or parsed.
pub fn is_uv_workspace(pyproject_path: &Path) -> Result<bool, UvLockError> {
    let meta = std::fs::symlink_metadata(pyproject_path)?;
    if meta.file_type().is_symlink() {
        return Err(UvLockError::SymlinkRejected);
    }
    if !meta.is_file() {
        return Err(UvLockError::NotRegularFile);
    }
    if meta.len() > 1024 * 1024 {
        return Err(UvLockError::FileTooLarge {
            size: meta.len(),
            max: 1024 * 1024,
        });
    }
    let data = std::fs::read_to_string(pyproject_path)?;
    let value: toml::Value = toml::from_str(&data)?;
    Ok(value
        .get("tool")
        .and_then(|t| t.get("uv"))
        .and_then(|u| u.get("workspace"))
        .is_some())
}

/// Environment variables that Arbitraitor should set for uv interop.
#[must_use]
pub fn uv_env_vars(cas_dir: &str) -> Vec<(&'static str, String)> {
    vec![
        ("UV_DEFAULT_INDEX", cas_dir.to_owned()),
        ("UV_REQUIRE_HASHES", "1".to_owned()),
        ("UV_MALWARE_CHECK", "1".to_owned()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const V1_LOCK: &str = r#"
version = 1

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/.../requests-2.31.0.tar.gz", hash = "sha256:c8d728e5b7d3c8d728e5b7d3c8d728e5b7d3c8d728e5b7d3c8d728e5b7d3c8d7" }
wheels = [{ url = "https://files.pythonhosted.org/packages/.../requests-2.31.0-py3-none-any.whl", hash = "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2" }]

[[package]]
name = "local-pkg"
version = "0.1.0"
source = { virtual = "." }
"#;

    #[test]
    fn uv_adapter_trait() {
        let adapter = UvAdapter;
        assert_eq!(adapter.tool(), RegistryTool::Uv);
        assert_eq!(adapter.lockfile_format(), LockfileFormat::UvLock);
        assert_eq!(
            adapter.lifecycle_script_policy(),
            LifecycleScriptPolicy::SandboxRequired
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
    fn parse_v1_lockfile() -> TestResult {
        let lock = parse_uv_lock(V1_LOCK)?;
        assert_eq!(lock.version, 1);
        assert_eq!(lock.packages.len(), 2);
        assert_eq!(lock.packages[0].name, "requests");
        assert_eq!(lock.packages[0].version, "2.31.0");
        assert!(
            lock.packages[0]
                .source
                .as_ref()
                .is_some_and(|s| s.contains("pypi.org"))
        );
        assert!(lock.packages[0].sdist_hash.is_some());
        assert_eq!(lock.packages[0].wheel_hashes.len(), 1);
        assert_eq!(lock.packages[1].name, "local-pkg");
        assert!(
            lock.packages[1]
                .source
                .as_ref()
                .is_some_and(|s| s.contains("virtual"))
        );
        Ok(())
    }

    #[test]
    fn parse_empty_lockfile() -> TestResult {
        let lock = parse_uv_lock("version = 1\n")?;
        assert!(lock.packages.is_empty());
        Ok(())
    }

    #[test]
    fn parse_rejects_invalid_version() {
        let result = parse_uv_lock("version = 99\n");
        assert!(matches!(result, Err(UvLockError::InvalidVersion(99))));
    }

    #[test]
    fn parse_rejects_invalid_hash() {
        let lock = "version = 1\n[[package]]\nname = \"x\"\nversion = \"1\"\nsdist = { hash = \"not-sha256\" }\n";
        assert!(matches!(parse_uv_lock(lock), Err(UvLockError::InvalidHash)));
    }

    #[test]
    fn parse_invalid_toml_errors() {
        let result = parse_uv_lock("this is not [[valid toml");
        assert!(result.is_err());
    }

    #[test]
    fn extract_source_from_registry() -> TestResult {
        let value: toml::Value = toml::from_str("registry = \"https://pypi.org/simple\"")?;
        let source = extract_source_string(&value);
        assert!(source.is_some_and(|s| s.contains("pypi.org")));
        Ok(())
    }

    #[test]
    fn extract_source_from_git() -> TestResult {
        let value: toml::Value = toml::from_str("git = \"https://github.com/user/repo\"")?;
        let source = extract_source_string(&value);
        assert!(source.is_some_and(|s| s.contains("github.com")));
        Ok(())
    }

    #[test]
    fn extract_source_from_virtual() -> TestResult {
        let value: toml::Value = toml::from_str("virtual = \".\"")?;
        let source = extract_source_string(&value);
        assert!(source.is_some_and(|s| s == "virtual:."));
        Ok(())
    }

    #[test]
    fn uv_env_vars_sets_interop_flags() {
        let vars = uv_env_vars("/tmp/arbitraitor-cas");
        assert!(
            vars.iter()
                .any(|(k, v)| *k == "UV_DEFAULT_INDEX" && v == "/tmp/arbitraitor-cas")
        );
        assert!(
            vars.iter()
                .any(|(k, v)| *k == "UV_REQUIRE_HASHES" && v == "1")
        );
        assert!(
            vars.iter()
                .any(|(k, v)| *k == "UV_MALWARE_CHECK" && v == "1")
        );
    }

    #[test]
    fn uv_workspace_detection() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("arb-uv-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let pyproject = dir.join("pyproject.toml");
        std::fs::write(
            &pyproject,
            "[tool.uv.workspace]\nmembers = [\"packages/*\"]\n",
        )?;
        assert!(is_uv_workspace(&pyproject)?);
        std::fs::write(&pyproject, "[project]\nname = \"foo\"\nversion = \"0.1\"\n")?;
        assert!(!is_uv_workspace(&pyproject)?);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
