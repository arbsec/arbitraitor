//! Cargo adapter — first registry-based package-manager integration.
//!
//! Implements spec §39.14.1 cargo row. Cargo has no first-party proxy support;
//! the binding constraint is `build.rs` executing outside any registry
//! boundaries. This adapter combines:
//!
//! - **Lockfile pre-scan** (primary): parse `Cargo.lock`, verify checksums
//! - **Build-script sandbox** (secondary): static-analyse `build.rs`
//! - **Post-install scan** (secondary): scan the target directory

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;

use crate::recipe::{
    AdapterRecipe, InspectionPattern, LifecycleScriptPolicy, LockfileFormat, RegistryAdapter,
    RegistryTool,
};

/// Cargo registry adapter (spec §39.14.1).
#[derive(Clone, Debug)]
pub struct CargoAdapter;

impl RegistryAdapter for CargoAdapter {
    fn tool(&self) -> RegistryTool {
        RegistryTool::Cargo
    }

    fn recipe(&self) -> AdapterRecipe {
        AdapterRecipe::new(
            InspectionPattern::LockfilePrescan,
            vec![
                InspectionPattern::BuildScriptSandbox,
                InspectionPattern::PostInstallScan,
            ],
        )
    }

    fn lockfile_format(&self) -> LockfileFormat {
        LockfileFormat::CargoLock
    }

    fn lifecycle_script_policy(&self) -> LifecycleScriptPolicy {
        LifecycleScriptPolicy::PolicyApprovedOrIncomplete
    }
}

/// A single package entry from `Cargo.lock`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CargoPackage {
    /// Crate name (e.g. `"serde"`).
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Registry source URL (e.g. `"registry+https://github.com/rust-lang/crates.io-index"`).
    pub source: Option<String>,
    /// SHA-256 checksum from the lockfile, if present (V3+).
    pub checksum: Option<String>,
}

/// Parsed `Cargo.lock` contents.
#[derive(Clone, Debug)]
pub struct CargoLock {
    /// Lockfile format version (1–4).
    pub version: u32,
    /// All package entries.
    pub packages: Vec<CargoPackage>,
}

/// Errors produced while parsing `Cargo.lock`.
#[derive(Debug, thiserror::Error)]
pub enum CargoLockError {
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
    /// Checksum is not 64 lowercase hex chars.
    #[error("invalid checksum format")]
    InvalidChecksum,
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

#[derive(Deserialize)]
struct LockFile {
    #[serde(default = "default_lockfile_version")]
    version: u32,
    #[serde(default)]
    package: Vec<LockPackage>,
}

const MAX_LOCKFILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_PACKAGES: usize = 100_000;
const MAX_FIELD_LEN: usize = 512;

fn default_lockfile_version() -> u32 {
    1
}

#[derive(Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

/// Parses a `Cargo.lock` file from its raw bytes.
///
/// Supports all format versions (V1–V4). V1 lacks the `version` field and
/// is treated as version 1. Validates version range, package count, and
/// field lengths.
///
/// # Errors
///
/// Returns [`CargoLockError`] if the file cannot be parsed or fails validation.
pub fn parse_cargo_lock(data: &str) -> Result<CargoLock, CargoLockError> {
    let lock: LockFile = toml::from_str(data)?;
    if !(1..=4).contains(&lock.version) {
        return Err(CargoLockError::InvalidVersion(lock.version));
    }
    if lock.package.len() > MAX_PACKAGES {
        return Err(CargoLockError::TooManyPackages(lock.package.len()));
    }
    let packages = lock
        .package
        .into_iter()
        .map(|p| {
            validate_field_len("name", &p.name)?;
            validate_field_len("version", &p.version)?;
            if let Some(ref s) = p.source {
                validate_field_len("source", s)?;
            }
            if let Some(ref c) = p.checksum {
                validate_checksum(c)?;
            }
            Ok::<_, CargoLockError>(CargoPackage {
                name: p.name,
                version: p.version,
                source: p.source,
                checksum: p.checksum,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CargoLock {
        version: lock.version,
        packages,
    })
}

fn validate_field_len(field: &'static str, value: &str) -> Result<(), CargoLockError> {
    if value.len() > MAX_FIELD_LEN {
        return Err(CargoLockError::FieldTooLong {
            field,
            len: value.len(),
        });
    }
    Ok(())
}

fn validate_checksum(checksum: &str) -> Result<(), CargoLockError> {
    if checksum.len() != 64 || !checksum.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CargoLockError::InvalidChecksum);
    }
    Ok(())
}

fn check_regular_file(path: &Path, max_bytes: u64) -> Result<std::fs::File, CargoLockError> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(CargoLockError::SymlinkRejected);
    }
    if !meta.is_file() {
        return Err(CargoLockError::NotRegularFile);
    }
    if meta.len() > max_bytes {
        return Err(CargoLockError::FileTooLarge {
            size: meta.len(),
            max: max_bytes,
        });
    }
    Ok(std::fs::File::open(path)?)
}

/// Reads and parses a `Cargo.lock` file from disk.
///
/// Rejects symlinks, non-regular files, and files exceeding 16 MiB.
///
/// # Errors
///
/// Returns [`CargoLockError`] if the file cannot be read or parsed.
pub fn read_cargo_lock(path: &Path) -> Result<CargoLock, CargoLockError> {
    let mut file = check_regular_file(path, MAX_LOCKFILE_BYTES)?;
    let mut data = String::new();
    std::io::Read::read_to_string(&mut file, &mut data)?;
    parse_cargo_lock(&data)
}

/// Categories of dangerous patterns detected in build scripts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DangerCategory {
    /// Patterns that execute external commands.
    ProcessInvocation,
    /// Patterns that access the filesystem.
    FilesystemAccess,
    /// Patterns that perform network operations.
    NetworkAccess,
}

/// Result of static-analysing a `build.rs` file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildScriptAnalysis {
    /// Detected danger categories.
    pub categories: HashSet<DangerCategory>,
    /// Environment variables read beyond standard cargo vars.
    pub reads_env_vars: HashSet<String>,
    /// Raw text matches for dangerous patterns.
    pub dangerous_patterns: Vec<String>,
    /// Pattern scanning is inherently incomplete. This is always `true` —
    /// a `false` value here would be a soundness bug. Downstream code MUST
    /// treat any non-empty build.rs as requiring policy approval.
    pub incomplete_coverage: bool,
}

/// Statically analyses a `build.rs` source file for dangerous patterns.
///
/// This is a conservative regex-free scan that looks for known dangerous
/// API patterns in Rust source. It does NOT execute or compile the script.
#[must_use]
pub fn analyse_build_script(source: &str) -> BuildScriptAnalysis {
    let mut categories = HashSet::new();
    let mut reads_env_vars = HashSet::new();
    let mut dangerous_patterns = Vec::new();

    for pattern in DANGEROUS_PROCESS_PATTERNS {
        if source.contains(*pattern) {
            categories.insert(DangerCategory::ProcessInvocation);
            dangerous_patterns.push((*pattern).to_owned());
        }
    }
    for pattern in DANGEROUS_FS_PATTERNS {
        if source.contains(*pattern) {
            categories.insert(DangerCategory::FilesystemAccess);
            dangerous_patterns.push((*pattern).to_owned());
        }
    }
    for pattern in DANGEROUS_NETWORK_PATTERNS {
        if source.contains(*pattern) {
            categories.insert(DangerCategory::NetworkAccess);
            dangerous_patterns.push((*pattern).to_owned());
        }
    }
    for (marker, var_name) in extract_env_vars(source) {
        reads_env_vars.insert(var_name);
        if !marker.is_empty() {
            dangerous_patterns.push(marker);
        }
    }

    BuildScriptAnalysis {
        categories,
        reads_env_vars,
        dangerous_patterns,
        incomplete_coverage: true,
    }
}

const DANGEROUS_PROCESS_PATTERNS: &[&str] = &[
    "Command::new",
    "std::process::Command",
    "process::Command",
    ".spawn()",
    ".status()",
    ".output()",
    "std::process",
];

const DANGEROUS_FS_PATTERNS: &[&str] = &[
    "std::fs::read",
    "std::fs::write",
    "std::fs::remove",
    "std::fs::create",
    "std::fs::rename",
    "std::fs::copy",
    "fs::read_to_string",
    "fs::write(",
    "File::open",
    "File::create",
    "std::path::Path",
];

const DANGEROUS_NETWORK_PATTERNS: &[&str] = &[
    "reqwest::",
    "ureq::",
    "hyper::",
    "std::net::Tcp",
    "std::net::Udp",
    "TcpStream::connect",
    "UdpSocket::bind",
    "curl::",
    "http::",
    "wget",
    "curl ",
];

fn extract_env_vars(source: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(idx) = trimmed.find("env::var(") {
            let after = &trimmed[idx + "env::var(".len()..];
            if let Some(end) = after.find(')') {
                let raw = after[..end].trim();
                let var_name = raw.trim_matches('"').to_owned();
                results.push((format!("env::var({raw})"), var_name));
            }
        } else if let Some(idx) = trimmed.find("env!(") {
            let after = &trimmed[idx + "env!(".len()..];
            if let Some(end) = after.find(')') {
                let raw = after[..end].trim();
                let var_name = raw.trim_matches('"').to_owned();
                results.push((format!("env!({raw})"), var_name));
            }
        }
    }
    results
}

/// Checks whether a `Cargo.toml` declares a workspace.
///
/// Returns `true` if the `[workspace]` table is present.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn is_workspace_root(cargo_toml_path: &Path) -> Result<bool, CargoLockError> {
    let mut file = check_regular_file(cargo_toml_path, MAX_MANIFEST_BYTES)?;
    let mut data = String::new();
    std::io::Read::read_to_string(&mut file, &mut data)?;
    let value: toml::Value = toml::from_str(&data)?;
    Ok(value.get("workspace").is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4_LOCK: &str = r#"
version = 4

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c8d728e5b7d3c8d728e5b7d3c8d728e5b7d3c8d728e5b7d3c8d728e5b7d3c8d7"

[[package]]
name = "local-crate"
version = "0.1.0"
"#;

    const V1_LOCK: &str = r#"
[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c8d728e5b7d3c8d728e5b7d3c8d728e5b7d3c8d728e5b7d3c8d728e5b7d3c8d7"
"#;

    #[test]
    fn cargo_adapter_trait() {
        let adapter = CargoAdapter;
        assert_eq!(adapter.tool(), RegistryTool::Cargo);
        assert_eq!(adapter.lockfile_format(), LockfileFormat::CargoLock);
        assert_eq!(
            adapter.lifecycle_script_policy(),
            LifecycleScriptPolicy::PolicyApprovedOrIncomplete
        );
        let recipe = adapter.recipe();
        assert_eq!(recipe.primary(), InspectionPattern::LockfilePrescan);
        assert!(
            recipe
                .secondary()
                .contains(&InspectionPattern::BuildScriptSandbox)
        );
    }

    #[test]
    fn parse_v4_lockfile() -> Result<(), CargoLockError> {
        let lock = parse_cargo_lock(V4_LOCK)?;
        assert_eq!(lock.version, 4);
        assert_eq!(lock.packages.len(), 2);
        assert_eq!(lock.packages[0].name, "serde");
        assert_eq!(lock.packages[0].version, "1.0.210");
        assert!(
            lock.packages[0]
                .source
                .as_ref()
                .is_some_and(|s| s.contains("crates.io"))
        );
        assert!(lock.packages[0].checksum.is_some());
        assert_eq!(lock.packages[1].name, "local-crate");
        assert!(lock.packages[1].source.is_none());
        assert!(lock.packages[1].checksum.is_none());
        Ok(())
    }

    #[test]
    fn parse_v1_lockfile_without_version_field() -> Result<(), CargoLockError> {
        let lock = parse_cargo_lock(V1_LOCK)?;
        assert_eq!(lock.version, 1);
        assert_eq!(lock.packages.len(), 1);
        assert_eq!(lock.packages[0].name, "serde");
        Ok(())
    }

    #[test]
    fn parse_empty_lockfile() -> Result<(), CargoLockError> {
        let lock = parse_cargo_lock("version = 4\n")?;
        assert!(lock.packages.is_empty());
        Ok(())
    }

    #[test]
    fn parse_invalid_toml_errors() {
        let result = parse_cargo_lock("this is not [[valid toml");
        assert!(result.is_err());
    }

    #[test]
    fn build_script_detects_command_invocation() {
        let src = r#"
            use std::process::Command;
            fn main() {
                Command::new("cc").arg("-c").status().unwrap();
            }
        "#;
        let analysis = analyse_build_script(src);
        assert!(
            analysis
                .categories
                .contains(&DangerCategory::ProcessInvocation)
        );
        assert!(
            analysis
                .dangerous_patterns
                .contains(&"Command::new".to_owned())
        );
    }

    #[test]
    fn build_script_detects_filesystem_access() {
        let src = r#"
            use std::fs;
            fn main() {
                let data = fs::read_to_string("config.txt").unwrap();
                fs::write("output.h", "generated").unwrap();
            }
        "#;
        let analysis = analyse_build_script(src);
        assert!(
            analysis
                .categories
                .contains(&DangerCategory::FilesystemAccess)
        );
    }

    #[test]
    fn build_script_detects_network_access() {
        let src = r#"
            fn main() {
                let resp = reqwest::blocking::get("https://evil.example.com").unwrap();
            }
        "#;
        let analysis = analyse_build_script(src);
        assert!(analysis.categories.contains(&DangerCategory::NetworkAccess));
    }

    #[test]
    fn build_script_detects_env_vars() {
        let src = r#"
            fn main() {
                let target = env::var("TARGET").unwrap();
                let out = std::env::var("OUT_DIR").unwrap();
                println!("{}", env!("CARGO_PKG_NAME"));
            }
        "#;
        let analysis = analyse_build_script(src);
        assert!(analysis.reads_env_vars.contains("TARGET"));
        assert!(analysis.reads_env_vars.contains("OUT_DIR"));
        assert!(analysis.reads_env_vars.contains("CARGO_PKG_NAME"));
    }

    #[test]
    fn build_script_benign_still_incomplete() {
        let src = r#"
            fn main() {
                println!("cargo:rerun-if-changed=build.rs");
            }
        "#;
        let analysis = analyse_build_script(src);
        assert!(analysis.categories.is_empty());
        assert!(analysis.dangerous_patterns.is_empty());
        assert!(analysis.incomplete_coverage);
    }

    #[test]
    fn parse_rejects_invalid_version() {
        let result = parse_cargo_lock("version = 99\n[[package]]\nname = \"x\"\nversion = \"1\"\n");
        assert!(matches!(result, Err(CargoLockError::InvalidVersion(99))));
    }

    #[test]
    fn parse_rejects_invalid_checksum() {
        let lock = r#"version = 4
[[package]]
name = "bad"
version = "1.0"
checksum = "not-hex"
"#;
        assert!(matches!(
            parse_cargo_lock(lock),
            Err(CargoLockError::InvalidChecksum)
        ));
    }

    #[test]
    fn workspace_detection() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("arb-cargo-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let cargo_toml = dir.join("Cargo.toml");
        std::fs::write(&cargo_toml, "[workspace]\nmembers = [\"crates/*\"]\n")?;
        assert!(is_workspace_root(&cargo_toml)?);
        std::fs::write(
            &cargo_toml,
            "[package]\nname = \"foo\"\nversion = \"0.1\"\n",
        )?;
        assert!(!is_workspace_root(&cargo_toml)?);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
