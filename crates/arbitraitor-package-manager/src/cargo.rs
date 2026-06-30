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
    #[error("failed to read Cargo.lock: {0}")]
    Io(#[from] std::io::Error),
    /// The TOML could not be parsed.
    #[error("failed to parse Cargo.lock TOML: {0}")]
    Parse(#[from] toml::de::Error),
    /// The `version` field is missing or invalid.
    #[error("Cargo.lock missing or invalid version field")]
    MissingVersion,
}

#[derive(Deserialize)]
struct LockFile {
    #[serde(default = "default_lockfile_version")]
    version: u32,
    #[serde(default)]
    package: Vec<LockPackage>,
}

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
/// is treated as version 1.
///
/// # Errors
///
/// Returns [`CargoLockError`] if the file cannot be read or parsed.
pub fn parse_cargo_lock(data: &str) -> Result<CargoLock, CargoLockError> {
    let lock: LockFile = toml::from_str(data)?;
    let packages = lock
        .package
        .into_iter()
        .map(|p| CargoPackage {
            name: p.name,
            version: p.version,
            source: p.source,
            checksum: p.checksum,
        })
        .collect();
    Ok(CargoLock {
        version: lock.version,
        packages,
    })
}

/// Reads and parses a `Cargo.lock` file from disk.
///
/// # Errors
///
/// Returns [`CargoLockError`] if the file cannot be read or parsed.
pub fn read_cargo_lock(path: &Path) -> Result<CargoLock, CargoLockError> {
    let data = std::fs::read_to_string(path)?;
    parse_cargo_lock(&data)
}

/// Result of static-analysing a `build.rs` file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildScriptAnalysis {
    /// Patterns that execute external commands.
    pub invokes_process: bool,
    /// Patterns that access the filesystem beyond the crate directory.
    pub accesses_filesystem: bool,
    /// Patterns that perform network operations.
    pub accesses_network: bool,
    /// Patterns that read environment variables beyond standard cargo vars.
    pub reads_env_vars: HashSet<String>,
    /// Raw text matches for dangerous patterns.
    pub dangerous_patterns: Vec<String>,
}

/// Statically analyses a `build.rs` source file for dangerous patterns.
///
/// This is a conservative regex-free scan that looks for known dangerous
/// API patterns in Rust source. It does NOT execute or compile the script.
#[must_use]
pub fn analyse_build_script(source: &str) -> BuildScriptAnalysis {
    let mut invokes_process = false;
    let mut accesses_filesystem = false;
    let mut accesses_network = false;
    let mut reads_env_vars = HashSet::new();
    let mut dangerous_patterns = Vec::new();

    for pattern in DANGEROUS_PROCESS_PATTERNS {
        if source.contains(*pattern) {
            invokes_process = true;
            dangerous_patterns.push((*pattern).to_owned());
        }
    }
    for pattern in DANGEROUS_FS_PATTERNS {
        if source.contains(*pattern) {
            accesses_filesystem = true;
            dangerous_patterns.push((*pattern).to_owned());
        }
    }
    for pattern in DANGEROUS_NETWORK_PATTERNS {
        if source.contains(*pattern) {
            accesses_network = true;
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
        invokes_process,
        accesses_filesystem,
        accesses_network,
        reads_env_vars,
        dangerous_patterns,
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
    let data = std::fs::read_to_string(cargo_toml_path)?;
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
checksum = "c8d728e5b7d3"

[[package]]
name = "local-crate"
version = "0.1.0"
"#;

    const V1_LOCK: &str = r#"
[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c8d728e5b7d3"
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
        assert!(analysis.invokes_process);
        assert!(
            analysis
                .dangerous_patterns
                .contains(&"Command::new".to_owned())
        );
        assert!(
            analysis
                .dangerous_patterns
                .contains(&"std::process::Command".to_owned())
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
        assert!(analysis.accesses_filesystem);
    }

    #[test]
    fn build_script_detects_network_access() {
        let src = r#"
            fn main() {
                let resp = reqwest::blocking::get("https://evil.example.com").unwrap();
            }
        "#;
        let analysis = analyse_build_script(src);
        assert!(analysis.accesses_network);
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
    fn build_script_benign_passes_clean() {
        let src = r#"
            fn main() {
                println!("cargo:rerun-if-changed=build.rs");
            }
        "#;
        let analysis = analyse_build_script(src);
        assert!(!analysis.invokes_process);
        assert!(!analysis.accesses_filesystem);
        assert!(!analysis.accesses_network);
        assert!(analysis.dangerous_patterns.is_empty());
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
