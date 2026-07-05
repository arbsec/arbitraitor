//! On-disk manifest parsing and validation helpers.
//!
//! This module owns the untrusted-boundary TOML schema for plugin manifests
//! (`PluginManifestFile`, `CapabilitySetFile`) and the pure parsers that turn
//! the loose string fields into typed API values. The registry calls
//! [`parse_manifest_file`] to produce a [`ValidatedManifest`], then layers
//! binary checksum verification and admission policy on top.

#![forbid(unsafe_code)]

use std::path::Path;

use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_plugin_api::{
    CapabilitySet, FilesystemCapability, NetworkCapability, PluginType, ProcessCapability,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::registry::RegistryError;

/// On-disk TOML representation of a plugin manifest.
///
/// This is the untrusted boundary format. Fields are parsed as strings and
/// validated before conversion to the typed
/// [`arbitraitor_plugin_api::PluginManifest`].
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManifestFile {
    /// Stable plugin identifier (e.g. `dev.arbitraitor.curl`).
    pub id: String,
    /// Human-readable plugin name.
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Adapter category: `detector`, `wrapper`, `intelligence`, `provenance`, `sandbox`.
    pub plugin_type: String,
    /// Trust tier: `built-in`, `first-party`, `community-reviewed`, `community-unreviewed`.
    pub trust_class: String,
    /// Optional longer description.
    pub description: Option<String>,
    /// Optional author or maintainer.
    pub author: Option<String>,
    /// Optional homepage URL.
    pub homepage: Option<String>,
    /// Optional minimum Arbitraitor version required.
    pub min_arbitraitor_version: Option<String>,
    /// Binary or `.wasm` path relative to the manifest directory.
    pub binary: String,
    /// Expected SHA-256 of the binary, as lowercase hex.
    pub checksum: String,
    /// Capabilities requested by the plugin (ADR-0011). When omitted the
    /// plugin receives [`CapabilitySet::default()`], the most-restrictive set.
    #[serde(default)]
    pub capabilities: CapabilitySetFile,
}

/// On-disk TOML representation of a capability declaration.
///
/// All fields are optional; missing fields resolve to the most-restrictive
/// variant so that a manifest without a `[capabilities]` table is treated as
/// requesting no elevated authority.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetFile {
    /// Requested network access: `none`, `loopback-only`, `outbound-https`, `full`.
    pub network: Option<String>,
    /// Requested filesystem access: `none`, `read-only`, `read-write`.
    pub filesystem: Option<String>,
    /// Requested child-process access: `none`, `spawn`.
    pub process: Option<String>,
    /// Optional maximum memory budget in bytes.
    pub max_memory_bytes: Option<u64>,
    /// Optional maximum CPU budget in milliseconds.
    pub max_cpu_ms: Option<u64>,
}

/// Manifest fields that have passed string-level validation and are ready for
/// binary verification and admission.
#[derive(Clone, Debug)]
pub struct ValidatedManifest {
    /// Plugin id.
    pub id: String,
    /// Plugin version.
    pub version: String,
    /// Parsed adapter type.
    pub plugin_type: PluginType,
    /// Parsed trust tier.
    pub trust_class: arbitraitor_plugin_api::PluginTrustClass,
    /// Parsed capability set.
    pub capabilities: CapabilitySet,
    /// Human-readable description (empty if absent).
    pub description: String,
    /// Expected binary digest.
    pub expected_checksum: Sha256Digest,
    /// Binary path relative to the manifest directory.
    pub binary_rel: std::path::PathBuf,
}

/// Validates the string fields of a manifest file and returns typed values.
///
/// Binary existence and checksum are NOT verified here — the caller verifies
/// those against on-disk bytes after this function returns.
///
/// # Errors
///
/// Returns [`RegistryError::ManifestParse`] for malformed ids, versions,
/// plugin types, trust tiers, capabilities, or checksum shapes, and
/// [`RegistryError::BinaryNotFound`] when the binary path escapes the plugin
/// directory.
pub fn parse_manifest_file(
    file: &PluginManifestFile,
    dir: &Path,
    label: &str,
) -> Result<ValidatedManifest, RegistryError> {
    validate_id(&file.id).map_err(|reason| manifest_parse(label, reason))?;
    validate_semver(&file.version).map_err(|reason| manifest_parse(label, reason))?;

    let plugin_type = parse_plugin_type(&file.plugin_type, label)?;
    let trust_class = parse_trust_class(&file.trust_class, label)?;
    let capabilities = parse_capability_set(&file.capabilities, label)?;

    let binary_rel = validate_binary_path(&file.binary, dir, label)?;
    let expected_checksum = Sha256Digest::from_str(&file.checksum)
        .map_err(|err| manifest_parse(label, format!("invalid checksum: {err}")))?;

    Ok(ValidatedManifest {
        id: file.id.clone(),
        version: file.version.clone(),
        plugin_type,
        trust_class,
        capabilities,
        description: file.description.clone().unwrap_or_default(),
        expected_checksum,
        binary_rel,
    })
}

fn manifest_parse(label: &str, reason: String) -> RegistryError {
    RegistryError::ManifestParse {
        plugin: label.to_owned(),
        error: reason,
    }
}

fn validate_binary_path(
    binary: &str,
    dir: &Path,
    label: &str,
) -> Result<std::path::PathBuf, RegistryError> {
    let binary_rel = Path::new(binary);
    if binary_rel.is_absolute() || binary.starts_with("..") {
        return Err(manifest_parse(
            label,
            format!("binary path must be relative to the plugin directory: {binary}"),
        ));
    }
    let binary_path = dir.join(binary_rel);
    if !binary_path.is_file() {
        return Err(RegistryError::BinaryNotFound {
            plugin: label.to_owned(),
            path: binary_path,
        });
    }
    Ok(binary_rel.to_path_buf())
}

fn parse_capability_set(
    file: &CapabilitySetFile,
    label: &str,
) -> Result<CapabilitySet, RegistryError> {
    let network = file
        .network
        .as_deref()
        .map(|value| parse_network_capability(value, label))
        .transpose()?
        .unwrap_or_default();
    let filesystem = file
        .filesystem
        .as_deref()
        .map(|value| parse_filesystem_capability(value, label))
        .transpose()?
        .unwrap_or_default();
    let process = file
        .process
        .as_deref()
        .map(|value| parse_process_capability(value, label))
        .transpose()?
        .unwrap_or_default();
    Ok(CapabilitySet {
        network,
        filesystem,
        process,
        max_memory_bytes: file.max_memory_bytes,
        max_cpu_ms: file.max_cpu_ms,
    })
}

fn parse_network_capability(value: &str, label: &str) -> Result<NetworkCapability, RegistryError> {
    match value {
        "none" => Ok(NetworkCapability::None),
        "loopback-only" => Ok(NetworkCapability::LoopbackOnly),
        "outbound-https" => Ok(NetworkCapability::OutboundHttps),
        "full" => Ok(NetworkCapability::Full),
        other => Err(manifest_parse(
            label,
            format!(
                "unknown network capability '{other}'; expected one of: \
                 none, loopback-only, outbound-https, full"
            ),
        )),
    }
}

fn parse_filesystem_capability(
    value: &str,
    label: &str,
) -> Result<FilesystemCapability, RegistryError> {
    match value {
        "none" => Ok(FilesystemCapability::None),
        "read-only" => Ok(FilesystemCapability::ReadOnly),
        "read-write" => Ok(FilesystemCapability::ReadWrite),
        other => Err(manifest_parse(
            label,
            format!(
                "unknown filesystem capability '{other}'; expected one of: \
                 none, read-only, read-write"
            ),
        )),
    }
}

fn parse_process_capability(value: &str, label: &str) -> Result<ProcessCapability, RegistryError> {
    match value {
        "none" => Ok(ProcessCapability::None),
        "spawn" => Ok(ProcessCapability::Spawn),
        other => Err(manifest_parse(
            label,
            format!("unknown process capability '{other}'; expected one of: none, spawn"),
        )),
    }
}

/// Validates that `id` is non-empty and matches `[a-z0-9-]+`.
fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("plugin id must not be empty".to_owned());
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("plugin id must match [a-z0-9-]+".to_owned());
    }
    Ok(())
}

/// Basic semver `MAJOR.MINOR.PATCH` validation with optional pre-release and
/// build metadata, sufficient for manifest admission without pulling in a
/// dedicated semver crate.
fn validate_semver(version: &str) -> Result<(), String> {
    let (core, _rest) = match version.split_once('+') {
        Some((core, build)) => {
            if build.is_empty() {
                return Err(format!("version '{version}' has empty build metadata"));
            }
            (core, version)
        }
        None => (version, version),
    };

    let (numbers, pre) = match core.split_once('-') {
        Some((numbers, pre)) => {
            if pre.is_empty() {
                return Err(format!("version '{version}' has empty pre-release"));
            }
            (numbers, Some(pre))
        }
        None => (core, None),
    };

    let parts: Vec<&str> = numbers.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("version '{version}' must follow MAJOR.MINOR.PATCH"));
    }
    for part in parts {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("version '{version}' has non-numeric segment"));
        }
    }

    if let Some(pre_release) = pre
        && !pre_release
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(format!(
            "version '{version}' has invalid pre-release identifier"
        ));
    }

    Ok(())
}

/// Parses the `plugin_type` string into a [`PluginType`].
fn parse_plugin_type(value: &str, label: &str) -> Result<PluginType, RegistryError> {
    match value {
        "detector" => Ok(PluginType::Detector),
        "wrapper" => Ok(PluginType::Wrapper),
        "intelligence" => Ok(PluginType::Intelligence),
        "provenance" => Ok(PluginType::Provenance),
        "sandbox" => Ok(PluginType::Sandbox),
        other => Err(manifest_parse(
            label,
            format!(
                "unknown plugin_type '{other}'; expected one of: \
                 detector, wrapper, intelligence, provenance, sandbox"
            ),
        )),
    }
}

/// Parses the `trust_class` string into a [`arbitraitor_plugin_api::PluginTrustClass`].
fn parse_trust_class(
    value: &str,
    label: &str,
) -> Result<arbitraitor_plugin_api::PluginTrustClass, RegistryError> {
    match value {
        "built-in" => Ok(arbitraitor_plugin_api::PluginTrustClass::BuiltIn),
        "first-party" => Ok(arbitraitor_plugin_api::PluginTrustClass::FirstParty),
        "community-reviewed" => Ok(arbitraitor_plugin_api::PluginTrustClass::CommunityReviewed),
        "community-unreviewed" => Ok(arbitraitor_plugin_api::PluginTrustClass::CommunityUnreviewed),
        other => Err(manifest_parse(
            label,
            format!(
                "unknown trust_class '{other}'; expected one of: \
                 built-in, first-party, community-reviewed, community-unreviewed"
            ),
        )),
    }
}
