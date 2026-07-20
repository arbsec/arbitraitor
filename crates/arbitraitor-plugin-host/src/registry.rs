//! Plugin discovery and registry.
//!
//! Scans configured plugin directories for `manifest.toml` files, validates
//! each manifest, verifies the declared binary checksum, and tracks the set of
//! installed plugins. The registry owns metadata only — it never executes
//! plugin code.
//!
//! See `.spec/` §39.19 (Plugin registry) and ADR 0011 for the trust model.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_plugin_api::{PluginManifest, PluginTrustClass, PluginType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::admission::enforce_trust_tier_capabilities;
use crate::manifest::parse_manifest_file;

/// Filename looked for inside each plugin directory.
const MANIFEST_FILENAME: &str = "manifest.toml";

// Re-exported so existing callers that reached these via `registry::` continue
// to resolve now that the types live in the `manifest` submodule.
pub use crate::manifest::{CapabilitySetFile, PluginManifestFile};

/// A plugin that has passed validation and been accepted into the registry.
#[derive(Clone, Debug)]
pub struct RegisteredPlugin {
    /// Typed manifest derived from the on-disk TOML.
    pub manifest: PluginManifest,
    /// Absolute path to the plugin binary or WASM component.
    pub binary_path: PathBuf,
    /// Trust class assigned at registration.
    pub trust_class: PluginTrustClass,
    /// Unix timestamp (seconds) at which the plugin was registered.
    pub installed_at: u64,
    /// Verified SHA-256 of the binary, as lowercase hex.
    pub checksum: String,
}

/// Errors returned by registry operations.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// A configured plugin directory does not exist.
    #[error("plugin directory not found: {0}")]
    DirNotFound(PathBuf),
    /// The manifest could not be parsed or violated a structural rule.
    #[error("plugin manifest parse error for {plugin}: {error}")]
    ManifestParse {
        /// Plugin id or directory path label.
        plugin: String,
        /// Safe diagnostic reason.
        error: String,
    },
    /// The declared binary path does not exist on disk.
    #[error("plugin binary not found for {plugin}: {path}")]
    BinaryNotFound {
        /// Plugin id.
        plugin: String,
        /// Missing binary path.
        path: PathBuf,
    },
    /// A plugin with the same id is already registered.
    #[error("duplicate plugin id: {0}")]
    DuplicatePlugin(String),
    /// The on-disk binary digest did not match the manifest checksum.
    #[error("checksum mismatch for {plugin}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        /// Plugin id.
        plugin: String,
        /// Expected digest from the manifest.
        expected: String,
        /// Actual digest computed from the binary.
        actual: String,
    },
    /// The plugin's declared capabilities are denied by its trust tier
    /// (ADR-0011).
    #[error("plugin {plugin} denied admission: {reason}")]
    CapabilityDeniedByTrustTier {
        /// Plugin id.
        plugin: String,
        /// Safe diagnostic reason from the admission policy.
        reason: String,
    },
    /// No plugin is registered with the requested id.
    #[error("plugin not found: {0}")]
    NotFound(String),
    /// Reading a file or directory failed.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
}

/// Discovers and manages installed plugins.
pub struct PluginRegistry {
    plugin_dirs: Vec<PathBuf>,
    plugins: HashMap<String, RegisteredPlugin>,
}

impl PluginRegistry {
    /// Creates a new registry backed by the given plugin directories.
    ///
    /// Directories are recorded but not scanned; call [`discover`](Self::discover)
    /// to populate the registry.
    #[must_use]
    pub fn new(plugin_dirs: Vec<PathBuf>) -> Self {
        Self {
            plugin_dirs,
            plugins: HashMap::new(),
        }
    }

    /// Scans all configured plugin directories and registers every valid plugin
    /// found.
    ///
    /// Each immediate sub-directory must contain a `manifest.toml`. Directories
    /// without a manifest are silently skipped. Registration of a plugin whose
    /// id duplicates an already-registered plugin returns an error and stops
    /// further discovery.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] when a plugin directory does not exist, or when
    /// a manifest is malformed, its binary is missing, or its checksum does not
    /// verify.
    pub fn discover(&mut self) -> Result<usize, RegistryError> {
        let mut count = 0;
        for plugin_dir in &self.plugin_dirs.clone() {
            if !plugin_dir.is_dir() {
                return Err(RegistryError::DirNotFound(plugin_dir.clone()));
            }
            for entry in fs::read_dir(plugin_dir)? {
                let entry = entry?;
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                if path.join(MANIFEST_FILENAME).is_file() {
                    self.register(&path)?;
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Validates and registers a single plugin from its directory.
    ///
    /// The directory must contain a `manifest.toml` and the binary referenced
    /// therein. The binary's SHA-256 is verified against the manifest checksum,
    /// and ADR-0011 trust-tier capability admission is enforced.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] on a missing manifest, malformed fields,
    /// missing binary, checksum mismatch, trust-tier denial, or duplicate id.
    pub fn register(&mut self, dir: &Path) -> Result<(), RegistryError> {
        let manifest_path = dir.join(MANIFEST_FILENAME);
        let label = dir.display().to_string();

        let toml_text =
            fs::read_to_string(&manifest_path).map_err(|err| RegistryError::ManifestParse {
                plugin: label.clone(),
                error: format!("unable to read manifest.toml: {err}"),
            })?;

        let file: PluginManifestFile =
            toml::from_str(&toml_text).map_err(|err| RegistryError::ManifestParse {
                plugin: label.clone(),
                error: err.to_string(),
            })?;

        let validated = parse_manifest_file(&file, dir, &label)?;
        let binary_path = dir.join(&validated.binary_rel);
        let actual = hash_file(&binary_path)?;
        if actual != validated.expected_checksum {
            return Err(RegistryError::ChecksumMismatch {
                plugin: label.clone(),
                expected: validated.expected_checksum.to_string(),
                actual: actual.to_string(),
            });
        }

        enforce_trust_tier_capabilities(validated.trust_class, &validated.capabilities).map_err(
            |err| RegistryError::CapabilityDeniedByTrustTier {
                plugin: validated.id.clone(),
                reason: err.to_string(),
            },
        )?;

        let manifest = PluginManifest {
            identity: arbitraitor_plugin_api::PluginIdentity {
                id: validated.id,
                version: validated.version,
                trust_class: validated.trust_class,
            },
            capabilities: validated.capabilities,
            plugin_type: validated.plugin_type,
            description: validated.description,
        };
        let registered = RegisteredPlugin {
            manifest,
            binary_path,
            trust_class: validated.trust_class,
            installed_at: now_unix(),
            checksum: actual.to_string(),
        };

        if self.plugins.contains_key(&registered.manifest.identity.id) {
            return Err(RegistryError::DuplicatePlugin(
                registered.manifest.identity.id,
            ));
        }

        self.plugins
            .insert(registered.manifest.identity.id.clone(), registered);
        Ok(())
    }

    /// Returns all registered plugins, in arbitrary order.
    #[must_use]
    pub fn list(&self) -> Vec<&RegisteredPlugin> {
        self.plugins.values().collect()
    }

    /// Returns plugins matching the given adapter type.
    #[must_use]
    pub fn by_type(&self, plugin_type: PluginType) -> Vec<&RegisteredPlugin> {
        self.plugins
            .values()
            .filter(|plugin| plugin.manifest.plugin_type == plugin_type)
            .collect()
    }

    /// Looks up a plugin by its id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&RegisteredPlugin> {
        self.plugins.get(id)
    }

    /// Validates a wrapper-produced [`OperationPlan`] against the capabilities
    /// declared by the registered plugin with the given id.
    ///
    /// This is the production caller for
    /// [`OperationPlan::validate_for_plugin_capabilities`]: it ties a plan's
    /// requested capabilities to the manifest declaration captured at
    /// admission, so a wrapper cannot request authority it never declared.
    ///
    /// # Errors
    ///
    /// Returns [`arbitraitor_plugin_api::PlanError`] when the plan is
    /// malformed, exceeds the plugin's declared capabilities, or `plugin_id`
    /// is not registered (reported as `CapabilityExceedsDeclaration` because
    /// the plan cannot be reconciled against any declaration).
    pub fn validate_plan(
        &self,
        plugin_id: &str,
        plan: &arbitraitor_plugin_api::OperationPlan,
    ) -> Result<(), arbitraitor_plugin_api::PlanError> {
        let plugin = self
            .plugins
            .get(plugin_id)
            .ok_or(arbitraitor_plugin_api::PlanError::CapabilityExceedsDeclaration)?;
        plan.validate_for_plugin_capabilities(&plugin.manifest.capabilities)
    }

    /// Removes a plugin from the registry, returning the removed entry.
    ///
    /// This does **not** delete any files on disk.
    pub fn unregister(&mut self, id: &str) -> Option<RegisteredPlugin> {
        self.plugins.remove(id)
    }

    /// Returns the default plugin search directories.
    ///
    /// Currently this is `~/.arbitraitor/plugins`. If the home directory cannot
    /// be determined the list is empty.
    #[must_use]
    pub fn default_dirs() -> Vec<PathBuf> {
        home_arbitraitor_dir()
            .map(|dir| dir.join("plugins"))
            .into_iter()
            .collect()
    }
}

/// Computes the SHA-256 of a file's contents.
fn hash_file(path: &Path) -> Result<Sha256Digest, RegistryError> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(Sha256Digest::new(bytes))
}

/// Returns the current Unix timestamp in seconds, or `0` if the clock is before
/// the epoch.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Resolves the `~/.arbitraitor` directory using platform environment
/// variables.
fn home_arbitraitor_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".arbitraitor"))
    }
    #[cfg(not(unix))]
    {
        std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .map(|home| home.join(".arbitraitor"))
    }
}

/// Schema version for [`RegistryMetadata`] and the surrounding registry
/// document types.
///
/// Bump on any non-backwards-compatible change to the wire format. Deserializers
/// MUST reject unknown schema versions — see [`RegistryMetadata::SCHEMA_VERSION`].
pub const REGISTRY_METADATA_SCHEMA_VERSION: u32 = 1;

/// Outcome of verifying the publisher's signature over the release metadata
/// (spec §39.20).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// Metadata is covered by a valid publisher signature.
    Signed,
    /// No signature was provided for this release.
    Unsigned,
    /// A signature was present but did not verify against the publisher key.
    Invalid,
}

/// Outcome of verifying a provenance attestation against the release artifact
/// (spec §39.20).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceStatus {
    /// SLSA / Sigstore / minisign attestation verified against the artifact.
    Verified,
    /// An attestation was provided but verification failed.
    Failed,
    /// No provenance attestation was supplied with the release.
    Missing,
}

/// Result of an external security audit of the release (spec §39.20).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityAuditStatus {
    /// No audit has been recorded for this release.
    NotAudited,
    /// An audit was performed and found no blocking findings.
    Audited,
    /// An audit was performed and recorded one or more blocking findings.
    Failed,
}

/// Result of conformance testing against the supported plugin API version
/// (spec §39.20).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceStatus {
    /// Release passes the conformance suite for the declared API version.
    Conformant,
    /// Release does not pass conformance — do not load.
    NonConformant,
    /// Conformance testing is queued or in progress.
    Pending,
}

/// Lifecycle state of a release (spec §39.20).
///
/// `Active` releases are eligible for installation. `Revoked` releases MUST be
/// rejected by the registry loader regardless of any other field.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    /// Release is currently usable.
    Active,
    /// Release has been revoked by the publisher or operator.
    Revoked,
}

/// Rollout plan for a staged release (spec §39.20).
///
/// `percentage` is the fraction of eligible hosts that should receive the
/// release (0–100 inclusive). `target_audience` names the cohort that should
/// receive the release first (e.g. `"canary"`, `"dogfood"`, `"beta"`,
/// `"all"`). Hosts not in `target_audience` defer the update until the
/// rollout reaches their cohort.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedRollout {
    /// Rollout percentage in the inclusive range `0..=100`.
    pub percentage: u8,
    /// Free-form cohort label identifying the first recipients.
    pub target_audience: String,
}

impl StagedRollout {
    /// Construct a rollout covering `percentage` of the named audience.
    ///
    /// # Panics
    ///
    /// Panics if `percentage > 100`. Callers in production code MUST validate
    /// the value before constructing.
    #[must_use]
    pub fn new(percentage: u8, target_audience: impl Into<String>) -> Self {
        assert!(
            percentage <= 100,
            "staged rollout percentage must be in 0..=100, got {percentage}"
        );
        Self {
            percentage,
            target_audience: target_audience.into(),
        }
    }
}

/// State of a permission-diff review between the currently-installed release
/// and the proposed update (spec §39.20).
///
/// The registry loader MUST refuse to install an update while the diff is
/// `PendingApproval` and MUST refuse to install updates whose diff is
/// `Blocked`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDiffStatus {
    /// The operator has approved the permission changes.
    Approved,
    /// The operator has blocked the permission changes — release must not
    /// proceed.
    Blocked,
    /// Permission changes await operator review.
    PendingApproval,
}

/// Recorded publisher or operator revocation of a plugin release (spec §39.20).
///
/// Multiple revocations may exist for the same `(plugin_id, version)` pair —
/// the most recent entry by `revoked_at` is authoritative.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEntry {
    /// Plugin id whose release is being revoked.
    pub plugin_id: String,
    /// Version string of the release being revoked.
    pub version: String,
    /// Identifier of the publisher or operator who issued the revocation.
    pub issuer: String,
    /// Unix timestamp (seconds) at which the revocation was recorded.
    pub revoked_at: u64,
    /// Human-readable, non-secret reason for the revocation.
    pub reason: String,
}

/// Signed metadata describing a published plugin release (spec §39.20).
///
/// This is the artifact the registry loader evaluates to decide whether an
/// update is admissible: signature and provenance must verify, revocation
/// must not be set, the staged rollout must apply to the current host, and
/// the permission diff must be approved by an operator. All fields are
/// carried verbatim from the registry response — the registry does not
/// interpret them, only routes them to the admission pipeline.
///
/// The struct is `Serialize + Deserialize` so it can be embedded in receipts
/// and audit logs. The `schema_version` field lets downstream consumers
/// reject documents produced by a newer or older registry than they
/// understand.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryMetadata {
    /// Schema version of this document. Bumped on any non-backwards-compatible
    /// change to the wire format.
    pub schema_version: u32,
    /// Plugin id this metadata describes.
    pub plugin_id: String,
    /// Version string this metadata describes.
    pub version: String,
    /// Identity of the publisher who signed this release (key id, account
    /// id, or other stable label).
    pub publisher_identity: String,
    /// All release versions previously published for this plugin id, in
    /// ascending order (oldest first). Used for rollback / downgrade checks.
    pub version_history: Vec<String>,
    /// Platform triples this release is built for (e.g.
    /// `x86_64-unknown-linux-gnu`). An empty list means the release applies
    /// to no supported platform and must be rejected.
    pub supported_platforms: Vec<String>,
    /// Capabilities the release declares it requires. Compared against the
    /// currently installed release to compute the permission diff that an
    /// operator must approve.
    pub requested_permissions: Vec<String>,
    /// Outcome of signature verification over the release metadata.
    pub signature_status: SignatureStatus,
    /// Outcome of provenance attestation verification.
    pub provenance_status: ProvenanceStatus,
    /// Result of the most recent external security audit.
    pub security_audit_status: SecurityAuditStatus,
    /// Result of API conformance testing.
    pub conformance_status: ConformanceStatus,
    /// Advisory identifiers for known vulnerabilities affecting this
    /// release. An empty list means no advisories are recorded.
    pub known_vulnerabilities: Vec<String>,
    /// Revocation status for this release.
    pub revocation_status: RevocationStatus,
    /// SHA-256 (lowercase hex) of the artifact associated with this metadata.
    /// Tying the metadata to a digest prevents metadata-swap attacks where
    /// valid metadata is replayed against a different artifact.
    pub download_digest: String,
}

impl RegistryMetadata {
    /// Current schema version stamped onto newly constructed metadata.
    pub const SCHEMA_VERSION: u32 = REGISTRY_METADATA_SCHEMA_VERSION;

    /// Construct a metadata document stamped with the current schema version
    /// and `RevocationStatus::Active`.
    #[must_use]
    pub fn new(
        plugin_id: impl Into<String>,
        version: impl Into<String>,
        publisher_identity: impl Into<String>,
        download_digest: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            plugin_id: plugin_id.into(),
            version: version.into(),
            publisher_identity: publisher_identity.into(),
            version_history: Vec::new(),
            supported_platforms: Vec::new(),
            requested_permissions: Vec::new(),
            signature_status: SignatureStatus::Unsigned,
            provenance_status: ProvenanceStatus::Missing,
            security_audit_status: SecurityAuditStatus::NotAudited,
            conformance_status: ConformanceStatus::Pending,
            known_vulnerabilities: Vec::new(),
            revocation_status: RevocationStatus::Active,
            download_digest: download_digest.into(),
        }
    }

    /// Returns `true` iff the release is admissible purely from its
    /// verification fields. This is a convenience predicate — the loader
    /// applies the full admission policy, including permission-diff and
    /// staged-rollout checks.
    #[must_use]
    pub fn is_verification_clean(&self) -> bool {
        matches!(self.signature_status, SignatureStatus::Signed)
            && matches!(self.provenance_status, ProvenanceStatus::Verified)
            && matches!(
                self.security_audit_status,
                SecurityAuditStatus::Audited | SecurityAuditStatus::NotAudited
            )
            && matches!(self.conformance_status, ConformanceStatus::Conformant)
            && matches!(self.revocation_status, RevocationStatus::Active)
            && self.known_vulnerabilities.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct PluginFixture {
        _root: TempDir,
        plugin_dir: PathBuf,
    }

    impl PluginFixture {
        fn new(
            id: &str,
            plugin_type: &str,
            trust_class: &str,
            binary_contents: &[u8],
        ) -> Result<(Self, String), Box<dyn std::error::Error>> {
            let root = TempDir::new()?;
            let plugin_dir = root.path().join(id);
            fs::create_dir_all(&plugin_dir)?;
            let binary_name = "plugin.bin";
            fs::write(plugin_dir.join(binary_name), binary_contents)?;
            let checksum = sha256_hex(binary_contents);
            let manifest = format!(
                "id = \"{id}\"\n\
                 name = \"Test Plugin\"\n\
                 version = \"0.1.0\"\n\
                 plugin_type = \"{plugin_type}\"\n\
                 trust_class = \"{trust_class}\"\n\
                 description = \"test\"\n\
                 binary = \"{binary_name}\"\n\
                 checksum = \"{checksum}\"\n"
            );
            fs::write(plugin_dir.join(MANIFEST_FILENAME), manifest)?;
            Ok((
                Self {
                    _root: root,
                    plugin_dir,
                },
                checksum,
            ))
        }

        fn with_checksum(id: &str, checksum: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let root = TempDir::new()?;
            let plugin_dir = root.path().join(id);
            fs::create_dir_all(&plugin_dir)?;
            fs::write(plugin_dir.join("plugin.bin"), b"binary")?;
            let manifest = format!(
                "id = \"{id}\"\n\
                 name = \"Test\"\n\
                 version = \"0.1.0\"\n\
                 plugin_type = \"detector\"\n\
                 trust_class = \"community-reviewed\"\n\
                 binary = \"plugin.bin\"\n\
                 checksum = \"{checksum}\"\n"
            );
            fs::write(plugin_dir.join(MANIFEST_FILENAME), manifest)?;
            Ok(Self {
                _root: root,
                plugin_dir,
            })
        }

        /// Builds a fixture whose manifest declares a `[capabilities]` table
        /// matching `caps`. Used to exercise trust-tier admission.
        fn with_capabilities(
            id: &str,
            plugin_type: &str,
            trust_class: &str,
            caps: &str,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let root = TempDir::new()?;
            let plugin_dir = root.path().join(id);
            fs::create_dir_all(&plugin_dir)?;
            let binary_contents = b"caps-binary";
            fs::write(plugin_dir.join("plugin.bin"), binary_contents)?;
            let checksum = sha256_hex(binary_contents);
            let manifest = format!(
                "id = \"{id}\"\n\
                 name = \"Caps Plugin\"\n\
                 version = \"0.1.0\"\n\
                 plugin_type = \"{plugin_type}\"\n\
                 trust_class = \"{trust_class}\"\n\
                 description = \"declares capabilities\"\n\
                 binary = \"plugin.bin\"\n\
                 checksum = \"{checksum}\"\n\
                 {caps}\n"
            );
            fs::write(plugin_dir.join(MANIFEST_FILENAME), manifest)?;
            Ok(Self {
                _root: root,
                plugin_dir,
            })
        }

        fn root_path(&self) -> &Path {
            self.plugin_dir.parent().unwrap_or(Path::new("."))
        }

        fn path(&self) -> &Path {
            &self.plugin_dir
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut out = String::with_capacity(64);
        for byte in &digest {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    fn write_plugin(
        root: &TempDir,
        id: &str,
        plugin_type: &str,
        bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let plugin_dir = root.path().join(id);
        fs::create_dir_all(&plugin_dir)?;
        fs::write(plugin_dir.join("plugin.bin"), bytes)?;
        let checksum = sha256_hex(bytes);
        let manifest = format!(
            "id = \"{id}\"\n\
             name = \"Test\"\n\
             version = \"0.1.0\"\n\
             plugin_type = \"{plugin_type}\"\n\
             trust_class = \"community-reviewed\"\n\
             binary = \"plugin.bin\"\n\
             checksum = \"{checksum}\"\n"
        );
        fs::write(plugin_dir.join(MANIFEST_FILENAME), manifest)?;
        Ok(())
    }

    #[test]
    fn discover_finds_manifest_toml() -> TestResult {
        let (fixture, _checksum) =
            PluginFixture::new("clamav-scanner", "detector", "community-reviewed", b"scan")?;
        let mut registry = PluginRegistry::new(vec![fixture.root_path().to_path_buf()]);

        let count = registry.discover()?;

        assert_eq!(count, 1);
        assert!(registry.get("clamav-scanner").is_some());
        Ok(())
    }

    #[test]
    fn discover_skips_dirs_without_manifest() -> TestResult {
        let root = TempDir::new()?;
        fs::create_dir_all(root.path().join("not-a-plugin"))?;

        let mut registry = PluginRegistry::new(vec![root.path().to_path_buf()]);

        let count = registry.discover()?;

        assert_eq!(count, 0);
        assert!(registry.list().is_empty());
        Ok(())
    }

    #[test]
    fn register_validates_checksum() -> TestResult {
        // 64 zeros is a valid hex SHA-256 shape but cannot match any non-empty file.
        let wrong = "0".repeat(64);
        let fixture = PluginFixture::with_checksum("bad-checksum", &wrong)?;
        let mut registry = PluginRegistry::new(vec![]);

        let result = registry.register(fixture.path());

        assert!(
            matches!(result, Err(RegistryError::ChecksumMismatch { .. })),
            "expected ChecksumMismatch, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn register_rejects_duplicate_id() -> TestResult {
        let (fixture, _checksum) =
            PluginFixture::new("dup-plugin", "detector", "community-reviewed", b"a")?;
        let mut registry = PluginRegistry::new(vec![]);
        registry.register(fixture.path())?;

        let result = registry.register(fixture.path());

        assert!(
            matches!(result, Err(RegistryError::DuplicatePlugin(ref id)) if id == "dup-plugin"),
            "expected DuplicatePlugin, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn list_returns_all() -> TestResult {
        let root = TempDir::new()?;
        write_plugin(&root, "alpha", "detector", b"a")?;
        write_plugin(&root, "beta", "wrapper", b"b")?;

        let mut registry = PluginRegistry::new(vec![root.path().to_path_buf()]);
        registry.discover()?;

        let ids: Vec<&str> = registry
            .list()
            .iter()
            .map(|p| p.manifest.identity.id.as_str())
            .collect();

        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"alpha"));
        assert!(ids.contains(&"beta"));
        Ok(())
    }

    #[test]
    fn by_type_filters_correctly() -> TestResult {
        let root = TempDir::new()?;
        write_plugin(&root, "det-1", "detector", b"a")?;
        write_plugin(&root, "det-2", "detector", b"b")?;
        write_plugin(&root, "wrap-1", "wrapper", b"c")?;

        let mut registry = PluginRegistry::new(vec![root.path().to_path_buf()]);
        registry.discover()?;

        let detectors = registry.by_type(PluginType::Detector);
        let wrappers = registry.by_type(PluginType::Wrapper);
        let intel = registry.by_type(PluginType::Intelligence);

        assert_eq!(detectors.len(), 2);
        assert_eq!(wrappers.len(), 1);
        assert_eq!(intel.len(), 0);
        Ok(())
    }

    #[test]
    fn get_returns_by_id() -> TestResult {
        let (fixture, _checksum) =
            PluginFixture::new("find-me", "detector", "community-reviewed", b"x")?;
        let mut registry = PluginRegistry::new(vec![]);
        registry.register(fixture.path())?;

        let plugin = registry.get("find-me").ok_or("plugin not found")?;

        assert_eq!(plugin.manifest.identity.id, "find-me");
        assert_eq!(plugin.manifest.plugin_type, PluginType::Detector);
        Ok(())
    }

    #[test]
    fn unregister_removes_plugin() -> TestResult {
        let (fixture, _checksum) =
            PluginFixture::new("removable", "detector", "community-reviewed", b"x")?;
        let mut registry = PluginRegistry::new(vec![]);
        registry.register(fixture.path())?;
        assert!(registry.get("removable").is_some());

        let removed = registry.unregister("removable");

        assert!(removed.is_some());
        assert!(registry.get("removable").is_none());
        assert!(registry.list().is_empty());
        Ok(())
    }

    #[test]
    fn manifest_validation_rejects_empty_id() -> TestResult {
        let root = TempDir::new()?;
        let plugin_dir = root.path().join("empty-id");
        fs::create_dir_all(&plugin_dir)?;
        fs::write(plugin_dir.join("plugin.bin"), b"x")?;
        let checksum = sha256_hex(b"x");
        let manifest = format!(
            "id = \"\"\n\
             name = \"Bad\"\n\
             version = \"0.1.0\"\n\
             plugin_type = \"detector\"\n\
             trust_class = \"community-reviewed\"\n\
             binary = \"plugin.bin\"\n\
             checksum = \"{checksum}\"\n"
        );
        fs::write(plugin_dir.join(MANIFEST_FILENAME), manifest)?;

        let mut registry = PluginRegistry::new(vec![]);
        let result = registry.register(&plugin_dir);

        assert!(
            matches!(result, Err(RegistryError::ManifestParse { .. })),
            "expected ManifestParse, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn manifest_validation_requires_binary() -> TestResult {
        let root = TempDir::new()?;
        let plugin_dir = root.path().join("no-binary");
        fs::create_dir_all(&plugin_dir)?;
        let manifest = format!(
            "id = \"no-binary\"\n\
             name = \"NoBin\"\n\
             version = \"0.1.0\"\n\
             plugin_type = \"detector\"\n\
             trust_class = \"community-reviewed\"\n\
             binary = \"missing.bin\"\n\
             checksum = \"{}\"\n",
            "0".repeat(64)
        );
        fs::write(plugin_dir.join(MANIFEST_FILENAME), manifest)?;

        let mut registry = PluginRegistry::new(vec![]);
        let result = registry.register(&plugin_dir);

        assert!(
            matches!(result, Err(RegistryError::BinaryNotFound { .. })),
            "expected BinaryNotFound, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn default_dirs_includes_user_home() {
        let dirs = PluginRegistry::default_dirs();

        #[cfg(unix)]
        {
            if let Some(home) = std::env::var_os("HOME") {
                let expected = PathBuf::from(home).join(".arbitraitor").join("plugins");
                assert!(
                    dirs.contains(&expected),
                    "expected {expected:?} in {dirs:?}"
                );
            }
        }
        let _ = dirs;
    }

    const NET_HTTPS_TABLE: &str = "[capabilities]\nnetwork = \"outbound-https\"";
    const PROCESS_SPAWN_TABLE: &str = "[capabilities]\nprocess = \"spawn\"";
    const FS_READWRITE_TABLE: &str = "[capabilities]\nfilesystem = \"read-write\"";
    const FS_READONLY_TABLE: &str = "[capabilities]\nfilesystem = \"read-only\"";

    #[test]
    fn register_rejects_community_plugin_requesting_network() -> TestResult {
        let fixture = PluginFixture::with_capabilities(
            "community-net",
            "wrapper",
            "community-reviewed",
            NET_HTTPS_TABLE,
        )?;
        let mut registry = PluginRegistry::new(vec![]);

        let result = registry.register(fixture.path());

        assert!(
            matches!(
                result,
                Err(RegistryError::CapabilityDeniedByTrustTier { .. })
            ),
            "community plugin must not be admitted with network capability; got {result:?}"
        );
        assert!(registry.get("community-net").is_none());
        Ok(())
    }

    #[test]
    fn register_rejects_community_unreviewed_plugin_requesting_network() -> TestResult {
        let fixture = PluginFixture::with_capabilities(
            "unreviewed-net",
            "wrapper",
            "community-unreviewed",
            NET_HTTPS_TABLE,
        )?;
        let mut registry = PluginRegistry::new(vec![]);

        let result = registry.register(fixture.path());

        assert!(
            matches!(
                result,
                Err(RegistryError::CapabilityDeniedByTrustTier { .. })
            ),
            "community-unreviewed plugin must not be admitted with network capability; got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn register_rejects_community_plugin_requesting_process_spawn() -> TestResult {
        let fixture = PluginFixture::with_capabilities(
            "community-proc",
            "sandbox",
            "community-reviewed",
            PROCESS_SPAWN_TABLE,
        )?;
        let mut registry = PluginRegistry::new(vec![]);

        let result = registry.register(fixture.path());

        assert!(
            matches!(
                result,
                Err(RegistryError::CapabilityDeniedByTrustTier { .. })
            ),
            "community plugin must not be admitted with process spawn; got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn register_rejects_community_plugin_requesting_filesystem_read_write() -> TestResult {
        let fixture = PluginFixture::with_capabilities(
            "community-rw",
            "detector",
            "community-reviewed",
            FS_READWRITE_TABLE,
        )?;
        let mut registry = PluginRegistry::new(vec![]);

        let result = registry.register(fixture.path());

        assert!(
            matches!(
                result,
                Err(RegistryError::CapabilityDeniedByTrustTier { .. })
            ),
            "community plugin must not be admitted with read-write filesystem; got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn register_admits_first_party_wrapper_requesting_network() -> TestResult {
        let fixture = PluginFixture::with_capabilities(
            "first-party-curl",
            "wrapper",
            "first-party",
            NET_HTTPS_TABLE,
        )?;
        let mut registry = PluginRegistry::new(vec![]);

        registry.register(fixture.path())?;

        let plugin = registry
            .get("first-party-curl")
            .ok_or("first-party wrapper should be admitted")?;
        assert_eq!(
            plugin.manifest.capabilities.network,
            arbitraitor_plugin_api::NetworkCapability::OutboundHttps
        );
        Ok(())
    }

    #[test]
    fn register_admits_builtin_plugin_requesting_full_network() -> TestResult {
        let full_net = "[capabilities]\nnetwork = \"full\"";
        let fixture =
            PluginFixture::with_capabilities("builtin-adapter", "wrapper", "built-in", full_net)?;
        let mut registry = PluginRegistry::new(vec![]);

        registry.register(fixture.path())?;

        let plugin = registry
            .get("builtin-adapter")
            .ok_or("built-in plugin should be admitted")?;
        assert_eq!(
            plugin.manifest.capabilities.network,
            arbitraitor_plugin_api::NetworkCapability::Full
        );
        Ok(())
    }

    #[test]
    fn register_admits_community_plugin_with_no_capabilities() -> TestResult {
        let (fixture, _checksum) =
            PluginFixture::new("bare-detector", "detector", "community-reviewed", b"x")?;
        let mut registry = PluginRegistry::new(vec![]);

        registry.register(fixture.path())?;

        let plugin = registry
            .get("bare-detector")
            .ok_or("bare community detector should be admitted")?;
        assert_eq!(
            plugin.manifest.capabilities,
            arbitraitor_plugin_api::CapabilitySet::default()
        );
        Ok(())
    }

    #[test]
    fn register_admits_community_plugin_requesting_read_only_filesystem() -> TestResult {
        let fixture = PluginFixture::with_capabilities(
            "community-ro",
            "detector",
            "community-reviewed",
            FS_READONLY_TABLE,
        )?;
        let mut registry = PluginRegistry::new(vec![]);

        registry.register(fixture.path())?;

        let plugin = registry
            .get("community-ro")
            .ok_or("community plugin with read-only fs should be admitted")?;
        assert_eq!(
            plugin.manifest.capabilities.filesystem,
            arbitraitor_plugin_api::FilesystemCapability::ReadOnly
        );
        Ok(())
    }

    #[test]
    fn register_rejects_unknown_capability_value() -> TestResult {
        let bad = "[capabilities]\nnetwork = \"telepathy\"";
        let fixture = PluginFixture::with_capabilities("bad-cap", "detector", "first-party", bad)?;
        let mut registry = PluginRegistry::new(vec![]);

        let result = registry.register(fixture.path());

        assert!(
            matches!(result, Err(RegistryError::ManifestParse { .. })),
            "unknown capability value must be a manifest parse error; got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn validate_plan_rejects_plan_exceeding_declared_capabilities() -> TestResult {
        use arbitraitor_plugin_api::{
            CapabilitySet, FilesystemCapability, NetworkCapability,
            OPERATION_PLAN_PROTOCOL_VERSION, OperationPlan, PlannedOperation, PluginIdentity,
            SemanticConfidence,
        };
        let net_table = "[capabilities]\nnetwork = \"outbound-https\"";
        let fixture =
            PluginFixture::with_capabilities("plan-host", "wrapper", "first-party", net_table)?;
        let mut registry = PluginRegistry::new(vec![]);
        registry.register(fixture.path())?;

        let plan = OperationPlan {
            protocol_version: OPERATION_PLAN_PROTOCOL_VERSION,
            plugin: PluginIdentity {
                id: "plan-host".to_owned(),
                version: "0.1.0".to_owned(),
                trust_class: arbitraitor_plugin_api::PluginTrustClass::FirstParty,
            },
            original_tool: "curl".to_owned(),
            operations: vec![PlannedOperation::Retrieve {
                url: "https://example.invalid/x".to_owned(),
                headers: Vec::new(),
            }],
            requested_capabilities: CapabilitySet {
                network: NetworkCapability::Full,
                filesystem: FilesystemCapability::None,
                process: arbitraitor_plugin_api::ProcessCapability::None,
                max_memory_bytes: None,
                max_cpu_ms: None,
            },
            semantic_confidence: SemanticConfidence::Exact,
        };

        let result = registry.validate_plan("plan-host", &plan);

        assert!(
            matches!(
                result,
                Err(arbitraitor_plugin_api::PlanError::CapabilityExceedsDeclaration)
            ),
            "plan requesting `full` network against an `outbound-https` declaration must be rejected; got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn validate_plan_admits_plan_within_declared_capabilities() -> TestResult {
        use arbitraitor_plugin_api::{
            CapabilitySet, NetworkCapability, OPERATION_PLAN_PROTOCOL_VERSION, OperationPlan,
            PlannedOperation, PluginIdentity, PluginTrustClass, SemanticConfidence,
        };
        let net_table = "[capabilities]\nnetwork = \"outbound-https\"";
        let fixture =
            PluginFixture::with_capabilities("plan-ok", "wrapper", "first-party", net_table)?;
        let mut registry = PluginRegistry::new(vec![]);
        registry.register(fixture.path())?;

        let plan = OperationPlan {
            protocol_version: OPERATION_PLAN_PROTOCOL_VERSION,
            plugin: PluginIdentity {
                id: "plan-ok".to_owned(),
                version: "0.1.0".to_owned(),
                trust_class: PluginTrustClass::FirstParty,
            },
            original_tool: "curl".to_owned(),
            operations: vec![PlannedOperation::Retrieve {
                url: "https://example.invalid/x".to_owned(),
                headers: Vec::new(),
            }],
            requested_capabilities: CapabilitySet {
                network: NetworkCapability::OutboundHttps,
                filesystem: arbitraitor_plugin_api::FilesystemCapability::None,
                process: arbitraitor_plugin_api::ProcessCapability::None,
                max_memory_bytes: None,
                max_cpu_ms: None,
            },
            semantic_confidence: SemanticConfidence::Exact,
        };

        registry.validate_plan("plan-ok", &plan)?;
        Ok(())
    }

    fn sample_registry_metadata() -> RegistryMetadata {
        RegistryMetadata {
            schema_version: REGISTRY_METADATA_SCHEMA_VERSION,
            plugin_id: "clamav-scanner".to_owned(),
            version: "1.2.3".to_owned(),
            publisher_identity: "key:ed25519:abc123".to_owned(),
            version_history: vec!["1.0.0".to_owned(), "1.1.0".to_owned(), "1.2.3".to_owned()],
            supported_platforms: vec![
                "x86_64-unknown-linux-gnu".to_owned(),
                "aarch64-unknown-linux-gnu".to_owned(),
            ],
            requested_permissions: vec![
                "filesystem.read-only".to_owned(),
                "process.spawn".to_owned(),
            ],
            signature_status: SignatureStatus::Signed,
            provenance_status: ProvenanceStatus::Verified,
            security_audit_status: SecurityAuditStatus::Audited,
            conformance_status: ConformanceStatus::Conformant,
            known_vulnerabilities: Vec::new(),
            revocation_status: RevocationStatus::Active,
            download_digest: "0".repeat(64),
        }
    }

    #[test]
    fn registry_metadata_round_trips_through_json() -> TestResult {
        let original = sample_registry_metadata();
        let json = serde_json::to_string(&original)?;
        let decoded: RegistryMetadata = serde_json::from_str(&json)?;
        assert_eq!(decoded, original);
        Ok(())
    }

    #[test]
    fn registry_metadata_schema_version_is_current() {
        let meta = sample_registry_metadata();
        assert_eq!(meta.schema_version, REGISTRY_METADATA_SCHEMA_VERSION);
        assert_eq!(
            RegistryMetadata::SCHEMA_VERSION,
            REGISTRY_METADATA_SCHEMA_VERSION
        );
    }

    #[test]
    fn registry_metadata_new_stamps_active_and_schema() {
        let meta = RegistryMetadata::new("plugin", "1.0.0", "publisher", "0".repeat(64).as_str());
        assert_eq!(meta.schema_version, REGISTRY_METADATA_SCHEMA_VERSION);
        assert_eq!(meta.plugin_id, "plugin");
        assert_eq!(meta.version, "1.0.0");
        assert_eq!(meta.publisher_identity, "publisher");
        assert_eq!(meta.revocation_status, RevocationStatus::Active);
        assert_eq!(meta.signature_status, SignatureStatus::Unsigned);
        assert_eq!(meta.provenance_status, ProvenanceStatus::Missing);
        assert_eq!(meta.conformance_status, ConformanceStatus::Pending);
        assert!(meta.version_history.is_empty());
        assert!(meta.supported_platforms.is_empty());
        assert!(meta.requested_permissions.is_empty());
        assert!(meta.known_vulnerabilities.is_empty());
    }

    #[test]
    fn registry_metadata_rejects_unknown_fields() -> TestResult {
        let mut json = serde_json::to_value(sample_registry_metadata()).map_err(Box::new)?;
        json.as_object_mut()
            .ok_or("expected object")?
            .insert("sneaky".to_owned(), serde_json::Value::Bool(true));
        let result = serde_json::from_value::<RegistryMetadata>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields must reject smuggled field"
        );
        Ok(())
    }

    #[test]
    fn registry_metadata_is_verification_clean_only_when_all_green() {
        let mut meta = sample_registry_metadata();
        assert!(meta.is_verification_clean());

        meta.signature_status = SignatureStatus::Invalid;
        assert!(!meta.is_verification_clean());
        meta.signature_status = SignatureStatus::Signed;

        meta.provenance_status = ProvenanceStatus::Failed;
        assert!(!meta.is_verification_clean());
        meta.provenance_status = ProvenanceStatus::Missing;
        assert!(!meta.is_verification_clean());
        meta.provenance_status = ProvenanceStatus::Verified;

        meta.security_audit_status = SecurityAuditStatus::Failed;
        assert!(!meta.is_verification_clean());
        meta.security_audit_status = SecurityAuditStatus::Audited;

        meta.conformance_status = ConformanceStatus::NonConformant;
        assert!(!meta.is_verification_clean());
        meta.conformance_status = ConformanceStatus::Pending;
        assert!(!meta.is_verification_clean());
        meta.conformance_status = ConformanceStatus::Conformant;

        meta.revocation_status = RevocationStatus::Revoked;
        assert!(!meta.is_verification_clean());
        meta.revocation_status = RevocationStatus::Active;

        meta.known_vulnerabilities.push("CVE-2026-0001".to_owned());
        assert!(!meta.is_verification_clean());
        meta.known_vulnerabilities.clear();

        assert!(meta.is_verification_clean());
    }

    #[test]
    fn revocation_entry_round_trips_through_json() -> TestResult {
        let entry = RevocationEntry {
            plugin_id: "clamav-scanner".to_owned(),
            version: "1.0.0".to_owned(),
            issuer: "publisher:acme".to_owned(),
            revoked_at: 1_700_000_000,
            reason: "RCE in network scanner".to_owned(),
        };
        let json = serde_json::to_string(&entry)?;
        let decoded: RevocationEntry = serde_json::from_str(&json)?;
        assert_eq!(decoded, entry);
        Ok(())
    }

    #[test]
    fn revocation_entry_rejects_unknown_fields() -> TestResult {
        let mut json = serde_json::json!({
            "plugin_id": "clamav-scanner",
            "version": "1.0.0",
            "issuer": "publisher:acme",
            "revoked_at": 1_700_000_000_u64,
            "reason": "RCE",
        });
        let object = json.as_object_mut().ok_or("expected json object")?;
        object.insert("sneaky".to_owned(), serde_json::Value::Bool(true));
        let result = serde_json::from_value::<RevocationEntry>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields must reject smuggled field"
        );
        Ok(())
    }

    #[test]
    fn staged_rollout_round_trips_through_json() -> TestResult {
        let rollout = StagedRollout::new(10, "canary");
        let json = serde_json::to_string(&rollout)?;
        let decoded: StagedRollout = serde_json::from_str(&json)?;
        assert_eq!(decoded, rollout);
        assert_eq!(decoded.percentage, 10);
        assert_eq!(decoded.target_audience, "canary");
        Ok(())
    }

    #[test]
    fn staged_rollout_rejects_unknown_fields() -> TestResult {
        let mut json = serde_json::json!({"percentage": 50, "target_audience": "beta"});
        let object = json.as_object_mut().ok_or("expected json object")?;
        object.insert(
            "sneaky".to_owned(),
            serde_json::Value::String("x".to_owned()),
        );
        let result = serde_json::from_value::<StagedRollout>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields must reject smuggled field"
        );
        Ok(())
    }

    #[test]
    #[should_panic(expected = "staged rollout percentage must be in 0..=100")]
    fn staged_rollout_panics_above_one_hundred() {
        let _ = StagedRollout::new(101, "all");
    }

    #[test]
    fn staged_rollout_accepts_boundary_values() {
        let zero = StagedRollout::new(0, "none");
        assert_eq!(zero.percentage, 0);
        let hundred = StagedRollout::new(100, "all");
        assert_eq!(hundred.percentage, 100);
    }

    #[test]
    fn permission_diff_status_serializes_as_snake_case() -> TestResult {
        for (variant, expected) in [
            (PermissionDiffStatus::Approved, "\"approved\""),
            (PermissionDiffStatus::Blocked, "\"blocked\""),
            (
                PermissionDiffStatus::PendingApproval,
                "\"pending_approval\"",
            ),
        ] {
            let json = serde_json::to_string(&variant)?;
            assert_eq!(json, expected, "variant {variant:?}");
            let back: PermissionDiffStatus = serde_json::from_str(&json)?;
            assert_eq!(back, variant);
        }
        Ok(())
    }

    #[test]
    fn signature_status_serializes_as_snake_case() -> TestResult {
        for (variant, expected) in [
            (SignatureStatus::Signed, "\"signed\""),
            (SignatureStatus::Unsigned, "\"unsigned\""),
            (SignatureStatus::Invalid, "\"invalid\""),
        ] {
            let json = serde_json::to_string(&variant)?;
            assert_eq!(json, expected, "variant {variant:?}");
            let back: SignatureStatus = serde_json::from_str(&json)?;
            assert_eq!(back, variant);
        }
        Ok(())
    }

    #[test]
    fn provenance_status_serializes_as_snake_case() -> TestResult {
        for (variant, expected) in [
            (ProvenanceStatus::Verified, "\"verified\""),
            (ProvenanceStatus::Failed, "\"failed\""),
            (ProvenanceStatus::Missing, "\"missing\""),
        ] {
            let json = serde_json::to_string(&variant)?;
            assert_eq!(json, expected, "variant {variant:?}");
            let back: ProvenanceStatus = serde_json::from_str(&json)?;
            assert_eq!(back, variant);
        }
        Ok(())
    }

    #[test]
    fn security_audit_status_serializes_as_snake_case() -> TestResult {
        for (variant, expected) in [
            (SecurityAuditStatus::NotAudited, "\"not_audited\""),
            (SecurityAuditStatus::Audited, "\"audited\""),
            (SecurityAuditStatus::Failed, "\"failed\""),
        ] {
            let json = serde_json::to_string(&variant)?;
            assert_eq!(json, expected, "variant {variant:?}");
            let back: SecurityAuditStatus = serde_json::from_str(&json)?;
            assert_eq!(back, variant);
        }
        Ok(())
    }

    #[test]
    fn conformance_status_serializes_as_snake_case() -> TestResult {
        for (variant, expected) in [
            (ConformanceStatus::Conformant, "\"conformant\""),
            (ConformanceStatus::NonConformant, "\"non_conformant\""),
            (ConformanceStatus::Pending, "\"pending\""),
        ] {
            let json = serde_json::to_string(&variant)?;
            assert_eq!(json, expected, "variant {variant:?}");
            let back: ConformanceStatus = serde_json::from_str(&json)?;
            assert_eq!(back, variant);
        }
        Ok(())
    }

    #[test]
    fn revocation_status_serializes_as_snake_case() -> TestResult {
        for (variant, expected) in [
            (RevocationStatus::Active, "\"active\""),
            (RevocationStatus::Revoked, "\"revoked\""),
        ] {
            let json = serde_json::to_string(&variant)?;
            assert_eq!(json, expected, "variant {variant:?}");
            let back: RevocationStatus = serde_json::from_str(&json)?;
            assert_eq!(back, variant);
        }
        Ok(())
    }
}
