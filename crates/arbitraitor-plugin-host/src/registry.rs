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
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_plugin_api::{CapabilitySet, PluginManifest, PluginTrustClass, PluginType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Filename looked for inside each plugin directory.
const MANIFEST_FILENAME: &str = "manifest.toml";

/// On-disk TOML representation of a plugin manifest.
///
/// This is the untrusted boundary format. Fields are parsed as strings and
/// validated before conversion to the typed [`PluginManifest`].
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
}

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
    /// therein. The binary's SHA-256 is verified against the manifest checksum.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] on a missing manifest, malformed fields,
    /// missing binary, checksum mismatch, or duplicate id.
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

        let validated = validate_manifest(&file, dir, &label)?;

        if self.plugins.contains_key(&validated.manifest.identity.id) {
            return Err(RegistryError::DuplicatePlugin(
                validated.manifest.identity.id,
            ));
        }

        self.plugins
            .insert(validated.manifest.identity.id.clone(), validated);
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

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Result of validating and converting a manifest file.
fn validate_manifest(
    file: &PluginManifestFile,
    dir: &Path,
    label: &str,
) -> Result<RegisteredPlugin, RegistryError> {
    validate_id(&file.id).map_err(|reason| RegistryError::ManifestParse {
        plugin: label.to_owned(),
        error: reason,
    })?;

    validate_semver(&file.version).map_err(|reason| RegistryError::ManifestParse {
        plugin: label.to_owned(),
        error: reason,
    })?;

    let plugin_type = parse_plugin_type(&file.plugin_type, label)?;
    let trust_class = parse_trust_class(&file.trust_class, label)?;

    // The binary path is relative to the manifest directory. Reject absolute or
    // parent-escaping components — a manifest must not reference files outside
    // its own directory.
    let binary_rel = Path::new(&file.binary);
    if binary_rel.is_absolute() || file.binary.starts_with("..") {
        return Err(RegistryError::ManifestParse {
            plugin: label.to_owned(),
            error: format!(
                "binary path must be relative to the plugin directory: {}",
                file.binary
            ),
        });
    }
    let binary_path = dir.join(binary_rel);
    if !binary_path.is_file() {
        return Err(RegistryError::BinaryNotFound {
            plugin: label.to_owned(),
            path: binary_path,
        });
    }

    // Parse the declared checksum into a typed digest so we get hex validation
    // for free, then verify it against the on-disk bytes.
    let expected =
        Sha256Digest::from_str(&file.checksum).map_err(|err| RegistryError::ManifestParse {
            plugin: label.to_owned(),
            error: format!("invalid checksum: {err}"),
        })?;

    let actual = hash_file(&binary_path)?;
    if actual != expected {
        return Err(RegistryError::ChecksumMismatch {
            plugin: label.to_owned(),
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }

    let manifest = PluginManifest {
        identity: arbitraitor_plugin_api::PluginIdentity {
            id: file.id.clone(),
            version: file.version.clone(),
            trust_class,
        },
        capabilities: CapabilitySet::default(),
        plugin_type,
        description: file.description.clone().unwrap_or_default(),
    };

    Ok(RegisteredPlugin {
        manifest,
        binary_path,
        trust_class,
        installed_at: now_unix(),
        checksum: expected.to_string(),
    })
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
        other => Err(RegistryError::ManifestParse {
            plugin: label.to_owned(),
            error: format!(
                "unknown plugin_type '{other}'; expected one of: detector, wrapper, intelligence, provenance, sandbox"
            ),
        }),
    }
}

/// Parses the `trust_class` string into a [`PluginTrustClass`].
fn parse_trust_class(value: &str, label: &str) -> Result<PluginTrustClass, RegistryError> {
    match value {
        "built-in" => Ok(PluginTrustClass::BuiltIn),
        "first-party" => Ok(PluginTrustClass::FirstParty),
        "community-reviewed" => Ok(PluginTrustClass::CommunityReviewed),
        "community-unreviewed" => Ok(PluginTrustClass::CommunityUnreviewed),
        other => Err(RegistryError::ManifestParse {
            plugin: label.to_owned(),
            error: format!(
                "unknown trust_class '{other}'; expected one of: built-in, first-party, community-reviewed, community-unreviewed"
            ),
        }),
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
}
