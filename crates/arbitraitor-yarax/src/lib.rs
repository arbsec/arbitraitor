//! YARA-X rule compilation and scanning integration
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt::Write as _;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arbitraitor_analysis::{AnalysisContext, Detector, DetectorError};
use arbitraitor_artifact::ArtifactType;
use arbitraitor_model::artifact::ArtifactKind;
use arbitraitor_model::finding::{
    DetectorMetadata, Evidence, EvidenceKind, Finding, FindingCategory,
};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity};
use arbitraitor_receipt::DetectorVersion;
use sha2::{Digest, Sha256};
use thiserror::Error;
use yara_x::{Compiler, MetaValue, Rules, ScanError, Scanner};

const DETECTOR_ID: &str = "arbitraitor-yarax";
const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_MAX_SCAN_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_MATCHES_PER_PATTERN: usize = 64;
const MAX_EVIDENCE_CHARS: usize = 512;

/// Built-in suspicious shell YARA-X rules.
pub const BUILT_IN_SUSPICIOUS_SHELL_RULES: &str = include_str!("../rules/suspicious-shell.yar");
/// Built-in known bad URL YARA-X rules.
pub const BUILT_IN_KNOWN_BAD_URL_RULES: &str = include_str!("../rules/known-bad-urls.yar");
/// Built-in MVP YARA-X rules for high-signal malware and suspicious installer patterns.
pub const BUILT_IN_RULES: &str = concat!(
    include_str!("../rules/suspicious-shell.yar"),
    "\n",
    include_str!("../rules/known-bad-urls.yar")
);

/// Errors returned by YARA-X scanner setup and scanning.
#[derive(Debug, Error)]
pub enum YaraError {
    /// Rule compilation failed.
    #[error("failed to compile YARA-X rules: {0}")]
    Compile(String),
    /// Scanning failed for a non-timeout reason.
    #[error("YARA-X scan failed: {0}")]
    Scan(String),
    /// Scanning exceeded an explicit resource limit.
    #[error("YARA-X resource limit exceeded: {0}")]
    ResourceLimit(String),
    /// Rule pack input/output failed.
    #[error("failed to load YARA-X rule pack: {0}")]
    Io(String),
    /// Rule pack metadata is invalid.
    #[error("invalid YARA-X rule pack: {0}")]
    InvalidPack(String),
    /// Rule pack authentication failed.
    #[error("failed to authenticate YARA-X rule pack: {0}")]
    Auth(String),
}

/// Origin of a YARA-X rule pack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleSource {
    /// Rules shipped with Arbitraitor.
    BuiltIn,
    /// Rules loaded from a local filesystem path.
    FileSystem(PathBuf),
    /// Enterprise-managed rules.
    Enterprise,
    /// Community-maintained rules.
    Community,
    /// User-local rules.
    UserLocal,
}

/// Authentication status for a loaded YARA-X rule pack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RulePackAuth {
    /// Pack was verified with a configured trusted public key.
    Signed {
        /// Minisign key identifier as uppercase hexadecimal.
        key_id: String,
    },
    /// Pack was accepted without a trusted signature.
    Unsigned {
        /// Safe reason explaining why unsigned rules were accepted.
        reason: String,
    },
}

/// Text-based YARA-X rule pack with receipt-ready version metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RulePack {
    /// Pack origin.
    pub source: RuleSource,
    /// Compiler namespace for all rules in this pack.
    pub namespace: String,
    /// Human or content-derived pack version.
    pub version: String,
    /// Raw YARA-X rules text.
    pub rules_text: String,
    /// SHA-256 digest of [`Self::rules_text`].
    pub digest: Sha256Digest,
    /// Authentication status for this pack.
    pub auth: RulePackAuth,
}

impl RulePack {
    /// Creates a rule pack and computes its rules text digest.
    #[must_use]
    pub fn new(
        source: RuleSource,
        namespace: impl Into<String>,
        version: impl Into<String>,
        rules_text: impl Into<String>,
    ) -> Self {
        let rules_text = rules_text.into();
        Self::with_auth(
            source,
            namespace,
            version,
            rules_text,
            RulePackAuth::Unsigned {
                reason: "no detached minisign signature verified".to_owned(),
            },
        )
    }

    /// Creates a rule pack with explicit authentication metadata.
    #[must_use]
    pub fn with_auth(
        source: RuleSource,
        namespace: impl Into<String>,
        version: impl Into<String>,
        rules_text: impl Into<String>,
        auth: RulePackAuth,
    ) -> Self {
        let rules_text = rules_text.into();
        let digest = digest_rules(&rules_text);
        Self {
            source,
            namespace: namespace.into(),
            version: version.into(),
            rules_text,
            digest,
            auth,
        }
    }
}

/// Configured trusted minisign public key for external YARA-X rule packs.
#[derive(Clone)]
pub struct TrustedRulePackKey {
    public_key: minisign::PublicKey,
}

impl TrustedRulePackKey {
    /// Creates a trusted rule-pack verification key.
    #[must_use]
    pub const fn new(public_key: minisign::PublicKey) -> Self {
        Self { public_key }
    }

    /// Returns the minisign key identifier as uppercase hexadecimal.
    #[must_use]
    pub fn key_id(&self) -> String {
        minisign_key_id(&self.public_key)
    }
}

impl std::fmt::Debug for TrustedRulePackKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustedRulePackKey")
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

impl PartialEq for TrustedRulePackKey {
    fn eq(&self, other: &Self) -> bool {
        self.key_id() == other.key_id()
    }
}

impl Eq for TrustedRulePackKey {}

/// Ordered collection of YARA-X rule packs.
#[derive(Clone, Debug, Default)]
pub struct RulePackManager {
    packs: Vec<RulePack>,
    trusted_keys: Vec<TrustedRulePackKey>,
    compiled_cache: Option<CompiledRulesCache>,
}

impl RulePackManager {
    /// Creates an empty rule pack manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            packs: Vec::new(),
            trusted_keys: Vec::new(),
            compiled_cache: None,
        }
    }

    /// Adds a trusted minisign public key for external rule pack sidecars.
    #[must_use]
    pub fn with_trusted_key(mut self, public_key: minisign::PublicKey) -> Self {
        self.trusted_keys.push(TrustedRulePackKey::new(public_key));
        self
    }

    /// Adds a trusted minisign public key for external rule pack sidecars.
    pub fn add_trusted_key(&mut self, public_key: minisign::PublicKey) {
        self.trusted_keys.push(TrustedRulePackKey::new(public_key));
    }

    /// Creates a manager with built-in rule packs loaded first.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::InvalidPack`] if built-in pack metadata is invalid.
    pub fn with_built_in() -> Result<Self, YaraError> {
        let mut manager = Self::new();
        manager.add_pack(RulePack::new(
            RuleSource::BuiltIn,
            "arbitraitor_builtin_shell",
            env!("CARGO_PKG_VERSION"),
            BUILT_IN_SUSPICIOUS_SHELL_RULES,
        ))?;
        manager.add_pack(RulePack::new(
            RuleSource::BuiltIn,
            "arbitraitor_builtin_urls",
            env!("CARGO_PKG_VERSION"),
            BUILT_IN_KNOWN_BAD_URL_RULES,
        ))?;
        Ok(manager)
    }

    /// Adds a rule pack after validating metadata and rule syntax.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::InvalidPack`] for invalid metadata or
    /// [`YaraError::Compile`] for invalid YARA-X syntax.
    pub fn add_pack(&mut self, pack: RulePack) -> Result<(), YaraError> {
        validate_pack(&pack)?;
        let mut candidate = self.packs.clone();
        candidate.push(pack);
        compile_packs(&candidate)?;
        self.packs = candidate;
        Ok(())
    }

    /// Loads all `.yar` files from a directory as ordered filesystem packs.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::Io`] when directory traversal or file reading fails,
    /// and [`YaraError::Compile`] when any loaded rule is invalid.
    pub fn load_directory(&mut self, dir: &Path, source: RuleSource) -> Result<(), YaraError> {
        if !dir.is_dir() {
            return Err(YaraError::Io(format!(
                "{} is not a directory",
                dir.display()
            )));
        }
        let source = match source {
            RuleSource::FileSystem(_) => RuleSource::FileSystem(dir.to_path_buf()),
            other => other,
        };

        let mut entries = Vec::new();
        for entry in fs::read_dir(dir).map_err(|error| YaraError::Io(error.to_string()))? {
            let entry = entry.map_err(|error| YaraError::Io(error.to_string()))?;
            let path = entry.path();
            if path.extension().is_some_and(|extension| extension == "yar") {
                entries.push(path);
            }
        }
        entries.sort();

        for path in entries {
            let rules_text = fs::read_to_string(&path).map_err(|error| {
                YaraError::Io(format!("failed to read {}: {error}", path.display()))
            })?;
            let auth = self.authenticate_filesystem_pack(&path, rules_text.as_bytes())?;
            let pack = RulePack::with_auth(
                filesystem_source(source.clone(), &path),
                namespace_from_path(&path)?,
                version_from_rules(&rules_text),
                rules_text,
                auth,
            );
            self.add_pack(pack)?;
        }
        Ok(())
    }

    fn authenticate_filesystem_pack(
        &self,
        path: &Path,
        rules_bytes: &[u8],
    ) -> Result<RulePackAuth, YaraError> {
        let signature_path = minisign_sidecar_path(path);
        if !signature_path.exists() {
            return Ok(RulePackAuth::Unsigned {
                reason: "no .minisig sidecar found for user-local rule pack".to_owned(),
            });
        }

        let signature = fs::read(&signature_path).map_err(|error| {
            YaraError::Io(format!(
                "failed to read {}: {error}",
                signature_path.display()
            ))
        })?;
        if self.trusted_keys.is_empty() {
            tracing::warn!(
                rule_pack = %path.display(),
                signature = %signature_path.display(),
                "YARA-X rule pack has a minisign sidecar but no trusted rule-pack key is configured; accepting as user-local unsigned rules"
            );
            return Ok(RulePackAuth::Unsigned {
                reason: "minisign sidecar present but no trusted key configured".to_owned(),
            });
        }

        for key in &self.trusted_keys {
            if verify_rule_pack_signature(rules_bytes, &signature, &key.public_key).is_ok() {
                return Ok(RulePackAuth::Signed {
                    key_id: key.key_id(),
                });
            }
        }

        Err(YaraError::Auth(format!(
            "minisign verification failed for {}",
            path.display()
        )))
    }

    /// Compiles all packs into a scanner, preserving pack priority order.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::Compile`] when combined rule compilation fails.
    pub fn compile_all(&self) -> Result<YaraScanner, YaraError> {
        let rules = compile_packs(&self.packs)?;
        Ok(YaraScanner::from_rule_packs(self.packs.clone(), rules))
    }

    /// Compiles all packs with a compiled-rule cache (spec §17).
    ///
    /// The cache is keyed by a snapshot digest computed from all loaded
    /// rule pack namespaces, versions, and rule text. If the packs haven't
    /// changed since the last compile, the cached `Rules` are returned
    /// without recompilation.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::Compile`] when combined rule compilation fails.
    pub fn compile_all_cached(&mut self) -> Result<YaraScanner, YaraError> {
        let snapshot_digest = compute_snapshot_digest(&self.packs);
        if let Some(ref cached) = self.compiled_cache
            && cached.snapshot_digest == snapshot_digest
        {
            return Ok(YaraScanner::from_rule_packs_arc(
                self.packs.clone(),
                Arc::clone(&cached.rules),
            ));
        }
        let rules = compile_packs(&self.packs)?;
        let rules_arc = Arc::new(rules);
        let scanner = YaraScanner::from_rule_packs_arc(self.packs.clone(), Arc::clone(&rules_arc));
        self.compiled_cache = Some(CompiledRulesCache {
            snapshot_digest,
            rules: rules_arc,
        });
        Ok(scanner)
    }

    /// Returns the snapshot digest of the currently loaded rule packs, or
    /// `None` if no packs are loaded.
    #[must_use]
    pub fn snapshot_digest(&self) -> Option<String> {
        if self.packs.is_empty() {
            return None;
        }
        Some(compute_snapshot_digest(&self.packs))
    }

    /// Returns receipt detector-version entries for loaded rule packs.
    #[must_use]
    pub fn pack_versions(&self) -> Vec<DetectorVersion> {
        self.packs
            .iter()
            .map(|pack| DetectorVersion {
                id: format!("{DETECTOR_ID}.rules.{}", pack.namespace),
                version: pack.version.clone(),
            })
            .collect()
    }

    /// Returns loaded rule packs in compilation order.
    #[must_use]
    pub fn packs(&self) -> &[RulePack] {
        &self.packs
    }
}

/// Safe summary of a YARA-X rule match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YaraMatch {
    /// Matched rule identifier.
    pub rule_identifier: String,
    /// Rule namespace.
    pub namespace: String,
    /// Rule metadata as safe key-value summaries.
    pub metadata: Vec<(String, String)>,
    /// Rule tags.
    pub tags: Vec<String>,
    /// Offset-only summaries for matched byte ranges.
    pub matched_ranges: Vec<YaraMatchedRange>,
}

/// Safe location and length summary for a matched string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YaraMatchedRange {
    /// Absolute offset in the scanned artifact.
    pub offset: usize,
    /// Matched byte length.
    pub length: usize,
}

/// Compiles YARA-X rules and scans in-memory artifact bytes.
pub struct YaraScanner {
    compiler: Compiler<'static>,
    rules: Arc<Rules>,
    rule_packs: Vec<RulePack>,
    timeout: Duration,
    max_scan_bytes: usize,
    max_matches_per_pattern: usize,
}

impl YaraScanner {
    /// Creates a scanner loaded with the built-in MVP rules.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::Compile`] if a built-in rule fails to compile.
    pub fn new() -> Result<Self, YaraError> {
        RulePackManager::with_built_in()?.compile_all()
    }

    /// Creates a scanner with no rules loaded.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::Compile`] if the empty baseline rule set fails to build.
    pub fn empty() -> Result<Self, YaraError> {
        let compiler = Compiler::new();
        let rules = compile_packs(&[])?;
        Ok(Self {
            compiler,
            rules: Arc::new(rules),
            rule_packs: Vec::new(),
            timeout: DEFAULT_SCAN_TIMEOUT,
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
            max_matches_per_pattern: DEFAULT_MAX_MATCHES_PER_PATTERN,
        })
    }

    fn from_rule_packs(rule_packs: Vec<RulePack>, rules: Rules) -> Self {
        Self {
            compiler: Compiler::new(),
            rules: Arc::new(rules),
            rule_packs,
            timeout: DEFAULT_SCAN_TIMEOUT,
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
            max_matches_per_pattern: DEFAULT_MAX_MATCHES_PER_PATTERN,
        }
    }

    fn from_rule_packs_arc(rule_packs: Vec<RulePack>, rules: Arc<Rules>) -> Self {
        Self {
            compiler: Compiler::new(),
            rules,
            rule_packs,
            timeout: DEFAULT_SCAN_TIMEOUT,
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
            max_matches_per_pattern: DEFAULT_MAX_MATCHES_PER_PATTERN,
        }
    }

    /// Sets scan timeout and byte limits for subsequent scans.
    #[must_use]
    pub fn with_limits(mut self, timeout: Duration, max_scan_bytes: usize) -> Self {
        self.timeout = timeout;
        self.max_scan_bytes = max_scan_bytes;
        self
    }

    /// Adds YARA-X source and rebuilds the compiled rule set atomically.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::Compile`] and leaves existing rules unchanged when the
    /// supplied source or the combined rule set is invalid.
    pub fn add_rules(&mut self, rules: &str) -> Result<(), YaraError> {
        let mut packs = self.rule_packs.clone();
        packs.push(RulePack::new(
            RuleSource::UserLocal,
            "default",
            version_from_rules(rules),
            rules,
        ));
        let compiled = compile_packs(&packs)?;
        self.rule_packs = packs;
        self.rules = Arc::new(compiled);
        self.compiler = Compiler::new();
        Ok(())
    }

    /// Returns receipt detector-version entries for loaded rule packs.
    #[must_use]
    pub fn rule_pack_versions(&self) -> Vec<DetectorVersion> {
        RulePackManager {
            packs: self.rule_packs.clone(),
            trusted_keys: Vec::new(),
            compiled_cache: None,
        }
        .pack_versions()
    }

    /// Scans data and returns matching rule summaries.
    ///
    /// Scan errors are logged and converted to no matches for this convenience
    /// API. Use [`Self::scan_result`] when callers must distinguish resource
    /// limits and scanner failures.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<YaraMatch> {
        match self.scan_result(data) {
            Ok(matches) => matches,
            Err(error) => {
                tracing::warn!(error = %error, "YARA-X scan failed");
                Vec::new()
            }
        }
    }

    /// Scans data and returns matching rule summaries or a typed error.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::ResourceLimit`] for configured byte limits or
    /// YARA-X timeouts, and [`YaraError::Scan`] for other scanner errors.
    pub fn scan_result(&self, data: &[u8]) -> Result<Vec<YaraMatch>, YaraError> {
        self.scan_result_inner(data, None)
    }

    /// Scans data using only rules selected for the supplied artifact type.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::ResourceLimit`] for configured byte limits or
    /// YARA-X timeouts, and [`YaraError::Scan`] for other scanner errors.
    pub fn scan_result_for_artifact(
        &self,
        data: &[u8],
        artifact_type: ArtifactType,
    ) -> Result<Vec<YaraMatch>, YaraError> {
        self.scan_result_inner(data, Some(artifact_type))
    }

    fn scan_result_inner(
        &self,
        data: &[u8],
        artifact_type: Option<ArtifactType>,
    ) -> Result<Vec<YaraMatch>, YaraError> {
        if data.len() > self.max_scan_bytes {
            return Err(YaraError::ResourceLimit(format!(
                "artifact size {} exceeds configured scan limit {}",
                data.len(),
                self.max_scan_bytes
            )));
        }

        let mut scanner = Scanner::new(&self.rules);
        scanner
            .set_timeout(self.timeout)
            .max_matches_per_pattern(self.max_matches_per_pattern)
            .fast_scan(false);

        let results = scanner.scan(data).map_err(map_scan_error)?;
        Ok(results
            .matching_rules()
            .filter(|rule| {
                artifact_type.is_none_or(|artifact_type| rule_matches_artifact(rule, artifact_type))
            })
            .map(|rule| rule_to_match(&rule))
            .collect())
    }

    /// Returns compiled rules for detector construction within this crate.
    fn rules(&self) -> Arc<Rules> {
        Arc::clone(&self.rules)
    }
}

/// Detector adapter that runs YARA-X rules in the analysis pipeline.
pub struct YaraDetector {
    rules: Arc<Rules>,
    timeout: Duration,
    max_scan_bytes: usize,
    max_matches_per_pattern: usize,
}

impl YaraDetector {
    /// Creates a detector loaded with built-in YARA-X rules.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::Compile`] if a built-in rule fails to compile.
    pub fn new() -> Result<Self, YaraError> {
        let scanner = YaraScanner::new()?;
        Self::from_scanner(&scanner)
    }

    /// Creates a detector from a scanner's compiled rules and limits.
    ///
    /// # Errors
    ///
    /// Currently infallible, returning a result for API symmetry with [`Self::new`].
    pub fn from_scanner(scanner: &YaraScanner) -> Result<Self, YaraError> {
        Ok(Self {
            rules: scanner.rules(),
            timeout: scanner.timeout,
            max_scan_bytes: scanner.max_scan_bytes,
            max_matches_per_pattern: scanner.max_matches_per_pattern,
        })
    }

    /// Creates a detector from YARA-X source.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::Compile`] when the supplied source is invalid.
    pub fn from_rules(rules: &str) -> Result<Self, YaraError> {
        let mut scanner = YaraScanner::empty()?;
        scanner.add_rules(rules)?;
        Self::from_scanner(&scanner)
    }

    /// Overrides scan timeout and byte limits.
    #[must_use]
    pub fn with_limits(mut self, timeout: Duration, max_scan_bytes: usize) -> Self {
        self.timeout = timeout;
        self.max_scan_bytes = max_scan_bytes;
        self
    }

    fn scan_result(
        &self,
        data: &[u8],
        artifact_type: ArtifactType,
    ) -> Result<Vec<YaraMatch>, YaraError> {
        if data.len() > self.max_scan_bytes {
            return Err(YaraError::ResourceLimit(format!(
                "artifact size {} exceeds configured scan limit {}",
                data.len(),
                self.max_scan_bytes
            )));
        }

        let mut scanner = Scanner::new(&self.rules);
        scanner
            .set_timeout(self.timeout)
            .max_matches_per_pattern(self.max_matches_per_pattern)
            .fast_scan(false);

        let results = scanner.scan(data).map_err(map_scan_error)?;
        Ok(results
            .matching_rules()
            .filter(|rule| rule_matches_artifact(rule, artifact_type))
            .map(|rule| rule_to_match(&rule))
            .collect())
    }
}

impl Detector for YaraDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: DETECTOR_ID.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            supported_artifact_kinds: supported_artifact_kinds(),
            capabilities: vec!["yara-x-pattern-scan".to_owned()],
            is_local: true,
            may_upload: false,
            default_timeout_ms: timeout_millis(self.timeout),
            is_deterministic: true,
        }
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        Ok(
            match self.scan_result(ctx.artifact_bytes, ctx.classification.artifact_type) {
                Ok(matches) => matches
                    .iter()
                    .map(|matched| yara_match_to_finding(matched, &ctx.artifact_sha256))
                    .collect(),
                Err(error) => vec![scanner_error_finding(&error, &ctx.artifact_sha256)],
            },
        )
    }
}

/// Public handle describing a rule selected for an artifact class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleHandle {
    /// Matched rule identifier.
    pub identifier: String,
    /// Rule namespace.
    pub namespace: String,
    /// Rule tags.
    pub tags: Vec<String>,
    /// Optional artifact class required by rule metadata.
    pub artifact_class: Option<String>,
}

/// Returns handles for rules whose `artifact_class` metadata allows scanning an artifact type.
#[must_use]
pub fn select_rules_for_artifact(rules: &Rules, artifact_type: ArtifactType) -> Vec<RuleHandle> {
    rules
        .iter()
        .filter(|rule| rule_matches_artifact(rule, artifact_type))
        .map(|rule| RuleHandle {
            identifier: rule.identifier().to_owned(),
            namespace: rule.namespace().to_owned(),
            tags: rule.tags().map(|tag| tag.identifier().to_owned()).collect(),
            artifact_class: artifact_class_metadata(&rule).map(ToOwned::to_owned),
        })
        .collect()
}

/// Converts a YARA-X match summary into a detector finding.
#[must_use]
pub fn yara_match_to_finding(matched: &YaraMatch, artifact_sha256: &Sha256Digest) -> Finding {
    let mut tags = vec!["yara-x".to_owned(), "malware-signature".to_owned()];
    tags.extend(matched.tags.iter().cloned());

    Finding {
        id: format!("yara-x.{}", stable_identifier(&matched.rule_identifier)),
        detector: DETECTOR_ID.to_owned(),
        category: FindingCategory::MalwareSignature,
        severity: Severity::Critical,
        confidence: Confidence::Confirmed,
        title: format!("YARA-X rule matched: {}", matched.rule_identifier),
        description: "A YARA-X signature matched the artifact. Match evidence reports rule metadata only and intentionally omits raw matched bytes.".to_owned(),
        evidence: vec![Evidence {
            kind: EvidenceKind::Other,
            description: "YARA-X rule match metadata without raw matched bytes".to_owned(),
            content: Some(match_evidence(matched)),
        }],
        artifact_sha256: artifact_sha256.clone(),
        location: None,
        remediation: Some("Treat this artifact as malicious unless the matching rule is explicitly reviewed and allowlisted by policy.".to_owned()),
        references: Vec::new(),
        tags,
        taxonomies: Vec::new(),
    }
}

fn compile_packs(packs: &[RulePack]) -> Result<Rules, YaraError> {
    let mut compiler = Compiler::new();
    for pack in packs {
        compiler
            .new_namespace(&pack.namespace)
            .add_source(pack.rules_text.as_str())
            .map_err(|error| YaraError::Compile(error.to_string()))?;
    }
    Ok(compiler.build())
}

#[derive(Clone, Debug)]
struct CompiledRulesCache {
    snapshot_digest: String,
    rules: Arc<Rules>,
}

fn compute_snapshot_digest(packs: &[RulePack]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for pack in packs {
        hasher.update(pack.namespace.as_bytes());
        hasher.update(pack.version.as_bytes());
        hasher.update(pack.rules_text.as_bytes());
    }
    let result = hasher.finalize();
    let mut hex = String::with_capacity(result.len() * 2);
    for b in &result {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

fn validate_pack(pack: &RulePack) -> Result<(), YaraError> {
    if pack.namespace.is_empty() {
        return Err(YaraError::InvalidPack(
            "rule pack namespace must not be empty".to_owned(),
        ));
    }
    if !pack
        .namespace
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err(YaraError::InvalidPack(format!(
            "rule pack namespace {} contains unsupported characters",
            pack.namespace
        )));
    }
    if pack.rules_text.trim().is_empty() {
        return Err(YaraError::InvalidPack(format!(
            "rule pack namespace {} has no rules",
            pack.namespace
        )));
    }
    Ok(())
}

fn digest_rules(rules_text: &str) -> Sha256Digest {
    Sha256Digest::new(Sha256::digest(rules_text.as_bytes()).into())
}

fn version_from_rules(rules_text: &str) -> String {
    format!("sha256:{}", digest_rules(rules_text))
}

fn filesystem_source(source: RuleSource, path: &Path) -> RuleSource {
    match source {
        RuleSource::FileSystem(_) => RuleSource::FileSystem(path.to_path_buf()),
        other => other,
    }
}

fn namespace_from_path(path: &Path) -> Result<String, YaraError> {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| {
            YaraError::InvalidPack(format!("{} has no valid UTF-8 file stem", path.display()))
        })?;
    let namespace = stem
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if namespace.is_empty() {
        return Err(YaraError::InvalidPack(format!(
            "{} has empty namespace",
            path.display()
        )));
    }
    Ok(namespace)
}

fn minisign_sidecar_path(path: &Path) -> PathBuf {
    let mut sidecar = path.as_os_str().to_owned();
    sidecar.push(".minisig");
    PathBuf::from(sidecar)
}

fn verify_rule_pack_signature(
    rules_bytes: &[u8],
    signature: &[u8],
    public_key: &minisign::PublicKey,
) -> Result<(), YaraError> {
    let signature_text = std::str::from_utf8(signature)
        .map_err(|error| YaraError::Auth(format!("malformed minisign signature: {error}")))?;
    let signature_box = minisign::SignatureBox::from_string(signature_text)
        .map_err(|error| YaraError::Auth(format!("malformed minisign signature: {error}")))?;
    minisign::verify(
        public_key,
        &signature_box,
        Cursor::new(rules_bytes),
        true,
        false,
        false,
    )
    .map_err(|error| YaraError::Auth(error.to_string()))
}

fn minisign_key_id(public_key: &minisign::PublicKey) -> String {
    let mut output = String::with_capacity(public_key.keynum().len() * 2);
    for byte in public_key.keynum() {
        let _ = write!(output, "{byte:02X}");
    }
    output
}

fn map_scan_error(error: ScanError) -> YaraError {
    match error {
        ScanError::Timeout => YaraError::ResourceLimit("scan timeout elapsed".to_owned()),
        other => YaraError::Scan(other.to_string()),
    }
}

fn rule_to_match(rule: &yara_x::Rule<'_, '_>) -> YaraMatch {
    YaraMatch {
        rule_identifier: rule.identifier().to_owned(),
        namespace: rule.namespace().to_owned(),
        metadata: rule
            .metadata()
            .map(|(key, value)| (key.to_owned(), safe_meta_value(&value)))
            .collect(),
        tags: rule.tags().map(|tag| tag.identifier().to_owned()).collect(),
        matched_ranges: matched_ranges(rule),
    }
}

fn matched_ranges(rule: &yara_x::Rule<'_, '_>) -> Vec<YaraMatchedRange> {
    rule.patterns()
        .flat_map(|pattern| pattern.matches())
        .map(|matched| {
            let range = matched.range();
            YaraMatchedRange {
                offset: range.start,
                length: range.end.saturating_sub(range.start),
            }
        })
        .collect()
}

fn rule_matches_artifact(rule: &yara_x::Rule<'_, '_>, artifact_type: ArtifactType) -> bool {
    artifact_class_metadata(rule)
        .is_none_or(|artifact_class| artifact_class == artifact_class_label(artifact_type))
}

fn artifact_class_metadata<'rule>(rule: &yara_x::Rule<'_, 'rule>) -> Option<&'rule str> {
    rule.metadata().find_map(|(key, value)| {
        if key == "artifact_class"
            && let MetaValue::String(value) = value
        {
            return Some(value);
        }
        None
    })
}

fn artifact_class_label(artifact_type: ArtifactType) -> &'static str {
    match artifact_type {
        ArtifactType::ShellScript(_) => "shell_script",
        ArtifactType::PowerShellScript => "powershell_script",
        ArtifactType::PythonScript => "python_script",
        ArtifactType::JavaScript => "javascript",
        ArtifactType::PeExecutable => "pe_executable",
        ArtifactType::ElfExecutable => "elf_executable",
        ArtifactType::MachOExecutable => "macho_executable",
        ArtifactType::ZipArchive => "zip_archive",
        ArtifactType::TarArchive => "tar_archive",
        ArtifactType::GzipCompressed => "gzip_compressed",
        ArtifactType::XzCompressed => "xz_compressed",
        ArtifactType::Bzip2Compressed => "bzip2_compressed",
        ArtifactType::ZstdCompressed => "zstd_compressed",
        ArtifactType::GenericText => "generic_text",
        ArtifactType::GenericBinary => "generic_binary",
        ArtifactType::HtmlDocument => "html_document",
        ArtifactType::JsonDocument => "json_document",
        ArtifactType::XmlDocument => "xml_document",
        ArtifactType::Unknown => "unknown",
    }
}

fn safe_meta_value(value: &MetaValue<'_>) -> String {
    match value {
        MetaValue::Integer(value) => value.to_string(),
        MetaValue::Float(value) => value.to_string(),
        MetaValue::Bool(value) => value.to_string(),
        MetaValue::String(value) => bounded_text(value),
        MetaValue::Bytes(value) => format!("<binary metadata: {} bytes>", value.len()),
    }
}

fn match_evidence(matched: &YaraMatch) -> String {
    let metadata = matched
        .metadata
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(", ");
    let ranges = matched
        .matched_ranges
        .iter()
        .map(|range| {
            format!(
                "matched at offset {}, length {}",
                range.offset, range.length
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    bounded_text(&format!(
        "rule={} namespace={} tags=[{}] metadata=[{}] matches=[{}] raw_matches=omitted",
        matched.rule_identifier,
        matched.namespace,
        matched.tags.join(","),
        metadata,
        ranges
    ))
}

fn bounded_text(value: &str) -> String {
    let mut bounded: String = value.chars().take(MAX_EVIDENCE_CHARS).collect();
    if value.chars().count() > MAX_EVIDENCE_CHARS {
        bounded.push('…');
    }
    bounded
}

fn scanner_error_finding(error: &YaraError, artifact_sha256: &Sha256Digest) -> Finding {
    let (category, title) = match error {
        YaraError::ResourceLimit(_) => (
            FindingCategory::ResourceLimitEvent,
            "YARA-X scanner resource limit reached",
        ),
        YaraError::Compile(_)
        | YaraError::Scan(_)
        | YaraError::Io(_)
        | YaraError::InvalidPack(_)
        | YaraError::Auth(_) => (FindingCategory::ParserError, "YARA-X scanner failed"),
    };

    Finding {
        id: "yara-x.scanner-error".to_owned(),
        detector: DETECTOR_ID.to_owned(),
        category,
        severity: Severity::High,
        confidence: Confidence::Confirmed,
        title: title.to_owned(),
        description: "YARA-X analysis did not complete successfully, so malware-signature coverage is incomplete.".to_owned(),
        evidence: vec![Evidence {
            kind: EvidenceKind::Other,
            description: "safe scanner diagnostic".to_owned(),
            content: Some(error.to_string()),
        }],
        artifact_sha256: artifact_sha256.clone(),
        location: None,
        remediation: Some("Fail closed or rescan with sufficient resources before release.".to_owned()),
        references: Vec::new(),
        tags: vec!["yara-x".to_owned(), "incomplete-analysis".to_owned()],
        taxonomies: Vec::new(),
    }
}

fn stable_identifier(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

fn timeout_millis(timeout: Duration) -> u64 {
    u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)
}

fn supported_artifact_kinds() -> Vec<ArtifactKind> {
    vec![
        ArtifactKind::GenericText,
        ArtifactKind::GenericBinary,
        ArtifactKind::ShellScript(arbitraitor_model::artifact::ShellDialect::Posix),
        ArtifactKind::ShellScript(arbitraitor_model::artifact::ShellDialect::Bash),
        ArtifactKind::ShellScript(arbitraitor_model::artifact::ShellDialect::Zsh),
        ArtifactKind::PowerShellScript,
        ArtifactKind::PythonScript,
        ArtifactKind::JavaScript,
        ArtifactKind::PeExecutable,
        ArtifactKind::ElfExecutable,
        ArtifactKind::MachOExecutable,
    ]
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
