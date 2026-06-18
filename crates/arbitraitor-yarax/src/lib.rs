//! YARA-X rule compilation and scanning integration
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arbitraitor_analysis::{AnalysisContext, Detector};
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
        let digest = digest_rules(&rules_text);
        Self {
            source,
            namespace: namespace.into(),
            version: version.into(),
            rules_text,
            digest,
        }
    }
}

/// Ordered collection of YARA-X rule packs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RulePackManager {
    packs: Vec<RulePack>,
}

impl RulePackManager {
    /// Creates an empty rule pack manager.
    #[must_use]
    pub fn new() -> Self {
        Self { packs: Vec::new() }
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
            let pack = RulePack::new(
                filesystem_source(source.clone(), &path),
                namespace_from_path(&path)?,
                version_from_rules(&rules_text),
                rules_text,
            );
            self.add_pack(pack)?;
        }
        Ok(())
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
            .fast_scan(true);

        let results = scanner.scan(data).map_err(map_scan_error)?;
        Ok(results
            .matching_rules()
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

    fn scan_result(&self, data: &[u8]) -> Result<Vec<YaraMatch>, YaraError> {
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
            .fast_scan(true);

        let results = scanner.scan(data).map_err(map_scan_error)?;
        Ok(results
            .matching_rules()
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

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Vec<Finding> {
        match self.scan_result(ctx.artifact_bytes) {
            Ok(matches) => matches
                .iter()
                .map(|matched| yara_match_to_finding(matched, &ctx.artifact_sha256))
                .collect(),
            Err(error) => vec![scanner_error_finding(&error, &ctx.artifact_sha256)],
        }
    }
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
    bounded_text(&format!(
        "rule={} namespace={} tags=[{}] metadata=[{}] raw_matches=omitted",
        matched.rule_identifier,
        matched.namespace,
        matched.tags.join(","),
        metadata
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
        | YaraError::InvalidPack(_) => (FindingCategory::ParserError, "YARA-X scanner failed"),
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
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    use arbitraitor_analysis::AnalysisCoordinator;
    use arbitraitor_model::finding::FindingCategory;

    use super::{RulePack, RulePackManager, RuleSource, YaraDetector, YaraError, YaraScanner};

    const TEST_RULE: &str = r#"
rule Arbitraitor_Test_Malware : malware unit_test
{
  meta:
    description = "test rule"
  strings:
    $marker = "arbitraitor-malware-marker" ascii
  condition:
    $marker
}
"#;

    #[test]
    fn scan_with_matching_rule_produces_finding() -> Result<(), Box<dyn std::error::Error>> {
        let detector = YaraDetector::from_rules(TEST_RULE)?;
        let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(detector)]);

        let result = coordinator.analyze(b"prefix arbitraitor-malware-marker suffix");

        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert_eq!(finding.category, FindingCategory::MalwareSignature);
        assert!(finding.tags.iter().any(|tag| tag == "unit_test"));
        assert!(finding.evidence.iter().all(|evidence| {
            evidence
                .content
                .as_deref()
                .is_none_or(|content| !content.contains("arbitraitor-malware-marker"))
        }));
        Ok(())
    }

    #[test]
    fn scan_with_no_match_produces_no_findings() -> Result<(), Box<dyn std::error::Error>> {
        let detector = YaraDetector::from_rules(TEST_RULE)?;
        let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(detector)]);

        let result = coordinator.analyze(b"benign content");

        assert!(result.findings.is_empty());
        Ok(())
    }

    #[test]
    fn invalid_rule_syntax_returns_error() -> Result<(), Box<dyn std::error::Error>> {
        let mut scanner = YaraScanner::empty()?;

        let error = scanner.add_rules("rule broken { condition: }");

        assert!(matches!(error, Err(YaraError::Compile(_))));
        assert!(scanner.scan(b"anything").is_empty());
        Ok(())
    }

    #[test]
    fn resource_limit_is_enforced_as_finding() -> Result<(), Box<dyn std::error::Error>> {
        let detector = YaraDetector::from_rules(TEST_RULE)?.with_limits(Duration::from_secs(1), 4);
        let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(detector)]);

        let result = coordinator.analyze(b"longer than four bytes");

        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].category,
            FindingCategory::ResourceLimitEvent
        );
        Ok(())
    }

    #[test]
    fn built_in_rules_compile_and_scan() -> Result<(), Box<dyn std::error::Error>> {
        let scanner = RulePackManager::with_built_in()?.compile_all()?;

        let matches = scanner.scan_result(b"curl https://example.test/install.sh | sh")?;

        assert!(
            matches
                .iter()
                .any(|matched| matched.rule_identifier == "Arbitraitor_Suspicious_CurlPipeShell")
        );
        assert!(scanner.rule_pack_versions().len() >= 2);
        Ok(())
    }

    #[test]
    fn load_external_rules_from_directory() -> Result<(), Box<dyn std::error::Error>> {
        let dir = test_dir("external-rules")?;
        fs::write(dir.join("external.yar"), TEST_RULE)?;
        let mut manager = RulePackManager::new();

        manager.load_directory(&dir, RuleSource::FileSystem(dir.clone()))?;
        let scanner = manager.compile_all()?;

        assert_eq!(scanner.scan(b"arbitraitor-malware-marker").len(), 1);
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn multiple_namespaces_allow_duplicate_rule_names() -> Result<(), Box<dyn std::error::Error>> {
        let duplicate_rule = r#"
rule Duplicate_Rule
{
  strings:
    $marker = "shared-marker" ascii
  condition:
    $marker
}
"#;
        let mut manager = RulePackManager::new();
        manager.add_pack(RulePack::new(
            RuleSource::Community,
            "community",
            "1",
            duplicate_rule,
        ))?;
        manager.add_pack(RulePack::new(
            RuleSource::Enterprise,
            "enterprise",
            "2",
            duplicate_rule,
        ))?;

        let matches = manager.compile_all()?.scan_result(b"shared-marker")?;

        let namespaces: Vec<&str> = matches
            .iter()
            .map(|matched| matched.namespace.as_str())
            .collect();
        assert_eq!(namespaces, vec!["community", "enterprise"]);
        Ok(())
    }

    #[test]
    fn invalid_rule_file_returns_error() -> Result<(), Box<dyn std::error::Error>> {
        let dir = test_dir("invalid-rules")?;
        fs::write(dir.join("broken.yar"), "rule broken { condition: }")?;
        let mut manager = RulePackManager::new();

        let error = manager.load_directory(&dir, RuleSource::FileSystem(dir.clone()));

        assert!(matches!(error, Err(YaraError::Compile(_))));
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn pack_versions_track_namespace_and_version() -> Result<(), Box<dyn std::error::Error>> {
        let mut manager = RulePackManager::new();
        manager.add_pack(RulePack::new(
            RuleSource::UserLocal,
            "local_rules",
            "2026.06.18",
            TEST_RULE,
        ))?;

        let versions = manager.pack_versions();

        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].id, "arbitraitor-yarax.rules.local_rules");
        assert_eq!(versions[0].version, "2026.06.18");
        Ok(())
    }

    fn test_dir(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dir =
            std::env::temp_dir().join(format!("arbitraitor-yarax-{name}-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}
