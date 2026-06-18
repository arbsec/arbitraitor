//! YARA-X rule compilation and scanning integration
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;
use std::time::Duration;

use arbitraitor_analysis::{AnalysisContext, Detector};
use arbitraitor_model::artifact::ArtifactKind;
use arbitraitor_model::finding::{
    DetectorMetadata, Evidence, EvidenceKind, Finding, FindingCategory,
};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity};
use thiserror::Error;
use yara_x::{Compiler, MetaValue, Rules, ScanError, Scanner};

const DETECTOR_ID: &str = "arbitraitor-yarax";
const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_MAX_SCAN_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_MATCHES_PER_PATTERN: usize = 64;
const MAX_EVIDENCE_CHARS: usize = 512;

/// Built-in MVP YARA-X rules for high-signal malware and suspicious installer patterns.
pub const BUILT_IN_RULES: &str = r#"
rule Arbitraitor_Suspicious_CurlPipeShell : suspicious_shell downloader
{
  meta:
    description = "Downloads content and pipes it directly into a shell"
    source = "arbitraitor-builtin"
  strings:
    $curl = "curl" ascii nocase
    $wget = "wget" ascii nocase
    $pipe_sh = /\|\s*(sudo\s+)?(ba)?sh\b/ ascii
  condition:
    any of ($curl, $wget) and $pipe_sh
}

rule Arbitraitor_Suspicious_Powershell_DownloadCradle : suspicious_powershell downloader
{
  meta:
    description = "PowerShell download cradle pattern"
    source = "arbitraitor-builtin"
  strings:
    $webclient = "System.Net.WebClient" ascii nocase
    $download = "DownloadString" ascii nocase
    $iex = "IEX" ascii nocase
  condition:
    $webclient and $download and $iex
}

rule Arbitraitor_Known_Eicar_Test_String : malware test_signature
{
  meta:
    description = "EICAR anti-malware test string"
    source = "arbitraitor-builtin"
  strings:
    $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
  condition:
    $eicar
}
"#;

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
    rule_sources: Vec<String>,
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
        let mut scanner = Self::empty()?;
        scanner.add_rules(BUILT_IN_RULES)?;
        Ok(scanner)
    }

    /// Creates a scanner with no rules loaded.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::Compile`] if the empty baseline rule set fails to build.
    pub fn empty() -> Result<Self, YaraError> {
        let compiler = Compiler::new();
        let rules = compile_sources(&[])?;
        Ok(Self {
            compiler,
            rules: Arc::new(rules),
            rule_sources: Vec::new(),
            timeout: DEFAULT_SCAN_TIMEOUT,
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
            max_matches_per_pattern: DEFAULT_MAX_MATCHES_PER_PATTERN,
        })
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
        let mut sources = self.rule_sources.clone();
        sources.push(rules.to_owned());
        let compiled = compile_sources(&sources)?;
        self.rule_sources = sources;
        self.rules = Arc::new(compiled);
        self.compiler = Compiler::new();
        Ok(())
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

fn compile_sources(sources: &[String]) -> Result<Rules, YaraError> {
    let mut compiler = Compiler::new();
    for source in sources {
        compiler
            .add_source(source.as_str())
            .map_err(|error| YaraError::Compile(error.to_string()))?;
    }
    Ok(compiler.build())
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
        YaraError::Compile(_) | YaraError::Scan(_) => {
            (FindingCategory::ParserError, "YARA-X scanner failed")
        }
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
    use std::time::Duration;

    use arbitraitor_analysis::AnalysisCoordinator;
    use arbitraitor_model::finding::FindingCategory;

    use super::{YaraDetector, YaraError, YaraScanner};

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
}
