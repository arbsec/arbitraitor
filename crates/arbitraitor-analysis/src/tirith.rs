//! Tirith subprocess detector (spec §46.1).
//!
//! Integrates the [Tirith](https://github.com/sheeki03/tirith) terminal-command
//! security scanner as a subprocess detector. Tirith is AGPL-3.0-only; subprocess
//! invocation via `tirith scan --json` is license-clean (AGPL copyleft attaches to
//! derivative works, not arm's-length JSON-over-stdio protocols).

#![forbid(unsafe_code)]

use arbitraitor_model::artifact::ArtifactKind;
use arbitraitor_model::finding::{Evidence, EvidenceKind, Finding, FindingCategory};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use crate::{AnalysisContext, Detector, DetectorMetadata};

const DETECTOR_ID: &str = "tirith";
const DETECTOR_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Tirith subprocess detector. Resolves the `tirith` binary at construction
/// time; if not found, the detector is inert and returns no findings.
#[derive(Clone, Debug)]
pub struct TirithDetector {
    binary_path: Option<PathBuf>,
    timeout: Duration,
}

impl TirithDetector {
    /// Creates a detector that resolves `tirith` on `PATH`.
    #[must_use]
    pub fn new() -> Self {
        Self::with_binary(None)
    }

    /// Creates a detector with an explicit binary path, or PATH lookup if `None`.
    #[must_use]
    pub fn with_binary(explicit_path: Option<PathBuf>) -> Self {
        let binary_path = explicit_path
            .filter(|p| p.is_file())
            .or_else(|| which("tirith"));
        Self {
            binary_path,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    /// Overrides the subprocess timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Returns `true` if the tirith binary was found.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.binary_path.is_some()
    }
}

impl Default for TirithDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for TirithDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: DETECTOR_ID.to_owned(),
            version: DETECTOR_VERSION.to_owned(),
            supported_artifact_kinds: vec![
                ArtifactKind::ShellScript(arbitraitor_model::artifact::ShellDialect::Posix),
                ArtifactKind::GenericText,
            ],
            capabilities: vec!["subprocess-scan".to_owned()],
            is_local: true,
            may_upload: false,
            default_timeout_ms: u64::try_from(self.timeout.as_millis()).unwrap_or(30_000),
            is_deterministic: false,
        }
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Vec<Finding> {
        let Some(ref binary) = self.binary_path else {
            tracing::debug!("tirith: binary not found, skipping");
            return Vec::new();
        };

        let temp_file = match tempfile::NamedTempFile::new() {
            Ok(f) => f,
            Err(error) => {
                tracing::warn!("tirith: failed to create temp file: {error}");
                return Vec::new();
            }
        };
        if let Err(error) = std::io::Write::write_all(&mut temp_file.as_file(), ctx.artifact_bytes)
        {
            tracing::warn!("tirith: failed to write temp file: {error}");
            return Vec::new();
        }
        let temp_path = temp_file.path().to_path_buf();

        let mut child = match Command::new(binary)
            .args([
                "scan",
                "--json",
                "--non-interactive",
                "--shell",
                "posix",
                "--",
            ])
            .arg(&temp_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(error) => {
                tracing::warn!("tirith: subprocess spawn failed: {error}");
                return Vec::new();
            }
        };

        let mut stdout = Vec::new();
        if let Some(mut pipe) = child.stdout.take() {
            let mut buf = [0_u8; 8192];
            loop {
                match std::io::Read::read(&mut pipe, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if stdout.len() + n > MAX_OUTPUT_BYTES {
                            tracing::warn!(
                                "tirith: output exceeded {MAX_OUTPUT_BYTES} bytes, killing subprocess"
                            );
                            let _ = child.kill();
                            let _ = child.wait();
                            drop(temp_file);
                            return Vec::new();
                        }
                        stdout.extend_from_slice(&buf[..n]);
                    }
                    Err(error) => {
                        tracing::debug!("tirith: stdout read error: {error}");
                        break;
                    }
                }
            }
        }

        let deadline = std::time::Instant::now() + self.timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        tracing::debug!(
                            "tirith: non-zero exit code {}",
                            status.code().unwrap_or(-1)
                        );
                    }
                    break;
                }
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        tracing::warn!(
                            "tirith: subprocess timed out after {:?}, killing",
                            self.timeout
                        );
                        let _ = child.kill();
                        let _ = child.wait();
                        drop(temp_file);
                        return Vec::new();
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(error) => {
                    tracing::warn!("tirith: subprocess wait failed: {error}");
                    let _ = child.kill();
                    let _ = child.wait();
                    drop(temp_file);
                    return Vec::new();
                }
            }
        }

        drop(temp_file);

        parse_tirith_findings(&stdout, &ctx.artifact_sha256)
    }
}

fn parse_tirith_findings(stdout: &[u8], artifact_sha256: &Sha256Digest) -> Vec<Finding> {
    let json: serde_json::Value = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(error) => {
            tracing::debug!("tirith: failed to parse JSON output: {error}");
            return Vec::new();
        }
    };

    let findings = json.get("findings").unwrap_or(&json);

    if let Some(arr) = findings.as_array() {
        arr.iter()
            .map(|item| convert_tirith_finding(item, artifact_sha256))
            .collect()
    } else {
        tracing::debug!("tirith: no findings array in output");
        Vec::new()
    }
}

fn convert_tirith_finding(item: &serde_json::Value, artifact_sha256: &Sha256Digest) -> Finding {
    let title = item
        .get("title")
        .or_else(|| item.get("description"))
        .and_then(|v| v.as_str())
        .unwrap_or("Tirith finding");
    let rule_id = item
        .get("rule_id")
        .or_else(|| item.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let severity_str = item
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("medium");
    let description = item
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or(title);

    let severity = match severity_str.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "low" => Severity::Low,
        _ => Severity::Medium,
    };

    Finding {
        id: format!("tirith.{rule_id}"),
        detector: DETECTOR_ID.to_owned(),
        category: FindingCategory::SuspiciousScriptBehavior,
        severity,
        confidence: Confidence::High,
        title: title.to_owned(),
        description: description.to_owned(),
        evidence: vec![Evidence {
            kind: EvidenceKind::Other,
            description: format!("Tirith rule {rule_id} matched"),
            content: item
                .get("match")
                .and_then(|m| m.as_str())
                .map(str::to_owned),
        }],
        artifact_sha256: artifact_sha256.clone(),
        location: None,
        remediation: item
            .get("remediation")
            .and_then(|r| r.as_str())
            .map(str::to_owned),
        references: Vec::new(),
        tags: vec!["tirith".to_owned(), "subprocess-detector".to_owned()],
        taxonomies: Vec::new(),
    }
}

fn which(binary: &str) -> Option<PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn test_digest() -> Sha256Digest {
        Sha256Digest::new(Sha256::digest(b"test").into())
    }

    #[test]
    fn convert_valid_tirith_finding() {
        let digest = test_digest();
        let json = serde_json::json!({
            "title": "Dangerous curl pipe to shell",
            "rule_id": "curl-pipe-shell",
            "severity": "high",
            "description": "curl output piped directly to shell interpreter",
            "match": "curl ... | sh"
        });
        let f = convert_tirith_finding(&json, &digest);
        assert_eq!(f.id, "tirith.curl-pipe-shell");
        assert_eq!(f.detector, "tirith");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.title, "Dangerous curl pipe to shell");
        assert!(f.tags.contains(&"tirith".to_owned()));
    }

    #[test]
    fn convert_finding_with_missing_fields() {
        let digest = test_digest();
        let json = serde_json::json!({});
        let f = convert_tirith_finding(&json, &digest);
        assert_eq!(f.severity, Severity::Medium);
        assert!(!f.id.is_empty());
    }

    #[test]
    fn parse_findings_array() -> TestResult {
        let digest = test_digest();
        let json = serde_json::json!({
            "findings": [
                {"title": "Finding 1", "rule_id": "r1", "severity": "critical"},
                {"title": "Finding 2", "rule_id": "r2", "severity": "low"}
            ]
        });
        let stdout = serde_json::to_vec(&json)?;
        let findings = parse_tirith_findings(&stdout, &digest);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn parse_flat_array() -> TestResult {
        let digest = test_digest();
        let json = serde_json::json!([
            {"title": "Finding 1", "rule_id": "r1"}
        ]);
        let stdout = serde_json::to_vec(&json)?;
        let findings = parse_tirith_findings(&stdout, &digest);
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn parse_invalid_json_returns_empty() {
        let digest = test_digest();
        let findings = parse_tirith_findings(b"not json", &digest);
        assert!(findings.is_empty());
    }

    #[test]
    fn parse_empty_findings() -> TestResult {
        let digest = test_digest();
        let json = serde_json::json!({"findings": []});
        let stdout = serde_json::to_vec(&json)?;
        let findings = parse_tirith_findings(&stdout, &digest);
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn detector_metadata() {
        let detector = TirithDetector::new();
        let meta = detector.metadata();
        assert_eq!(meta.id, "tirith");
        assert!(meta.is_local);
        assert!(!meta.may_upload);
    }

    #[test]
    fn detector_without_binary_is_inert() {
        let detector = TirithDetector {
            binary_path: None,
            timeout: Duration::from_secs(5),
        };
        assert!(!detector.is_available());
    }
}
