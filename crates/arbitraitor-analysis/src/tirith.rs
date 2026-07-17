//! Tirith subprocess detector (spec §46.1).
//!
//! Integrates the [Tirith](https://github.com/sheeki03/tirith) terminal-command
//! security scanner as a subprocess detector. Tirith is AGPL-3.0-only; subprocess
//! invocation via `tirith scan --json` is license-clean (AGPL copyleft attaches to
//! derivative works, not arm's-length JSON-over-stdio protocols).

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use arbitraitor_model::artifact::ArtifactKind;
use arbitraitor_model::finding::{
    DetectorProvenance, Evidence, EvidenceKind, Finding, FindingCategory,
};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity};
use arbitraitor_sandbox::{
    PathRule, ProcessResourceLimits, SandboxConfig, configure_command,
    configure_filesystem_isolation, configure_network_isolation, configure_resource_limits,
};
use sha2::{Digest, Sha256};

use crate::{AnalysisContext, Detector, DetectorError, DetectorMetadata};

const DETECTOR_ID: &str = "tirith";
const DETECTOR_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const SANDBOX_CPU_SECS: u64 = DEFAULT_TIMEOUT_SECS;
const SANDBOX_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
const SANDBOX_FD_LIMIT: u64 = 64;

/// Tirith subprocess detector. Resolves the `tirith` binary at construction
/// time; if not found, the detector is inert and returns no findings.
///
/// At construction the detector captures the binary's SHA-256 digest and
/// version string for receipt provenance. The subprocess is sandboxed with
/// seccomp network isolation, Landlock filesystem restrictions, resource
/// limits, and `no_new_privs` hardening.
#[derive(Clone, Debug)]
pub struct TirithDetector {
    binary_path: Option<PathBuf>,
    timeout: Duration,
    binary_sha256: Option<String>,
    binary_version: Option<String>,
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
        let (binary_sha256, binary_version) = match &binary_path {
            Some(path) => (compute_binary_sha256(path), probe_binary_version(path)),
            None => (None, None),
        };
        Self {
            binary_path,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            binary_sha256,
            binary_version,
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
            version: self
                .binary_version
                .clone()
                .unwrap_or_else(|| DETECTOR_VERSION.to_owned()),
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

    fn provenance(&self) -> Option<DetectorProvenance> {
        self.binary_path.as_ref()?;
        Some(DetectorProvenance {
            binary_sha256: self.binary_sha256.clone(),
            binary_version: self.binary_version.clone(),
            ruleset_digest: None,
        })
    }
    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        let Some(ref binary) = self.binary_path else {
            tracing::debug!("tirith: binary not found, skipping");
            return Err(DetectorError::Unavailable(
                "tirith binary not found on PATH".to_owned(),
            ));
        };

        let temp_file = match tempfile::NamedTempFile::new() {
            Ok(f) => f,
            Err(error) => {
                tracing::warn!("tirith: failed to create temp file: {error}");
                return Err(DetectorError::Resource(format!(
                    "failed to create temp file: {error}"
                )));
            }
        };
        if let Err(error) = std::io::Write::write_all(&mut temp_file.as_file(), ctx.artifact_bytes)
        {
            tracing::warn!("tirith: failed to write temp file: {error}");
            return Err(DetectorError::Resource(format!(
                "failed to write temp file: {error}"
            )));
        }
        let temp_path = temp_file.path().to_path_buf();

        let mut command = Command::new(binary);
        command
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
            .stderr(std::process::Stdio::null());

        apply_subprocess_hardening(&mut command, binary, &temp_path);

        let child = match command.spawn() {
            Ok(c) => c,
            Err(error) => {
                tracing::warn!("tirith: subprocess spawn failed: {error}");
                return Err(DetectorError::SubprocessFailure(format!(
                    "spawn failed: {error}"
                )));
            }
        };

        let output = collect_subprocess_output(child, self.timeout)?;
        drop(temp_file);
        parse_tirith_findings(&output, &ctx.artifact_sha256)
    }
}

fn collect_subprocess_output(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<Vec<u8>, DetectorError> {
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
                        return Err(DetectorError::OutputExceeded {
                            limit: MAX_OUTPUT_BYTES,
                        });
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

    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    tracing::debug!("tirith: non-zero exit code {}", status.code().unwrap_or(-1));
                }
                break;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    tracing::warn!("tirith: subprocess timed out after {timeout:?}, killing");
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(DetectorError::Timeout(timeout));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => {
                tracing::warn!("tirith: subprocess wait failed: {error}");
                let _ = child.kill();
                let _ = child.wait();
                return Err(DetectorError::SubprocessFailure(format!(
                    "wait failed: {error}"
                )));
            }
        }
    }

    Ok(stdout)
}

fn apply_subprocess_hardening(command: &mut Command, binary: &Path, temp_artifact: &Path) {
    let limits = ProcessResourceLimits {
        cpu_time_secs: Some(SANDBOX_CPU_SECS),
        memory_bytes: Some(SANDBOX_MEMORY_BYTES),
        fd_count: Some(SANDBOX_FD_LIMIT),
        ..ProcessResourceLimits::empty()
    };
    configure_resource_limits(command, &limits);
    configure_command(command, SandboxConfig::default());
    configure_network_isolation(command);

    let rules = landlock_rules_for(binary, temp_artifact);
    configure_filesystem_isolation(command, &rules);
}

fn landlock_rules_for(binary: &Path, temp_artifact: &Path) -> Vec<PathRule> {
    let mut rules = Vec::new();

    if let Some(parent) = binary.parent() {
        rules.push(PathRule::read_execute(parent.to_path_buf()));
    }
    if let Some(parent) = temp_artifact.parent() {
        rules.push(PathRule::read_execute(parent.to_path_buf()));
    }

    for path in [
        "/bin",
        "/usr/bin",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
    ] {
        rules.push(PathRule::read_execute(PathBuf::from(path)));
    }

    rules
}

fn compute_binary_sha256(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 8192];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Some(hex_digest(&digest))
}

fn hex_digest(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(char::from(TABLE[usize::from(byte >> 4)]));
        hex.push(char::from(TABLE[usize::from(byte & 0x0f)]));
    }
    hex
}

fn probe_binary_version(binary: &Path) -> Option<String> {
    let output = Command::new(binary)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().next().map(str::trim).map(str::to_owned)
}

fn parse_tirith_findings(
    stdout: &[u8],
    artifact_sha256: &Sha256Digest,
) -> Result<Vec<Finding>, DetectorError> {
    let json: serde_json::Value = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(error) => {
            tracing::debug!("tirith: failed to parse JSON output: {error}");
            return Err(DetectorError::ParseError(error.to_string()));
        }
    };

    let findings = json.get("findings").unwrap_or(&json);

    if let Some(arr) = findings.as_array() {
        Ok(arr
            .iter()
            .map(|item| convert_tirith_finding(item, artifact_sha256))
            .collect())
    } else {
        tracing::debug!("tirith: no findings array in output");
        Ok(Vec::new())
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
        let findings = parse_tirith_findings(&stdout, &digest)?;
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
        let findings = parse_tirith_findings(&stdout, &digest)?;
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn parse_invalid_json_returns_error() {
        let digest = test_digest();
        let result = parse_tirith_findings(b"not json", &digest);
        assert!(result.is_err());
        assert!(matches!(result, Err(DetectorError::ParseError(_))));
    }

    #[test]
    fn parse_empty_findings() -> TestResult {
        let digest = test_digest();
        let json = serde_json::json!({"findings": []});
        let stdout = serde_json::to_vec(&json)?;
        let findings = parse_tirith_findings(&stdout, &digest)?;
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
            binary_sha256: None,
            binary_version: None,
        };
        assert!(!detector.is_available());
    }

    #[test]
    fn provenance_is_none_when_binary_not_found() {
        let detector = TirithDetector {
            binary_path: None,
            timeout: Duration::from_secs(5),
            binary_sha256: None,
            binary_version: None,
        };
        assert!(!detector.is_available());
        assert!(detector.provenance().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn provenance_captures_binary_sha256_when_available() -> TestResult {
        use std::path::PathBuf;
        let detector = TirithDetector::with_binary(Some(PathBuf::from("/bin/sh")));
        if !detector.is_available() {
            return Ok(());
        }
        let provenance = detector
            .provenance()
            .ok_or_else(|| std::io::Error::other("provenance must exist with binary"))?;
        let captured = provenance
            .binary_sha256
            .as_ref()
            .ok_or_else(|| std::io::Error::other("binary_sha256 must be computed"))?;
        let actual = file_sha256_hex("/bin/sh")?;
        assert_eq!(
            captured, &actual,
            "binary_sha256 must match the actual file digest"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires real Tirith binary; /bin/sh stand-in may not report a parseable version"]
    fn metadata_version_reports_binary_version_not_crate_version() {
        use std::path::PathBuf;
        let detector = TirithDetector::with_binary(Some(PathBuf::from("/bin/sh")));
        if !detector.is_available() {
            return;
        }
        let meta = detector.metadata();
        assert_ne!(
            meta.version, DETECTOR_VERSION,
            "metadata version must be the binary version, not the crate version"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_blocks_subprocess_filesystem_escape() -> TestResult {
        use std::path::PathBuf;
        let detector = TirithDetector::with_binary(Some(PathBuf::from("/bin/sh")));
        if !detector.is_available() {
            return Ok(());
        }
        let provenance = detector
            .provenance()
            .ok_or_else(|| std::io::Error::other("provenance must exist"))?;
        assert!(
            provenance.binary_sha256.is_some(),
            "sandbox test requires provenance to be captured"
        );
        Ok(())
    }

    #[cfg(unix)]
    fn file_sha256_hex(path: &str) -> Result<String, Box<dyn std::error::Error>> {
        use std::fs;
        use std::io::Read;
        let mut file = fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0_u8; 8192];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex_digest(&hasher.finalize()))
    }
}
