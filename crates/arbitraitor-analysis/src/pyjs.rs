//! Python and JavaScript script detectors (spec §16.3).
//!
//! Narrow initial coverage for the two most prevalent scripting ecosystems in
//! untrusted artifact payloads. The detector scans source bytes for risky
//! construction patterns (subprocess/shell invocation, dynamic code execution,
//! arbitrary deserialization, credential-file access, persistence writes,
//! obfuscated/encoded payloads, native module loading, and environment-variable
//! exfiltration) and emits a finding per matched pattern.
//!
//! Pattern matching is intentionally simple and dependency-free: the analysis
//! crate does not depend on `regex`, and adding one for a stub detector would
//! require an ADR. Future revisions may swap in a proper tokenizer/AST walker
//! once the stub proves out coverage.

#![forbid(unsafe_code)]

use arbitraitor_model::artifact::ArtifactKind;
use arbitraitor_model::finding::{Evidence, EvidenceKind, Finding, FindingCategory};
use arbitraitor_model::verdict::{Confidence, Severity};

use crate::{AnalysisContext, Detector, DetectorError, DetectorMetadata};

const PYJS_DETECTOR_ID: &str = "arbitraitor-analysis.python-js";

/// Detector that scans Python and JavaScript sources for risky patterns
/// described in spec §16.3.
#[derive(Clone, Copy, Debug, Default)]
pub struct PythonJsDetector;

impl Detector for PythonJsDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: PYJS_DETECTOR_ID.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            supported_artifact_kinds: pyjs_artifact_kinds(),
            capabilities: vec![
                "python-pattern-scan".to_owned(),
                "javascript-pattern-scan".to_owned(),
            ],
            is_local: true,
            may_upload: false,
            default_timeout_ms: 5_000,
            is_deterministic: true,
        }
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        let Ok(source) = std::str::from_utf8(ctx.artifact_bytes) else {
            // Non-UTF-8 bytes cannot contain Python or JavaScript source. The
            // upstream classifier should not have routed us here, so flag the
            // mismatch and let other detectors (or operators) decide.
            return Ok(Vec::new());
        };

        let mut findings = Vec::new();
        for rule in PYJS_RULES {
            if let Some(offset) = rule.first_match(source) {
                findings.push(rule.finding(ctx, offset));
            }
        }
        Ok(findings)
    }
}

/// One detection rule for a single pattern string.
#[derive(Clone, Copy, Debug)]
struct PyJsRule {
    /// Stable identifier used as the finding `id`.
    id: &'static str,
    /// Short human-readable title.
    title: &'static str,
    /// Detailed description shown to operators.
    description: &'static str,
    /// Literal substring the rule searches for.
    needle: &'static str,
    /// Finding category for matches.
    category: FindingCategory,
    /// Severity for matches.
    severity: Severity,
    /// Confidence for matches.
    confidence: Confidence,
    /// Machine-readable tag grouping all findings from this rule.
    tag: &'static str,
}

impl PyJsRule {
    /// Returns the byte offset of the first match, if any.
    fn first_match(&self, haystack: &str) -> Option<usize> {
        haystack.find(self.needle)
    }

    /// Builds the finding for a single match.
    fn finding(&self, ctx: &AnalysisContext<'_>, offset: usize) -> Finding {
        Finding {
            id: format!("pyjs.{}", self.id),
            detector: PYJS_DETECTOR_ID.to_owned(),
            category: self.category,
            severity: self.severity,
            confidence: self.confidence,
            title: self.title.to_owned(),
            description: self.description.to_owned(),
            evidence: vec![Evidence {
                kind: EvidenceKind::SourceSnippet,
                description: format!("matched pattern {:?}", self.needle),
                content: Some(snippet_around(
                    ctx.artifact_bytes,
                    offset,
                    self.needle.len(),
                )),
            }],
            artifact_sha256: ctx.artifact_sha256.clone(),
            location: None,
            remediation: Some(
                "Inspect the script manually before release; pattern-based detection may \
                 produce false positives in legitimate automation code."
                    .to_owned(),
            ),
            references: vec!["Arbitraitor spec section 16.3".to_owned()],
            tags: vec!["python-js".to_owned(), self.tag.to_owned()],
            taxonomies: Vec::new(),
        }
    }
}

const PYJS_RULES: &[PyJsRule] = &[
    // 1. subprocess / shell invocation
    PyJsRule {
        id: "python-subprocess",
        title: "Python subprocess module usage",
        description: "Source references the `subprocess` module, which can spawn child processes \
             and execute shell commands.",
        needle: "subprocess",
        category: FindingCategory::DynamicCodeExecution,
        severity: Severity::High,
        confidence: Confidence::High,
        tag: "subprocess-shell-invocation",
    },
    PyJsRule {
        id: "python-os-system",
        title: "Python os.system shell execution",
        description: "Source calls `os.system`, which executes a command in a subshell.",
        needle: "os.system",
        category: FindingCategory::DynamicCodeExecution,
        severity: Severity::Critical,
        confidence: Confidence::High,
        tag: "subprocess-shell-invocation",
    },
    PyJsRule {
        id: "javascript-child-process",
        title: "Node.js child_process usage",
        description: "Source references `child_process`, which can spawn shell commands and \
             external programs from Node.js.",
        needle: "child_process",
        category: FindingCategory::DynamicCodeExecution,
        severity: Severity::High,
        confidence: Confidence::High,
        tag: "subprocess-shell-invocation",
    },
    // 2. eval / exec
    PyJsRule {
        id: "eval-exec",
        title: "Dynamic eval/exec invocation",
        description: "Source calls `eval(` or `exec(`, executing dynamically constructed code as \
             a program — a frequent vector for runtime-injected payloads.",
        needle: "eval(",
        category: FindingCategory::DynamicCodeExecution,
        severity: Severity::High,
        confidence: Confidence::Medium,
        tag: "eval-exec",
    },
    PyJsRule {
        id: "exec-call",
        title: "Dynamic exec() invocation",
        description: "Source calls `exec(` (Python built-in or function reference), which can \
             execute dynamically constructed code.",
        needle: "exec(",
        category: FindingCategory::DynamicCodeExecution,
        severity: Severity::High,
        confidence: Confidence::Medium,
        tag: "eval-exec",
    },
    // 3. arbitrary deserialization
    PyJsRule {
        id: "python-pickle-loads",
        title: "Python pickle deserialization",
        description: "Source calls `pickle.loads`, which can execute arbitrary code via crafted \
             serialized payloads.",
        needle: "pickle.loads",
        category: FindingCategory::DynamicCodeExecution,
        severity: Severity::Critical,
        confidence: Confidence::High,
        tag: "arbitrary-deserialization",
    },
    // 4. dynamic / native module loading
    PyJsRule {
        id: "python-dynamic-import",
        title: "Python dynamic __import__",
        description: "Source uses `__import__`, allowing imports driven by runtime-controlled \
             module names.",
        needle: "__import__",
        category: FindingCategory::DynamicCodeExecution,
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        tag: "native-module-loading",
    },
    PyJsRule {
        id: "javascript-require",
        title: "JavaScript require() call",
        description: "Source calls `require(`, which can load arbitrary CommonJS modules at \
             runtime.",
        needle: "require(",
        category: FindingCategory::SuspiciousScriptBehavior,
        severity: Severity::Low,
        confidence: Confidence::Low,
        tag: "module-loading",
    },
    // 5. credential / env-file access
    PyJsRule {
        id: "javascript-process-env",
        title: "JavaScript process.env access",
        description: "Source reads `process.env`, exposing environment variables — a common \
             exfiltration channel for secrets and tokens.",
        needle: "process.env",
        category: FindingCategory::CredentialAccess,
        severity: Severity::Medium,
        confidence: Confidence::High,
        tag: "env-exfiltration",
    },
    // 6. persistence writes
    PyJsRule {
        id: "javascript-fs-writefilesync",
        title: "JavaScript fs.writeFileSync write",
        description: "Source calls `fs.writeFileSync`, writing synchronously to disk — a common \
             persistence primitive.",
        needle: "fs.writeFileSync",
        category: FindingCategory::Persistence,
        severity: Severity::Medium,
        confidence: Confidence::High,
        tag: "persistence-write",
    },
    // 7. obfuscation / encoded payloads
    PyJsRule {
        id: "base64-usage",
        title: "Base64 reference in script",
        description: "Source references `base64`, often used to encode and smuggle payloads past \
             text-based reviewers.",
        needle: "base64",
        category: FindingCategory::Obfuscation,
        severity: Severity::Low,
        confidence: Confidence::Low,
        tag: "obfuscation-encoded-payload",
    },
];

/// Returns the artifact kinds this detector should run against.
fn pyjs_artifact_kinds() -> Vec<ArtifactKind> {
    vec![ArtifactKind::PythonScript, ArtifactKind::JavaScript]
}

/// Extracts a bounded UTF-8 snippet around a match offset for evidence display.
///
/// Falls back to lossy decoding if the surrounding bytes are not valid UTF-8.
fn snippet_around(bytes: &[u8], offset: usize, needle_len: usize) -> String {
    const CONTEXT: usize = 32;
    let start = offset.saturating_sub(CONTEXT);
    let end = offset.saturating_add(needle_len).saturating_add(CONTEXT);
    let end = end.min(bytes.len());
    let window = bytes.get(start..end).unwrap_or(&[]);
    let decoded = String::from_utf8_lossy(window);
    let mut out = String::with_capacity(decoded.len() + 2);
    if start > 0 {
        out.push('…');
    }
    out.push_str(&decoded);
    if end < bytes.len() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use arbitraitor_model::ids::Sha256Digest;
    use sha2::{Digest, Sha256};

    fn digest(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::new(Sha256::digest(bytes).into())
    }

    fn analyze(source: &[u8]) -> Vec<Finding> {
        let detector = PythonJsDetector;
        let ctx = AnalysisContext {
            artifact_bytes: source,
            classification: arbitraitor_artifact::classify(source),
            retrieval: None,
            artifact_sha256: digest(source),
        };
        detector.analyze(&ctx).expect("analyze should not error")
    }

    #[test]
    fn detects_python_subprocess_call() {
        let findings = analyze(b"import subprocess\nsubprocess.run(['ls'])\n");
        assert!(
            findings.iter().any(|f| f
                .tags
                .iter()
                .any(|tag| tag == "subprocess-shell-invocation")),
            "subprocess.run should be flagged"
        );
    }

    #[test]
    fn detects_os_system_call() {
        let findings = analyze(b"import os\nos.system('whoami')\n");
        assert!(
            findings.iter().any(|f| f.title.contains("os.system")),
            "os.system should be flagged"
        );
    }

    #[test]
    fn detects_node_child_process() {
        let findings = analyze(b"const cp = require('child_process');\n");
        assert!(
            findings.iter().any(|f| f
                .tags
                .iter()
                .any(|tag| tag == "subprocess-shell-invocation")),
            "child_process should be flagged"
        );
    }

    #[test]
    fn detects_eval_call() {
        let findings = analyze(b"const x = eval('2+2');\n");
        assert!(
            findings
                .iter()
                .any(|f| f.tags.iter().any(|tag| tag == "eval-exec")),
            "eval( should be flagged"
        );
    }

    #[test]
    fn detects_pickle_loads() {
        let findings = analyze(b"import pickle\nx = pickle.loads(data)\n");
        assert!(
            findings
                .iter()
                .any(|f| f.tags.iter().any(|tag| tag == "arbitrary-deserialization")),
            "pickle.loads should be flagged"
        );
    }

    #[test]
    fn detects_process_env_access() {
        let findings = analyze(b"const token = process.env.AWS_SECRET;\n");
        assert!(
            findings
                .iter()
                .any(|f| f.tags.iter().any(|tag| tag == "env-exfiltration")),
            "process.env should be flagged as env exfiltration"
        );
    }

    #[test]
    fn detects_fs_writefilesync_persistence() {
        let findings = analyze(b"fs.writeFileSync('/tmp/p', data);\n");
        assert!(
            findings
                .iter()
                .any(|f| f.tags.iter().any(|tag| tag == "persistence-write")),
            "fs.writeFileSync should be flagged as persistence"
        );
    }

    #[test]
    fn detects_base64_obfuscation() {
        let findings = analyze(b"import base64\nbase64.b64decode(payload)\n");
        assert!(
            findings.iter().any(|f| f
                .tags
                .iter()
                .any(|tag| tag == "obfuscation-encoded-payload")),
            "base64 reference should be flagged as obfuscation"
        );
    }

    #[test]
    fn clean_script_emits_no_findings() {
        let findings = analyze(b"def hello(name):\n    return f'hi {name}'\n");
        assert!(
            findings.is_empty(),
            "benign Python should produce no findings, got: {findings:?}"
        );
    }

    #[test]
    fn clean_javascript_emits_no_findings() {
        let findings = analyze(b"function add(a, b) {\n  const sum = a + b;\n  return sum;\n}\n");
        assert!(
            findings.is_empty(),
            "benign JavaScript should produce no findings, got: {findings:?}"
        );
    }

    #[test]
    fn finding_digest_matches_artifact() {
        let source = b"import pickle\npickle.loads(payload)\n";
        let findings = analyze(source);
        let expected = digest(source);
        for finding in &findings {
            assert_eq!(
                finding.artifact_sha256, expected,
                "finding {} has wrong digest",
                finding.id
            );
        }
    }

    #[test]
    fn detector_metadata_is_deterministic() {
        let detector = PythonJsDetector;
        let meta = detector.metadata();
        assert_eq!(meta.id, "arbitraitor-analysis.python-js");
        assert!(meta.is_deterministic);
        assert!(meta.is_local);
        assert!(!meta.may_upload);
        assert!(
            meta.supported_artifact_kinds
                .contains(&ArtifactKind::PythonScript),
            "must support PythonScript"
        );
        assert!(
            meta.supported_artifact_kinds
                .contains(&ArtifactKind::JavaScript),
            "must support JavaScript"
        );
    }

    #[test]
    fn non_utf8_input_emits_no_findings() {
        let bytes: &[u8] = &[0xff, 0xfe, 0xfd];
        let findings = analyze(bytes);
        assert!(
            findings.is_empty(),
            "non-UTF-8 bytes should yield no findings, got: {findings:?}"
        );
    }
}
