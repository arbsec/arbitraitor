//! Artifact identification and content classification
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use arbitraitor_model::finding::{Evidence, EvidenceKind, Finding, FindingCategory};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity};
use sha2::{Digest, Sha256};
use thiserror::Error;

const DETECTOR_ID: &str = "arbitraitor-artifact";
const TAR_MAGIC_OFFSET: usize = 257;
const TAR_MAGIC: &[u8] = b"ustar";
const MAX_SHEBANG_BYTES: usize = 256;

/// Shell interpreter family identified from a script shebang.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShellKind {
    /// POSIX `sh` or compatible shell.
    Posix,
    /// GNU Bash.
    Bash,
    /// Z shell.
    Zsh,
}

/// Initial artifact content type identified from immutable artifact bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArtifactType {
    /// Shell script with a detected shell kind.
    ShellScript(ShellKind),
    /// PowerShell script.
    PowerShellScript,
    /// Python source or executable script.
    PythonScript,
    /// JavaScript source or executable script.
    JavaScript,
    /// Windows Portable Executable.
    PeExecutable,
    /// Executable and Linkable Format binary.
    ElfExecutable,
    /// Mach-O binary.
    MachOExecutable,
    /// ZIP or ZIP-derived archive.
    ZipArchive,
    /// POSIX tar archive.
    TarArchive,
    /// Gzip-compressed payload.
    GzipCompressed,
    /// XZ-compressed payload.
    XzCompressed,
    /// Zstandard-compressed payload.
    ZstdCompressed,
    /// Plain text without a more specific recognized structure.
    GenericText,
    /// Binary payload without a more specific recognized structure.
    GenericBinary,
    /// HTML document.
    HtmlDocument,
    /// JSON document.
    JsonDocument,
    /// XML document.
    XmlDocument,
    /// Empty or otherwise unclassifiable payload.
    Unknown,
}

/// Text encoding class detected while classifying content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DetectedEncoding {
    /// All bytes are ASCII text.
    Ascii,
    /// Bytes are valid UTF-8 text containing non-ASCII data.
    Utf8,
    /// Bytes are likely binary rather than text.
    Binary,
}

/// Artifact classification output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassificationResult {
    /// Detected artifact type.
    pub artifact_type: ArtifactType,
    /// Classifier confidence in the selected artifact type.
    pub confidence: Confidence,
    /// Detected text encoding, or binary marker for non-text payloads.
    pub detected_encoding: Option<DetectedEncoding>,
    /// Optional MIME hint from heuristic fallback detection.
    pub mime_hint: Option<String>,
    /// First-line shebang, when present and valid UTF-8.
    pub shebang: Option<String>,
}

/// Error type reserved for artifact classifier integrations.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ArtifactClassificationError {
    /// Expected content type did not match the observed content type.
    #[error("expected artifact type {expected:?}, observed {actual:?}")]
    ContentMismatch {
        /// Expected artifact type.
        expected: ArtifactType,
        /// Observed artifact type.
        actual: ArtifactType,
    },
}

/// Classifies immutable artifact bytes by content type.
#[must_use]
pub fn classify(data: &[u8]) -> ClassificationResult {
    let shebang = extract_shebang(data);
    let encoding = detect_encoding(data);
    let mime_hint = infer::get(data).map(|kind| kind.mime_type().to_owned());

    if data.is_empty() {
        return result(
            ArtifactType::Unknown,
            Confidence::Low,
            Some(DetectedEncoding::Ascii),
            mime_hint,
            shebang,
        );
    }

    if let Some(artifact_type) = detect_magic(data) {
        return result(
            artifact_type,
            Confidence::Confirmed,
            Some(DetectedEncoding::Binary),
            mime_hint,
            shebang,
        );
    }

    if let Some(artifact_type) = shebang.as_deref().and_then(detect_shebang) {
        return result(
            artifact_type,
            Confidence::Confirmed,
            Some(encoding),
            mime_hint,
            shebang,
        );
    }

    if encoding == DetectedEncoding::Binary {
        return result(
            detect_infer_binary(mime_hint.as_deref()).unwrap_or(ArtifactType::GenericBinary),
            Confidence::Medium,
            Some(DetectedEncoding::Binary),
            mime_hint,
            shebang,
        );
    }

    let artifact_type = detect_text_document(data).unwrap_or(ArtifactType::GenericText);
    let confidence = if artifact_type == ArtifactType::GenericText {
        Confidence::Medium
    } else {
        Confidence::High
    };

    result(
        artifact_type,
        confidence,
        Some(encoding),
        mime_hint,
        shebang,
    )
}

/// Classifies bytes and emits a content-mismatch finding when an expected type is supplied and differs.
#[must_use]
pub fn classify_with_expected(
    data: &[u8],
    expected: Option<ArtifactType>,
) -> (ClassificationResult, Option<Finding>) {
    let classification = classify(data);
    let finding = expected.and_then(|expected_type| {
        (classification.artifact_type != expected_type)
            .then(|| mismatch_finding(data, expected_type, &classification))
    });

    (classification, finding)
}

fn result(
    artifact_type: ArtifactType,
    confidence: Confidence,
    detected_encoding: Option<DetectedEncoding>,
    mime_hint: Option<String>,
    shebang: Option<String>,
) -> ClassificationResult {
    ClassificationResult {
        artifact_type,
        confidence,
        detected_encoding,
        mime_hint,
        shebang,
    }
}

fn detect_magic(data: &[u8]) -> Option<ArtifactType> {
    if data.starts_with(b"\x7fELF") {
        return Some(ArtifactType::ElfExecutable);
    }
    if data.starts_with(b"MZ") {
        return Some(ArtifactType::PeExecutable);
    }
    if is_macho(data) {
        return Some(ArtifactType::MachOExecutable);
    }
    if data.starts_with(b"PK\x03\x04") {
        return Some(ArtifactType::ZipArchive);
    }
    if data.starts_with(b"\x1f\x8b") {
        return Some(ArtifactType::GzipCompressed);
    }
    if data.starts_with(b"\xfd7zXZ\0") {
        return Some(ArtifactType::XzCompressed);
    }
    if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some(ArtifactType::ZstdCompressed);
    }
    is_tar(data).then_some(ArtifactType::TarArchive)
}

fn is_macho(data: &[u8]) -> bool {
    matches!(
        data.get(..4),
        Some(
            b"\xfe\xed\xfa\xce"
                | b"\xce\xfa\xed\xfe"
                | b"\xfe\xed\xfa\xcf"
                | b"\xcf\xfa\xed\xfe"
                | b"\xca\xfe\xba\xbe"
                | b"\xbe\xba\xfe\xca"
        )
    )
}

fn is_tar(data: &[u8]) -> bool {
    data.get(TAR_MAGIC_OFFSET..TAR_MAGIC_OFFSET + TAR_MAGIC.len()) == Some(TAR_MAGIC)
}

fn extract_shebang(data: &[u8]) -> Option<String> {
    let first_line = data.split(|byte| *byte == b'\n').next()?;
    if !first_line.starts_with(b"#!") || first_line.len() > MAX_SHEBANG_BYTES {
        return None;
    }
    core::str::from_utf8(first_line)
        .ok()
        .map(|value| value.trim_end_matches('\r').to_owned())
}

fn detect_shebang(shebang: &str) -> Option<ArtifactType> {
    let interpreter = normalized_interpreter_tokens(shebang);
    let name = interpreter.last()?;

    match name.as_str() {
        "sh" | "dash" | "ash" | "busybox" => Some(ArtifactType::ShellScript(ShellKind::Posix)),
        "bash" => Some(ArtifactType::ShellScript(ShellKind::Bash)),
        "zsh" => Some(ArtifactType::ShellScript(ShellKind::Zsh)),
        "python" | "python2" | "python3" => Some(ArtifactType::PythonScript),
        "node" | "nodejs" | "deno" | "bun" => Some(ArtifactType::JavaScript),
        "pwsh" | "powershell" | "powershell.exe" => Some(ArtifactType::PowerShellScript),
        _ => None,
    }
}

fn normalized_interpreter_tokens(shebang: &str) -> Vec<String> {
    let mut tokens = shebang
        .trim_start_matches("#!")
        .split_whitespace()
        .filter(|token| !token.starts_with('-'))
        .map(interpreter_name)
        .filter(|token| token != "env")
        .collect::<Vec<_>>();

    if tokens.first().is_some_and(|token| token == "busybox") && tokens.len() > 1 {
        tokens.remove(0);
    }
    tokens
}

fn interpreter_name(token: &str) -> String {
    token
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(token)
        .to_ascii_lowercase()
}

fn detect_encoding(data: &[u8]) -> DetectedEncoding {
    if data.contains(&0) {
        return DetectedEncoding::Binary;
    }
    if core::str::from_utf8(data).is_err() || has_binary_control_bytes(data) {
        return DetectedEncoding::Binary;
    }
    if data.is_ascii() {
        DetectedEncoding::Ascii
    } else {
        DetectedEncoding::Utf8
    }
}

fn has_binary_control_bytes(data: &[u8]) -> bool {
    data.iter()
        .any(|byte| matches!(*byte, 0x01..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f | 0x7f))
}

fn detect_text_document(data: &[u8]) -> Option<ArtifactType> {
    let text = core::str::from_utf8(data).ok()?;
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    let lower_prefix = trimmed
        .chars()
        .take(32)
        .flat_map(char::to_lowercase)
        .collect::<String>();

    if lower_prefix.starts_with("<!doctype html") || lower_prefix.starts_with("<html") {
        return Some(ArtifactType::HtmlDocument);
    }
    if lower_prefix.starts_with("<?xml") {
        return Some(ArtifactType::XmlDocument);
    }
    if matches!(trimmed.as_bytes().first(), Some(b'{' | b'[')) {
        return Some(ArtifactType::JsonDocument);
    }
    None
}

fn detect_infer_binary(mime_hint: Option<&str>) -> Option<ArtifactType> {
    match mime_hint {
        Some("application/zip") => Some(ArtifactType::ZipArchive),
        Some("application/gzip" | "application/x-gzip") => Some(ArtifactType::GzipCompressed),
        Some("application/x-xz") => Some(ArtifactType::XzCompressed),
        Some("application/zstd" | "application/x-zstd") => Some(ArtifactType::ZstdCompressed),
        Some("application/x-executable" | "application/x-elf") => Some(ArtifactType::ElfExecutable),
        Some("application/x-msdownload" | "application/vnd.microsoft.portable-executable") => {
            Some(ArtifactType::PeExecutable)
        }
        _ => None,
    }
}

fn mismatch_finding(
    data: &[u8],
    expected: ArtifactType,
    classification: &ClassificationResult,
) -> Finding {
    Finding {
        id: "artifact.content-mismatch".to_owned(),
        detector: DETECTOR_ID.to_owned(),
        category: FindingCategory::ContentMismatch,
        severity: Severity::High,
        confidence: Confidence::Confirmed,
        title: "Artifact content type mismatch".to_owned(),
        description: format!(
            "Expected artifact type {expected:?}, observed {:?}",
            classification.artifact_type
        ),
        evidence: vec![Evidence {
            kind: EvidenceKind::Other,
            description: "classifier result".to_owned(),
            content: Some(format!(
                "expected={expected:?}; observed={:?}; shebang={:?}; mime_hint={:?}",
                classification.artifact_type, classification.shebang, classification.mime_hint
            )),
        }],
        artifact_sha256: digest(data),
        location: None,
        remediation: Some("Inspect the exact downloaded bytes and update policy expectations only if the content is trusted.".to_owned()),
        references: Vec::new(),
        tags: vec!["artifact-classifier".to_owned(), "content-mismatch".to_owned()],
    }
}

fn digest(data: &[u8]) -> Sha256Digest {
    Sha256Digest::new(Sha256::digest(data).into())
}

#[cfg(test)]
mod tests {
    use super::{ArtifactType, DetectedEncoding, ShellKind, classify, classify_with_expected};
    use arbitraitor_model::finding::FindingCategory;

    #[test]
    fn identifies_common_shell_scripts() {
        assert_eq!(
            classify(b"#!/bin/bash\necho ok\n").artifact_type,
            ArtifactType::ShellScript(ShellKind::Bash)
        );
        assert_eq!(
            classify(b"#!/bin/sh\necho ok\n").artifact_type,
            ArtifactType::ShellScript(ShellKind::Posix)
        );
        assert_eq!(
            classify(b"#!/usr/bin/env zsh\necho ok\n").artifact_type,
            ArtifactType::ShellScript(ShellKind::Zsh)
        );
    }

    #[test]
    fn identifies_executable_magic_bytes() {
        assert_eq!(
            classify(b"\x7fELF\x02\x01").artifact_type,
            ArtifactType::ElfExecutable
        );
        assert_eq!(
            classify(b"MZ\x90\0").artifact_type,
            ArtifactType::PeExecutable
        );
        assert_eq!(
            classify(b"\xfe\xed\xfa\xcepayload").artifact_type,
            ArtifactType::MachOExecutable
        );
    }

    #[test]
    fn identifies_archive_magic_bytes() {
        assert_eq!(
            classify(b"PK\x03\x04rest").artifact_type,
            ArtifactType::ZipArchive
        );
        assert_eq!(
            classify(b"\x1f\x8b\x08rest").artifact_type,
            ArtifactType::GzipCompressed
        );
        assert_eq!(
            classify(b"\xfd7zXZ\0rest").artifact_type,
            ArtifactType::XzCompressed
        );
        assert_eq!(
            classify(&tar_bytes()).artifact_type,
            ArtifactType::TarArchive
        );
    }

    #[test]
    fn identifies_html_json_and_xml_documents() {
        assert_eq!(
            classify(b"<!DOCTYPE html><html></html>").artifact_type,
            ArtifactType::HtmlDocument
        );
        assert_eq!(
            classify(b"  {\"ok\":true}").artifact_type,
            ArtifactType::JsonDocument
        );
        assert_eq!(
            classify(b"<?xml version=\"1.0\"?>").artifact_type,
            ArtifactType::XmlDocument
        );
    }

    #[test]
    fn classifies_random_binary_as_generic_binary() {
        let result = classify(&[0x00, 0xff, 0x13, 0x37, 0xc0]);
        assert_eq!(result.artifact_type, ArtifactType::GenericBinary);
        assert_eq!(result.detected_encoding, Some(DetectedEncoding::Binary));
    }

    #[test]
    fn classifies_plain_text_as_generic_text() {
        let result = classify(b"plain text\nwith another line\n");
        assert_eq!(result.artifact_type, ArtifactType::GenericText);
        assert_eq!(result.detected_encoding, Some(DetectedEncoding::Ascii));
    }

    #[test]
    fn detects_various_shebang_interpreters() {
        assert_eq!(
            classify(b"#!/usr/bin/env python3\nprint('ok')\n").artifact_type,
            ArtifactType::PythonScript
        );
        assert_eq!(
            classify(b"#!/usr/bin/node\nconsole.log('ok')\n").artifact_type,
            ArtifactType::JavaScript
        );
        assert_eq!(
            classify(b"#!/usr/bin/env pwsh\nWrite-Host ok\n").artifact_type,
            ArtifactType::PowerShellScript
        );
    }

    #[test]
    fn expected_type_mismatch_generates_finding() -> Result<(), Box<dyn std::error::Error>> {
        let (classification, finding) = classify_with_expected(
            b"#!/usr/bin/env python3\nprint('ok')\n",
            Some(ArtifactType::ShellScript(ShellKind::Bash)),
        );

        assert_eq!(classification.artifact_type, ArtifactType::PythonScript);
        let finding = finding.ok_or("mismatch should emit a finding")?;
        assert_eq!(finding.category, FindingCategory::ContentMismatch);
        assert_eq!(finding.detector, "arbitraitor-artifact");
        Ok(())
    }

    #[test]
    fn matching_expected_type_does_not_generate_finding() {
        let (_, finding) = classify_with_expected(
            b"#!/bin/bash\necho ok\n",
            Some(ArtifactType::ShellScript(ShellKind::Bash)),
        );

        assert!(finding.is_none());
    }

    fn tar_bytes() -> Vec<u8> {
        let mut data = vec![0_u8; 512];
        data[257..262].copy_from_slice(b"ustar");
        data
    }
}
