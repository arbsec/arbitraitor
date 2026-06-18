//! Provenance and integrity verification
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::ffi::OsString;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

/// Signature verification system used for an artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureSystem {
    /// Minisign detached Ed25519 signature.
    Minisign,
    /// Sigstore/cosign bundle verification.
    Cosign,
}

impl SignatureSystem {
    /// Stable lower-case label for receipts and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minisign => "minisign",
            Self::Cosign => "cosign",
        }
    }
}

/// Successful signature verification evidence for an artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureVerification {
    /// Signature system that produced this result.
    pub system: SignatureSystem,
    /// Trusted identity required by the caller, if applicable.
    pub trusted_identity: Option<String>,
    /// Whether verification succeeded.
    pub verified: bool,
    /// Identity observed or bound by the signature verification, if applicable.
    pub identity: Option<String>,
}

/// Provenance verification failures.
#[derive(Debug, Error)]
pub enum ProvenanceError {
    /// Minisign public key text was not a valid public key.
    #[error("minisign public key is malformed: {reason}")]
    MalformedMinisignPublicKey {
        /// Safe diagnostic reason.
        reason: String,
    },
    /// Minisign signature bytes were not a valid signature box.
    #[error("minisign signature is malformed: {reason}")]
    MalformedMinisignSignature {
        /// Safe diagnostic reason.
        reason: String,
    },
    /// Minisign verification failed.
    #[error("minisign signature verification failed: {reason}")]
    MinisignVerification {
        /// Safe diagnostic reason.
        reason: String,
    },
    /// Cosign is required but not installed or not executable.
    #[error("cosign executable is not available")]
    CosignUnavailable,
    /// Cosign verification failed.
    #[error("cosign signature verification failed: {reason}")]
    CosignVerification {
        /// Safe diagnostic reason.
        reason: String,
    },
    /// Local I/O failed while preparing verification.
    #[error("I/O failure during {stage}: {source}")]
    Io {
        /// I/O stage.
        stage: &'static str,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

/// Parse a minisign public key from a base64 key or public-key box.
///
/// # Errors
///
/// Returns an error when the key text is neither minisign base64 public key
/// material nor a minisign public-key box.
pub fn parse_minisign_public_key(key_text: &str) -> Result<minisign::PublicKey, ProvenanceError> {
    let trimmed = key_text.trim();
    minisign::PublicKey::from_base64(trimmed).or_else(|base64_error| {
        minisign::PublicKeyBox::from_string(key_text)
            .and_then(minisign::PublicKeyBox::into_public_key)
            .map_err(|box_error| ProvenanceError::MalformedMinisignPublicKey {
                reason: format!("base64: {base64_error}; public-key box: {box_error}"),
            })
    })
}

/// Verify a detached minisign signature over artifact bytes.
///
/// # Errors
///
/// Returns an error when the signature is malformed or verification fails.
pub fn verify_minisign(
    artifact_bytes: &[u8],
    signature: &[u8],
    public_key: &minisign::PublicKey,
) -> Result<SignatureVerification, ProvenanceError> {
    let signature_text = std::str::from_utf8(signature).map_err(|error| {
        ProvenanceError::MalformedMinisignSignature {
            reason: error.to_string(),
        }
    })?;
    let signature_box = minisign::SignatureBox::from_string(signature_text).map_err(|error| {
        ProvenanceError::MalformedMinisignSignature {
            reason: error.to_string(),
        }
    })?;

    minisign::verify(
        public_key,
        &signature_box,
        Cursor::new(artifact_bytes),
        true,
        false,
        false,
    )
    .map_err(|error| ProvenanceError::MinisignVerification {
        reason: error.to_string(),
    })?;

    Ok(SignatureVerification {
        system: SignatureSystem::Minisign,
        trusted_identity: Some(key_id(public_key)),
        verified: true,
        identity: Some(key_id(public_key)),
    })
}

/// Verify a Sigstore/cosign bundle over artifact bytes by invoking `cosign verify-blob`.
///
/// # Errors
///
/// Returns an error when `cosign` is unavailable, verification fails, or the
/// temporary artifact file cannot be prepared.
pub fn verify_cosign(
    artifact_bytes: &[u8],
    bundle_path: &Path,
    identity: &str,
    issuer: &str,
) -> Result<SignatureVerification, ProvenanceError> {
    let artifact_path = TemporaryArtifact::write(artifact_bytes)?;
    verify_cosign_subprocess(artifact_path.path(), bundle_path, identity, issuer)?;
    Ok(SignatureVerification {
        system: SignatureSystem::Cosign,
        trusted_identity: Some(identity.to_owned()),
        verified: true,
        identity: Some(identity.to_owned()),
    })
}

fn verify_cosign_subprocess(
    artifact_path: &Path,
    bundle_path: &Path,
    identity: &str,
    issuer: &str,
) -> Result<(), ProvenanceError> {
    let output = Command::new("cosign")
        .arg("verify-blob")
        .arg("--bundle")
        .arg(bundle_path)
        .arg("--certificate-identity")
        .arg(identity)
        .arg("--certificate-oidc-issuer")
        .arg(issuer)
        .arg(artifact_path)
        .output()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ProvenanceError::CosignUnavailable
            } else {
                ProvenanceError::Io {
                    stage: "run cosign",
                    source: error,
                }
            }
        })?;

    if output.status.success() {
        return Ok(());
    }

    Err(ProvenanceError::CosignVerification {
        reason: bounded_command_output(&output.stderr, &output.stdout),
    })
}

fn bounded_command_output(stderr: &[u8], stdout: &[u8]) -> String {
    const MAX_CHARS: usize = 512;
    let source = if stderr.is_empty() { stdout } else { stderr };
    let text = String::from_utf8_lossy(source);
    let mut bounded: String = text.chars().take(MAX_CHARS).collect();
    if text.chars().count() > MAX_CHARS {
        bounded.push('…');
    }
    if bounded.trim().is_empty() {
        "cosign exited with a non-zero status".to_owned()
    } else {
        bounded.trim().to_owned()
    }
}

fn key_id(public_key: &minisign::PublicKey) -> String {
    let mut output = String::with_capacity(public_key.keynum().len() * 2);
    for byte in public_key.keynum() {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02X}");
    }
    output
}

struct TemporaryArtifact {
    path: PathBuf,
}

impl TemporaryArtifact {
    fn write(bytes: &[u8]) -> Result<Self, ProvenanceError> {
        let mut path = std::env::temp_dir();
        path.push(unique_temp_name());
        fs::write(&path, bytes).map_err(|source| ProvenanceError::Io {
            stage: "write temporary artifact",
            source,
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryArtifact {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn unique_temp_name() -> OsString {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("arbitraitor-cosign-{}-{nanos}.blob", std::process::id()).into()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::Path;
    use std::process::Command;

    use super::{ProvenanceError, SignatureSystem, verify_cosign, verify_minisign};

    #[test]
    fn minisign_verifies_artifact_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let key = minisign::KeyPair::generate_unencrypted_keypair()?;
        let artifact = b"trusted release artifact";
        let signature = minisign::sign(
            Some(&key.pk),
            &key.sk,
            Cursor::new(artifact),
            Some("arbitraitor artifact"),
            Some("signature from artifact producer"),
        )?;

        let verification = verify_minisign(artifact, &signature.to_bytes(), &key.pk)?;

        assert_eq!(verification.system, SignatureSystem::Minisign);
        assert!(verification.verified);
        assert_eq!(verification.identity, verification.trusted_identity);
        Ok(())
    }

    #[test]
    fn minisign_rejects_wrong_key() -> Result<(), Box<dyn std::error::Error>> {
        let signing_key = minisign::KeyPair::generate_unencrypted_keypair()?;
        let wrong_key = minisign::KeyPair::generate_unencrypted_keypair()?;
        let artifact = b"trusted release artifact";
        let signature = minisign::sign(
            Some(&signing_key.pk),
            &signing_key.sk,
            Cursor::new(artifact),
            Some("arbitraitor artifact"),
            Some("signature from artifact producer"),
        )?;

        assert!(matches!(
            verify_minisign(artifact, &signature.to_bytes(), &wrong_key.pk),
            Err(ProvenanceError::MinisignVerification { .. })
        ));
        Ok(())
    }

    #[test]
    fn parses_minisign_base64_public_key() -> Result<(), Box<dyn std::error::Error>> {
        let key = minisign::KeyPair::generate_unencrypted_keypair()?;
        let parsed = super::parse_minisign_public_key(&key.pk.to_base64())?;

        assert_eq!(parsed, key.pk);
        Ok(())
    }

    #[test]
    fn verifies_all_required_minisign_signatures() -> Result<(), Box<dyn std::error::Error>> {
        let first_key = minisign::KeyPair::generate_unencrypted_keypair()?;
        let second_key = minisign::KeyPair::generate_unencrypted_keypair()?;
        let artifact = b"artifact with multiple required signatures";
        let signatures = [
            minisign::sign(
                Some(&first_key.pk),
                &first_key.sk,
                Cursor::new(artifact),
                Some("first"),
                Some("first signer"),
            )?,
            minisign::sign(
                Some(&second_key.pk),
                &second_key.sk,
                Cursor::new(artifact),
                Some("second"),
                Some("second signer"),
            )?,
        ];
        let keys = [&first_key.pk, &second_key.pk];

        let results: Result<Vec<_>, _> = signatures
            .iter()
            .zip(keys)
            .map(|(signature, key)| verify_minisign(artifact, &signature.to_bytes(), key))
            .collect();

        assert_eq!(results?.len(), 2);
        Ok(())
    }

    #[test]
    fn cosign_test_is_conditional_on_installed_binary() {
        if Command::new("cosign").arg("version").output().is_err() {
            return;
        }

        let result = verify_cosign(
            b"artifact bytes",
            Path::new("/definitely/missing/cosign.bundle"),
            "issuer@example.test",
            "https://issuer.example.test",
        );
        assert!(matches!(
            result,
            Err(ProvenanceError::CosignVerification { .. } | ProvenanceError::Io { .. })
        ));
    }
}
