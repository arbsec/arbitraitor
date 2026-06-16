//! Verifier trait and minisign-backed implementation.

use minisign_verify::{PublicKey, Signature};
use sha2::{Digest, Sha256};

use crate::error::UpdateError;
use crate::manifest::{UpdateManifest, UpdateTarget};

/// Abstraction for signed update manifest and target verification.
pub trait UpdateVerifier: Send + Sync {
    /// Verify the manifest signature and return the parsed manifest.
    ///
    /// # Errors
    ///
    /// Returns an error when the signature is missing or invalid, or when the
    /// signed manifest bytes cannot be parsed as update metadata.
    fn verify_manifest(
        &self,
        manifest_bytes: &[u8],
        signature: &[u8],
    ) -> Result<UpdateManifest, UpdateError>;

    /// Check that the new manifest version is newer than the current one.
    ///
    /// # Errors
    ///
    /// Returns an error when `new_manifest` is not newer than
    /// `current_version`.
    fn check_rollback(
        &self,
        new_manifest: &UpdateManifest,
        current_version: u64,
    ) -> Result<(), UpdateError>;

    /// Check that the manifest has not expired at the supplied ISO 8601 time.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest expiration is less than or equal to
    /// `current_time`.
    fn check_freshness(
        &self,
        manifest: &UpdateManifest,
        current_time: &str,
    ) -> Result<(), UpdateError>;

    /// Verify a downloaded target matches its declared SHA-256 and size.
    ///
    /// # Errors
    ///
    /// Returns an error when the content length or SHA-256 digest differs from
    /// the target declaration.
    fn verify_target(&self, target: &UpdateTarget, content: &[u8]) -> Result<(), UpdateError>;
}

/// Minisign-backed update verifier using a pinned public key.
#[derive(Clone, Debug)]
pub struct MinisignVerifier {
    public_key: PublicKey,
}

impl MinisignVerifier {
    /// Construct a verifier from a minisign public key file or base64 public key.
    ///
    /// # Errors
    ///
    /// Returns an error when `public_key` is not UTF-8 or cannot be decoded as
    /// minisign public key material.
    pub fn new(public_key: &[u8]) -> Result<Self, UpdateError> {
        let public_key_text =
            std::str::from_utf8(public_key).map_err(|error| UpdateError::VerifierUnavailable {
                reason: format!("public key is not UTF-8: {error}"),
            })?;
        let trimmed = public_key_text.trim();
        let parsed = if trimmed.contains('\n') {
            PublicKey::decode(trimmed)
        } else {
            PublicKey::from_base64(trimmed)
        }
        .map_err(|error| UpdateError::VerifierUnavailable {
            reason: format!("could not parse minisign public key: {error}"),
        })?;

        Ok(Self { public_key: parsed })
    }
}

impl UpdateVerifier for MinisignVerifier {
    fn verify_manifest(
        &self,
        manifest_bytes: &[u8],
        signature: &[u8],
    ) -> Result<UpdateManifest, UpdateError> {
        if signature.is_empty() {
            return Err(UpdateError::SignatureMissing {
                manifest_version: manifest_version_for_error(manifest_bytes),
            });
        }

        let decoded_signature = decode_signature(signature)?;
        self.public_key
            .verify(manifest_bytes, &decoded_signature, false)
            .map_err(|error| UpdateError::SignatureInvalid {
                reason: error.to_string(),
            })?;

        parse_manifest(manifest_bytes)
    }

    fn check_rollback(
        &self,
        new_manifest: &UpdateManifest,
        current_version: u64,
    ) -> Result<(), UpdateError> {
        if new_manifest.manifest_version <= current_version {
            return Err(UpdateError::VersionRollback {
                current: current_version,
                attempted: new_manifest.manifest_version,
            });
        }
        Ok(())
    }

    fn check_freshness(
        &self,
        manifest: &UpdateManifest,
        current_time: &str,
    ) -> Result<(), UpdateError> {
        if manifest.expires_at.as_str() <= current_time {
            return Err(UpdateError::ManifestExpired {
                expired_at: manifest.expires_at.clone(),
            });
        }
        Ok(())
    }

    fn verify_target(&self, target: &UpdateTarget, content: &[u8]) -> Result<(), UpdateError> {
        let actual_size =
            u64::try_from(content.len()).map_err(|error| UpdateError::ManifestMalformed {
                reason: format!("target content length cannot fit into u64: {error}"),
            })?;
        if actual_size != target.size {
            return Err(UpdateError::ManifestMalformed {
                reason: format!(
                    "target {} size mismatch: expected {}, got {}",
                    target.path, target.size, actual_size
                ),
            });
        }

        let actual_hash = hex::encode(Sha256::digest(content));
        if !actual_hash.eq_ignore_ascii_case(&target.sha256) {
            return Err(UpdateError::ManifestMalformed {
                reason: format!("target {} SHA-256 mismatch", target.path),
            });
        }
        Ok(())
    }
}

fn parse_manifest(manifest_bytes: &[u8]) -> Result<UpdateManifest, UpdateError> {
    serde_json::from_slice(manifest_bytes).map_err(|error| UpdateError::ManifestMalformed {
        reason: error.to_string(),
    })
}

fn decode_signature(signature: &[u8]) -> Result<Signature, UpdateError> {
    let signature_text =
        std::str::from_utf8(signature).map_err(|error| UpdateError::SignatureInvalid {
            reason: format!("signature is not UTF-8: {error}"),
        })?;
    Signature::decode(signature_text).map_err(|error| UpdateError::SignatureInvalid {
        reason: error.to_string(),
    })
}

fn manifest_version_for_error(manifest_bytes: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(manifest_bytes)
        .ok()
        .and_then(|value| {
            value
                .get("manifest_version")
                .and_then(serde_json::Value::as_u64)
        })
        .map_or_else(|| "unknown".to_owned(), |version| version.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::UpdateChannel;

    const PUBLIC_KEY: &str = "RURBUkJJVFIwMQOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
    const MANIFEST: &str = r#"{"schema_version":1,"manifest_version":7,"channel":"rule_packs","targets":[{"path":"rules/core.yar","sha256":"3cfe5c044c1050206b76c938a3b5645d9c6ad975748b078516f871bbb384875b","size":12,"target_version":"1.2.3"}],"published_at":"2026-06-16T00:00:00Z","expires_at":"2026-12-31T23:59:59Z","publisher":"test-key"}"#;
    const SIGNATURE: &str = "untrusted comment: signature from test key\nRURBUkJJVFIwMQLTrE979YgTD/u0YhZ+6KOK0WBQqxYrYqIbIJIjfun7uU3acA7vV4Xn3bk9slZUp93r78OYrtq4HG/pf82ANwc=\ntrusted comment: timestamp:1782863999\tfile:manifest.json\tprehashed\nCstT1+4h98eD0tBzXYCEXBiNYga7AuiSuQOROalhfZ9JHdcFCgKU83Cemo5uA8M7Y1LcvlviV0ZRSqo+5f/8AA==";

    #[test]
    fn verifies_signed_manifest() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = MinisignVerifier::new(PUBLIC_KEY.as_bytes())?;
        let manifest = verifier.verify_manifest(MANIFEST.as_bytes(), SIGNATURE.as_bytes())?;
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.manifest_version, 7);
        assert_eq!(manifest.channel, UpdateChannel::RulePacks);
        assert_eq!(manifest.targets.len(), 1);
        verifier.check_rollback(&manifest, 6)?;
        verifier.check_freshness(&manifest, "2026-06-16T00:00:01Z")?;
        verifier.verify_target(&manifest.targets[0], b"rule-content")?;
        Ok(())
    }

    #[test]
    fn rejects_tampered_manifest_signature() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = MinisignVerifier::new(PUBLIC_KEY.as_bytes())?;
        let tampered = MANIFEST.replace("1.2.3", "9.9.9");
        let error = verifier
            .verify_manifest(tampered.as_bytes(), SIGNATURE.as_bytes())
            .err();
        assert!(matches!(error, Some(UpdateError::SignatureInvalid { .. })));
        Ok(())
    }

    #[test]
    fn rejects_rollback_manifest_version() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = MinisignVerifier::new(PUBLIC_KEY.as_bytes())?;
        let manifest = verifier.verify_manifest(MANIFEST.as_bytes(), SIGNATURE.as_bytes())?;
        let error = verifier.check_rollback(&manifest, 7).err();
        assert!(matches!(
            error,
            Some(UpdateError::VersionRollback {
                current: 7,
                attempted: 7
            })
        ));
        Ok(())
    }

    #[test]
    fn rejects_expired_manifest() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = MinisignVerifier::new(PUBLIC_KEY.as_bytes())?;
        let manifest = verifier.verify_manifest(MANIFEST.as_bytes(), SIGNATURE.as_bytes())?;
        let error = verifier
            .check_freshness(&manifest, "2027-01-01T00:00:00Z")
            .err();
        assert!(matches!(
            error,
            Some(UpdateError::ManifestExpired { expired_at })
                if expired_at == "2026-12-31T23:59:59Z"
        ));
        Ok(())
    }

    #[test]
    fn rejects_target_hash_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = MinisignVerifier::new(PUBLIC_KEY.as_bytes())?;
        let manifest = verifier.verify_manifest(MANIFEST.as_bytes(), SIGNATURE.as_bytes())?;
        let error = verifier
            .verify_target(&manifest.targets[0], b"wrong-content")
            .err();
        assert!(matches!(error, Some(UpdateError::ManifestMalformed { .. })));
        Ok(())
    }
}
