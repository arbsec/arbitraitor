//! Receipt signing trait and adapters (spec §31.3).
//!
//! The [`ReceiptSigner`] trait abstracts over signing backends so receipts can
//! be signed by minisign (default), Sigstore/cosign, a local enterprise key,
//! or a TPM-backed key in later releases. Each adapter produces a [`Signature`]
//! that is embedded in the receipt's `signatures` field (ADR-0014).
//!
//! The canonical bytes passed to [`ReceiptSigner::sign`] are the RFC 8785 JCS
//! canonicalization of the receipt with all signature fields cleared
//! ([`Receipt::unsigned_canonical_bytes`]), preventing recursive signatures.

use std::io::Cursor;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Receipt signing method (spec §31.3).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningMethod {
    /// minisign Ed25519 with `BLAKE2b` prehashing (default adapter).
    Minisign,
    /// Sigstore/cosign keyless or key-based signing.
    Cosign,
    /// Local enterprise signing key (PKCS#11 or similar).
    EnterpriseKey,
    /// TPM-backed signing key (stubbed for later releases).
    Tpm,
}

impl FromStr for SigningMethod {
    type Err = SignerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "minisign" => Ok(Self::Minisign),
            "cosign" => Ok(Self::Cosign),
            "enterprisekey" | "enterprise-key" => Ok(Self::EnterpriseKey),
            "tpm" => Ok(Self::Tpm),
            _ => Err(SignerError::NotImplemented {
                method: s.to_owned(),
            }),
        }
    }
}

/// A receipt signature produced by a [`ReceiptSigner`].
///
/// Stored in [`Receipt::signatures`](crate::Receipt::signatures) and serialized
/// as part of the receipt JSON. The signature is computed over the RFC 8785
/// JCS canonical bytes of the receipt with all signature fields cleared
/// (ADR-0014).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// Signing method that produced this signature.
    pub method: SigningMethod,
    /// Key identifier as uppercase hexadecimal, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Raw signature bytes (format depends on `method`).
    pub signature: Vec<u8>,
}

/// Errors produced by receipt signers.
#[derive(Debug, Error)]
pub enum SignerError {
    /// Signing operation failed.
    #[error("receipt signing failed: {reason}")]
    Sign {
        /// Safe diagnostic reason for the signing failure.
        reason: String,
    },
    /// Requested signing method is not yet implemented.
    #[error("signing method {method} is not yet implemented")]
    NotImplemented {
        /// Name of the unimplemented signing method.
        method: String,
    },
}

/// Trait for receipt signing adapters (spec §31.3).
///
/// Implementations receive the RFC 8785 JCS canonical bytes of the unsigned
/// receipt and return a [`Signature`] to embed in the receipt. The trait is
/// `Send + Sync` so signers can be used from async contexts.
pub trait ReceiptSigner: Send + Sync {
    /// Sign the canonical receipt bytes and return a [`Signature`].
    ///
    /// # Errors
    ///
    /// Returns [`SignerError`] if the signing operation fails or the method
    /// is not yet implemented.
    fn sign(&self, canonical_bytes: &[u8]) -> Result<Signature, SignerError>;

    /// Returns the signing method this adapter implements.
    fn method(&self) -> SigningMethod;
}

/// Minisign receipt signer (spec §31.3, default adapter).
///
/// Wraps a [`minisign::KeyPair`] and signs receipt canonical bytes using
/// minisign's Ed25519 + `BLAKE2b` prehash signature scheme. The resulting
/// signature box bytes are stored in [`Signature::signature`].
pub struct MinisignSigner {
    key_pair: minisign::KeyPair,
}

impl MinisignSigner {
    /// Creates a new minisign signer from a key pair.
    #[must_use]
    pub fn new(key_pair: minisign::KeyPair) -> Self {
        Self { key_pair }
    }

    /// Returns the minisign key identifier as uppercase hexadecimal.
    #[must_use]
    pub fn key_id(&self) -> String {
        hex_upper(self.key_pair.pk.keynum())
    }
}

impl ReceiptSigner for MinisignSigner {
    fn sign(&self, canonical_bytes: &[u8]) -> Result<Signature, SignerError> {
        let signature = minisign::sign(
            Some(&self.key_pair.pk),
            &self.key_pair.sk,
            Cursor::new(canonical_bytes),
            Some("arbitraitor receipt"),
            Some("signature from arbitraitor receipt key"),
        )
        .map_err(|error| SignerError::Sign {
            reason: error.to_string(),
        })?;

        Ok(Signature {
            method: SigningMethod::Minisign,
            key_id: Some(hex_upper(self.key_pair.pk.keynum())),
            signature: signature.to_bytes(),
        })
    }

    fn method(&self) -> SigningMethod {
        SigningMethod::Minisign
    }
}

/// Stub signer for not-yet-implemented signing methods.
///
/// Returns [`SignerError::NotImplemented`] for any signing attempt. Used as
/// the default adapter for `Cosign`, `EnterpriseKey`, and `Tpm` methods until
/// full implementations are available.
pub struct StubSigner {
    method: SigningMethod,
}

impl StubSigner {
    /// Creates a stub signer for the given method.
    #[must_use]
    pub const fn new(method: SigningMethod) -> Self {
        Self { method }
    }
}

impl ReceiptSigner for StubSigner {
    fn sign(&self, _canonical_bytes: &[u8]) -> Result<Signature, SignerError> {
        Err(SignerError::NotImplemented {
            method: format!("{:?}", self.method).to_lowercase(),
        })
    }

    fn method(&self) -> SigningMethod {
        self.method
    }
}

/// Selects a signer for the given [`SigningMethod`].
///
/// `Minisign` returns a [`MinisignSigner`] when a key pair is supplied.
/// All other methods return a [`StubSigner`] that errors with
/// [`SignerError::NotImplemented`].
#[must_use]
pub fn select_signer(
    method: SigningMethod,
    minisign_key: Option<&minisign::KeyPair>,
) -> Box<dyn ReceiptSigner> {
    match method {
        SigningMethod::Minisign => match minisign_key {
            Some(key_pair) => Box::new(MinisignSigner::new(key_pair.clone())),
            None => Box::new(StubSigner::new(SigningMethod::Minisign)),
        },
        SigningMethod::Cosign => Box::new(StubSigner::new(SigningMethod::Cosign)),
        SigningMethod::EnterpriseKey => Box::new(StubSigner::new(SigningMethod::EnterpriseKey)),
        SigningMethod::Tpm => Box::new(StubSigner::new(SigningMethod::Tpm)),
    }
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02X}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_round_trips_with_minisign_method() -> Result<(), Box<dyn std::error::Error>> {
        let signature = Signature {
            method: SigningMethod::Minisign,
            key_id: Some("ABCD1234".to_owned()),
            signature: vec![0_u8, 1, 2, 3],
        };
        let json = serde_json::to_string(&signature)?;
        let decoded: Signature = serde_json::from_str(&json)?;
        assert_eq!(decoded, signature);
        assert_eq!(decoded.method, SigningMethod::Minisign);
        Ok(())
    }

    #[test]
    fn signature_round_trips_with_tpm_method() -> Result<(), Box<dyn std::error::Error>> {
        let signature = Signature {
            method: SigningMethod::Tpm,
            key_id: None,
            signature: vec![0xFF; 32],
        };
        let json = serde_json::to_string(&signature)?;
        let decoded: Signature = serde_json::from_str(&json)?;
        assert_eq!(decoded, signature);
        Ok(())
    }

    #[test]
    fn signature_serializes_method_as_lowercase() -> Result<(), Box<dyn std::error::Error>> {
        let signature = Signature {
            method: SigningMethod::EnterpriseKey,
            key_id: None,
            signature: Vec::new(),
        };
        let json = serde_json::to_string(&signature)?;
        assert!(json.contains("\"enterprisekey\""));
        Ok(())
    }

    #[test]
    fn signature_omits_key_id_when_none() -> Result<(), Box<dyn std::error::Error>> {
        let signature = Signature {
            method: SigningMethod::Cosign,
            key_id: None,
            signature: Vec::new(),
        };
        let json = serde_json::to_string(&signature)?;
        assert!(!json.contains("key_id"));
        Ok(())
    }

    #[test]
    fn signature_rejects_unknown_fields() {
        let json = r#"{"method":"minisign","key_id":null,"signature":[],"extra":true}"#;
        assert!(serde_json::from_str::<Signature>(json).is_err());
    }

    #[test]
    fn signing_method_round_trips_all_variants() -> Result<(), Box<dyn std::error::Error>> {
        for method in [
            SigningMethod::Minisign,
            SigningMethod::Cosign,
            SigningMethod::EnterpriseKey,
            SigningMethod::Tpm,
        ] {
            let json = serde_json::to_string(&method)?;
            let decoded: SigningMethod = serde_json::from_str(&json)?;
            assert_eq!(decoded, method);
        }
        Ok(())
    }

    #[test]
    fn minisign_signer_produces_verifiable_signature() -> Result<(), Box<dyn std::error::Error>> {
        let key = minisign::KeyPair::generate_unencrypted_keypair()?;
        let signer = MinisignSigner::new(key.clone());
        let message = b"canonical receipt bytes";
        let signature = signer.sign(message)?;

        assert_eq!(signature.method, SigningMethod::Minisign);
        assert_eq!(signature.key_id, Some(hex_upper(key.pk.keynum())));
        assert!(!signature.signature.is_empty());

        // Verify the signature round-trips through minisign verification.
        let signature_text = std::str::from_utf8(&signature.signature)?;
        let signature_box = minisign::SignatureBox::from_string(signature_text)?;
        minisign::verify(
            &key.pk,
            &signature_box,
            Cursor::new(message),
            true,
            false,
            false,
        )?;
        Ok(())
    }

    #[test]
    fn stub_signer_returns_not_implemented() {
        let stub = StubSigner::new(SigningMethod::Cosign);
        let result = stub.sign(b"test");
        assert!(matches!(result, Err(SignerError::NotImplemented { .. })));
        assert_eq!(stub.method(), SigningMethod::Cosign);
    }

    #[test]
    fn select_signer_returns_stub_for_unimplemented_methods() {
        for method in [
            SigningMethod::Cosign,
            SigningMethod::EnterpriseKey,
            SigningMethod::Tpm,
        ] {
            let signer = select_signer(method, None);
            assert_eq!(signer.method(), method);
            assert!(matches!(
                signer.sign(b"test"),
                Err(SignerError::NotImplemented { .. })
            ));
        }
    }

    #[test]
    fn select_signer_returns_stub_for_minisign_without_key() {
        let signer = select_signer(SigningMethod::Minisign, None);
        assert_eq!(signer.method(), SigningMethod::Minisign);
        assert!(matches!(
            signer.sign(b"test"),
            Err(SignerError::NotImplemented { .. })
        ));
    }

    #[test]
    fn select_signer_returns_minisign_signer_with_key() -> Result<(), Box<dyn std::error::Error>> {
        let key = minisign::KeyPair::generate_unencrypted_keypair()?;
        let signer = select_signer(SigningMethod::Minisign, Some(&key));
        assert_eq!(signer.method(), SigningMethod::Minisign);
        let signature = signer.sign(b"test")?;
        assert_eq!(signature.method, SigningMethod::Minisign);
        Ok(())
    }

    /// Mock signer for testing receipt signing integration.
    struct MockSigner {
        method: SigningMethod,
    }

    impl ReceiptSigner for MockSigner {
        fn sign(&self, canonical_bytes: &[u8]) -> Result<Signature, SignerError> {
            Ok(Signature {
                method: self.method,
                key_id: Some("mock-key".to_owned()),
                signature: canonical_bytes.to_vec(),
            })
        }

        fn method(&self) -> SigningMethod {
            self.method
        }
    }

    #[test]
    fn mock_signer_echoes_canonical_bytes() -> Result<(), SignerError> {
        let signer = MockSigner {
            method: SigningMethod::EnterpriseKey,
        };
        let bytes = b"test canonical bytes";
        let signature = signer.sign(bytes)?;
        assert_eq!(signature.method, SigningMethod::EnterpriseKey);
        assert_eq!(signature.key_id, Some("mock-key".to_owned()));
        assert_eq!(signature.signature, bytes);
        Ok(())
    }
}
