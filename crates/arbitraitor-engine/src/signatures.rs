//! Engine-owned provenance verification inputs (ADR-0038).
//!
//! Signature inputs are configured once on [`crate::ArbitraitorBuilder`] and
//! verified against the fetched artifact bytes on every inspection. This is
//! the provenance stage of the consolidated pipeline: consumers that
//! previously skipped it (daemon, MCP) now run it by default, with an empty
//! input set when no signatures are pinned.

use std::path::PathBuf;

use arbitraitor_provenance::{SignatureVerification, verify_cosign, verify_minisign};

/// A minisign detached signature plus its trusted public key.
#[derive(Clone, Debug)]
pub struct MinisignSignatureInput {
    /// Path to the detached `.minisig` signature file.
    pub signature_path: PathBuf,
    /// Minisign public key (base64 or public-key box form).
    pub public_key: String,
}

/// A Sigstore/cosign bundle plus the identity it must certify.
#[derive(Clone, Debug)]
pub struct CosignBundleInput {
    /// Path to the Sigstore bundle JSON file.
    pub bundle_path: PathBuf,
    /// Required signer identity (e.g. `builder@example.com`).
    pub identity: String,
    /// Required identity issuer (e.g. `https://token.actions.githubusercontent.com`).
    pub issuer: String,
}

/// Provenance verification inputs collected from consumer configuration.
#[derive(Clone, Debug, Default)]
pub struct SignatureInputs {
    /// Detached minisign signatures to verify.
    pub minisign: Vec<MinisignSignatureInput>,
    /// Sigstore/cosign bundles to verify.
    pub cosign: Vec<CosignBundleInput>,
}

impl SignatureInputs {
    /// Returns `true` when no signature verification is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.minisign.is_empty() && self.cosign.is_empty()
    }

    /// Verifies every configured signature against `artifact_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::EngineError::Provenance`] when any signature file
    /// cannot be read, a public key cannot be parsed, or verification fails.
    /// Fail-closed: a requested verification never degrades to "skipped".
    pub fn verify(
        &self,
        artifact_bytes: &[u8],
    ) -> Result<Vec<SignatureVerification>, crate::EngineError> {
        let mut verifications = Vec::with_capacity(self.minisign.len() + self.cosign.len());
        for input in &self.minisign {
            let signature = std::fs::read(&input.signature_path)?;
            let public_key = arbitraitor_provenance::parse_minisign_public_key(&input.public_key)?;
            verifications.push(verify_minisign(artifact_bytes, &signature, &public_key)?);
        }
        for input in &self.cosign {
            verifications.push(verify_cosign(
                artifact_bytes,
                &input.bundle_path,
                &input.identity,
                &input.issuer,
            )?);
        }
        Ok(verifications)
    }
}
