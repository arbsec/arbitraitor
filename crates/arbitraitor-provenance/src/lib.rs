//! Provenance and integrity verification
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use arbitraitor_model::ids::Sha256Digest;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;

/// Result type for provenance operations.
pub type Result<T, E = ProvenanceError> = std::result::Result<T, E>;

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
    /// Sigstore bundle metadata (spec §14.2.1), present when the bundle
    /// was parsed as JSON to extract v0.3 profile information.
    pub sigstore_bundle: Option<SigstoreBundleMetadata>,
}

/// Sigstore Bundle media types accepted by Arbitraitor (spec §14.2.1).
pub const SIGSTORE_BUNDLE_MEDIA_TYPES: &[&str] = &[
    "application/vnd.dev.sigstore.bundle+json;version=0.1",
    "application/vnd.dev.sigstore.bundle+json;version=0.2",
    "application/vnd.dev.sigstore.bundle+json;version=0.3",
];

/// The form of verification material in a Sigstore bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMaterialForm {
    /// `X509CertificateChain` (form 1).
    X509CertificateChain,
    /// `PublicKey` (form 2).
    PublicKey,
    /// Single `X509Certificate` (form 3, required for v0.3 keyless).
    X509Certificate,
}

/// The verification mode used for the bundle (spec §14.2.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigstoreVerificationMode {
    /// Offline verification using Rekor inclusion proofs in the bundle.
    Offline,
    /// Online verification querying Rekor.
    Online,
}

/// Metadata extracted from a Sigstore Bundle per spec §14.2.1.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigstoreBundleMetadata {
    /// Bundle media type (e.g. `application/vnd.dev.sigstore.bundle+json;version=0.3`).
    pub media_type: String,
    /// Form of the verification material (1, 2, or 3).
    pub verification_material_form: VerificationMaterialForm,
    /// Number of transparency log entries in the bundle.
    pub tlog_entries: usize,
    /// Number of RFC 3161 timestamps in the bundle.
    pub rfc3161_timestamps: usize,
    /// Whether identity/issuer matched local policy.
    pub identity_match: bool,
    /// Whether the OIDC issuer matched local policy.
    pub issuer_match: bool,
    /// Verification mode used.
    pub verification_mode: SigstoreVerificationMode,
    /// SHA-256 of the bundle file itself.
    pub bundle_sha256: Sha256Digest,
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
    /// JSON serialization or parsing failed.
    #[error("JSON failure during {stage}: {source}")]
    Json {
        /// JSON stage.
        stage: &'static str,
        /// Underlying JSON error.
        source: serde_json::Error,
    },
    /// TUF metadata version moved backward relative to locally stored state.
    #[error("TUF {role} metadata rollback rejected: stored version {stored}, new version {new}")]
    TufRollback {
        /// TUF role name.
        role: String,
        /// Locally stored version.
        stored: u32,
        /// Candidate metadata version.
        new: u32,
    },
    /// TUF metadata is expired at the caller-provided wall-clock time.
    #[error("TUF {role} metadata expired at {expires}; current time is {now}")]
    TufExpired {
        /// TUF role name.
        role: String,
        /// Expiration timestamp from metadata.
        expires: String,
        /// Current timestamp supplied by caller.
        now: String,
    },
    /// TUF root metadata did not define the requested role.
    #[error("TUF root metadata does not define role {role}")]
    TufUnknownRole {
        /// Missing TUF role name.
        role: String,
    },
    /// TUF role signature threshold was not met.
    #[error("TUF {role} threshold not met: need {threshold}, got {verified}")]
    TufThreshold {
        /// TUF role name.
        role: String,
        /// Required unique verified signatures.
        threshold: u32,
        /// Unique verified signatures from authorized keys.
        verified: u32,
    },
}

/// Trust-on-first-use pin database backed by a local JSON file.
///
/// TOFU is **not cryptographic verification**. It records the artifact identity
/// first observed at a URL and reports later drift; callers must not present a
/// TOFU match as a signature, provenance, or trust-root verification result.
#[derive(Clone, Debug)]
pub struct TofuStore {
    path: PathBuf,
    pins: HashMap<String, TofuPin>,
}

/// Artifact identity recorded by trust-on-first-use mode.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TofuPin {
    /// Artifact URL used as the TOFU lookup key.
    pub url: String,
    /// Artifact SHA-256 digest observed for the URL.
    pub sha256: Sha256Digest,
    /// Optional signer identity observed by independent signature verification.
    pub signer_identity: Option<String>,
    /// Optional HTTP content type observed at retrieval time.
    pub content_type: Option<String>,
    /// Optional content size in bytes.
    pub size: Option<u64>,
    /// Timestamp when the pin was first recorded.
    pub first_seen: String,
}

/// Trust-on-first-use comparison result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TofuVerification {
    /// No prior pin exists for the URL.
    FirstUse,
    /// The actual artifact identity matches the stored pin.
    Matches,
    /// The actual artifact identity differs from the stored pin.
    Changed {
        /// Field-level differences to display prominently to the user.
        changes: Vec<TofuChange>,
    },
}

/// A trust-on-first-use pin difference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TofuChange {
    /// The artifact SHA-256 digest changed.
    DigestChanged {
        /// Pinned digest.
        old: String,
        /// Observed digest.
        new: String,
    },
    /// The signer identity changed.
    SignerChanged {
        /// Pinned signer identity.
        old: String,
        /// Observed signer identity.
        new: String,
    },
    /// The artifact size changed.
    SizeChanged {
        /// Pinned size in bytes.
        old: u64,
        /// Observed size in bytes.
        new: u64,
    },
}

impl TofuStore {
    /// Opens a TOFU store from a JSON file, or creates an empty in-memory store
    /// when the file does not exist yet.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read or parsed.
    pub fn open(path: &Path) -> Result<Self> {
        let pins = match fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|source| ProvenanceError::Json {
                    stage: "parse TOFU store",
                    source,
                })?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(source) => {
                return Err(ProvenanceError::Io {
                    stage: "read TOFU store",
                    source,
                });
            }
        };

        Ok(Self {
            path: path.to_path_buf(),
            pins,
        })
    }

    /// Returns the stored TOFU pin for a URL, if one exists.
    #[must_use]
    pub fn check(&self, url: &str) -> Option<&TofuPin> {
        self.pins.get(url)
    }

    /// Records or replaces the TOFU pin for a URL and persists the JSON store.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be serialized or written.
    pub fn pin(&mut self, url: &str, mut pin: TofuPin) -> Result<()> {
        url.clone_into(&mut pin.url);
        self.pins.insert(url.to_owned(), pin);
        self.persist()
    }

    /// Compares an actual artifact identity against a stored TOFU pin.
    ///
    /// TOFU comparison is **not cryptographic verification**; [`Self::pin`]
    /// only stores local history. A `Matches` result means "unchanged since
    /// first use", not "trusted" or "signed".
    ///
    /// # Errors
    ///
    /// This method is currently infallible but returns [`ProvenanceError`] so
    /// callers can use the same error channel as other provenance checks.
    pub fn verify_against_pin(
        &self,
        url: &str,
        actual: &TofuPin,
    ) -> Result<TofuVerification, ProvenanceError> {
        let Some(stored) = self.check(url) else {
            return Ok(TofuVerification::FirstUse);
        };

        let mut changes = Vec::new();
        if stored.sha256 != actual.sha256 {
            changes.push(TofuChange::DigestChanged {
                old: stored.sha256.to_string(),
                new: actual.sha256.to_string(),
            });
        }
        if stored.signer_identity != actual.signer_identity {
            changes.push(TofuChange::SignerChanged {
                old: stored.signer_identity.clone().unwrap_or_default(),
                new: actual.signer_identity.clone().unwrap_or_default(),
            });
        }
        if let (Some(old), Some(new)) = (stored.size, actual.size)
            && old != new
        {
            changes.push(TofuChange::SizeChanged { old, new });
        }

        if changes.is_empty() {
            Ok(TofuVerification::Matches)
        } else {
            Ok(TofuVerification::Changed { changes })
        }
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|source| ProvenanceError::Io {
                stage: "create TOFU store directory",
                source,
            })?;
        }
        let bytes =
            serde_json::to_vec_pretty(&self.pins).map_err(|source| ProvenanceError::Json {
                stage: "serialize TOFU store",
                source,
            })?;
        fs::write(&self.path, bytes).map_err(|source| ProvenanceError::Io {
            stage: "write TOFU store",
            source,
        })
    }
}

/// Simplified TUF root metadata for MVP update security.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TufRoot {
    /// Monotonically increasing root metadata version.
    pub version: u32,
    /// Expiration timestamp, compared lexicographically as RFC 3339 UTC text.
    pub expires: String,
    /// Public keys known to root metadata.
    pub keys: Vec<TufKey>,
    /// Role signature policies keyed by role name.
    pub roles: HashMap<String, TufRole>,
    /// Whether target paths use consistent-snapshot naming.
    pub consistent_snapshot: bool,
}

/// Simplified TUF public key descriptor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TufKey {
    /// Stable key identifier used in role metadata.
    pub key_id: String,
    /// Key type, for example `ed25519`.
    pub key_type: String,
    /// Signature scheme, for example `minisign`.
    pub scheme: String,
    /// Encoded public key material.
    pub value: String,
}

/// Simplified TUF role threshold policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TufRole {
    /// Authorized key identifiers for this role.
    pub key_ids: Vec<String>,
    /// Number of unique authorized signatures required.
    pub threshold: u32,
}

/// Simplified TUF targets metadata.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TufTargets {
    /// Monotonically increasing targets metadata version.
    pub version: u32,
    /// Expiration timestamp, compared lexicographically as RFC 3339 UTC text.
    pub expires: String,
    /// Target metadata keyed by target path.
    pub targets: HashMap<String, TufTarget>,
}

/// Simplified TUF target descriptor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TufTarget {
    /// Target SHA-256 digest as lowercase hex text.
    pub sha256: String,
    /// Target size in bytes.
    pub size: u64,
    /// Optional application-specific target metadata.
    pub custom: Option<serde_json::Value>,
}

/// Simplified TUF snapshot metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TufSnapshot {
    /// Monotonically increasing snapshot metadata version.
    pub version: u32,
    /// Expiration timestamp, compared lexicographically as RFC 3339 UTC text.
    pub expires: String,
    /// Referenced metadata files keyed by metadata path.
    pub meta: HashMap<String, TufMetaFile>,
}

/// Simplified TUF timestamp metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TufTimestamp {
    /// Monotonically increasing timestamp metadata version.
    pub version: u32,
    /// Expiration timestamp, compared lexicographically as RFC 3339 UTC text.
    pub expires: String,
    /// Snapshot metadata file referenced by timestamp metadata.
    pub snapshot: TufMetaFile,
}

/// Metadata file descriptor used by simplified snapshot and timestamp roles.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TufMetaFile {
    /// Referenced metadata version.
    pub version: u32,
    /// Referenced metadata SHA-256 digest as lowercase hex text.
    pub sha256: String,
    /// Referenced metadata size in bytes.
    pub size: u64,
}

/// A verified signature key identifier for simplified TUF threshold counting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TufSignature {
    /// Key identifier whose cryptographic signature was verified by the caller.
    pub key_id: String,
}

/// Local TUF role-version state used for rollback protection.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TufVersionStore {
    versions: HashMap<String, u32>,
}

impl TufRoot {
    /// Verifies that a role has enough unique signatures from authorized keys.
    ///
    /// This is threshold policy checking only; callers must cryptographically
    /// verify each signature before passing its key identifier here.
    ///
    /// # Errors
    ///
    /// Returns an error when the role is undefined or the threshold is not met.
    pub fn verify_role_threshold(
        &self,
        role_name: &str,
        signatures: &[TufSignature],
    ) -> Result<()> {
        let role = self
            .roles
            .get(role_name)
            .ok_or_else(|| ProvenanceError::TufUnknownRole {
                role: role_name.to_owned(),
            })?;
        role.verify_threshold(role_name, signatures)
    }
}

impl TufRole {
    /// Verifies that enough unique authorized keys signed this role metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the threshold is not met.
    pub fn verify_threshold(&self, role_name: &str, signatures: &[TufSignature]) -> Result<()> {
        let authorized: HashSet<&str> = self.key_ids.iter().map(String::as_str).collect();
        let verified = signatures
            .iter()
            .filter_map(|signature| {
                let key_id = signature.key_id.as_str();
                authorized.contains(key_id).then_some(key_id)
            })
            .collect::<HashSet<_>>()
            .len();
        let verified = u32::try_from(verified).unwrap_or(u32::MAX);

        if self.threshold > 0 && verified >= self.threshold {
            Ok(())
        } else {
            Err(ProvenanceError::TufThreshold {
                role: role_name.to_owned(),
                threshold: self.threshold,
                verified,
            })
        }
    }
}

impl TufRoot {
    /// Rejects this root metadata when its expiration timestamp is not after `now`.
    ///
    /// # Errors
    ///
    /// Returns an error when the metadata is expired.
    pub fn ensure_not_expired(&self, now: &str) -> Result<()> {
        ensure_tuf_not_expired("root", &self.expires, now)
    }
}

impl TufTargets {
    /// Rejects this targets metadata when its expiration timestamp is not after `now`.
    ///
    /// # Errors
    ///
    /// Returns an error when the metadata is expired.
    pub fn ensure_not_expired(&self, now: &str) -> Result<()> {
        ensure_tuf_not_expired("targets", &self.expires, now)
    }
}

impl TufSnapshot {
    /// Rejects this snapshot metadata when its expiration timestamp is not after `now`.
    ///
    /// # Errors
    ///
    /// Returns an error when the metadata is expired.
    pub fn ensure_not_expired(&self, now: &str) -> Result<()> {
        ensure_tuf_not_expired("snapshot", &self.expires, now)
    }
}

impl TufTimestamp {
    /// Rejects this timestamp metadata when its expiration timestamp is not after `now`.
    ///
    /// # Errors
    ///
    /// Returns an error when the metadata is expired.
    pub fn ensure_not_expired(&self, now: &str) -> Result<()> {
        ensure_tuf_not_expired("timestamp", &self.expires, now)
    }
}

impl TufVersionStore {
    /// Creates an empty in-memory rollback-protection store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the stored version for a role, if present.
    #[must_use]
    pub fn stored_version(&self, role: &str) -> Option<u32> {
        self.versions.get(role).copied()
    }

    /// Rejects metadata whose version is lower than the stored role version.
    ///
    /// # Errors
    ///
    /// Returns an error when `version < stored_version` for the role.
    pub fn validate_version(&self, role: &str, version: u32) -> Result<()> {
        if let Some(stored) = self.stored_version(role)
            && version < stored
        {
            return Err(ProvenanceError::TufRollback {
                role: role.to_owned(),
                stored,
                new: version,
            });
        }
        Ok(())
    }

    /// Records a role version after rollback validation succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error when `version < stored_version` for the role.
    pub fn record_version(&mut self, role: &str, version: u32) -> Result<()> {
        self.validate_version(role, version)?;
        self.versions.insert(role.to_owned(), version);
        Ok(())
    }
}

fn ensure_tuf_not_expired(role: &str, expires: &str, now: &str) -> Result<()> {
    if expires > now {
        Ok(())
    } else {
        Err(ProvenanceError::TufExpired {
            role: role.to_owned(),
            expires: expires.to_owned(),
            now: now.to_owned(),
        })
    }
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
        sigstore_bundle: None,
    })
}

/// Verify a Sigstore/cosign bundle over artifact bytes by invoking `cosign verify-blob`.
///
/// # Errors
///
/// Returns an error when `cosign` is unavailable, verification fails, the
/// subprocess times out, or the temporary artifact file cannot be prepared.
pub fn verify_cosign(
    artifact_bytes: &[u8],
    bundle_path: &Path,
    identity: &str,
    issuer: &str,
) -> Result<SignatureVerification, ProvenanceError> {
    let mut temp = NamedTempFile::new().map_err(|source| ProvenanceError::Io {
        stage: "create-temp",
        source,
    })?;
    temp.write_all(artifact_bytes)
        .map_err(|source| ProvenanceError::Io {
            stage: "write-temp",
            source,
        })?;
    temp.flush().map_err(|source| ProvenanceError::Io {
        stage: "flush-temp",
        source,
    })?;

    verify_cosign_subprocess(temp.path(), bundle_path, identity, issuer)?;
    let bundle_metadata = parse_bundle_metadata(bundle_path, identity, issuer);
    Ok(SignatureVerification {
        system: SignatureSystem::Cosign,
        trusted_identity: Some(identity.to_owned()),
        verified: true,
        identity: Some(identity.to_owned()),
        sigstore_bundle: bundle_metadata,
    })
}

/// Maximum captured bytes per cosign output stream (stdout/stderr).
///
/// Bounds memory use when a hostile or broken `cosign` writes unbounded
/// output. Each stream is drained independently, so worst-case capture is
/// `2 * COSIGN_MAX_OUTPUT_BYTES`.
const COSIGN_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Wall-clock seconds before `cosign` is killed.
const COSIGN_TIMEOUT_SECS: u64 = 60;

/// Parses a Sigstore Bundle JSON file to extract metadata per spec §14.2.1.
///
/// This function reads the bundle file, determines the media type,
/// verification material form, counts transparency log entries and RFC 3161
/// timestamps, and computes the bundle's SHA-256. It does not perform
/// cryptographic verification — that is the responsibility of `cosign`.
fn parse_bundle_metadata(
    bundle_path: &Path,
    _identity: &str,
    _issuer: &str,
) -> Option<SigstoreBundleMetadata> {
    let bundle_bytes = fs::read(bundle_path).ok()?;
    let bundle_json: serde_json::Value = serde_json::from_slice(&bundle_bytes).ok()?;

    let media_type = bundle_json
        .get("mediaType")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_owned();

    let form = determine_material_form(&bundle_json);

    let tlog_entries = bundle_json
        .get("verificationMaterial")
        .and_then(|m| m.get("tlogEntries"))
        .and_then(|t| t.as_array())
        .map_or(0, Vec::len);

    let rfc3161_timestamps = bundle_json
        .get("verificationMaterial")
        .and_then(|m| m.get("timestampVerificationData"))
        .and_then(|t| t.get("rfc3161Timestamps"))
        .and_then(|t| t.as_array())
        .map_or(0, Vec::len);

    let bundle_sha256 = {
        use sha2::Digest;
        Sha256Digest::new(sha2::Sha256::digest(&bundle_bytes).into())
    };

    Some(SigstoreBundleMetadata {
        media_type,
        verification_material_form: form,
        tlog_entries,
        rfc3161_timestamps,
        identity_match: true,
        issuer_match: true,
        verification_mode: SigstoreVerificationMode::Offline,
        bundle_sha256,
    })
}

/// Determines the verification material form from the bundle JSON.
fn determine_material_form(bundle: &serde_json::Value) -> VerificationMaterialForm {
    let content = bundle
        .get("verificationMaterial")
        .and_then(|m| m.get("content"));

    match content {
        Some(c) if c.get("x509CertificateChain").is_some() => {
            VerificationMaterialForm::X509CertificateChain
        }
        Some(c) if c.get("publicKey").is_some() => VerificationMaterialForm::PublicKey,
        Some(c) if c.get("x509Certificate").is_some() => VerificationMaterialForm::X509Certificate,
        _ => VerificationMaterialForm::X509CertificateChain,
    }
}

fn verify_cosign_subprocess(
    artifact_path: &Path,
    bundle_path: &Path,
    identity: &str,
    issuer: &str,
) -> Result<(), ProvenanceError> {
    let mut command = Command::new("cosign");
    command
        .arg("verify-blob")
        .arg("--bundle")
        .arg(bundle_path)
        .arg("--certificate-identity")
        .arg(identity)
        .arg("--certificate-oidc-issuer")
        .arg(issuer)
        .arg(artifact_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().map_err(|source| {
        if source.kind() == ErrorKind::NotFound {
            ProvenanceError::CosignUnavailable
        } else {
            ProvenanceError::Io {
                stage: "spawn-cosign",
                source,
            }
        }
    })?;

    // Drain stdout and stderr concurrently. Without this, a child that
    // produces more than the kernel pipe buffer (~64 KiB on Linux) blocks on
    // write and never exits, defeating the timeout below.
    let stdout_handle = spawn_drainer(child.stdout.take());
    let stderr_handle = spawn_drainer(child.stderr.take());

    let deadline = Instant::now() + Duration::from_secs(COSIGN_TIMEOUT_SECS);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    // Best-effort cleanup: kill, reap, and join the drainers
                    // so no captured output escapes the cap and no thread is
                    // left dangling.
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_handle.join();
                    let _ = stderr_handle.join();
                    return Err(ProvenanceError::CosignVerification {
                        reason: format!("cosign timed out after {COSIGN_TIMEOUT_SECS}s"),
                    });
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(source) => {
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(ProvenanceError::Io {
                    stage: "wait-cosign",
                    source,
                });
            }
        }
    };

    let stdout_bounded = join_drainer(stdout_handle, "stdout")?;
    let stderr_bounded = join_drainer(stderr_handle, "stderr")?;

    if stdout_bounded.truncated || stderr_bounded.truncated {
        return Err(ProvenanceError::CosignVerification {
            reason: format!("cosign output exceeded {COSIGN_MAX_OUTPUT_BYTES} byte limit"),
        });
    }

    if status.success() {
        Ok(())
    } else {
        Err(ProvenanceError::CosignVerification {
            reason: bounded_command_output(&stderr_bounded.bytes, &stdout_bounded.bytes),
        })
    }
}

/// Output captured from a single cosign stream, capped at
/// [`COSIGN_MAX_OUTPUT_BYTES`] bytes. When `truncated` is set, the child
/// produced more output than the cap; the remainder was still drained from the
/// pipe (to avoid deadlocking the child) but discarded.
struct BoundedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

/// Reads `reader` to EOF, retaining at most [`COSIGN_MAX_OUTPUT_BYTES`] bytes.
/// Continues reading past the cap so the child's pipe stays drained and it can
/// exit normally.
///
/// # Errors
///
/// Returns the underlying I/O error on a non-interrupted read failure.
fn drain_to_bound<R: Read>(reader: &mut R) -> std::io::Result<BoundedOutput> {
    let mut buf = [0u8; 8 * 1024];
    let mut bytes: Vec<u8> = Vec::new();
    let mut truncated = false;
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let remaining = COSIGN_MAX_OUTPUT_BYTES.saturating_sub(bytes.len());
                if remaining == 0 {
                    truncated = true;
                    continue;
                }
                let take = n.min(remaining);
                bytes.extend_from_slice(&buf[..take]);
                if take < n {
                    truncated = true;
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(BoundedOutput { bytes, truncated })
}

/// Spawns a thread that drains `reader` into a [`BoundedOutput`]. `None` is
/// surfaced as an I/O error so callers cannot silently lose a stream that was
/// expected to be piped.
fn spawn_drainer<R: Read + Send + 'static>(
    reader: Option<R>,
) -> JoinHandle<std::io::Result<BoundedOutput>> {
    thread::spawn(move || {
        let mut reader =
            reader.ok_or_else(|| std::io::Error::other("cosign output stream was not piped"))?;
        drain_to_bound(&mut reader)
    })
}

/// Joins a drainer thread, flattening the panic and I/O results into a single
/// [`ProvenanceError`] channel.
fn join_drainer(
    handle: JoinHandle<std::io::Result<BoundedOutput>>,
    stream: &'static str,
) -> Result<BoundedOutput, ProvenanceError> {
    handle
        .join()
        .map_err(|_| ProvenanceError::CosignVerification {
            reason: format!("cosign {stream} reader panicked"),
        })?
        .map_err(|source| ProvenanceError::Io {
            stage: "read-cosign-output",
            source,
        })
}

fn bounded_command_output(stderr: &[u8], stdout: &[u8]) -> String {
    const MAX_BYTES: usize = 512;
    let source = if stderr.is_empty() { stdout } else { stderr };
    // Strip control characters (except newline and tab) so a hostile cosign
    // cannot inject terminal-control sequences, ANSI escapes, or CRLF
    // header-splitting into logs and receipt diagnostics.
    let filtered: Vec<u8> = source
        .iter()
        .copied()
        .filter(|b| *b >= 0x20 || matches!(*b, b'\n' | b'\t'))
        .collect();
    let truncated = filtered.len() > MAX_BYTES;
    let end = filtered.len().min(MAX_BYTES);
    let text = String::from_utf8_lossy(&filtered[..end]);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        "cosign exited with a non-zero status".to_owned()
    } else if truncated {
        format!("{trimmed}…")
    } else {
        trimmed.to_owned()
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

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
