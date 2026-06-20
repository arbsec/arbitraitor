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
    Ok(SignatureVerification {
        system: SignatureSystem::Cosign,
        trusted_identity: Some(identity.to_owned()),
        verified: true,
        identity: Some(identity.to_owned()),
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
mod tests {
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::path::Path;
    use std::process::Command;

    use arbitraitor_model::ids::Sha256Digest;

    use super::{
        ProvenanceError, SignatureSystem, TofuChange, TofuPin, TofuStore, TofuVerification, TufKey,
        TufRole, TufRoot, TufSignature, TufTargets, TufVersionStore, verify_cosign,
        verify_minisign,
    };

    #[test]
    fn minisign_verifies_artifact_bytes() -> std::result::Result<(), Box<dyn std::error::Error>> {
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
    fn minisign_rejects_wrong_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
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
    fn parses_minisign_base64_public_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let key = minisign::KeyPair::generate_unencrypted_keypair()?;
        let parsed = super::parse_minisign_public_key(&key.pk.to_base64())?;

        assert_eq!(parsed, key.pk);
        Ok(())
    }

    #[test]
    fn verifies_all_required_minisign_signatures()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
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

    #[test]
    fn tofu_first_use_pins_artifact_identity() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let (_temp_dir, path) = temp_store_path("first-use")?;
        let mut store = TofuStore::open(&path)?;
        let url = "https://example.test/artifact";
        let pin = tofu_pin(url, 0x11, Some("signer@example.test"), Some(123));

        assert_eq!(
            store.verify_against_pin(url, &pin)?,
            TofuVerification::FirstUse
        );
        store.pin(url, pin.clone())?;
        let reopened = TofuStore::open(&path)?;

        assert_eq!(reopened.check(url), Some(&pin));
        Ok(())
    }

    #[test]
    fn tofu_subsequent_match_passes() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (_temp_dir, path) = temp_store_path("match")?;
        let url = "https://example.test/tool";
        let pin = tofu_pin(url, 0x22, Some("release@example.test"), Some(42));
        let mut store = TofuStore::open(&path)?;
        store.pin(url, pin.clone())?;

        assert_eq!(
            store.verify_against_pin(url, &pin)?,
            TofuVerification::Matches
        );
        Ok(())
    }

    #[test]
    fn tofu_change_produces_field_diff() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (_temp_dir, path) = temp_store_path("changed")?;
        let url = "https://example.test/tool";
        let pinned = tofu_pin(url, 0x33, Some("old@example.test"), Some(100));
        let actual = tofu_pin(url, 0x44, Some("new@example.test"), Some(101));
        let mut store = TofuStore::open(&path)?;
        store.pin(url, pinned)?;

        assert_eq!(
            store.verify_against_pin(url, &actual)?,
            TofuVerification::Changed {
                changes: vec![
                    TofuChange::DigestChanged {
                        old: digest(0x33).to_string(),
                        new: digest(0x44).to_string(),
                    },
                    TofuChange::SignerChanged {
                        old: "old@example.test".to_owned(),
                        new: "new@example.test".to_owned(),
                    },
                    TofuChange::SizeChanged { old: 100, new: 101 },
                ],
            }
        );
        Ok(())
    }

    #[test]
    fn tuf_version_validation_rejects_rollback()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut versions = TufVersionStore::new();
        versions.record_version("snapshot", 3)?;

        assert!(matches!(
            versions.validate_version("snapshot", 2),
            Err(ProvenanceError::TufRollback { .. })
        ));
        versions.validate_version("snapshot", 3)?;
        versions.validate_version("snapshot", 4)?;
        Ok(())
    }

    #[test]
    fn tuf_expiration_rejects_expired_metadata()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let targets = TufTargets {
            version: 1,
            expires: "2026-01-01T00:00:00Z".to_owned(),
            targets: HashMap::new(),
        };

        assert!(matches!(
            targets.ensure_not_expired("2026-06-18T00:00:00Z"),
            Err(ProvenanceError::TufExpired { .. })
        ));
        targets.ensure_not_expired("2025-06-18T00:00:00Z")?;
        Ok(())
    }

    #[test]
    fn tuf_threshold_requires_unique_authorized_signatures()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let root = TufRoot {
            version: 1,
            expires: "9999-01-01T00:00:00Z".to_owned(),
            keys: vec![tuf_key("root-a"), tuf_key("root-b"), tuf_key("unrelated")],
            roles: HashMap::from([(
                "root".to_owned(),
                TufRole {
                    key_ids: vec!["root-a".to_owned(), "root-b".to_owned()],
                    threshold: 2,
                },
            )]),
            consistent_snapshot: true,
        };

        assert!(matches!(
            root.verify_role_threshold(
                "root",
                &[
                    TufSignature {
                        key_id: "root-a".to_owned(),
                    },
                    TufSignature {
                        key_id: "root-a".to_owned(),
                    },
                    TufSignature {
                        key_id: "unrelated".to_owned(),
                    },
                ],
            ),
            Err(ProvenanceError::TufThreshold { .. })
        ));

        root.verify_role_threshold(
            "root",
            &[
                TufSignature {
                    key_id: "root-a".to_owned(),
                },
                TufSignature {
                    key_id: "root-b".to_owned(),
                },
            ],
        )?;
        Ok(())
    }

    #[test]
    fn drain_to_bound_caps_output_and_marks_truncated() -> std::io::Result<()> {
        use std::io::Cursor;
        let payload = vec![b'a'; super::COSIGN_MAX_OUTPUT_BYTES * 2];
        let mut cursor = Cursor::new(payload);
        let output = super::drain_to_bound(&mut cursor)?;
        assert!(output.truncated);
        assert_eq!(output.bytes.len(), super::COSIGN_MAX_OUTPUT_BYTES);
        Ok(())
    }

    #[test]
    fn drain_to_bound_marks_not_truncated_under_cap() -> std::io::Result<()> {
        use std::io::Cursor;
        let payload = b"short output".to_vec();
        let mut cursor = Cursor::new(payload);
        let output = super::drain_to_bound(&mut cursor)?;
        assert!(!output.truncated);
        assert_eq!(output.bytes, b"short output");
        Ok(())
    }

    #[test]
    fn bounded_command_output_strips_terminal_control_bytes() {
        let result = super::bounded_command_output(b"ok\x1b\x07done", b"");
        assert_eq!(result, "okdone");
    }

    #[test]
    fn bounded_command_output_marks_truncated_output() {
        let long = vec![b'x'; 1024];
        let result = super::bounded_command_output(&long, b"");
        assert!(result.ends_with('…'), "got: {result}");
        assert!(result.len() < long.len());
    }

    #[test]
    fn bounded_command_output_falls_back_when_only_whitespace() {
        assert_eq!(
            super::bounded_command_output(b"   \n\t\x07\x07", b""),
            "cosign exited with a non-zero status"
        );
    }

    #[test]
    fn bounded_command_output_prefers_stderr_when_present() {
        assert_eq!(
            super::bounded_command_output(b"from stderr", b"from stdout"),
            "from stderr"
        );
    }

    fn tofu_pin(url: &str, byte: u8, signer_identity: Option<&str>, size: Option<u64>) -> TofuPin {
        TofuPin {
            url: url.to_owned(),
            sha256: digest(byte),
            signer_identity: signer_identity.map(str::to_owned),
            content_type: Some("application/octet-stream".to_owned()),
            size,
            first_seen: "2026-06-18T00:00:00Z".to_owned(),
        }
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::new([byte; 32])
    }

    fn tuf_key(key_id: &str) -> TufKey {
        TufKey {
            key_id: key_id.to_owned(),
            key_type: "ed25519".to_owned(),
            scheme: "minisign".to_owned(),
            value: "public-key".to_owned(),
        }
    }

    fn temp_store_path(name: &str) -> std::io::Result<(tempfile::TempDir, std::path::PathBuf)> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join(format!("{name}.json"));
        Ok((dir, path))
    }
}
