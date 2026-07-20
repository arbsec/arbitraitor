//! Destination-safe release of approved artifact bytes.
//!
//! Release is the final filesystem boundary crossing: bytes leave quarantine
//! and become visible at a caller-provided path. This module therefore repeats
//! digest verification immediately before and after writing, writes only via a
//! sibling temporary file, refuses surprising destination state, and records the
//! method used for the operation receipt.
//!
//! Threat model scope: for the MVP, the approved destination parent and its
//! ancestors are assumed not to be writable by the same untrusted UID that may
//! race the release operation. Active same-UID directory watchers and writable
//! ancestor rename races are documented inline as known limitations.

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use std::time::{Duration, SystemTime};

use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_store::{ContentStore, StoreError};
use cap_std::ambient_authority;
use cap_std::fs::{
    Dir, File, FileTypeExt as CapFileTypeExt, MetadataExt as CapMetadataExt, OpenOptions,
    OpenOptionsExt, Permissions, PermissionsExt,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, warn};
use uuid::Uuid;

const PRIVATE_RELEASE_MODE: u32 = 0o600;
const COPY_BUFFER_BYTES: usize = 8192;

const OPEN_NOFOLLOW_FLAGS: i32 = libc::O_NOFOLLOW;
const OPEN_DIR_NOFOLLOW_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_DIRECTORY;
#[cfg(target_os = "linux")]
const OPEN_TMPFILE_FLAGS: i32 = libc::O_TMPFILE;

/// Policy gates for destination release.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReleasePolicy {
    /// Permit replacing an existing regular destination file.
    pub allow_overwrite: bool,
    /// Permit the non-atomic copy fallback when atomic publication is unavailable.
    pub allow_non_atomic_copy: bool,
    /// Optional POSIX mode applied to the released inode via the capability
    /// handle after atomic publish. `None` keeps ADR-0015's `0o600` default.
    /// Callers releasing an executable cache pass `Some(0o700)` so no separate
    /// post-release chmod reopens a TOCTOU window.
    #[cfg(unix)]
    pub final_mode: Option<u32>,
    /// Maximum age of the verdict before release. When set, release will
    /// fail with [`ReleaseError::StaleVerdict`] if the verdict was
    /// computed more than this duration ago (spec §26.2 step 4).
    pub verdict_max_age: Option<Duration>,
    /// Timestamp when the verdict was computed. Caller populates this
    /// from the verdict result so the release layer can check freshness.
    pub verdict_timestamp: Option<SystemTime>,
}

#[cfg(not(unix))]
impl ReleasePolicy {
    /// Returns `None`; `final_mode` is Unix-only.
    #[must_use]
    pub const fn final_mode(&self) -> Option<u32> {
        None
    }
}

/// Platform provenance attributes to apply to a released artifact.
///
/// Downloaded artifact bytes do not carry filesystem extended attributes from
/// the network. Arbitraitor therefore starts releases from a clean provenance
/// boundary: releasable Linux xattrs are cleared from the destination inode and
/// only attributes explicitly configured here are added.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProvenanceConfig {
    /// Linux extended attributes to set after clearing inherited release xattrs.
    #[cfg(target_os = "linux")]
    pub linux_xattrs: Vec<LinuxXattr>,
}

/// Linux extended attribute to set during release provenance application.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxXattr {
    /// Attribute name, for example `security.selinux` or `user.arbitraitor.origin`.
    pub name: OsString,
    /// Attribute value bytes.
    pub value: Vec<u8>,
}

/// Receipt data emitted for a completed release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseReceipt {
    /// Scanned artifact identity that was released.
    pub digest: Sha256Digest,
    /// Final destination path requested by policy/user approval.
    pub destination: PathBuf,
    /// Number of artifact bytes released.
    pub bytes_written: u64,
    /// Filesystem method used to publish the file.
    pub method: ReleaseMethod,
    /// Security-relevant warnings that must be surfaced in the operation receipt.
    pub warnings: Vec<ReleaseWarning>,
}

/// Publication method recorded in a release receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseMethod {
    /// Named sibling temporary file was atomically linked into a previously empty destination.
    AtomicNoReplaceLink,
    /// Named sibling temporary file was atomically renamed over a policy-approved destination.
    AtomicRename,
    /// Atomic publication was unavailable and policy approved a non-atomic copy.
    NonAtomicCopy,
    /// Artifact bytes were emitted to stdout (spec §26.1) — used by
    /// `scan --emit-on-pass` and wrapper pipe semantics. The bytes are
    /// still verified against the scanned digest before emission.
    StdoutEmit,
}

/// Warning recorded for exceptional release paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseWarning {
    /// Release used the explicitly approved non-atomic copy fallback.
    NonAtomicCopy {
        /// Safe diagnostic reason for falling back from atomic publication.
        reason: String,
    },
}

/// Release operation failure.
#[derive(Debug, Error)]
pub enum ReleaseError {
    /// The CAS object could not be reopened or verified.
    #[error("failed to reopen CAS object for release: {0}")]
    Store(#[from] StoreError),
    /// Filesystem I/O failed during a named release stage.
    #[error("release I/O failure during {stage}: {source}")]
    Io {
        /// Operation stage.
        stage: &'static str,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// Digest verification failed before or after release writing.
    #[error("release digest mismatch during {stage}: expected {expected}, actual {actual}")]
    DigestMismatch {
        /// Verification stage.
        stage: &'static str,
        /// Scanned/approved SHA-256 digest.
        expected: Sha256Digest,
        /// Recomputed SHA-256 digest.
        actual: Sha256Digest,
    },
    /// The destination path cannot be addressed safely.
    #[error("unsafe release destination: {path}")]
    UnsafeDestination {
        /// Rejected destination path.
        path: PathBuf,
    },
    /// The destination exists but overwrite was not explicitly approved.
    #[error("release destination already exists: {path}")]
    DestinationExists {
        /// Existing destination path.
        path: PathBuf,
    },
    /// The destination or one of its parents is a symlink or special indirection.
    #[error("release destination uses forbidden indirection: {path}")]
    ForbiddenIndirection {
        /// Rejected path.
        path: PathBuf,
    },
    /// Destination has multiple hard links or another unexpected link state.
    #[error("release destination has surprising hard-link state: {path}")]
    HardLinkSurprise {
        /// Rejected path.
        path: PathBuf,
    },
    /// Atomic release failed and policy did not approve a non-atomic copy.
    #[error("atomic release unavailable and non-atomic copy was not policy-approved: {reason}")]
    NonAtomicCopyNotApproved {
        /// Safe diagnostic reason.
        reason: String,
    },
    /// Verdict is too old to safely release (spec §26.2 step 4).
    #[error("verdict is stale: computed {verdict_age_secs}s ago, max allowed is {max_age_secs}s")]
    StaleVerdict {
        /// Age of the verdict in seconds.
        verdict_age_secs: u64,
        /// Maximum allowed age in seconds.
        max_age_secs: u64,
    },
}

/// Releases the exact CAS bytes named by `scanned_digest` to `destination`.
///
/// # Errors
///
/// Returns [`ReleaseError`] if CAS verification fails, the destination is unsafe,
/// digest verification fails, or an exceptional publication path lacks explicit
/// policy approval.
pub fn release_artifact(
    store: &ContentStore,
    scanned_digest: &Sha256Digest,
    destination: &Path,
    policy: &ReleasePolicy,
) -> Result<ReleaseReceipt, ReleaseError> {
    release_artifact_with_provenance(
        store,
        scanned_digest,
        destination,
        policy,
        &ProvenanceConfig::default(),
    )
}

/// Releases the exact CAS bytes with explicit platform provenance attributes.
///
/// # Errors
///
/// Returns [`ReleaseError`] if CAS verification fails, the destination is unsafe,
/// digest verification fails, provenance application fails, or an exceptional
/// publication path lacks explicit policy approval.
pub fn release_artifact_with_provenance(
    store: &ContentStore,
    scanned_digest: &Sha256Digest,
    destination: &Path,
    policy: &ReleasePolicy,
    provenance: &ProvenanceConfig,
) -> Result<ReleaseReceipt, ReleaseError> {
    release_artifact_inner(
        store,
        scanned_digest,
        destination,
        policy,
        provenance,
        ReleaseFsMode::Normal,
    )
}

/// Emits the exact CAS bytes to stdout (spec §26.1).
///
/// Used by `scan --emit-on-pass` and wrapper pipe semantics. The bytes
/// are verified against `scanned_digest` before emission, preserving
/// invariant 2 (immutable identity). No destination file is written.
///
/// # Errors
///
/// Returns [`ReleaseError`] if CAS verification or digest verification
/// fails.
pub fn emit_artifact_to_stdout(
    store: &ContentStore,
    scanned_digest: &Sha256Digest,
    writer: &mut dyn Write,
) -> Result<ReleaseReceipt, ReleaseError> {
    let handle = store.get(scanned_digest)?;
    let mut reader = handle
        .read()
        .try_clone()
        .map_err(|source| ReleaseError::Io {
            stage: "clone-cas-object",
            source,
        })?;
    verify_reader_digest(&mut reader, scanned_digest, "verify-cas-before-emit")?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|source| ReleaseError::Io {
            stage: "seek-after-verify",
            source,
        })?;

    let mut hasher = Sha256::new();
    let mut bytes_written: u64 = 0;
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    loop {
        let n = reader
            .read(&mut buffer)
            .map_err(|source| ReleaseError::Io {
                stage: "read-cas-for-emit",
                source,
            })?;
        if n == 0 {
            break;
        }
        writer
            .write_all(&buffer[..n])
            .map_err(|source| ReleaseError::Io {
                stage: "write-stdout-emit",
                source,
            })?;
        hasher.update(&buffer[..n]);
        bytes_written += n as u64;
    }

    let actual = Sha256Digest::new(hasher.finalize().into());
    if actual != *scanned_digest {
        return Err(ReleaseError::DigestMismatch {
            stage: "verify-after-emit",
            expected: scanned_digest.clone(),
            actual,
        });
    }

    Ok(ReleaseReceipt {
        digest: scanned_digest.clone(),
        destination: PathBuf::from("-"),
        bytes_written,
        method: ReleaseMethod::StdoutEmit,
        warnings: Vec::new(),
    })
}

/// Verifies the verdict is fresh enough to safely release (spec §26.2 step 4).
///
/// When `verdict_max_age` is set on the policy and `verdict_timestamp` is
/// provided, the function checks that the verdict was computed within the
/// allowed age window. If the verdict is stale, release fails with
/// [`ReleaseError::StaleVerdict`] — preventing a TOCTOU where policy or
/// intelligence was updated between verdict and release.
fn check_verdict_freshness(policy: &ReleasePolicy) -> Result<(), ReleaseError> {
    let Some(max_age) = policy.verdict_max_age else {
        return Ok(());
    };
    let Some(ts) = policy.verdict_timestamp else {
        return Ok(());
    };
    let now = SystemTime::now();
    let elapsed = now
        .duration_since(ts)
        .map_err(|_| ReleaseError::StaleVerdict {
            verdict_age_secs: 0,
            max_age_secs: max_age.as_secs(),
        })?;
    if elapsed > max_age {
        return Err(ReleaseError::StaleVerdict {
            verdict_age_secs: elapsed.as_secs(),
            max_age_secs: max_age.as_secs(),
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReleaseFsMode {
    Normal,
    #[cfg(test)]
    ForceNonAtomicForTest,
    #[cfg(test)]
    ForceNonAtomicCopyFailureForTest,
    #[cfg(test)]
    ForceNamedTempForTest,
}

fn release_artifact_inner(
    store: &ContentStore,
    scanned_digest: &Sha256Digest,
    destination: &Path,
    policy: &ReleasePolicy,
    provenance: &ProvenanceConfig,
    fs_mode: ReleaseFsMode,
) -> Result<ReleaseReceipt, ReleaseError> {
    check_verdict_freshness(policy)?;
    let handle = store.get(scanned_digest)?;
    let mut preflight_reader = handle
        .read()
        .try_clone()
        .map_err(|source| ReleaseError::Io {
            stage: "clone-cas-object",
            source,
        })?;
    verify_reader_digest(
        &mut preflight_reader,
        scanned_digest,
        "verify-cas-before-release",
    )?;
    let parent = DestinationParent::open(destination)?;
    reject_existing_destination(&parent.dir, &parent.name, destination, policy)?;
    let temp = SiblingTemp::create(&parent.dir, fs_mode)?;
    let bytes_written = write_and_verify_temp(&handle, scanned_digest, &temp)?;
    apply_platform_provenance(&temp.file, provenance, "apply-release-temp-provenance")?;
    let method = publish_temp(&parent, temp, destination, policy, provenance, fs_mode)?;
    apply_final_mode(&parent.dir, &parent.name, policy)?;
    verify_final_destination(&parent.dir, &parent.name, destination, scanned_digest)?;

    let mut warnings = Vec::new();
    if method == ReleaseMethod::NonAtomicCopy {
        warnings.push(ReleaseWarning::NonAtomicCopy {
            reason: "atomic publication unavailable; policy approved non-atomic copy".to_owned(),
        });
    }
    debug!(%scanned_digest, destination = %destination.display(), ?method, bytes_written, "released artifact");
    Ok(ReleaseReceipt {
        digest: scanned_digest.clone(),
        destination: destination.to_path_buf(),
        bytes_written,
        method,
        warnings,
    })
}

struct DestinationParent {
    dir: Dir,
    path: PathBuf,
    name: OsString,
}

impl DestinationParent {
    fn open(destination: &Path) -> Result<Self, ReleaseError> {
        let name = destination
            .file_name()
            .filter(|name| !name.is_empty())
            .map(OsStr::to_os_string)
            .ok_or_else(|| ReleaseError::UnsafeDestination {
                path: destination.to_path_buf(),
            })?;
        let parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| ReleaseError::UnsafeDestination {
                path: destination.to_path_buf(),
            })?;
        let dir = open_parent_capability(parent)?;
        let metadata = dir.dir_metadata().map_err(|source| ReleaseError::Io {
            stage: "metadata-destination-parent",
            source,
        })?;
        if !metadata.is_dir() {
            return Err(ReleaseError::UnsafeDestination {
                path: parent.to_path_buf(),
            });
        }
        // SECURITY NOTE: The capability above pins the opened parent directory,
        // but the user-facing `destination` path can name a different directory
        // if an attacker can rename writable ancestors after this point. That
        // writable-ancestor attacker model is out of scope for the MVP; release
        // policy assumes the destination parent and ancestors are not
        // attacker-writable. Future work should verify the parent directory
        // identity again before emitting the release receipt.
        Ok(Self {
            dir,
            path: parent.to_path_buf(),
            name,
        })
    }
}

struct SiblingTemp {
    dir: Dir,
    name: Option<OsString>,
    file: File,
    removed: bool,
    kind: SiblingTempKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SiblingTempKind {
    Anonymous,
    Named,
}

impl SiblingTemp {
    fn create(parent: &Dir, fs_mode: ReleaseFsMode) -> Result<Self, ReleaseError> {
        #[cfg(target_os = "linux")]
        if !force_named_temp(fs_mode) {
            match Self::create_anonymous(parent) {
                Ok(temp) => return Ok(temp),
                Err(error) if is_otmpfile_unsupported(&error) => {}
                Err(error) => return Err(error),
            }
        }
        let _ = fs_mode;
        Self::create_named(parent)
    }

    #[cfg(target_os = "linux")]
    fn create_anonymous(parent: &Dir) -> Result<Self, ReleaseError> {
        let dir = parent.try_clone().map_err(|source| ReleaseError::Io {
            stage: "clone-destination-parent",
            source,
        })?;
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        options.mode(PRIVATE_RELEASE_MODE);
        options.custom_flags(OPEN_TMPFILE_FLAGS);
        let file = dir
            .open_with(".", &options)
            .map_err(|source| ReleaseError::Io {
                stage: "create-anonymous-release-temp",
                source,
            })?;
        file.set_permissions(Permissions::from_mode(PRIVATE_RELEASE_MODE))
            .map_err(|source| ReleaseError::Io {
                stage: "chmod-release-temp",
                source,
            })?;
        Ok(Self {
            dir,
            name: None,
            file,
            removed: false,
            kind: SiblingTempKind::Anonymous,
        })
    }

    fn create_named(parent: &Dir) -> Result<Self, ReleaseError> {
        let dir = parent.try_clone().map_err(|source| ReleaseError::Io {
            stage: "clone-destination-parent",
            source,
        })?;
        for _attempt in 0..128 {
            let name = random_temp_name();
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            options.mode(PRIVATE_RELEASE_MODE);
            options.custom_flags(OPEN_NOFOLLOW_FLAGS);
            // SECURITY NOTE: This named fallback is used only when Linux
            // `O_TMPFILE` is unavailable or unsupported by the destination
            // filesystem, and on non-Linux platforms. A same-UID attacker
            // actively watching the destination directory can hard-link this
            // named temporary file before the later `nlink()` check. The UUID
            // name prevents pre-creation but does not defeat active watching.
            // The post-write link-count check remains defense-in-depth for the
            // fallback path, not a complete same-UID guarantee.
            match dir.open_with(&name, &options) {
                Ok(file) => {
                    file.set_permissions(Permissions::from_mode(PRIVATE_RELEASE_MODE))
                        .map_err(|source| ReleaseError::Io {
                            stage: "chmod-release-temp",
                            source,
                        })?;
                    return Ok(Self {
                        dir,
                        name: Some(name),
                        file,
                        removed: false,
                        kind: SiblingTempKind::Named,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
                Err(source) => {
                    return Err(ReleaseError::Io {
                        stage: "create-release-temp",
                        source,
                    });
                }
            }
        }
        Err(ReleaseError::Io {
            stage: "create-release-temp",
            source: io::Error::new(
                io::ErrorKind::AlreadyExists,
                "unable to create unique sibling release temporary file",
            ),
        })
    }

    fn remove(&mut self) -> Result<(), ReleaseError> {
        if !self.removed
            && let Some(name) = &self.name
        {
            self.dir
                .remove_file(name)
                .map_err(|source| ReleaseError::Io {
                    stage: "remove-release-temp",
                    source,
                })?;
            self.removed = true;
        }
        Ok(())
    }

    fn expected_nlink_after_write(&self) -> u64 {
        match self.kind {
            SiblingTempKind::Anonymous => 0,
            SiblingTempKind::Named => 1,
        }
    }

    fn named_path(&self) -> Result<&OsStr, ReleaseError> {
        self.name.as_deref().ok_or_else(|| ReleaseError::Io {
            stage: "release-temp-name",
            source: io::Error::other("anonymous release temporary file has no sibling name"),
        })
    }
}

#[cfg(target_os = "linux")]
fn force_named_temp(fs_mode: ReleaseFsMode) -> bool {
    #[cfg(test)]
    {
        fs_mode == ReleaseFsMode::ForceNamedTempForTest
    }
    #[cfg(not(test))]
    {
        let _ = fs_mode;
        false
    }
}

impl Drop for SiblingTemp {
    fn drop(&mut self) {
        if !self.removed
            && let Some(name) = &self.name
        {
            let _cleanup_result = self.dir.remove_file(name);
        }
    }
}

#[cfg(target_os = "linux")]
fn is_otmpfile_unsupported(error: &ReleaseError) -> bool {
    matches!(
        error,
        ReleaseError::Io {
            stage: "create-anonymous-release-temp",
            source,
        } if matches!(
            source.raw_os_error(),
            Some(libc::EOPNOTSUPP | libc::EINVAL | libc::EISDIR | libc::ENOENT | libc::ENOTDIR)
        )
    )
}

fn random_temp_name() -> OsString {
    OsString::from(format!(
        ".arbitraitor-release-{}.tmp",
        Uuid::new_v4().as_simple()
    ))
}

fn publish_no_replace(temp: &mut SiblingTemp, parent: &Dir, name: &OsStr) -> io::Result<()> {
    match temp.kind {
        SiblingTempKind::Named => match &temp.name {
            Some(temp_name) => temp.dir.hard_link(temp_name, parent, name),
            None => Err(io::Error::other(
                "named release temporary file has no sibling name",
            )),
        },
        #[cfg(target_os = "linux")]
        SiblingTempKind::Anonymous => link_anonymous_temp(temp, parent, name),
        #[cfg(not(target_os = "linux"))]
        SiblingTempKind::Anonymous => Err(io::Error::other(
            "anonymous release temporary files are Linux-only",
        )),
    }
}

#[cfg(target_os = "linux")]
fn link_anonymous_temp(temp: &SiblingTemp, parent: &Dir, name: &OsStr) -> io::Result<()> {
    rustix::fs::linkat(
        temp.file.as_fd(),
        "",
        parent.as_fd(),
        name,
        rustix::fs::AtFlags::EMPTY_PATH,
    )
    .map_err(rustix_to_io)
}

#[cfg(target_os = "linux")]
fn link_anonymous_temp_to_unique_sibling(temp: &mut SiblingTemp) -> Result<(), ReleaseError> {
    for _attempt in 0..128 {
        let name = random_temp_name();
        match link_anonymous_temp(temp, &temp.dir, &name) {
            Ok(()) => {
                let metadata = temp.file.metadata().map_err(|source| ReleaseError::Io {
                    stage: "metadata-release-temp-after-link",
                    source,
                })?;
                if metadata.nlink() != 1 {
                    let _cleanup_result = temp.dir.remove_file(&name);
                    return Err(ReleaseError::HardLinkSurprise {
                        path: PathBuf::from("release temporary file"),
                    });
                }
                temp.name = Some(name);
                temp.kind = SiblingTempKind::Named;
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(ReleaseError::Io {
                    stage: "link-anonymous-release-temp",
                    source,
                });
            }
        }
    }
    Err(ReleaseError::Io {
        stage: "link-anonymous-release-temp",
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "unable to create unique sibling release temporary file link",
        ),
    })
}

#[cfg(target_os = "linux")]
fn rustix_to_io(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

fn open_parent_capability(parent: &Path) -> Result<Dir, ReleaseError> {
    let root = if parent.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let mut dir =
        Dir::open_ambient_dir(root, ambient_authority()).map_err(|source| ReleaseError::Io {
            stage: "open-destination-root",
            source,
        })?;
    let mut current = if parent.is_absolute() {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };
    for component in parent.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Prefix(_) | Component::ParentDir => {
                return Err(ReleaseError::UnsafeDestination {
                    path: parent.to_path_buf(),
                });
            }
            Component::Normal(part) => {
                current.push(part);
                dir = open_child_dir_nofollow(&dir, part, &current)?;
            }
        }
    }
    Ok(dir)
}

fn open_child_dir_nofollow(
    parent: &Dir,
    part: &OsStr,
    component_path: &Path,
) -> Result<Dir, ReleaseError> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(OPEN_DIR_NOFOLLOW_FLAGS);
    let file = parent.open_with(part, &options).map_err(|source| {
        if source.kind() == io::ErrorKind::Other {
            ReleaseError::ForbiddenIndirection {
                path: component_path.to_path_buf(),
            }
        } else {
            ReleaseError::Io {
                stage: "open-destination-parent-component",
                source,
            }
        }
    })?;
    let metadata = file.metadata().map_err(|source| ReleaseError::Io {
        stage: "metadata-destination-parent-component",
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || is_forbidden_special(&metadata) {
        return Err(ReleaseError::ForbiddenIndirection {
            path: component_path.to_path_buf(),
        });
    }
    Ok(Dir::from_std_file(file.into_std()))
}

fn reject_existing_destination(
    parent: &Dir,
    name: &OsStr,
    destination: &Path,
    policy: &ReleasePolicy,
) -> Result<(), ReleaseError> {
    match parent.symlink_metadata(name) {
        Ok(metadata) => {
            reject_destination_metadata(destination, &metadata)?;
            if !policy.allow_overwrite {
                return Err(ReleaseError::DestinationExists {
                    path: destination.to_path_buf(),
                });
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ReleaseError::Io {
                stage: "metadata-destination",
                source,
            });
        }
    }
    Ok(())
}

fn reject_destination_metadata(
    destination: &Path,
    metadata: &cap_std::fs::Metadata,
) -> Result<(), ReleaseError> {
    if metadata.file_type().is_symlink() || is_forbidden_special(metadata) {
        return Err(ReleaseError::ForbiddenIndirection {
            path: destination.to_path_buf(),
        });
    }
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(ReleaseError::HardLinkSurprise {
            path: destination.to_path_buf(),
        });
    }
    Ok(())
}

fn is_forbidden_special(metadata: &cap_std::fs::Metadata) -> bool {
    let file_type = metadata.file_type();
    file_type.is_block_device()
        || file_type.is_char_device()
        || file_type.is_fifo()
        || file_type.is_socket()
}

fn write_and_verify_temp(
    handle: &arbitraitor_store::ArtifactHandle,
    expected: &Sha256Digest,
    temp: &SiblingTemp,
) -> Result<u64, ReleaseError> {
    let temp_file = &temp.file;
    let mut source = handle
        .read()
        .try_clone()
        .map_err(|source| ReleaseError::Io {
            stage: "clone-cas-object-for-write",
            source,
        })?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|source| ReleaseError::Io {
            stage: "rewind-cas-object-for-write",
            source,
        })?;
    let mut writer = temp_file.try_clone().map_err(|source| ReleaseError::Io {
        stage: "clone-release-temp",
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut bytes_written = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|source| ReleaseError::Io {
                stage: "read-cas-object-for-release",
                source,
            })?;
        if read == 0 {
            break;
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|source| ReleaseError::Io {
                stage: "write-release-temp",
                source,
            })?;
        hasher.update(&buffer[..read]);
        bytes_written = bytes_written
            .checked_add(u64::try_from(read).map_err(|source| ReleaseError::Io {
                stage: "count-release-bytes",
                source: io::Error::new(io::ErrorKind::InvalidData, source),
            })?)
            .ok_or_else(|| ReleaseError::Io {
                stage: "count-release-bytes",
                source: io::Error::new(io::ErrorKind::InvalidData, "release byte count overflow"),
            })?;
    }
    let copied = Sha256Digest::new(hasher.finalize().into());
    if &copied != expected {
        return Err(ReleaseError::DigestMismatch {
            stage: "copy-cas-to-release-temp",
            expected: expected.clone(),
            actual: copied,
        });
    }
    writer.flush().map_err(|source| ReleaseError::Io {
        stage: "flush-release-temp",
        source,
    })?;
    temp_file.sync_all().map_err(|source| ReleaseError::Io {
        stage: "fsync-release-temp",
        source,
    })?;
    let mut verifier = temp_file.try_clone().map_err(|source| ReleaseError::Io {
        stage: "clone-release-temp-for-verify",
        source,
    })?;
    verify_reader_digest(&mut verifier, expected, "verify-release-temp")?;
    let metadata = temp_file.metadata().map_err(|source| ReleaseError::Io {
        stage: "metadata-release-temp",
        source,
    })?;
    if metadata.nlink() != temp.expected_nlink_after_write() {
        return Err(ReleaseError::HardLinkSurprise {
            path: PathBuf::from("release temporary file"),
        });
    }
    Ok(bytes_written)
}

fn publish_temp(
    parent: &DestinationParent,
    mut temp: SiblingTemp,
    destination: &Path,
    policy: &ReleasePolicy,
    provenance: &ProvenanceConfig,
    fs_mode: ReleaseFsMode,
) -> Result<ReleaseMethod, ReleaseError> {
    #[cfg(test)]
    if matches!(
        fs_mode,
        ReleaseFsMode::ForceNonAtomicForTest | ReleaseFsMode::ForceNonAtomicCopyFailureForTest
    ) {
        return publish_non_atomic(parent, &mut temp, destination, policy, provenance, fs_mode);
    }
    let _ = fs_mode;
    if policy.allow_overwrite {
        reject_existing_destination(&parent.dir, &parent.name, destination, policy)?;
        #[cfg(target_os = "linux")]
        if temp.kind == SiblingTempKind::Anonymous {
            link_anonymous_temp_to_unique_sibling(&mut temp)?;
        }
        match temp
            .dir
            .rename(temp.named_path()?, &parent.dir, &parent.name)
        {
            Ok(()) => {
                temp.removed = true;
                sync_parent_dir(&parent.path)?;
                Ok(ReleaseMethod::AtomicRename)
            }
            Err(error) if is_cross_filesystem(&error) => {
                publish_non_atomic(parent, &mut temp, destination, policy, provenance, fs_mode)
            }
            Err(source) => Err(ReleaseError::Io {
                stage: "rename-release-temp",
                source,
            }),
        }
    } else {
        match publish_no_replace(&mut temp, &parent.dir, &parent.name) {
            Ok(()) => {
                if temp.kind == SiblingTempKind::Named {
                    temp.remove()?;
                } else {
                    temp.removed = true;
                }
                sync_parent_dir(&parent.path)?;
                Ok(ReleaseMethod::AtomicNoReplaceLink)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Err(ReleaseError::DestinationExists {
                    path: destination.to_path_buf(),
                })
            }
            Err(error) if is_cross_filesystem(&error) => {
                publish_non_atomic(parent, &mut temp, destination, policy, provenance, fs_mode)
            }
            Err(source) => Err(ReleaseError::Io {
                stage: "link-release-temp",
                source,
            }),
        }
    }
}

fn publish_non_atomic(
    parent: &DestinationParent,
    temp: &mut SiblingTemp,
    destination: &Path,
    policy: &ReleasePolicy,
    provenance: &ProvenanceConfig,
    fs_mode: ReleaseFsMode,
) -> Result<ReleaseMethod, ReleaseError> {
    if !policy.allow_non_atomic_copy {
        return Err(ReleaseError::NonAtomicCopyNotApproved {
            reason: "atomic publication failed with cross-filesystem semantics".to_owned(),
        });
    }
    warn!(destination = %destination.display(), "using policy-approved non-atomic release copy");
    reject_existing_destination(&parent.dir, &parent.name, destination, policy)?;
    let mut output = open_non_atomic_destination(parent, destination, policy, provenance)?;
    let mut input = temp.file.try_clone().map_err(|source| ReleaseError::Io {
        stage: "clone-release-temp-for-copy",
        source,
    })?;
    input
        .seek(SeekFrom::Start(0))
        .map_err(|source| ReleaseError::Io {
            stage: "rewind-release-temp-for-copy",
            source,
        })?;
    let copy_result = copy_and_sync_non_atomic(&mut input, &mut output, fs_mode);
    if let Err(error) = copy_result {
        cleanup_partial_non_atomic_destination(parent, destination);
        return Err(error);
    }
    temp.remove()?;
    sync_parent_dir(&parent.path)?;
    Ok(ReleaseMethod::NonAtomicCopy)
}

fn open_non_atomic_destination(
    parent: &DestinationParent,
    destination: &Path,
    policy: &ReleasePolicy,
    provenance: &ProvenanceConfig,
) -> Result<File, ReleaseError> {
    if policy.allow_overwrite {
        open_existing_or_create_non_atomic_destination(parent, destination, provenance)
    } else {
        create_new_non_atomic_destination(parent, destination, provenance)
    }
}

fn open_existing_or_create_non_atomic_destination(
    parent: &DestinationParent,
    destination: &Path,
    provenance: &ProvenanceConfig,
) -> Result<File, ReleaseError> {
    let mut existing_options = OpenOptions::new();
    existing_options.write(true);
    existing_options.mode(PRIVATE_RELEASE_MODE);
    existing_options.custom_flags(OPEN_NOFOLLOW_FLAGS);
    match parent.dir.open_with(&parent.name, &existing_options) {
        Ok(file) => {
            reject_open_file_metadata(destination, &file)?;
            apply_platform_provenance(
                &file,
                provenance,
                "apply-non-atomic-destination-provenance",
            )?;
            file.set_len(0).map_err(|source| ReleaseError::Io {
                stage: "truncate-non-atomic-destination",
                source,
            })?;
            Ok(file)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_new_non_atomic_destination(parent, destination, provenance)
        }
        Err(source) => Err(ReleaseError::Io {
            stage: "open-non-atomic-destination",
            source,
        }),
    }
}

fn create_new_non_atomic_destination(
    parent: &DestinationParent,
    destination: &Path,
    provenance: &ProvenanceConfig,
) -> Result<File, ReleaseError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    options.mode(PRIVATE_RELEASE_MODE);
    options.custom_flags(OPEN_NOFOLLOW_FLAGS);
    let file = parent
        .dir
        .open_with(&parent.name, &options)
        .map_err(|source| ReleaseError::Io {
            stage: "open-non-atomic-destination",
            source,
        })?;
    reject_open_file_metadata(destination, &file)?;
    apply_platform_provenance(&file, provenance, "apply-non-atomic-destination-provenance")?;
    Ok(file)
}

fn reject_open_file_metadata(destination: &Path, file: &File) -> Result<(), ReleaseError> {
    let metadata = file.metadata().map_err(|source| ReleaseError::Io {
        stage: "metadata-open-destination",
        source,
    })?;
    reject_destination_metadata(destination, &metadata)
}

fn copy_and_sync_non_atomic(
    input: &mut File,
    output: &mut File,
    fs_mode: ReleaseFsMode,
) -> Result<(), ReleaseError> {
    #[cfg(test)]
    if fs_mode == ReleaseFsMode::ForceNonAtomicCopyFailureForTest {
        output
            .write_all(b"partial")
            .map_err(|source| ReleaseError::Io {
                stage: "write-non-atomic-copy",
                source,
            })?;
        return Err(ReleaseError::Io {
            stage: "write-non-atomic-copy",
            source: io::Error::other("simulated non-atomic copy failure"),
        });
    }
    let _ = fs_mode;
    copy_stream(input, output)?;
    output.flush().map_err(|source| ReleaseError::Io {
        stage: "flush-non-atomic-destination",
        source,
    })?;
    output.sync_all().map_err(|source| ReleaseError::Io {
        stage: "fsync-non-atomic-destination",
        source,
    })
}

fn cleanup_partial_non_atomic_destination(parent: &DestinationParent, destination: &Path) {
    if let Err(source) = parent.dir.remove_file(&parent.name) {
        warn!(
            destination = %destination.display(),
            error = %source,
            "best-effort cleanup of partial non-atomic release destination failed"
        );
    }
}

fn apply_final_mode(
    parent: &Dir,
    name: &OsStr,
    policy: &ReleasePolicy,
) -> Result<(), ReleaseError> {
    #[cfg(unix)]
    {
        if let Some(mode) = policy.final_mode {
            let mut options = OpenOptions::new();
            options.write(true);
            options.custom_flags(OPEN_NOFOLLOW_FLAGS);
            let file = parent
                .open_with(name, &options)
                .map_err(|source| ReleaseError::Io {
                    stage: "open-final-mode",
                    source,
                })?;
            file.set_permissions(Permissions::from_mode(mode))
                .map_err(|source| ReleaseError::Io {
                    stage: "set-final-mode",
                    source,
                })?;
            file.sync_all().map_err(|source| ReleaseError::Io {
                stage: "fsync-final-mode",
                source,
            })?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (parent, name, policy);
    }
    Ok(())
}

fn verify_final_destination(
    parent: &Dir,
    name: &OsStr,
    destination: &Path,
    expected: &Sha256Digest,
) -> Result<(), ReleaseError> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(OPEN_NOFOLLOW_FLAGS);
    let mut file = parent
        .open_with(name, &options)
        .map_err(|source| ReleaseError::Io {
            stage: "open-final-destination",
            source,
        })?;
    reject_open_file_metadata(destination, &file)?;
    verify_reader_digest(&mut file, expected, "verify-final-destination")
}

fn apply_platform_provenance(
    file: &File,
    config: &ProvenanceConfig,
    stage: &'static str,
) -> Result<(), ReleaseError> {
    #[cfg(target_os = "linux")]
    {
        apply_linux_xattr_provenance(file, config, stage)?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, config, stage);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_linux_xattr_provenance(
    file: &File,
    config: &ProvenanceConfig,
    stage: &'static str,
) -> Result<(), ReleaseError> {
    clear_releasable_linux_xattrs(file, stage)?;
    for xattr in &config.linux_xattrs {
        let name = linux_xattr_name(&xattr.name, stage)?;
        rustix::fs::fsetxattr(
            file.as_fd(),
            name.as_c_str(),
            &xattr.value,
            rustix::fs::XattrFlags::empty(),
        )
        .map_err(|source| ReleaseError::Io {
            stage,
            source: rustix_to_io(source),
        })?;
    }
    file.sync_all()
        .map_err(|source| ReleaseError::Io { stage, source })
}

#[cfg(target_os = "linux")]
fn clear_releasable_linux_xattrs(file: &File, stage: &'static str) -> Result<(), ReleaseError> {
    for name in releasable_linux_xattr_names(file, stage)? {
        match rustix::fs::fremovexattr(file.as_fd(), name.as_c_str()) {
            Ok(()) => {}
            Err(error) if is_absent_or_unsupported_xattr_error(error) => {}
            Err(source) => {
                return Err(ReleaseError::Io {
                    stage,
                    source: rustix_to_io(source),
                });
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn releasable_linux_xattr_names(
    file: &File,
    stage: &'static str,
) -> Result<Vec<CString>, ReleaseError> {
    let mut empty = [0_u8; 0];
    let size = match rustix::fs::flistxattr(file.as_fd(), &mut empty) {
        Ok(size) => size,
        Err(error) if is_absent_or_unsupported_xattr_error(error) => return Ok(Vec::new()),
        Err(source) => {
            return Err(ReleaseError::Io {
                stage,
                source: rustix_to_io(source),
            });
        }
    };
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut names = vec![0_u8; size];
    let len =
        rustix::fs::flistxattr(file.as_fd(), &mut names).map_err(|source| ReleaseError::Io {
            stage,
            source: rustix_to_io(source),
        })?;
    names.truncate(len);
    names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .filter(|name| should_clear_linux_xattr(name))
        .map(|name| linux_xattr_name_bytes(name, stage))
        .collect()
}

#[cfg(target_os = "linux")]
fn should_clear_linux_xattr(name: &[u8]) -> bool {
    name.starts_with(b"user.")
        || name == b"security.capability"
        || name == b"system.posix_acl_access"
        || name == b"system.posix_acl_default"
        || name.starts_with(b"trusted.")
}

#[cfg(target_os = "linux")]
fn linux_xattr_name(name: &OsStr, stage: &'static str) -> Result<CString, ReleaseError> {
    linux_xattr_name_bytes(name.as_bytes(), stage)
}

#[cfg(target_os = "linux")]
fn linux_xattr_name_bytes(name: &[u8], stage: &'static str) -> Result<CString, ReleaseError> {
    if name.is_empty() {
        return Err(ReleaseError::Io {
            stage,
            source: io::Error::new(io::ErrorKind::InvalidInput, "empty Linux xattr name"),
        });
    }
    CString::new(name).map_err(|source| ReleaseError::Io {
        stage,
        source: io::Error::new(io::ErrorKind::InvalidInput, source),
    })
}

#[cfg(target_os = "linux")]
fn is_absent_or_unsupported_xattr_error(error: rustix::io::Errno) -> bool {
    matches!(error.raw_os_error(), libc::ENODATA | libc::EOPNOTSUPP)
}

fn verify_reader_digest(
    reader: &mut File,
    expected: &Sha256Digest,
    stage: &'static str,
) -> Result<(), ReleaseError> {
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|source| ReleaseError::Io { stage, source })?;
    let actual = digest_reader(reader)?;
    if &actual == expected {
        Ok(())
    } else {
        Err(ReleaseError::DigestMismatch {
            stage,
            expected: expected.clone(),
            actual,
        })
    }
}

fn digest_reader(reader: &mut impl Read) -> Result<Sha256Digest, ReleaseError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| ReleaseError::Io {
                stage: "digest-release-bytes",
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Sha256Digest::new(hasher.finalize().into()))
}

fn copy_stream(reader: &mut impl Read, writer: &mut impl Write) -> Result<(), ReleaseError> {
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| ReleaseError::Io {
                stage: "read-non-atomic-copy",
                source,
            })?;
        if read == 0 {
            break;
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|source| ReleaseError::Io {
                stage: "write-non-atomic-copy",
                source,
            })?;
    }
    Ok(())
}

fn sync_parent_dir(path: &Path) -> Result<(), ReleaseError> {
    fs::File::open(path)
        .map_err(|source| ReleaseError::Io {
            stage: "open-destination-parent-for-sync",
            source,
        })?
        .sync_all()
        .map_err(|source| ReleaseError::Io {
            stage: "fsync-destination-parent",
            source,
        })
}

fn is_cross_filesystem(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(18))
}

impl fmt::Display for ReleaseMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtomicNoReplaceLink => formatter.write_str("atomic-no-replace-link"),
            Self::AtomicRename => formatter.write_str("atomic-rename"),
            Self::NonAtomicCopy => formatter.write_str("non-atomic-copy"),
            Self::StdoutEmit => formatter.write_str("stdout-emit"),
        }
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{
        MetadataExt as StdMetadataExt, PermissionsExt as StdPermissionsExt, symlink,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    use proptest::prelude::*;
    use proptest::test_runner::TestRunner;

    use super::*;

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_root(label: &str) -> io::Result<PathBuf> {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "arbitraitor-release-{label}-{}-{id}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::new(Sha256::digest(bytes).into())
    }

    async fn store_bytes(
        store: &ContentStore,
        bytes: &[u8],
    ) -> Result<Sha256Digest, Box<dyn std::error::Error>> {
        let mut sink = store.sink(None)?;
        for chunk in bytes.chunks(3) {
            sink.write_chunk(chunk).await?;
        }
        Ok(sink.finish().await?)
    }

    fn read_std_digest(path: &Path) -> Result<Sha256Digest, Box<dyn std::error::Error>> {
        let mut file = fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; COPY_BUFFER_BYTES];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(Sha256Digest::new(hasher.finalize().into()))
    }

    #[cfg(target_os = "linux")]
    fn set_test_xattr(path: &Path, name: &str, value: &[u8]) -> io::Result<bool> {
        let file = fs::File::options().read(true).write(true).open(path)?;
        let name = CString::new(name)
            .map_err(|source| io::Error::new(io::ErrorKind::InvalidInput, source))?;
        match rustix::fs::fsetxattr(
            file.as_fd(),
            name.as_c_str(),
            value,
            rustix::fs::XattrFlags::empty(),
        ) {
            Ok(()) => Ok(true),
            Err(error) if is_absent_or_unsupported_xattr_error(error) => Ok(false),
            Err(error) if error.raw_os_error() == libc::EPERM => Ok(false),
            Err(error) => Err(rustix_to_io(error)),
        }
    }

    #[cfg(target_os = "linux")]
    fn get_test_xattr(path: &Path, name: &str) -> io::Result<Option<Vec<u8>>> {
        let file = fs::File::open(path)?;
        let name = CString::new(name)
            .map_err(|source| io::Error::new(io::ErrorKind::InvalidInput, source))?;
        let mut empty = [0_u8; 0];
        let size = match rustix::fs::fgetxattr(file.as_fd(), name.as_c_str(), &mut empty) {
            Ok(size) => size,
            Err(error) if is_absent_or_unsupported_xattr_error(error) => return Ok(None),
            Err(error) => return Err(rustix_to_io(error)),
        };
        let mut value = vec![0_u8; size];
        let len = rustix::fs::fgetxattr(file.as_fd(), name.as_c_str(), &mut value)
            .map_err(rustix_to_io)?;
        value.truncate(len);
        Ok(Some(value))
    }

    #[cfg(target_os = "linux")]
    fn releasable_xattr_names(path: &Path) -> io::Result<Vec<Vec<u8>>> {
        let file = fs::File::open(path)?;
        let mut empty = [0_u8; 0];
        let size = match rustix::fs::flistxattr(file.as_fd(), &mut empty) {
            Ok(size) => size,
            Err(error) if is_absent_or_unsupported_xattr_error(error) => return Ok(Vec::new()),
            Err(error) => return Err(rustix_to_io(error)),
        };
        let mut names = vec![0_u8; size];
        let len = rustix::fs::flistxattr(file.as_fd(), &mut names).map_err(rustix_to_io)?;
        names.truncate(len);
        Ok(names
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
            .filter(|name| should_clear_linux_xattr(name))
            .map(<[u8]>::to_vec)
            .collect())
    }

    #[tokio::test]
    async fn released_file_digest_always_equals_scanned_digest()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("digest")?;
        let store = ContentStore::open(&root.join("store"))?;
        let bytes = b"approved release bytes";
        let digest = store_bytes(&store, bytes).await?;
        let destination = root.join("released.bin");
        let receipt = release_artifact(&store, &digest, &destination, &ReleasePolicy::default())?;

        assert_eq!(receipt.digest, digest);
        assert_eq!(receipt.destination, destination);
        assert_eq!(receipt.bytes_written, u64::try_from(bytes.len())?);
        assert_eq!(read_std_digest(&destination)?, digest_bytes(bytes));
        assert_eq!(fs::read(&destination)?, bytes);
        assert_eq!(
            fs::metadata(&destination)?.permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn symlink_at_destination_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("symlink")?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = store_bytes(&store, b"symlink reject").await?;
        let target = root.join("target");
        let destination = root.join("link");
        fs::write(&target, b"keep")?;
        symlink(&target, &destination)?;

        let result = release_artifact(&store, &digest, &destination, &ReleasePolicy::default());
        assert!(matches!(
            result,
            Err(ReleaseError::ForbiddenIndirection { .. })
        ));
        assert_eq!(fs::read(&target)?, b"keep");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn existing_destination_is_rejected_without_force()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("exists")?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = store_bytes(&store, b"new bytes").await?;
        let destination = root.join("existing");
        fs::write(&destination, b"old bytes")?;

        let result = release_artifact(&store, &digest, &destination, &ReleasePolicy::default());
        assert!(matches!(
            result,
            Err(ReleaseError::DestinationExists { .. })
        ));
        assert_eq!(fs::read(&destination)?, b"old bytes");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn overwrite_uses_atomic_rename_when_policy_approves()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("rename")?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = store_bytes(&store, b"replacement bytes").await?;
        let destination = root.join("replace-me");
        fs::write(&destination, b"old")?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;

        let receipt = release_artifact(
            &store,
            &digest,
            &destination,
            &ReleasePolicy {
                allow_overwrite: true,
                allow_non_atomic_copy: false,
                ..Default::default()
            },
        )?;
        assert_eq!(receipt.method, ReleaseMethod::AtomicRename);
        assert_eq!(read_std_digest(&destination)?, digest);
        assert_eq!(fs::metadata(&destination)?.nlink(), 1);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn release_has_no_releasable_linux_xattrs_by_default()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("xattr-clean-new")?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = store_bytes(&store, b"clean xattr bytes").await?;
        let destination = root.join("released");

        release_artifact(&store, &digest, &destination, &ReleasePolicy::default())?;

        assert_eq!(releasable_xattr_names(&destination)?, Vec::<Vec<u8>>::new());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn overwrite_clears_pre_existing_linux_xattrs() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = temp_root("xattr-clear-overwrite")?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = store_bytes(&store, b"replacement without leaked attrs").await?;
        let destination = root.join("replace-me");
        fs::write(&destination, b"old")?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;
        if !set_test_xattr(&destination, "user.arbitraitor-test", b"leak")? {
            fs::remove_dir_all(root)?;
            return Ok(());
        }

        release_artifact(
            &store,
            &digest,
            &destination,
            &ReleasePolicy {
                allow_overwrite: true,
                allow_non_atomic_copy: false,
                ..Default::default()
            },
        )?;

        assert_eq!(get_test_xattr(&destination, "user.arbitraitor-test")?, None);
        assert_eq!(releasable_xattr_names(&destination)?, Vec::<Vec<u8>>::new());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn non_atomic_overwrite_clears_pre_existing_linux_xattrs()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("xattr-clear-non-atomic")?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = store_bytes(&store, b"non atomic replacement").await?;
        let destination = root.join("replace-me");
        fs::write(&destination, b"old")?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;
        if !set_test_xattr(&destination, "user.arbitraitor-test", b"leak")? {
            fs::remove_dir_all(root)?;
            return Ok(());
        }

        release_artifact_inner(
            &store,
            &digest,
            &destination,
            &ReleasePolicy {
                allow_overwrite: true,
                allow_non_atomic_copy: true,
                ..Default::default()
            },
            &ProvenanceConfig::default(),
            ReleaseFsMode::ForceNonAtomicForTest,
        )?;

        assert_eq!(get_test_xattr(&destination, "user.arbitraitor-test")?, None);
        assert_eq!(read_std_digest(&destination)?, digest);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn explicit_linux_xattrs_are_applied_after_cleaning()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("xattr-configured")?;
        let probe = root.join("probe");
        fs::write(&probe, b"probe")?;
        if !set_test_xattr(&probe, "user.arbitraitor-test", b"probe")? {
            fs::remove_dir_all(root)?;
            return Ok(());
        }
        let store = ContentStore::open(&root.join("store"))?;
        let digest = store_bytes(&store, b"configured provenance").await?;
        let destination = root.join("released");

        release_artifact_with_provenance(
            &store,
            &digest,
            &destination,
            &ReleasePolicy::default(),
            &ProvenanceConfig {
                linux_xattrs: vec![LinuxXattr {
                    name: OsString::from("user.arbitraitor-test"),
                    value: b"configured".to_vec(),
                }],
            },
        )?;

        assert_eq!(
            get_test_xattr(&destination, "user.arbitraitor-test")?,
            Some(b"configured".to_vec())
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn hard_link_destination_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("hardlink-destination")?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = store_bytes(&store, b"replacement bytes").await?;
        let destination = root.join("linked-destination");
        let alias = root.join("linked-alias");
        fs::write(&destination, b"do not truncate")?;
        fs::hard_link(&destination, &alias)?;

        let result = release_artifact(
            &store,
            &digest,
            &destination,
            &ReleasePolicy {
                allow_overwrite: true,
                allow_non_atomic_copy: false,
                ..Default::default()
            },
        );

        assert!(matches!(result, Err(ReleaseError::HardLinkSurprise { .. })));
        assert_eq!(fs::read(&destination)?, b"do not truncate");
        assert_eq!(fs::read(&alias)?, b"do not truncate");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn temp_file_names_are_unpredictable_across_calls() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("temp-random")?;
        let parent = Dir::open_ambient_dir(&root, ambient_authority())?;
        let mut first = SiblingTemp::create(&parent, ReleaseFsMode::ForceNamedTempForTest)?;
        let mut second = SiblingTemp::create(&parent, ReleaseFsMode::ForceNamedTempForTest)?;

        assert_ne!(first.name, second.name);
        assert!(matches!(
            first.name.as_deref(),
            Some(name) if name.to_string_lossy().starts_with(".arbitraitor-release-")
        ));
        assert!(matches!(
            second.name.as_deref(),
            Some(name) if name.to_string_lossy().starts_with(".arbitraitor-release-")
        ));
        first.remove()?;
        second.remove()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn otmpfile_temp_has_no_visible_name_before_publish() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = temp_root("otmpfile-invisible")?;
        let parent = Dir::open_ambient_dir(&root, ambient_authority())?;
        let temp = SiblingTemp::create(&parent, ReleaseFsMode::Normal)?;

        assert_eq!(temp.kind, SiblingTempKind::Anonymous);
        assert_eq!(temp.name, None);
        assert_eq!(temp.file.metadata()?.nlink(), 0);
        let entries = fs::read_dir(&root)?.collect::<Result<Vec<_>, _>>()?;
        assert!(entries.is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn otmpfile_temp_cannot_be_hard_linked_through_std_procfd()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("otmpfile-hardlink")?;
        let parent = Dir::open_ambient_dir(&root, ambient_authority())?;
        let temp = SiblingTemp::create(&parent, ReleaseFsMode::Normal)?;
        let proc_path = PathBuf::from(format!("/proc/self/fd/{}", temp.file.as_raw_fd()));
        let alias = root.join("attacker-link");

        let result = fs::hard_link(proc_path, &alias);

        assert!(result.is_err());
        assert!(!alias.exists());
        assert_eq!(temp.file.metadata()?.nlink(), 0);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn forced_named_temp_fallback_releases_and_cleans_up()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("named-fallback")?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = store_bytes(&store, b"named fallback bytes").await?;
        let destination = root.join("released.bin");

        let receipt = release_artifact_inner(
            &store,
            &digest,
            &destination,
            &ReleasePolicy::default(),
            &ProvenanceConfig::default(),
            ReleaseFsMode::ForceNamedTempForTest,
        )?;

        assert_eq!(receipt.method, ReleaseMethod::AtomicNoReplaceLink);
        assert_eq!(read_std_digest(&destination)?, digest);
        let leftover_temp_count = fs::read_dir(&root)?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".arbitraitor-release-")
            })
            .count();
        assert_eq!(leftover_temp_count, 0);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn non_atomic_partial_copy_failure_removes_destination()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("partial-cleanup")?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = store_bytes(&store, b"bytes that will fail mid-copy").await?;
        let destination = root.join("partial-output");

        let result = release_artifact_inner(
            &store,
            &digest,
            &destination,
            &ReleasePolicy {
                allow_overwrite: false,
                allow_non_atomic_copy: true,
                ..Default::default()
            },
            &ProvenanceConfig::default(),
            ReleaseFsMode::ForceNonAtomicCopyFailureForTest,
        );

        assert!(matches!(result, Err(ReleaseError::Io { .. })));
        assert!(!destination.exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn fd_link_count_validation_rejects_linked_destination_before_truncate()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("fd-link-count")?;
        let destination = root.join("destination");
        let alias = root.join("alias");
        fs::write(&destination, b"preserve")?;
        fs::hard_link(&destination, &alias)?;
        let parent = DestinationParent::open(&destination)?;

        let result = open_non_atomic_destination(
            &parent,
            &destination,
            &ReleasePolicy {
                allow_overwrite: true,
                allow_non_atomic_copy: true,
                ..Default::default()
            },
            &ProvenanceConfig::default(),
        );

        assert!(matches!(result, Err(ReleaseError::HardLinkSurprise { .. })));
        assert_eq!(fs::read(&destination)?, b"preserve");
        assert_eq!(fs::read(&alias)?, b"preserve");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn cross_filesystem_fallback_is_gated_by_policy() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = temp_root("fallback")?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = store_bytes(&store, b"fallback bytes").await?;
        let denied_destination = root.join("denied");

        let denied = release_artifact_inner(
            &store,
            &digest,
            &denied_destination,
            &ReleasePolicy::default(),
            &ProvenanceConfig::default(),
            ReleaseFsMode::ForceNonAtomicForTest,
        );
        assert!(matches!(
            denied,
            Err(ReleaseError::NonAtomicCopyNotApproved { .. })
        ));
        assert!(!denied_destination.exists());

        let approved_destination = root.join("approved");
        let receipt = release_artifact_inner(
            &store,
            &digest,
            &approved_destination,
            &ReleasePolicy {
                allow_overwrite: false,
                allow_non_atomic_copy: true,
                ..Default::default()
            },
            &ProvenanceConfig::default(),
            ReleaseFsMode::ForceNonAtomicForTest,
        )?;
        assert_eq!(receipt.method, ReleaseMethod::NonAtomicCopy);
        assert_eq!(receipt.warnings.len(), 1);
        assert_eq!(read_std_digest(&approved_destination)?, digest);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn final_mode_produces_executable_permission_after_atomic_release()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("final-mode")?;
        let store = ContentStore::open(&root.join("store"))?;
        let bytes = b"native binary payload";
        let digest = store_bytes(&store, bytes).await?;
        let destination = root.join("native.bin");

        let receipt = release_artifact(
            &store,
            &digest,
            &destination,
            &ReleasePolicy {
                final_mode: Some(0o700),
                ..ReleasePolicy::default()
            },
        )?;

        assert_eq!(receipt.destination, destination);
        assert_eq!(fs::read(&destination)?, bytes);
        assert_eq!(
            fs::metadata(&destination)?.permissions().mode() & 0o777,
            0o700,
            "final_mode must chmod the released inode via the capability handle"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn final_mode_rejects_pre_created_symlink_at_destination()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("final-mode-symlink")?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = store_bytes(&store, b"native binary payload").await?;
        let outside = root.join("outside-target");
        let destination = root.join("native.bin");
        fs::write(&outside, b"sensitive outside bytes")?;
        symlink(&outside, &destination)?;

        let result = release_artifact(
            &store,
            &digest,
            &destination,
            &ReleasePolicy {
                final_mode: Some(0o700),
                ..ReleasePolicy::default()
            },
        );

        assert!(matches!(
            result,
            Err(ReleaseError::ForbiddenIndirection { .. })
        ));
        // The symlink target must be untouched — no overwrite, no follow.
        assert_eq!(fs::read(&outside)?, b"sensitive outside bytes");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn final_mode_with_overwrite_replaces_existing_executable()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("final-mode-overwrite")?;
        let store = ContentStore::open(&root.join("store"))?;
        let bytes = b"replacement native payload";
        let digest = store_bytes(&store, bytes).await?;
        let destination = root.join("native.bin");
        fs::write(&destination, b"old payload")?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;

        release_artifact(
            &store,
            &digest,
            &destination,
            &ReleasePolicy {
                allow_overwrite: true,
                final_mode: Some(0o700),
                ..ReleasePolicy::default()
            },
        )?;

        assert_eq!(fs::read(&destination)?, bytes);
        assert_eq!(
            fs::metadata(&destination)?.permissions().mode() & 0o777,
            0o700
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn default_final_mode_is_none_and_keeps_0600() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("final-mode-default")?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = store_bytes(&store, b"plain release").await?;
        let destination = root.join("released.bin");

        release_artifact(&store, &digest, &destination, &ReleasePolicy::default())?;

        assert_eq!(
            fs::metadata(&destination)?.permissions().mode() & 0o777,
            0o600,
            "absent final_mode must preserve ADR-0015's restrictive 0600 default"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn released_file_digest_matches_scanned_digest_for_arbitrary_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Runtime::new()?;
        let mut runner = TestRunner::default();
        let strategy = proptest::collection::vec(any::<u8>(), 0..4096);

        runner.run(&strategy, |bytes| {
            let root = temp_root("digest-property")
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let store = ContentStore::open(&root.join("store"))
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let digest = runtime
                .block_on(store_bytes(&store, &bytes))
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let destination = root.join("released.bin");

            release_artifact(&store, &digest, &destination, &ReleasePolicy::default())
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let released =
                fs::read(&destination).map_err(|error| TestCaseError::fail(error.to_string()))?;
            prop_assert_eq!(digest_bytes(&released), digest);
            prop_assert_eq!(released, bytes);
            fs::remove_dir_all(root).map_err(|error| TestCaseError::fail(error.to_string()))?;
            Ok(())
        })?;
        Ok(())
    }

    #[test]
    fn stale_verdict_blocks_release() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("stale-verdict")?;
        let store = ContentStore::open(&root.join("store"))?;
        let runtime = tokio::runtime::Runtime::new()?;
        let digest = runtime.block_on(store_bytes(&store, b"stale-verdict-test"))?;
        let destination = root.join("stale.bin");

        let policy = ReleasePolicy {
            verdict_max_age: Some(Duration::from_secs(1)),
            verdict_timestamp: Some(SystemTime::now() - Duration::from_secs(10)),
            ..ReleasePolicy::default()
        };

        let result = release_artifact(&store, &digest, &destination, &policy);
        assert!(
            matches!(result, Err(ReleaseError::StaleVerdict { .. })),
            "stale verdict must block release: {result:?}"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn fresh_verdict_allows_release() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("fresh-verdict")?;
        let store = ContentStore::open(&root.join("store"))?;
        let runtime = tokio::runtime::Runtime::new()?;
        let digest = runtime.block_on(store_bytes(&store, b"fresh-verdict-test"))?;
        let destination = root.join("fresh.bin");

        let policy = ReleasePolicy {
            verdict_max_age: Some(Duration::from_mins(1)),
            verdict_timestamp: Some(SystemTime::now()),
            ..ReleasePolicy::default()
        };

        let result = release_artifact(&store, &digest, &destination, &policy);
        assert!(
            result.is_ok(),
            "fresh verdict must allow release: {result:?}"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn no_freshness_check_when_max_age_unset() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("no-freshness")?;
        let store = ContentStore::open(&root.join("store"))?;
        let runtime = tokio::runtime::Runtime::new()?;
        let digest = runtime.block_on(store_bytes(&store, b"no-freshness-test"))?;
        let destination = root.join("none.bin");

        let policy = ReleasePolicy {
            verdict_max_age: None,
            verdict_timestamp: Some(SystemTime::now() - Duration::from_secs(9999)),
            ..ReleasePolicy::default()
        };

        let result = release_artifact(&store, &digest, &destination, &policy);
        assert!(
            result.is_ok(),
            "when verdict_max_age is None, release must proceed: {result:?}"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn stdout_emit_verifies_digest_and_writes_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("stdout-emit")?;
        let store = ContentStore::open(&root.join("store"))?;
        let runtime = tokio::runtime::Runtime::new()?;
        let data = b"hello stdout release";
        let digest = runtime.block_on(store_bytes(&store, data))?;

        let mut output = Vec::new();
        let receipt = emit_artifact_to_stdout(&store, &digest, &mut output)?;

        assert_eq!(output.as_slice(), data);
        assert_eq!(receipt.method, ReleaseMethod::StdoutEmit);
        assert_eq!(receipt.bytes_written, data.len() as u64);
        assert_eq!(receipt.digest, digest);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn stdout_emit_rejects_digest_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("stdout-mismatch")?;
        let store = ContentStore::open(&root.join("store"))?;
        let runtime = tokio::runtime::Runtime::new()?;
        let _digest = runtime.block_on(store_bytes(&store, b"actual data"))?;
        let wrong_digest = Sha256Digest::new([0xff; 32]);

        let mut output = Vec::new();
        let result = emit_artifact_to_stdout(&store, &wrong_digest, &mut output);
        assert!(result.is_err(), "mismatched digest must fail");
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
