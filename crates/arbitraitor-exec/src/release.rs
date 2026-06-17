//! Destination-safe release of approved artifact bytes.
//!
//! Release is the final filesystem boundary crossing: bytes leave quarantine
//! and become visible at a caller-provided path. This module therefore repeats
//! digest verification immediately before and after writing, writes only via a
//! sibling temporary file, refuses surprising destination state, and records the
//! method used for the operation receipt.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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

const PRIVATE_RELEASE_MODE: u32 = 0o600;
const COPY_BUFFER_BYTES: usize = 8192;

#[cfg(any(target_os = "linux", target_os = "android"))]
const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
const O_NOFOLLOW: i32 = 0x0000_0100;

static TEMP_NAME_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Policy gates for destination release.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReleasePolicy {
    /// Permit replacing an existing regular destination file.
    pub allow_overwrite: bool,
    /// Permit the non-atomic copy fallback when atomic publication is unavailable.
    pub allow_non_atomic_copy: bool,
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
    release_artifact_inner(
        store,
        scanned_digest,
        destination,
        policy,
        ReleaseFsMode::Normal,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReleaseFsMode {
    Normal,
    #[cfg(test)]
    ForceNonAtomicForTest,
}

fn release_artifact_inner(
    store: &ContentStore,
    scanned_digest: &Sha256Digest,
    destination: &Path,
    policy: &ReleasePolicy,
    fs_mode: ReleaseFsMode,
) -> Result<ReleaseReceipt, ReleaseError> {
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
    let temp = SiblingTemp::create(&parent.dir)?;
    let bytes_written = write_and_verify_temp(&handle, scanned_digest, &temp.file)?;
    let method = publish_temp(&parent, temp, destination, policy, fs_mode)?;
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
        reject_parent_indirection(parent)?;
        let dir = Dir::open_ambient_dir(parent, ambient_authority()).map_err(|source| {
            ReleaseError::Io {
                stage: "open-destination-parent",
                source,
            }
        })?;
        let metadata = dir.dir_metadata().map_err(|source| ReleaseError::Io {
            stage: "metadata-destination-parent",
            source,
        })?;
        if !metadata.is_dir() {
            return Err(ReleaseError::UnsafeDestination {
                path: parent.to_path_buf(),
            });
        }
        Ok(Self {
            dir,
            path: parent.to_path_buf(),
            name,
        })
    }
}

struct SiblingTemp {
    dir: Dir,
    name: OsString,
    file: File,
    removed: bool,
}

impl SiblingTemp {
    fn create(parent: &Dir) -> Result<Self, ReleaseError> {
        let dir = parent.try_clone().map_err(|source| ReleaseError::Io {
            stage: "clone-destination-parent",
            source,
        })?;
        for _attempt in 0..128 {
            let counter = TEMP_NAME_COUNTER.fetch_add(1, Ordering::Relaxed);
            let name = OsString::from(format!(
                ".arbitraitor-release-{}-{counter}.tmp",
                std::process::id()
            ));
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            options.mode(PRIVATE_RELEASE_MODE);
            options.custom_flags(O_NOFOLLOW);
            match dir.open_with(&name, &options) {
                Ok(file) => {
                    file.set_permissions(Permissions::from_mode(PRIVATE_RELEASE_MODE))
                        .map_err(|source| ReleaseError::Io {
                            stage: "chmod-release-temp",
                            source,
                        })?;
                    return Ok(Self {
                        dir,
                        name,
                        file,
                        removed: false,
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
        if !self.removed {
            self.dir
                .remove_file(&self.name)
                .map_err(|source| ReleaseError::Io {
                    stage: "remove-release-temp",
                    source,
                })?;
            self.removed = true;
        }
        Ok(())
    }
}

impl Drop for SiblingTemp {
    fn drop(&mut self) {
        if !self.removed {
            let _cleanup_result = self.dir.remove_file(&self.name);
        }
    }
}

fn reject_parent_indirection(parent: &Path) -> Result<(), ReleaseError> {
    let mut current = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => current.push(component.as_os_str()),
            Component::CurDir => continue,
            Component::Normal(part) => current.push(part),
            Component::ParentDir => {
                return Err(ReleaseError::UnsafeDestination {
                    path: parent.to_path_buf(),
                });
            }
        }
        if current.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(&current).map_err(|source| ReleaseError::Io {
            stage: "metadata-destination-parent-component",
            source,
        })?;
        if metadata.file_type().is_symlink() || is_forbidden_special_std(&metadata) {
            return Err(ReleaseError::ForbiddenIndirection { path: current });
        }
    }
    Ok(())
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

fn is_forbidden_special_std(metadata: &fs::Metadata) -> bool {
    let file_type = metadata.file_type();
    file_type.is_block_device()
        || file_type.is_char_device()
        || file_type.is_fifo()
        || file_type.is_socket()
}

fn write_and_verify_temp(
    handle: &arbitraitor_store::ArtifactHandle,
    expected: &Sha256Digest,
    temp_file: &File,
) -> Result<u64, ReleaseError> {
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
    if metadata.nlink() != 1 {
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
    fs_mode: ReleaseFsMode,
) -> Result<ReleaseMethod, ReleaseError> {
    #[cfg(test)]
    if fs_mode == ReleaseFsMode::ForceNonAtomicForTest {
        return publish_non_atomic(parent, &mut temp, destination, policy);
    }
    let _ = fs_mode;
    if policy.allow_overwrite {
        reject_existing_destination(&parent.dir, &parent.name, destination, policy)?;
        match temp.dir.rename(&temp.name, &parent.dir, &parent.name) {
            Ok(()) => {
                temp.removed = true;
                sync_parent_dir(&parent.path)?;
                Ok(ReleaseMethod::AtomicRename)
            }
            Err(error) if is_cross_filesystem(&error) => {
                publish_non_atomic(parent, &mut temp, destination, policy)
            }
            Err(source) => Err(ReleaseError::Io {
                stage: "rename-release-temp",
                source,
            }),
        }
    } else {
        match temp.dir.hard_link(&temp.name, &parent.dir, &parent.name) {
            Ok(()) => {
                temp.remove()?;
                sync_parent_dir(&parent.path)?;
                Ok(ReleaseMethod::AtomicNoReplaceLink)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Err(ReleaseError::DestinationExists {
                    path: destination.to_path_buf(),
                })
            }
            Err(error) if is_cross_filesystem(&error) => {
                publish_non_atomic(parent, &mut temp, destination, policy)
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
) -> Result<ReleaseMethod, ReleaseError> {
    if !policy.allow_non_atomic_copy {
        return Err(ReleaseError::NonAtomicCopyNotApproved {
            reason: "atomic publication failed with cross-filesystem semantics".to_owned(),
        });
    }
    warn!(destination = %destination.display(), "using policy-approved non-atomic release copy");
    reject_existing_destination(&parent.dir, &parent.name, destination, policy)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(!policy.allow_overwrite);
    if policy.allow_overwrite {
        options.create(true).truncate(true);
    }
    options.mode(PRIVATE_RELEASE_MODE);
    options.custom_flags(O_NOFOLLOW);
    let mut output = parent
        .dir
        .open_with(&parent.name, &options)
        .map_err(|source| ReleaseError::Io {
            stage: "open-non-atomic-destination",
            source,
        })?;
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
    copy_stream(&mut input, &mut output)?;
    output.flush().map_err(|source| ReleaseError::Io {
        stage: "flush-non-atomic-destination",
        source,
    })?;
    output.sync_all().map_err(|source| ReleaseError::Io {
        stage: "fsync-non-atomic-destination",
        source,
    })?;
    temp.remove()?;
    sync_parent_dir(&parent.path)?;
    Ok(ReleaseMethod::NonAtomicCopy)
}

fn verify_final_destination(
    parent: &Dir,
    name: &OsStr,
    destination: &Path,
    expected: &Sha256Digest,
) -> Result<(), ReleaseError> {
    let metadata = parent
        .symlink_metadata(name)
        .map_err(|source| ReleaseError::Io {
            stage: "metadata-final-destination",
            source,
        })?;
    reject_destination_metadata(destination, &metadata)?;
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(O_NOFOLLOW);
    let mut file = parent
        .open_with(name, &options)
        .map_err(|source| ReleaseError::Io {
            stage: "open-final-destination",
            source,
        })?;
    verify_reader_digest(&mut file, expected, "verify-final-destination")
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
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{
        MetadataExt as StdMetadataExt, PermissionsExt as StdPermissionsExt, symlink,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

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
            },
        )?;
        assert_eq!(receipt.method, ReleaseMethod::AtomicRename);
        assert_eq!(read_std_digest(&destination)?, digest);
        assert_eq!(fs::metadata(&destination)?.nlink(), 1);
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
            },
            ReleaseFsMode::ForceNonAtomicForTest,
        )?;
        assert_eq!(receipt.method, ReleaseMethod::NonAtomicCopy);
        assert_eq!(receipt.warnings.len(), 1);
        assert_eq!(read_std_digest(&approved_destination)?, digest);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
