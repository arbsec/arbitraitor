//! Content-addressed storage for quarantined artifacts
//!
//! See `docs/spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arbitraitor_fetch::{ArtifactSink, ArtifactSinkError};
use arbitraitor_model::ids::{ArtifactId, Sha256Digest};
use async_trait::async_trait;
use cap_std::ambient_authority;
use cap_std::fs::{Dir, DirBuilder, File, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use cap_tempfile::TempFile;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, instrument};

pub mod gc;
pub mod metadata;
pub mod nonce;
pub mod retention;

pub use gc::{GarbageCollector, GcStats};
pub use metadata::{MetadataEntry, MetadataIndex};
pub use nonce::SpentNonceStore;
pub use retention::RetentionMode;

const OBJECTS_DIR: &str = "objects";
const LOCKS_DIR: &str = "locks";
const STAGING_DIR: &str = "staging";
const META_DB: &str = "meta.db";
const SHA256_HEX_LEN: usize = 64;
const DEFAULT_MAX_BYTES: u64 = 1024 * 1024 * 1024;

#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;
#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;
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

/// Content-addressed quarantine store rooted at one filesystem capability.
#[derive(Clone)]
pub struct ContentStore {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    root: Dir,
    staging: Dir,
    root_path: PathBuf,
    metadata: MetadataIndex,
}

/// Guard for an artifact operation lock in the metadata index.
pub struct ArtifactLock {
    digest: Sha256Digest,
    store: Arc<ContentStore>,
    _lock: Option<LockGuard>,
}

/// A streaming artifact sink that hashes bytes while writing to a staging file.
pub struct StreamingSink<'store> {
    store: &'store ContentStore,
    temp: Option<TempFile<'store>>,
    hasher: Sha256,
    bytes_written: u64,
    max_bytes: u64,
    expected_digest: Option<Sha256Digest>,
    lock: Option<LockGuard>,
    finished: bool,
}

/// A read-only handle to a verified artifact in the CAS store.
///
/// # Verification
///
/// The content digest is verified once at handle creation. The handle does NOT
/// continuously verify content integrity. If the underlying file is modified
/// after handle creation, reads may return bytes that no longer match the
/// expected digest.
///
/// Callers that need streaming integrity verification (e.g., during release)
/// should re-hash while reading and verify the final digest.
pub struct ArtifactHandle {
    digest: Sha256Digest,
    size: u64,
    file: File,
}

/// Store operation failure.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Filesystem I/O failed during a named stage.
    #[error("store I/O failure during {stage}: {source}")]
    Io {
        /// Operation stage.
        stage: &'static str,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// The computed digest did not match the expected digest.
    #[error("digest mismatch: expected {expected}, actual {actual}")]
    DigestMismatch {
        /// Expected SHA-256 digest.
        expected: Sha256Digest,
        /// Actual SHA-256 digest.
        actual: Sha256Digest,
    },
    /// A per-digest operation lock is already held.
    #[error("artifact operation already active for digest {digest}")]
    LockHeld {
        /// Locked digest.
        digest: Sha256Digest,
    },
    /// A store path component is a symlink.
    #[error("symlink detected in store path: {0}")]
    SymlinkDetected(PathBuf),
    /// The requested artifact was not present in the CAS.
    #[error("artifact {digest} was not found")]
    NotFound {
        /// Missing digest.
        digest: Sha256Digest,
    },
    /// The non-authoritative metadata index failed.
    #[error("metadata index failure during {stage}: {message}")]
    Index {
        /// Operation stage.
        stage: &'static str,
        /// Safe diagnostic message.
        message: String,
    },
    /// The streaming sink had already been finished or aborted.
    #[error("streaming sink is already closed")]
    Closed,
    /// Artifact bytes exceeded the configured sink limit.
    #[error("artifact size exceeded limit: attempted {attempted} bytes, maximum {max_bytes} bytes")]
    SizeExceeded {
        /// Attempted total artifact size in bytes.
        attempted: u64,
        /// Maximum allowed artifact size in bytes.
        max_bytes: u64,
    },
}

impl ContentStore {
    /// Opens or initializes a content-addressed store under `root`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the root, CAS directories, staging area, lock
    /// directory, or metadata index cannot be created or opened safely.
    pub fn open(root: &Path) -> Result<Self, StoreError> {
        std::fs::create_dir_all(root).map_err(|source| StoreError::Io {
            stage: "create-root",
            source,
        })?;
        set_std_dir_private(root, "chmod-root")?;

        let cap_root =
            Dir::open_ambient_dir(root, ambient_authority()).map_err(|source| StoreError::Io {
                stage: "open-root",
                source,
            })?;

        ensure_private_dir(&cap_root, root, OBJECTS_DIR)?;
        ensure_private_dir(&cap_root, root, LOCKS_DIR)?;
        ensure_private_dir(&cap_root, root, STAGING_DIR)?;
        let staging = cap_root
            .open_dir(STAGING_DIR)
            .map_err(|source| StoreError::Io {
                stage: "open-staging",
                source,
            })?;

        let metadata = MetadataIndex::open(&root.join(META_DB))?;

        Ok(Self {
            inner: Arc::new(StoreInner {
                root: cap_root,
                staging,
                root_path: root.to_path_buf(),
                metadata,
            }),
        })
    }

    /// Returns the store's non-authoritative metadata index.
    #[must_use]
    pub fn metadata_index(&self) -> &MetadataIndex {
        &self.inner.metadata
    }

    /// Stores a complete artifact and records its rebuildable metadata sidecar.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if storing bytes, writing the sidecar, or updating
    /// the non-authoritative metadata index fails.
    pub fn store_with_metadata(
        &self,
        bytes: Vec<u8>,
        source_url: Option<String>,
        content_type: Option<String>,
        retention: RetentionMode,
    ) -> Result<ArtifactId, StoreError> {
        let size_bytes = u64::try_from(bytes.len()).map_err(|source| StoreError::Io {
            stage: "count-metadata-bytes",
            source: io::Error::new(io::ErrorKind::InvalidData, source),
        })?;
        let mut sink = self.sink(None)?;
        sink.write_chunk_sync(&bytes)?;
        let digest = Sha256Digest::new(sink.hasher.clone().finalize().into());
        drop(bytes);
        sink.lock = Some(self.acquire_lock(&digest)?);
        sink.commit(digest.clone())?;
        sink.finished = true;
        drop(sink.lock.take());

        let entry = MetadataEntry {
            sha256: digest.to_string(),
            retrieved_at: unix_timestamp()?,
            retention_mode: retention,
            locked: false,
            source_url,
            content_type,
            size_bytes,
        };
        entry.write_sidecar(&metadata_sidecar_path(&self.inner.root_path, &digest))?;
        self.inner.metadata.record(entry)?;
        Ok(ArtifactId(digest))
    }

    /// Marks an artifact locked until the returned guard is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the digest lock or metadata update fails.
    pub fn lock(&self, digest: &Sha256Digest) -> Result<ArtifactLock, StoreError> {
        let lock = self.acquire_lock(digest)?;
        self.inner.metadata.set_locked(&digest.to_string(), true)?;
        Ok(ArtifactLock {
            digest: digest.clone(),
            store: Arc::new(self.clone()),
            _lock: Some(lock),
        })
    }

    /// Updates the artifact retention mode in the metadata index and sidecar.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the metadata row is absent or cannot be written.
    pub fn set_retention(
        &self,
        digest: &Sha256Digest,
        mode: RetentionMode,
    ) -> Result<(), StoreError> {
        self.inner
            .metadata
            .set_retention(&digest.to_string(), mode)?;
        if let Some(entry) = self.inner.metadata.get(&digest.to_string())? {
            entry.write_sidecar(&metadata_sidecar_path(&self.inner.root_path, digest))?;
        }
        Ok(())
    }

    /// Creates a streaming sink for receiving a quarantined artifact.
    ///
    /// When `expected_digest` is supplied, the sink obtains a per-digest lock
    /// before accepting bytes.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if staging file creation or lock acquisition fails.
    pub fn sink(
        &self,
        expected_digest: Option<&Sha256Digest>,
    ) -> Result<StreamingSink<'_>, StoreError> {
        self.sink_with_limits(expected_digest, DEFAULT_MAX_BYTES)
    }

    /// Creates a streaming sink with an explicit maximum artifact size in bytes.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if staging file creation or lock acquisition fails.
    pub fn sink_with_limits(
        &self,
        expected_digest: Option<&Sha256Digest>,
        max_bytes: u64,
    ) -> Result<StreamingSink<'_>, StoreError> {
        let lock = expected_digest
            .map(|digest| self.acquire_lock(digest))
            .transpose()?;
        let temp = TempFile::new(&self.inner.staging).map_err(|source| StoreError::Io {
            stage: "create-staging",
            source,
        })?;
        set_file_private(temp.as_file(), "chmod-staging")?;
        Ok(StreamingSink {
            store: self,
            temp: Some(temp),
            hasher: Sha256::new(),
            bytes_written: 0,
            max_bytes,
            expected_digest: expected_digest.cloned(),
            lock,
            finished: false,
        })
    }

    /// Opens a read-only handle for `digest` after verifying stored bytes.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the object is absent or digest verification fails.
    pub fn get(&self, digest: &Sha256Digest) -> Result<ArtifactHandle, StoreError> {
        let path = object_path(digest);
        let mut file = open_read_only_nofollow(&self.inner.root, &self.inner.root_path, &path)
            .map_err(|error| match error {
                StoreError::Io { source, .. } if source.kind() == io::ErrorKind::NotFound => {
                    StoreError::NotFound {
                        digest: digest.clone(),
                    }
                }
                StoreError::Io { source, .. } => StoreError::Io {
                    stage: "open-object",
                    source,
                },
                error => error,
            })?;
        let size = file
            .metadata()
            .map_err(|source| StoreError::Io {
                stage: "metadata-object",
                source,
            })?
            .len();
        let actual = digest_file(&file)?;
        if &actual != digest {
            return Err(StoreError::DigestMismatch {
                expected: digest.clone(),
                actual,
            });
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|source| StoreError::Io {
                stage: "rewind-handle",
                source,
            })?;
        Ok(ArtifactHandle {
            digest: digest.clone(),
            size,
            file,
        })
    }

    /// Returns true when `digest` names an object that verifies successfully.
    #[must_use]
    pub fn contains(&self, digest: &Sha256Digest) -> bool {
        self.verify(digest).is_ok()
    }

    /// Reopens and verifies the CAS object named by `digest`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the object is absent or its bytes no longer hash
    /// to the path digest.
    pub fn verify(&self, digest: &Sha256Digest) -> Result<(), StoreError> {
        self.get(digest).map(|_| ())
    }

    fn acquire_lock(&self, digest: &Sha256Digest) -> Result<LockGuard, StoreError> {
        let path = lock_path(digest);
        let file =
            open_lock_file(&self.inner.root, &self.inner.root_path, &path).map_err(|error| {
                match error {
                    StoreError::Io { source, .. }
                        if source.kind() == io::ErrorKind::AlreadyExists =>
                    {
                        StoreError::LockHeld {
                            digest: digest.clone(),
                        }
                    }
                    StoreError::Io { source, .. } => StoreError::Io {
                        stage: "create-lock",
                        source,
                    },
                    error => error,
                }
            })?;
        Ok(LockGuard {
            root: self
                .inner
                .root
                .try_clone()
                .map_err(|source| StoreError::Io {
                    stage: "clone-root",
                    source,
                })?,
            path,
            _file: file,
        })
    }
}

impl StreamingSink<'_> {
    /// Writes one chunk of artifact bytes to staging and updates SHA-256 state.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the sink is closed, byte count overflows, or the
    /// staged file write fails.
    pub async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), StoreError> {
        tokio::task::yield_now().await;
        self.write_chunk_sync(chunk)
    }

    /// Finishes streaming, verifies any expected digest, and atomically commits
    /// the staged file into the CAS.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if digest verification, fsync, lock acquisition, or
    /// atomic rename fails.
    #[instrument(skip(self), fields(bytes = self.bytes_written))]
    pub async fn finish(mut self) -> Result<Sha256Digest, StoreError> {
        if self.finished {
            return Err(StoreError::Closed);
        }
        let digest = Sha256Digest::new(self.hasher.clone().finalize().into());
        if let Some(expected) = &self.expected_digest
            && expected != &digest
        {
            return Err(StoreError::DigestMismatch {
                expected: expected.clone(),
                actual: digest,
            });
        }
        if self.lock.is_none() {
            self.lock = Some(self.store.acquire_lock(&digest)?);
        }
        self.commit(digest.clone())?;
        self.finished = true;
        drop(self.lock.take());
        debug!(%digest, bytes = self.bytes_written, "committed artifact to CAS");
        Ok(digest)
    }

    /// Aborts the receive operation and removes the staged temporary file.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the sink was already closed.
    pub async fn abort(mut self) -> Result<(), StoreError> {
        tokio::task::yield_now().await;
        if self.finished {
            return Err(StoreError::Closed);
        }
        self.finished = true;
        drop(self.temp.take());
        drop(self.lock.take());
        Ok(())
    }

    fn write_chunk_sync(&mut self, chunk: &[u8]) -> Result<(), StoreError> {
        if self.finished {
            return Err(StoreError::Closed);
        }
        let chunk_len = u64::try_from(chunk.len()).map_err(|source| StoreError::Io {
            stage: "count-bytes",
            source: io::Error::new(io::ErrorKind::InvalidData, source),
        })?;
        let attempted =
            self.bytes_written
                .checked_add(chunk_len)
                .ok_or_else(|| StoreError::Io {
                    stage: "count-bytes",
                    source: io::Error::new(io::ErrorKind::InvalidData, "artifact size overflow"),
                })?;
        if attempted > self.max_bytes {
            self.finished = true;
            drop(self.temp.take());
            drop(self.lock.take());
            return Err(StoreError::SizeExceeded {
                attempted,
                max_bytes: self.max_bytes,
            });
        }
        let temp = self.temp.as_mut().ok_or(StoreError::Closed)?;
        temp.write_all(chunk).map_err(|source| StoreError::Io {
            stage: "write-staging",
            source,
        })?;
        self.hasher.update(chunk);
        self.bytes_written = attempted;
        Ok(())
    }

    fn commit(&mut self, digest: Sha256Digest) -> Result<(), StoreError> {
        let mut temp = self.temp.take().ok_or(StoreError::Closed)?;
        temp.flush().map_err(|source| StoreError::Io {
            stage: "flush-staging",
            source,
        })?;
        temp.as_file().sync_all().map_err(|source| StoreError::Io {
            stage: "fsync-staging",
            source,
        })?;
        temp.seek(SeekFrom::Start(0))
            .map_err(|source| StoreError::Io {
                stage: "rewind-staging",
                source,
            })?;
        let actual = digest_reader(&mut temp)?;
        if actual != digest {
            return Err(StoreError::DigestMismatch {
                expected: digest,
                actual,
            });
        }

        let (shard, shard_created) = ensure_object_shard(&self.store.inner, &digest)?;
        if shard_created {
            sync_dir_path(
                &self.store.inner.root_path.join(OBJECTS_DIR),
                "fsync-objects",
            )?;
        }
        let target = digest.to_string();
        if shard.open(&target).is_ok() {
            drop(temp);
            self.store.verify(&digest)?;
            return Ok(());
        }

        temp.seek(SeekFrom::Start(0))
            .map_err(|source| StoreError::Io {
                stage: "rewind-staging-copy",
                source,
            })?;
        let mut final_temp = TempFile::new(&shard).map_err(|source| StoreError::Io {
            stage: "create-object-temp",
            source,
        })?;
        set_file_private(final_temp.as_file(), "chmod-object-temp")?;
        copy_stream(&mut temp, &mut final_temp)?;
        final_temp.flush().map_err(|source| StoreError::Io {
            stage: "flush-object-temp",
            source,
        })?;
        final_temp
            .as_file()
            .sync_all()
            .map_err(|source| StoreError::Io {
                stage: "fsync-object-temp",
                source,
            })?;
        final_temp
            .replace(&target)
            .map_err(|source| StoreError::Io {
                stage: "rename-object",
                source,
            })?;
        drop(temp);
        sync_dir_path(
            &self
                .store
                .inner
                .root_path
                .join(OBJECTS_DIR)
                .join(&digest.to_string()[..2]),
            "fsync-shard",
        )?;
        self.store.verify(&digest)
    }
}

#[async_trait]
impl ArtifactSink for StreamingSink<'_> {
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), ArtifactSinkError> {
        self.write_chunk_sync(chunk)
            .map_err(|error| ArtifactSinkError::new(error.to_string()))
    }
}

impl ArtifactHandle {
    /// Returns the verified SHA-256 digest for this artifact.
    #[must_use]
    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    /// Returns the verified object size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns read-only access to the verified object bytes.
    #[must_use]
    pub const fn read(&self) -> &File {
        &self.file
    }
}

impl Drop for ArtifactLock {
    fn drop(&mut self) {
        let _ = self
            .store
            .inner
            .metadata
            .set_locked(&self.digest.to_string(), false);
    }
}

struct LockGuard {
    root: Dir,
    path: PathBuf,
    _file: File,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        if let Err(error) = self.root.remove_file(&self.path) {
            debug!(path = %self.path.display(), %error, "failed to remove CAS lock file");
        }
    }
}

fn ensure_private_dir(
    root: &Dir,
    root_path: &Path,
    path: impl AsRef<Path>,
) -> Result<bool, StoreError> {
    let path = path.as_ref();
    reject_intermediate_symlinks(root_path, path)?;
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    builder.mode(PRIVATE_DIR_MODE);
    let created = match root.create_dir_with(path, &builder) {
        Ok(()) => true,
        Err(error)
            if error.kind() == io::ErrorKind::AlreadyExists && root.open_dir(path).is_ok() =>
        {
            false
        }
        Err(source) => {
            return Err(StoreError::Io {
                stage: "create-dir",
                source,
            });
        }
    };
    reject_intermediate_symlinks(root_path, path)?;
    #[cfg(unix)]
    root.set_permissions(path, cap_std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))
        .map_err(|source| StoreError::Io {
            stage: "chmod-dir",
            source,
        })?;
    Ok(created)
}

fn ensure_object_shard(
    store: &StoreInner,
    digest: &Sha256Digest,
) -> Result<(Dir, bool), StoreError> {
    let hex = digest.to_string();
    let shard_path = PathBuf::from(OBJECTS_DIR).join(&hex[..2]);
    let created = ensure_private_dir(&store.root, &store.root_path, &shard_path)?;
    let shard = store
        .root
        .open_dir(&shard_path)
        .map_err(|source| StoreError::Io {
            stage: "open-shard",
            source,
        })?;
    Ok((shard, created))
}

fn object_path(digest: &Sha256Digest) -> PathBuf {
    let hex = digest.to_string();
    debug_assert_eq!(hex.len(), SHA256_HEX_LEN);
    PathBuf::from(OBJECTS_DIR).join(&hex[..2]).join(hex)
}

pub(crate) fn object_absolute_path(root: &Path, digest: &Sha256Digest) -> PathBuf {
    root.join(object_path(digest))
}

pub(crate) fn metadata_sidecar_path(root: &Path, digest: &Sha256Digest) -> PathBuf {
    let hex = digest.to_string();
    root.join(OBJECTS_DIR)
        .join(&hex[..2])
        .join(format!("{hex}.meta.json"))
}

pub(crate) fn remove_artifact_files(
    root: &Path,
    digest: &Sha256Digest,
    index: &MetadataIndex,
) -> Result<u64, StoreError> {
    let object = object_absolute_path(root, digest);
    let sidecar = metadata_sidecar_path(root, digest);
    let object_bytes = std::fs::read(&object).map_err(|source| StoreError::Io {
        stage: "read-object-before-delete",
        source,
    })?;
    let sidecar_bytes = match std::fs::read(&sidecar) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(StoreError::Io {
                stage: "read-sidecar-before-delete",
                source,
            });
        }
    };
    let freed_bytes = u64::try_from(object_bytes.len()).map_err(|source| StoreError::Io {
        stage: "count-deleted-bytes",
        source: io::Error::new(io::ErrorKind::InvalidData, source),
    })?;

    std::fs::remove_file(&object).map_err(|source| StoreError::Io {
        stage: "delete-object",
        source,
    })?;
    if let Err(error) = remove_optional_file(&sidecar) {
        restore_file(
            &object,
            &object_bytes,
            "restore-object-after-sidecar-delete",
        )?;
        return Err(error);
    }
    if let Err(error) = index.delete(&digest.to_string()) {
        restore_file(&object, &object_bytes, "restore-object-after-index-delete")?;
        if let Some(bytes) = &sidecar_bytes {
            restore_file(&sidecar, bytes, "restore-sidecar-after-index-delete")?;
        }
        return Err(error);
    }
    Ok(freed_bytes)
}

fn restore_file(path: &Path, bytes: &[u8], stage: &'static str) -> Result<(), StoreError> {
    std::fs::write(path, bytes).map_err(|source| StoreError::Io { stage, source })?;
    set_std_file_private(path, stage)
}

fn remove_optional_file(path: &Path) -> Result<(), StoreError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(StoreError::Io {
            stage: "delete-sidecar",
            source,
        }),
    }
}

fn unix_timestamp() -> Result<u64, StoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| StoreError::Io {
            stage: "system-time",
            source: io::Error::new(io::ErrorKind::InvalidData, source),
        })
        .map(|duration| duration.as_secs())
}

fn lock_path(digest: &Sha256Digest) -> PathBuf {
    PathBuf::from(LOCKS_DIR).join(format!("{digest}.lock"))
}

fn open_read_only_nofollow(root: &Dir, root_path: &Path, path: &Path) -> Result<File, StoreError> {
    reject_intermediate_symlinks(root_path, path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(O_NOFOLLOW);
    root.open_with(path, &options)
        .map_err(|source| StoreError::Io {
            stage: "open-object",
            source,
        })
}

fn open_lock_file(root: &Dir, root_path: &Path, path: &Path) -> Result<File, StoreError> {
    reject_intermediate_symlinks(root_path, path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(PRIVATE_FILE_MODE);
    #[cfg(unix)]
    options.custom_flags(O_NOFOLLOW);
    root.open_with(path, &options)
        .map_err(|source| StoreError::Io {
            stage: "create-lock",
            source,
        })
}

fn reject_intermediate_symlinks(root: &Path, relative: &Path) -> Result<(), StoreError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StoreError::SymlinkDetected(current));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(StoreError::Io {
                    stage: "metadata-store-path",
                    source,
                });
            }
        }
    }
    Ok(())
}

fn digest_file(file: &File) -> Result<Sha256Digest, StoreError> {
    let mut reader = file.try_clone().map_err(|source| StoreError::Io {
        stage: "clone-object",
        source,
    })?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|source| StoreError::Io {
            stage: "rewind-object",
            source,
        })?;
    digest_reader(&mut reader)
}

fn digest_reader(reader: &mut impl Read) -> Result<Sha256Digest, StoreError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).map_err(|source| StoreError::Io {
            stage: "read-object",
            source,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Sha256Digest::new(hasher.finalize().into()))
}

fn copy_stream(reader: &mut impl Read, writer: &mut impl Write) -> Result<(), StoreError> {
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).map_err(|source| StoreError::Io {
            stage: "read-staging-copy",
            source,
        })?;
        if read == 0 {
            break;
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|source| StoreError::Io {
                stage: "write-object-temp",
                source,
            })?;
    }
    Ok(())
}

fn set_file_private(file: &File, stage: &'static str) -> Result<(), StoreError> {
    #[cfg(unix)]
    file.set_permissions(cap_std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .map_err(|source| StoreError::Io { stage, source })?;
    Ok(())
}

fn set_std_file_private(path: &Path, stage: &'static str) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as StdPermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            .map_err(|source| StoreError::Io { stage, source })?;
    }
    #[cfg(not(unix))]
    let _ = (path, stage);
    Ok(())
}

fn set_std_dir_private(path: &Path, stage: &'static str) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as StdPermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))
            .map_err(|source| StoreError::Io { stage, source })?;
    }
    #[cfg(not(unix))]
    let _ = (path, stage);
    Ok(())
}

fn sync_dir_path(path: &Path, stage: &'static str) -> Result<(), StoreError> {
    std::fs::File::open(path)
        .map_err(|source| StoreError::Io {
            stage: "open-dir-sync",
            source,
        })?
        .sync_all()
        .map_err(|source| StoreError::Io { stage, source })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
