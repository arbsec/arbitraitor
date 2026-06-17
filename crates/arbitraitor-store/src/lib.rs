//! Content-addressed storage for quarantined artifacts
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arbitraitor_fetch::{ArtifactSink, ArtifactSinkError};
use arbitraitor_model::ids::Sha256Digest;
use async_trait::async_trait;
use cap_std::ambient_authority;
use cap_std::fs::{Dir, DirBuilder, File, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use cap_tempfile::TempFile;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, instrument};

const OBJECTS_DIR: &str = "objects";
const LOCKS_DIR: &str = "locks";
const STAGING_DIR: &str = "staging";
const META_DB: &str = "meta.db";
const SHA256_HEX_LEN: usize = 64;

#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;
#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;
#[cfg(all(unix, target_os = "linux"))]
const O_NOFOLLOW: i32 = 0o400_000;

/// Content-addressed quarantine store rooted at one filesystem capability.
#[derive(Clone)]
pub struct ContentStore {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    root: Dir,
    staging: Dir,
    root_path: PathBuf,
    _db: redb::Database,
}

/// A streaming artifact sink that hashes bytes while writing to a staging file.
pub struct StreamingSink<'store> {
    store: &'store ContentStore,
    temp: Option<TempFile<'store>>,
    hasher: Sha256,
    bytes_written: u64,
    expected_digest: Option<Sha256Digest>,
    lock: Option<LockGuard>,
    finished: bool,
}

/// Read-only handle to a digest-verified CAS object.
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

        ensure_private_dir(&cap_root, OBJECTS_DIR)?;
        ensure_private_dir(&cap_root, LOCKS_DIR)?;
        ensure_private_dir(&cap_root, STAGING_DIR)?;
        let staging = cap_root
            .open_dir(STAGING_DIR)
            .map_err(|source| StoreError::Io {
                stage: "open-staging",
                source,
            })?;

        let db_path = root.join(META_DB);
        let db = if db_path.exists() {
            redb::Database::open(&db_path)
        } else {
            redb::Database::create(&db_path)
        }
        .map_err(|source| StoreError::Index {
            stage: "open",
            message: source.to_string(),
        })?;

        Ok(Self {
            inner: Arc::new(StoreInner {
                root: cap_root,
                staging,
                root_path: root.to_path_buf(),
                _db: db,
            }),
        })
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
        let mut file = open_read_only_nofollow(&self.inner.root, &path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                StoreError::NotFound {
                    digest: digest.clone(),
                }
            } else {
                StoreError::Io {
                    stage: "open-object",
                    source,
                }
            }
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
        let file = open_lock_file(&self.inner.root, &path).map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                StoreError::LockHeld {
                    digest: digest.clone(),
                }
            } else {
                StoreError::Io {
                    stage: "create-lock",
                    source,
                }
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
        let temp = self.temp.as_mut().ok_or(StoreError::Closed)?;
        temp.write_all(chunk).map_err(|source| StoreError::Io {
            stage: "write-staging",
            source,
        })?;
        self.hasher.update(chunk);
        self.bytes_written = self
            .bytes_written
            .checked_add(u64::try_from(chunk.len()).map_err(|source| StoreError::Io {
                stage: "count-bytes",
                source: io::Error::new(io::ErrorKind::InvalidData, source),
            })?)
            .ok_or_else(|| StoreError::Io {
                stage: "count-bytes",
                source: io::Error::new(io::ErrorKind::InvalidData, "artifact size overflow"),
            })?;
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

        let shard = ensure_object_shard(&self.store.inner.root, &digest)?;
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

fn ensure_private_dir(root: &Dir, path: impl AsRef<Path>) -> Result<(), StoreError> {
    let path = path.as_ref();
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    builder.mode(PRIVATE_DIR_MODE);
    match root.create_dir_with(path, &builder) {
        Ok(()) => {}
        Err(error)
            if error.kind() == io::ErrorKind::AlreadyExists && root.open_dir(path).is_ok() => {}
        Err(source) => {
            return Err(StoreError::Io {
                stage: "create-dir",
                source,
            });
        }
    }
    #[cfg(unix)]
    root.set_permissions(path, cap_std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))
        .map_err(|source| StoreError::Io {
            stage: "chmod-dir",
            source,
        })?;
    Ok(())
}

fn ensure_object_shard(root: &Dir, digest: &Sha256Digest) -> Result<Dir, StoreError> {
    let hex = digest.to_string();
    let shard_path = PathBuf::from(OBJECTS_DIR).join(&hex[..2]);
    ensure_private_dir(root, &shard_path)?;
    root.open_dir(&shard_path).map_err(|source| StoreError::Io {
        stage: "open-shard",
        source,
    })
}

fn object_path(digest: &Sha256Digest) -> PathBuf {
    let hex = digest.to_string();
    debug_assert_eq!(hex.len(), SHA256_HEX_LEN);
    PathBuf::from(OBJECTS_DIR).join(&hex[..2]).join(hex)
}

fn lock_path(digest: &Sha256Digest) -> PathBuf {
    PathBuf::from(LOCKS_DIR).join(format!("{digest}.lock"))
}

fn open_read_only_nofollow(root: &Dir, path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(all(unix, target_os = "linux"))]
    options.custom_flags(O_NOFOLLOW);
    root.open_with(path, &options)
}

fn open_lock_file(root: &Dir, path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(PRIVATE_FILE_MODE);
    #[cfg(all(unix, target_os = "linux"))]
    options.custom_flags(O_NOFOLLOW);
    root.open_with(path, &options)
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
mod tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use sha2::{Digest, Sha256};
    use tokio::task;

    use super::*;

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_root() -> io::Result<PathBuf> {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "arbitraitor-store-test-{}-{id}",
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
        expected: Option<&Sha256Digest>,
        bytes: &[u8],
    ) -> Result<Sha256Digest, StoreError> {
        let mut sink = store.sink(expected)?;
        for chunk in bytes.chunks(3) {
            sink.write_chunk(chunk).await?;
        }
        sink.finish().await
    }

    #[tokio::test]
    async fn streaming_hash_matches_sha256sum() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root()?;
        let store = ContentStore::open(&root)?;
        let bytes = b"known artifact bytes";
        let digest = store_bytes(&store, None, bytes).await?;
        assert_eq!(digest, digest_bytes(bytes));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn files_created_with_0600_permissions() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as StdPermissionsExt;

        let root = temp_root()?;
        let store = ContentStore::open(&root)?;
        let digest = store_bytes(&store, None, b"mode-check").await?;
        let mode = fs::metadata(root.join(object_path(&digest)))?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, PRIVATE_FILE_MODE);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dirs_created_with_0700_permissions() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as StdPermissionsExt;

        let root = temp_root()?;
        let store = ContentStore::open(&root)?;
        let digest = store_bytes(&store, None, b"dir-mode-check").await?;
        for path in [
            root.join(OBJECTS_DIR),
            root.join(LOCKS_DIR),
            root.join(STAGING_DIR),
            root.join(object_path(&digest))
                .parent()
                .ok_or("no parent")?
                .to_path_buf(),
        ] {
            let mode = fs::metadata(path)?.permissions().mode() & 0o777;
            assert_eq!(mode, PRIVATE_DIR_MODE);
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn digest_mismatch_on_reopen_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root()?;
        let store = ContentStore::open(&root)?;
        let digest = store_bytes(&store, None, b"untampered").await?;
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(root.join(object_path(&digest)))?
            .write_all(b"tampered")?;
        assert!(matches!(
            store.get(&digest),
            Err(StoreError::DigestMismatch { .. })
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn atomic_commit_does_not_leave_partial_state() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = temp_root()?;
        let store = ContentStore::open(&root)?;
        let mut sink = store.sink(None)?;
        sink.write_chunk(b"partial").await?;
        sink.abort().await?;
        assert_eq!(fs::read_dir(root.join(STAGING_DIR))?.count(), 0);
        assert_eq!(fs::read_dir(root.join(OBJECTS_DIR))?.count(), 0);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn sharded_directory_layout() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root()?;
        let store = ContentStore::open(&root)?;
        let bytes = b"layout bytes";
        let digest = digest_bytes(bytes);
        let mut sink = store.sink(Some(&digest))?;
        sink.write_chunk(bytes).await?;
        let actual = sink.finish().await?;
        assert_eq!(actual, digest);
        let hex = digest.to_string();
        assert!(
            Path::new(&root)
                .join(OBJECTS_DIR)
                .join(&hex[..2])
                .join(hex)
                .is_file()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn contains_and_get_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root()?;
        let store = ContentStore::open(&root)?;
        let bytes = b"roundtrip content";
        let digest = store_bytes(&store, None, bytes).await?;
        assert!(store.contains(&digest));
        let handle = store.get(&digest)?;
        assert_eq!(handle.digest(), &digest);
        assert_eq!(handle.size(), u64::try_from(bytes.len())?);
        let mut actual = Vec::new();
        let mut reader = handle.read();
        reader.read_to_end(&mut actual)?;
        assert_eq!(actual, bytes);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_writes_to_different_digests() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root()?;
        let store = ContentStore::open(&root)?;
        let first_store = store.clone();
        let second_store = store.clone();
        let first = task::spawn_blocking(move || {
            tokio::runtime::Handle::current()
                .block_on(async move { store_bytes(&first_store, None, b"first artifact").await })
        });
        let second = task::spawn_blocking(move || {
            tokio::runtime::Handle::current()
                .block_on(async move { store_bytes(&second_store, None, b"second artifact").await })
        });
        let first_digest = first.await??;
        let second_digest = second.await??;
        assert_ne!(first_digest, second_digest);
        assert!(store.contains(&first_digest));
        assert!(store.contains(&second_digest));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn lock_file_prevents_concurrent_write_to_same_digest()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root()?;
        let store = ContentStore::open(&root)?;
        let digest = digest_bytes(b"same digest");
        let _sink = store.sink(Some(&digest))?;
        assert!(matches!(
            store.sink(Some(&digest)),
            Err(StoreError::LockHeld { .. })
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn large_file_streaming() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root()?;
        let store = ContentStore::open(&root)?;
        let mut bytes = Vec::with_capacity(2 * 1024 * 1024);
        for index in 0..(2 * 1024 * 1024) {
            bytes.push(u8::try_from(index % 251)?);
        }
        let digest = store_bytes(&store, None, &bytes).await?;
        assert_eq!(digest, digest_bytes(&bytes));
        assert_eq!(store.get(&digest)?.size(), u64::try_from(bytes.len())?);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
