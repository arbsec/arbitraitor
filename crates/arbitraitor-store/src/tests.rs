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
async fn atomic_commit_does_not_leave_partial_state() -> Result<(), Box<dyn std::error::Error>> {
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
async fn store_enforces_byte_limit() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root()?;
    let store = ContentStore::open(&root)?;
    let mut sink = store.sink_with_limits(None, 5)?;
    sink.write_chunk(b"12345").await?;
    assert!(matches!(
        sink.write_chunk(b"6").await,
        Err(StoreError::SizeExceeded {
            attempted: 6,
            max_bytes: 5
        })
    ));
    assert_eq!(fs::read_dir(root.join(STAGING_DIR))?.count(), 0);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn store_rejects_symlinked_shard_directory() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let root = temp_root()?;
    let outside = temp_root()?;
    let store = ContentStore::open(&root)?;
    let bytes = b"symlink shard bytes";
    let digest = digest_bytes(bytes);
    let hex = digest.to_string();
    symlink(&outside, root.join(OBJECTS_DIR).join(&hex[..2]))?;
    assert!(matches!(
        store_bytes(&store, Some(&digest), bytes).await,
        Err(StoreError::SymlinkDetected(_))
    ));
    fs::remove_file(root.join(OBJECTS_DIR).join(&hex[..2]))?;
    fs::remove_dir_all(root)?;
    fs::remove_dir_all(outside)?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn get_rejects_symlinked_objects_directory() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let root = temp_root()?;
    let outside = temp_root()?;
    let store = ContentStore::open(&root)?;
    let digest = store_bytes(&store, None, b"objects symlink bytes").await?;
    fs::remove_dir_all(root.join(OBJECTS_DIR))?;
    symlink(&outside, root.join(OBJECTS_DIR))?;
    assert!(matches!(
        store.get(&digest),
        Err(StoreError::SymlinkDetected(_))
    ));
    fs::remove_file(root.join(OBJECTS_DIR))?;
    fs::remove_dir_all(root)?;
    fs::remove_dir_all(outside)?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn get_rejects_symlinked_shard_directory() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let root = temp_root()?;
    let outside = temp_root()?;
    let store = ContentStore::open(&root)?;
    let digest = store_bytes(&store, None, b"shard symlink bytes").await?;
    let hex = digest.to_string();
    let shard_path = root.join(OBJECTS_DIR).join(&hex[..2]);
    fs::remove_dir_all(&shard_path)?;
    symlink(&outside, &shard_path)?;
    assert!(matches!(
        store.get(&digest),
        Err(StoreError::SymlinkDetected(_))
    ));
    fs::remove_file(shard_path)?;
    fs::remove_dir_all(root)?;
    fs::remove_dir_all(outside)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn lock_rejects_symlinked_locks_directory() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let root = temp_root()?;
    let outside = temp_root()?;
    let store = ContentStore::open(&root)?;
    let digest = digest_bytes(b"lock symlink bytes");
    fs::remove_dir_all(root.join(LOCKS_DIR))?;
    symlink(&outside, root.join(LOCKS_DIR))?;
    assert!(matches!(
        store.sink(Some(&digest)),
        Err(StoreError::SymlinkDetected(_))
    ));
    fs::remove_file(root.join(LOCKS_DIR))?;
    fs::remove_dir_all(root)?;
    fs::remove_dir_all(outside)?;
    Ok(())
}

#[tokio::test]
async fn new_shard_reports_parent_directory_fsync_needed_once()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root()?;
    let store = ContentStore::open(&root)?;
    let digest = digest_bytes(b"new shard fsync marker");
    let (_first_shard, first_created) = ensure_object_shard(&store.inner, &digest)?;
    assert!(first_created);
    let (_second_shard, second_created) = ensure_object_shard(&store.inner, &digest)?;
    assert!(!second_created);
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

#[tokio::test]
async fn contains_returns_false_for_missing_digest() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root()?;
    let store = ContentStore::open(&root)?;
    let missing = Sha256Digest::new([0xff; 32]);
    assert!(!store.contains(&missing));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn get_returns_not_found_for_missing_digest() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root()?;
    let store = ContentStore::open(&root)?;
    let missing = Sha256Digest::new([0xab; 32]);
    let result = store.get(&missing);
    assert!(result.is_err());
    let err = result.err().ok_or("expected error")?;
    assert!(matches!(err, StoreError::NotFound { .. }));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn verify_succeeds_for_existing_digest() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root()?;
    let store = ContentStore::open(&root)?;
    let bytes = b"verify-test-data";
    let digest = store_bytes(&store, None, bytes).await?;
    store.verify(&digest)?;
    fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn verify_fails_for_missing_digest() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root()?;
    let store = ContentStore::open(&root)?;
    let missing = Sha256Digest::new([0xcd; 32]);
    let result = store.verify(&missing);
    assert!(result.is_err());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn store_with_metadata_records_source_url() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root()?;
    let store = ContentStore::open(&root)?;
    let bytes = b"metadata-test";
    let artifact_id = store.store_with_metadata(
        bytes.to_vec(),
        Some("https://example.com/test".to_owned()),
        Some("text/plain".to_owned()),
        RetentionMode::Ephemeral,
    )?;
    let index = store.metadata_index();
    let entry = index
        .get(&artifact_id.0.to_string())?
        .ok_or("metadata entry not found")?;
    assert_eq!(
        entry.source_url.as_deref(),
        Some("https://example.com/test")
    );
    assert_eq!(entry.content_type.as_deref(), Some("text/plain"));
    assert_eq!(entry.retention_mode, RetentionMode::Ephemeral);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn set_retention_changes_mode() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root()?;
    let store = ContentStore::open(&root)?;
    let bytes = b"retention-test";
    let artifact_id =
        store.store_with_metadata(bytes.to_vec(), None, None, RetentionMode::Ephemeral)?;
    store.set_retention(&artifact_id.0, RetentionMode::Session)?;
    let index = store.metadata_index();
    let entry = index
        .get(&artifact_id.0.to_string())?
        .ok_or("metadata entry not found")?;
    assert_eq!(entry.retention_mode, RetentionMode::Session);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn lock_prevents_concurrent_write() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root()?;
    let store = ContentStore::open(&root)?;
    let bytes = b"lock-test";
    let artifact_id =
        store.store_with_metadata(bytes.to_vec(), None, None, RetentionMode::Ephemeral)?;
    let _lock = store.lock(&artifact_id.0)?;
    let second_attempt = store.lock(&artifact_id.0);
    assert!(second_attempt.is_err());
    assert!(matches!(
        second_attempt.err().ok_or("expected error")?,
        StoreError::LockHeld { .. }
    ));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn handle_read_returns_correct_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root()?;
    let store = ContentStore::open(&root)?;
    let bytes = b"read-handle-test";
    let digest = store_bytes(&store, None, bytes).await?;
    let handle = store.get(&digest)?;
    let mut read_back = Vec::new();
    handle.read().read_to_end(&mut read_back)?;
    assert_eq!(read_back.as_slice(), bytes);
    assert_eq!(handle.digest(), &digest);
    assert_eq!(handle.size(), u64::try_from(bytes.len())?);
    fs::remove_dir_all(root)?;
    Ok(())
}
