use std::thread;
use std::time::Duration;

use arbitraitor_model::ids::Sha256Digest;
use tempfile::TempDir;

use super::*;
use crate::{ContentStore, StoreError};

fn store() -> Result<(TempDir, ContentStore), StoreError> {
    let root = TempDir::new().map_err(|source| StoreError::Io {
        stage: "test-temp-dir",
        source,
    })?;
    let store = ContentStore::open(root.path())?;
    Ok((root, store))
}

fn store_entry(
    store: &ContentStore,
    bytes: &[u8],
    retention: RetentionMode,
    retrieved_at: u64,
) -> Result<Sha256Digest, StoreError> {
    let artifact = store.store_with_metadata(bytes.to_vec(), None, None, retention)?;
    let digest = artifact.0;
    let mut entry = store
        .metadata_index()
        .get(&digest.to_string())?
        .ok_or_else(|| StoreError::Index {
            stage: "test-metadata-entry",
            message: digest.to_string(),
        })?;
    entry.retrieved_at = retrieved_at;
    store.metadata_index().record(entry.clone())?;
    entry.write_sidecar(&crate::metadata_sidecar_path(
        &store.inner.root_path,
        &digest,
    ))?;
    Ok(digest)
}

#[test]
fn ephemeral_retention_marks_for_immediate_deletion() -> Result<(), StoreError> {
    let (_root, store) = store()?;
    let digest = store_entry(&store, b"ephemeral", RetentionMode::Ephemeral, 1)?;

    let stats = GarbageCollector::new().run(&store, store.metadata_index())?;

    assert_eq!(stats.collected, 1);
    assert!(!store.contains(&digest));
    Ok(())
}

#[test]
fn session_retention_survives_gc_while_running() -> Result<(), StoreError> {
    let (_root, store) = store()?;
    let digest = store_entry(&store, b"session", RetentionMode::Session, 1)?;

    let stats = GarbageCollector::new()
        .with_max_age(Duration::from_secs(0))
        .run(&store, store.metadata_index())?;

    assert_eq!(stats.collected, 0);
    assert!(store.contains(&digest));
    Ok(())
}

#[test]
fn forensic_retention_never_collected() -> Result<(), StoreError> {
    let (_root, store) = store()?;
    let digest = store_entry(&store, b"forensic", RetentionMode::Forensic, 1)?;

    let stats = GarbageCollector::new()
        .with_max_age(Duration::from_secs(0))
        .with_max_size(0)
        .run(&store, store.metadata_index())?;

    assert_eq!(stats.retained_forensic, 1);
    assert!(store.contains(&digest));
    Ok(())
}

#[test]
fn cache_retention_keeps_passed_deletes_blocked() -> Result<(), StoreError> {
    let (_root, store) = store()?;
    let passed = store_entry(&store, b"passed", RetentionMode::Cache, 1)?;
    let blocked = store_entry(&store, b"blocked", RetentionMode::Ephemeral, 1)?;

    let stats = GarbageCollector::new().run(&store, store.metadata_index())?;

    assert_eq!(stats.collected, 1);
    assert!(store.contains(&passed));
    assert!(!store.contains(&blocked));
    Ok(())
}

#[test]
fn gc_respects_active_locks() -> Result<(), StoreError> {
    let (_root, store) = store()?;
    let digest = store_entry(&store, b"locked", RetentionMode::Ephemeral, 1)?;
    let _lock = store.lock(&digest)?;

    let stats = GarbageCollector::new().run(&store, store.metadata_index())?;

    assert_eq!(stats.retained_locked, 1);
    assert!(store.contains(&digest));
    Ok(())
}

#[test]
fn gc_collects_by_age() -> Result<(), StoreError> {
    let (_root, store) = store()?;
    let old = store_entry(&store, b"old", RetentionMode::Indefinite, 1)?;
    let fresh = store_entry(&store, b"fresh", RetentionMode::Indefinite, u64::MAX)?;

    let stats = GarbageCollector::new()
        .with_max_age(Duration::from_secs(1))
        .run(&store, store.metadata_index())?;

    assert_eq!(stats.collected, 1);
    assert!(!store.contains(&old));
    assert!(store.contains(&fresh));
    Ok(())
}

#[test]
fn gc_collects_by_size() -> Result<(), StoreError> {
    let (_root, store) = store()?;
    let oldest = store_entry(&store, b"12345", RetentionMode::Indefinite, 1)?;
    let newest = store_entry(&store, b"12", RetentionMode::Indefinite, 2)?;

    let stats = GarbageCollector::new()
        .with_max_size(2)
        .run(&store, store.metadata_index())?;

    assert_eq!(stats.collected, 1);
    assert!(!store.contains(&oldest));
    assert!(store.contains(&newest));
    Ok(())
}

#[test]
fn lock_prevents_concurrent_gc() -> Result<(), StoreError> {
    let (_root, store) = store()?;
    let digest = store_entry(&store, b"operation", RetentionMode::Ephemeral, 1)?;
    let lock = store.lock(&digest)?;
    let gc_store = store.clone();
    let digest_for_thread = digest.clone();

    let handle = thread::spawn(move || {
        let stats = GarbageCollector::new().run(&gc_store, gc_store.metadata_index())?;
        assert_eq!(stats.retained_locked, 1);
        assert!(gc_store.contains(&digest_for_thread));
        Ok::<(), StoreError>(())
    });
    assert!(handle.join().is_ok_and(|result| result.is_ok()));

    drop(lock);
    let stats = GarbageCollector::new().run(&store, store.metadata_index())?;
    assert_eq!(stats.collected, 1);
    assert!(!store.contains(&digest));
    Ok(())
}
