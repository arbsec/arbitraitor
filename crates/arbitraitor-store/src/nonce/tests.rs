use std::collections::HashSet;

use tempfile::TempDir;

use crate::StoreError;
use crate::nonce::SpentNonceStore;

fn store() -> Result<(TempDir, SpentNonceStore), StoreError> {
    let root = TempDir::new().map_err(|source| StoreError::Io {
        stage: "test-temp-dir",
        source,
    })?;
    let path = root.path().join("nonces.db");
    let store = SpentNonceStore::open(&path)?;
    Ok((root, store))
}

fn path_for(root: &TempDir) -> std::path::PathBuf {
    root.path().join("nonces.db")
}

#[test]
fn insert_returns_true_for_new_nonce() -> Result<(), StoreError> {
    let (_root, store) = store()?;
    assert!(store.insert("nonce-1")?);
    Ok(())
}

#[test]
fn insert_returns_false_for_duplicate_nonce() -> Result<(), StoreError> {
    let (_root, store) = store()?;
    assert!(store.insert("nonce-1")?);
    assert!(!store.insert("nonce-1")?);
    Ok(())
}

#[test]
fn contains_returns_false_for_unknown_nonce() -> Result<(), StoreError> {
    let (_root, store) = store()?;
    assert!(!store.contains("absent")?);
    Ok(())
}

#[test]
fn contains_returns_true_after_insert() -> Result<(), StoreError> {
    let (_root, store) = store()?;
    store.insert("nonce-2")?;
    assert!(store.contains("nonce-2")?);
    Ok(())
}

#[test]
fn load_all_returns_every_inserted_nonce() -> Result<(), StoreError> {
    let (_root, store) = store()?;
    store.insert("a")?;
    store.insert("b")?;
    store.insert("c")?;
    let all = store.load_all()?;
    let expected: HashSet<String> = ["a", "b", "c"].into_iter().map(String::from).collect();
    assert_eq!(all, expected);
    Ok(())
}

#[test]
fn load_all_is_empty_for_fresh_store() -> Result<(), StoreError> {
    let (_root, store) = store()?;
    assert!(store.load_all()?.is_empty());
    Ok(())
}

#[test]
fn nonces_persist_across_reopen() -> Result<(), StoreError> {
    let (root, store) = store()?;
    store.insert("persisted-nonce")?;
    drop(store);

    // Reopen the same database file — the nonce must survive.
    let reopened = SpentNonceStore::open(&path_for(&root))?;
    assert!(reopened.contains("persisted-nonce")?);
    assert!(
        reopened.load_all()?.contains("persisted-nonce"),
        "reopened store must contain the persisted nonce"
    );
    Ok(())
}

#[test]
fn duplicate_insert_across_reopen_returns_false() -> Result<(), StoreError> {
    let (root, store) = store()?;
    assert!(store.insert("once")?);
    drop(store);

    let reopened = SpentNonceStore::open(&path_for(&root))?;
    assert!(
        !reopened.insert("once")?,
        "replayed nonce must be rejected across reopen"
    );
    Ok(())
}

#[test]
fn fresh_nonce_succeeds_after_reopen() -> Result<(), StoreError> {
    let (root, store) = store()?;
    store.insert("old")?;
    drop(store);

    let reopened = SpentNonceStore::open(&path_for(&root))?;
    assert!(
        reopened.insert("new")?,
        "fresh nonce must succeed after reopen"
    );
    Ok(())
}
