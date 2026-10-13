#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;

use tempfile::TempDir;

use super::*;

fn entry(sha256: &str) -> MetadataEntry {
    MetadataEntry {
        sha256: sha256.to_owned(),
        retrieved_at: 7,
        retention_mode: RetentionMode::Indefinite,
        locked: false,
        source_url: Some("https://example.invalid/tool".to_owned()),
        content_type: Some("application/octet-stream".to_owned()),
        size_bytes: 3,
    }
}

#[test]
fn metadata_index_rebuild_from_objects() -> Result<(), StoreError> {
    let root = TempDir::new().map_err(|source| StoreError::Io {
        stage: "test-temp-dir",
        source,
    })?;
    let object_dir = root.path().join("objects");
    fs::create_dir_all(object_dir.join("ab")).map_err(|source| StoreError::Io {
        stage: "test-create-shard",
        source,
    })?;
    let sha = "ab00000000000000000000000000000000000000000000000000000000000000";
    fs::write(object_dir.join("ab").join(sha), b"abc").map_err(|source| StoreError::Io {
        stage: "test-write-object",
        source,
    })?;
    entry(sha).write_sidecar(&object_dir.join("ab").join(format!("{sha}.meta.json")))?;

    let index = MetadataIndex::open(&root.path().join("metadata.redb"))?;
    let rebuilt = index.rebuild_from_objects(&object_dir)?;

    assert_eq!(rebuilt, 1);
    assert_eq!(index.get(sha)?, Some(entry(sha)));
    Ok(())
}

#[test]
fn contended_open_names_holder_after_retry_budget() {
    // Hold the metadata database open in-process (simulating another
    // arbitraitor process), then open a second index on the same file: the
    // retry budget must elapse and the error must name the situation rather
    // than surfacing redb's raw "Database already open." message.
    let root = TempDir::new().unwrap();
    let path = root.path().join("meta.db");
    let _holder = MetadataIndex::open(&path).unwrap();

    let started = std::time::Instant::now();
    let Err(error) = MetadataIndex::open(&path) else {
        panic!("contended open must fail");
    };
    let elapsed = started.elapsed();

    // The retry budget ran before failing closed.
    assert!(
        elapsed >= std::time::Duration::from_millis(400),
        "open must exhaust the retry budget, elapsed {elapsed:?}"
    );
    let message = match &error {
        StoreError::Index { message, .. } => message.clone(),
        other => panic!("expected StoreError::Index, got {other:?}"),
    };
    assert!(
        message.contains("another arbitraitor process"),
        "error must name the holder situation: {message}"
    );
    assert!(message.contains("pgrep -af arbitraitor"));
}

#[test]
fn open_succeeds_after_holder_releases_within_retry_budget() {
    // The holder releases the database inside the retry budget: the second
    // open must succeed without surfacing an error. The holder runs on
    // another thread so the drop happens independently of the contended
    // open (the retried open polls until the lock frees).
    let root = TempDir::new().unwrap();
    let path = root.path().join("meta.db");
    let path_for_holder = path.clone();
    let holder = std::thread::spawn(move || {
        let writer = MetadataIndex::open(&path_for_holder).unwrap();
        writer
            .record(entry(
                "ab00000000000000000000000000000000000000000000000000000000000000",
            ))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        // `writer` (and its redb lock) drops when this thread returns.
        writer
    });
    let writer = holder.join().expect("holder thread must not panic");
    drop(writer);

    let reader = MetadataIndex::open(&path).unwrap();
    assert!(
        reader
            .get("ab00000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .is_some(),
        "released store must be readable by the retried open"
    );
}
