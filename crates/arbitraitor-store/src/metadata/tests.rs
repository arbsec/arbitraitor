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
