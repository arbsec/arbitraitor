//! Rebuildable metadata index for the content-addressed store.

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;
use std::str::FromStr;

use arbitraitor_model::ids::Sha256Digest;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::retention::RetentionMode;
use crate::{SHA256_HEX_LEN, StoreError, metadata_sidecar_path};

const ARTIFACTS: TableDefinition<&str, &str> = TableDefinition::new("artifacts");

/// Rebuildable metadata for one artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataEntry {
    /// SHA-256 digest hex string used as the primary key.
    pub sha256: String,
    /// Unix timestamp when the artifact was retrieved.
    pub retrieved_at: u64,
    /// Retention mode selected for this artifact.
    pub retention_mode: RetentionMode,
    /// True while an active operation holds an artifact lock.
    pub locked: bool,
    /// Optional source URL with secrets already redacted by the caller.
    pub source_url: Option<String>,
    /// Optional retrieved content type.
    pub content_type: Option<String>,
    /// Artifact size in bytes.
    pub size_bytes: u64,
}

/// Non-authoritative redb metadata index.
pub struct MetadataIndex {
    db: redb::Database,
}

impl MetadataEntry {
    /// Writes this entry as a JSON sidecar next to the CAS object.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when JSON serialization or filesystem I/O fails.
    pub fn write_sidecar(&self, path: &Path) -> Result<(), StoreError> {
        let json = serde_json::to_vec_pretty(self).map_err(|source| StoreError::Index {
            stage: "serialize-sidecar",
            message: source.to_string(),
        })?;
        fs::write(path, json).map_err(|source| StoreError::Io {
            stage: "write-sidecar",
            source,
        })
    }
}

impl MetadataIndex {
    /// Opens or creates a metadata index at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when redb cannot be opened or initialized.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let db = if path.exists() {
            redb::Database::open(path)
        } else {
            redb::Database::create(path)
        }
        .map_err(|source| StoreError::Index {
            stage: "open",
            message: source.to_string(),
        })?;
        let index = Self { db };
        index.ensure_table()?;
        Ok(index)
    }

    /// Records or replaces one metadata entry.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when serialization or redb write fails.
    pub fn record(&self, entry: MetadataEntry) -> Result<(), StoreError> {
        let key = entry.sha256.clone();
        let value = serde_json::to_string(&entry).map_err(|source| StoreError::Index {
            stage: "serialize-entry",
            message: source.to_string(),
        })?;
        drop(entry);
        let write = self.begin_write("record-begin")?;
        {
            let mut table = write
                .open_table(ARTIFACTS)
                .map_err(|source| StoreError::Index {
                    stage: "record-open-table",
                    message: source.to_string(),
                })?;
            table
                .insert(key.as_str(), value.as_str())
                .map_err(|source| StoreError::Index {
                    stage: "record-insert",
                    message: source.to_string(),
                })?;
        }
        write.commit().map_err(|source| StoreError::Index {
            stage: "record-commit",
            message: source.to_string(),
        })
    }

    /// Gets one entry by digest hex.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when redb read or JSON parsing fails.
    pub fn get(&self, sha256: &str) -> Result<Option<MetadataEntry>, StoreError> {
        let read = self.begin_read("get-begin")?;
        let table = read
            .open_table(ARTIFACTS)
            .map_err(|source| StoreError::Index {
                stage: "get-open-table",
                message: source.to_string(),
            })?;
        table
            .get(sha256)
            .map_err(|source| StoreError::Index {
                stage: "get-entry",
                message: source.to_string(),
            })?
            .map(|value| parse_entry(value.value(), "parse-entry"))
            .transpose()
    }

    /// Lists all entries in key order.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when redb iteration or JSON parsing fails.
    pub fn list(&self) -> Result<Vec<MetadataEntry>, StoreError> {
        let read = self.begin_read("list-begin")?;
        let table = read
            .open_table(ARTIFACTS)
            .map_err(|source| StoreError::Index {
                stage: "list-open-table",
                message: source.to_string(),
            })?;
        let mut entries = Vec::new();
        for row in table.iter().map_err(|source| StoreError::Index {
            stage: "list-iter",
            message: source.to_string(),
        })? {
            let (_key, value) = row.map_err(|source| StoreError::Index {
                stage: "list-row",
                message: source.to_string(),
            })?;
            entries.push(parse_entry(value.value(), "list-parse")?);
        }
        Ok(entries)
    }

    /// Deletes one metadata entry.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when redb deletion fails.
    pub fn delete(&self, sha256: &str) -> Result<(), StoreError> {
        let write = self.begin_write("delete-begin")?;
        {
            let mut table = write
                .open_table(ARTIFACTS)
                .map_err(|source| StoreError::Index {
                    stage: "delete-open-table",
                    message: source.to_string(),
                })?;
            table.remove(sha256).map_err(|source| StoreError::Index {
                stage: "delete-remove",
                message: source.to_string(),
            })?;
        }
        write.commit().map_err(|source| StoreError::Index {
            stage: "delete-commit",
            message: source.to_string(),
        })
    }

    /// Updates the active-lock flag for one entry.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the entry is absent or redb write fails.
    pub fn set_locked(&self, sha256: &str, locked: bool) -> Result<(), StoreError> {
        let mut entry = self.require_entry(sha256)?;
        entry.locked = locked;
        self.record(entry)
    }

    /// Updates the retention mode for one entry.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the entry is absent or redb write fails.
    pub fn set_retention(&self, sha256: &str, mode: RetentionMode) -> Result<(), StoreError> {
        let mut entry = self.require_entry(sha256)?;
        if entry.retention_mode == RetentionMode::Forensic && mode != RetentionMode::Forensic {
            return Err(StoreError::Index {
                stage: "set-retention",
                message: "forensic retention cannot be downgraded".to_owned(),
            });
        }
        entry.retention_mode = mode;
        self.record(entry)
    }

    /// Rebuilds index rows from object sidecar files.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when scanning, parsing, or redb writes fail.
    pub fn rebuild_from_objects(&self, object_dir: &Path) -> Result<usize, StoreError> {
        let mut rebuilt = 0usize;
        for shard in fs::read_dir(object_dir).map_err(|source| StoreError::Io {
            stage: "read-objects-dir",
            source,
        })? {
            let shard = shard.map_err(|source| StoreError::Io {
                stage: "read-object-shard",
                source,
            })?;
            if !shard
                .file_type()
                .map_err(|source| StoreError::Io {
                    stage: "object-shard-type",
                    source,
                })?
                .is_dir()
            {
                continue;
            }
            rebuilt += self.rebuild_shard(&shard.path())?;
        }
        Ok(rebuilt)
    }

    fn ensure_table(&self) -> Result<(), StoreError> {
        let write = self.begin_write("init-begin")?;
        {
            write
                .open_table(ARTIFACTS)
                .map_err(|source| StoreError::Index {
                    stage: "init-open-table",
                    message: source.to_string(),
                })?;
        }
        write.commit().map_err(|source| StoreError::Index {
            stage: "init-commit",
            message: source.to_string(),
        })
    }

    fn require_entry(&self, sha256: &str) -> Result<MetadataEntry, StoreError> {
        self.get(sha256)?.ok_or_else(|| StoreError::Index {
            stage: "metadata-missing",
            message: format!("missing metadata for {sha256}"),
        })
    }

    fn rebuild_shard(&self, shard: &Path) -> Result<usize, StoreError> {
        let mut rebuilt = 0usize;
        for object in fs::read_dir(shard).map_err(|source| StoreError::Io {
            stage: "read-shard-dir",
            source,
        })? {
            let object = object.map_err(|source| StoreError::Io {
                stage: "read-shard-entry",
                source,
            })?;
            if !is_object_file(&object)? {
                continue;
            }
            let digest = object.file_name().to_string_lossy().into_owned();
            let parsed = Sha256Digest::from_str(&digest).map_err(|source| StoreError::Index {
                stage: "parse-object-digest",
                message: source.to_string(),
            })?;
            let sidecar = metadata_sidecar_path(
                shard
                    .parent()
                    .and_then(Path::parent)
                    .ok_or_else(|| StoreError::Index {
                        stage: "resolve-store-root",
                        message: "object shard is not under objects/<shard>".to_owned(),
                    })?,
                &parsed,
            );
            let json = fs::read_to_string(sidecar).map_err(|source| StoreError::Io {
                stage: "read-sidecar",
                source,
            })?;
            self.record(parse_entry(&json, "parse-sidecar")?)?;
            rebuilt = rebuilt.checked_add(1).ok_or_else(|| StoreError::Io {
                stage: "count-rebuilt",
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "rebuild count overflow",
                ),
            })?;
        }
        Ok(rebuilt)
    }

    fn begin_read(&self, stage: &'static str) -> Result<redb::ReadTransaction, StoreError> {
        self.db.begin_read().map_err(|source| StoreError::Index {
            stage,
            message: source.to_string(),
        })
    }

    fn begin_write(&self, stage: &'static str) -> Result<redb::WriteTransaction, StoreError> {
        self.db.begin_write().map_err(|source| StoreError::Index {
            stage,
            message: source.to_string(),
        })
    }
}

fn parse_entry(json: &str, stage: &'static str) -> Result<MetadataEntry, StoreError> {
    serde_json::from_str(json).map_err(|source| StoreError::Index {
        stage,
        message: source.to_string(),
    })
}

fn is_object_file(entry: &fs::DirEntry) -> Result<bool, StoreError> {
    let file_type = entry.file_type().map_err(|source| StoreError::Io {
        stage: "object-entry-type",
        source,
    })?;
    if !file_type.is_file() {
        return Ok(false);
    }
    let name = entry.file_name().to_string_lossy().into_owned();
    Ok(name.len() == SHA256_HEX_LEN && !name.ends_with(".meta.json"))
}

#[cfg(test)]
mod tests;
