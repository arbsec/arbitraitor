//! Durable spent-nonce store backed by redb (ADR-0013 replay protection).
//!
//! [`SpentNonceStore`] persists approval-token nonces so a token spent before
//! a process restart cannot be replayed after restart. The store is a single
//! redb table mapping nonce strings to unit values.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::path::Path;

use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use tracing::debug;

use crate::StoreError;

const SPENT_NONCES: TableDefinition<&str, ()> = TableDefinition::new("spent_nonces");

/// Durable store of spent approval-token nonces.
pub struct SpentNonceStore {
    db: redb::Database,
}

impl SpentNonceStore {
    /// Opens or creates the nonce store at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when redb cannot open or initialise the table.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let db = if path.exists() {
            redb::Database::open(path)
        } else {
            redb::Database::create(path)
        }
        .map_err(|source| StoreError::Index {
            stage: "nonce-store-open",
            message: source.to_string(),
        })?;
        let store = Self { db };
        store.ensure_table()?;
        debug!("opened durable spent-nonce store at {}", path.display());
        Ok(store)
    }

    /// Returns `true` when `nonce` has already been spent.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] on redb read failure.
    pub fn contains(&self, nonce: &str) -> Result<bool, StoreError> {
        let read = self.db.begin_read().map_err(|source| StoreError::Index {
            stage: "nonce-contains-begin",
            message: source.to_string(),
        })?;
        let table = read
            .open_table(SPENT_NONCES)
            .map_err(|source| StoreError::Index {
                stage: "nonce-contains-open",
                message: source.to_string(),
            })?;
        Ok(table
            .get(nonce)
            .map_err(|source| StoreError::Index {
                stage: "nonce-contains-get",
                message: source.to_string(),
            })?
            .is_some())
    }

    /// Inserts `nonce`. Returns `false` when the nonce was already present.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] on redb write failure.
    pub fn insert(&self, nonce: &str) -> Result<bool, StoreError> {
        let write = self.db.begin_write().map_err(|source| StoreError::Index {
            stage: "nonce-insert-begin",
            message: source.to_string(),
        })?;
        let inserted = {
            let mut table = write
                .open_table(SPENT_NONCES)
                .map_err(|source| StoreError::Index {
                    stage: "nonce-insert-open",
                    message: source.to_string(),
                })?;
            if table
                .get(nonce)
                .map_err(|source| StoreError::Index {
                    stage: "nonce-insert-get",
                    message: source.to_string(),
                })?
                .is_some()
            {
                false
            } else {
                table
                    .insert(nonce, ())
                    .map_err(|source| StoreError::Index {
                        stage: "nonce-insert-put",
                        message: source.to_string(),
                    })?;
                true
            }
        };
        write.commit().map_err(|source| StoreError::Index {
            stage: "nonce-insert-commit",
            message: source.to_string(),
        })?;
        Ok(inserted)
    }

    /// Loads every spent nonce into a [`HashSet`].
    ///
    /// Used at startup to warm the in-memory cache.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] on redb iteration failure.
    pub fn load_all(&self) -> Result<HashSet<String>, StoreError> {
        let read = self.db.begin_read().map_err(|source| StoreError::Index {
            stage: "nonce-load-begin",
            message: source.to_string(),
        })?;
        let table = read
            .open_table(SPENT_NONCES)
            .map_err(|source| StoreError::Index {
                stage: "nonce-load-open",
                message: source.to_string(),
            })?;
        let mut nonces = HashSet::new();
        for row in table.iter().map_err(|source| StoreError::Index {
            stage: "nonce-load-iter",
            message: source.to_string(),
        })? {
            let (key, _) = row.map_err(|source| StoreError::Index {
                stage: "nonce-load-row",
                message: source.to_string(),
            })?;
            nonces.insert(key.value().to_owned());
        }
        Ok(nonces)
    }

    fn ensure_table(&self) -> Result<(), StoreError> {
        let write = self.db.begin_write().map_err(|source| StoreError::Index {
            stage: "nonce-init-begin",
            message: source.to_string(),
        })?;
        {
            write
                .open_table(SPENT_NONCES)
                .map_err(|source| StoreError::Index {
                    stage: "nonce-init-open",
                    message: source.to_string(),
                })?;
        }
        write.commit().map_err(|source| StoreError::Index {
            stage: "nonce-init-commit",
            message: source.to_string(),
        })
    }
}

#[cfg(test)]
mod tests;
