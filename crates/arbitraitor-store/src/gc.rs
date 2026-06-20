//! Garbage collection for the content-addressed store.

#![forbid(unsafe_code)]

use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arbitraitor_model::ids::Sha256Digest;

use crate::metadata::{MetadataEntry, MetadataIndex};
use crate::retention::RetentionMode;
use crate::{ContentStore, StoreError, remove_artifact_files};

/// Content-addressed store garbage collector.
#[derive(Debug, Default)]
pub struct GarbageCollector {
    max_age: Option<Duration>,
    max_size: Option<u64>,
}

/// Garbage collection statistics.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct GcStats {
    /// Number of metadata entries examined.
    pub examined: usize,
    /// Number of artifacts collected.
    pub collected: usize,
    /// Number of locked artifacts retained.
    pub retained_locked: usize,
    /// Number of forensic artifacts retained.
    pub retained_forensic: usize,
    /// Total object bytes freed.
    pub freed_bytes: u64,
}

impl GarbageCollector {
    /// Creates a collector without age or size limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_age: None,
            max_size: None,
        }
    }

    /// Collects eligible artifacts older than `max_age`.
    #[must_use]
    pub const fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Collects eligible artifacts until total indexed size is at most `max_size`.
    #[must_use]
    pub const fn with_max_size(mut self, max_size: u64) -> Self {
        self.max_size = Some(max_size);
        self
    }

    /// Runs garbage collection and returns collection statistics.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when metadata listing, digest parsing, or per-artifact
    /// deletion fails.
    pub fn run(&self, store: &ContentStore, index: &MetadataIndex) -> Result<GcStats, StoreError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|source| StoreError::Io {
                stage: "gc-system-time",
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
            })?
            .as_secs();
        let mut stats = GcStats::default();
        let mut entries = index.list()?;
        stats.examined = entries.len();
        entries.sort_by_key(|entry| entry.retrieved_at);

        let mut retained_size = 0u64;
        let mut candidates = Vec::new();
        for entry in entries {
            match retention_decision(&entry, self.max_age, now) {
                RetentionDecision::Locked => stats.retained_locked += 1,
                RetentionDecision::Forensic => stats.retained_forensic += 1,
                RetentionDecision::Retain => {
                    retained_size =
                        retained_size.checked_add(entry.size_bytes).ok_or_else(|| {
                            StoreError::Io {
                                stage: "gc-size-total",
                                source: std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "indexed size overflow",
                                ),
                            }
                        })?;
                    candidates.push(SizeCandidate::retained(entry));
                }
                RetentionDecision::Collect => collect_entry(store, index, entry, &mut stats)?,
            }
        }

        if let Some(max_size) = self.max_size {
            for candidate in candidates {
                if retained_size <= max_size {
                    break;
                }
                retained_size = retained_size.saturating_sub(candidate.entry.size_bytes);
                collect_entry(store, index, candidate.entry, &mut stats)?;
            }
        }
        Ok(stats)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetentionDecision {
    Locked,
    Forensic,
    Retain,
    Collect,
}

struct SizeCandidate {
    entry: MetadataEntry,
}

impl SizeCandidate {
    const fn retained(entry: MetadataEntry) -> Self {
        Self { entry }
    }
}

fn retention_decision(
    entry: &MetadataEntry,
    max_age: Option<Duration>,
    now: u64,
) -> RetentionDecision {
    if entry.locked {
        return RetentionDecision::Locked;
    }
    match entry.retention_mode {
        RetentionMode::Forensic => RetentionDecision::Forensic,
        RetentionMode::Session => RetentionDecision::Retain,
        RetentionMode::Indefinite | RetentionMode::Cache => {
            if is_expired(entry, max_age, now) {
                RetentionDecision::Collect
            } else {
                RetentionDecision::Retain
            }
        }
        RetentionMode::Ephemeral => RetentionDecision::Collect,
    }
}

fn is_expired(entry: &MetadataEntry, max_age: Option<Duration>, now: u64) -> bool {
    max_age.is_some_and(|age| now.saturating_sub(entry.retrieved_at) > age.as_secs())
}

fn collect_entry(
    store: &ContentStore,
    index: &MetadataIndex,
    entry: MetadataEntry,
    stats: &mut GcStats,
) -> Result<(), StoreError> {
    let MetadataEntry {
        sha256,
        size_bytes: _,
        ..
    } = entry;
    let digest = Sha256Digest::from_str(&sha256).map_err(|source| StoreError::Index {
        stage: "gc-parse-digest",
        message: source.to_string(),
    })?;
    let freed = remove_artifact_files(&store.inner.root_path, &digest, index)?;
    stats.collected += 1;
    stats.freed_bytes = stats
        .freed_bytes
        .checked_add(freed)
        .ok_or_else(|| StoreError::Io {
            stage: "gc-freed-total",
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, "freed byte overflow"),
        })?;
    Ok(())
}

#[cfg(test)]
mod tests;
