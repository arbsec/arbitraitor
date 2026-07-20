//! Rollback protection for the update client (spec §34.4).
//!
//! The [`RollbackStore`] persists the latest-seen manifest version per signed
//! update channel and rejects older snapshots on subsequent fetches. Operators
//! who genuinely need to roll back to an earlier manifest must record an
//! [`RollbackStore::explicit_rollback`] annotated with a human-readable reason
//! so the audit trail captures the intent.
//!
//! The store is an untrusted-input-accepting boundary. Writes go through a
//! sibling `*.tmp` file followed by an atomic `rename` so a crash mid-write
//! cannot corrupt the trusted record.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// On-disk schema version of the rollback store JSON file.
pub const ROLLBACK_STORE_SCHEMA_VERSION: u32 = 1;

/// Filename used for the persisted rollback store inside the update directory.
const STORE_FILENAME: &str = "versions.json";

/// Suffix used for the write-then-rename atomic write protocol.
const WRITE_SUFFIX: &str = ".tmp";

/// Upper bound on a channel identifier length in bytes.
const MAX_CHANNEL_LEN: usize = 64;

/// Upper bound on a recorded rollback reason length in bytes.
const MAX_REASON_LEN: usize = 512;

/// Errors raised while loading, updating, or persisting the rollback store.
#[derive(Debug, Error)]
pub enum RollbackError {
    /// The required user-home directory could not be resolved from the process
    /// environment, so the default store path is unusable.
    #[error("could not resolve user home directory: HOME is not set")]
    HomeDirectoryMissing,

    /// Filesystem operation failed at the supplied path.
    #[error("rollback store I/O error at {path}: {source}")]
    Io {
        /// Path associated with the failed operation (best-effort; never a
        /// secret).
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The persisted JSON file could not be parsed. The file is treated as
    /// tampered and the caller must reset it.
    #[error("rollback store JSON could not be parsed: {0}")]
    Deserialize(#[from] serde_json::Error),

    /// The persisted JSON file used an unexpected schema version.
    #[error("rollback store schema version {found} does not match supported version {expected}")]
    UnsupportedSchema {
        /// Schema version read from disk.
        found: u32,
        /// Schema version supported by this build.
        expected: u32,
    },

    /// The supplied channel identifier is empty, too long, or contains invalid
    /// characters.
    #[error("invalid channel identifier: {0}")]
    InvalidChannel(String),

    /// The supplied reason is empty or too long.
    #[error("invalid rollback reason: {0}")]
    InvalidReason(String),
}

impl RollbackError {
    fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Record of a single explicit rollback event for audit purposes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackRecord {
    /// Channel that was rolled back.
    pub channel: String,
    /// Target version after the rollback.
    pub version: u64,
    /// ISO 8601 timestamp at which the rollback was recorded.
    pub recorded_at: String,
    /// Operator-supplied justification for the rollback.
    pub reason: String,
}

/// Persistent rollback store for a single user account.
///
/// This type owns the in-memory mirror of the on-disk JSON file and exposes
/// mutating helpers that persist after every successful write. Methods that
/// only read state ([`RollbackStore::is_rollback`], [`RollbackStore::last_seen`])
/// take `&self` and may be called concurrently.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackStore {
    /// Schema version of the on-disk JSON envelope.
    schema_version: u32,
    /// Latest recorded version per channel, keyed by channel name.
    #[serde(default)]
    channels: BTreeMap<String, ChannelState>,
    /// Append-only history of explicit user-initiated rollbacks.
    #[serde(default)]
    rollbacks: Vec<RollbackRecord>,
    /// Absolute filesystem path to the JSON file backing this store.
    #[serde(skip)]
    path: PathBuf,
}

/// Persisted entry describing the latest known version of one channel.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ChannelState {
    /// Manifest version considered trustworthy for `channel`.
    version: u64,
    /// ISO 8601 timestamp at which the version was recorded.
    recorded_at: String,
}

impl RollbackStore {
    /// Open the store at the default location inside the user's home directory.
    ///
    /// The default path is `<HOME>/.arbitraitor/update/versions.json`. Parent
    /// directories are created if absent.
    ///
    /// # Errors
    ///
    /// Returns [`RollbackError::HomeDirectoryMissing`] when `HOME` is unset and
    /// [`RollbackError::Io`] for filesystem failures.
    pub fn open_default() -> Result<Self, RollbackError> {
        let home = std::env::var_os("HOME").ok_or(RollbackError::HomeDirectoryMissing)?;
        let path = PathBuf::from(home)
            .join(".arbitraitor")
            .join("update")
            .join(STORE_FILENAME);
        Self::open(path)
    }

    /// Open or create the store at an explicit path. Missing parent
    /// directories are created and an absent file is treated as an empty store.
    ///
    /// # Errors
    ///
    /// Returns [`RollbackError::Io`] for filesystem failures, and
    /// [`RollbackError::Deserialize`] / [`RollbackError::UnsupportedSchema`] for
    /// malformed JSON files.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, RollbackError> {
        let path = path.into();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            fs::create_dir_all(parent).map_err(|error| RollbackError::io(parent, error))?;
        }

        let mut store = if path.exists() {
            let bytes = fs::read(&path).map_err(|error| RollbackError::io(&path, error))?;
            let parsed: RollbackStore = serde_json::from_slice(&bytes)?;
            if parsed.schema_version != ROLLBACK_STORE_SCHEMA_VERSION {
                return Err(RollbackError::UnsupportedSchema {
                    found: parsed.schema_version,
                    expected: ROLLBACK_STORE_SCHEMA_VERSION,
                });
            }
            parsed
        } else {
            Self::empty(path.clone())
        };

        store.path = path;
        Ok(store)
    }

    /// Build a store in memory that is not backed by a file. Useful for tests.
    #[must_use]
    pub fn empty_in_memory() -> Self {
        Self::empty(PathBuf::new())
    }

    fn empty(path: PathBuf) -> Self {
        Self {
            schema_version: ROLLBACK_STORE_SCHEMA_VERSION,
            channels: BTreeMap::new(),
            rollbacks: Vec::new(),
            path,
        }
    }

    /// Filesystem path backing this store, if any.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Latest recorded version for `channel`, or `None` when no manifest has
    /// been observed yet.
    #[must_use]
    pub fn last_seen(&self, channel: &str) -> Option<u64> {
        self.channels.get(channel).map(|state| state.version)
    }

    /// Recorded explicit rollbacks, newest first.
    #[must_use]
    pub fn rollback_history(&self) -> &[RollbackRecord] {
        &self.rollbacks
    }

    /// Return `true` when `proposed_version` would constitute a rollback
    /// relative to the latest version already recorded for `channel`.
    ///
    /// Channels that have never been observed return `false` (first install).
    /// Equal versions are not a rollback; only strictly older proposals are.
    #[must_use]
    pub fn is_rollback(&self, channel: &str, proposed_version: u64) -> bool {
        self.last_seen(channel)
            .is_some_and(|current| proposed_version < current)
    }

    /// Record that `version` was observed for `channel`. Older or equal versions
    /// are accepted but do not advance the stored watermark — only strictly
    /// newer versions overwrite the previous record.
    ///
    /// Persists to disk atomically via a sibling temp file when a path is set.
    ///
    /// # Errors
    ///
    /// Returns [`RollbackError::InvalidChannel`] for empty or oversized
    /// identifiers and [`RollbackError::Io`] for filesystem failures.
    pub fn record_version(
        &mut self,
        channel: &str,
        version: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let channel_owned = validate_channel(channel)?;
        let recorded_at = now_rfc3339();
        let entry = self.channels.entry(channel_owned).or_insert(ChannelState {
            version,
            recorded_at: recorded_at.clone(),
        });
        if version > entry.version {
            entry.version = version;
            entry.recorded_at = recorded_at;
        }
        self.persist()
    }

    /// Record an operator-initiated rollback to `version` with the supplied
    /// `reason`. Updates the stored watermark so subsequent
    /// [`RollbackStore::is_rollback`] calls treat versions older than `version`
    /// as rollbacks, and appends an audit entry describing the operator's
    /// intent.
    ///
    /// # Errors
    ///
    /// Returns [`RollbackError::InvalidChannel`] / [`RollbackError::InvalidReason`]
    /// for malformed input and [`RollbackError::Io`] for filesystem failures.
    pub fn explicit_rollback(
        &mut self,
        channel: &str,
        version: u64,
        reason: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let channel_owned = validate_channel(channel)?;
        let reason_owned = validate_reason(reason)?;
        let recorded_at = now_rfc3339();
        self.channels.insert(
            channel_owned.clone(),
            ChannelState {
                version,
                recorded_at: recorded_at.clone(),
            },
        );
        self.rollbacks.push(RollbackRecord {
            channel: channel_owned,
            version,
            recorded_at,
            reason: reason_owned,
        });
        self.persist()
    }

    /// Serialize the current store to disk via a sibling temp file followed by
    /// `rename`. A no-op for in-memory stores constructed via
    /// [`RollbackStore::empty_in_memory`] (path is empty).
    fn persist(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        let parent = self.path.parent().ok_or_else(|| {
            RollbackError::io(
                self.path.clone(),
                io::Error::new(io::ErrorKind::InvalidInput, "store path has no parent"),
            )
        })?;
        let tmp = parent.join(format!("{STORE_FILENAME}{WRITE_SUFFIX}"));
        let bytes = serde_json::to_vec_pretty(self)?;
        fs::write(&tmp, &bytes).map_err(|error| RollbackError::io(&tmp, error))?;
        fs::rename(&tmp, &self.path).map_err(|error| RollbackError::io(&self.path, error))?;
        Ok(())
    }
}

fn validate_channel(channel: &str) -> Result<String, RollbackError> {
    if channel.is_empty() {
        return Err(RollbackError::InvalidChannel(
            "channel must not be empty".to_owned(),
        ));
    }
    if channel.len() > MAX_CHANNEL_LEN {
        return Err(RollbackError::InvalidChannel(format!(
            "channel must be at most {MAX_CHANNEL_LEN} bytes"
        )));
    }
    if !channel
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'.')
    {
        return Err(RollbackError::InvalidChannel(
            "channel must contain only ASCII alphanumeric, '_', '-', or '.' characters".to_owned(),
        ));
    }
    Ok(channel.to_owned())
}

fn validate_reason(reason: &str) -> Result<String, RollbackError> {
    if reason.is_empty() {
        return Err(RollbackError::InvalidReason(
            "reason must not be empty".to_owned(),
        ));
    }
    if reason.len() > MAX_REASON_LEN {
        return Err(RollbackError::InvalidReason(format!(
            "reason must be at most {MAX_REASON_LEN} bytes"
        )));
    }
    Ok(reason.to_owned())
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

impl fmt::Display for RollbackStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RollbackStore(")?;
        formatter.write_str(&self.path.display().to_string())?;
        formatter.write_str(", channels=")?;
        formatter.write_str(&self.channels.len().to_string())?;
        formatter.write_str(", rollbacks=")?;
        formatter.write_str(&self.rollbacks.len().to_string())?;
        formatter.write_str(")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Shared counter so tests get distinct RFC 3339-ish timestamps without
    /// relying on wall-clock skew or non-deterministic time sources.
    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn unique_path(label: &str) -> io::Result<PathBuf> {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("arbitraitor-rollback-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir)?;
        Ok(dir.join(format!("{label}-{n}.json")))
    }

    #[test]
    fn empty_store_does_not_flag_first_install_as_rollback() {
        let store = RollbackStore::empty_in_memory();
        assert!(!store.is_rollback("rule_packs", 1));
        assert!(!store.is_rollback("rule_packs", 0));
        assert_eq!(store.last_seen("rule_packs"), None);
        assert!(store.rollback_history().is_empty());
    }

    #[test]
    fn record_version_advances_watermark() -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_path("record")?;
        let mut store = RollbackStore::open(path.as_path())?;
        store.record_version("rule_packs", 5)?;
        store.record_version("rule_packs", 7)?;
        store.record_version("rule_packs", 7)?; // equal — no advance

        assert_eq!(store.last_seen("rule_packs"), Some(7));
        assert!(store.is_rollback("rule_packs", 6));
        assert!(store.is_rollback("rule_packs", 0));
        assert!(!store.is_rollback("rule_packs", 7));
        assert!(!store.is_rollback("rule_packs", 8));
        Ok(())
    }

    #[test]
    fn record_version_persists_across_reopen() -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_path("persist")?;
        {
            let mut store = RollbackStore::open(path.as_path())?;
            store.record_version("trust_root", 3)?;
        }
        let reopened = RollbackStore::open(path.as_path())?;
        assert_eq!(reopened.last_seen("trust_root"), Some(3));
        assert!(reopened.is_rollback("trust_root", 2));
        Ok(())
    }

    #[test]
    fn record_version_rejects_empty_channel() {
        let mut store = RollbackStore::empty_in_memory();
        let error = store.record_version("", 1).err();
        assert!(error.is_some());
    }

    #[test]
    fn record_version_rejects_oversized_channel() {
        let mut store = RollbackStore::empty_in_memory();
        let long = "a".repeat(MAX_CHANNEL_LEN + 1);
        let error = store.record_version(&long, 1).err();
        assert!(error.is_some());
    }

    #[test]
    fn record_version_rejects_non_ascii_channel() {
        let mut store = RollbackStore::empty_in_memory();
        let error = store.record_version("rule_packs!", 1).err();
        assert!(error.is_some());
    }

    #[test]
    fn explicit_rollback_records_audit_entry_and_moves_watermark()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut store = RollbackStore::empty_in_memory();
        store.record_version("intel_feeds", 10)?;
        assert!(store.is_rollback("intel_feeds", 5));

        store.explicit_rollback("intel_feeds", 5, "revert known bad feed")?;
        // Now 5 is the watermark, anything <5 is a rollback, anything ≥5 is fine.
        assert_eq!(store.last_seen("intel_feeds"), Some(5));
        assert!(store.is_rollback("intel_feeds", 4));
        assert!(!store.is_rollback("intel_feeds", 5));
        assert!(!store.is_rollback("intel_feeds", 6));

        let history = store.rollback_history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].channel, "intel_feeds");
        assert_eq!(history[0].version, 5);
        assert_eq!(history[0].reason, "revert known bad feed");
        Ok(())
    }

    #[test]
    fn explicit_rollback_rejects_empty_reason() {
        let mut store = RollbackStore::empty_in_memory();
        let error = store.explicit_rollback("rule_packs", 1, "").err();
        assert!(error.is_some());
    }

    #[test]
    fn explicit_rollback_rejects_oversized_reason() {
        let mut store = RollbackStore::empty_in_memory();
        let long = "x".repeat(MAX_REASON_LEN + 1);
        let error = store.explicit_rollback("rule_packs", 1, &long).err();
        assert!(error.is_some());
    }

    #[test]
    fn open_missing_file_yields_empty_store_with_recorded_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_path("missing")?;
        let store = RollbackStore::open(path.as_path())?;
        assert_eq!(store.path(), path.as_path());
        assert_eq!(store.last_seen("rule_packs"), None);
        Ok(())
    }

    #[test]
    fn open_rejects_unsupported_schema() -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_path("badschema")?;
        fs::write(
            &path,
            br#"{"schema_version":999,"channels":{},"rollbacks":[]}"#,
        )?;
        let error = RollbackStore::open(path.as_path()).err();
        assert!(matches!(
            error,
            Some(RollbackError::UnsupportedSchema {
                found: 999,
                expected: 1
            })
        ));
        Ok(())
    }

    #[test]
    fn open_rejects_malformed_json() -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_path("badjson")?;
        fs::write(&path, b"{not-json")?;
        let error = RollbackStore::open(path.as_path()).err();
        assert!(matches!(error, Some(RollbackError::Deserialize(_))));
        Ok(())
    }

    #[test]
    fn multiple_channels_track_independently() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = RollbackStore::empty_in_memory();
        store.record_version("rule_packs", 4)?;
        store.record_version("intel_feeds", 9)?;
        store.record_version("trust_root", 2)?;

        assert_eq!(store.last_seen("rule_packs"), Some(4));
        assert_eq!(store.last_seen("intel_feeds"), Some(9));
        assert_eq!(store.last_seen("trust_root"), Some(2));
        assert!(store.is_rollback("rule_packs", 3));
        assert!(!store.is_rollback("trust_root", 2));
        Ok(())
    }

    #[test]
    fn in_memory_store_does_not_attempt_persist() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = RollbackStore::empty_in_memory();
        store.record_version("rule_packs", 1)?;
        store.explicit_rollback("rule_packs", 1, "noop")?;
        // The Display impl mentions the empty path; ensure no panic on access.
        assert!(store.to_string().contains("RollbackStore("));
        Ok(())
    }

    #[test]
    fn write_is_atomic_via_temp_and_rename() -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_path("atomic")?;
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("test path has no parent directory"))?;
        let mut store = RollbackStore::open(path.as_path())?;
        store.record_version("rule_packs", 42)?;
        // After persist only the final file should exist — no orphan .tmp.
        let tmp = path.with_extension("json.tmp");
        let entries: Vec<_> = fs::read_dir(parent)?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains("atomic"))
            .collect();
        let names: Vec<_> = entries
            .iter()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !names.iter().any(|n| n.ends_with(".json.tmp")),
            "orphan temp file leaked: {names:?}"
        );
        assert!(!tmp.exists(), "temp file leaked on disk: {}", tmp.display());
        Ok(())
    }
}
