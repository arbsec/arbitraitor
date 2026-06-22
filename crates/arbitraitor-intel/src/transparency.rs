//! Append-only transparency log for feed operations (spec §22.4).
//!
//! Every mutation of the intelligence feed — a submission accepted, a review
//! recorded, an indicator expired — is appended to a [`TransparencyLog`] as a
//! hash-chained [`LogEntry`]. Each entry's hash is SHA-256 of the previous
//! entry's hash concatenated with the canonical JSON of the operation, forming
//! a tamper-evident chain: modifying or removing any entry invalidates the
//! hash of every subsequent entry.
//!
//! # Canonical JSON
//!
//! The hash chain requires deterministic serialization. All types reachable
//! from [`LogOperation`] are structs with named fields or ordered sequences —
//! none use hash maps — so [`serde_json::to_string`] produces canonical output
//! (struct fields in declaration order, enum tag before payload). This matches
//! the determinism approach used for receipt canonicalization (ADR 0014).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::current_unix_timestamp;
use crate::review::{Dispute, Review};
use crate::submission::FeedSubmission;

/// Genesis previous-hash: 64 zeros marking the head of the chain.
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A single entry in the transparency log.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogEntry {
    /// Monotonically increasing 0-based sequence number.
    pub sequence: u64,
    /// Unix timestamp (seconds since epoch) when the entry was appended.
    pub timestamp: u64,
    /// The operation recorded by this entry.
    pub operation: LogOperation,
    /// SHA-256 hex digest of `previous_hash || canonical_json(operation)`.
    pub hash: String,
    /// Hash of the preceding entry, or the genesis hash for the first entry.
    pub previous_hash: String,
}

/// The operation recorded by a transparency log entry.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LogOperation {
    /// A community submission was accepted into the feed.
    SubmissionAccepted {
        /// The accepted submission.
        submission: FeedSubmission,
    },
    /// A community submission was rejected.
    SubmissionRejected {
        /// The rejected submission.
        submission: FeedSubmission,
        /// The reason the submission was rejected.
        reason: String,
    },
    /// A review decision was recorded against a submission.
    ReviewRecorded {
        /// Hash of the submission the review applies to.
        submission_hash: String,
        /// The recorded review.
        review: Review,
    },
    /// A dispute was filed against an accepted indicator.
    DisputeFiled {
        /// The filed dispute.
        dispute: Dispute,
    },
    /// An indicator reached its expiration.
    IndicatorExpired {
        /// The expired indicator value.
        indicator_value: String,
    },
    /// An indicator was manually removed from the feed.
    IndicatorRemoved {
        /// The removed indicator value.
        indicator_value: String,
        /// The reason for removal.
        reason: String,
    },
    /// A feed rule was updated.
    RuleUpdated {
        /// Identifier of the updated rule.
        rule_id: String,
        /// Description of the change.
        change: String,
    },
}

/// Append-only transparency log backed by a JSONL file.
///
/// Each entry is persisted as one compact JSON object per line. The hash chain
/// ([`LogEntry::hash`]) makes the log tamper-evident: use [`Self::verify`] to
/// detect any modification after the fact.
pub struct TransparencyLog {
    /// Path to the backing JSONL file.
    path: PathBuf,
    /// Sequence number assigned to the next appended entry.
    next_sequence: u64,
    /// Hash of the most recent entry (genesis hash before any entry exists).
    last_hash: String,
}

impl TransparencyLog {
    /// Opens the transparency log at `path`, creating it if absent.
    ///
    /// Reads existing entries to recover the next sequence number and last hash
    /// so appended entries continue the chain seamlessly across reopens.
    ///
    /// # Errors
    ///
    /// Returns [`LogError::Io`] if the file cannot be read, or
    /// [`LogError::Json`] if an entry cannot be decoded.
    pub fn open(path: &Path) -> Result<Self, LogError> {
        let mut log = Self {
            path: path.to_path_buf(),
            next_sequence: 0,
            last_hash: GENESIS_HASH.to_owned(),
        };
        log.recover_state()?;
        Ok(log)
    }

    /// Appends `operation` to the log and returns the created entry.
    ///
    /// The entry is assigned the next sequence number, the current timestamp,
    /// and a hash chaining it to the previous entry. The entry is persisted
    /// immediately as a single JSONL line.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation cannot be serialized or the backing
    /// file cannot be written.
    pub fn append(&mut self, operation: LogOperation) -> Result<LogEntry, LogError> {
        let entry = LogEntry {
            sequence: self.next_sequence,
            timestamp: current_unix_timestamp(),
            hash: compute_hash(&self.last_hash, &operation)?,
            previous_hash: self.last_hash.clone(),
            operation,
        };

        self.write_entry(&entry)?;

        self.next_sequence = self.next_sequence.saturating_add(1);
        self.last_hash.clone_from(&entry.hash);
        Ok(entry)
    }

    /// Reads all entries from the log in sequence order.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or an entry cannot be
    /// decoded.
    pub fn entries(&self) -> Result<Vec<LogEntry>, LogError> {
        read_entries(&self.path)
    }

    /// Verifies the integrity of the hash chain.
    ///
    /// Returns `Ok(true)` when every entry's hash matches the recomputed value
    /// and every `previous_hash` links to the preceding entry. Returns
    /// `Ok(false)` when the chain is broken (e.g. a tampered entry).
    ///
    /// # Errors
    ///
    /// Returns an error only if the log file cannot be read or parsed — a
    /// broken chain itself is reported via `Ok(false)`, not as an error.
    pub fn verify(&self) -> Result<bool, LogError> {
        match self.verify_chain() {
            Ok(()) => Ok(true),
            Err(LogError::BrokenChain(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Returns entries whose sequence number is strictly greater than
    /// `sequence`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or an entry cannot be
    /// decoded.
    pub fn since(&self, sequence: u64) -> Result<Vec<LogEntry>, LogError> {
        Ok(self
            .entries()?
            .into_iter()
            .filter(|entry| entry.sequence > sequence)
            .collect())
    }

    /// Recomputes every hash and links, returning the first break.
    fn verify_chain(&self) -> Result<(), LogError> {
        let entries = self.entries()?;
        let mut expected_previous: &str = GENESIS_HASH;

        for entry in &entries {
            if entry.previous_hash != expected_previous {
                return Err(LogError::BrokenChain(entry.sequence));
            }
            let recomputed = compute_hash(&entry.previous_hash, &entry.operation)?;
            if recomputed != entry.hash {
                return Err(LogError::BrokenChain(entry.sequence));
            }
            expected_previous = &entry.hash;
        }
        Ok(())
    }

    /// Reads the backing file and recovers `next_sequence` and `last_hash`.
    fn recover_state(&mut self) -> Result<(), LogError> {
        let entries = read_entries(&self.path)?;
        if let Some(last) = entries.last() {
            self.next_sequence = last.sequence.saturating_add(1);
            self.last_hash.clone_from(&last.hash);
        }
        Ok(())
    }

    /// Appends `entry` as one JSONL line to the backing file.
    fn write_entry(&self, entry: &LogEntry) -> Result<(), LogError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(LogError::Io)?;
        }
        let line = serde_json::to_string(entry).map_err(LogError::Json)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(LogError::Io)?;
        file.write_all(line.as_bytes()).map_err(LogError::Io)?;
        file.write_all(b"\n").map_err(LogError::Io)?;
        Ok(())
    }
}

/// Errors produced by transparency log operations.
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    /// Backing file I/O failed.
    #[error("log I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization or deserialization failed.
    #[error("log serialization error: {0}")]
    Json(#[from] serde_json::Error),
    /// The hash chain is broken at the given sequence number.
    #[error("hash chain broken at sequence {0}")]
    BrokenChain(u64),
}

/// Computes the SHA-256 hex digest of `previous_hash || json(operation)`.
fn compute_hash(previous_hash: &str, operation: &LogOperation) -> Result<String, LogError> {
    let json = serde_json::to_string(operation)?;
    let mut hasher = Sha256::new();
    hasher.update(previous_hash.as_bytes());
    hasher.update(json.as_bytes());
    let digest = hasher.finalize();
    Ok(hex_encode(&digest))
}

/// Encodes `bytes` as a lowercase hexadecimal string.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Reads and decodes all entries from the JSONL file at `path`.
///
/// Returns an empty vector when the file does not exist yet.
fn read_entries(path: &Path) -> Result<Vec<LogEntry>, LogError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(LogError::Io(error)),
    };

    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(LogError::Json))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review::{DisputeReason, Review, ReviewDecision, ReviewerIdentity};
    use crate::submission::{
        ConfidenceLevel, IndicatorType, SubmissionEvidence, SubmissionMetadata, SubmittedIndicator,
        SubmitterIdentity, TrustTier,
    };
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Builds a unique temporary log path to avoid parallel-test collisions.
    fn temp_log_path(label: &str) -> PathBuf {
        let unique = format!(
            "arbitraitor-tlog-{label}-{}-{}.jsonl",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        );
        std::env::temp_dir().join(unique)
    }

    /// Removes `path` if it exists, ignoring errors.
    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
    }

    fn sample_submission() -> FeedSubmission {
        FeedSubmission {
            submitter: SubmitterIdentity {
                handle: "analyst".to_owned(),
                trust_tier: TrustTier::Registered,
                key_fingerprint: None,
            },
            indicator: SubmittedIndicator {
                indicator_type: IndicatorType::Domain,
                value: "evil.example".to_owned(),
                confidence: ConfidenceLevel::Medium,
            },
            evidence: SubmissionEvidence::default(),
            metadata: SubmissionMetadata::default(),
        }
    }

    fn sample_review() -> Review {
        Review {
            reviewer: ReviewerIdentity {
                handle: "reviewer".to_owned(),
                trust_tier: TrustTier::Verified,
            },
            decision: ReviewDecision::Accept,
            rationale: "Verified against telemetry".to_owned(),
            reviewed_at: 1000,
        }
    }

    fn sample_dispute() -> crate::review::Dispute {
        crate::review::Dispute {
            submitter: SubmitterIdentity {
                handle: "analyst".to_owned(),
                trust_tier: TrustTier::Registered,
                key_fingerprint: None,
            },
            indicator_value: "evil.example".to_owned(),
            reason: DisputeReason::FalsePositive,
            evidence: "Not malicious in sandbox".to_owned(),
            filed_at: 2000,
        }
    }

    fn expired(value: &str) -> LogOperation {
        LogOperation::IndicatorExpired {
            indicator_value: value.to_owned(),
        }
    }

    #[test]
    fn append_creates_entry_with_correct_sequence() -> Result<(), LogError> {
        // Given a fresh log
        let path = temp_log_path("seq");
        let mut log = TransparencyLog::open(&path)?;

        // When two entries are appended
        let first = log.append(expired("first.example"))?;
        let second = log.append(expired("second.example"))?;

        // Then sequences are 0 and 1
        assert_eq!(first.sequence, 0);
        assert_eq!(second.sequence, 1);

        cleanup(&path);
        Ok(())
    }

    #[test]
    fn hash_chain_links_entries() -> Result<(), LogError> {
        // Given a fresh log
        let path = temp_log_path("chain");
        let mut log = TransparencyLog::open(&path)?;

        // When two entries are appended
        let first = log.append(expired("a.example"))?;
        let second = log.append(expired("b.example"))?;

        // Then the first entry links to genesis and the second links to the first
        assert_eq!(first.previous_hash, GENESIS_HASH);
        assert_eq!(second.previous_hash, first.hash);
        assert_eq!(first.hash.len(), 64);
        assert_eq!(second.hash.len(), 64);

        cleanup(&path);
        Ok(())
    }

    #[test]
    fn verify_passes_on_clean_log() -> Result<(), LogError> {
        // Given a log with several entries
        let path = temp_log_path("clean");
        let mut log = TransparencyLog::open(&path)?;
        log.append(expired("x.example"))?;
        log.append(expired("y.example"))?;
        log.append(expired("z.example"))?;

        // When verify is called
        // Then it passes
        assert!(log.verify()?);

        cleanup(&path);
        Ok(())
    }

    #[test]
    fn verify_fails_on_tampered_entry() -> Result<(), Box<dyn std::error::Error>> {
        // Given a log with two entries
        let path = temp_log_path("tampered");
        let mut log = TransparencyLog::open(&path)?;
        log.append(expired("original.example"))?;
        log.append(expired("second.example"))?;
        drop(log);

        // When the first entry's operation is tampered without updating hashes
        let entries = read_entries(&path)?;
        let mut tampered = entries.clone();
        tampered[0].operation = expired("TAMPERED.example");
        let mut contents = String::new();
        for entry in &tampered {
            contents.push_str(&serde_json::to_string(entry)?);
            contents.push('\n');
        }
        fs::write(&path, contents)?;

        // Then verify returns false
        let log = TransparencyLog::open(&path)?;
        assert!(!log.verify()?);

        cleanup(&path);
        Ok(())
    }

    #[test]
    fn since_returns_entries_after_sequence() -> Result<(), LogError> {
        // Given a log with five entries (sequences 0–4)
        let path = temp_log_path("since");
        let mut log = TransparencyLog::open(&path)?;
        for i in 0..5 {
            log.append(expired(&format!("entry-{i}.example")))?;
        }

        // When since(2) is called
        let result = log.since(2)?;

        // Then only entries with sequence > 2 are returned
        let sequences: Vec<u64> = result.iter().map(|e| e.sequence).collect();
        assert_eq!(sequences, vec![3, 4]);

        cleanup(&path);
        Ok(())
    }

    #[test]
    fn reopen_log_continues_sequence() -> Result<(), LogError> {
        // Given a log with two entries that is then closed
        let path = temp_log_path("reopen");
        {
            let mut log = TransparencyLog::open(&path)?;
            log.append(expired("first.example"))?;
            log.append(expired("second.example"))?;
        }

        // When the log is reopened and a third entry is appended
        let mut reopened = TransparencyLog::open(&path)?;
        let third = reopened.append(expired("third.example"))?;

        // Then the sequence continues at 2 and the chain still verifies
        assert_eq!(third.sequence, 2);
        assert!(reopened.verify()?);

        cleanup(&path);
        Ok(())
    }

    #[test]
    fn all_operation_types_serializable() -> Result<(), Box<dyn std::error::Error>> {
        // Given one of every LogOperation variant
        let operations = [
            LogOperation::SubmissionAccepted {
                submission: sample_submission(),
            },
            LogOperation::SubmissionRejected {
                submission: sample_submission(),
                reason: "invalid indicator".to_owned(),
            },
            LogOperation::ReviewRecorded {
                submission_hash: "abc123".to_owned(),
                review: sample_review(),
            },
            LogOperation::DisputeFiled {
                dispute: sample_dispute(),
            },
            expired("expired.example"),
            LogOperation::IndicatorRemoved {
                indicator_value: "removed.example".to_owned(),
                reason: "false positive".to_owned(),
            },
            LogOperation::RuleUpdated {
                rule_id: "rule-001".to_owned(),
                change: "severity raised to high".to_owned(),
            },
        ];

        // When each is serialized and deserialized
        for operation in &operations {
            let json = serde_json::to_string(operation)?;
            let decoded: LogOperation = serde_json::from_str(&json)?;

            // Then re-serializing produces the identical bytes (canonical)
            assert_eq!(
                serde_json::to_string(&decoded)?,
                json,
                "round-trip is not canonical for {json}"
            );
        }
        Ok(())
    }

    #[test]
    fn concurrent_appends_are_serialized() -> Result<(), Box<dyn std::error::Error>> {
        // Given a shared log guarded by a mutex
        let path = temp_log_path("concurrent");
        let log = Arc::new(Mutex::new(TransparencyLog::open(&path)?));

        // When four threads each append one entry through the mutex
        let handles: Vec<_> = (0..4_u64)
            .map(|i| {
                let log = Arc::clone(&log);
                thread::spawn(move || {
                    let mut guard = log
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    guard.append(expired(&format!("thread-{i}.example")))
                })
            })
            .collect();

        for handle in handles {
            match handle.join() {
                Ok(append_result) => {
                    append_result?;
                }
                Err(_) => return Err("thread panicked".into()),
            }
        }

        // Then all four entries are present and the chain verifies
        let guard = log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(guard.entries()?.len(), 4);
        assert!(guard.verify()?);

        cleanup(&path);
        Ok(())
    }

    #[test]
    fn empty_log_verifies_ok() -> Result<(), LogError> {
        // Given a fresh log with no entries
        let path = temp_log_path("empty");
        let log = TransparencyLog::open(&path)?;

        // When verify is called
        // Then it passes vacuously
        assert!(log.verify()?);
        assert!(log.entries()?.is_empty());

        cleanup(&path);
        Ok(())
    }
}
