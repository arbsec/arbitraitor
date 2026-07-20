//! Background operation queue for asynchronous daemon operations.
//!
//! Long-running operations (fetch+scan, release) are enqueued and executed
//! asynchronously, bounded by a concurrency semaphore. Callers receive an
//! [`OperationId`] immediately and poll for completion via
//! [`OperationQueue::status`]. Mid-flight cancellation propagates through a
//! shared [`CancellationToken`] (spec §37.1).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

use crate::api::ArbitraitorApi;

/// Unique identifier for a queued operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OperationId(String);

impl OperationId {
    /// Creates a new random operation identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Returns the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for OperationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Shareable, single-shot cancellation flag (spec §37.1).
///
/// The flag is observed cooperatively by the executing task. Flipping it
/// after the operation has already reached a terminal state is a no-op.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    flag: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Creates a fresh, uncancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks the token as cancelled. All observers see the change on the
    /// next load.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

/// Status of a background operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationStatus {
    /// Operation is waiting for a concurrency slot.
    Queued,
    /// Operation is actively executing.
    Running,
    /// Operation completed successfully.
    Completed(OperationResult),
    /// Operation failed with an error message.
    Failed(String),
    /// Operation was cancelled before completion.
    Cancelled,
}

/// Result of a completed inspection operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationResult {
    /// SHA-256 hex digest of the analyzed artifact.
    pub sha256: String,
    /// Human-readable policy verdict.
    pub verdict: String,
    /// Number of findings emitted by analysis.
    pub findings_count: usize,
    /// Wall-clock duration of the operation in milliseconds.
    pub duration_ms: u64,
}

/// Internal entry tracking an operation's status and lifecycle timestamps.
struct OperationEntry {
    status: OperationStatus,
    /// When the operation reached a terminal state (`Completed`, `Failed`,
    /// or `Cancelled`). `None` while `Queued` or `Running`.
    terminal_at: Option<Instant>,
    /// Cancellation flag shared with the executing task.
    cancellation: CancellationToken,
}

impl OperationEntry {
    fn queued() -> Self {
        Self {
            status: OperationStatus::Queued,
            terminal_at: None,
            cancellation: CancellationToken::new(),
        }
    }

    /// Transitions the entry to a new status, recording the terminal timestamp
    /// when the new status is terminal.
    fn transition(&mut self, status: OperationStatus) {
        let is_terminal = matches!(
            status,
            OperationStatus::Completed(_) | OperationStatus::Failed(_) | OperationStatus::Cancelled
        );
        if is_terminal {
            self.terminal_at = Some(Instant::now());
        }
        self.status = status;
    }
}

/// A background operation queue with bounded concurrency.
///
/// Operations are executed asynchronously via [`OperationQueue::enqueue_inspect`].
/// Concurrency is limited by an internal [`Semaphore`]; excess operations remain
/// [`OperationStatus::Queued`] until a slot is available.
///
/// Mid-flight cancellation is exposed via [`OperationQueue::cancel_operation`]
/// and [`OperationQueue::is_cancelled`], backed by a per-operation
/// [`CancellationToken`] shared with the executing task (spec §37.1).
///
/// Instances are cheap to clone-share internally (the operation table and
/// semaphore are behind `Arc`) and safe to share across tasks via `&self`.
pub struct OperationQueue {
    api: Arc<ArbitraitorApi>,
    operations: Arc<Mutex<HashMap<OperationId, OperationEntry>>>,
    semaphore: Arc<Semaphore>,
    max_concurrent: usize,
}

impl OperationQueue {
    /// Creates a new queue backed by the given API with the specified
    /// concurrency limit.
    #[must_use]
    pub fn new(api: Arc<ArbitraitorApi>, max_concurrent: usize) -> Self {
        Self {
            api,
            operations: Arc::new(Mutex::new(HashMap::new())),
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            max_concurrent,
        }
    }

    /// Returns the maximum number of concurrently executing operations.
    #[must_use]
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Enqueues an inspect operation and returns its ID immediately.
    ///
    /// The actual inspection runs in a background task bounded by the
    /// concurrency semaphore. Poll [`OperationQueue::status`] for completion.
    /// Cooperative cancellation is available via
    /// [`OperationQueue::cancel_operation`].
    pub async fn enqueue_inspect(&self, url: String) -> OperationId {
        let id = OperationId::new();
        let token = {
            let mut ops = self.operations.lock().await;
            let entry = OperationEntry::queued();
            let token = entry.cancellation.clone();
            ops.insert(id.clone(), entry);
            token
        };

        let api = Arc::clone(&self.api);
        let operations = Arc::clone(&self.operations);
        let semaphore = Arc::clone(&self.semaphore);
        let task_id = id.clone();
        tokio::spawn(async move {
            // _permit is held for the lifetime of the task: its Drop releases
            // the semaphore slot to the next queued operation.
            let Ok(_permit) = Arc::clone(&semaphore).acquire_owned().await else {
                let mut ops = operations.lock().await;
                if let Some(entry) = ops.get_mut(&task_id) {
                    entry.transition(OperationStatus::Failed("semaphore closed".to_owned()));
                }
                return;
            };

            {
                let mut ops = operations.lock().await;
                let Some(entry) = ops.get_mut(&task_id) else {
                    return;
                };
                if !matches!(entry.status, OperationStatus::Queued) {
                    // Already cancelled or otherwise terminal before this
                    // task acquired its permit; still ensure a partial
                    // receipt is written if configured.
                    if matches!(entry.status, OperationStatus::Cancelled)
                        && api.emit_partial_receipt_on_cancel()
                    {
                        let _ = write_partial_receipt(api.receipts_dir(), &task_id);
                    }
                    return;
                }
                if entry.cancellation.is_cancelled() {
                    Self::finalize_cancelled(&api, &operations, &task_id).await;
                    return;
                }
                entry.transition(OperationStatus::Running);
            }

            if token.is_cancelled() {
                Self::finalize_cancelled(&api, &operations, &task_id).await;
                return;
            }

            let start = Instant::now();
            let outcome = api.inspect(&url).await;
            let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

            let mut ops = operations.lock().await;
            let Some(entry) = ops.get_mut(&task_id) else {
                return;
            };
            match outcome {
                Ok(result) => entry.transition(OperationStatus::Completed(OperationResult {
                    sha256: result.sha256,
                    verdict: format!("{:?}", result.verdict),
                    findings_count: result.findings.len(),
                    duration_ms,
                })),
                Err(error) => entry.transition(OperationStatus::Failed(error.to_string())),
            }
        });

        id
    }

    /// Returns the current status of an operation, if it exists.
    pub async fn status(&self, id: &OperationId) -> Option<OperationStatus> {
        self.operations
            .lock()
            .await
            .get(id)
            .map(|entry| entry.status.clone())
    }

    /// Lists all operations and their current statuses.
    pub async fn list(&self) -> Vec<(OperationId, OperationStatus)> {
        self.operations
            .lock()
            .await
            .iter()
            .map(|(id, entry)| (id.clone(), entry.status.clone()))
            .collect()
    }

    /// Cancels a queued operation. Returns `true` if the operation was queued
    /// and is now cancelled. Running or already-terminal operations are
    /// unaffected.
    pub async fn cancel(&self, id: &OperationId) -> bool {
        let mut ops = self.operations.lock().await;
        let Some(entry) = ops.get_mut(id) else {
            return false;
        };
        if matches!(entry.status, OperationStatus::Queued) {
            entry.cancellation.cancel();
            entry.transition(OperationStatus::Cancelled);
            true
        } else {
            false
        }
    }

    /// Cancels an operation identified by its string-form ID (spec §37.1).
    ///
    /// Triggers the shared [`CancellationToken`] so a running task observes
    /// the request at its next check. Returns `true` if the operation was
    /// found (regardless of state). For a queued operation, the status is
    /// transitioned to [`OperationStatus::Cancelled`] immediately and the
    /// partial receipt (if configured) is written before this call returns.
    /// For a running operation, the executing task finalises the transition
    /// once it observes the flag.
    pub async fn cancel_operation(&self, operation_id: &str) -> bool {
        let key = OperationId(operation_id.to_owned());
        let mut ops = self.operations.lock().await;
        let Some(entry) = ops.get_mut(&key) else {
            return false;
        };
        entry.cancellation.cancel();
        let mut need_receipt = false;
        if matches!(entry.status, OperationStatus::Queued) {
            entry.transition(OperationStatus::Cancelled);
            need_receipt = self.api.emit_partial_receipt_on_cancel();
        }
        drop(ops);
        if need_receipt {
            let _ = write_partial_receipt(self.api.receipts_dir(), &key);
        }
        true
    }

    /// Returns whether cancellation has been requested for the operation
    /// identified by its string-form ID (spec §37.1). Returns `false` for
    /// unknown IDs.
    #[must_use]
    pub async fn is_cancelled(&self, operation_id: &str) -> bool {
        let key = OperationId(operation_id.to_owned());
        self.operations
            .lock()
            .await
            .get(&key)
            .is_some_and(|entry| entry.cancellation.is_cancelled())
    }

    /// Removes terminal operations (completed, failed, cancelled) older than
    /// the given duration. Non-terminal operations are never reaped.
    pub async fn reap(&self, max_age: Duration) {
        let now = Instant::now();
        self.operations.lock().await.retain(|_, entry| {
            entry
                .terminal_at
                .is_none_or(|terminal| now.duration_since(terminal) < max_age)
        });
    }

    async fn finalize_cancelled(
        api: &ArbitraitorApi,
        operations: &Arc<Mutex<HashMap<OperationId, OperationEntry>>>,
        task_id: &OperationId,
    ) {
        let mut ops = operations.lock().await;
        let Some(entry) = ops.get_mut(task_id) else {
            return;
        };
        if matches!(entry.status, OperationStatus::Cancelled) {
            return;
        }
        entry.transition(OperationStatus::Cancelled);
        if api.emit_partial_receipt_on_cancel() {
            // Best-effort: a write failure must not resurrect a terminal
            // operation. The status stays `Cancelled` either way.
            let _ = write_partial_receipt(api.receipts_dir(), task_id);
        }
    }
}

/// Partial-receipt file body for a cancelled operation (spec §37.1).
///
/// The schema is intentionally minimal: the inspection never completed, so
/// there is no artifact digest, verdict, or detector output to attest to.
/// Operators who need richer forensic state should extend this struct in a
/// later ADR-bound change.
#[derive(Serialize)]
struct PartialReceipt<'a> {
    /// Receipt schema identifier. Distinct from the full-receipt schema
    /// so consumers can detect partial state.
    schema: &'a str,
    /// Operation identifier this receipt corresponds to.
    operation_id: &'a str,
    /// Cancellation status text, fixed for grep-ability.
    status: &'a str,
    /// Unix timestamp (seconds) at which the partial receipt was written.
    cancelled_at: u64,
}

fn write_partial_receipt(
    receipts_dir: &std::path::Path,
    id: &OperationId,
) -> std::io::Result<PathBuf> {
    fs::create_dir_all(receipts_dir)?;
    let receipt = PartialReceipt {
        schema: "arbitraitor-partial-receipt/v1",
        operation_id: id.as_str(),
        status: "cancelled",
        cancelled_at: epoch_seconds(),
    };
    let path = receipts_dir.join(format!("{}.cancelled.json", id.as_str()));
    let json = serde_json::to_vec_pretty(&receipt)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    fs::write(&path, json)?;
    Ok(path)
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
