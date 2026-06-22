//! Background operation queue for asynchronous daemon operations.
//!
//! Long-running operations (fetch+scan, release) are enqueued and executed
//! asynchronously, bounded by a concurrency semaphore. Callers receive an
//! [`OperationId`] immediately and poll for completion via
//! [`OperationQueue::status`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    /// Operation was cancelled before execution began.
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
}

impl OperationEntry {
    fn queued() -> Self {
        Self {
            status: OperationStatus::Queued,
            terminal_at: None,
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
    pub async fn enqueue_inspect(&self, url: String) -> OperationId {
        let id = OperationId::new();
        self.operations
            .lock()
            .await
            .insert(id.clone(), OperationEntry::queued());

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
                    return;
                }
                entry.transition(OperationStatus::Running);
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
            entry.transition(OperationStatus::Cancelled);
            true
        } else {
            false
        }
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
}
