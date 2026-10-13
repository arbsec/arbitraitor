//! Bounded retry for the redb cross-process open lock.
//!
//! redb's whole-file lock means only one process may hold a
//! [`redb::Database`] open at a time. Two Arbitraitor processes fetching at
//! the same moment (a CLI fetch racing a daemon- or MCP-triggered fetch) is
//! normal, transient contention: the loser only needs to wait for the
//! winner's open→use→close window. [`open_with_retry`] therefore retries
//! `redb::DatabaseError::DatabaseAlreadyOpen` with a short backoff for a
//! bounded total duration, then fails closed with a diagnostic that names
//! the situation instead of the raw redb message.

#![forbid(unsafe_code)]

use std::path::Path;
use std::time::{Duration, Instant};

use redb::DatabaseError;

use crate::StoreError;

/// Per-attempt backoff between open retries.
const RETRY_BACKOFF: Duration = Duration::from_millis(50);

/// Total budget for retrying a contended metadata-database open.
///
/// Sized for the realistic holder window (an open→store→close of a
/// concurrent fetch, or a daemon health/metadata probe): after this budget
/// the contention is no longer transient and failing fast with a pointed
/// diagnostic beats blocking the caller.
const OPEN_RETRY_BUDGET: Duration = Duration::from_millis(400);

/// Returns `true` when the redb open failed because another process holds
/// the database file lock (the retryable contention class).
const fn is_already_open(error: &redb::DatabaseError) -> bool {
    matches!(error, DatabaseError::DatabaseAlreadyOpen)
}

/// Holder-naming diagnostic appended to the raw redb message after the
/// retry budget is exhausted.
fn holder_hint() -> &'static str {
    "another arbitraitor process (daemon or MCP server) may be holding the \
     metadata store; inspect with `pgrep -af arbitraitor`"
}

/// Opens (or creates) the redb database at `path`, retrying a contended
/// open within [`OPEN_RETRY_BUDGET`].
///
/// # Errors
///
/// Returns [`StoreError::Index`] when redb cannot open the database. A lock
/// conflict that survives the retry budget produces a message naming the
/// likely holder; all other errors surface redb's message unchanged.
pub(crate) fn open_with_retry(
    path: &Path,
    stage: &'static str,
    exists: fn(&Path) -> bool,
) -> Result<redb::Database, StoreError> {
    let open = || -> Result<redb::Database, redb::DatabaseError> {
        if exists(path) {
            redb::Database::open(path)
        } else {
            redb::Database::create(path)
        }
    };

    let deadline = Instant::now() + OPEN_RETRY_BUDGET;
    loop {
        match open() {
            Ok(db) => return Ok(db),
            Err(error) if is_already_open(&error) && Instant::now() < deadline => {
                std::thread::sleep(RETRY_BACKOFF);
            }
            Err(error) if is_already_open(&error) => {
                return Err(StoreError::Index {
                    stage,
                    message: format!(
                        "metadata store at {} is locked: {error}. {}",
                        path.display(),
                        holder_hint(),
                    ),
                });
            }
            Err(error) => {
                return Err(StoreError::Index {
                    stage,
                    message: error.to_string(),
                });
            }
        }
    }
}
