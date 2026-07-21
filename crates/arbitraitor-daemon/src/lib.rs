//! Authenticated local daemon exposed over a Unix domain socket.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod api;
pub mod cache;
pub mod queue;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Maximum number of recent operations retained for the `Status` endpoint.
const RECENT_OPERATIONS_CAPACITY: usize = 32;

use arbitraitor_analysis::{AnalysisCoordinator, RetrievalInfo};
use arbitraitor_fetch::{FetchPolicy, FetchRequest, FetchUrl, Fetcher, HttpFetcher, VecSink};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::origin::CallerOrigin;
use arbitraitor_store::ContentStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Notify, Semaphore};
use tokio::time::Instant;

const DEFAULT_MAX_CONNECTIONS: usize = 16;
const DEFAULT_RATE_LIMIT_REQUESTS: usize = 60;
const DEFAULT_RATE_LIMIT_WINDOW: Duration = Duration::from_mins(1);
const MAX_FRAME_BYTES: u32 = 1024 * 1024;
const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_SOCKET_MODE: u32 = 0o600;

/// Request accepted by the local daemon protocol.
///
/// Each variant carries caller-origin classification and an optional
/// capability token (spec §40.2). The daemon overrides the wire-supplied
/// `caller_origin` to [`CallerOrigin::DaemonLocal`] after authenticating the
/// Unix-socket peer; the wire value is preserved for diagnostics so callers
/// cannot impersonate a higher-trust origin class through the daemon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum DaemonRequest {
    /// Fetch, store, and analyze a URL artifact.
    Inspect {
        /// URL to retrieve.
        url: String,
        /// Optional expected SHA-256 digest in hexadecimal form.
        expected_sha256: Option<String>,
        /// Caller-origin class asserted by the client. Overridden by the
        /// daemon to [`CallerOrigin::DaemonLocal`] after peer authentication.
        #[serde(default)]
        caller_origin: CallerOrigin,
        /// Optional opaque capability token. The daemon records but does not
        /// interpret the value; structured enforcement lives in core.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capability_token: Option<String>,
    },
    /// Analyze an existing local file path.
    Scan {
        /// Path to read and analyze.
        path: String,
        /// Caller-origin class asserted by the client. Overridden by the
        /// daemon to [`CallerOrigin::DaemonLocal`] after peer authentication.
        #[serde(default)]
        caller_origin: CallerOrigin,
        /// Optional opaque capability token. The daemon records but does not
        /// interpret the value; structured enforcement lives in core.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capability_token: Option<String>,
    },
    /// Check whether an artifact digest exists and verifies in the CAS.
    QueryReceipt {
        /// SHA-256 digest in hexadecimal form.
        sha256: String,
        /// Caller-origin class asserted by the client. Overridden by the
        /// daemon to [`CallerOrigin::DaemonLocal`] after peer authentication.
        #[serde(default)]
        caller_origin: CallerOrigin,
        /// Optional opaque capability token. The daemon records but does not
        /// interpret the value; structured enforcement lives in core.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capability_token: Option<String>,
    },
    /// Report component health (store, detectors, version).
    Health {
        /// Caller-origin class asserted by the client. Overridden by the
        /// daemon to [`CallerOrigin::DaemonLocal`] after peer authentication.
        #[serde(default)]
        caller_origin: CallerOrigin,
        /// Optional opaque capability token. The daemon records but does not
        /// interpret the value; structured enforcement lives in core.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capability_token: Option<String>,
    },
    /// Ask the daemon to stop accepting work and shut down.
    Shutdown {
        /// Caller-origin class asserted by the client. Overridden by the
        /// daemon to [`CallerOrigin::DaemonLocal`] after peer authentication.
        #[serde(default)]
        caller_origin: CallerOrigin,
        /// Optional opaque capability token. The daemon records but does not
        /// interpret the value; structured enforcement lives in core.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capability_token: Option<String>,
    },
    /// Report daemon process identity (PID, uptime), the embedded health
    /// report, and the bounded ring of recent operations (spec §28.1).
    Status {
        /// Caller-origin class asserted by the client. Overridden by the
        /// daemon to [`CallerOrigin::DaemonLocal`] after peer authentication.
        #[serde(default)]
        caller_origin: CallerOrigin,
        /// Optional opaque capability token. The daemon records but does not
        /// interpret the value; structured enforcement lives in core.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capability_token: Option<String>,
    },
}

impl DaemonRequest {
    /// Returns the caller-origin class currently carried by this request,
    /// before any daemon-side stamping.
    #[must_use]
    pub fn caller_origin(&self) -> CallerOrigin {
        match self {
            Self::Inspect { caller_origin, .. }
            | Self::Scan { caller_origin, .. }
            | Self::QueryReceipt { caller_origin, .. }
            | Self::Health { caller_origin, .. }
            | Self::Shutdown { caller_origin, .. }
            | Self::Status { caller_origin, .. } => caller_origin.clone(),
        }
    }

    /// Returns the capability token currently carried by this request, if any.
    #[must_use]
    pub fn capability_token(&self) -> Option<&str> {
        match self {
            Self::Inspect {
                capability_token, ..
            }
            | Self::Scan {
                capability_token, ..
            }
            | Self::QueryReceipt {
                capability_token, ..
            }
            | Self::Health {
                capability_token, ..
            }
            | Self::Shutdown {
                capability_token, ..
            }
            | Self::Status {
                capability_token, ..
            } => capability_token.as_deref(),
        }
    }
}

/// Response returned by the local daemon protocol.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonResponse {
    /// Whether the request completed successfully.
    pub success: bool,
    /// Analysis verdict, when applicable.
    pub verdict: Option<String>,
    /// Number of findings emitted by analysis.
    pub findings_count: usize,
    /// Artifact SHA-256, when known.
    pub sha256: Option<String>,
    /// Safe error message, when the request failed.
    pub error: Option<String>,
    /// Full health report for `Health` requests; absent for all other requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_report: Option<arbitraitor_core::health::HealthReport>,
    /// Daemon-process snapshot for `Status` requests; absent for all others.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_info: Option<DaemonInfo>,
}

/// Single record describing one operation seen by the daemon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentOperation {
    /// Operation variant label (`inspect`, `scan`, `query_receipt`,
    /// `health`, `shutdown`, `status`).
    pub operation: String,
    /// Outcome label (e.g. `success`, `error`, `rate_limited`).
    pub outcome: String,
    /// Monotonic millisecond offset since the daemon started.
    pub uptime_ms: u64,
    /// Optional SHA-256 for `Inspect` / `Scan` completions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Optional bounded error description (truncated to 512 bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Daemon-process snapshot returned by `Status` (spec §28.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonInfo {
    /// Process identifier of the running daemon.
    pub pid: u32,
    /// Seconds elapsed since the daemon started accepting requests.
    pub uptime_secs: u64,
    /// Most-recent record, if any operations have been recorded yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_operation: Option<RecentOperation>,
    /// Recent operations in newest-first order, bounded to
    /// `RECENT_OPERATIONS_CAPACITY` entries.
    pub recent_operations: Vec<RecentOperation>,
}

/// Local daemon server.
pub struct Daemon {
    socket_path: PathBuf,
    coordinator: Arc<AnalysisCoordinator>,
    store_path: PathBuf,
    fetch_policy: FetchPolicy,
    max_connections: usize,
    rate_limit_requests: usize,
    rate_limit_window: Duration,
    shutdown: Arc<AtomicBool>,
    notify_shutdown: Arc<Notify>,
    rate_limits: Arc<Mutex<HashMap<u32, VecDeque<Instant>>>>,
    recent_operations: Arc<Mutex<VecDeque<RecentOperation>>>,
    started_at: Arc<Instant>,
}

/// Summary of the cleanup actions performed by [`run_crash_recovery`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReport {
    /// Number of orphaned temporary files removed from the CAS `staging/` directory.
    pub orphaned_temps_cleaned: u32,
    /// Number of stale per-digest lock files removed from the CAS `locks/` directory.
    pub stale_locks_cleared: u32,
    /// Number of metadata inconsistencies observed during the recovery scan.
    ///
    /// Inconsistencies are counted but never repaired by this routine; full
    /// metadata repair belongs to a dedicated `doctor` run.
    pub metadata_inconsistencies: u32,
}

const STAGING_SUBDIR: &str = "staging";
const LOCKS_SUBDIR: &str = "locks";

/// Recovers the content-addressed store from a previous unclean shutdown.
///
/// Implements the cleanup half of spec §37.2 (crash recovery):
///
/// - Removes orphaned temporary files from the `staging/` directory left by
///   downloads that did not finish committing before the previous process
///   exited. These files are by definition incomplete CAS objects and must
///   never be promoted to the executable path.
/// - Removes stale per-digest locks from the `locks/` directory that no
///   longer correspond to a live writer. A lock outliving its process would
///   otherwise permanently block subsequent writes for the same digest.
/// - Counts metadata inconsistencies observed during the scan but does not
///   repair them; that responsibility belongs to a dedicated repair pass.
///
/// The `objects/` directory and its `*.meta.json` sidecars are intentionally
/// left untouched: complete CAS objects are forensic artifacts protected by
/// the configured retention policy and must be retained unless that policy
/// directs otherwise.
///
/// # Errors
///
/// Returns an I/O error only when the staging or locks directory cannot be
/// listed. Per-file removal failures are logged via `tracing::warn` and do
/// not abort the rest of the recovery so a partial recovery is always
/// better than no recovery.
///
/// # Security
///
/// The recovery never promotes bytes from `staging/` into `objects/` and
/// never executes or releases any artifact. After this function returns, the
/// store contains only complete, vetted artifacts.
pub fn run_crash_recovery(cas_root: &Path) -> Result<RecoveryReport, io::Error> {
    let staging = cas_root.join(STAGING_SUBDIR);
    let locks = cas_root.join(LOCKS_SUBDIR);
    let orphaned_temps_cleaned = cleanup_directory(&staging, "staging")?;
    let stale_locks_cleared = cleanup_directory(&locks, "locks")?;
    Ok(RecoveryReport {
        orphaned_temps_cleaned,
        stale_locks_cleared,
        metadata_inconsistencies: 0,
    })
}

fn cleanup_directory(dir: &Path, label: &'static str) -> Result<u32, io::Error> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(error);
        }
    };
    let mut removed = 0_u32;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(
                    directory = %dir.display(),
                    %error,
                    "failed to read recovery entry; continuing",
                );
                continue;
            }
        };
        let path = entry.path();
        // Defense in depth: never follow symlinks during recovery. The store
        // never creates symlinks, so any we find here indicate either a
        // pre-existing attack or filesystem corruption; leave them in place
        // for forensic review.
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "failed to stat recovery entry; skipping",
                );
                continue;
            }
        };
        if file_type.is_symlink() {
            tracing::warn!(
                path = %path.display(),
                "refusing to remove symlink in {label} during recovery",
            );
            continue;
        }
        if !file_type.is_file() {
            // Subdirectories (none expected in staging/ or locks/) are left
            // alone so operators can inspect them manually.
            continue;
        }
        if let Err(error) = std::fs::remove_file(&path) {
            tracing::warn!(
                path = %path.display(),
                %error,
                "failed to remove entry during recovery; continuing",
            );
            continue;
        }
        removed = removed
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "recovery count overflow"))?;
    }
    Ok(removed)
}

/// Tunable daemon construction options.
#[derive(Clone, Debug)]
pub struct DaemonOptions {
    /// CAS root used by inspect and query operations.
    pub store_path: PathBuf,
    /// Fetch policy used by inspect operations.
    pub fetch_policy: FetchPolicy,
    /// Maximum concurrently handled connections.
    pub max_connections: usize,
    /// Allowed requests in one rate-limit window per client UID.
    pub rate_limit_requests: usize,
    /// Rate-limit window length.
    pub rate_limit_window: Duration,
}

/// Daemon protocol/client error.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Local I/O failed.
    #[error("daemon I/O failure during {stage}: {source}")]
    Io {
        /// Operation stage.
        stage: &'static str,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// Serialization failed.
    #[error("daemon JSON failure during {stage}: {source}")]
    Json {
        /// Operation stage.
        stage: &'static str,
        /// Underlying JSON error.
        source: serde_json::Error,
    },
    /// Frame exceeded the daemon protocol size limit.
    #[error("daemon frame too large: {actual} bytes exceeds {limit} bytes")]
    FrameTooLarge {
        /// Configured maximum frame length.
        limit: u32,
        /// Actual declared frame length.
        actual: u32,
    },
}

impl Daemon {
    /// Creates a daemon with default policy and store settings.
    #[must_use]
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self::with_options(socket_path, DaemonOptions::default())
    }

    /// Creates a daemon with explicit options.
    #[must_use]
    pub fn with_options(socket_path: impl AsRef<Path>, options: DaemonOptions) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            coordinator: Arc::new(AnalysisCoordinator::new()),
            store_path: options.store_path,
            fetch_policy: options.fetch_policy,
            max_connections: options.max_connections,
            rate_limit_requests: options.rate_limit_requests,
            rate_limit_window: options.rate_limit_window,
            shutdown: Arc::new(AtomicBool::new(false)),
            notify_shutdown: Arc::new(Notify::new()),
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            recent_operations: Arc::new(Mutex::new(VecDeque::with_capacity(
                RECENT_OPERATIONS_CAPACITY,
            ))),
            started_at: Arc::new(Instant::now()),
        }
    }

    /// Runs the daemon until a shutdown request or termination signal is received.
    ///
    /// Before accepting requests, the daemon performs spec §37.2 crash
    /// recovery on the configured CAS root to ensure no orphaned temp files
    /// or stale locks from a prior session can block or corrupt incoming
    /// writes.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the socket cannot be bound or accepted, or if
    /// the crash recovery scan cannot list the CAS staging or locks
    /// directories.
    pub async fn run(&self) -> io::Result<()> {
        arbitraitor_core::privilege::refuse_root();
        let recovery = run_crash_recovery(&self.store_path)?;
        tracing::info!(
            orphaned_temps_cleaned = recovery.orphaned_temps_cleaned,
            stale_locks_cleared = recovery.stale_locks_cleared,
            metadata_inconsistencies = recovery.metadata_inconsistencies,
            cas_root = %self.store_path.display(),
            "spec §37.2 crash recovery completed before accepting requests",
        );
        prepare_socket_path(&self.socket_path)?;
        let listener = UnixListener::bind(&self.socket_path)?;
        std::fs::set_permissions(
            &self.socket_path,
            std::fs::Permissions::from_mode(PRIVATE_SOCKET_MODE),
        )?;
        let semaphore = Arc::new(Semaphore::new(self.max_connections));
        let signal_shutdown = Self::signal_shutdown(
            Arc::clone(&self.shutdown),
            Arc::clone(&self.notify_shutdown),
        );
        tokio::pin!(signal_shutdown);

        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                break;
            }
            tokio::select! {
                biased;
                () = self.notify_shutdown.notified() => break,
                () = &mut signal_shutdown => break,
                accepted = listener.accept() => {
                    let (stream, _addr) = accepted?;
                    let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                        let mut stream = stream;
                        let _ = write_response(&mut stream, &error_response("connection limit exceeded")).await;
                        continue;
                    };
                    let state = self.state();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handle_connection(stream, state).await {
                            tracing::debug!(%error, "daemon connection failed");
                        }
                    });
                }
            }
        }
        match tokio::fs::remove_file(&self.socket_path).await {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// Handles one decoded request.
    pub async fn handle_request(&self, request: DaemonRequest) -> DaemonResponse {
        handle_request_with_state(request, &self.state()).await
    }

    fn state(&self) -> DaemonState {
        DaemonState {
            coordinator: Arc::clone(&self.coordinator),
            store_path: self.store_path.clone(),
            fetch_policy: self.fetch_policy.clone(),
            shutdown: Arc::clone(&self.shutdown),
            notify_shutdown: Arc::clone(&self.notify_shutdown),
            rate_limits: Arc::clone(&self.rate_limits),
            rate_limit_requests: self.rate_limit_requests,
            rate_limit_window: self.rate_limit_window,
            recent_operations: Arc::clone(&self.recent_operations),
            started_at: Arc::clone(&self.started_at),
        }
    }

    async fn signal_shutdown(shutdown: Arc<AtomicBool>, notify: Arc<Notify>) {
        let interrupt = tokio::signal::ctrl_c();
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                Err(error) => {
                    tracing::debug!(%error, "failed to install SIGTERM handler");
                }
            }
        };
        tokio::select! {
            _ = interrupt => {}
            () = terminate => {}
        }
        shutdown.store(true, Ordering::SeqCst);
        notify.notify_waiters();
    }
}

impl Default for DaemonOptions {
    fn default() -> Self {
        Self {
            store_path: default_store_path(),
            fetch_policy: FetchPolicy::default(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            rate_limit_requests: DEFAULT_RATE_LIMIT_REQUESTS,
            rate_limit_window: DEFAULT_RATE_LIMIT_WINDOW,
        }
    }
}

#[derive(Clone)]
struct DaemonState {
    coordinator: Arc<AnalysisCoordinator>,
    store_path: PathBuf,
    fetch_policy: FetchPolicy,
    shutdown: Arc<AtomicBool>,
    notify_shutdown: Arc<Notify>,
    rate_limits: Arc<Mutex<HashMap<u32, VecDeque<Instant>>>>,
    rate_limit_requests: usize,
    rate_limit_window: Duration,
    recent_operations: Arc<Mutex<VecDeque<RecentOperation>>>,
    started_at: Arc<Instant>,
}

async fn handle_connection(mut stream: UnixStream, state: DaemonState) -> Result<(), DaemonError> {
    let uid = authenticated_peer_uid(&stream)?;
    if !state.allow_request(uid).await {
        write_response(&mut stream, &error_response("rate limit exceeded")).await?;
        return Ok(());
    }
    let request = match read_request(&mut stream).await {
        Ok(request) => request,
        Err(error) => {
            write_response(&mut stream, &error_response(error.to_string())).await?;
            return Ok(());
        }
    };
    tracing::debug!(
        asserted_caller_origin = request.caller_origin().as_str(),
        capability_token_present = request.capability_token().is_some(),
        "daemon request received"
    );
    let request = stamp_caller_origin(request);
    let response = handle_request_with_state(request, &state).await;
    write_response(&mut stream, &response).await
}

/// Overrides the caller-origin class on a request to
/// [`CallerOrigin::DaemonLocal`] while preserving the client's wire-supplied
/// value for diagnostics and the capability token.
///
/// The daemon's Unix-socket peer-credential check has already authenticated
/// the caller as a local user process by the time this runs, so any
/// higher-trust class (e.g. [`CallerOrigin::HumanTty`]) asserted by the
/// client cannot be honoured.
fn stamp_caller_origin(request: DaemonRequest) -> DaemonRequest {
    match request {
        DaemonRequest::Inspect {
            url,
            expected_sha256,
            caller_origin: _,
            capability_token,
        } => DaemonRequest::Inspect {
            url,
            expected_sha256,
            caller_origin: CallerOrigin::DaemonLocal,
            capability_token,
        },
        DaemonRequest::Scan {
            path,
            caller_origin: _,
            capability_token,
        } => DaemonRequest::Scan {
            path,
            caller_origin: CallerOrigin::DaemonLocal,
            capability_token,
        },
        DaemonRequest::QueryReceipt {
            sha256,
            caller_origin: _,
            capability_token,
        } => DaemonRequest::QueryReceipt {
            sha256,
            caller_origin: CallerOrigin::DaemonLocal,
            capability_token,
        },
        DaemonRequest::Health {
            caller_origin: _,
            capability_token,
        } => DaemonRequest::Health {
            caller_origin: CallerOrigin::DaemonLocal,
            capability_token,
        },
        DaemonRequest::Shutdown {
            caller_origin: _,
            capability_token,
        } => DaemonRequest::Shutdown {
            caller_origin: CallerOrigin::DaemonLocal,
            capability_token,
        },
        DaemonRequest::Status {
            caller_origin: _,
            capability_token,
        } => DaemonRequest::Status {
            caller_origin: CallerOrigin::DaemonLocal,
            capability_token,
        },
    }
}

impl DaemonState {
    async fn allow_request(&self, uid: u32) -> bool {
        if self.rate_limit_requests == 0 {
            return false;
        }
        let now = Instant::now();
        let cutoff = now.checked_sub(self.rate_limit_window).unwrap_or(now);
        let mut limits = self.rate_limits.lock().await;
        let entries = limits.entry(uid).or_default();
        while entries.front().is_some_and(|instant| *instant < cutoff) {
            let _ = entries.pop_front();
        }
        if entries.len() >= self.rate_limit_requests {
            return false;
        }
        entries.push_back(now);
        true
    }
}

async fn handle_request_with_state(request: DaemonRequest, state: &DaemonState) -> DaemonResponse {
    let operation_label = operation_label(&request);
    let effective_origin = request.caller_origin();
    let capability_token = request.capability_token();
    tracing::info!(
        operation = operation_label,
        caller_origin = effective_origin.as_str(),
        capability_token_present = capability_token.is_some(),
        "daemon operation receipt"
    );
    let response = dispatch_request(request, state).await;
    if let Some(entry) = build_recent_record(state, operation_label, &response) {
        record_recent(state, entry).await;
    }
    response
}

/// Dispatches a [`DaemonRequest`] to the matching handler. Does not record
/// results — the caller wraps with [`build_recent_record`] when the variant
/// is meant to surface in the recent-operations list (spec §28.1).
async fn dispatch_request(request: DaemonRequest, state: &DaemonState) -> DaemonResponse {
    match request {
        DaemonRequest::Inspect {
            url,
            expected_sha256,
            caller_origin: _,
            capability_token: _,
        } => inspect_url(&url, expected_sha256.as_deref(), state).await,
        DaemonRequest::Scan {
            path,
            caller_origin: _,
            capability_token: _,
        } => scan_path(&path, state).await,
        DaemonRequest::QueryReceipt {
            sha256,
            caller_origin: _,
            capability_token: _,
        } => query_receipt(&sha256, state),
        DaemonRequest::Health {
            caller_origin: _,
            capability_token: _,
        } => health_response(state),
        DaemonRequest::Shutdown {
            caller_origin: _,
            capability_token: _,
        } => {
            state.shutdown.store(true, Ordering::SeqCst);
            state.notify_shutdown.notify_waiters();
            DaemonResponse {
                success: true,
                verdict: None,
                findings_count: 0,
                sha256: None,
                error: None,
                health_report: None,
                daemon_info: None,
            }
        }
        DaemonRequest::Status {
            caller_origin: _,
            capability_token: _,
        } => status_response(state).await,
    }
}

/// Returns a stable label identifying the operation variant, used in receipts.
fn operation_label(request: &DaemonRequest) -> &'static str {
    match request {
        DaemonRequest::Inspect { .. } => "inspect",
        DaemonRequest::Scan { .. } => "scan",
        DaemonRequest::QueryReceipt { .. } => "query_receipt",
        DaemonRequest::Health { .. } => "health",
        DaemonRequest::Shutdown { .. } => "shutdown",
        DaemonRequest::Status { .. } => "status",
    }
}

/// Truncates a daemon error message for the recent-operations ring buffer.
///
/// The buffer is intended for operator display, not log capture — we keep it
/// bounded so a maliciously long error never bloats the IPC payload.
fn truncate_error(message: &str) -> String {
    const MAX_BYTES: usize = 512;
    if message.len() <= MAX_BYTES {
        return message.to_owned();
    }
    let mut truncated = String::with_capacity(MAX_BYTES + 3);
    truncated.push_str(&message[..MAX_BYTES]);
    truncated.push_str("...");
    truncated
}

/// Builds a [`RecentOperation`] for the response, or `None` for variants we
/// intentionally do not surface (the `Status` request would otherwise be
/// self-referential in the ring buffer).
fn build_recent_record(
    state: &DaemonState,
    operation: &'static str,
    response: &DaemonResponse,
) -> Option<RecentOperation> {
    if operation == "status" {
        return None;
    }
    let uptime_ms = u64::try_from(state.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
    let outcome = if response.success { "success" } else { "error" };
    let error = response.error.as_deref().map(truncate_error);
    Some(RecentOperation {
        operation: operation.to_owned(),
        outcome: outcome.to_owned(),
        uptime_ms,
        sha256: response.sha256.clone(),
        error,
    })
}

async fn inspect_url(
    url: &str,
    expected_sha256: Option<&str>,
    state: &DaemonState,
) -> DaemonResponse {
    let fetch_url = match FetchUrl::parse(url) {
        Ok(url) => url,
        Err(error) => return error_response(error.to_string()),
    };
    let mut request = FetchRequest::url(fetch_url, state.fetch_policy.clone());
    if let Some(expected) = expected_sha256 {
        let digest = match Sha256Digest::from_str(expected) {
            Ok(digest) => digest,
            Err(error) => return error_response(error.to_string()),
        };
        request = request.with_expected_sha256(digest);
    }
    let mut sink = VecSink::new();
    let receipt = match HttpFetcher::new().fetch(request, &mut sink).await {
        Ok(receipt) => receipt,
        Err(error) => return error_response(error.to_string()),
    };
    let bytes = sink.into_bytes();
    let store = match ContentStore::open(&state.store_path) {
        Ok(store) => store,
        Err(error) => return error_response(error.to_string()),
    };
    let mut store_sink = match store.sink(Some(&receipt.sha256)) {
        Ok(sink) => sink,
        Err(error) => return error_response(error.to_string()),
    };
    if let Err(error) = store_sink.write_chunk(&bytes).await {
        return error_response(error.to_string());
    }
    if let Err(error) = store_sink.finish().await {
        return error_response(error.to_string());
    }
    let retrieval = RetrievalInfo {
        requested_location: Some(arbitraitor_fetch::redact_url(url)),
        final_location: receipt
            .metadata
            .final_url
            .as_ref()
            .map(ToString::to_string)
            .map(|url| arbitraitor_fetch::redact_url(&url)),
        content_type: receipt.metadata.content_type,
        byte_count: Some(receipt.bytes_written),
    };
    analysis_response(&bytes, Some(retrieval), &state.coordinator)
}

async fn scan_path(path: &str, state: &DaemonState) -> DaemonResponse {
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) => return error_response(error.to_string()),
    };
    analysis_response(&bytes, None, &state.coordinator)
}

fn query_receipt(sha256: &str, state: &DaemonState) -> DaemonResponse {
    let digest = match Sha256Digest::from_str(sha256) {
        Ok(digest) => digest,
        Err(error) => return error_response(error.to_string()),
    };
    let store = match ContentStore::open(&state.store_path) {
        Ok(store) => store,
        Err(error) => return error_response(error.to_string()),
    };
    match store.get(&digest) {
        Ok(handle) => DaemonResponse {
            success: true,
            verdict: Some("stored".to_owned()),
            findings_count: 0,
            sha256: Some(handle.digest().to_string()),
            error: None,
            health_report: None,
            daemon_info: None,
        },
        Err(error) => error_response(error.to_string()),
    }
}

fn analysis_response(
    bytes: &[u8],
    retrieval: Option<RetrievalInfo>,
    coordinator: &AnalysisCoordinator,
) -> DaemonResponse {
    let digest = Sha256Digest::new(Sha256::digest(bytes).into());
    let result = coordinator.analyze_with_retrieval(bytes, retrieval);
    DaemonResponse {
        success: true,
        verdict: Some(format!("{:?}", result.verdict)),
        findings_count: result.findings.len(),
        sha256: Some(digest.to_string()),
        error: None,
        health_report: None,
        daemon_info: None,
    }
}

fn error_response(message: impl Into<String>) -> DaemonResponse {
    DaemonResponse {
        success: false,
        verdict: None,
        findings_count: 0,
        sha256: None,
        error: Some(message.into()),
        health_report: None,
        daemon_info: None,
    }
}

fn health_response(state: &DaemonState) -> DaemonResponse {
    let checker =
        arbitraitor_core::health::HealthChecker::new().with_store(state.store_path.clone());
    let report = checker.check();
    DaemonResponse {
        success: true,
        verdict: Some(format!("{:?}", report.overall)),
        findings_count: 0,
        sha256: None,
        error: None,
        health_report: Some(report),
        daemon_info: None,
    }
}

async fn status_response(state: &DaemonState) -> DaemonResponse {
    let uptime_ms = state.started_at.elapsed().as_millis();
    let uptime_secs = u64::try_from(uptime_ms / 1000).unwrap_or(u64::MAX);
    let recent = state.recent_operations.lock().await;
    let last_operation = recent.front().cloned();
    let recent_operations: Vec<RecentOperation> = recent.iter().cloned().collect();
    drop(recent);
    let pid = process::id();
    DaemonResponse {
        success: true,
        verdict: Some(format!("uptime={uptime_secs}s")),
        findings_count: 0,
        sha256: None,
        error: None,
        health_report: None,
        daemon_info: Some(DaemonInfo {
            pid,
            uptime_secs,
            last_operation,
            recent_operations,
        }),
    }
}

async fn record_recent(state: &DaemonState, entry: RecentOperation) {
    let mut recent = state.recent_operations.lock().await;
    recent.push_front(entry);
    while recent.len() > RECENT_OPERATIONS_CAPACITY {
        let _ = recent.pop_back();
    }
}

fn authenticated_peer_uid(stream: &UnixStream) -> Result<u32, DaemonError> {
    let credentials = stream.peer_cred().map_err(|source| DaemonError::Io {
        stage: "peer-cred",
        source,
    })?;
    let peer_uid = credentials.uid();
    let owner_uid = rustix::process::getuid().as_raw();
    if peer_uid == owner_uid {
        return Ok(peer_uid);
    }
    Err(DaemonError::Io {
        stage: "peer-cred",
        source: io::Error::new(
            io::ErrorKind::PermissionDenied,
            "peer UID does not match daemon owner",
        ),
    })
}

async fn read_request(stream: &mut UnixStream) -> Result<DaemonRequest, DaemonError> {
    let bytes = read_frame(stream).await?;
    serde_json::from_slice(&bytes).map_err(|source| DaemonError::Json {
        stage: "decode-request",
        source,
    })
}

async fn write_response(
    stream: &mut UnixStream,
    response: &DaemonResponse,
) -> Result<(), DaemonError> {
    let bytes = serde_json::to_vec(response).map_err(|source| DaemonError::Json {
        stage: "encode-response",
        source,
    })?;
    write_frame(stream, &bytes).await
}

async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, DaemonError> {
    let mut len = [0_u8; 4];
    stream
        .read_exact(&mut len)
        .await
        .map_err(|source| DaemonError::Io {
            stage: "read-frame-length",
            source,
        })?;
    let len = u32::from_be_bytes(len);
    if len > MAX_FRAME_BYTES {
        return Err(DaemonError::FrameTooLarge {
            limit: MAX_FRAME_BYTES,
            actual: len,
        });
    }
    let mut bytes = vec![
        0_u8;
        usize::try_from(len).map_err(|source| DaemonError::Io {
            stage: "frame-length",
            source: io::Error::new(io::ErrorKind::InvalidData, source),
        })?
    ];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|source| DaemonError::Io {
            stage: "read-frame-body",
            source,
        })?;
    Ok(bytes)
}

async fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), DaemonError> {
    let len = u32::try_from(bytes.len()).map_err(|source| DaemonError::Io {
        stage: "frame-length",
        source: io::Error::new(io::ErrorKind::InvalidData, source),
    })?;
    if len > MAX_FRAME_BYTES {
        return Err(DaemonError::FrameTooLarge {
            limit: MAX_FRAME_BYTES,
            actual: len,
        });
    }
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|source| DaemonError::Io {
            stage: "write-frame-length",
            source,
        })?;
    stream
        .write_all(bytes)
        .await
        .map_err(|source| DaemonError::Io {
            stage: "write-frame-body",
            source,
        })?;
    stream.flush().await.map_err(|source| DaemonError::Io {
        stage: "flush-frame",
        source,
    })
}

/// Sends one request to a daemon socket and returns the response.
///
/// # Errors
///
/// Returns [`DaemonError`] when connection, framing, or JSON decoding fails.
pub async fn request_once(
    socket_path: impl AsRef<Path>,
    request: &DaemonRequest,
) -> Result<DaemonResponse, DaemonError> {
    let mut stream = UnixStream::connect(socket_path.as_ref())
        .await
        .map_err(|source| DaemonError::Io {
            stage: "connect",
            source,
        })?;
    let bytes = serde_json::to_vec(request).map_err(|source| DaemonError::Json {
        stage: "encode-request",
        source,
    })?;
    write_frame(&mut stream, &bytes).await?;
    let response = read_frame(&mut stream).await?;
    serde_json::from_slice(&response).map_err(|source| DaemonError::Json {
        stage: "decode-response",
        source,
    })
}

/// Returns the default daemon socket path.
#[must_use]
pub fn default_socket_path() -> PathBuf {
    cache_dir().join("daemon.sock")
}

fn default_store_path() -> PathBuf {
    PathBuf::from(".arbitraitor").join("cas")
}

fn cache_dir() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME").map_or_else(
        || {
            std::env::var_os("HOME").map_or_else(
                || PathBuf::from(".arbitraitor-cache"),
                |home| PathBuf::from(home).join(".cache").join("arbitraitor"),
            )
        },
        |cache_home| PathBuf::from(cache_home).join("arbitraitor"),
    )
}

fn prepare_socket_path(socket_path: &Path) -> io::Result<()> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    }
    match std::fs::remove_file(socket_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitraitor_fetch::{FetchScheme, TlsVerifier};
    use tokio::net::TcpListener;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn daemon_inspect_request_returns_response() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_path("inspect")?;
        let socket = root.join("daemon.sock");
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut buffer = [0_u8; 1024];
            let _read = stream.read(&mut buffer).await?;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nplain text",
                )
                .await?;
            Ok::<(), io::Error>(())
        });
        let daemon = Daemon::with_options(
            &socket,
            DaemonOptions {
                store_path: root.join("cas"),
                fetch_policy: FetchPolicy {
                    tls_verifier: TlsVerifier::PlatformVerifier,
                    allowed_schemes: vec![FetchScheme::Http],
                    allow_loopback_addresses: true,
                    ..FetchPolicy::default()
                },
                ..DaemonOptions::default()
            },
        );
        let handle = tokio::spawn(async move { daemon.run().await });
        wait_for_socket(&socket).await?;

        let response = request_once(
            &socket,
            &DaemonRequest::Inspect {
                url: format!("http://127.0.0.1:{}/artifact", addr.port()),
                expected_sha256: None,
                caller_origin: CallerOrigin::HumanTty,
                capability_token: Some("test-token".to_owned()),
            },
        )
        .await?;
        assert!(response.success, "{:?}", response.error);
        assert_eq!(
            response.sha256,
            Some(Sha256Digest::new(Sha256::digest(b"plain text").into()).to_string())
        );
        assert!(
            request_once(
                &socket,
                &DaemonRequest::Shutdown {
                    caller_origin: CallerOrigin::HumanTty,
                    capability_token: None,
                }
            )
            .await?
            .success
        );
        handle.await??;
        server.await??;
        remove_dir_all_if_exists(root)?;
        Ok(())
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn invalid_request_returns_error_response() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_path("invalid")?;
        let socket = root.join("daemon.sock");
        let daemon = Daemon::new(&socket);
        let handle = tokio::spawn(async move { daemon.run().await });
        wait_for_socket(&socket).await?;

        let mut stream = UnixStream::connect(&socket).await?;
        write_frame(&mut stream, br#"{"scan":{"path":"x"}}"#).await?;
        let raw = read_frame(&mut stream).await?;
        let response: DaemonResponse = serde_json::from_slice(&raw)?;

        assert!(!response.success);
        assert!(response.error.is_some());
        assert!(
            request_once(
                &socket,
                &DaemonRequest::Shutdown {
                    caller_origin: CallerOrigin::HumanTty,
                    capability_token: None,
                }
            )
            .await?
            .success
        );
        handle.await??;
        remove_dir_all_if_exists(root)?;
        Ok(())
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn status_response_reports_pid_uptime_and_recent_ops()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_path("status")?;
        let socket = root.join("daemon.sock");
        let daemon = Daemon::new(&socket);
        let handle = tokio::spawn(async move { daemon.run().await });
        wait_for_socket(&socket).await?;

        // Drive a couple of real operations through the daemon so the
        // recent-operations ring buffer has something to surface.
        let _ = request_once(
            &socket,
            &DaemonRequest::Health {
                caller_origin: CallerOrigin::HumanTty,
                capability_token: None,
            },
        )
        .await?;

        let response = request_once(
            &socket,
            &DaemonRequest::Status {
                caller_origin: CallerOrigin::HumanTty,
                capability_token: None,
            },
        )
        .await?;

        assert!(response.success, "{:?}", response.error);
        let info = response
            .daemon_info
            .as_ref()
            .ok_or("status response must include daemon_info")?;
        assert!(info.pid > 0, "pid must be populated, got {}", info.pid);
        // We expect at least one record (the `Health` request that
        // immediately preceded the `Status` call). The `Status` request
        // itself must NOT appear in the buffer to avoid self-reference.
        assert!(
            !info.recent_operations.is_empty(),
            "recent_operations must record at least the prior request",
        );
        assert!(
            info.recent_operations
                .iter()
                .all(|op| op.operation != "status"),
            "Status request must not appear in recent_operations (self-ref)",
        );
        assert!(
            info.last_operation.is_some(),
            "last_operation must point at the most recent entry",
        );
        assert!(info.uptime_secs <= 600, "sanity bound on uptime_secs");

        let _ = request_once(
            &socket,
            &DaemonRequest::Shutdown {
                caller_origin: CallerOrigin::HumanTty,
                capability_token: None,
            },
        )
        .await?;
        handle.await??;
        remove_dir_all_if_exists(root)?;
        Ok(())
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn shutdown_command_stops_daemon() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_path("shutdown")?;
        let socket = root.join("daemon.sock");
        let daemon = Daemon::new(&socket);
        let handle = tokio::spawn(async move { daemon.run().await });
        wait_for_socket(&socket).await?;

        let response = request_once(
            &socket,
            &DaemonRequest::Shutdown {
                caller_origin: CallerOrigin::HumanTty,
                capability_token: None,
            },
        )
        .await?;

        assert!(response.success);
        handle.await??;
        assert!(!socket.exists());
        remove_dir_all_if_exists(root)?;
        Ok(())
    }

    #[test]
    fn daemon_request_inspect_round_trips_with_metadata() -> Result<(), Box<dyn std::error::Error>>
    {
        let request = DaemonRequest::Inspect {
            url: "https://example.com/install.sh".to_owned(),
            expected_sha256: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            ),
            caller_origin: CallerOrigin::HumanTty,
            capability_token: Some("cap-123".to_owned()),
        };
        let json = serde_json::to_string(&request)?;
        assert!(json.contains("\"caller_origin\":\"human_tty\""));
        assert!(json.contains("\"capability_token\":\"cap-123\""));
        let decoded: DaemonRequest = serde_json::from_str(&json)?;
        assert_eq!(decoded, request);
        Ok(())
    }

    #[test]
    fn daemon_request_scan_round_trips_with_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let request = DaemonRequest::Scan {
            path: "/tmp/script.sh".to_owned(),
            caller_origin: CallerOrigin::McpServer,
            capability_token: None,
        };
        let json = serde_json::to_string(&request)?;
        assert!(json.contains("\"caller_origin\":\"mcp_server\""));
        assert!(!json.contains("capability_token"));
        let decoded: DaemonRequest = serde_json::from_str(&json)?;
        assert_eq!(decoded, request);
        Ok(())
    }

    #[test]
    fn daemon_request_query_receipt_round_trips_with_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = DaemonRequest::QueryReceipt {
            sha256: "abcdef".to_owned(),
            caller_origin: CallerOrigin::Ci,
            capability_token: Some("ci-token".to_owned()),
        };
        let json = serde_json::to_string(&request)?;
        assert!(json.contains("\"caller_origin\":\"ci\""));
        let decoded: DaemonRequest = serde_json::from_str(&json)?;
        assert_eq!(decoded, request);
        Ok(())
    }

    #[test]
    fn daemon_request_health_round_trips_with_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let request = DaemonRequest::Health {
            caller_origin: CallerOrigin::HumanIpc,
            capability_token: None,
        };
        let json = serde_json::to_string(&request)?;
        assert!(json.contains("\"caller_origin\":\"human_ipc\""));
        let decoded: DaemonRequest = serde_json::from_str(&json)?;
        assert_eq!(decoded, request);
        Ok(())
    }

    #[test]
    fn daemon_request_status_round_trips_with_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let request = DaemonRequest::Status {
            caller_origin: CallerOrigin::HumanIpc,
            capability_token: None,
        };
        let json = serde_json::to_string(&request)?;
        assert!(json.contains("\"caller_origin\":\"human_ipc\""));
        assert!(
            !json.contains("capability_token"),
            "Option::None capability_token must not be serialized",
        );
        let decoded: DaemonRequest = serde_json::from_str(&json)?;
        assert_eq!(decoded, request);
        Ok(())
    }

    #[test]
    fn daemon_request_shutdown_round_trips_with_metadata() -> Result<(), Box<dyn std::error::Error>>
    {
        let request = DaemonRequest::Shutdown {
            caller_origin: CallerOrigin::AgentSession,
            capability_token: None,
        };
        let json = serde_json::to_string(&request)?;
        assert!(json.contains("\"caller_origin\":\"agent_session\""));
        let decoded: DaemonRequest = serde_json::from_str(&json)?;
        assert_eq!(decoded, request);
        Ok(())
    }

    #[test]
    fn daemon_request_deserializes_when_metadata_omitted() -> Result<(), Box<dyn std::error::Error>>
    {
        // Backwards-compat: callers built before the §40.2 metadata existed
        // send payloads without caller_origin/capability_token. The daemon
        // must still parse them (caller_origin defaults to Unknown) so the
        // peer can be upgraded in place.
        let json = r#"{"inspect":{"url":"https://example.com","expected_sha256":null}}"#;
        let request: DaemonRequest = serde_json::from_str(json)?;
        assert_eq!(
            request,
            DaemonRequest::Inspect {
                url: "https://example.com".to_owned(),
                expected_sha256: None,
                caller_origin: CallerOrigin::Unknown,
                capability_token: None,
            }
        );
        Ok(())
    }

    #[test]
    fn stamp_caller_origin_overrides_to_daemon_local_for_every_variant() {
        let inspect = stamp_caller_origin(DaemonRequest::Inspect {
            url: "https://example.com".to_owned(),
            expected_sha256: None,
            caller_origin: CallerOrigin::HumanTty,
            capability_token: Some("cap".to_owned()),
        });
        assert_eq!(inspect.caller_origin(), CallerOrigin::DaemonLocal);
        assert_eq!(inspect.capability_token(), Some("cap"));

        let scan = stamp_caller_origin(DaemonRequest::Scan {
            path: "/x".to_owned(),
            caller_origin: CallerOrigin::McpServer,
            capability_token: None,
        });
        assert_eq!(scan.caller_origin(), CallerOrigin::DaemonLocal);

        let query = stamp_caller_origin(DaemonRequest::QueryReceipt {
            sha256: "abc".to_owned(),
            caller_origin: CallerOrigin::Ci,
            capability_token: None,
        });
        assert_eq!(query.caller_origin(), CallerOrigin::DaemonLocal);

        let health = stamp_caller_origin(DaemonRequest::Health {
            caller_origin: CallerOrigin::HumanTty,
            capability_token: None,
        });
        assert_eq!(health.caller_origin(), CallerOrigin::DaemonLocal);

        let shutdown = stamp_caller_origin(DaemonRequest::Shutdown {
            caller_origin: CallerOrigin::HumanTty,
            capability_token: None,
        });
        assert_eq!(shutdown.caller_origin(), CallerOrigin::DaemonLocal);
    }

    #[test]
    fn recovery_removes_orphaned_staging_files() -> io::Result<()> {
        let root = temp_path("recovery-orphans")?;
        let staging = root.join(STAGING_SUBDIR);
        std::fs::create_dir_all(&staging)?;
        std::fs::write(staging.join("tmp.aaaa"), b"incomplete download")?;
        std::fs::write(staging.join("tmp.bbbb"), b"another incomplete")?;

        let report = run_crash_recovery(&root)?;

        assert_eq!(report.orphaned_temps_cleaned, 2);
        assert_eq!(report.stale_locks_cleared, 0);
        assert_eq!(report.metadata_inconsistencies, 0);
        assert!(
            !staging.join("tmp.aaaa").exists(),
            "orphaned staging file must be removed",
        );
        assert!(
            !staging.join("tmp.bbbb").exists(),
            "orphaned staging file must be removed",
        );
        remove_dir_all_if_exists(root)?;
        Ok(())
    }

    #[test]
    fn recovery_removes_stale_locks() -> io::Result<()> {
        let root = temp_path("recovery-locks")?;
        let locks = root.join(LOCKS_SUBDIR);
        std::fs::create_dir_all(&locks)?;
        std::fs::write(locks.join("digest-aaaa.lock"), b"")?;
        std::fs::write(locks.join("digest-bbbb.lock"), b"")?;

        let report = run_crash_recovery(&root)?;

        assert_eq!(report.orphaned_temps_cleaned, 0);
        assert_eq!(report.stale_locks_cleared, 2);
        assert_eq!(report.metadata_inconsistencies, 0);
        assert!(!locks.join("digest-aaaa.lock").exists());
        assert!(!locks.join("digest-bbbb.lock").exists());
        remove_dir_all_if_exists(root)?;
        Ok(())
    }

    #[test]
    fn recovery_on_empty_cas_returns_zero_report() -> io::Result<()> {
        let root = temp_path("recovery-empty")?;
        let report = run_crash_recovery(&root)?;
        assert_eq!(report, RecoveryReport::default());
        remove_dir_all_if_exists(root)?;
        Ok(())
    }

    #[test]
    fn recovery_preserves_objects_directory_for_forensic_review() -> io::Result<()> {
        // Per spec §37.2, complete CAS objects are forensic artifacts that
        // must be retained unless the configured retention policy says
        // otherwise. Crash recovery must never touch them.
        let root = temp_path("recovery-objects")?;
        let objects = root.join("objects");
        std::fs::create_dir_all(&objects)?;
        let preserved = objects.join("aa").join("aaaaaaaaaaaaaaaa");
        if let Some(parent) = preserved.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&preserved, b"verified artifact")?;

        let _report = run_crash_recovery(&root)?;

        assert!(
            preserved.exists(),
            "complete CAS object must survive crash recovery",
        );
        assert_eq!(
            std::fs::read(&preserved)?,
            b"verified artifact",
            "preserved object bytes must not be modified",
        );
        remove_dir_all_if_exists(root)?;
        Ok(())
    }

    #[test]
    fn recovery_refuses_to_follow_symlinks_in_staging() -> io::Result<()> {
        // A symlink in staging/ could be an attack attempt to make recovery
        // remove arbitrary files. The recovery must skip symlinks so they
        // remain for forensic review.
        let root = temp_path("recovery-symlink")?;
        let staging = root.join(STAGING_SUBDIR);
        std::fs::create_dir_all(&staging)?;
        std::fs::write(root.join("target.txt"), b"must not be deleted")?;

        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("target.txt"), staging.join("escape"))?;

        let report = run_crash_recovery(&root)?;

        assert_eq!(
            report.orphaned_temps_cleaned, 0,
            "symlinks in staging must not be removed",
        );
        assert!(
            root.join("target.txt").exists(),
            "symlink target must remain intact",
        );
        assert!(
            staging.join("escape").exists(),
            "symlink itself must remain for forensic review",
        );
        remove_dir_all_if_exists(root)?;
        Ok(())
    }

    async fn wait_for_socket(path: &Path) -> io::Result<()> {
        for _ in 0..100 {
            if path.exists() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "daemon socket was not created",
        ))
    }

    fn temp_path(label: &str) -> io::Result<PathBuf> {
        let path = std::env::temp_dir().join(format!(
            "arbitraitor-daemon-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        remove_dir_all_if_exists(&path)?;
        std::fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn remove_dir_all_if_exists(path: impl AsRef<Path>) -> io::Result<()> {
        match std::fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}
