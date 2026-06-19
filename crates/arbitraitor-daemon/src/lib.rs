//! Authenticated local daemon exposed over a Unix domain socket.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{HashMap, VecDeque};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arbitraitor_analysis::{AnalysisCoordinator, RetrievalInfo};
use arbitraitor_fetch::{FetchPolicy, FetchRequest, FetchUrl, Fetcher, HttpFetcher, VecSink};
use arbitraitor_model::ids::Sha256Digest;
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum DaemonRequest {
    /// Fetch, store, and analyze a URL artifact.
    Inspect {
        /// URL to retrieve.
        url: String,
        /// Optional expected SHA-256 digest in hexadecimal form.
        expected_sha256: Option<String>,
    },
    /// Analyze an existing local file path.
    Scan {
        /// Path to read and analyze.
        path: String,
    },
    /// Check whether an artifact digest exists and verifies in the CAS.
    QueryReceipt {
        /// SHA-256 digest in hexadecimal form.
        sha256: String,
    },
    /// Ask the daemon to stop accepting work and shut down.
    Shutdown,
}

/// Response returned by the local daemon protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
        }
    }

    /// Runs the daemon until a shutdown request or termination signal is received.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the socket cannot be bound or accepted.
    pub async fn run(&self) -> io::Result<()> {
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
    let response = handle_request_with_state(request, &state).await;
    write_response(&mut stream, &response).await
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
    match request {
        DaemonRequest::Inspect {
            url,
            expected_sha256,
        } => inspect_url(&url, expected_sha256.as_deref(), state).await,
        DaemonRequest::Scan { path } => scan_path(&path, state).await,
        DaemonRequest::QueryReceipt { sha256 } => query_receipt(&sha256, state),
        DaemonRequest::Shutdown => {
            state.shutdown.store(true, Ordering::SeqCst);
            state.notify_shutdown.notify_waiters();
            DaemonResponse {
                success: true,
                verdict: None,
                findings_count: 0,
                sha256: None,
                error: None,
            }
        }
    }
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
    }
}

fn error_response(message: impl Into<String>) -> DaemonResponse {
    DaemonResponse {
        success: false,
        verdict: None,
        findings_count: 0,
        sha256: None,
        error: Some(message.into()),
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
    use arbitraitor_fetch::FetchScheme;
    use tokio::net::TcpListener;

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
            },
        )
        .await?;
        assert!(response.success, "{:?}", response.error);
        assert_eq!(
            response.sha256,
            Some(Sha256Digest::new(Sha256::digest(b"plain text").into()).to_string())
        );
        assert!(
            request_once(&socket, &DaemonRequest::Shutdown)
                .await?
                .success
        );
        handle.await??;
        server.await??;
        remove_dir_all_if_exists(root)?;
        Ok(())
    }

    #[tokio::test]
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
            request_once(&socket, &DaemonRequest::Shutdown)
                .await?
                .success
        );
        handle.await??;
        remove_dir_all_if_exists(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_command_stops_daemon() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_path("shutdown")?;
        let socket = root.join("daemon.sock");
        let daemon = Daemon::new(&socket);
        let handle = tokio::spawn(async move { daemon.run().await });
        wait_for_socket(&socket).await?;

        let response = request_once(&socket, &DaemonRequest::Shutdown).await?;

        assert!(response.success);
        handle.await??;
        assert!(!socket.exists());
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
