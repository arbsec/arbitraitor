//! Integration tests for the background operation queue.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use arbitraitor_daemon::api::{ArbitraitorApi, Config};
use arbitraitor_daemon::queue::{OperationId, OperationQueue, OperationStatus};
use arbitraitor_fetch::{FetchPolicy, FetchScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const POLL_INTERVAL: Duration = Duration::from_millis(5);
const POLL_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unique_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "arb-queue-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn test_config(root: &Path) -> Config {
    Config {
        store_path: root.join("cas"),
        receipts_path: root.join("receipts"),
        fetch_policy: FetchPolicy {
            allowed_schemes: vec![FetchScheme::Http],
            allow_loopback_addresses: true,
            ..FetchPolicy::default()
        },
        policy_toml: String::new(),
    }
}

fn make_api(root: &Path) -> Arc<ArbitraitorApi> {
    Arc::new(ArbitraitorApi::new(test_config(root)).unwrap())
}

/// Multi-connection mock HTTP server that responds immediately.
async fn mock_http_server(body: &'static [u8]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0_u8; 1024];
                let _ = stream.read(&mut buf).await;
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(body).await;
            });
        }
    });
    format!("http://127.0.0.1:{port}/artifact")
}

/// Mock server whose responses block until [`BlockingServer::release_all`] is
/// called, and which tracks the number of in-flight connections.
struct BlockingServer {
    url: String,
    active: Arc<AtomicUsize>,
    release: Arc<AtomicBool>,
}

impl BlockingServer {
    fn url(&self) -> &str {
        &self.url
    }

    /// Returns the number of connections currently waiting for a response.
    fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    /// Releases every connection, allowing all blocked responses to proceed.
    fn release_all(&self) {
        self.release.store(true, Ordering::SeqCst);
    }
}

async fn blocking_server(body: &'static [u8]) -> BlockingServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let active = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let active_cloned = Arc::clone(&active);
    let release_cloned = Arc::clone(&release);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let active = Arc::clone(&active_cloned);
            let release = Arc::clone(&release_cloned);
            tokio::spawn(async move {
                let mut buf = [0_u8; 1024];
                let _ = stream.read(&mut buf).await;
                active.fetch_add(1, Ordering::SeqCst);
                while !release.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                     Content-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(body).await;
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    BlockingServer {
        url: format!("http://127.0.0.1:{port}/artifact"),
        active,
        release,
    }
}

/// Returns a URL on an ephemeral port that is not listening.
async fn unreachable_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("http://127.0.0.1:{port}/artifact")
}

async fn wait_for_running(queue: &OperationQueue, id: &OperationId) {
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        if matches!(queue.status(id).await, Some(OperationStatus::Running)) {
            return;
        }
        assert!(Instant::now() < deadline, "operation did not reach Running");
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_terminal(queue: &OperationQueue, id: &OperationId) -> OperationStatus {
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        if let Some(status) = queue.status(id).await
            && matches!(
                status,
                OperationStatus::Completed(_)
                    | OperationStatus::Failed(_)
                    | OperationStatus::Cancelled
            )
        {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "operation did not reach terminal state"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn enqueue_returns_immediately() {
    let root = unique_dir("enqueue");
    let queue = OperationQueue::new(make_api(&root), 2);
    let server = blocking_server(b"blocked").await;

    let start = Instant::now();
    let id = queue.enqueue_inspect(server.url().to_owned()).await;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(500),
        "enqueue blocked for {elapsed:?}"
    );
    let status = queue.status(&id).await;
    assert!(status.is_some(), "operation missing from queue");
    assert!(
        !matches!(
            status,
            Some(OperationStatus::Completed(_) | OperationStatus::Failed(_))
        ),
        "operation completed before server was released"
    );
}

#[tokio::test]
async fn queued_status_before_execution() {
    let root = unique_dir("queued");
    let queue = OperationQueue::new(make_api(&root), 1);
    let server = blocking_server(b"first").await;

    let id1 = queue.enqueue_inspect(server.url().to_owned()).await;
    wait_for_running(&queue, &id1).await;

    let id2 = queue.enqueue_inspect(server.url().to_owned()).await;
    let status2 = queue.status(&id2).await;
    assert_eq!(status2, Some(OperationStatus::Queued));
}

#[tokio::test]
async fn completed_status_after_execution() {
    let root = unique_dir("completed");
    let queue = OperationQueue::new(make_api(&root), 2);
    let url = mock_http_server(b"hello world").await;

    let id = queue.enqueue_inspect(url).await;
    let status = wait_for_terminal(&queue, &id).await;

    let result = match status {
        OperationStatus::Completed(result) => result,
        other => panic!("expected Completed, got {other:?}"),
    };
    assert!(!result.sha256.is_empty());
    assert!(result.duration_ms < 5_000);
}

#[tokio::test]
async fn failed_status_on_error() {
    let root = unique_dir("failed");
    let queue = OperationQueue::new(make_api(&root), 2);
    let url = unreachable_url().await;

    let id = queue.enqueue_inspect(url).await;
    let status = wait_for_terminal(&queue, &id).await;

    assert!(
        matches!(status, OperationStatus::Failed(_)),
        "got {status:?}"
    );
}

#[tokio::test]
async fn cancel_queued_operation() {
    let root = unique_dir("cancel");
    let queue = OperationQueue::new(make_api(&root), 1);
    let server = blocking_server(b"blocker").await;

    let id1 = queue.enqueue_inspect(server.url().to_owned()).await;
    wait_for_running(&queue, &id1).await;

    let id2 = queue.enqueue_inspect(server.url().to_owned()).await;
    assert_eq!(queue.status(&id2).await, Some(OperationStatus::Queued));

    assert!(queue.cancel(&id2).await);
    assert_eq!(queue.status(&id2).await, Some(OperationStatus::Cancelled));
    assert!(!queue.cancel(&id2).await);
}

#[tokio::test]
async fn list_shows_all_operations() {
    let root = unique_dir("list");
    let queue = OperationQueue::new(make_api(&root), 4);
    let url = mock_http_server(b"item").await;

    let id1 = queue.enqueue_inspect(url.clone()).await;
    let id2 = queue.enqueue_inspect(url.clone()).await;
    let id3 = queue.enqueue_inspect(url).await;

    wait_for_terminal(&queue, &id1).await;
    wait_for_terminal(&queue, &id2).await;
    wait_for_terminal(&queue, &id3).await;

    let list = queue.list().await;
    assert_eq!(list.len(), 3);
    let ids: Vec<&OperationId> = list.iter().map(|(id, _)| id).collect();
    assert!(ids.contains(&&id1));
    assert!(ids.contains(&&id2));
    assert!(ids.contains(&&id3));
}

#[tokio::test]
async fn reap_removes_old_operations() {
    let root = unique_dir("reap");
    let queue = OperationQueue::new(make_api(&root), 2);

    let server = blocking_server(b"alive").await;
    let blocker = queue.enqueue_inspect(server.url().to_owned()).await;
    wait_for_running(&queue, &blocker).await;

    let fast_url = mock_http_server(b"quick").await;
    let completed = queue.enqueue_inspect(fast_url).await;
    wait_for_terminal(&queue, &completed).await;

    queue.reap(Duration::from_hours(1)).await;
    assert!(
        queue.status(&blocker).await.is_some(),
        "running op should survive"
    );
    assert!(
        queue.status(&completed).await.is_some(),
        "young terminal op should survive"
    );

    queue.reap(Duration::ZERO).await;
    assert!(
        queue.status(&completed).await.is_none(),
        "old terminal op should be reaped"
    );
    assert!(
        queue.status(&blocker).await.is_some(),
        "running op should survive zero-age reap"
    );
}

#[tokio::test]
async fn max_concurrent_limits_parallelism() {
    let root = unique_dir("concurrency");
    let max_concurrent = 2;
    let queue = OperationQueue::new(make_api(&root), max_concurrent);
    let server = blocking_server(b"concurrent").await;

    let mut ids = Vec::new();
    for _ in 0..4 {
        ids.push(queue.enqueue_inspect(server.url().to_owned()).await);
    }

    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        let active = server.active();
        if active >= max_concurrent {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "never reached {max_concurrent} connections"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        server.active(),
        max_concurrent,
        "semaphore did not limit concurrency"
    );

    server.release_all();
    for id in &ids {
        let status = wait_for_terminal(&queue, id).await;
        assert!(
            matches!(status, OperationStatus::Completed(_)),
            "operation did not complete: {status:?}"
        );
    }
}
