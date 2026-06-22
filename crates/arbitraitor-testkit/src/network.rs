//! Raw TCP-based mock HTTP servers for adversarial network testing.
//!
//! Unlike [`crate::mock_server::MockHttpServer`] (which uses `WireMock`), these
//! servers operate at the raw TCP level. This allows testing scenarios that
//! `WireMock` cannot express: slow-drip responses for timeout testing, servers
//! that accept TCP but never speak HTTP (for TLS failure testing), and servers
//! bound to specific loopback addresses for real SSRF network verification.
//!
//! # Errors
//!
//! All constructors return [`std::io::Result`]. Binding failures (extremely
//! rare on loopback with ephemeral ports) are propagated to the caller.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Polling interval for the non-blocking accept loop.
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Read timeout applied to each accepted connection.
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// A local TCP server that responds to HTTP requests with configured behavior.
///
/// The server runs in a dedicated OS thread. Dropping the server signals
/// shutdown and joins the thread, ensuring clean teardown.
pub struct MockHttpServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockHttpServer {
    /// Creates a server that responds with the given status, headers, and body.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if binding the TCP listener fails.
    pub fn new(
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> std::io::Result<Self> {
        let status_line = format!("HTTP/1.1 {status} {}\r\n", reason_phrase(status));
        Self::spawn(move |stream| {
            consume_request(stream);
            let response = build_response(&status_line, &headers, &body);
            let _ = stream.write_all(&response);
            let _ = stream.flush();
        })
    }

    /// Creates a server that responds with an HTTP redirect to `target_url`.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if binding the TCP listener fails.
    pub fn redirect(target_url: &str) -> std::io::Result<Self> {
        Self::new(
            302,
            vec![("Location".to_owned(), target_url.to_owned())],
            Vec::new(),
        )
    }

    /// Creates a server that sends body bytes with a `delay` between chunks.
    ///
    /// The server sends `chunk_size` bytes at a time, sleeping `delay` after
    /// each write. This exercises read-timeout enforcement in the fetcher.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if binding the TCP listener fails.
    pub fn slow_stream(
        delay: Duration,
        chunk_size: usize,
        total_bytes: usize,
    ) -> std::io::Result<Self> {
        Self::spawn(move |stream| {
            consume_request(stream);
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {total_bytes}\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.flush();
            let chunk = vec![b'a'; chunk_size];
            let mut sent = 0;
            while sent < total_bytes {
                let n = chunk_size.min(total_bytes - sent);
                let _ = stream.write_all(&chunk[..n]);
                let _ = stream.flush();
                sent += n;
                thread::sleep(delay);
            }
        })
    }

    /// Creates a server that accepts connections but never sends HTTP data.
    ///
    /// Used to verify that HTTPS fetches to a non-TLS server fail — the TLS
    /// handshake cannot complete because no `ServerHello` is ever sent.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if binding the TCP listener fails.
    pub fn silent() -> std::io::Result<Self> {
        Self::spawn(|stream| {
            let _ = stream;
        })
    }

    fn spawn<F>(handler: F) -> std::io::Result<Self>
    where
        F: Fn(&mut TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_flag = shutdown.clone();

        let handle = thread::spawn(move || {
            while !shutdown_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).ok();
                        stream.set_read_timeout(Some(CONNECTION_READ_TIMEOUT)).ok();
                        handler(&mut stream);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_POLL_INTERVAL);
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            addr,
            shutdown,
            handle: Some(handle),
        })
    }

    /// Returns the bound socket address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns the base URL to connect to.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }
}

impl Drop for MockHttpServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Creates a redirect server pointing to `target_url`.
///
/// # Errors
///
/// Returns [`std::io::Error`] if binding the TCP listener fails.
pub fn redirect_server(target_url: &str) -> std::io::Result<MockHttpServer> {
    MockHttpServer::redirect(target_url)
}

/// Binds a TCP listener to obtain a free port, then drops it.
///
/// The returned port will refuse connections — useful for testing
/// connection-refused behavior without a long-running server.
///
/// # Errors
///
/// Returns [`std::io::Error`] if binding the TCP listener fails.
pub fn unlistening_port() -> std::io::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Returns a loopback URL for the given port.
#[must_use]
pub fn loopback_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/")
}

fn consume_request(stream: &mut TcpStream) {
    let mut buf = [0_u8; 4096];
    let mut accumulated = Vec::new();
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                accumulated.extend_from_slice(&buf[..n]);
                if accumulated.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
}

fn build_response(status_line: &str, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(status_line.as_bytes());
    let mut has_content_length = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
        response.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    if !has_content_length {
        response.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    response.extend_from_slice(b"Connection: close\r\n\r\n");
    response.extend_from_slice(body);
    response
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    }
}
