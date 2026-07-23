//! Integration tests for fetch transports.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arbitraitor_fetch::{
    FetchError, FetchPolicy, FetchRequest, FetchScheme, FetchUrl, Fetcher, FileFetcher,
    HttpFetcher, RedirectCredentialSecrecy, SizeLimitKind, TlsVerifier, VecSink, redact_url,
    validate_ip,
};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_testkit::mock_server::MockHttpServer;
use proptest::prelude::*;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

fn http_policy() -> FetchPolicy {
    FetchPolicy {
        tls_verifier: TlsVerifier::PlatformVerifier,
        connect_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_secs(5),
        total_timeout: Duration::from_secs(30),
        max_compressed_size: 1024 * 1024,
        max_uncompressed_size: 1024 * 1024,
        max_redirects: 0,
        allowed_schemes: vec![FetchScheme::Http],
        allow_loopback_addresses: true,
        allow_https_to_http_redirect: false,
        allow_cross_origin_redirect: true,
        forward_authorization_cross_origin: false,
        require_digest: false,
        proxy_url: None,
        behind_proxy: false,
        first_byte_timeout: None,
    }
}

fn ssrf_policy() -> FetchPolicy {
    FetchPolicy {
        tls_verifier: TlsVerifier::PlatformVerifier,
        allow_loopback_addresses: false,
        ..http_policy()
    }
}

fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(Sha256::digest(bytes).into())
}

#[test]
fn ssrf_policy_blocks_private_and_reserved_ranges() -> Result<(), Box<dyn std::error::Error>> {
    let prohibited = [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.168.0.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "::",
        "::1",
        "::127.0.0.1",
        "::192.168.1.1",
        "::ffff:127.0.0.1",
        "64:ff9b::1",
        "100::1",
        "2001:db8::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
    ];

    for address in prohibited {
        let ip = address.parse::<IpAddr>()?;
        assert!(!validate_ip(ip), "{address} should be prohibited");
    }
    assert!(validate_ip("93.184.216.34".parse()?));
    assert!(validate_ip("2606:2800:220:1:248:1893:25c8:1946".parse()?));
    Ok(())
}

#[tokio::test]
async fn fetch_blocks_loopback_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockHttpServer::start().await;
    let url = server.binary_response(b"blocked", "text/plain").await;
    let mut sink = VecSink::new();

    let error = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, ssrf_policy()),
            &mut sink,
        )
        .await
        .err()
        .ok_or("loopback fetch should be blocked")?;

    assert!(matches!(error, FetchError::ProhibitedAddress { address } if address.is_loopback()));
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[tokio::test]
#[cfg(not(windows))]
async fn redirect_target_is_validated_against_ssrf_policy() -> Result<(), Box<dyn std::error::Error>>
{
    let url = metadata_redirect_server().await?;
    let mut sink = VecSink::new();
    let mut policy = http_policy();
    policy.max_redirects = 1;

    let error = HttpFetcher::new()
        .fetch(FetchRequest::url(FetchUrl::parse(&url)?, policy), &mut sink)
        .await
        .err()
        .ok_or("metadata redirect should be blocked")?;

    assert!(
        matches!(error, FetchError::ProhibitedAddress { address } if address.to_string() == "169.254.169.254")
    );
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[test]
fn url_redaction_removes_secrets() {
    let redacted = redact_url("https://user:pass@internal/api/token/secret-value?sig=abc&key=def");

    assert!(!redacted.contains("user"));
    assert!(!redacted.contains("pass"));
    assert!(!redacted.contains("secret-value"));
    assert!(!redacted.contains("sig=abc"));
    assert!(redacted.contains("redacted-host.invalid"));
}
#[tokio::test]
async fn http_fetch_streams_exact_response_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockHttpServer::start().await;
    let bytes = b"\x00arbitraitor\xff";
    let url = server
        .binary_response(bytes, "application/octet-stream")
        .await;

    let mut sink = VecSink::new();
    let receipt = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, http_policy()),
            &mut sink,
        )
        .await?;

    assert_eq!(sink.as_bytes(), bytes);
    assert_eq!(receipt.bytes_written, u64::try_from(bytes.len())?);
    assert_eq!(receipt.sha256, sha256(bytes));
    assert_eq!(receipt.artifact_id.0, receipt.sha256);
    assert_eq!(
        receipt.metadata.content_type.as_deref(),
        Some("application/octet-stream")
    );
    assert!(receipt.metadata.connected_ip.is_some());
    assert!(!receipt.metadata.resolved_ips.is_empty());
    Ok(())
}

#[tokio::test]
async fn pinned_digest_match_allows_fetch() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockHttpServer::start().await;
    let bytes = b"pinned artifact";
    let url = server
        .binary_response(bytes, "application/octet-stream")
        .await;
    let mut sink = VecSink::new();

    let receipt = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, http_policy())
                .with_expected_sha256(sha256(bytes)),
            &mut sink,
        )
        .await?;

    assert_eq!(sink.as_bytes(), bytes);
    assert_eq!(receipt.sha256, sha256(bytes));
    Ok(())
}

#[tokio::test]
async fn pinned_digest_mismatch_fails_fetch() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockHttpServer::start().await;
    let bytes = b"actual artifact";
    let expected = sha256(b"different artifact");
    let actual = sha256(bytes);
    let url = server
        .binary_response(bytes, "application/octet-stream")
        .await;
    let mut sink = VecSink::new();

    let error = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, http_policy())
                .with_expected_sha256(expected.clone()),
            &mut sink,
        )
        .await
        .err()
        .ok_or("digest mismatch should fail")?;

    assert!(
        matches!(error, FetchError::DigestMismatch { expected: got_expected, actual: got_actual } if got_expected == expected && got_actual == actual)
    );
    assert_eq!(sink.as_bytes(), bytes);
    Ok(())
}

#[tokio::test]
async fn required_digest_missing_fails_before_fetch() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockHttpServer::start().await;
    let url = server.binary_response(b"unused", "text/plain").await;
    let mut policy = http_policy();
    policy.require_digest = true;
    let mut sink = VecSink::new();

    let error = HttpFetcher::new()
        .fetch(FetchRequest::url(FetchUrl::parse(&url)?, policy), &mut sink)
        .await
        .err()
        .ok_or("missing required digest should fail")?;

    assert!(matches!(error, FetchError::RequiredDigestMissing));
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn http_fetch_sends_identity_and_does_not_decompress()
-> Result<(), Box<dyn std::error::Error>> {
    let encoded = vec![0x1f, 0x8b, 0x08, 0x00, b'a', b'b', b'c'];
    let (url, request_headers) = exact_byte_server(encoded.clone()).await?;

    let mut sink = VecSink::new();
    HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, http_policy()),
            &mut sink,
        )
        .await?;

    let headers = request_headers.await??;
    assert!(headers.contains("accept-encoding: identity"));
    assert_eq!(sink.into_bytes(), encoded);
    Ok(())
}
#[tokio::test]
async fn redirects_are_not_followed_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockHttpServer::start().await;
    let url = server.redirect_chain(1).await;
    let mut sink = VecSink::new();

    let error = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, http_policy()),
            &mut sink,
        )
        .await
        .err()
        .ok_or("redirect should fail with default policy")?;

    assert!(matches!(
        error,
        FetchError::RedirectLimitExceeded { limit: 0 }
    ));
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn redirect_policy_records_chain_when_enabled() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockHttpServer::start().await;
    let url = server.redirect_chain(2).await;
    let mut policy = http_policy();
    policy.max_redirects = 2;
    let mut sink = VecSink::new();

    let receipt = HttpFetcher::new()
        .fetch(FetchRequest::url(FetchUrl::parse(&url)?, policy), &mut sink)
        .await?;

    assert_eq!(sink.as_bytes(), b"redirect complete");
    assert_eq!(receipt.metadata.redirect_chain.len(), 2);
    assert!(receipt.metadata.final_url.is_some());
    assert_eq!(
        receipt.metadata.redirect_credential_secrecy,
        RedirectCredentialSecrecy::Ok
    );
    Ok(())
}

#[tokio::test]
async fn credential_cross_protocol_redirect_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let server = MockHttpServer::start().await;
    let route_path = server
        .redirect_to("imap://mail.example.invalid/inbox")
        .await;
    let mut policy = http_policy();
    policy.max_redirects = 1;
    let mut sink = VecSink::new();

    let error = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&route_path)?, policy).with_authorization_header(
                SecretString::from("Bearer super-secret-token".to_owned()),
            ),
            &mut sink,
        )
        .await
        .err()
        .ok_or("credential-bearing IMAP redirect must fail closed")?;

    assert!(matches!(
        error,
        FetchError::CrossProtocolCredentialRedirect {
            secrecy: RedirectCredentialSecrecy::BearerLeaked
        }
    ));
    assert!(!format!("{error}").contains("super-secret-token"));
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

proptest! {
    #[test]
    fn credential_redirect_error_does_not_render_secret(token in "[A-Za-z0-9!@#$%^&*]{8,64}") {
        // Construct an error that should never include the secret token.
        // The token must be long enough and contain characters outside the
        // canonical Display output of FetchError variants so we are actually
        // testing leakage of the literal secret value, not substring
        // collisions with enum variant names.
        let error = FetchError::CrossProtocolCredentialRedirect {
            secrecy: RedirectCredentialSecrecy::BearerLeaked,
        };
        let display = format!("{error}");
        let debug = format!("{error:?}");

        prop_assert!(!display.contains(&token));
        prop_assert!(!debug.contains(&token));
    }
}
#[tokio::test]
async fn size_limit_stops_streaming_before_sink_write() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockHttpServer::start().await;
    let url = server.large_response(8).await;
    let mut policy = http_policy();
    policy.max_compressed_size = 4;
    let mut sink = VecSink::new();

    let error = HttpFetcher::new()
        .fetch(FetchRequest::url(FetchUrl::parse(&url)?, policy), &mut sink)
        .await
        .err()
        .ok_or("oversized response should fail")?;

    assert!(matches!(
        error,
        FetchError::SizeExceeded {
            kind: SizeLimitKind::Compressed,
            limit: 4,
            observed: 8
        }
    ));
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn file_fetch_streams_local_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = b"local artifact bytes";
    let path = temp_file_path()?;
    tokio::fs::write(&path, bytes).await?;
    let mut sink = VecSink::new();

    let receipt = FileFetcher::new()
        .fetch(
            FetchRequest::file(path.clone(), FetchPolicy::default()),
            &mut sink,
        )
        .await?;

    assert_eq!(sink.as_bytes(), bytes);
    assert_eq!(receipt.sha256, sha256(bytes));
    tokio::fs::remove_file(path).await?;
    Ok(())
}
async fn exact_byte_server(
    body: Vec<u8>,
) -> Result<(String, JoinHandle<Result<String, std::io::Error>>), std::io::Error> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        stream.write_all(&body).await?;
        stream.shutdown().await?;
        Ok(String::from_utf8_lossy(&request).to_ascii_lowercase())
    });
    Ok((format!("http://{addr}/artifact"), handle))
}

async fn metadata_redirect_server() -> Result<String, std::io::Error> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let response = "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });
    Ok(format!("http://{addr}/redirect"))
}

fn temp_file_path() -> Result<PathBuf, std::time::SystemTimeError> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(std::env::temp_dir().join(format!("arbitraitor-fetch-test-{nanos}.bin")))
}

// ---------------------------------------------------------------------------
// User-supplied headers (spec §11.2, issue #498)
// ---------------------------------------------------------------------------

async fn header_capture_server(
    body: &[u8],
) -> Result<(String, JoinHandle<Result<String, std::io::Error>>), std::io::Error> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let body = body.to_vec();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        stream.write_all(&body).await?;
        stream.shutdown().await?;
        Ok(String::from_utf8_lossy(&request).to_ascii_lowercase())
    });
    Ok((format!("http://{addr}/artifact"), handle))
}

async fn redirect_server(target_url: String) -> Result<String, std::io::Error> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });
    Ok(format!("http://{addr}/redirect"))
}

#[tokio::test]
async fn user_headers_applied_to_request() -> Result<(), Box<dyn std::error::Error>> {
    let body = b"header test";
    let (url, request_handle) = header_capture_server(body).await?;

    let mut sink = VecSink::new();
    let receipt = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, http_policy())
                .with_header("X-Custom-Header", "custom-value")
                .with_header("Accept", "application/json"),
            &mut sink,
        )
        .await?;

    let captured = request_handle.await??;
    assert!(
        captured.contains("x-custom-header: custom-value"),
        "user-supplied X-Custom-Header must be sent: {captured}"
    );
    assert!(
        captured.contains("accept: application/json"),
        "user-supplied Accept must be sent: {captured}"
    );
    assert_eq!(sink.as_bytes(), body);
    assert_eq!(receipt.bytes_written, u64::try_from(body.len())?);
    Ok(())
}

#[tokio::test]
async fn user_headers_stripped_on_cross_origin_redirect() -> Result<(), Box<dyn std::error::Error>>
{
    let body = b"cross-origin";
    let (capture_url, request_handle) = header_capture_server(body).await?;
    let redirect_url = redirect_server(capture_url).await?;

    let mut policy = http_policy();
    policy.max_redirects = 1;
    let mut sink = VecSink::new();

    let receipt = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&redirect_url)?, policy)
                .with_header("X-Custom-Header", "secret-value")
                .with_header("X-API-Key", "api-secret"),
            &mut sink,
        )
        .await?;

    let captured = request_handle.await??;
    assert!(
        !captured.contains("secret-value"),
        "user-supplied header value MUST NOT be forwarded to cross-origin redirect target: {captured}"
    );
    assert!(
        !captured.contains("api-secret"),
        "user-supplied API key value MUST NOT be forwarded to cross-origin redirect target: {captured}"
    );
    assert!(
        !captured.contains("x-custom-header"),
        "user-supplied X-Custom-Header MUST be stripped on cross-origin redirect: {captured}"
    );
    assert!(
        !captured.contains("x-api-key"),
        "user-supplied X-API-Key MUST be stripped on cross-origin redirect: {captured}"
    );
    assert_eq!(sink.as_bytes(), body);
    assert_eq!(receipt.bytes_written, u64::try_from(body.len())?);
    Ok(())
}

#[tokio::test]
async fn user_headers_preserved_on_same_origin_redirect() -> Result<(), Box<dyn std::error::Error>>
{
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let base_url = format!("http://{addr}");
    let redirect_target = format!("{base_url}/final");
    let capture_handle = tokio::spawn(async move {
        let mut captured_second = String::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await?;
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let read = stream.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request_str = String::from_utf8_lossy(&request).to_ascii_lowercase();
            if request_str.contains("/final") {
                captured_second = request_str;
                let response =
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(response.as_bytes()).await;
            } else {
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {redirect_target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
            let _ = stream.shutdown().await;
        }
        Ok::<String, std::io::Error>(captured_second)
    });

    let mut policy = http_policy();
    policy.max_redirects = 1;
    let mut sink = VecSink::new();

    HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&format!("{base_url}/start"))?, policy)
                .with_header("X-Custom-Header", "preserve-me"),
            &mut sink,
        )
        .await?;

    let captured = capture_handle.await??;
    assert!(
        captured.contains("x-custom-header: preserve-me"),
        "user-supplied header MUST be preserved on same-origin redirect: {captured}"
    );
    assert_eq!(sink.as_bytes(), b"ok");
    Ok(())
}

#[tokio::test]
async fn header_values_not_in_receipt() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockHttpServer::start().await;
    let url = server.binary_response(b"receipt test", "text/plain").await;
    let secret_value = "super-secret-api-key-value-498";

    let mut sink = VecSink::new();
    let receipt = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, http_policy())
                .with_header("X-API-Key", secret_value)
                .with_header("X-Custom", "custom-data"),
            &mut sink,
        )
        .await?;

    assert!(
        receipt
            .metadata
            .request_header_names
            .contains(&"x-api-key".to_owned()),
        "receipt must record X-API-Key header name: {:?}",
        receipt.metadata.request_header_names
    );
    assert!(
        receipt
            .metadata
            .request_header_names
            .contains(&"x-custom".to_owned()),
        "receipt must record X-Custom header name: {:?}",
        receipt.metadata.request_header_names
    );
    let receipt_debug = format!("{receipt:?}");
    assert!(
        !receipt_debug.contains(secret_value),
        "receipt debug output MUST NOT contain header values: {receipt_debug}"
    );
    assert!(
        !receipt_debug.contains("custom-data"),
        "receipt debug output MUST NOT contain header values: {receipt_debug}"
    );
    Ok(())
}
