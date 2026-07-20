//! HTTPS downgrade, TLS verification, and output capping tests.
//!
//! These tests verify scheme enforcement, TLS failure detection, certificate
//! fingerprint capture, response size limits, and read-timeout behavior using
//! real TCP connections to local mock servers.

#![forbid(unsafe_code)]

use std::time::Duration;

use arbitraitor_fetch::{
    FetchError, FetchPolicy, FetchRequest, FetchScheme, FetchUrl, Fetcher, HttpFetcher,
    SizeLimitKind, TlsVerifier, VecSink,
};

use crate::network;

/// Policy that permits HTTP on loopback for mock-server interaction.
fn http_loopback_policy() -> FetchPolicy {
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
    }
}

#[tokio::test]
async fn https_upgrade_rejects_plain_http() -> Result<(), Box<dyn std::error::Error>> {
    let server = network::MockHttpServer::new(200, Vec::new(), b"not-https".to_vec())?;
    let url = server.url();
    let mut sink = VecSink::new();

    let error = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, FetchPolicy::default()),
            &mut sink,
        )
        .await
        .err()
        .ok_or("plain HTTP must be rejected by default HTTPS-only policy")?;

    assert!(
        matches!(error, FetchError::InvalidScheme { ref scheme } if scheme == "http"),
        "expected InvalidScheme for http, got {error:?}"
    );
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn mixed_content_detected() -> Result<(), Box<dyn std::error::Error>> {
    let server = network::MockHttpServer::new(200, Vec::new(), b"mixed".to_vec())?;
    let url = server.url();
    let mut sink = VecSink::new();

    let https_only = FetchPolicy {
        tls_verifier: TlsVerifier::PlatformVerifier,
        allowed_schemes: vec![FetchScheme::Https],
        ..FetchPolicy::default()
    };

    let error = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, https_only),
            &mut sink,
        )
        .await
        .err()
        .ok_or("HTTP resource must be blocked by HTTPS-only policy")?;

    assert!(
        matches!(error, FetchError::InvalidScheme { ref scheme } if scheme == "http"),
        "expected InvalidScheme for mixed content, got {error:?}"
    );
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn invalid_cert_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let server = network::MockHttpServer::silent()?;
    let url = format!("https://{}/", server.addr());
    let mut sink = VecSink::new();

    let policy = FetchPolicy {
        tls_verifier: TlsVerifier::PlatformVerifier,
        allowed_schemes: vec![FetchScheme::Https],
        allow_loopback_addresses: true,
        connect_timeout: Duration::from_secs(3),
        read_timeout: Duration::from_secs(3),
        total_timeout: Duration::from_secs(8),
        ..FetchPolicy::default()
    };

    let error = HttpFetcher::new()
        .fetch(FetchRequest::url(FetchUrl::parse(&url)?, policy), &mut sink)
        .await
        .err()
        .ok_or("HTTPS to non-TLS server must fail")?;

    // The fetcher must not silently fall back to plaintext HTTP. The TLS
    // handshake fails because the server never sends ServerHello. The exact
    // error classification depends on timing and platform.
    assert!(
        !matches!(
            error,
            FetchError::ProhibitedAddress { .. } | FetchError::InvalidScheme { .. }
        ),
        "must not be an SSRF/scheme rejection, got {error:?}"
    );
    assert!(
        sink.as_bytes().is_empty(),
        "no bytes must be delivered on TLS failure"
    );
    Ok(())
}

#[tokio::test]
async fn cert_fingerprint_captured_for_pin_verification() -> Result<(), Box<dyn std::error::Error>>
{
    let server = network::MockHttpServer::new(200, Vec::new(), b"fingerprint-check".to_vec())?;
    let url = server.url();
    let mut sink = VecSink::new();

    let receipt = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, http_loopback_policy()),
            &mut sink,
        )
        .await?;

    // HTTP connections do not have a TLS certificate. HTTPS connections
    // populate this field with the SHA-256 of the peer's DER leaf certificate,
    // which callers can compare against a pinned fingerprint.
    assert!(
        receipt.metadata.peer_certificate_fingerprint.is_none(),
        "HTTP connections must not report a certificate fingerprint"
    );
    assert!(
        receipt.metadata.tls_version.is_none(),
        "HTTP connections must not report a TLS protocol version"
    );
    assert!(
        receipt.metadata.tls_cipher_suite.is_none(),
        "HTTP connections must not report a TLS cipher suite"
    );
    assert_eq!(sink.as_bytes(), b"fingerprint-check");
    Ok(())
}

#[tokio::test]
async fn large_response_capped() -> Result<(), Box<dyn std::error::Error>> {
    let cap = 4_096_u64;
    let server =
        network::MockHttpServer::new(200, Vec::new(), vec![b'x'; usize::try_from(cap * 2)?])?;
    let url = server.url();
    let mut sink = VecSink::new();
    let mut policy = http_loopback_policy();
    policy.max_compressed_size = cap;

    let error = HttpFetcher::new()
        .fetch(FetchRequest::url(FetchUrl::parse(&url)?, policy), &mut sink)
        .await
        .err()
        .ok_or("response exceeding size cap must be rejected")?;

    assert!(
        matches!(error, FetchError::SizeExceeded { kind, limit, .. }
            if kind == SizeLimitKind::Compressed && limit == cap),
        "expected SizeExceeded with cap {cap}, got {error:?}"
    );
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn streaming_timeout() -> Result<(), Box<dyn std::error::Error>> {
    let server = network::MockHttpServer::slow_stream(Duration::from_millis(100), 1, 2)?;
    let url = server.url();
    let mut sink = VecSink::new();
    let mut policy = http_loopback_policy();
    policy.read_timeout = Duration::from_millis(50);
    policy.total_timeout = Duration::from_secs(2);

    let error = HttpFetcher::new()
        .fetch(FetchRequest::url(FetchUrl::parse(&url)?, policy), &mut sink)
        .await
        .err()
        .ok_or("slow server must trigger read timeout")?;

    assert!(
        matches!(error, FetchError::Timeout { .. }),
        "expected Timeout from slow stream, got {error:?}"
    );
    Ok(())
}

#[tokio::test]
async fn truncated_response_detected() -> Result<(), Box<dyn std::error::Error>> {
    let server = network::MockHttpServer::truncated_response(1024, 16)?;
    let url = server.url();
    let mut sink = VecSink::new();

    let error = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, http_loopback_policy()),
            &mut sink,
        )
        .await
        .err()
        .ok_or("truncated response must produce an error")?;

    assert!(
        matches!(error, FetchError::TruncatedBody { .. })
            || error.to_string().contains("decoding response body"),
        "expected truncation error, got: {error}"
    );
    Ok(())
}

#[tokio::test]
async fn malformed_http_response_handled() -> Result<(), Box<dyn std::error::Error>> {
    let raw = b"NOT-HTTP/1.1 GARBAGE\r\n\r\n".to_vec();
    let server = network::MockHttpServer::raw_bytes(raw)?;
    let url = server.url();
    let mut sink = VecSink::new();

    let result = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, http_loopback_policy()),
            &mut sink,
        )
        .await;

    assert!(
        result.is_err(),
        "malformed HTTP response must produce an error, got: {result:?}"
    );
    Ok(())
}
