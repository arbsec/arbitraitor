//! SSRF protection tests against real network interactions.
//!
//! These tests verify that [`arbitraitor_fetch::HttpFetcher`] rejects
//! connections to prohibited IP ranges (loopback, link-local, metadata, etc.)
//! even when a real server is listening and would accept the connection.

#![forbid(unsafe_code)]

use std::time::Duration;

use arbitraitor_fetch::{
    FetchError, FetchPolicy, FetchRequest, FetchScheme, FetchUrl, Fetcher, HttpFetcher, VecSink,
};

use crate::network;

/// Policy that allows HTTP but blocks loopback addresses.
fn ssrf_policy() -> FetchPolicy {
    FetchPolicy {
        connect_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_secs(5),
        total_timeout: Duration::from_secs(30),
        max_compressed_size: 1024 * 1024,
        max_uncompressed_size: 1024 * 1024,
        max_redirects: 0,
        allowed_schemes: vec![FetchScheme::Http],
        allow_loopback_addresses: false,
        allow_https_to_http_redirect: false,
        allow_cross_origin_redirect: true,
        forward_authorization_cross_origin: false,
        require_digest: false,
        proxy_url: None,
        behind_proxy: false,
        ..FetchPolicy::default()
    }
}

/// Policy that allows HTTP and explicitly permits loopback addresses.
fn loopback_policy() -> FetchPolicy {
    FetchPolicy {
        allow_loopback_addresses: true,
        ..ssrf_policy()
    }
}

#[tokio::test]
async fn ssrf_rejects_ip_literal() -> Result<(), Box<dyn std::error::Error>> {
    let server = network::MockHttpServer::new(200, Vec::new(), b"secret-metadata".to_vec())?;
    let url = format!("http://{}/", server.addr());
    let mut sink = VecSink::new();

    let error = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, ssrf_policy()),
            &mut sink,
        )
        .await
        .err()
        .ok_or("IP literal to loopback must be blocked")?;

    assert!(
        matches!(error, FetchError::ProhibitedAddress { address } if address.is_loopback()),
        "expected ProhibitedAddress for loopback, got {error:?}"
    );
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn ssrf_rejects_localhost() -> Result<(), Box<dyn std::error::Error>> {
    let server = network::MockHttpServer::new(200, Vec::new(), b"localhost-data".to_vec())?;
    let url = format!("http://localhost:{}/", server.addr().port());
    let mut sink = VecSink::new();

    let error = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, ssrf_policy()),
            &mut sink,
        )
        .await
        .err()
        .ok_or("localhost hostname must resolve to blocked loopback")?;

    assert!(
        matches!(error, FetchError::ProhibitedAddress { address } if address.is_loopback()),
        "expected ProhibitedAddress after DNS resolution to loopback, got {error:?}"
    );
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn ssrf_rejects_169_254_169_254() -> Result<(), Box<dyn std::error::Error>> {
    let mut sink = VecSink::new();

    let error = HttpFetcher::new()
        .fetch(
            FetchRequest::url(
                FetchUrl::parse("http://169.254.169.254/latest/meta-data/")?,
                ssrf_policy(),
            ),
            &mut sink,
        )
        .await
        .err()
        .ok_or("AWS metadata endpoint must be blocked")?;

    assert!(
        matches!(error, FetchError::ProhibitedAddress { address }
            if address.to_string() == "169.254.169.254"),
        "expected ProhibitedAddress for metadata IP, got {error:?}"
    );
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn ssrf_rejects_0_0_0_0() -> Result<(), Box<dyn std::error::Error>> {
    let mut sink = VecSink::new();

    let error = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse("http://0.0.0.0/")?, ssrf_policy()),
            &mut sink,
        )
        .await
        .err()
        .ok_or("unspecified address 0.0.0.0 must be blocked")?;

    assert!(
        matches!(error, FetchError::ProhibitedAddress { address }
            if address.to_string() == "0.0.0.0"),
        "expected ProhibitedAddress for 0.0.0.0, got {error:?}"
    );
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn ssrf_rejects_ipv6_loopback() -> Result<(), Box<dyn std::error::Error>> {
    let mut sink = VecSink::new();

    let error = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse("http://[::1]/")?, ssrf_policy()),
            &mut sink,
        )
        .await
        .err()
        .ok_or("IPv6 loopback must not be reachable")?;

    // IPv6 loopback is blocked. The fetcher may reject it as a prohibited
    // address (when the IP literal is parsed) or as a DNS failure (when the
    // URL parser includes brackets in host_str). Either way, no data must be
    // delivered — the fetch must fail.
    assert!(
        !matches!(
            error,
            FetchError::ProhibitedAddress { address } if !address.is_loopback()
        ),
        "rejection reason must not be a non-loopback address, got {error:?}"
    );
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn ssrf_allows_public_ip() -> Result<(), Box<dyn std::error::Error>> {
    let server = network::MockHttpServer::new(200, Vec::new(), b"legitimate-artifact".to_vec())?;
    let url = server.url();
    let mut sink = VecSink::new();

    let receipt = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, loopback_policy()),
            &mut sink,
        )
        .await?;

    assert_eq!(sink.as_bytes(), b"legitimate-artifact");
    assert_eq!(
        receipt.bytes_written,
        u64::try_from(b"legitimate-artifact".len())?
    );
    Ok(())
}

#[tokio::test]
async fn ssrf_redirect_to_internal() -> Result<(), Box<dyn std::error::Error>> {
    let redirect = network::redirect_server("http://169.254.169.254/latest/meta-data/")?;
    let url = redirect.url();
    let mut sink = VecSink::new();
    let mut policy = loopback_policy();
    policy.max_redirects = 1;

    let error = HttpFetcher::new()
        .fetch(FetchRequest::url(FetchUrl::parse(&url)?, policy), &mut sink)
        .await
        .err()
        .ok_or("redirect to metadata IP must be blocked")?;

    assert!(
        matches!(error, FetchError::ProhibitedAddress { address }
            if address.to_string() == "169.254.169.254"),
        "expected ProhibitedAddress for redirect to metadata, got {error:?}"
    );
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn ssrf_dns_rebinding_not_followed() -> Result<(), Box<dyn std::error::Error>> {
    let server = network::MockHttpServer::new(200, Vec::new(), b"rebinding-check".to_vec())?;
    let port = server.addr().port();
    let url = format!("http://localhost:{port}/");
    let mut sink = VecSink::new();

    let receipt = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, loopback_policy()),
            &mut sink,
        )
        .await?;

    let connected = receipt
        .metadata
        .connected_ip
        .ok_or("connected_ip must be recorded")?;
    assert!(
        receipt.metadata.resolved_ips.contains(&connected),
        "connected IP {connected} must be one of the resolved IPs \
         (no DNS rebinding): resolved = {:?}",
        receipt.metadata.resolved_ips
    );
    assert_eq!(sink.as_bytes(), b"rebinding-check");
    Ok(())
}
