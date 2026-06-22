//! Integration tests for the programmatic library API.
//!
//! These tests use a local `TcpListener` mock HTTP server to avoid real network
//! requests. The fetch policy is configured to allow loopback addresses.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use arbitraitor_daemon::api::{ApiError, ArbitraitorApi, Config};
use arbitraitor_fetch::{FetchPolicy, FetchScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn unique_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "arb-api-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn test_config(root: &std::path::Path) -> Config {
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

/// Spawns a mock HTTP server that responds with `body` and the given content type.
async fn mock_http_server(body: &'static [u8], content_type: &'static str) -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 1024];
        let _ = stream.read(&mut buf).await;
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: {content_type}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
    });
    format!("http://127.0.0.1:{port}/artifact")
}

fn expected_sha256(data: &[u8]) -> String {
    use std::fmt::Write;
    let digest = Sha256::digest(data);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(hex, "{byte:02x}").unwrap();
    }
    hex
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn inspect_fetches_and_analyzes() -> Result<(), Box<dyn std::error::Error>> {
    let root = unique_dir("inspect");
    let api = ArbitraitorApi::new(test_config(&root))?;
    let url = mock_http_server(b"plain text", "text/plain").await;

    let result = api.inspect(&url).await?;

    assert_eq!(result.sha256, expected_sha256(b"plain text"));
    assert_eq!(result.size_bytes, u64::try_from(b"plain text".len())?);
    assert_eq!(result.content_type.as_deref(), Some("text/plain"));
    assert!(result.receipt_path.is_some());
    Ok(())
}

#[tokio::test]
async fn fetch_stores_in_cas() -> Result<(), Box<dyn std::error::Error>> {
    let root = unique_dir("fetch");
    let api = ArbitraitorApi::new(test_config(&root))?;
    let url = mock_http_server(b"hello world", "text/plain").await;

    let result = api.fetch(&url).await?;

    assert_eq!(result.sha256, expected_sha256(b"hello world"));
    assert_eq!(result.size_bytes, u64::try_from(b"hello world".len())?);
    let artifacts = api.list_artifacts()?;
    assert!(artifacts.iter().any(|a| a.sha256 == result.sha256));
    Ok(())
}

#[tokio::test]
async fn scan_existing_artifact() -> Result<(), Box<dyn std::error::Error>> {
    let root = unique_dir("scan");
    let api = ArbitraitorApi::new(test_config(&root))?;
    let url = mock_http_server(b"#!/bin/sh\necho hi", "text/x-shellscript").await;

    let fetched = api.fetch(&url).await?;
    let scanned = api.scan(&fetched.sha256)?;

    assert_eq!(scanned.sha256, fetched.sha256);
    assert_eq!(scanned.size_bytes, fetched.size_bytes);
    Ok(())
}

#[tokio::test]
async fn release_writes_verified_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let root = unique_dir("release");
    let api = ArbitraitorApi::new(test_config(&root))?;
    let payload = b"release-me-payload";
    let url = mock_http_server(payload, "application/octet-stream").await;

    let fetched = api.fetch(&url).await?;
    let dest = root.join("released.bin");
    let result = api.release(&fetched.sha256, &dest)?;

    assert_eq!(result.path, dest);
    assert!(result.sha256_verified);
    let written = std::fs::read(&dest)?;
    assert_eq!(written.as_slice(), payload);
    assert_eq!(expected_sha256(&written), fetched.sha256);
    Ok(())
}

#[tokio::test]
async fn list_artifacts_returns_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let root = unique_dir("list");
    let api = ArbitraitorApi::new(test_config(&root))?;

    assert!(api.list_artifacts()?.is_empty());

    let url = mock_http_server(b"artifact-one", "text/plain").await;
    let result = api.fetch(&url).await?;

    let artifacts = api.list_artifacts()?;
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].sha256, result.sha256);
    assert_eq!(artifacts[0].size_bytes, result.size_bytes);
    Ok(())
}

#[tokio::test]
async fn api_error_on_missing_artifact() {
    let root = unique_dir("missing");
    let api = ArbitraitorApi::new(test_config(&root)).unwrap();

    let fake = "0".repeat(64);
    let result = api.scan(&fake);

    assert!(matches!(result, Err(ApiError::NotFound(_))));
}

#[tokio::test]
async fn config_with_policy() -> Result<(), Box<dyn std::error::Error>> {
    use arbitraitor_model::verdict::Verdict;
    let root = unique_dir("policy");
    let policy_toml = "\
version = 1\n\
[defaults]\n\
action = \"block\"\n";
    let config = Config {
        policy_toml: policy_toml.to_owned(),
        ..test_config(&root)
    };
    let api = ArbitraitorApi::new(config)?;

    let url = mock_http_server(b"any content", "text/plain").await;
    let result = api.inspect(&url).await?;

    assert_eq!(result.verdict, Verdict::Block);
    Ok(())
}
