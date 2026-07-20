//! Integration tests for the programmatic library API.
//!
//! These tests use a local `TcpListener` mock HTTP server to avoid real network
//! requests. The fetch policy is configured to allow loopback addresses.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use arbitraitor_daemon::api::{ApiError, Arbitraitor, ArbitraitorApi, Config};
use arbitraitor_fetch::{FetchPolicy, FetchScheme};
use arbitraitor_policy::PolicyEngine;
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
        emit_partial_receipt_on_cancel: false,
    }
}

fn pass_policy_config(label: &str) -> Config {
    let policy_toml = "\
version = 1\n\
[network]\n\
require_https = false\n\
block_private_networks = false\n\
[defaults]\n\
action = \"pass\"\n";
    Config {
        policy_toml: policy_toml.to_owned(),
        ..test_config(&unique_dir(label))
    }
}

fn block_policy_config(label: &str) -> Config {
    let policy_toml = "\
version = 1\n\
[network]\n\
require_https = false\n\
block_private_networks = false\n\
[defaults]\n\
action = \"block\"\n";
    Config {
        policy_toml: policy_toml.to_owned(),
        ..test_config(&unique_dir(label))
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
async fn builder_config_matches_new_constructor() -> Result<(), Box<dyn std::error::Error>> {
    // Given: equivalent configurations for the legacy constructor and builder.
    let direct_root = unique_dir("builder-direct");
    let builder_root = unique_dir("builder-fluent");
    let direct_api = ArbitraitorApi::new(test_config(&direct_root))?;
    let builder_api = Arbitraitor::builder()
        .config(test_config(&builder_root))
        .build()?;
    let direct_url = mock_http_server(b"builder-equivalence", "text/plain").await;
    let builder_url = mock_http_server(b"builder-equivalence", "text/plain").await;

    // When: both APIs fetch the same artifact.
    let direct_result = direct_api.fetch(&direct_url).await?;
    let builder_result = builder_api.fetch(&builder_url).await?;

    // Then: construction paths expose equivalent behavior and configured stores.
    assert_eq!(builder_result.sha256, direct_result.sha256);
    assert_eq!(builder_result.size_bytes, direct_result.size_bytes);
    assert_eq!(builder_api.list_artifacts()?.len(), 1);
    assert_eq!(direct_api.list_artifacts()?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn builder_policy_overrides_config_policy() -> Result<(), Box<dyn std::error::Error>> {
    use arbitraitor_model::verdict::Verdict;

    // Given: invalid policy TOML in Config and an explicitly compiled block policy.
    let root = unique_dir("builder-policy");
    let mut config = test_config(&root);
    config.policy_toml = "not valid policy TOML".to_owned();
    let compiled_config = block_policy_config("builder-compiled-policy");
    let policy = PolicyEngine::load(&compiled_config.policy_toml)?;

    // When: the explicit policy is supplied through the fluent builder.
    let api = Arbitraitor::builder()
        .config(config)
        .policy(policy)
        .build()?;
    let url = mock_http_server(b"builder policy", "text/plain").await;
    let result = api.inspect(&url).await?;

    // Then: the explicit policy takes precedence over Config::policy_toml.
    assert_eq!(result.verdict, Verdict::Block);
    Ok(())
}

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
async fn release_without_inspection_receipt_is_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let root = unique_dir("release-no-receipt");
    let api = ArbitraitorApi::new(test_config(&root))?;
    let payload = b"never-inspected-payload";
    let url = mock_http_server(payload, "application/octet-stream").await;

    // Fetch stores the artifact but never analyzes it — no receipt exists.
    let fetched = api.fetch(&url).await?;
    let dest = root.join("should-not-exist.bin");
    let result = api.release(&fetched.sha256, &dest);

    assert!(
        matches!(result, Err(ApiError::NoReceipt(_))),
        "release without inspection receipt must be rejected, got {result:?}"
    );
    assert!(
        !dest.exists(),
        "destination must not be written on rejection"
    );
    Ok(())
}

#[tokio::test]
async fn release_after_block_verdict_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    use arbitraitor_model::verdict::Verdict;
    let root = unique_dir("release-blocked-root");
    let config = block_policy_config("release-blocked");
    let api = ArbitraitorApi::new(config)?;
    let url = mock_http_server(b"blocked-content", "text/plain").await;

    let inspected = api.inspect(&url).await?;
    assert_eq!(inspected.verdict, Verdict::Block);

    let dest = root.join("blocked-release.bin");
    let result = api.release(&inspected.sha256, &dest);

    assert!(
        matches!(result, Err(ApiError::PolicyBlocked(Verdict::Block))),
        "release after Block verdict must be rejected, got {result:?}"
    );
    assert!(!dest.exists());
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn release_after_inspection_uses_safe_primitive() -> Result<(), Box<dyn std::error::Error>> {
    let config = pass_policy_config("release-safe");
    let api = ArbitraitorApi::new(config)?;
    let payload = b"safe-release-payload";
    let url = mock_http_server(payload, "text/plain").await;

    let inspected = api.inspect(&url).await?;
    let dest = unique_dir("release-safe-dest").join("released.bin");
    let result = api.release(&inspected.sha256, &dest)?;

    assert_eq!(result.path, dest);
    assert!(result.sha256_verified);
    assert_eq!(result.bytes_written, u64::try_from(payload.len())?);
    let written = std::fs::read(&dest)?;
    assert_eq!(written.as_slice(), payload);
    assert_eq!(expected_sha256(&written), inspected.sha256);

    // ADR-0015: released files must have restrictive permissions (0600 on POSIX).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dest)?.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "released file must have 0600 permissions, got {mode:o}"
        );
    }
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn release_rejects_symlink_destination() -> Result<(), Box<dyn std::error::Error>> {
    let root = unique_dir("release-symlink-root");
    let config = pass_policy_config("release-symlink");
    let api = ArbitraitorApi::new(config)?;
    let payload = b"symlink-reject-payload";
    let url = mock_http_server(payload, "text/plain").await;

    let inspected = api.inspect(&url).await?;

    // ADR-0015: the safe-release primitive must reject symlink destinations.
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("nonexistent-target"), root.join("link-dest"))?;

    let dest = root.join("link-dest");
    let result = api.release(&inspected.sha256, &dest);

    assert!(
        result.is_err(),
        "release to a symlink destination must be rejected"
    );
    assert!(!root.join("nonexistent-target").exists());
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
