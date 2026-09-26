//! Integration tests for the pipeline engine's programmatic API.
//!
//! These tests use a local `TcpListener` mock HTTP server to avoid real network
//! requests. The fetch policy is configured to allow loopback addresses.
//!
//! Moved from `crates/arbitraitor-daemon/tests/api.rs` when the API moved to
//! the engine (ADR-0038); the assertions are preserved, with `ApiError`
//! renamed to the engine's `EngineError`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use arbitraitor_engine::{Arbitraitor, ArbitraitorApi, Config, EngineError};
use arbitraitor_fetch::{FetchPolicy, FetchScheme, TlsVerifier};
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
            tls_verifier: TlsVerifier::PlatformVerifier,
            allowed_schemes: vec![FetchScheme::Http],
            allow_loopback_addresses: true,
            ..FetchPolicy::default()
        },
        store_max_bytes: arbitraitor_store::DEFAULT_MAX_BYTES,
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
        matches!(result, Err(EngineError::NoReceipt(_))),
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
        matches!(result, Err(EngineError::PolicyBlocked(Verdict::Block))),
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

    assert!(matches!(result, Err(EngineError::NotFound(_))));
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

// ---------------------------------------------------------------------------
// ADR-0038 decision tests
// ---------------------------------------------------------------------------

/// ADR-0038 decision 1 + staged rollout stage 2: the engine owns provenance
/// verification. The former `ArbitraitorApi` (daemon composition) never
/// verified signatures; every consumer routed through the engine now gets
/// the provenance stage. This is the migration-parity fixture for the
/// daemon path: a signature configured on the builder is verified during
/// `inspect` and recorded in the result and the receipt.
#[tokio::test]
async fn inspect_with_minisign_signature_records_provenance()
-> Result<(), Box<dyn std::error::Error>> {
    let key = minisign::KeyPair::generate_unencrypted_keypair()?;
    let root = unique_dir("provenance");
    let payload = b"#!/bin/sh\necho provenance\n";
    let signature_path = root.join("artifact.minisig");
    let signature = minisign::sign(
        Some(&key.pk),
        &key.sk,
        std::io::Cursor::new(payload),
        Some("arbitraitor engine test"),
        Some("engine test signer"),
    )?;
    std::fs::write(&signature_path, signature.to_bytes())?;

    let api = Arbitraitor::builder()
        .config(test_config(&root))
        .signatures(arbitraitor_engine::SignatureInputs {
            minisign: vec![arbitraitor_engine::MinisignSignatureInput {
                signature_path,
                public_key: key.pk.to_box()?.to_string(),
            }],
            cosign: Vec::new(),
        })
        .build()?;
    let url = mock_http_server(payload, "text/x-shellscript").await;

    let result = api.inspect(&url).await?;

    assert_eq!(
        result.signature_verifications.len(),
        1,
        "the provenance stage must run on the engine path"
    );
    let verification = &result.signature_verifications[0];
    assert_eq!(verification.system, "minisign");
    assert!(verification.verified);
    assert!(verification.identity.is_some());
    let receipt_json = result.receipt.to_vec_pretty()?;
    let receipt: serde_json::Value = serde_json::from_slice(&receipt_json)?;
    let findings = receipt["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("findings"));
    assert!(
        findings.iter().any(|f| f["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("provenance.signature.minisign"))),
        "the receipt must record the signature verification as a finding"
    );
    Ok(())
}

/// ADR-0038 decision 1: a pinned digest that does not match the fetched
/// bytes fails the retrieval (immutable identity, invariant 2).
#[tokio::test]
async fn inspect_pinned_rejects_digest_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let root = unique_dir("pinned-mismatch");
    let api = ArbitraitorApi::new(test_config(&root))?;
    let url = mock_http_server(b"pinned payload", "text/plain").await;
    let wrong = "0".repeat(64).parse()?;

    let result = api.inspect_pinned(&url, Some(wrong)).await;

    assert!(result.is_err(), "digest mismatch must fail the inspection");
    Ok(())
}

/// ADR-0038 decision 5: the exported fail-closed policy constant is valid
/// policy TOML and blocks unmatched artifacts in the engine's
/// non-interactive evaluation context (the daemon socket behavior).
#[tokio::test]
async fn fail_closed_policy_blocks_unmatched_artifacts() -> Result<(), Box<dyn std::error::Error>> {
    use arbitraitor_model::verdict::Verdict;
    let root = unique_dir("fail-closed");
    let config = arbitraitor_engine::Config {
        policy_toml: arbitraitor_engine::FAIL_CLOSED_POLICY_TOML.to_owned(),
        ..test_config(&root)
    };
    let api = ArbitraitorApi::new(config)?;
    let url = mock_http_server(b"clean content", "text/plain").await;

    let result = api.inspect(&url).await?;

    assert_eq!(result.verdict, Verdict::Block);
    Ok(())
}

/// ADR-0038 decision 6 + receipt unification: `query_receipts` reads the
/// engine's canonical `unix:<secs>...` timestamps (the former daemon
/// composition wrote bare epoch seconds and parsed its own format back as
/// zero).
#[tokio::test]
async fn query_receipts_parses_engine_timestamps() -> Result<(), Box<dyn std::error::Error>> {
    let root = unique_dir("query-timestamps");
    let api = ArbitraitorApi::new(test_config(&root))?;
    let url = mock_http_server(b"timestamped", "text/plain").await;
    let result = api.inspect(&url).await?;

    let summaries = api.query_receipts(arbitraitor_engine::ReceiptFilter::default())?;

    let summary = summaries
        .iter()
        .find(|s| s.sha256 == result.sha256)
        .unwrap_or_else(|| panic!("receipt summary for inspect must exist"));
    assert!(
        summary.created_at > 0,
        "engine timestamps must parse back to nonzero epoch seconds"
    );
    Ok(())
}

/// Engine `scan_path` preserves the MCP tool's bounded-read contract:
/// symlinks are rejected and the size bound is enforced.
#[test]
fn scan_path_rejects_symlinks_and_enforces_size_bound() -> Result<(), Box<dyn std::error::Error>> {
    let root = unique_dir("scan-path");
    let api = ArbitraitorApi::new(test_config(&root))?;
    let target = root.join("target.sh");
    std::fs::write(&target, b"#!/bin/sh\necho target\n")?;
    let link = root.join("link.sh");
    std::os::unix::fs::symlink(&target, &link)?;

    let symlink_result = api.scan_path(&link, arbitraitor_engine::DEFAULT_SCAN_MAX_BYTES);
    assert!(symlink_result.is_err(), "symlink must be rejected");

    let oversized = root.join("oversized.sh");
    std::fs::write(&oversized, b"0123456789")?;
    let bounded = api.scan_path(&oversized, 3);
    assert!(bounded.is_err(), "size bound must be enforced");

    let ok = api.scan_path(&target, arbitraitor_engine::DEFAULT_SCAN_MAX_BYTES)?;
    assert_eq!(ok.verdict, arbitraitor_model::verdict::Verdict::Pass);
    Ok(())
}
