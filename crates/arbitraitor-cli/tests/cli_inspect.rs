//! CLI inspect pipeline tests — Tier 2.
//!
//! Tests that require HTTP backends are in Tier 3 (`cli_pipeline_e2e.rs`).

use assert_cmd::Command;
use predicates::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn inspect_nonexistent_file_url_fails_with_fetch_error() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("inspect")
        .arg("file:///nonexistent/path/to/file.sh")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("fetch")
                .or(predicate::str::contains("URL"))
                .or(predicate::str::contains("open"))
                .or(predicate::str::contains("file")),
        );
    Ok(())
}

#[test]
fn inspect_invalid_url_fails_with_parse_error() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("inspect")
        .arg("ftp://not-a-valid-scheme")
        .assert()
        .failure()
        .stderr(predicate::str::contains("scheme").or(predicate::str::contains("unsupported")));
    Ok(())
}

#[test]
fn inspect_with_sha256_flag_accepts_valid_hex() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("inspect")
        .arg("file:///nonexistent/test.sh")
        .arg("--sha256")
        .arg("0000000000000000000000000000000000000000000000000000000000000000")
        .assert()
        .failure();
    Ok(())
}

#[test]
fn inspect_with_sha256_flag_rejects_invalid_hex() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("inspect")
        .arg("file:///nonexistent/test.sh")
        .arg("--sha256")
        .arg("not-hex")
        .assert()
        .failure()
        .stderr(predicate::str::contains("sha").or(predicate::str::contains("hex")));
    Ok(())
}

#[test]
fn inspect_with_explain_flag_on_nonexistent_url_fails() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("inspect")
        .arg("file:///nonexistent/test.sh")
        .arg("--explain")
        .arg("--format")
        .arg("text")
        .assert()
        .failure();
    Ok(())
}

/// ADR-0038 decision 4 (migration parity): `inspect` routes through the
/// pipeline engine, so a receipt is persisted to the default receipts
/// directory even without `--receipt` — the former CLI composition only
/// wrote a receipt when the flag was passed.
#[test]
fn inspect_persists_receipt_by_default() -> TestResult {
    let home = tempfile::tempdir()?;
    let script = home.path().join("clean.sh");
    std::fs::write(&script, b"#!/bin/sh\necho clean\n")?;

    let output = Command::cargo_bin("arbitraitor")?
        .env("HOME", home.path())
        .env_remove("XDG_CACHE_HOME")
        .arg("inspect")
        .arg(script.to_str().unwrap_or("clean.sh"))
        .output()?;

    assert!(output.status.success(), "inspect must pass a clean script");
    let receipts_dir = home
        .path()
        .join(".cache")
        .join("arbitraitor")
        .join("receipts");
    let receipts: Vec<_> = std::fs::read_dir(&receipts_dir)?
        .filter_map(Result::ok)
        .collect();
    assert_eq!(
        receipts.len(),
        1,
        "exactly one receipt must be persisted for the inspected artifact"
    );
    Ok(())
}

/// ADR-0038 decision 4 (migration parity): `inspect` now honors configured
/// policy — the former CLI composition skipped policy evaluation entirely.
/// A block-everything policy file must drive the verdict (and exit code)
/// even for a clean script.
#[test]
fn inspect_honors_configured_policy() -> TestResult {
    let home = tempfile::tempdir()?;
    let script = home.path().join("clean.sh");
    std::fs::write(&script, b"#!/bin/sh\necho clean\n")?;
    let policy = home.path().join("block-all.toml");
    std::fs::write(&policy, "version = 1\n[defaults]\naction = \"block\"\n")?;
    let config = home.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[policy]\npolicy_file = {:?}\n",
            policy.to_str().unwrap_or("block-all.toml")
        ),
    )?;

    let output = Command::cargo_bin("arbitraitor")?
        .env("HOME", home.path())
        .env_remove("XDG_CACHE_HOME")
        .arg("--config")
        .arg(config.to_str().unwrap_or("config.toml"))
        .arg("inspect")
        .arg(script.to_str().unwrap_or("clean.sh"))
        .output()?;

    // `inspect` reports the verdict and exits zero on completion; the
    // policy's effect is the verdict itself, which previously stayed at
    // `Pass` because the CLI skipped policy evaluation entirely.
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("verdict: Block"),
        "the report must show the policy verdict, got: {stderr}"
    );
    Ok(())
}

/// `store.max_bytes` is enforced on `inspect` the same way it is on `scan`:
/// an artifact larger than the configured bound is refused, and the refusal
/// is the store's typed `SizeExceeded`, surfaced via the engine as
/// `store error: artifact size exceeded limit: attempted N bytes, maximum M
/// bytes`. The bound is plumbed through `Config::store_max_bytes` into the
/// engine's `sink_with_limits` callsite so the same byte holds across
/// fetch, inspect, `scan_path`, and child-artifact expansion.
#[test]
fn inspect_rejects_artifact_exceeding_store_max_bytes() -> TestResult {
    let home = tempfile::tempdir()?;
    let config = home.path().join("config.toml");
    std::fs::write(&config, "[store]\nmax_bytes = 1024\n")?;
    let script = home.path().join("oversized.sh");
    let mut body = b"#!/bin/sh\n".to_vec();
    body.extend(std::iter::repeat_n(b'a', 2 * 1024));
    std::fs::write(&script, body)?;

    let output = Command::cargo_bin("arbitraitor")?
        .env("HOME", home.path())
        .env_remove("XDG_CACHE_HOME")
        .arg("--config")
        .arg(config.to_str().unwrap_or("config.toml"))
        .arg("inspect")
        .arg(script.to_str().unwrap_or("oversized.sh"))
        .output()?;

    assert!(
        !output.status.success(),
        "inspect must fail when the artifact exceeds the configured store limit"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("artifact size exceeded limit"),
        "expected the SizeExceeded wording, got: {stderr}"
    );
    Ok(())
}

/// Default inspection is unaffected: with no `store.max_bytes` override,
/// the engine falls back to the store's 1 GiB bound and small scripts
/// inspect cleanly. Pairs with `inspect_rejects_artifact_exceeding_store_max_bytes`.
#[test]
fn inspect_uses_default_one_gib_store_limit_when_unset() -> TestResult {
    let home = tempfile::tempdir()?;
    let script = home.path().join("clean.sh");
    std::fs::write(&script, b"#!/bin/sh\necho clean\n")?;

    let output = Command::cargo_bin("arbitraitor")?
        .env("HOME", home.path())
        .env_remove("XDG_CACHE_HOME")
        .arg("inspect")
        .arg(script.to_str().unwrap_or("clean.sh"))
        .output()?;

    assert!(
        output.status.success(),
        "default inspect must succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
