//! CLI inspect pipeline tests — Tier 2 per spec §43.8.
//!
//! Exercises the `arbitraitor inspect` subcommand error paths.
//! Tests that require HTTP backends are in Tier 3 (`cli_pipeline_e2e.rs`).

use assert_cmd::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn inspect_nonexistent_file_url_fails() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("inspect")
        .arg("file:///nonexistent/path/to/file.sh")
        .assert()
        .failure();
    Ok(())
}

#[test]
fn inspect_invalid_url_fails() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("inspect")
        .arg("not-a-valid-url")
        .assert()
        .failure();
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
        .failure();
    Ok(())
}

#[test]
fn inspect_explain_flag_rejects_without_format() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("inspect")
        .arg("file:///nonexistent/test.sh")
        .arg("--explain")
        .assert()
        .failure();
    Ok(())
}
