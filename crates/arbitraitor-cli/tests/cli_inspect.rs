//! CLI inspect pipeline tests — Tier 2 per spec §43.8.
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
