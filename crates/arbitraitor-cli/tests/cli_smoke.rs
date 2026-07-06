//! CLI smoke tests — Tier 2 per spec §43.8.
//!
//! Black-box tests that exercise the `arbitraitor` binary surface:
//! exit codes, help output, and basic subcommand behavior. These do
//! not require network access, Docker, or any external service.

use assert_cmd::Command;
use predicates::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn version_flag_exits_zero_and_prints_version() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("arbitraitor"));
    Ok(())
}

#[test]
fn help_flag_exits_zero_and_lists_subcommands() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("inspect"))
        .stdout(predicate::str::contains("run"))
        .stdout(predicate::str::contains("daemon"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("wrappers"))
        .stdout(predicate::str::contains("mcp"));
    Ok(())
}

#[test]
fn no_args_prints_help() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
    Ok(())
}

#[test]
fn inspect_help_exits_zero() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("inspect")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("inspect"));
    Ok(())
}

#[test]
fn run_help_exits_zero() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("run")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("run"));
    Ok(())
}

#[test]
fn status_help_exits_zero() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("status")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("status"));
    Ok(())
}

#[test]
fn wrappers_help_exits_zero() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("wrappers")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("wrappers"));
    Ok(())
}

#[test]
fn mcp_help_exits_zero() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("mcp")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("mcp"));
    Ok(())
}

#[test]
fn unknown_subcommand_exits_non_zero() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("nonexistent-subcommand")
        .assert()
        .failure();
    Ok(())
}

#[test]
fn doctor_defaults_to_human_panel_when_shell_integration_missing() -> TestResult {
    let home = tempfile::tempdir()?;
    Command::cargo_bin("arbitraitor")?
        .arg("--allow-root")
        .arg("doctor")
        .env("HOME", home.path())
        .env("SHELL", "/bin/bash")
        .env("PATH", "/usr/bin:/bin")
        .assert()
        .failure()
        .stdout(predicate::str::contains("Arbitraitor Doctor"))
        .stdout(predicate::str::contains("✓ Version:"))
        .stdout(predicate::str::contains("Shell detection:"))
        .stdout(predicate::str::contains("Fix shell integration:"))
        .stdout(predicate::str::contains("arbitraitor wrappers install"))
        .stdout(predicate::str::contains(
            "arbitraitor wrappers init --install",
        ));
    Ok(())
}

#[test]
fn doctor_json_flag_preserves_machine_readable_report() -> TestResult {
    let home = tempfile::tempdir()?;
    Command::cargo_bin("arbitraitor")?
        .arg("--allow-root")
        .arg("doctor")
        .arg("--json")
        .env("HOME", home.path())
        .env("SHELL", "/bin/bash")
        .env("PATH", "/usr/bin:/bin")
        .assert()
        .failure()
        .stdout(predicate::str::starts_with("{"))
        .stdout(predicate::str::contains("\"checks\""))
        .stdout(predicate::str::contains("\"version\""));
    Ok(())
}
