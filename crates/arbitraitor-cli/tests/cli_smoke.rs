//! CLI smoke tests — Tier 2.
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
fn doctor_help_exits_zero() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("doctor")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("doctor"));
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
fn doctor_help_lists_allow_degraded_detectors_flag() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .arg("doctor")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--allow-degraded-detectors"))
        .stdout(predicate::str::contains(
            "ARBITRAITOR_ALLOW_DEGRADED_DETECTORS",
        ));
    Ok(())
}

// --- #763: wrapper scheme handling and diagnostics ---

/// Message demanded when the wrapper cannot identify a URL argument. It must
/// state every accepted form — including the scheme-less `host[:port]/path`
/// default — so the guidance is satisfiable (previously it demanded only
/// `http://`/`https://` while the same invocation's fetch policy refused
/// plaintext `http`, a self-contradiction). Assertions use fragments short
/// enough to survive miette's line wrapping of long diagnostics.
#[test]
fn wrapper_missing_url_diagnostic_states_accepted_forms() -> TestResult {
    Command::cargo_bin("arbitraitor")?
        .args(["fetch", "--tool", "curl", "--", "-s", "-o", "/dev/null"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("requires a URL argument")
                .and(predicate::str::contains("http://host[:port]/"))
                .and(predicate::str::contains("https://host[:port]/path"))
                .and(predicate::str::contains("the scheme-less form")),
        );
    Ok(())
}

#[test]
fn wrapper_schemeless_ftp_is_still_rejected_as_unsupported_scheme() -> TestResult {
    // Negative control: normalization defaults scheme-less arguments to
    // http; explicit non-http(s) schemes remain opaque rejections.
    Command::cargo_bin("arbitraitor")?
        .args(["fetch", "--tool", "curl", "--", "ftp://example.com/file"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported URI scheme 'ftp'"));
    Ok(())
}

#[test]
fn wrapper_schemeless_host_port_reaches_fetch_policy_as_http() -> TestResult {
    // A scheme-less host:port argument must normalize to http:// and flow
    // through the fetch pipeline (which then applies its own scheme/SSRF
    // policy), instead of dying as "unsupported URI scheme 'localhost'".
    // No listener is needed: the observable behavior is that the fetch
    // policy — not URL parsing — produces the verdict, here the policy
    // rejection of plaintext http in the default configuration. A unique
    // temp HOME keeps the CAS metadata lock isolated from other tests.
    let home = tempfile::TempDir::new()?;
    Command::cargo_bin("arbitraitor")?
        .args(["fetch", "--tool", "curl", "--", "localhost:59999/health"])
        .env("HOME", home.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("scheme `http` is not allowed"));
    Ok(())
}

#[test]
fn wrapper_quiet_fail_flags_do_not_suppress_mapped_transport_diagnostic() -> TestResult {
    // `-sf` silences curl's own progress/error output, not the gate's
    // verdict: a mapped transport failure (DNS → exit 6) must still print
    // its diagnostic on stderr before exiting with curl's exit code.
    // Previously `std::process::exit` bypassed the error printer and the
    // shim failed with bare exit 6 and zero bytes on stderr.
    let home = tempfile::TempDir::new()?;
    Command::cargo_bin("arbitraitor")?
        .args([
            "fetch",
            "--tool",
            "curl",
            "--",
            "-sf",
            "https://arbitraitor-test-no-such-host.invalid/x",
        ])
        .env("HOME", home.path())
        .assert()
        .failure()
        .code(6)
        .stderr(predicate::str::contains("could not resolve host"));
    Ok(())
}

#[test]
fn wrapper_inline_url_option_reaches_fetch_policy() -> TestResult {
    // MEDIUM-1 regression: `--url=host:port/path` must be recognized as a
    // URL argument (normalized to http://) and reach fetch policy, not the
    // missing-URL diagnostic. A unique temp HOME keeps the CAS metadata
    // lock isolated from other tests.
    let home = tempfile::TempDir::new()?;
    Command::cargo_bin("arbitraitor")?
        .args(["fetch", "--tool", "curl", "--", "--url=example.com:8080/x"])
        .env("HOME", home.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("scheme `http` is not allowed"));
    Ok(())
}
