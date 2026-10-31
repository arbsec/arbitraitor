//! Regression tests for #837: `arbitraitor execute` must not fail open.
//!
//! The approved-execution contract (spec §29, `ExitCode::ExecutionFailed`,
//! `book/src/cli/run.md`) is: exit `50` whenever an approved execution does
//! not complete successfully — non-zero child exit, death by signal, spawn
//! failure, or sandbox rejection. Before the fix `execute` printed the child's
//! status and returned exit `0` unconditionally.
//!
//! These are black-box tests: the real binary is driven against a real CAS
//! object and a real plan-bound approval file, so they exercise the same
//! inspect → approve → execute decision path users hit (the approval is
//! constructed directly because `arbitraitor approve` always binds
//! `network_isolated = true`, while these tests run with `--network` to stay
//! independent of user-namespace availability; the approval's canonical plan
//! digest is still verified by `execute`).
//!
//! # macOS
//!
//! Three of these tests are skipped on non-Linux hosts. `running_as_root()`
//! (`crates/arbitraitor-exec/src/lib.rs:1591`) reads `/proc/self/status`, which
//! does not exist on macOS, so every approved execution fails with
//! `exec setup failed: failed to determine current uid` before the child is
//! spawned. That is a tracked product defect, not an unsupported platform —
//! macOS `mediated` execution is promised by spec §3.11 (`docs/spec/spec.md:230`)
//! and §27.4 (`docs/spec/spec.md:2352`). The affected tests are marked with
//! `#[cfg_attr(not(target_os = "linux"), ignore = "...")]` so the skip is
//! explicit rather than a silent pass (spec §43.8, `docs/spec/spec.md:6792`),
//! and the file still type-checks on macOS. See issue #839 for the defect and
//! its acceptance criteria.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{SystemTime, UNIX_EPOCH};

use arbitraitor_model::exit_code::ExitCode;
use arbitraitor_store::ContentStore;
use assert_cmd::Command;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// An isolated CLI environment: private HOME, config dir, and cache root so
/// the default CAS directory (`$XDG_CACHE_HOME/arbitraitor/cas`) and the
/// user config cannot leak in from the host.
struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            root: tempfile::tempdir()?,
        })
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn cache(&self) -> PathBuf {
        self.root.path().join("cache")
    }

    fn config(&self) -> PathBuf {
        self.root.path().join("config")
    }

    /// CAS root matching the CLI's `default_cas_dir()` under the fixture's
    /// `XDG_CACHE_HOME`.
    fn cas(&self) -> PathBuf {
        self.cache().join("arbitraitor").join("cas")
    }

    fn command(&self) -> Result<Command, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(self.home())?;
        std::fs::create_dir_all(self.config())?;
        let mut command = Command::cargo_bin("arbitraitor")?;
        command
            .env("HOME", self.home())
            .env("XDG_CACHE_HOME", self.cache())
            .env("XDG_CONFIG_HOME", self.config())
            .env_remove("ARBITRAITOR_SYSTEM_CONFIG");
        Ok(command)
    }
}

/// Stores `bytes` in the fixture CAS and returns its digest.
fn store_artifact(fixture: &Fixture, bytes: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let store = ContentStore::open(&fixture.cas())?;
    let runtime = tokio::runtime::Runtime::new()?;
    let digest = runtime.block_on(async {
        let mut sink = store.sink(None)?;
        sink.write_chunk(bytes).await?;
        sink.finish().await
    })?;
    Ok(digest.to_string())
}

/// Mirrors `ApprovalFile::compute_plan_digest` (the canonical field-order
/// encoding `execute` re-verifies). Kept explicit so a drift in either side
/// makes these tests fail loudly at `approval verification failed`.
fn plan_digest(approval: &Value) -> String {
    let text = |key: &str| approval[key].as_str().unwrap_or_default().to_owned();
    let list = |key: &str| {
        approval[key]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default()
    };
    let body = format!(
        "artifact_sha256={}\n\
         operation={}\n\
         release_mode={}\n\
         interpreter={}\n\
         interpreter_arguments={}\n\
         environment_profile_digest={}\n\
         working_directory_policy={}\n\
         filesystem_grants={}\n\
         network_isolated={}\n\
         sandbox_capabilities={}\n\
         release_destination={}\n\
         policy_snapshot_digest={}\n\
         detector_snapshot_digest={}\n\
         nonce={}\n\
         expires_at={}\n",
        text("artifact_sha256"),
        text("operation"),
        text("release_mode"),
        text("interpreter"),
        list("interpreter_arguments"),
        text("environment_profile_digest"),
        text("working_directory_policy"),
        list("filesystem_grants"),
        approval["network_isolated"].as_bool().unwrap_or(false),
        text("sandbox_capabilities"),
        text("release_destination"),
        text("policy_snapshot_digest"),
        text("detector_snapshot_digest"),
        text("nonce"),
        approval["expires_at"].as_u64().unwrap_or_default(),
    );
    hex::encode(Sha256::digest(body.as_bytes()))
}

/// Writes a plan-bound approval file for `sha256` and returns its path.
fn write_approval(
    fixture: &Fixture,
    sha256: &str,
    network_isolated: bool,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut approval = json!({
        "schema_version": 2,
        "artifact_sha256": sha256,
        "operation": "execute",
        "release_mode": "execute",
        "interpreter": "/bin/bash",
        "interpreter_arguments": ["--noprofile", "--norc"],
        "environment_profile_digest": "mvp ExecutionContext allowlist v1",
        "working_directory_policy": "sandbox-root-stdin-fed",
        "filesystem_grants": [],
        "network_isolated": network_isolated,
        "sandbox_capabilities": "prctl NoNewPrivs + close_range fd closure",
        "release_destination": "inline-execute",
        "policy_snapshot_digest": "policy:test",
        "detector_snapshot_digest": "detector.test:1.0.0",
        "plan_digest": "",
        "nonce": "arbitraitor-execute-exit-code-test",
        "approver": "test",
        "approved_at": now,
        "expires_at": now + 300,
        "verdict": "Pass"
    });
    approval["plan_digest"] = json!(plan_digest(&approval));
    let path = fixture.root.path().join("approval.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&approval)?)?;
    Ok(path)
}

/// Runs `arbitraitor execute --approval <approval>` (plus `extra_args`).
fn run_execute(
    fixture: &Fixture,
    approval: &Path,
    extra_args: &[&str],
) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(fixture
        .command()?
        .arg("execute")
        .arg("--approval")
        .arg(approval)
        .args(extra_args)
        .output()?)
}

fn assert_exit(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "expected exit {expected}; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Control arm: a successful approved execution must still exit 0. Without
/// this the failure assertions could pass vacuously (e.g. if the harness
/// itself broke before reaching the child).
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "macOS: running_as_root() requires procfs — tracked product defect, see #839"
)]
fn approved_execution_child_exit_zero_exits_zero() -> TestResult {
    let fixture = Fixture::new()?;
    let sha256 = store_artifact(&fixture, b"#!/bin/sh\necho control-arm\nexit 0\n")?;
    let approval = write_approval(&fixture, &sha256, false)?;

    let output = run_execute(&fixture, &approval, &["--network"])?;

    assert_exit(&output, ExitCode::Success.as_i32());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("control-arm"),
        "child stdout must be forwarded; got {:?}",
        String::from_utf8_lossy(&output.stdout),
    );
    Ok(())
}

/// A non-zero child exit is an execution failure: exit 50, not 0 and not the
/// child's own code.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "macOS: running_as_root() requires procfs — tracked product defect, see #839"
)]
fn approved_execution_child_exit_non_zero_exits_50() -> TestResult {
    let fixture = Fixture::new()?;
    let sha256 = store_artifact(&fixture, b"#!/bin/sh\nexit 3\n")?;
    let approval = write_approval(&fixture, &sha256, false)?;

    let output = run_execute(&fixture, &approval, &["--network"])?;

    assert_exit(&output, ExitCode::ExecutionFailed.as_i32());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("exit code: 3"),
        "the child's own code must still be reported; got {stdout:?}",
    );
    Ok(())
}

/// Death by signal has no exit code (`exit_code == None`); it is still an
/// execution failure and must exit 50.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "macOS: running_as_root() requires procfs — tracked product defect, see #839"
)]
fn approved_execution_child_killed_by_signal_exits_50() -> TestResult {
    let fixture = Fixture::new()?;
    let sha256 = store_artifact(&fixture, b"#!/bin/sh\nkill -TERM $$\n")?;
    let approval = write_approval(&fixture, &sha256, false)?;

    let output = run_execute(&fixture, &approval, &["--network"])?;

    assert_exit(&output, ExitCode::ExecutionFailed.as_i32());
    Ok(())
}

/// Approval/plan mismatch is a validation failure before dispatch; it keeps
/// its existing non-zero code (1) and must not become 50 or 0.
#[test]
fn approval_network_mismatch_keeps_validation_exit_code() -> TestResult {
    let fixture = Fixture::new()?;
    let sha256 = store_artifact(&fixture, b"#!/bin/sh\nexit 0\n")?;
    let approval = write_approval(&fixture, &sha256, true)?;

    // The approval binds network isolation, `--network` requests network
    // access: the plan no longer matches.
    let output = run_execute(&fixture, &approval, &["--network"])?;

    assert_exit(&output, 1);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("approval was issued for network_isolated"),
        "expected plan-mismatch diagnostic; got {:?}",
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(())
}
