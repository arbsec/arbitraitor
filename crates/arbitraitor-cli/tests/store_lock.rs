//! Op-scoped store access regression tests (#762).
//!
//! The MCP stdio server and the daemon construct the engine once at startup.
//! Before #762 the engine opened the redb metadata index eagerly, so that
//! startup open held the whole-file lock for the process lifetime and every
//! concurrent CLI fetch died at store open. These tests pin the fixed
//! behavior at two levels:
//!
//! - in-process: a long-lived [`ArbitraitorApi`] holds no redb lock between
//!   operations, so a second process-equivalent open of the same store
//!   succeeds while the API instance is alive;
//! - cross-process: while one process holds the store open, a real CLI
//!   invocation against the same store completes (the retry budget bridges
//!   the holder's open→use→close window).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arbitraitor_engine::{ArbitraitorApi, Config};
use assert_cmd::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn unique_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let path = std::env::temp_dir().join(format!(
        "arb-store-lock-{label}-{}-{nanos}",
        std::process::id(),
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn engine_config(root: &Path) -> Config {
    Config {
        store_path: root.join("cas"),
        receipts_path: root.join("receipts"),
        ..Config::default()
    }
}

fn write_scan_script(root: &Path, body: &[u8]) -> PathBuf {
    let script = root.join("sample.sh");
    std::fs::write(&script, body).unwrap();
    script
}

/// The #762 regression: an idle long-lived engine instance (MCP server /
/// daemon startup shape) must not hold the metadata lock. While the
/// instance is alive, a second store open — what a concurrent CLI fetch
/// performs — must succeed against the same store.
#[test]
fn idle_engine_does_not_block_concurrent_store_open() {
    let root = unique_dir("idle-no-block");
    let api = ArbitraitorApi::new(engine_config(&root)).unwrap();

    // Warm the engine so its per-operation store has actually been opened
    // once and then closed: the exact idle state of an MCP server between
    // requests.
    let script = write_scan_script(&root, b"#!/bin/sh\necho idle-probe\n");
    api.scan_path(&script, arbitraitor_engine::DEFAULT_SCAN_MAX_BYTES)
        .unwrap();

    // Same-store open while the engine instance is still alive: this is the
    // open that failed before #762.
    let second = ArbitraitorApi::new(engine_config(&root)).unwrap();
    let other = write_scan_script(&root, b"#!/bin/sh\necho second-open\n");
    let result = second.scan_path(&other, arbitraitor_engine::DEFAULT_SCAN_MAX_BYTES);

    assert!(
        result.is_ok(),
        "concurrent same-store open must succeed while an idle engine is alive: {:?}",
        result.map(|r| r.sha256).map_err(|e| e.to_string())
    );
}

/// Cross-process shape: one process holds the metadata database open (a
/// long in-flight operation, or pre-fix long-lived surface), a real CLI
/// invocation targets the same store. The holder releases within the retry
/// budget, and the CLI must complete instead of dying at store open.
#[cfg(unix)]
#[test]
fn cli_fetch_completes_while_another_process_holds_store_briefly() -> TestResult {
    let root = unique_dir("cross-process");
    let cas = root.join("cas");
    let script = write_scan_script(&root, b"#!/bin/sh\necho cross-process\n");

    // Process A (this test, acting as the other process): spawn the holder
    // probe as a real separate process that opens the store and keeps it
    // open for a bounded window shorter than the store layer's retry budget
    // (400 ms), then releases.
    let mut holder = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "holder_probe_opens_store_holds_then_releases",
            "--ignored",
            "--nocapture",
        ])
        .env("ARBITRAITOR_HOLDER_CAS", &cas)
        .env("ARBITRAITOR_HOLDER_MS", "150")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    // Give the holder a moment to actually acquire the lock before the CLI
    // starts, so the CLI genuinely contends with it.
    std::thread::sleep(Duration::from_millis(50));

    let started = std::time::Instant::now();
    Command::cargo_bin("arbitraitor")?
        .arg("inspect")
        .arg(format!("file://{}", script.display()))
        .arg("--cas-dir")
        .arg(&cas)
        .env("HOME", &root)
        .assert()
        .success();
    let elapsed = started.elapsed();

    let holder_status = holder.wait()?;

    // The CLI actually contended: the holder was still inside its 150 ms
    // hold window (50 ms settle + hold + open margin), so the CLI elapsed
    // time must include at least part of the remaining hold. If the spawn
    // or the contention were removed, the CLI would finish in its normal
    // fast path and this lower bound would fail.
    assert!(
        elapsed >= Duration::from_millis(100),
        "CLI must have contended with the 150 ms holder; finished in {elapsed:?}, \
         which suggests the holder never held the store"
    );
    assert!(
        holder_status.success(),
        "holder probe must have opened and released the store cleanly"
    );
    Ok(())
}

/// Holder helper: opens the store, holds it for `ARBITRAITOR_HOLDER_MS`,
/// then exits (releasing the lock). Spawned by
/// `cli_fetch_completes_while_another_process_holds_store_briefly` with
/// `--exact holder_probe_opens_store_holds_then_releases --ignored` and the
/// CAS path in `ARBITRAITOR_HOLDER_CAS`.
#[cfg(unix)]
#[test]
#[ignore = "spawned explicitly by cli_fetch_completes_while_another_process_holds_store_briefly"]
fn holder_probe_opens_store_holds_then_releases() {
    let cas = std::env::var("ARBITRAITOR_HOLDER_CAS")
        .unwrap_or_else(|_| panic!("ARBITRAITOR_HOLDER_CAS must be set by the spawning test"));
    let hold_ms: u64 = std::env::var("ARBITRAITOR_HOLDER_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(150);
    let store =
        arbitraitor_store::ContentStore::open(Path::new(&cas)).expect("holder probe store open");
    std::thread::sleep(Duration::from_millis(hold_ms));
    drop(store);
}
