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
//! - cross-process: a spawned holder process confirms it holds the metadata
//!   lock, the real CLI binary is spawned against the same store while the
//!   lock is held, and the holder releases on a signal file inside the
//!   retry budget — the CLI's contended open recovers via retry and
//!   succeeds (the exact #762 shape). Signal-file release (not a timer)
//!   makes the hold deterministic under CI scheduler load.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arbitraitor_engine::{ArbitraitorApi, Config};

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
///
/// On a heavily loaded runner the CLI's own process startup (binary spawn +
/// engine init) can consume the 400 ms retry budget before its open reaches
/// the released window, which is an environment artifact, not a product
/// regression. The scenario therefore retries with a FRESH store up to
/// three times; the contention assertion (`lock_observed`, `elapsed`) keeps
/// every scenario honest — a product regression to eager opens fails all
/// three.
#[cfg(unix)]
#[test]
fn cli_fetch_completes_while_another_process_holds_store_briefly() -> TestResult {
    let mut last_error: Option<String> = None;
    for _ in 0..3 {
        match contended_open_scenario() {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    Err(Box::<dyn std::error::Error>::from(
        last_error.unwrap_or_else(|| String::from("scenario failed without a diagnostic")),
    ))
}

/// One contended-open scenario: fresh store, holder probe, contended CLI.
fn contended_open_scenario() -> TestResult {
    let root = unique_dir("cross-process");
    let cas = root.join("cas");
    let script = write_scan_script(&root, b"#!/bin/sh\necho cross-process\n");

    // Process A (this test, acting as the other process): spawn the holder
    // probe as a real separate process that opens the store and keeps it
    // open until the test tells it to release. The release is a signal file
    // (not a wall-clock sleep): a loaded CI runner can deschedule the holder
    // past any fixed hold, which is exactly the flake the previous
    // timer-based design hit. The test controls the hold precisely —
    // release right after the CLI's contended open is underway, well inside
    // the 400 ms retry budget.
    let release_signal = root.join("release-holder");
    let mut holder = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "holder_probe_opens_store_holds_then_releases",
            "--ignored",
            "--nocapture",
        ])
        .env("ARBITRAITOR_HOLDER_CAS", &cas)
        .env("ARBITRAITOR_HOLDER_RELEASE", &release_signal)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    // Wait until the holder actually holds the metadata lock before the CLI
    // starts (poll the flock, 5 ms steps): slow CI process spawns must not
    // miss the hold window, or the CLI would sail through uncontended and
    // the contention assertion below would flake. The poll's own successful
    // try_locks drop their fd at each iteration end, so the poll never holds
    // the lock itself.
    let meta_db = cas.join("meta.db");
    let mut lock_observed = false;
    for _ in 0..600 {
        let probe = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&meta_db);
        // `try_lock` fails while the holder's flock is live — exactly the
        // signal we poll for.
        let held_by_other = match probe {
            Ok(file) => file.try_lock().is_err(),
            Err(_) => false,
        };
        if held_by_other {
            lock_observed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        lock_observed,
        "holder probe must acquire the metadata lock within 3 s; \
         if this fails the spawn environment is too slow to test contention"
    );

    let started = std::time::Instant::now();
    let cli_bin = env!("CARGO_BIN_EXE_arbitraitor");
    let mut cli = std::process::Command::new(cli_bin)
        .arg("inspect")
        .arg(format!("file://{}", script.display()))
        .arg("--cas-dir")
        .arg(&cas)
        .env("HOME", &root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    // The CLI process is now running its contended open. Hold the lock a
    // moment longer so the CLI's first open attempt definitely hits the
    // flock, then release well inside the 400 ms retry budget: the CLI's
    // open retries until the flock frees, then succeeds — the exact #762
    // recovery path.
    std::thread::sleep(Duration::from_millis(100));
    std::fs::write(&release_signal, b"release")?;

    let status = cli.wait()?;
    let elapsed = started.elapsed();

    let holder_status = holder.wait()?;

    // The CLI actually contended: the lock was confirmed held before the
    // CLI spawned, so its open necessarily blocked until the holder
    // released. If the contention were removed (holder skipped, or the
    // engine regressed to a process-lifetime eager open), either the
    // lock-observation assert or the success assert here would catch it.
    assert!(
        status.success(),
        "CLI must succeed after the contended open recovers via retry"
    );
    assert!(
        elapsed >= Duration::from_millis(20),
        "CLI must have blocked on the held lock; finished in {elapsed:?}, \
         which suggests the holder never held the store"
    );
    assert!(
        holder_status.success(),
        "holder probe must have opened and released the store cleanly"
    );
    Ok(())
}

/// Holder helper: opens the store and holds it until the release signal file
/// (`ARBITRAITOR_HOLDER_RELEASE`) appears, then exits (releasing the lock).
/// Spawned by `cli_fetch_completes_while_another_process_holds_store_briefly`
/// with `--exact holder_probe_opens_store_holds_then_releases --ignored` and
/// the CAS path in `ARBITRAITOR_HOLDER_CAS`.
#[cfg(unix)]
#[test]
#[ignore = "spawned explicitly by cli_fetch_completes_while_another_process_holds_store_briefly"]
fn holder_probe_opens_store_holds_then_releases() {
    let cas = std::env::var("ARBITRAITOR_HOLDER_CAS")
        .unwrap_or_else(|_| panic!("ARBITRAITOR_HOLDER_CAS must be set by the spawning test"));
    let release = std::env::var("ARBITRAITOR_HOLDER_RELEASE")
        .unwrap_or_else(|_| panic!("ARBITRAITOR_HOLDER_RELEASE must be set by the spawning test"));
    let store =
        arbitraitor_store::ContentStore::open(Path::new(&cas)).expect("holder probe store open");
    // Hold until the test signals release (poll every 2 ms). A cap prevents
    // a hung test from blocking the suite forever; 30 s is far beyond any
    // realistic scheduler delay while staying bounded.
    for _ in 0..15_000 {
        if Path::new(&release).exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    drop(store);
}
