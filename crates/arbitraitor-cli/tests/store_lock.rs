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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arbitraitor_engine::{ArbitraitorApi, Config};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Monotonic per-call counter: nanos alone can collide on coarse clocks, and
/// two scenarios sharing a root would fight over `cas/` (the same #788 class
/// of bug as the pid-only helper in `threat_model_adversaries.rs`).
static UNIQUE_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir(label: &str) -> PathBuf {
    let id = UNIQUE_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let path = std::env::temp_dir().join(format!(
        "arb-store-lock-{label}-{}-{id}-{nanos}",
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
/// three times; the `lock_observed` check keeps every scenario honest — a
/// product regression to eager opens fails all three.
///
/// Residual limitation, stated honestly: this test cannot prove the CLI's
/// open actually *blocked* on the held flock. `open_with_retry` in
/// `arbitraitor-store` emits no tracing event or log line for a contended
/// attempt, so there is no observable contention signal to assert on (and
/// adding product logging is out of scope for a test change). A successful
/// CLI run whose open happened to land entirely after the release would pass
/// without exercising the retry path on that particular run. The scenario
/// still catches the #762 regression (an eager process-lifetime open fails
/// the store open after the retry budget) and the holder-side failure modes,
/// it just does not prove the retry path itself was exercised.
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
    let held_signal = root.join("holder-holding");
    let mut holder = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "holder_probe_opens_store_holds_then_releases",
            "--ignored",
            "--nocapture",
        ])
        .env("ARBITRAITOR_HOLDER_CAS", &cas)
        .env("ARBITRAITOR_HOLDER_RELEASE", &release_signal)
        .env("ARBITRAITOR_HOLDER_HELD", &held_signal)
        .stdout(std::process::Stdio::null())
        // Capture the holder's stderr: its panics were previously invisible
        // behind `Stdio::null()`, so an early holder exit had no diagnostic.
        // Output volume is a few lines, so piping cannot deadlock the hold
        // window; it is drained to EOF via `wait_with_output` after exit.
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    // Wait until the holder process has *actually acquired the flock*,
    // signalled by the holder writing `ARBITRAITOR_HOLDER_HELD` after its
    // open returns. A flock probe alone (below) races on loaded CI runners:
    // the test process can observe a stale/probe-side lock state while the
    // holder's own open has not yet landed, then the CLI spawns and its
    // open either sails through or races the holder's open for the same
    // retry budget — the 2026-10-13 CI flake (issue #803). The signal file
    // makes the hold window exact, mirroring how release is signalled.
    let held_deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !held_signal.exists() {
        if let Some(status) = holder.try_wait()? {
            // The holder exited before acquiring the lock. It has already
            // exited, so draining stderr via `wait_with_output` cannot block;
            // without it the panic message that made the holder fail stays
            // invisible in the pipe.
            let output = holder.wait_with_output()?;
            return Err(format!(
                "holder probe exited before acquiring the store lock \
                 (exit status: {status}): {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        assert!(
            held_deadline > std::time::Instant::now(),
            "holder probe must signal lock acquisition within 10 s"
        );
        std::thread::sleep(Duration::from_millis(2));
    }

    // Belt-and-suspenders: also confirm the flock from this process' view.
    // The poll's own successful try_locks drop their fd at each iteration
    // end, so the poll never holds the lock itself.
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
            Err(_) => true,
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

    let cli_bin = env!("CARGO_BIN_EXE_arbitraitor");
    let cli = std::process::Command::new(cli_bin)
        .arg("inspect")
        .arg(format!("file://{}", script.display()))
        .arg("--cas-dir")
        .arg(&cas)
        .env("HOME", &root)
        .stdout(std::process::Stdio::null())
        // Capture the CLI's stderr so a failed contended open reports the
        // product's actual diagnostic instead of a generic string. Drained
        // to EOF by `wait_with_output` (no undrained `.spawn()` + piped
        // stdio, which deadlocks once the child fills the pipe buffer).
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    // The CLI process is now running its contended open. Hold the lock a
    // moment longer so the CLI's first open attempt definitely hits the
    // flock, then release well inside the 400 ms retry budget: the CLI's
    // open retries until the flock frees, then succeeds — the exact #762
    // recovery path.
    std::thread::sleep(Duration::from_millis(100));
    std::fs::write(&release_signal, b"release")?;

    let cli_output = cli.wait_with_output()?;

    let holder_output = holder.wait_with_output()?;
    let holder_status = holder_output.status;

    // What is actually asserted here: the flock was confirmed held (from
    // this process' own probe) before the CLI was spawned, the holder kept
    // holding until after the CLI had been running for 100 ms, and the CLI
    // then succeeded against the same store. This catches a regression to a
    // process-lifetime eager open — the CLI's open would exhaust the retry
    // budget and fail — but it cannot prove the CLI's open itself blocked on
    // the flock (see the residual-limitation note in the test's doc
    // comment). An unsuccessful status must return an error (not panic) so
    // the outer retry loop in
    // `cli_fetch_completes_while_another_process_holds_store_briefly` can
    // retry and retain the final diagnostic.
    if !cli_output.status.success() {
        return Err(format!(
            "CLI must succeed after the contended open recovers via retry \
             (exit status: {}): {}",
            cli_output.status,
            String::from_utf8_lossy(&cli_output.stderr)
        )
        .into());
    }
    assert!(
        holder_status.success(),
        "holder probe must have opened and released the store cleanly: {}",
        String::from_utf8_lossy(&holder_output.stderr)
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
    let held = std::env::var("ARBITRAITOR_HOLDER_HELD")
        .unwrap_or_else(|_| panic!("ARBITRAITOR_HOLDER_HELD must be set by the spawning test"));
    let store =
        arbitraitor_store::ContentStore::open(Path::new(&cas)).expect("holder probe store open");
    // Signal the spawning test that the flock is now actually held (issue
    // #803): the test must not spawn the contended CLI until this lands,
    // or the CLI's open races the holder's open inside the same retry
    // budget. Write-after-acquire ordering is the point of the signal.
    std::fs::write(&held, b"holding").expect("write holder-held signal");
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
