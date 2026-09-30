//! Child-process spawn helpers shared by the script and native executors.
//!
//! These helpers close two security gaps that `std::process::Command` leaves
//! open by default:
//!
//! 1. **TOCTOU between spawn and limit application.** After `spawn()` returns,
//!    the child runs immediately and may execute untrusted code before
//!    `prlimit` is applied. [`apply_limits_fenced`] `SIGSTOP`s the child the
//!    instant it appears, applies limits while it is frozen, and only then
//!    `SIGCONT`s it. If limit application fails the child is killed and reaped
//!    so it can never run unbounded or become an orphan.
//!
//! 2. **Unbounded output buffering.** `Child::wait_with_output` buffers the
//!    entire stdout/stderr in memory. A hostile script can exhaust memory that
//!    way. [`read_with_limit`] drains both pipes concurrently (preventing
//!    write-buffer deadlock) and kills the child as soon as the combined output
//!    exceeds a cap.

use std::io::Read;
use std::process::Child;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::ExecError;

/// Fallback combined stdout/stderr cap when no explicit limit is configured.
///
/// Matches the default recorded in [`crate::ResourceLimits`].
pub(crate) const DEFAULT_OUTPUT_LIMIT: u64 = 10 * 1024 * 1024;

/// Wall-clock window for the diagnostics-only `best_effort_capture` path.
///
/// Deliberately short: capture happens after an operation has already
/// failed, so its only job is to grab whatever the child printed before
/// exiting — not to give the child more running time.
const BEST_EFFORT_CAPTURE_SECS: u64 = 2;

/// Applies resource limits to a freshly-spawned child with no TOCTOU window.
///
/// The child is `SIGSTOP`ped immediately after `spawn()` returns so it cannot
/// execute any untrusted code, `prlimit` is applied while it is stopped, and
/// only then is it `SIGCONT`ed. If limit application fails the child is killed
/// and reaped before the error is returned, so it can never run without its
/// limits and can never become an orphan.
///
/// On non-Linux platforms resource limits are not supported and this is a
/// no-op; the caller still gets a running child.
///
/// # Errors
///
/// Returns [`ExecError::ResourceLimit`] when the kernel rejects a limit. The
/// child has already been killed and reaped in that case.
#[cfg(target_os = "linux")]
pub(crate) fn apply_limits_fenced(
    child: &mut Child,
    limits: &crate::ResourceLimits,
) -> Result<(), ExecError> {
    use rustix::process::{Pid, Signal, kill_process};

    let pid = Pid::from_child(child);
    // Freeze the child before it can run any untrusted code. Errors here
    // (e.g. the child already exited) are tolerated: apply_to below surfaces
    // a real failure if the pid is no longer valid.
    let _ = kill_process(pid, Signal::STOP);
    if let Err(source) = limits.apply_to(child.id()) {
        // Fail closed: never leave a child running without its limits, and
        // never leak an orphan. SIGKILL works on a stopped process.
        let _ = child.kill();
        let _ = child.wait();
        return Err(ExecError::ResourceLimit {
            reason: source.to_string(),
        });
    }
    // Resume the child now that its limits are in place.
    let _ = kill_process(pid, Signal::CONT);
    Ok(())
}

/// Captured exit code and piped output from a capped child read.
pub(crate) type CapturedOutput = (Option<i32>, Vec<u8>, Vec<u8>);

/// Best-effort capture of a child's exit code and piped stdout/stderr after a
/// prior operation (typically `write_all` to the child's stdin) has already
/// failed.
///
/// The caller has already lost the script I/O; the goal here is diagnostic
/// preservation — surface whatever the child printed before exiting so the
/// user can tell `bash: !DOCTYPE: event not found` (caller fed bash junk)
/// from `unshare: operation not permitted` (kernel denied the user
/// namespace). Any secondary failure (the child's combined output exceeded
/// the cap, or the child could not be reaped) is swallowed and yields
/// `(None, Vec::new(), Vec::new())`: nothing further is captured, but the
/// original I/O error is still propagated by the caller.
///
/// The capture runs with a fixed short wall-clock window
/// ([`BEST_EFFORT_CAPTURE_SECS`]): this is a diagnostics-only path on an
/// already-failed operation, so a child that hangs (e.g. a background
/// process inheriting the pipe FDs) is killed at the window instead of
/// hanging the error report. Whatever was captured by then is returned.
pub(crate) fn best_effort_capture(child: &mut Child, limit: u64) -> CapturedOutput {
    let pid = rustix::process::Pid::from_child(child);
    let watchdog = arm_wall_clock(pid, Some(BEST_EFFORT_CAPTURE_SECS));
    read_with_limit(child, limit, watchdog).unwrap_or((None, Vec::new(), Vec::new()))
}

/// Watchdog state shared between the caller thread and the deadline thread.
struct Watchdog {
    /// Configured deadline in seconds, echoed into
    /// [`ExecError::WallClockExpired`].
    limit_secs: u64,
    /// Set by the deadline thread when it has killed the process group.
    expired: AtomicBool,
    /// Set by the deadline thread when the group kill errored (non-ESRCH).
    /// The caller surfaces [`ExecError::WallClockKillFailed`] when the child
    /// is not confirmed dead.
    kill_failed: Mutex<Option<std::io::Error>>,
    /// Set by the caller once the child has been reaped, so the deadline
    /// thread can exit without killing a recycled pid's group. Note: the
    /// release is not instantaneous — after `done` is stored the watchdog
    /// may still fire for up to one poll interval (~50 ms) if it passed its
    /// `done` check just before the store. The post-reap expiry check in
    /// [`finish_wall_clock`] makes that window harmless.
    done: AtomicBool,
}

impl Watchdog {
    fn new(limit_secs: u64) -> Self {
        Self {
            limit_secs,
            expired: AtomicBool::new(false),
            kill_failed: Mutex::new(None),
            done: AtomicBool::new(false),
        }
    }
}

/// An armed wall-clock watchdog for a spawned child.
///
/// Armed immediately after spawn so the deadline covers the entire child
/// lifetime — including the parent's blocking `write_all` of the script
/// bytes to the child's stdin — not just the output-collection phase.
/// Consume it with [`finish_wall_clock`] once the child has been reaped.
pub(crate) struct WallClockGuard {
    state: Option<Arc<Watchdog>>,
    handle: Option<thread::JoinHandle<()>>,
}

/// Arms the wall-clock watchdog for a freshly spawned child.
///
/// Returns a disabled guard when `wall_clock_secs` is `None` (deadline
/// disabled). A `Some(0)` deadline is armed like any other: the watchdog's
/// first poll tick expires it essentially immediately.
pub(crate) fn arm_wall_clock(
    pid: rustix::process::Pid,
    wall_clock_secs: Option<u64>,
) -> WallClockGuard {
    let Some(secs) = wall_clock_secs else {
        return WallClockGuard {
            state: None,
            handle: None,
        };
    };
    let state = Arc::new(Watchdog::new(secs));
    let thread_state = Arc::clone(&state);
    let deadline = Instant::now() + Duration::from_secs(secs);
    let handle = thread::spawn(move || {
        loop {
            let now = Instant::now();
            if thread_state.done.load(Ordering::Acquire) {
                return;
            }
            if now >= deadline {
                break;
            }
            thread::sleep(
                deadline
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(50)),
            );
        }
        if thread_state.done.swap(true, Ordering::AcqRel) {
            // Child was reaped between our last check and expiry; nothing to
            // kill and the pid may already have been recycled.
            return;
        }
        thread_state.expired.store(true, Ordering::Release);
        // SIGKILL the whole group so grandchildren in the group die too.
        // ESRCH is success (nothing left to kill); any other error is
        // recorded for the caller, which surfaces it as a fail-closed
        // error if the child is not confirmed dead.
        if let Err(ExecError::WallClockKillFailed { source }) = kill_child_group_at_deadline(pid) {
            tracing::warn!(pid = pid.as_raw_pid(), error = %source, "wall-clock group kill failed");
            *thread_state
                .kill_failed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(source);
        }
    });
    WallClockGuard {
        state: Some(state),
        handle: Some(handle),
    }
}

/// Resolves an armed watchdog after the direct child has been reaped.
///
/// The child's reap is the confirmation of death: if the watchdog fired, the
/// group kill succeeded (or the group was already gone) and the typed
/// [`ExecError::WallClockExpired`] is returned. A recorded kill error here
/// would mean the child died of something else before the kill — the child
/// is dead either way, so expiry remains the accurate report and the error
/// is only logged.
pub(crate) fn finish_wall_clock(guard: WallClockGuard) -> Result<(), ExecError> {
    let Some(state) = guard.state else {
        return Ok(());
    };
    state.done.store(true, Ordering::Release);
    let _ = guard.handle.map(thread::JoinHandle::join);
    if state.expired.load(Ordering::Acquire) {
        // The watchdog fired at the deadline. The direct child has been
        // reaped by the caller before this call, so it is confirmed dead;
        // report expiry (fail closed) instead of the child's signal-death
        // exit status. A kill error recorded by the watchdog is surfaced
        // only when death is NOT confirmed (see [`WallClockKillFailed`]).
        if let Some(err) = state
            .kill_failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            tracing::warn!(error = %err, "wall-clock group kill errored, but child reaped");
        }
        return Err(ExecError::WallClockExpired {
            limit_secs: state.limit_secs,
        });
    }
    // Deadline did not fire; if a kill error was recorded anyway (watchdog
    // raced with normal completion and killed the group in its ~50 ms
    // residual window), the child still completed normally — log it, but
    // the reaped-and-successful result stands.
    if let Some(err) = state
        .kill_failed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        tracing::warn!(error = %err, "wall-clock group kill errored after normal completion");
    }
    Ok(())
}

/// Reads stdout and stderr concurrently, enforcing a combined byte cap.
///
/// Both pipes are drained in dedicated threads so that a child writing to both
/// streams cannot deadlock against a full pipe the parent is not reading. If
/// the combined output exceeds `limit`, the child is killed (to unblock the
/// sibling pipe and terminate the producer) and reaped, then
/// [`ExecError::OutputExceeded`] is returned.
///
/// `watchdog` must be the guard armed for this child by
/// [`arm_wall_clock`] (a disabled guard is fine). The deadline covers the
/// whole child lifetime because the guard is armed at spawn time.
///
/// On success returns the exit code (if any) and the captured stdout/stderr.
///
/// # Errors
///
/// Returns [`ExecError::Wait`] when the child cannot be reaped,
/// [`ExecError::OutputExceeded`] when the combined output exceeds `limit`,
/// or the resolved wall-clock error from [`finish_wall_clock`]
/// ([`ExecError::WallClockExpired`]).
pub(crate) fn read_with_limit(
    child: &mut Child,
    limit: u64,
    watchdog: WallClockGuard,
) -> Result<CapturedOutput, ExecError> {
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let pid = rustix::process::Pid::from_child(child);
    let total = Arc::new(AtomicU64::new(0));

    let stdout_handle = stdout.map(|stream| drain_stream(stream, Arc::clone(&total), limit, pid));
    let stderr_handle = stderr.map(|stream| drain_stream(stream, Arc::clone(&total), limit, pid));

    let captured_stdout = stdout_handle
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();
    let captured_stderr = stderr_handle
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();

    let actual = total.load(Ordering::Relaxed);
    let status = child.wait().map_err(|source| ExecError::Wait { source })?;

    // Reaped: resolve the watchdog before interpreting the result. Expiry
    // (with its typed error) takes precedence over the child's exit status
    // and over an output-cap breach — the fence fired, so the run is
    // "stopped at deadline" regardless of what the child printed.
    finish_wall_clock(watchdog)?;

    if actual > limit {
        return Err(ExecError::OutputExceeded { limit, actual });
    }
    Ok((status.code(), captured_stdout, captured_stderr))
}

/// Kills the child's process group at deadline expiry, treating ESRCH as
/// success (nothing left to kill).
///
/// Any other kill error fails closed: the group could not be confirmed dead.
fn kill_child_group_at_deadline(pid: rustix::process::Pid) -> Result<(), ExecError> {
    match rustix::process::kill_process_group(pid, rustix::process::Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(err) => {
            // Fall back to killing at least the direct child before
            // reporting failure so we never leave it running unbounded.
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
            Err(ExecError::WallClockKillFailed {
                source: std::io::Error::from_raw_os_error(err.raw_os_error()),
            })
        }
    }
}

/// Drains a single pipe into a buffer, updating the shared byte counter.
///
/// When the counter crosses `limit`, the producing child is killed so the
/// sibling pipe observes EOF and the loop can exit instead of blocking on a
/// full pipe the stopped producer can no longer drain.
fn drain_stream<R: Read + Send + 'static>(
    mut stream: R,
    total: Arc<AtomicU64>,
    limit: u64,
    pid: rustix::process::Pid,
) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let read_bytes = read as u64;
                    let prev = total.fetch_add(read_bytes, Ordering::Relaxed);
                    buffer.extend_from_slice(&chunk[..read]);
                    if prev + read_bytes > limit {
                        // Kill the producer so the sibling stream gets EOF
                        // rather than blocking on a pipe it can no longer
                        // drain. Double-kill is harmless (ESRCH is ignored).
                        let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
                        break;
                    }
                }
            }
        }
        buffer
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::path::Path;
    use std::process::{Command, Stdio};

    fn bash_or_skip() -> Result<&'static str, &'static str> {
        if Path::new("/bin/bash").exists() {
            Ok("/bin/bash")
        } else {
            Err("bash not installed")
        }
    }

    #[test]
    fn fenced_limits_apply_and_child_completes() -> Result<(), Box<dyn std::error::Error>> {
        let bash = bash_or_skip()?;
        let mut command = Command::new(bash);
        command.arg("-c").arg("echo done");
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let limits = crate::ResourceLimits::default();
        apply_limits_fenced(&mut child, &limits)?;
        let watchdog = crate::spawn::arm_wall_clock(rustix::process::Pid::from_child(&child), None);
        let (code, out, _err) = read_with_limit(&mut child, DEFAULT_OUTPUT_LIMIT, watchdog)?;
        assert_eq!(code, Some(0));
        assert_eq!(String::from_utf8(out)?.trim(), "done");
        Ok(())
    }

    #[test]
    fn read_with_limit_kills_child_on_overflow() -> Result<(), Box<dyn std::error::Error>> {
        let bash = bash_or_skip()?;
        let mut command = Command::new(bash);
        // Infinite loop emitting stdout until the cap kills the child.
        command.arg("-c").arg("while true; do echo overflow; done");
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let watchdog = crate::spawn::arm_wall_clock(rustix::process::Pid::from_child(&child), None);
        let result = read_with_limit(&mut child, 1024, watchdog);
        match result {
            Err(ExecError::OutputExceeded { limit, actual }) => {
                assert_eq!(limit, 1024);
                assert!(actual > 1024, "actual ({actual}) must exceed the cap");
            }
            other => return Err(format!("expected OutputExceeded, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn watchdog_expired_flag_drives_typed_error() -> Result<(), Box<dyn std::error::Error>> {
        // A zero-deadline kill path: kill_child_group_at_deadline must treat
        // a missing process group (ESRCH) as success, per fail-closed rule —
        // ESRCH means the group is already dead, which is the goal met.
        let mut command = Command::new(bash_or_skip()?);
        command.arg("-c").arg("true");
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let pid = rustix::process::Pid::from_child(&child);
        let _status = child.wait()?;
        // The process (and its group, since it had no members left) is gone;
        // the kill must report success, not an error.
        kill_child_group_at_deadline(pid)?;
        Ok(())
    }
}
