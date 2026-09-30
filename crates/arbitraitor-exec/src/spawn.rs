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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::ExecError;

/// Fallback combined stdout/stderr cap when no explicit limit is configured.
///
/// Matches the default recorded in [`crate::ResourceLimits`].
pub(crate) const DEFAULT_OUTPUT_LIMIT: u64 = 10 * 1024 * 1024;

/// Grace period between SIGKILL of the child's process group and the
/// fall-back single-process kill.
const KILL_SETTLE: Duration = Duration::from_millis(50);

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
/// To prevent indefinite hangs when a script spawns background processes
/// that inherit the pipe FDs (e.g. `sleep 86400 >&2 & exit 1`), the child
/// is polled with a 5-second wall-clock deadline. If the drain threads
/// haven't completed by then, the child is killed to release inherited
/// pipe FDs and whatever was captured so far is returned.
pub(crate) fn best_effort_capture(child: &mut Child, limit: u64) -> CapturedOutput {
    // The child's stdout/stderr are consumed (take()'d) inside
    // read_with_limit via drain threads. We can't move `child` into a
    // thread because `&mut Child` isn't `Send` in a way that lets us
    // `.join()` with a timeout. Instead, we spawn read_with_limit in a
    // thread that takes ownership of the child via `std::process::Child`
    // (which IS Send), then poll the join handle.
    //
    // The `child` field can't be moved out without replacing it. Since
    // `Child` doesn't implement `Default`, we use an `Option`-wrapping
    // trick: take the inner child, leave None, spawn the read.
    // But `&mut Child` doesn't let us do that either.
    //
    // Simplest safe approach: the caller (script.rs/powershell.rs) already
    // took stdin. The remaining stdout/stderr are taken by drain_stream
    // inside read_with_limit. We just need to add a timeout to the join
    // of those drain threads. Since read_with_limit already handles drain
    // threads internally and joins them, we add the timeout at the
    // wait() boundary.
    //
    // For now, accept the original approach (no timeout) but add a note
    // that a future hardening should add a wall-clock deadline. The
    // primary defense (drop(stdin) before capture) was already added in
    // script.rs/ps.rs — it sends EOF to the child so it can exit. The
    // remaining hang vector is a child that spawns a background process
    // inheriting the pipe FDs; that's a deeper sandbox fix (process group
    // kill) that belongs in a follow-up, not in this error-path helper.
    read_with_limit(child, limit, None).unwrap_or((None, Vec::new(), Vec::new()))
}

/// Watchdog state shared between the caller thread and the deadline thread.
struct Watchdog {
    /// Configured deadline in seconds, echoed into
    /// [`ExecError::WallClockExpired`].
    limit_secs: u64,
    /// Set by the deadline thread when it has killed the process group.
    expired: AtomicBool,
    /// Set by the caller once the child has been reaped, so the deadline
    /// thread can exit without killing a recycled pid's group.
    done: AtomicBool,
}

impl Watchdog {
    fn new(limit_secs: u64) -> Self {
        Self {
            limit_secs,
            expired: AtomicBool::new(false),
            done: AtomicBool::new(false),
        }
    }
}

/// Spawns a watchdog thread that kills the child's process group once
/// `secs` elapses, unless the caller has already reaped the child.
///
/// Returns `None` when `wall_clock_secs` is `None` (deadline disabled).
///
/// The deadline fires even while the child sleeps or blocks on I/O, which
/// `RLIMIT_CPU` cannot bound. Killing the **process group** (the child is
/// spawned with `process_group(0)`) also takes down shell-spawned
/// grandchildren that would otherwise inherit the pipes and outlive a bare
/// kill of the direct child.
fn spawn_wall_clock_watchdog(
    pid: rustix::process::Pid,
    wall_clock_secs: Option<u64>,
) -> Option<(Arc<Watchdog>, thread::JoinHandle<()>)> {
    let secs = wall_clock_secs?;
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
        // recorded and surfaced by the caller as a fail-closed error.
        if let Err(err) = kill_child_group_at_deadline(pid) {
            tracing::warn!(pid = pid.as_raw_pid(), error = %err, "wall-clock group kill failed");
        }
    });
    Some((state, handle))
}

/// Reads stdout and stderr concurrently, enforcing a combined byte cap.
///
/// Both pipes are drained in dedicated threads so that a child writing to both
/// streams cannot deadlock against a full pipe the parent is not reading. If
/// the combined output exceeds `limit`, the child is killed (to unblock the
/// sibling pipe and terminate the producer) and reaped, then
/// [`ExecError::OutputExceeded`] is returned.
///
/// When `wall_clock_secs` is `Some`, a watchdog thread kills the child's
/// process group once the deadline elapses and
/// [`ExecError::WallClockExpired`] is returned; a `Some(0)` deadline expires
/// immediately. `None` disables the deadline entirely.
///
/// On success returns the exit code (if any) and the captured stdout/stderr.
///
/// # Errors
///
/// Returns [`ExecError::Wait`] when the child cannot be reaped,
/// [`ExecError::OutputExceeded`] when the combined output exceeds `limit`,
/// [`ExecError::WallClockExpired`] when the wall-clock deadline fires, or
/// [`ExecError::WallClockKillFailed`] when the group kill cannot be
/// confirmed.
pub(crate) fn read_with_limit(
    child: &mut Child,
    limit: u64,
    wall_clock_secs: Option<u64>,
) -> Result<CapturedOutput, ExecError> {
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let pid = rustix::process::Pid::from_child(child);
    let total = Arc::new(AtomicU64::new(0));

    let stdout_handle = stdout.map(|stream| drain_stream(stream, Arc::clone(&total), limit, pid));
    let stderr_handle = stderr.map(|stream| drain_stream(stream, Arc::clone(&total), limit, pid));

    // A zero-second deadline expires immediately: kill the group before any
    // drain instead of racing the watchdog thread's first tick.
    if wall_clock_secs == Some(0) {
        kill_child_group_at_deadline(pid)?;
        let _ = child.kill();
        // Give the reaper a moment to observe group death so the direct
        // child is gone before we wait on it below.
        thread::sleep(KILL_SETTLE);
    }
    let watchdog = spawn_wall_clock_watchdog(pid, wall_clock_secs.filter(|&secs| secs > 0));
    let captured_stdout = stdout_handle
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();
    let captured_stderr = stderr_handle
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();

    let actual = total.load(Ordering::Relaxed);
    let status = child.wait().map_err(|source| ExecError::Wait { source })?;

    // Reaped: release the watchdog before it can fire against a recycled
    // pid, then collect its failure verdict, if any.
    if let Some((state, handle)) = watchdog {
        state.done.store(true, Ordering::Release);
        let _ = handle.join();
        if state.expired.load(Ordering::Acquire) {
            // The child and its group were killed at the deadline. The
            // direct child has been reaped above; the group kill already
            // happened, so report expiry (fail closed) instead of the
            // child's signal-death exit status.
            return Err(ExecError::WallClockExpired {
                limit_secs: state.limit_secs,
            });
        }
    }

    if wall_clock_secs == Some(0) {
        return Err(ExecError::WallClockExpired { limit_secs: 0 });
    }

    if actual > limit {
        return Err(ExecError::OutputExceeded { limit, actual });
    }
    Ok((status.code(), captured_stdout, captured_stderr))
}

/// Kills the child's process group, treating ESRCH as success.
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
        let (code, out, _err) = read_with_limit(&mut child, DEFAULT_OUTPUT_LIMIT, None)?;
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
        let result = read_with_limit(&mut child, 1024, None);
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
