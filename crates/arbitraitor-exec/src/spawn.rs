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

use std::io::{Read, Write};
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
    /// Shared with the output-drain threads: set by the deadline thread
    /// after the group kill so a drain blocked on a pipe held open by an
    /// out-of-group descendant (a `setsid` survivor the kill cannot reach)
    /// wakes and exits promptly instead of hanging the parent past the
    /// deadline.
    drain_expired: Arc<AtomicBool>,
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
            drain_expired: Arc::new(AtomicBool::new(false)),
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

impl Drop for WallClockGuard {
    fn drop(&mut self) {
        // Every exit path must stop the watchdog: a caller that drops the
        // guard without reaching [`finish_wall_clock`] (e.g. an early
        // `?` on a wait error) must not leave the deadline thread running
        // until expiry and killing a possibly recycled pid's group. The
        // handle is dropped without joining: the thread observes `done`
        // within one poll interval (~50 ms) and exits on its own.
        if let Some(state) = self.state.take() {
            state.done.store(true, Ordering::Release);
        }
    }
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
    // `Duration::from_secs` + `Instant` addition panics on overflow; a
    // caller can pass `Some(u64::MAX)` through the public API, so treat an
    // unrepresentable deadline as no deadline instead of panicking.
    let Some(deadline) = Instant::now().checked_add(Duration::from_secs(secs)) else {
        return WallClockGuard {
            state: None,
            handle: None,
        };
    };
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
        // Wake the output-drain threads only after the kill has been
        // attempted: a drain blocked on a pipe write-end still held by an
        // out-of-group descendant (e.g. a `setsid` survivor) observes this
        // flag and exits promptly with its partial bytes instead of
        // blocking the parent past the deadline.
        thread_state.drain_expired.store(true, Ordering::Release);
    });
    WallClockGuard {
        state: Some(state),
        handle: Some(handle),
    }
}

/// Resolves an armed watchdog after the wall-clock window ended.
///
/// `death_confirmed` reports whether the caller reaped the direct child
/// before calling. Reap is the confirmation of death: with it, a watchdog
/// firing means the group kill succeeded (or the group was already gone) and
/// the typed [`ExecError::WallClockExpired`] is returned — a recorded kill
/// error would mean the child died of something else before the kill, so the
/// error is only logged. Without it (`death_confirmed == false`, e.g. the
/// best-effort capture after a blocked stdin write could not reap), an
/// expiry paired with a recorded kill error fails closed as
/// [`ExecError::WallClockKillFailed`]: the child may still be alive, so
/// reporting "was killed" would be a false claim.
pub(crate) fn finish_wall_clock(
    guard: WallClockGuard,
    death_confirmed: bool,
) -> Result<(), ExecError> {
    let mut guard = guard;
    let Some(state) = guard.state.take() else {
        return Ok(());
    };
    state.done.store(true, Ordering::Release);
    let _ = guard.handle.take().map(thread::JoinHandle::join);
    if state.expired.load(Ordering::Acquire) {
        // The watchdog fired at the deadline. Fail closed when the kill
        // errored AND death is unconfirmed: the child may still be running,
        // so expiry ("was killed") would misreport. When the caller reaped
        // the child first, death is confirmed and expiry is the accurate
        // report even if the kill errored (the child died of something else
        // before or despite the kill).
        let kill_failed = state
            .kill_failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let (Some(err), true) = (&kill_failed, death_confirmed) {
            tracing::warn!(error = %err, "wall-clock group kill errored, but child reaped");
        }
        if let (Some(err), false) = (kill_failed, death_confirmed) {
            return Err(ExecError::WallClockKillFailed { source: err });
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

/// Writes script bytes to a child's stdin under the wall-clock deadline.
///
/// A plain blocking `write_all` does not observe the watchdog: if the child
/// exits without reading stdin (or a surviving `setsid` descendant keeps the
/// pipe's read end open), the 64 KiB pipe buffer fills and the parent blocks
/// in the kernel past the deadline — `WallClockExpired` would never be
/// produced. This helper flips the stdin fd to non-blocking and writes in a
/// loop that polls the watchdog's shared expiry flag (raised by the deadline
/// thread after the process-group kill), so the write is bounded by the same
/// deadline that bounds output collection.
///
/// On success the bytes are fully written and flushed (best-effort flush:
/// a flush failure is reported like a write failure). On watchdog expiry the
/// remaining bytes are lost, the caller's stdin handle should be dropped, and
/// the error is the resolved wall-clock error from [`finish_wall_clock`]
/// ([`ExecError::WallClockExpired`], or the fail-closed
/// [`ExecError::WallClockKillFailed`] when the group kill errored and death
/// is unconfirmed) — the caller must not treat this as script I/O failure.
/// Any other I/O error is returned as-is and resolved by the caller through
/// its existing stdin-write-failure path.
///
/// # Errors
///
/// Returns the resolved wall-clock error on expiry, or the underlying
/// [`std::io::Error`] for genuine write/flush failures.
pub(crate) fn write_stdin_with_deadline<W: Write + std::os::unix::io::AsFd>(
    mut stdin: W,
    bytes: &[u8],
    watchdog: &mut WallClockGuard,
) -> Result<(), StdinWriteError> {
    // Non-blocking is best-effort: on failure fall back to blocking writes.
    // The flag is then only observed between chunk writes that made
    // progress, but the deadline thread's group kill still bounds the run
    // (a blocked write then unblocks with EPIPE or an I/O error once the
    // read end closes).
    let deadline_aware = watchdog.state.is_some();
    if deadline_aware && let Err(error) = set_nonblocking(&stdin) {
        tracing::warn!(error = %error, "could not set stdin non-blocking for deadline-aware write");
    }
    let expired = watchdog
        .state
        .as_ref()
        .map(|state| Arc::clone(&state.drain_expired));

    let mut written = 0_usize;
    while written < bytes.len() {
        if expired
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            // The deadline thread has killed the process group. Resolve the
            // watchdog now: the remaining bytes are lost, and the caller
            // reports expiry instead of a misleading ScriptIo.
            return Err(StdinWriteError::Deadline);
        }
        match stdin.write(&bytes[written..]) {
            Ok(0) => {
                // A non-blocking write returning 0 means the pipe is full
                // and would block; sleep one poll interval so the expiry
                // flag is re-checked promptly.
                thread::sleep(Duration::from_millis(DRAIN_POLL_INTERVAL_MS));
            }
            Ok(n) => written += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(DRAIN_POLL_INTERVAL_MS));
            }
            Err(error) => return Err(StdinWriteError::Io(error)),
        }
    }
    // The script bytes are in the kernel pipe buffer; the flush merely
    // preserves the historical "flush after write" step and must not be
    // allowed to outlive the deadline either.
    if expired
        .as_ref()
        .is_some_and(|flag| flag.load(Ordering::Acquire))
    {
        return Err(StdinWriteError::Deadline);
    }
    match stdin.flush() {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            // The bytes are already in the kernel pipe buffer; a WouldBlock
            // flush cannot be waited out without re-entering a loop the
            // deadline no longer bounds, and there is nothing left to push.
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(()),
        Err(error) => Err(StdinWriteError::Io(error)),
    }
}

/// Failure of a deadline-aware stdin write ([`write_stdin_with_deadline`]).
pub(crate) enum StdinWriteError {
    /// The wall-clock deadline fired during the write. The watchdog has
    /// been resolved; the caller reaps the child through
    /// [`read_with_limit`], whose own [`finish_wall_clock`] call surfaces
    /// the typed expiry (`WallClockExpired`, or the fail-closed
    /// `WallClockKillFailed`).
    Deadline,
    /// A genuine write or flush I/O failure; resolved by the caller through
    /// its existing stdin-write-failure path.
    Io(std::io::Error),
}

/// Reads stdout and stderr concurrently, enforcing a combined byte cap and
/// honoring the wall-clock deadline.
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
/// Expiry bounds the parent even when a descendant escaped the process group:
/// a `setsid` survivor keeps the pipes' write-ends open, so an unbounded
/// blocking read would hang past the deadline. Instead the deadline thread
/// kills the group, then raises [`Watchdog::drain_expired`], which the drain
/// threads poll (they never block on a read for more than one poll interval)
/// so they exit promptly with whatever partial bytes they captured. The main
/// thread reaps the child directly (never joins the drains first) and joins
/// the drains only afterwards, when the flag guarantees they are finishing.
///
/// If the child exits normally first, the flag is never set and the drains
/// end at EOF exactly as before.
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
    // `None` when the deadline is disabled: the drains then run to EOF (the
    // historical behavior — the caller opted out of the fence).
    let drain_flag = watchdog
        .state
        .as_ref()
        .map(|state| Arc::clone(&state.drain_expired));
    let drain_expired = drain_flag.as_ref();

    let stdout_handle =
        stdout.map(|stream| drain_stream(stream, Arc::clone(&total), limit, pid, drain_expired));
    let stderr_handle =
        stderr.map(|stream| drain_stream(stream, Arc::clone(&total), limit, pid, drain_expired));

    // Reap the direct child FIRST: joining the drains here would let an
    // out-of-group descendant holding a pipe write-end block the parent past
    // the deadline. The drains are guaranteed to exit soon after expiry (the
    // flag) or EOF (normal completion), so they are joined after the reap.
    let status = child.wait().map_err(|source| ExecError::Wait { source })?;
    let captured_stdout = stdout_handle.map(|handle| handle.join().unwrap_or_default());
    let captured_stderr = stderr_handle.map(|handle| handle.join().unwrap_or_default());

    let actual = total.load(Ordering::Relaxed);

    // Reaped: resolve the watchdog before interpreting the result. Expiry
    // (with its typed error) takes precedence over the child's exit status
    // and over an output-cap breach — the fence fired, so the run is
    // "stopped at deadline" regardless of what the child printed. The
    // successful reap confirms death.
    finish_wall_clock(watchdog, true)?;

    if actual > limit {
        return Err(ExecError::OutputExceeded { limit, actual });
    }
    Ok((
        status.code(),
        captured_stdout.unwrap_or_default(),
        captured_stderr.unwrap_or_default(),
    ))
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
/// sibling stream observes EOF and the loop can exit instead of blocking on a
/// full pipe the stopped producer can no longer drain.
///
/// `expired` bounds the drain against the wall-clock deadline: when set (by
/// the deadline thread after the process-group kill), the drain exits
/// promptly with its partial bytes even though an out-of-group descendant
/// (a `setsid` survivor the group kill cannot reach) still holds a write-end
/// of the pipe. With a flag, the fd is flipped to `O_NONBLOCK` so reads never
/// block: each iteration re-checks the flag and sleeps
/// [`DRAIN_POLL_INTERVAL_MS`] between would-block attempts, so the drain
/// observes expiry within one poll interval. Without a flag (`None`,
/// deadline disabled) the drain is the historical blocking read-to-EOF loop.
fn drain_stream<R: Read + std::os::unix::io::AsFd + Send + 'static>(
    stream: R,
    total: Arc<AtomicU64>,
    limit: u64,
    pid: rustix::process::Pid,
    expired: Option<&Arc<AtomicBool>>,
) -> thread::JoinHandle<Vec<u8>> {
    let deadline_aware = expired.is_some();
    let expired = expired.cloned();
    thread::spawn(move || {
        let mut stream = stream;
        // Non-blocking setup is best-effort: on failure fall back to
        // blocking reads. The flag is then only observed between reads that
        // return data, but the overall run is still bounded by the deadline
        // thread's group kill.
        let setup = if deadline_aware {
            set_nonblocking(&stream)
        } else {
            Ok(())
        };
        if let Err(error) = setup {
            // Best-effort: fcntl failures are not expected on the freshly
            // created pipes this crate spawns, but if one occurs, fall back
            // to blocking reads. The flag is then only observed between
            // reads that return data, so the partial-output bound holds only
            // when no out-of-group descendant survives holding the pipe —
            // the overall run is still bounded by the deadline thread's
            // group kill.
            tracing::warn!(error = %error, "could not set pipe non-blocking for deadline-aware drain");
        }
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            if expired
                .as_ref()
                .is_some_and(|flag| flag.load(Ordering::Acquire))
            {
                break;
            }
            match stream.read(&mut chunk) {
                // Non-blocking pipe with no data yet: sleep one poll
                // interval so the expiry flag is re-checked promptly.
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(DRAIN_POLL_INTERVAL_MS));
                }
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

/// Milliseconds between expiry-flag checks in the deadline-aware drain loop.
const DRAIN_POLL_INTERVAL_MS: u64 = 25;

/// Flips a readable stream's fd to non-blocking mode so reads return
/// immediately instead of blocking while the expiry flag is pending.
fn set_nonblocking(stream: &impl std::os::unix::io::AsFd) -> std::io::Result<()> {
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

    let fd = stream.as_fd();
    let mut flags = fcntl_getfl(fd).map_err(rustix_to_io_error)?;
    flags.insert(OFlags::NONBLOCK);
    fcntl_setfl(fd, flags).map_err(rustix_to_io_error)
}

/// Converts a rustix error into a [`std::io::Error`].
fn rustix_to_io_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use std::os::unix::process::CommandExt;
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

    /// Resolves when the `setsid` helper binary is installed, else `Err`
    /// (callers skip the test).
    fn setsid_or_skip() -> Result<&'static str, &'static str> {
        if Path::new("/usr/bin/setsid").exists() {
            Ok("/usr/bin/setsid")
        } else if Path::new("/bin/setsid").exists() {
            Ok("/bin/setsid")
        } else {
            Err("setsid not installed")
        }
    }

    #[test]
    fn deadline_bounds_drain_when_setsid_descendant_holds_stdout()
    -> Result<(), Box<dyn std::error::Error>> {
        // Regression test for the CodeRabbit finding: a descendant that
        // escapes the process group (setsid) inherits the pipe write-ends,
        // so the group kill cannot end its output and an EOF-blocking drain
        // would hang the parent past the deadline. The drain must observe
        // the shared expiry flag and exit promptly; the call must return
        // WallClockExpired in bounded time.
        let bash = bash_or_skip()?;
        let setsid = setsid_or_skip()?;
        let mut command = Command::new(bash);
        command.arg("-c").arg(format!(
            // A grandchild in a new session (the group kill cannot reach it)
            // that inherits and holds the pipe write-ends forever — no
            // redirect, unlike a well-behaved daemon — plus a marker byte so
            // the drain has captured data at expiry. Mirrors production
            // wiring with process_group(0).
            "{setsid} sleep 30 &\n\
             echo started\n\
             exec sleep 30\n"
        ));
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.process_group(0);
        let mut child = command.spawn()?;
        let watchdog =
            crate::spawn::arm_wall_clock(rustix::process::Pid::from_child(&child), Some(1));
        let started = std::time::Instant::now();
        let result = read_with_limit(&mut child, DEFAULT_OUTPUT_LIMIT, watchdog);
        let elapsed = started.elapsed();
        match result {
            Err(ExecError::WallClockExpired { limit_secs: 1 }) => {}
            Err(ExecError::WallClockExpired { limit_secs }) => {
                return Err(format!("expected limit_secs 1, got {limit_secs}").into());
            }
            other => {
                return Err(format!("expected WallClockExpired, got {other:?}").into());
            }
        }
        assert!(
            elapsed < Duration::from_secs(10),
            "expiry must bound the parent even with an out-of-group pipe holder: {elapsed:?}"
        );
        Ok(())
    }

    #[test]
    fn kill_child_group_treats_esrch_as_success() -> Result<(), Box<dyn std::error::Error>> {
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

    #[test]
    fn dropping_guard_disarms_watchdog() {
        // Regression test for the CodeRabbit finding: a caller that drops
        // the guard without calling finish_wall_clock (an early `?` on a
        // wait error) must disarm the watchdog, or the deadline thread
        // would keep running until expiry and kill a possibly recycled
        // pid's group.
        let guard = arm_wall_clock(
            rustix::process::Pid::from_raw(1).expect("pid 1 is valid"),
            Some(1),
        );
        let state = Arc::clone(guard.state.as_ref().expect("armed state"));
        assert!(!state.done.load(Ordering::Acquire));
        drop(guard);
        // Dropping disarms: the deadline thread observes `done` on its next
        // poll (~50 ms) and exits without killing anything.
        assert!(state.done.load(Ordering::Acquire));
    }

    #[test]
    fn unconfirmed_death_with_kill_error_fails_closed() {
        // finish_wall_clock must return WallClockKillFailed when the
        // watchdog fired, the group kill errored (non-ESRCH), and the
        // caller could NOT reap the child (death unconfirmed): reporting
        // "was killed" (WallClockExpired) would be a false claim.
        let guard = arm_wall_clock(
            rustix::process::Pid::from_raw(1).expect("pid 1 is valid"),
            Some(3600),
        );
        let state = Arc::clone(guard.state.as_ref().expect("armed state"));
        // Simulate the deadline thread: expiry fired but the kill failed.
        state.expired.store(true, Ordering::Release);
        *state
            .kill_failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(std::io::Error::from_raw_os_error(libc::EPERM));
        let result = finish_wall_clock(guard, false);
        match result {
            Err(ExecError::WallClockKillFailed { source }) => {
                assert_eq!(
                    source.raw_os_error(),
                    Some(libc::EPERM),
                    "the kill error must be surfaced: {source}"
                );
            }
            other => {
                panic!("expected WallClockKillFailed, got {other:?}");
            }
        }
    }

    #[test]
    fn confirmed_death_reports_expiry_despite_kill_error() {
        // With death confirmed (child reaped), a recorded kill error is only
        // logged: the child is dead either way, so expiry is the accurate
        // report.
        let guard = arm_wall_clock(
            rustix::process::Pid::from_raw(1).expect("pid 1 is valid"),
            Some(3600),
        );
        let state = Arc::clone(guard.state.as_ref().expect("armed state"));
        state.expired.store(true, Ordering::Release);
        *state
            .kill_failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(std::io::Error::from_raw_os_error(libc::EPERM));
        let result = finish_wall_clock(guard, true);
        match result {
            Err(ExecError::WallClockExpired { limit_secs: 3600 }) => {}
            other => {
                panic!("expected WallClockExpired{{limit_secs: 3600}}, got {other:?}");
            }
        }
    }

    #[test]
    fn unrepresentable_deadline_disables_watchdog() {
        // `Instant::now() + Duration::from_secs(u64::MAX)` would panic; the
        // overflow must be treated as "no deadline" (a disabled guard)
        // instead.
        let guard = arm_wall_clock(
            rustix::process::Pid::from_raw(1).expect("pid 1 is valid"),
            Some(u64::MAX),
        );
        assert!(guard.state.is_none());
        assert!(guard.handle.is_none());
    }
}
