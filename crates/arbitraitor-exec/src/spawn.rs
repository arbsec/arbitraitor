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
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use crate::ExecError;

/// Fallback combined stdout/stderr cap when no explicit limit is configured.
///
/// Matches the default recorded in [`crate::ResourceLimits`].
pub(crate) const DEFAULT_OUTPUT_LIMIT: u64 = 10 * 1024 * 1024;

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

/// Reads stdout and stderr concurrently, enforcing a combined byte cap.
///
/// Both pipes are drained in dedicated threads so that a child writing to both
/// streams cannot deadlock against a full pipe the parent is not reading. If
/// the combined output exceeds `limit`, the child is killed (to unblock the
/// sibling pipe and terminate the producer) and reaped, then
/// [`ExecError::OutputExceeded`] is returned.
///
/// On success returns the exit code (if any) and the captured stdout/stderr.
///
/// # Errors
///
/// Returns [`ExecError::Wait`] when the child cannot be reaped, or
/// [`ExecError::OutputExceeded`] when the combined output exceeds `limit`.
pub(crate) fn read_with_limit(child: &mut Child, limit: u64) -> Result<CapturedOutput, ExecError> {
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

    if actual > limit {
        return Err(ExecError::OutputExceeded { limit, actual });
    }
    Ok((status.code(), captured_stdout, captured_stderr))
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
        let (code, out, _err) = read_with_limit(&mut child, DEFAULT_OUTPUT_LIMIT)?;
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
        let result = read_with_limit(&mut child, 1024);
        match result {
            Err(ExecError::OutputExceeded { limit, actual }) => {
                assert_eq!(limit, 1024);
                assert!(actual > 1024, "actual ({actual}) must exceed the cap");
            }
            other => return Err(format!("expected OutputExceeded, got {other:?}").into()),
        }
        Ok(())
    }
}
