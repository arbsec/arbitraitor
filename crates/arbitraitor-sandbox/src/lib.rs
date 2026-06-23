//! Platform sandbox adapters for contained execution
//!
//! See `.spec/` for the full specification.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod landlock;
mod resource_limits;
mod seccomp;

pub use landlock::{PathRule, access_fs, configure_filesystem_isolation};
pub use resource_limits::{ProcessResourceLimits, configure_resource_limits};
pub use seccomp::configure_network_isolation;

use std::io;
use std::process::Command;

/// Privilege and isolation settings for child processes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxConfig {
    /// Prevent the child and its descendants from gaining new privileges via `execve`.
    pub no_new_privs: bool,
    /// Whether the child should remain dumpable by same-uid processes.
    pub dumpable: bool,
    /// Close all inherited file descriptors other than standard input, output, and error.
    pub close_fds: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            no_new_privs: true,
            dumpable: false,
            close_fds: true,
        }
    }
}

/// Close all inherited file descriptors except stdin, stdout, and stderr.
///
/// This function is designed for use from `CommandExt::pre_exec()`. It first
/// attempts Linux `close_range(2)`, passing `u32::MAX` as the upper bound so
/// the kernel closes every descriptor above the start regardless of any soft
/// `RLIMIT_NOFILE` the parent may have lowered *after* opening high
/// descriptors. On kernels that predate `close_range` (Linux < 5.9, signaled
/// by `ENOSYS`) it falls back to a `getrlimit(RLIMIT_NOFILE)`-bounded close
/// loop, capped at 1<<20 iterations.
///
/// # Errors
///
/// Returns the OS error reported by `close_range(2)` when it fails for any
/// reason other than `ENOSYS`. The fallback paths are best-effort: `close(2)`
/// errors on unopened descriptors are ignored, which is async-signal-safe.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn close_inherited_fds() -> io::Result<()> {
    // SAFETY: `syscall(SYS_close_range)`, `getrlimit`, and `close` are
    // async-signal-safe libc/kernel calls. They perform no heap allocation,
    // acquire no locks, and dereference no caller-controlled pointers
    // (`getrlimit` writes only to a stack-local `rlimit`). File descriptors
    // are raw process-local integers; closing descriptors >= 3 preserves the
    // stdio descriptors already prepared by `Command`.
    unsafe {
        // `u32::MAX` instructs the kernel to close every fd >= 3 regardless of
        // the current `RLIMIT_NOFILE`. A parent that opened high descriptors
        // and then lowered the soft limit would leak them past a scan bounded
        // by `sysconf(_SC_OPEN_MAX)` — that is CVE-class bug #192.
        let ret = libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32);
        if ret == 0 {
            return Ok(());
        }

        // Only fall back on `ENOSYS` (kernel predates `close_range`). Any
        // other failure — e.g. `EINVAL` from a malformed argument — is a real
        // bug and must propagate rather than be masked by a silent loop.
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOSYS) {
            return Err(err);
        }

        // `ENOSYS`: kernel < 5.9. Bound the loop with the current soft limit,
        // capped at 1<<20 to avoid pathological iteration on systems whose
        // `RLIM_INFINITY` resolves to a huge value. `getrlimit` is
        // async-signal-safe.
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rlim) == 0 {
            let cap: libc::rlim_t = 1 << 20;
            let max_fd = u32::try_from(rlim.rlim_cur.min(cap)).unwrap_or(u32::MAX);
            for fd in 3..max_fd {
                // EBADF on unopened descriptors is safe to ignore.
                let _ignored = libc::close(i32::try_from(fd).unwrap_or(i32::MAX));
            }
            return Ok(());
        }

        // Last resort (`getrlimit` failed): scan a small fixed window. This is
        // best-effort — descriptors above 1024 may leak — but it matches the
        // historical behavior of portable Unix child-spawning code on kernels
        // too old to support `close_range`.
        for fd in 3..1024_u32 {
            let _ignored = libc::close(i32::try_from(fd).unwrap_or(i32::MAX));
        }
    }
    Ok(())
}

/// Apply all sandbox hardening to the current process.
///
/// This function is intended to run inside `CommandExt::pre_exec()`, after the
/// child has been forked and before it executes untrusted code.
///
/// # Errors
///
/// Returns the first OS error raised by a requested sandbox operation.
#[cfg(target_os = "linux")]
pub fn apply_sandbox(config: &SandboxConfig) -> io::Result<()> {
    if config.no_new_privs {
        set_no_new_privs()?;
    }
    if !config.dumpable {
        set_dumpable(false)?;
    }
    if config.close_fds {
        close_inherited_fds()?;
    }
    Ok(())
}

/// Apply all sandbox hardening to the current process.
///
/// Non-Linux platforms currently have no in-process sandbox adapter.
///
/// # Errors
///
/// This implementation does not fail.
#[cfg(not(target_os = "linux"))]
pub fn apply_sandbox(_config: &SandboxConfig) -> io::Result<()> {
    Ok(())
}

/// Configure a command so sandbox hardening is applied in the child before `exec`.
///
/// This safe wrapper keeps the `CommandExt::pre_exec` unsafe boundary inside the
/// sandbox crate, preserving `unsafe_code = forbid` in execution broker crates.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn configure_command(command: &mut Command, config: SandboxConfig) {
    use std::os::unix::process::CommandExt;

    // SAFETY: The registered closure only calls `apply_sandbox`, whose Linux
    // implementation is restricted to async-signal-safe libc/kernel operations
    // and does not allocate or acquire locks between fork and exec.
    unsafe {
        command.pre_exec(move || apply_sandbox(&config));
    }
}

/// Configure a command so sandbox hardening is applied in the child before `exec`.
///
/// Non-Linux platforms currently have no in-process sandbox adapter.
#[cfg(not(target_os = "linux"))]
pub fn configure_command(_command: &mut Command, _config: SandboxConfig) {}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn set_no_new_privs() -> io::Result<()> {
    // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` is a well-defined Linux
    // process control operation that does not dereference pointers.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn set_dumpable(dumpable: bool) -> io::Result<()> {
    let value = i32::from(dumpable);
    // SAFETY: `prctl(PR_SET_DUMPABLE, value, 0, 0, 0)` is a well-defined Linux
    // process control operation that does not dereference pointers.
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, value, 0, 0, 0) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_secure_defaults() {
        let config = SandboxConfig::default();
        assert!(config.no_new_privs);
        assert!(!config.dumpable);
        assert!(config.close_fds);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn apply_sandbox_hardening_does_not_error() -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new("/bin/true");
        configure_command(
            &mut command,
            SandboxConfig {
                close_fds: false,
                ..SandboxConfig::default()
            },
        );
        let status = command.status()?;
        assert!(status.success());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn close_fds_prevents_fd_inheritance() -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::File;
        use std::os::unix::io::AsRawFd;

        // Open a probe descriptor in the parent that the child must NOT inherit
        // when close_fds is enabled. This exercises the close_range path.
        let probe = File::open("/dev/null")?;
        let probe_fd = probe.as_raw_fd();

        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(format!("test ! -e /proc/self/fd/{probe_fd}"));
        configure_command(&mut command, SandboxConfig::default());
        let status = command.status()?;
        assert!(
            status.success(),
            "child inherited fd {probe_fd} from parent despite close_fds = true"
        );
        Ok(())
    }
}
