//! Platform sandbox adapters for contained execution
//!
//! See `.spec/` for the full specification.

#![deny(unsafe_code)]
#![warn(missing_docs)]

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

/// Apply privilege hardening to the current process via `pre_exec`.
///
/// This function is designed to be called from `CommandExt::pre_exec()`.
/// It must remain async-signal-safe: no allocation, no locks, and no calls into
/// code that is not safe between `fork` and `exec`.
///
/// # Errors
///
/// Returns the last OS error when a required `prctl` call fails.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn apply_privilege_hardening() -> io::Result<()> {
    set_no_new_privs()?;
    set_dumpable(false)
}

/// Close all inherited file descriptors except stdin, stdout, and stderr.
///
/// This function is designed for use from `CommandExt::pre_exec()`. It first
/// attempts Linux `close_range(2)` and falls back to a bounded close loop for
/// older kernels.
///
/// # Errors
///
/// Returns the OS error reported by `sysconf(_SC_OPEN_MAX)` when that call
/// fails for a reason other than an indeterminate limit.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn close_inherited_fds() -> io::Result<()> {
    // SAFETY: `sysconf`, `syscall(SYS_close_range)`, and `close` are async-signal-safe
    // libc/kernel calls. File descriptors are raw process-local integers; closing
    // descriptors >= 3 preserves the stdio descriptors already prepared by `Command`.
    unsafe {
        let open_max = libc::sysconf(libc::_SC_OPEN_MAX);
        let max_fd = if open_max > 0 {
            u32::try_from(open_max).unwrap_or(u32::MAX)
        } else {
            1024
        };

        let ret = libc::syscall(libc::SYS_close_range, 3_u32, max_fd, 0_u32);
        if ret == 0 {
            return Ok(());
        }

        for fd in 3..max_fd {
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
}
