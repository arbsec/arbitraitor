//! Linux Landlock filesystem isolation for child processes.
//!
//! Landlock is a stacked Linux Security Module (LSM) available on Linux 5.13+
//! that lets an unprivileged process restrict its own future filesystem access.
//! This module installs a deny-by-default ruleset in a `pre_exec` hook so only
//! the forked child (and its descendants) are constrained; the Arbitraitor host
//! process remains unrestricted.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr;

/// Landlock filesystem access flags.
///
/// These constants mirror Linux `LANDLOCK_ACCESS_FS_*` UAPI bits. The sandbox
/// masks requested access to the kernel-supported ABI version before creating
/// the ruleset and adding rules.
pub mod access_fs {
    /// Execute a file.
    pub const EXECUTE: u64 = 1 << 0;
    /// Open a file with write access.
    pub const WRITE_FILE: u64 = 1 << 1;
    /// Open a file with read access.
    pub const READ_FILE: u64 = 1 << 2;
    /// Open a directory or list its entries.
    pub const READ_DIR: u64 = 1 << 3;
    /// Remove an empty directory.
    pub const REMOVE_DIR: u64 = 1 << 4;
    /// Remove a file.
    pub const REMOVE_FILE: u64 = 1 << 5;
    /// Create a character device.
    pub const MAKE_CHAR: u64 = 1 << 6;
    /// Create a directory.
    pub const MAKE_DIR: u64 = 1 << 7;
    /// Create a regular file.
    pub const MAKE_REG: u64 = 1 << 8;
    /// Create a Unix-domain socket.
    pub const MAKE_SOCK: u64 = 1 << 9;
    /// Create a FIFO.
    pub const MAKE_FIFO: u64 = 1 << 10;
    /// Create a block device.
    pub const MAKE_BLOCK: u64 = 1 << 11;
    /// Create a symbolic link.
    pub const MAKE_SYM: u64 = 1 << 12;
    /// Reparent a file or directory across directories (ABI v2+).
    pub const REFER: u64 = 1 << 13;
    /// Truncate a file (ABI v3+).
    pub const TRUNCATE: u64 = 1 << 14;

    /// Read files and enumerate directories.
    pub const READ: u64 = READ_FILE | READ_DIR;
    /// Read files, enumerate directories, and execute files.
    pub const READ_EXECUTE: u64 = READ | EXECUTE;
    /// Read, write, create, remove, and execute beneath a writable work tree.
    pub const READ_WRITE_EXECUTE: u64 = READ_EXECUTE
        | WRITE_FILE
        | REMOVE_DIR
        | REMOVE_FILE
        | MAKE_CHAR
        | MAKE_DIR
        | MAKE_REG
        | MAKE_SOCK
        | MAKE_FIFO
        | MAKE_BLOCK
        | MAKE_SYM
        | REFER
        | TRUNCATE;
}

/// A path-beneath Landlock rule captured before `fork` and installed in the child.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathRule {
    /// The path under which access is granted.
    pub path: PathBuf,
    /// Bitmask of [`access_fs`] rights granted beneath [`Self::path`].
    pub access: u64,
}

impl PathRule {
    /// Creates a path rule with an explicit Landlock access bitmask.
    #[must_use]
    pub fn new(path: PathBuf, access: u64) -> Self {
        Self { path, access }
    }

    /// Grants read and execute access beneath `path`.
    #[must_use]
    pub fn read_execute(path: PathBuf) -> Self {
        Self::new(path, access_fs::READ_EXECUTE)
    }

    /// Grants read, write, create, remove, and execute access beneath `path`.
    #[must_use]
    pub fn read_write_execute(path: PathBuf) -> Self {
        Self::new(path, access_fs::READ_WRITE_EXECUTE)
    }
}

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const ABI_V1_ACCESS: u64 = (1_u64 << 13) - 1;
const ABI_V2_ACCESS: u64 = ABI_V1_ACCESS | access_fs::REFER;
const ABI_V3_ACCESS: u64 = ABI_V2_ACCESS | access_fs::TRUNCATE;

/// Registers a `pre_exec` closure that installs a Landlock ruleset.
///
/// On Linux kernels that support Landlock (5.13+), the child is denied all
/// governed filesystem access except the rights explicitly granted by `rules`.
/// On unsupported kernels, the hook returns success without installing a
/// ruleset so subprocess plugins degrade gracefully instead of failing to start.
#[cfg(target_os = "linux")]
pub fn configure_filesystem_isolation(command: &mut Command, rules: &[PathRule]) {
    use std::os::unix::process::CommandExt;

    let captured = capture_rules(rules);

    // SAFETY: The registered closure runs in the forked child between `fork`
    // and `execve`. It calls only async-signal-safe libc/kernel operations:
    // raw `syscall(2)`, `open(2)`, and `close(2)`. All allocation and path
    // conversion happen above, before the closure is registered.
    unsafe {
        command.pre_exec(move || install_landlock_ruleset(&captured));
    }
}

/// Registers a filesystem-isolation hook on unsupported platforms.
///
/// Non-Linux platforms currently have no Landlock adapter; callers may invoke
/// this unconditionally, but filesystem isolation is enforced only on Linux.
#[cfg(not(target_os = "linux"))]
pub fn configure_filesystem_isolation(_command: &mut Command, _rules: &[PathRule]) {}

#[cfg(target_os = "linux")]
fn capture_rules(rules: &[PathRule]) -> Vec<(CString, u64)> {
    rules
        .iter()
        .filter_map(|rule| {
            CString::new(rule.path.as_os_str().as_bytes())
                .ok()
                .map(|path| (path, rule.access))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn install_landlock_ruleset(rules: &[(CString, u64)]) -> io::Result<()> {
    install_landlock_ruleset_with_abi(rules, landlock_abi())
}

#[cfg(target_os = "linux")]
fn install_landlock_ruleset_with_abi(rules: &[(CString, u64)], abi: Option<u32>) -> io::Result<()> {
    let Some(abi) = abi else {
        return Ok(());
    };
    let access_mask = supported_access_mask(abi);
    let ruleset_fd = create_ruleset(access_mask)?;

    for (path, access) in rules {
        let allowed_access = *access & access_mask;
        if allowed_access == 0 {
            continue;
        }
        let parent_fd = match open_path(path) {
            Ok(fd) => fd,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(error) => return Err(error),
        };
        add_path_beneath_rule(
            ruleset_fd.as_raw_fd(),
            parent_fd.as_raw_fd(),
            allowed_access,
        )?;
    }

    restrict_self(ruleset_fd.as_raw_fd())
}

#[cfg(target_os = "linux")]
fn landlock_abi() -> Option<u32> {
    // SAFETY: `landlock_create_ruleset(NULL, 0, 0)` is the documented ABI probe.
    // It dereferences no pointers, creates no ruleset fd, and returns the highest
    // supported Landlock ABI version or `ENOSYS` on kernels without Landlock.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            ptr::null::<libc::c_void>(),
            0_usize,
            0_u32,
        )
    };
    if ret < 0 {
        return None;
    }
    u32::try_from(ret).ok()
}

#[cfg(target_os = "linux")]
const fn supported_access_mask(abi: u32) -> u64 {
    match abi {
        0 => 0,
        1 => ABI_V1_ACCESS,
        2 => ABI_V2_ACCESS,
        _ => ABI_V3_ACCESS,
    }
}

#[cfg(target_os = "linux")]
fn create_ruleset(handled_access_fs: u64) -> io::Result<OwnedFd> {
    let attr = LandlockRulesetAttr { handled_access_fs };
    // SAFETY: [Category 8 — FFI Boundary]
    // `attr` points to an initialized `landlock_ruleset_attr` with the exact
    // kernel UAPI layout. The kernel copies the structure synchronously before
    // returning a new owned ruleset fd.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attr,
            core::mem::size_of::<LandlockRulesetAttr>(),
            0_u32,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = i32::try_from(ret)
        .map_err(|_| io::Error::other("landlock ruleset fd did not fit RawFd"))?;
    // SAFETY: `fd` is freshly returned by `landlock_create_ruleset` and is owned
    // by this process. Wrapping it in `OwnedFd` ensures it is closed exactly once.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn open_path(path: &CString) -> io::Result<OwnedFd> {
    // SAFETY: [Category 8 — FFI Boundary]
    // `path` is a NUL-terminated string captured before `fork`. `O_PATH` opens
    // only a path reference for Landlock; `O_CLOEXEC` prevents descriptor leaks
    // if a future edit leaves the fd open past `execve`.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is freshly returned by `open(2)` and is owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn add_path_beneath_rule(
    ruleset_fd: RawFd,
    parent_fd: RawFd,
    allowed_access: u64,
) -> io::Result<()> {
    let path_beneath = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd,
    };
    // SAFETY: [Category 8 — FFI Boundary]
    // `path_beneath` has the packed kernel UAPI layout. Both fds are valid for
    // the duration of the syscall; the kernel copies the structure synchronously.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &raw const path_beneath,
            0_u32,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn restrict_self(ruleset_fd: RawFd) -> io::Result<()> {
    // SAFETY: [Category 8 — FFI Boundary]
    // `ruleset_fd` refers to an initialized Landlock ruleset fd. `flags = 0` is
    // the only currently accepted value. Restrictions apply only to this child.
    let ret = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0_u32) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_rule_helpers_set_expected_access_masks() {
        let path = PathBuf::from("/tmp/plugin-work");
        assert_eq!(
            PathRule::read_execute(path.clone()).access,
            access_fs::READ_EXECUTE
        );
        assert_eq!(
            PathRule::read_write_execute(path).access,
            access_fs::READ_WRITE_EXECUTE
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_supported_returns_bool() {
        fn accepts_bool(_value: bool) {}

        accepts_bool(landlock_abi().is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn graceful_degradation_on_unsupported_kernel() -> Result<(), Box<dyn std::error::Error>> {
        install_landlock_ruleset_with_abi(&[], None)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_allows_binary_execution() -> Result<(), Box<dyn std::error::Error>> {
        if landlock_abi().is_none() {
            return Ok(());
        }

        let mut command = std::process::Command::new("/bin/true");
        crate::configure_command(&mut command, crate::SandboxConfig::default());
        configure_filesystem_isolation(&mut command, &runtime_rules_for("/bin/true"));

        let status = command.status()?;
        assert!(
            status.success(),
            "/bin/true failed under Landlock: {status}"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_allows_working_directory() -> Result<(), Box<dyn std::error::Error>> {
        if landlock_abi().is_none() {
            return Ok(());
        }

        let workdir = unique_temp_dir("landlock-workdir")?;
        let mut rules = runtime_rules_for("/bin/sh");
        rules.push(PathRule::read_write_execute(workdir.clone()));

        let mut command = std::process::Command::new("/bin/sh");
        command
            .current_dir(&workdir)
            .args(["-c", "printf ok > allowed.txt && cat allowed.txt"]);
        crate::configure_command(&mut command, crate::SandboxConfig::default());
        configure_filesystem_isolation(&mut command, &rules);

        let output = command.output()?;
        let cleanup_result = std::fs::remove_dir_all(&workdir);
        assert!(
            output.status.success(),
            "workdir probe failed: status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8(output.stdout)?, "ok");
        if let Err(error) = cleanup_result {
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_blocks_access_to_disallowed_paths() -> Result<(), Box<dyn std::error::Error>> {
        if landlock_abi().is_none() {
            return Ok(());
        }

        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "/bin/cat /etc/passwd"]);
        crate::configure_command(&mut command, crate::SandboxConfig::default());
        configure_filesystem_isolation(&mut command, &runtime_rules_for("/bin/sh"));

        let output = command.output()?;
        assert!(
            !output.status.success(),
            "disallowed /etc/passwd read unexpectedly succeeded: stdout={}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Permission denied"),
            "disallowed read did not return EACCES-like stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn runtime_rules_for(binary: &str) -> Vec<PathRule> {
        let mut rules = Vec::new();
        if let Some(parent) = std::path::Path::new(binary).parent() {
            rules.push(PathRule::read_execute(parent.to_path_buf()));
        }
        for path in [
            "/bin",
            "/usr/bin",
            "/lib",
            "/lib64",
            "/usr/lib",
            "/usr/lib64",
        ] {
            rules.push(PathRule::read_execute(PathBuf::from(path)));
        }
        rules
    }

    #[cfg(target_os = "linux")]
    fn unique_temp_dir(prefix: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "arbitraitor-{prefix}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path)?;
        Ok(path)
    }
}
