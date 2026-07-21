//! Linux Landlock filesystem isolation for child processes.
//!
//! Landlock is a stacked Linux Security Module (LSM) available on Linux 5.13+
//! that lets an unprivileged process restrict its own future filesystem access.
//! This module installs a deny-by-default ruleset in a `pre_exec` hook so only
//! the forked child (and its descendants) are constrained; the Arbitraitor host
//! process remains unrestricted.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr;

use serde::{Deserialize, Deserializer, Serialize};

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

/// Running-kernel Landlock ABI version returned by the kernel probe.
///
/// The Linux UAPI currently defines ABI versions v1 through v10. The wrapper
/// accepts any non-zero version so newer kernels remain representable until
/// Arbitraitor's policy matrix is updated.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct LandlockAbiVersion(u32);

impl LandlockAbiVersion {
    /// Landlock ABI v1: initial filesystem restrictions (Linux 5.13).
    pub const V1: Self = Self(1);
    /// Landlock ABI v2: file modes isolation (Linux 5.19).
    pub const V2: Self = Self(2);
    /// Landlock ABI v3: truncate / ioctl restrictions (Linux 6.2).
    pub const V3: Self = Self(3);
    /// Landlock ABI v4: TCP connect/bind (Linux 6.7).
    pub const V4: Self = Self(4);
    /// Landlock ABI v5: IOCTL device (Linux 6.10).
    pub const V5: Self = Self(5);
    /// Landlock ABI v6: signal scope + abstract UNIX socket (Linux 6.12).
    pub const V6: Self = Self(6);
    /// Landlock ABI v7: audit log (Linux 6.15).
    pub const V7: Self = Self(7);
    /// Landlock ABI v8: TSYNC flag on `landlock_restrict_self` (Linux 7.0-rc).
    pub const V8: Self = Self(8);
    /// Landlock ABI v9: `RESOLVE_UNIX` behind downstream patches.
    pub const V9: Self = Self(9);
    /// Landlock ABI v10: UDP connect/bind (Linux 6.16).
    pub const V10: Self = Self(10);

    /// Builds a Landlock ABI version from a kernel-reported version number.
    #[must_use]
    pub const fn new(version: u32) -> Option<Self> {
        if version == 0 {
            None
        } else {
            Some(Self(version))
        }
    }

    /// Returns the numeric ABI version reported by the kernel.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for LandlockAbiVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "v{}", self.0)
    }
}

impl<'de> Deserialize<'de> for LandlockAbiVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = u32::deserialize(deserializer)?;
        Self::new(version)
            .ok_or_else(|| serde::de::Error::custom("Landlock ABI version must be non-zero"))
    }
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
#[cfg(target_os = "linux")]
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const ABI_V1_ACCESS: u64 = (1_u64 << 13) - 1;
const ABI_V2_ACCESS: u64 = ABI_V1_ACCESS | access_fs::REFER;
const ABI_V3_ACCESS: u64 = ABI_V2_ACCESS | access_fs::TRUNCATE;

/// Probes the running kernel's effective Landlock ABI version.
///
/// Linux exposes the ABI probe through `landlock_create_ruleset(NULL, 0,
/// LANDLOCK_CREATE_RULESET_VERSION)`, returning the highest ABI version the
/// kernel supports. Unsupported kernels and non-Linux platforms return `None`.
#[must_use]
#[cfg(target_os = "linux")]
pub fn probe_landlock_abi_version() -> Option<LandlockAbiVersion> {
    // SAFETY: [Category 8 — FFI Boundary]
    // `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` is
    // the documented Landlock ABI probe. The kernel dereferences no pointers,
    // creates no fd, and returns a scalar ABI version or a negative errno.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            ptr::null::<libc::c_void>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    parse_landlock_abi_probe(ret)
}

/// Probes the running kernel's effective Landlock ABI version.
///
/// Non-Linux platforms have no Landlock UAPI and therefore report `None`.
#[must_use]
#[cfg(not(target_os = "linux"))]
pub const fn probe_landlock_abi_version() -> Option<LandlockAbiVersion> {
    None
}

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
    install_landlock_ruleset_with_abi(rules, probe_landlock_abi_version())
}

#[cfg(target_os = "linux")]
fn install_landlock_ruleset_with_abi(
    rules: &[(CString, u64)],
    abi: Option<LandlockAbiVersion>,
) -> io::Result<()> {
    let Some(abi) = abi else {
        return Ok(());
    };
    let access_mask = supported_access_mask(abi.get());
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
fn parse_landlock_abi_probe(ret: libc::c_long) -> Option<LandlockAbiVersion> {
    if ret < 0 {
        return None;
    }
    u32::try_from(ret).ok().and_then(LandlockAbiVersion::new)
}

#[cfg(target_os = "linux")]
const fn supported_access_mask(abi: u32) -> u64 {
    // Only ABI v1-v3 filesystem rights are enforced today. ABI v4+ controls
    // are recorded for receipts only until ADR-0028's planned matrix is wired.
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

        accepts_bool(probe_landlock_abi_version().is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_abi_probe_returns_supported_version() {
        let version = probe_landlock_abi_version();
        assert!(
            version.is_some_and(|abi| abi >= LandlockAbiVersion::V1),
            "Linux host must report Landlock ABI v1+"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn landlock_abi_probe_is_absent_off_linux() {
        assert_eq!(probe_landlock_abi_version(), None);
    }

    #[test]
    fn landlock_abi_version_parses_nonzero_versions() -> Result<(), Box<dyn std::error::Error>> {
        // Given: kernel ABI probe result values in the documented v1-v10 range.
        // When: values are parsed into the Landlock ABI newtype.
        // Then: every non-zero ABI version preserves its number.
        let versions = [
            LandlockAbiVersion::V1,
            LandlockAbiVersion::V2,
            LandlockAbiVersion::V3,
            LandlockAbiVersion::V4,
            LandlockAbiVersion::V5,
            LandlockAbiVersion::V6,
            LandlockAbiVersion::V7,
            LandlockAbiVersion::V8,
            LandlockAbiVersion::V9,
            LandlockAbiVersion::V10,
        ];
        for (index, expected) in versions.into_iter().enumerate() {
            let version = u32::try_from(index + 1)?;
            assert_eq!(LandlockAbiVersion::new(version), Some(expected));
            assert_eq!(expected.get(), version);
            let json = serde_json::to_string(&expected)?;
            let decoded: LandlockAbiVersion = serde_json::from_str(&json)?;
            assert_eq!(decoded, expected);
        }
        assert_eq!(LandlockAbiVersion::V10.get(), 10);
        assert_eq!(LandlockAbiVersion::V10.to_string(), "v10");
        Ok(())
    }

    #[test]
    fn landlock_abi_version_rejects_zero_and_negative_json() {
        assert_eq!(LandlockAbiVersion::new(0), None);
        assert!(serde_json::from_str::<LandlockAbiVersion>("0").is_err());
        assert!(serde_json::from_str::<LandlockAbiVersion>("-1").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_probe_return_parsing_rejects_errors_and_zero() {
        assert_eq!(parse_landlock_abi_probe(-1), None);
        assert_eq!(parse_landlock_abi_probe(0), None);
        assert_eq!(parse_landlock_abi_probe(7), Some(LandlockAbiVersion::V7));
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
        if probe_landlock_abi_version().is_none() {
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
        if probe_landlock_abi_version().is_none() {
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
        if probe_landlock_abi_version().is_none() {
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
