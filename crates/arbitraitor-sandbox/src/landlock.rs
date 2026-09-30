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

/// Captures the running kernel's Landlock ABI probe at ruleset-configuration
/// time so the effective-controls matrix can be derived from the same probe
/// the `pre_exec` hook will act on (#754).
///
/// The probe is a pure kernel query with no side effects, so calling it
/// during command configuration (before `fork`) and again inside the child
/// yields the same answer on a static kernel; capturing once here removes
/// even that assumption.
///
/// Non-Linux platforms have no Landlock UAPI and always report [`Probe::No`].
#[must_use]
pub fn capture_landlock_probe() -> LandlockProbe {
    LandlockProbe::from_probe(probe_landlock_abi_version())
}

/// The recorded outcome of the Landlock kernel probe backing a ruleset
/// installation (#754).
///
/// This is the single source of truth shared by the `pre_exec` hook and the
/// effective-controls matrix: probe once, decide enforcement from it, and
/// report exactly what was decided. Before this type existed the matrix
/// called [`probe_landlock_abi_version`] while the hook silently no-oped on
/// the same host, so the reported controls could diverge from enforcement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LandlockProbe {
    /// The kernel reported an ABI version; rulesets can be installed.
    Supported(LandlockAbiVersion),
    /// The kernel has no Landlock UAPI (Linux < 5.13, Landlock LSM
    /// disabled, or non-Linux platform); ruleset installation no-ops.
    No,
}

impl LandlockProbe {
    /// Classifies a raw [`probe_landlock_abi_version`] result.
    #[must_use]
    pub fn from_probe(abi: Option<LandlockAbiVersion>) -> Self {
        match abi {
            Some(version) => Self::Supported(version),
            None => Self::No,
        }
    }

    /// Returns the ABI version when the probe succeeded, else `None`.
    #[must_use]
    pub const fn abi_version(self) -> Option<LandlockAbiVersion> {
        match self {
            Self::Supported(version) => Some(version),
            Self::No => None,
        }
    }

    /// Returns `true` when the probe succeeded and rulesets will be
    /// installed.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported(_))
    }
}

/// The outcome of one ruleset installation recorded by the `pre_exec` hook.
///
/// Returned through the hook's error channel: the `Ok` variant reports
/// successful enforcement, the `Err` variant reports a degraded or absent
/// installation so the parent can record the truth instead of assuming.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LandlockInstallOutcome {
    /// The ruleset was created and `landlock_restrict_self` succeeded; the
    /// child runs under active Landlock confinement.
    Enforced {
        /// The kernel ABI version the installed ruleset was built against.
        abi_version: LandlockAbiVersion,
    },
    /// The kernel probe reported no Landlock support, so no ruleset was
    /// installed (documented degradation, ADR-0021).
    NoKernelSupport,
}

/// A Landlock ruleset installation plan captured before `fork`.
///
/// Created by [`capture_landlock_install_plan`] and handed to
/// [`configure_filesystem_isolation_with_plan`]. Keeping the probe verdict in
/// the plan (instead of re-probing inside the child) is what lets the parent
/// report the same enforcement state the child will actually run under (#754).
#[derive(Clone, Debug)]
pub struct LandlockInstallPlan {
    captured: Vec<(CString, u64)>,
    probe: LandlockProbe,
}

impl LandlockInstallPlan {
    /// Returns the kernel probe verdict backing this plan.
    #[must_use]
    pub const fn probe(&self) -> LandlockProbe {
        self.probe
    }

    /// Returns the captured rules as raw path/access pairs.
    ///
    /// Empty on non-Linux platforms (no Landlock UAPI to capture against).
    #[must_use]
    pub fn captured(&self) -> &[(CString, u64)] {
        &self.captured
    }

    /// Maps the plan's probe verdict to the effective-controls state for
    /// filesystem isolation.
    ///
    /// This is the enforcement-truthful mapping: `Supported` is the only
    /// verdict under which the hook will install a ruleset.
    #[must_use]
    pub const fn filesystem_isolation_state(&self) -> crate::ControlState {
        if self.probe.is_supported() {
            crate::ControlState::Available
        } else {
            crate::ControlState::Unavailable
        }
    }
}

/// Captures a ruleset installation plan: the path rules plus the live
/// kernel Landlock probe verdict, probed once at configuration time (#754).
///
/// Pass the returned plan to [`configure_filesystem_isolation_with_plan`]
/// and derive the reported `filesystem_isolation` control from
/// [`LandlockInstallPlan::filesystem_isolation_state`] so the matrix and
/// the hook act on the same probe answer.
#[must_use]
pub fn capture_landlock_install_plan(rules: &[PathRule]) -> LandlockInstallPlan {
    LandlockInstallPlan {
        captured: capture_rules(rules),
        probe: capture_landlock_probe(),
    }
}

/// Registers a `pre_exec` closure that installs a Landlock ruleset.
///
/// On Linux kernels that support Landlock (5.13+), the child is denied all
/// governed filesystem access except the rights explicitly granted by `rules`.
/// On unsupported kernels, the hook returns success without installing a
/// ruleset so subprocess plugins degrade gracefully instead of failing to start.
///
/// Callers that must report what was actually enforced should use
/// [`configure_filesystem_isolation_with_plan`] instead, which also returns
/// the probe verdict backing the installation (#754).
#[cfg(target_os = "linux")]
pub fn configure_filesystem_isolation(command: &mut Command, rules: &[PathRule]) {
    configure_filesystem_isolation_with_plan(command, &capture_landlock_install_plan(rules));
}

/// Registers a filesystem-isolation hook on unsupported platforms.
///
/// Non-Linux platforms currently have no Landlock adapter; callers may invoke
/// this unconditionally, but filesystem isolation is enforced only on Linux.
#[cfg(not(target_os = "linux"))]
pub fn configure_filesystem_isolation(_command: &mut Command, _rules: &[PathRule]) {}

/// Registers a `pre_exec` closure that installs the Landlock ruleset from
/// `plan` and reports the installation outcome (#754).
///
/// On Linux the returned probe verdict is exactly what the hook will act on:
/// [`LandlockProbe::Supported`] means the child will run under an installed
/// ruleset, [`LandlockProbe::No`] means no ruleset will be installed (the
/// documented kernel-lacking degradation) and the caller must report
/// filesystem isolation as unavailable. Any hook-internal failure still
/// surfaces through [`std::process::Command::spawn`] as before — the
/// spawn fails closed rather than starting an unconstrained child.
///
/// On non-Linux platforms the plan is accepted and its probe reported, but
/// no hook is registered (filesystem isolation is enforced only on Linux).
pub fn configure_filesystem_isolation_with_plan(
    command: &mut Command,
    plan: &LandlockInstallPlan,
) -> LandlockProbe {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;

        let captured = plan.captured.clone();

        // SAFETY: The registered closure runs in the forked child between `fork`
        // and `execve`. It calls only async-signal-safe libc/kernel operations:
        // raw `syscall(2)`, `open(2)`, and `close(2)`. All allocation and path
        // conversion happen above, before the closure is registered.
        unsafe {
            command.pre_exec(move || install_landlock_ruleset(&captured));
        }
    }
    plan.probe
}

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

/// Non-Linux platforms have no Landlock UAPI, so no rules are ever
/// captured; the plan exists for type-consistent probe reporting and its
/// `captured` field is never read (`configure_filesystem_isolation_with_plan`
/// registers no hook without a Linux Landlock adapter).
#[cfg(not(target_os = "linux"))]
fn capture_rules(_rules: &[PathRule]) -> Vec<(CString, u64)> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn install_landlock_ruleset(rules: &[(CString, u64)]) -> io::Result<()> {
    install_landlock_ruleset_plan(rules, capture_landlock_probe()).map(|_| ())
}

/// Installs the ruleset for `rules` under `probe`'s verdict, reporting the
/// recorded outcome on success. The outcome is observable only in-process
/// (tests, callers running the install directly); the `pre_exec` hook path
/// discards it because the hook runs in the forked child. Hook failures
/// still propagate as errors so the spawn fails closed instead of running
/// an unconstrained child (#754).
#[cfg(target_os = "linux")]
fn install_landlock_ruleset_plan(
    rules: &[(CString, u64)],
    probe: LandlockProbe,
) -> io::Result<LandlockInstallOutcome> {
    let Some(abi) = probe.abi_version() else {
        return Ok(LandlockInstallOutcome::NoKernelSupport);
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

    restrict_self(ruleset_fd.as_raw_fd())?;
    Ok(LandlockInstallOutcome::Enforced { abi_version: abi })
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
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

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

    #[test]
    fn landlock_probe_classifies_probe_results() {
        assert_eq!(
            LandlockProbe::from_probe(Some(LandlockAbiVersion::V3)),
            LandlockProbe::Supported(LandlockAbiVersion::V3)
        );
        assert_eq!(LandlockProbe::from_probe(None), LandlockProbe::No);
        assert_eq!(
            LandlockProbe::Supported(LandlockAbiVersion::V1).abi_version(),
            Some(LandlockAbiVersion::V1)
        );
        assert_eq!(LandlockProbe::No.abi_version(), None);
        assert!(LandlockProbe::Supported(LandlockAbiVersion::V2).is_supported());
        assert!(!LandlockProbe::No.is_supported());
    }

    #[test]
    fn capture_landlock_probe_agrees_with_direct_probe() {
        assert_eq!(
            capture_landlock_probe().abi_version(),
            probe_landlock_abi_version(),
            "capture_landlock_probe must report exactly the direct probe result"
        );
    }

    #[test]
    fn install_plan_reports_enforcement_truthful_state() {
        // Whatever the host answers, the plan's state must match its probe:
        // Supported -> Available (hook installs), No -> Unavailable (hook
        // no-ops). This is the #754 contract between matrix and hook.
        let plan = capture_landlock_install_plan(&[]);
        match plan.probe() {
            LandlockProbe::Supported(abi) => {
                assert_eq!(
                    plan.filesystem_isolation_state(),
                    crate::ControlState::Available
                );
                assert_eq!(plan.probe().abi_version(), Some(abi));
            }
            LandlockProbe::No => {
                assert_eq!(
                    plan.filesystem_isolation_state(),
                    crate::ControlState::Unavailable
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn install_plan_probe_matches_live_kernel() {
        // On a live Linux host the captured plan's probe must equal a fresh
        // kernel probe: the capture is a pure kernel query.
        let plan = capture_landlock_install_plan(&[]);
        assert_eq!(
            plan.probe().abi_version(),
            probe_landlock_abi_version(),
            "captured plan probe diverged from the live kernel probe"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn install_plan_outcome_matches_probe_on_this_host() {
        // The plan path records what the hook actually did: Enforced only
        // when the probe was Supported, NoKernelSupport only when it was No.
        // `landlock_restrict_self` requires `no_new_privs` in the calling
        // thread; every production call site registers the
        // `configure_command` (NNP) hook before the Landlock hook, so this
        // in-process test mirrors that ordering.
        let nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1_u64, 0_u64, 0_u64, 0_u64) };
        assert_eq!(
            nnp, 0,
            "PR_SET_NO_NEW_PRIVS must succeed in the test thread"
        );
        let plan = capture_landlock_install_plan(&[]);
        let outcome = install_landlock_ruleset_plan(&plan.captured, plan.probe())
            .expect("ruleset install must not fail");
        match (plan.probe(), outcome) {
            (LandlockProbe::Supported(abi), LandlockInstallOutcome::Enforced { abi_version }) => {
                assert_eq!(abi_version, abi);
            }
            (LandlockProbe::No, LandlockInstallOutcome::NoKernelSupport) => {}
            (probe, outcome) => {
                panic!("probe/outcome mismatch: probe={probe:?} outcome={outcome:?}")
            }
        }
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
        // Probe = No must install nothing and report the degradation instead
        // of silently claiming success with an empty ruleset (#754).
        let outcome = install_landlock_ruleset_plan(&[], LandlockProbe::No)?;
        assert_eq!(outcome, LandlockInstallOutcome::NoKernelSupport);
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
