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

/// Sandbox containment mode per spec §27.2.
///
/// The mode declares the *intent* of the runtime sandbox envelope. It is a
/// declarative policy knob, not an enforcement claim: the actual capability
/// matrix for a given run is recorded in the receipt (§27.7) so downstream
/// auditors can verify which controls were effective.
///
/// Modes are ordered by strength of containment. `None` performs no
/// containment at all; `Disposable` provides the strongest guarantees,
/// including an ephemeral root filesystem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxMode {
    /// No sandbox envelope is constructed. The artifact runs in the
    /// inherited process context with the inherited environment.
    ///
    /// Spec §27.2 mode 1. Equivalent to running the artifact directly.
    /// No containment capability is claimed.
    None,

    /// Observation-only mode. The sandbox crate (or platform equivalent —
    /// Endpoint Security on macOS, audit/ptrace on Linux) records
    /// process-tree, file-access, and network events without blocking any
    /// operation.
    ///
    /// Spec §27.2 mode 2. No enforcement capability is claimed because
    /// observation is not a containment boundary. Receipts record the
    /// mode so auditors know the run was supervised, not contained.
    Observe,

    /// Restricted mode applies the platform containment primitives
    /// available on the host (Linux: Landlock filesystem isolation,
    /// seccomp-BPF syscall filtering, `no_new_privs`, `close_range` fd
    /// closing, and `rlimit`-based resource limits). On macOS this
    /// degrades to mediated execution per ADR-0024.
    ///
    /// Spec §27.2 mode 3. Enforces filesystem, network, syscall,
    /// privilege, and resource controls but does *not* discard the
    /// filesystem image after the run — the host filesystem persists.
    Restricted,

    /// Disposable mode is `Restricted` plus an ephemeral filesystem
    /// (overlayfs or tmpfs root) that is torn down after the run. The
    /// artifact sees an isolated, throwaway root that cannot observe or
    /// mutate any host state outside its allowlisted mount points.
    ///
    /// Spec §27.2 mode 4. Strongest guarantees: even if every other
    /// control is bypassed, the attacker cannot reach durable host
    /// storage.
    Disposable,
}

impl SandboxMode {
    /// Return the enforcement capability set this mode declares.
    ///
    /// These are *declared* capabilities — what the mode is *supposed* to
    /// enforce. The actually-effective capabilities are a property of the
    /// platform and the runtime; they are recorded in the receipt per
    /// spec §27.7. Callers must not collapse this struct into a single
    /// `sandboxed: bool` (ADR-0007).
    #[must_use]
    pub const fn capabilities(&self) -> SandboxCapabilities {
        match self {
            // None (no envelope) and Observe (supervision only) both
            // declare zero enforcement capabilities: the matrix only
            // tracks enforcement, and observation is not containment.
            Self::None | Self::Observe => SandboxCapabilities::none(),

            // Restricted enforces everything except an ephemeral root.
            Self::Restricted => SandboxCapabilities {
                filesystem_isolation: true,
                network_isolation: true,
                process_tree_containment: true,
                privilege_suppression: true,
                syscall_filtering: true,
                resource_limits: true,
                ephemeral_filesystem: false,
            },

            // Disposable is Restricted plus ephemeral root.
            Self::Disposable => SandboxCapabilities {
                filesystem_isolation: true,
                network_isolation: true,
                process_tree_containment: true,
                privilege_suppression: true,
                syscall_filtering: true,
                resource_limits: true,
                ephemeral_filesystem: true,
            },
        }
    }
}

/// Enforcement capability set declared by a [`SandboxMode`].
///
/// Every field is an independent boolean — never collapse into a single
/// `sandboxed` flag (ADR-0007). The capability matrix is part of the
/// receipt and is what downstream auditors verify.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "spec §27.2 + ADR-0007 mandate this exact per-control matrix shape; collapsing booleans into enums would break the receipt schema"
)]
pub struct SandboxCapabilities {
    /// Filesystem access is restricted to an explicit allowlist
    /// (Landlock on Linux, App Sandbox on macOS, etc.).
    pub filesystem_isolation: bool,
    /// Outbound network is blocked at the namespace / filter / broker
    /// layer.
    pub network_isolation: bool,
    /// The child process cannot spawn processes outside its allowlisted
    /// tree; descendants cannot escape.
    pub process_tree_containment: bool,
    /// `no_new_privs` (or platform equivalent) prevents privilege
    /// elevation via setuid, file capabilities, etc.
    pub privilege_suppression: bool,
    /// A seccomp-BPF / platform syscall filter is installed.
    pub syscall_filtering: bool,
    /// `RLIMIT_*` resource caps (CPU, memory, file size, fds, …) are
    /// enforced for the child.
    pub resource_limits: bool,
    /// The child runs against an ephemeral root filesystem that is
    /// discarded after the run.
    pub ephemeral_filesystem: bool,
}

impl SandboxCapabilities {
    /// All-false capability set. Returned by [`SandboxMode::None`] and
    /// [`SandboxMode::Observe`].
    #[must_use]
    pub const fn none() -> Self {
        Self {
            filesystem_isolation: false,
            network_isolation: false,
            process_tree_containment: false,
            privilege_suppression: false,
            syscall_filtering: false,
            resource_limits: false,
            ephemeral_filesystem: false,
        }
    }
}

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

    #[test]
    fn none_mode_declares_no_capabilities() {
        let caps = SandboxMode::None.capabilities();
        assert!(!caps.filesystem_isolation);
        assert!(!caps.network_isolation);
        assert!(!caps.process_tree_containment);
        assert!(!caps.privilege_suppression);
        assert!(!caps.syscall_filtering);
        assert!(!caps.resource_limits);
        assert!(!caps.ephemeral_filesystem);
    }

    #[test]
    fn observe_mode_declares_no_enforcement_capabilities() {
        // Observation is not a containment boundary (ADR-0024): the
        // capability struct only tracks enforcement, not supervision.
        let caps = SandboxMode::Observe.capabilities();
        assert_eq!(caps, SandboxCapabilities::none());
    }

    #[test]
    fn restricted_mode_enforces_everything_except_ephemeral_root() {
        let caps = SandboxMode::Restricted.capabilities();
        assert!(caps.filesystem_isolation);
        assert!(caps.network_isolation);
        assert!(caps.process_tree_containment);
        assert!(caps.privilege_suppression);
        assert!(caps.syscall_filtering);
        assert!(caps.resource_limits);
        // The host filesystem persists — ephemeral filesystem is the
        // Disposable-only capability.
        assert!(!caps.ephemeral_filesystem);
    }

    #[test]
    fn disposable_mode_enforces_everything_including_ephemeral_root() {
        let caps = SandboxMode::Disposable.capabilities();
        assert!(caps.filesystem_isolation);
        assert!(caps.network_isolation);
        assert!(caps.process_tree_containment);
        assert!(caps.privilege_suppression);
        assert!(caps.syscall_filtering);
        assert!(caps.resource_limits);
        assert!(caps.ephemeral_filesystem);
    }

    #[test]
    fn disposable_is_a_superset_of_restricted() {
        let r = SandboxMode::Restricted.capabilities();
        let d = SandboxMode::Disposable.capabilities();
        // Disposable must enable everything Restricted does, plus the
        // ephemeral root.
        assert!(d.filesystem_isolation >= r.filesystem_isolation);
        assert!(d.network_isolation >= r.network_isolation);
        assert!(d.process_tree_containment >= r.process_tree_containment);
        assert!(d.privilege_suppression >= r.privilege_suppression);
        assert!(d.syscall_filtering >= r.syscall_filtering);
        assert!(d.resource_limits >= r.resource_limits);
        assert!(d.ephemeral_filesystem && !r.ephemeral_filesystem);
    }

    #[test]
    fn sandbox_capabilities_none_is_all_false() {
        let caps = SandboxCapabilities::none();
        assert!(!caps.filesystem_isolation);
        assert!(!caps.network_isolation);
        assert!(!caps.process_tree_containment);
        assert!(!caps.privilege_suppression);
        assert!(!caps.syscall_filtering);
        assert!(!caps.resource_limits);
        assert!(!caps.ephemeral_filesystem);
    }

    #[test]
    fn sandbox_mode_variants_are_distinct() {
        // Spec §27.2 enumerates exactly four modes; this test fails if a
        // variant is added or removed without updating coverage.
        let modes = [
            SandboxMode::None,
            SandboxMode::Observe,
            SandboxMode::Restricted,
            SandboxMode::Disposable,
        ];
        for (i, a) in modes.iter().enumerate() {
            for (j, b) in modes.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b, "modes at indices {i} and {j} must differ");
                }
            }
        }
    }
}
