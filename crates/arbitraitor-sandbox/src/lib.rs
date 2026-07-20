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

/// State of an individual containment control as actually in effect at
/// runtime (spec §27.7).
///
/// A sandbox pass is not proof of safety: the `SandboxMode` declares an
/// *intent* (see [`SandboxMode::capabilities`]), and [`EffectiveControls`]
/// records what was *actually* enforced. Each control is reported
/// independently so auditors can verify whether the requested containment
/// was achieved.
///
/// A requested `Restricted` or `Disposable` mode that reports any control
/// as [`ControlState::Unavailable`] MUST fail closed at the enforcement
/// boundary — `Unavailable` is a containment gap, not a degraded guarantee
/// (ADR-0007).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ControlState {
    /// The control is fully active for the child process on this platform.
    Available,
    /// The control is partially active: some sub-mechanisms work, others
    /// do not. Downgrades the assurance level from "contained" to
    /// "mediated-degraded" — see ADR-0007.
    Degraded,
    /// The control is not active on this platform or configuration.
    Unavailable,
}

/// Per-control effective-controls matrix recorded in receipts per
/// spec §27.7.
///
/// Every field is reported independently — never collapse into a single
/// `sandboxed: bool` (ADR-0007). This struct answers the question "what
/// containment controls were actually in effect for this run?", in
/// contrast to [`SandboxCapabilities`] which answers "what did the mode
/// *intend* to enforce?".
///
/// Compute instances with [`compute_effective_controls`], which maps a
/// requested mode and the runtime platform string into the effective
/// matrix. Use [`EffectiveControls::is_fully_contained`] and
/// [`EffectiveControls::has_unavailable`] to drive fail-closed decisions
/// at the enforcement boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EffectiveControls {
    /// Filesystem access is restricted to an explicit allowlist
    /// (Landlock on Linux, App Sandbox on macOS, etc.).
    pub filesystem_isolation: ControlState,
    /// Outbound network is blocked at the namespace / filter / broker
    /// layer.
    pub network_isolation: ControlState,
    /// The child process cannot spawn processes outside its allowlisted
    /// tree; descendants cannot escape.
    pub process_tree_containment: ControlState,
    /// `no_new_privs` (or platform equivalent) prevents privilege
    /// elevation via setuid, file capabilities, etc.
    pub privilege_suppression: ControlState,
    /// A seccomp-BPF / platform syscall filter is installed.
    pub syscall_filtering: ControlState,
    /// Platform settings — registry keys on Windows, `sysctl` on macOS,
    /// `/proc/sys` writes on Linux — are isolated from the child.
    pub platform_settings_isolation: ControlState,
    /// `RLIMIT_*` resource caps (CPU, memory, file size, fds, …) are
    /// enforced for the child.
    pub resource_limits: ControlState,
}

impl EffectiveControls {
    /// Every control marked `Unavailable`. Returned for
    /// [`SandboxMode::None`] and [`SandboxMode::Observe`] on every
    /// platform — observation is not containment (ADR-0024).
    #[must_use]
    pub const fn all_unavailable() -> Self {
        Self {
            filesystem_isolation: ControlState::Unavailable,
            network_isolation: ControlState::Unavailable,
            process_tree_containment: ControlState::Unavailable,
            privilege_suppression: ControlState::Unavailable,
            syscall_filtering: ControlState::Unavailable,
            platform_settings_isolation: ControlState::Unavailable,
            resource_limits: ControlState::Unavailable,
        }
    }

    /// Every control marked `Available`. Returned for `Restricted` and
    /// `Disposable` modes on platforms where every required containment
    /// primitive is wired up (Linux today).
    #[must_use]
    pub const fn all_available() -> Self {
        Self {
            filesystem_isolation: ControlState::Available,
            network_isolation: ControlState::Available,
            process_tree_containment: ControlState::Available,
            privilege_suppression: ControlState::Available,
            syscall_filtering: ControlState::Available,
            platform_settings_isolation: ControlState::Available,
            resource_limits: ControlState::Available,
        }
    }

    /// Returns `true` only when every control is `Available`.
    ///
    /// Receipt consumers should treat a `false` result from this method
    /// as a containment gap and downgrade the recorded assurance level
    /// (ADR-0007).
    #[must_use]
    pub fn is_fully_contained(&self) -> bool {
        [
            self.filesystem_isolation,
            self.network_isolation,
            self.process_tree_containment,
            self.privilege_suppression,
            self.syscall_filtering,
            self.platform_settings_isolation,
            self.resource_limits,
        ]
        .iter()
        .all(|state| matches!(state, ControlState::Available))
    }

    /// Returns `true` if any control is `Unavailable`. A `Restricted` or
    /// `Disposable` request that yields this result MUST fail closed
    /// (spec §27.7).
    #[must_use]
    pub fn has_unavailable(&self) -> bool {
        [
            self.filesystem_isolation,
            self.network_isolation,
            self.process_tree_containment,
            self.privilege_suppression,
            self.syscall_filtering,
            self.platform_settings_isolation,
            self.resource_limits,
        ]
        .iter()
        .any(|state| matches!(state, ControlState::Unavailable))
    }

    /// Returns `true` if any control is `Degraded`. A `Degraded` control
    /// is enforceable but with reduced coverage — callers should report
    /// this in the receipt and may need to downgrade the assurance level.
    #[must_use]
    pub fn has_degraded(&self) -> bool {
        [
            self.filesystem_isolation,
            self.network_isolation,
            self.process_tree_containment,
            self.privilege_suppression,
            self.syscall_filtering,
            self.platform_settings_isolation,
            self.resource_limits,
        ]
        .iter()
        .any(|state| matches!(state, ControlState::Degraded))
    }
}

/// Compute the per-control effective-controls matrix for the given
/// sandbox mode and target platform string (spec §27.7).
///
/// This function answers: "If we attempted to execute a child process in
/// `mode` on `platform`, which containment controls would actually be
/// in effect?" The returned [`EffectiveControls`] is the *effective*
/// matrix — what the platform would deliver after best-effort hardening —
/// not the *requested* matrix returned by [`SandboxMode::capabilities`].
///
/// Platform recognition is case-insensitive and accepts the common
/// forms: `linux`/`Linux`, `macos`/`darwin`/`Darwin`, `windows`/`Windows`.
/// Unknown platforms fail closed: every control is reported as
/// `Unavailable`. This is intentional — a platform we cannot classify
/// is one we cannot guarantee containment on.
///
/// # Examples
///
/// ```
/// use arbitraitor_sandbox::{compute_effective_controls, SandboxMode};
///
/// let on_linux = compute_effective_controls(SandboxMode::Restricted, "linux");
/// assert!(on_linux.is_fully_contained());
///
/// let on_macos = compute_effective_controls(SandboxMode::Restricted, "macos");
/// assert!(on_macos.has_unavailable());
///
/// let unknown = compute_effective_controls(SandboxMode::Disposable, "plan9");
/// assert!(unknown.has_unavailable());
/// ```
#[must_use]
pub fn compute_effective_controls(mode: SandboxMode, platform: &str) -> EffectiveControls {
    match mode {
        SandboxMode::None | SandboxMode::Observe => EffectiveControls::all_unavailable(),

        // `Disposable` differs from `Restricted` only by the ephemeral
        // root, which is tracked in `SandboxCapabilities::ephemeral_filesystem`
        // and is not one of the seven effective-controls fields in spec §27.7.
        SandboxMode::Restricted | SandboxMode::Disposable => {
            effective_restricted_controls(platform)
        }
    }
}

/// Platform-specific effective-controls matrix for a `Restricted` or
/// `Disposable` request.
///
/// Centralizing this here keeps [`compute_effective_controls`] a thin
/// dispatcher and gives the platform-mapping table a single home — when
/// a new platform adapter ships (macOS containment ADR, Windows sandbox
/// ADR), this function is the one place that needs to learn about it.
fn effective_restricted_controls(platform: &str) -> EffectiveControls {
    if platform.eq_ignore_ascii_case("linux") {
        // Positive security claim: Linux wires up Landlock (filesystem),
        // seccomp-BPF (syscall + network + platform-settings via filter),
        // pid/user namespaces (process tree + privilege suppression),
        // `no_new_privs`, and `RLIMIT_*` for both Restricted and Disposable.
        EffectiveControls::all_available()
    } else if platform.eq_ignore_ascii_case("macos") || platform.eq_ignore_ascii_case("darwin") {
        // ADR-0024: macOS containment ADR deferred — no primitive wired up.
        EffectiveControls::all_unavailable()
    } else if platform.eq_ignore_ascii_case("windows") {
        // ADR-0024 spirit: no Windows sandbox adapter yet → fail closed.
        EffectiveControls::all_unavailable()
    } else {
        EffectiveControls::all_unavailable()
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

    #[test]
    fn control_state_variants_are_distinct() {
        let states = [
            ControlState::Available,
            ControlState::Degraded,
            ControlState::Unavailable,
        ];
        for (i, a) in states.iter().enumerate() {
            for (j, b) in states.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b, "states at indices {i} and {j} must differ");
                }
            }
        }
    }

    #[test]
    fn effective_controls_all_unavailable_reports_every_control_unavailable() {
        let controls = EffectiveControls::all_unavailable();
        assert_eq!(controls.filesystem_isolation, ControlState::Unavailable);
        assert_eq!(controls.network_isolation, ControlState::Unavailable);
        assert_eq!(controls.process_tree_containment, ControlState::Unavailable);
        assert_eq!(controls.privilege_suppression, ControlState::Unavailable);
        assert_eq!(controls.syscall_filtering, ControlState::Unavailable);
        assert_eq!(
            controls.platform_settings_isolation,
            ControlState::Unavailable
        );
        assert_eq!(controls.resource_limits, ControlState::Unavailable);
        assert!(controls.has_unavailable());
        assert!(!controls.is_fully_contained());
        assert!(!controls.has_degraded());
    }

    #[test]
    fn effective_controls_all_available_reports_every_control_available() {
        let controls = EffectiveControls::all_available();
        assert_eq!(controls.filesystem_isolation, ControlState::Available);
        assert_eq!(controls.network_isolation, ControlState::Available);
        assert_eq!(controls.process_tree_containment, ControlState::Available);
        assert_eq!(controls.privilege_suppression, ControlState::Available);
        assert_eq!(controls.syscall_filtering, ControlState::Available);
        assert_eq!(
            controls.platform_settings_isolation,
            ControlState::Available
        );
        assert_eq!(controls.resource_limits, ControlState::Available);
        assert!(controls.is_fully_contained());
        assert!(!controls.has_unavailable());
        assert!(!controls.has_degraded());
    }

    #[test]
    fn is_fully_contained_false_when_any_control_is_degraded() {
        let mut controls = EffectiveControls::all_available();
        controls.syscall_filtering = ControlState::Degraded;
        assert!(!controls.is_fully_contained());
        assert!(controls.has_degraded());
        assert!(!controls.has_unavailable());
    }

    #[test]
    fn is_fully_contained_false_when_any_control_is_unavailable() {
        let mut controls = EffectiveControls::all_available();
        controls.network_isolation = ControlState::Unavailable;
        assert!(!controls.is_fully_contained());
        assert!(controls.has_unavailable());
    }

    #[test]
    fn compute_effective_controls_for_none_mode_is_all_unavailable() {
        // No envelope → no controls in effect, on every platform.
        for platform in ["linux", "macos", "darwin", "windows", "freebsd", ""] {
            let controls = compute_effective_controls(SandboxMode::None, platform);
            assert_eq!(
                controls,
                EffectiveControls::all_unavailable(),
                "None mode on platform {platform:?} must be all-unavailable"
            );
        }
    }

    #[test]
    fn compute_effective_controls_for_observe_mode_is_all_unavailable() {
        // Observation is not containment (ADR-0024): no enforcement
        // control is in effect regardless of platform.
        for platform in ["linux", "macos", "darwin", "windows", "freebsd", ""] {
            let controls = compute_effective_controls(SandboxMode::Observe, platform);
            assert_eq!(
                controls,
                EffectiveControls::all_unavailable(),
                "Observe mode on platform {platform:?} must be all-unavailable"
            );
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn compute_effective_controls_for_restricted_on_linux_is_all_available() {
        let controls = compute_effective_controls(SandboxMode::Restricted, "linux");
        assert_eq!(controls, EffectiveControls::all_available());
        assert!(controls.is_fully_contained());
        assert!(!controls.has_unavailable());
        assert!(!controls.has_degraded());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn compute_effective_controls_for_disposable_on_linux_is_all_available() {
        let controls = compute_effective_controls(SandboxMode::Disposable, "linux");
        assert_eq!(controls, EffectiveControls::all_available());
        assert!(controls.is_fully_contained());
        assert!(!controls.has_unavailable());
        assert!(!controls.has_degraded());
    }

    #[test]
    fn compute_effective_controls_for_restricted_on_macos_is_all_unavailable() {
        // ADR-0024: macOS containment ADR deferred → no enforcement
        // primitive wired up; every control must be Unavailable.
        let controls = compute_effective_controls(SandboxMode::Restricted, "macos");
        assert_eq!(controls, EffectiveControls::all_unavailable());
        assert!(controls.has_unavailable());
        assert!(!controls.is_fully_contained());
    }

    #[test]
    fn compute_effective_controls_for_restricted_on_darwin_alias_is_all_unavailable() {
        // "darwin" is the recognized alias for macOS (matches `uname -s`
        // output and `cfg!(target_os = "macos")` historically used
        // `darwin` for the target triple).
        let controls = compute_effective_controls(SandboxMode::Restricted, "darwin");
        assert_eq!(controls, EffectiveControls::all_unavailable());
    }

    #[test]
    fn compute_effective_controls_for_disposable_on_macos_is_all_unavailable() {
        let controls = compute_effective_controls(SandboxMode::Disposable, "macos");
        assert_eq!(controls, EffectiveControls::all_unavailable());
    }

    #[test]
    fn compute_effective_controls_for_restricted_on_windows_is_all_unavailable() {
        // ADR-0024 spirit: no Windows sandbox adapter yet → fail closed.
        let controls = compute_effective_controls(SandboxMode::Restricted, "windows");
        assert_eq!(controls, EffectiveControls::all_unavailable());
    }

    #[test]
    fn compute_effective_controls_for_unknown_platform_fails_closed() {
        // A platform we cannot classify is one we cannot guarantee
        // containment on. Every control must be Unavailable.
        for platform in ["plan9", "freebsd", "solaris", "haiku", ""] {
            let controls = compute_effective_controls(SandboxMode::Restricted, platform);
            assert_eq!(
                controls,
                EffectiveControls::all_unavailable(),
                "unknown platform {platform:?} must fail closed"
            );
            assert!(controls.has_unavailable());
        }
    }

    #[test]
    fn compute_effective_controls_platform_match_is_case_insensitive() {
        // Verifies each variant of casing maps to the Linux all-available
        // branch. `eq_ignore_ascii_case` is allocation-free and bounded
        // to ASCII, which is sufficient for these inputs.
        for platform in ["linux", "Linux", "LINUX", "liNuX", "lInUx"] {
            let controls = compute_effective_controls(SandboxMode::Restricted, platform);
            assert_eq!(
                controls,
                EffectiveControls::all_available(),
                "platform {platform:?} must match linux case-insensitively"
            );
        }
        for platform in ["macos", "Macos", "MACOS", "Darwin", "DARWIN"] {
            let controls = compute_effective_controls(SandboxMode::Restricted, platform);
            assert_eq!(
                controls,
                EffectiveControls::all_unavailable(),
                "platform {platform:?} must match macos/darwin case-insensitively"
            );
        }
    }

    #[test]
    fn compute_effective_controls_restricted_and_disposable_produce_identical_matrix() {
        // The ephemeral root is tracked in `SandboxCapabilities::ephemeral_filesystem`
        // and is not one of the seven spec §27.7 effective-controls fields.
        // Restricted and Disposable must therefore produce identical
        // `EffectiveControls` matrices on every platform.
        for platform in ["linux", "macos", "windows", "freebsd"] {
            let r = compute_effective_controls(SandboxMode::Restricted, platform);
            let d = compute_effective_controls(SandboxMode::Disposable, platform);
            assert_eq!(
                r, d,
                "Restricted and Disposable effective matrices must match on platform {platform:?}"
            );
        }
    }
}
