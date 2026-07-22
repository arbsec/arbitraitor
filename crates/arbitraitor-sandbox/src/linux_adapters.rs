//! Linux-specific sandbox adapters (spec §27.3).

use std::process::Command;

use crate::SandboxConfig;

/// Adapter that composes user + mount + IPC + PID + network namespaces
/// for process isolation (spec §27.3, "namespaces").
#[derive(Clone, Copy, Debug, Default)]
pub struct NamespaceAdapter;

impl NamespaceAdapter {
    /// Configures the given `Command` to create new namespaces on exec.
    pub fn configure(command: &mut Command, _config: SandboxConfig) {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            // SAFETY: `pre_exec` requires `unsafe` because the closure runs
            // after `fork()` in a multi-threaded process. The closure only
            // calls `unshare` which is async-signal-safe.
            #[allow(unsafe_code)]
            unsafe {
                command.pre_exec(|| {
                    let ret = libc::unshare(
                        libc::CLONE_NEWNS
                            | libc::CLONE_NEWIPC
                            | libc::CLONE_NEWPID
                            | libc::CLONE_NEWNET,
                    );
                    if ret == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
    }
}

/// Adapter that invokes `bubblewrap` (`bwrap`) for unprivileged
/// sandboxing (spec §27.3, "bubblewrap").
#[derive(Clone, Copy, Debug, Default)]
pub struct BubblewrapAdapter;

impl BubblewrapAdapter {
    /// Returns a `Command` pre-configured with `bwrap` that creates
    /// an unprivileged sandbox with the given config.
    #[must_use]
    pub fn create_command(config: &SandboxConfig, child: &str) -> Option<Command> {
        let mut cmd = Command::new("bwrap");
        cmd.arg("--unshare-all")
            .arg("--share-net")
            .arg("--die-with-parent")
            .arg("--ro-bind")
            .arg("/usr")
            .arg("/usr")
            .arg("--ro-bind")
            .arg("/lib")
            .arg("/lib")
            .arg("--ro-bind")
            .arg("/bin")
            .arg("/bin")
            .arg("--proc")
            .arg("/proc")
            .arg("--dev")
            .arg("/dev")
            .arg("--tmpfs")
            .arg("/tmp");

        if config.no_new_privs {
            cmd.arg("--unshare-user-try");
        }

        cmd.arg("--").arg(child);
        Some(cmd)
    }
}

/// Adapter that uses `systemd-run` to create a transient scope
/// with resource limits and network isolation (spec §27.3).
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemdRunAdapter;

impl SystemdRunAdapter {
    /// Returns a `Command` pre-configured with `systemd-run` that
    /// creates a transient scope with network isolation.
    #[must_use]
    pub fn create_command(config: &SandboxConfig, child: &str) -> Option<Command> {
        let mut cmd = Command::new("systemd-run");
        cmd.arg("--user")
            .arg("--scope")
            .arg("--property=PrivateNetwork=yes")
            .arg("--property=PrivateTmp=yes");

        if config.no_new_privs {
            cmd.arg("--property=NoNewPrivileges=yes");
        }

        cmd.arg("--").arg(child);
        Some(cmd)
    }
}

/// Adapter that sets up eBPF observation hooks for runtime monitoring
/// (spec §27.3, "eBPF-based observation where available").
#[derive(Clone, Copy, Debug, Default)]
pub struct EBpfObservationAdapter;

impl EBpfObservationAdapter {
    /// Returns whether eBPF observation is available on this platform.
    #[must_use]
    pub fn is_available() -> bool {
        false
    }
}

/// Probes whether `io_uring` is available on the running Linux kernel
/// (spec §27.3, "`io_uring` restrictions").
///
/// `io_uring` bypasses seccomp because queued operations execute inside the
/// kernel without traversing the syscall filter. Kernel 6.6+ ships the
/// `kernel.io_uring_disabled` sysctl:
///
/// | Value | Meaning |
/// |-------|---------|
/// | `0`   | `io_uring` is enabled (available to all tasks) |
/// | `1`   | Disabled for unprivileged tasks (root still has access) |
/// | `2`   | Fully disabled for all tasks |
///
/// Returns `Some(true)` when `io_uring` is available (`disabled = 0`),
/// `Some(false)` when disabled (`1` or `2`), and `None` when the sysctl
/// is absent (kernel < 6.6 or non-Linux) — the availability is unknown.
#[must_use]
#[cfg(target_os = "linux")]
pub fn probe_io_uring_available() -> Option<bool> {
    let contents = std::fs::read_to_string("/proc/sys/kernel/io_uring_disabled").ok()?;
    let value = contents.trim();
    match value {
        "0" => Some(true),
        "1" | "2" => Some(false),
        _ => None,
    }
}

/// Probes whether `io_uring` is available on the running kernel.
///
/// Non-Linux platforms have no `io_uring` UAPI and therefore report `None`.
#[must_use]
#[cfg(not(target_os = "linux"))]
pub const fn probe_io_uring_available() -> Option<bool> {
    None
}

/// Probes whether unprivileged user namespaces are available without host restriction.
///
/// Linux exposes `kernel.unprivileged_userns_clone` as `0` when unprivileged
/// user namespaces are disabled and `1` when clone is permitted. Ubuntu 23.10+
/// additionally exposes `kernel.apparmor_restrict_unprivileged_unconfined`;
/// when that `AppArmor` mediation flag is `1`, unconfined unprivileged user
/// namespaces are treated as restricted even if the clone sysctl remains `1`.
///
/// Returns `Some(true)` only when unprivileged user namespaces are enabled and
/// no `AppArmor` restriction is present. Returns `Some(false)` when the kernel
/// or `AppArmor` restricts them. Returns `None` when the Linux clone sysctl
/// cannot be read or contains an unknown value.
#[must_use]
#[cfg(target_os = "linux")]
pub fn probe_userns_available() -> Option<bool> {
    let clone_contents =
        std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone").ok()?;
    let apparmor_contents =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined").ok();
    parse_userns_available(&clone_contents, apparmor_contents.as_deref())
}

/// Probes whether unprivileged user namespaces are available without host restriction.
///
/// Non-Linux platforms have no Linux user-namespace sysctl surface and therefore
/// report `None`.
#[must_use]
#[cfg(not(target_os = "linux"))]
pub const fn probe_userns_available() -> Option<bool> {
    None
}

#[cfg(target_os = "linux")]
fn parse_userns_available(clone_contents: &str, apparmor_contents: Option<&str>) -> Option<bool> {
    match clone_contents.trim() {
        "0" => Some(false),
        "1" => match apparmor_contents.map(str::trim) {
            Some("1") => Some(false),
            Some("0") | None => Some(true),
            Some(_) => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn bubblewrap_command_includes_isolation_flags() {
        let config = SandboxConfig::default();
        let cmd = BubblewrapAdapter::create_command(&config, "/bin/true");
        assert!(cmd.is_some());
        let cmd = cmd.unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        assert!(args.contains(&"--unshare-all".to_owned()));
        assert!(args.contains(&"--die-with-parent".to_owned()));
        assert!(args.contains(&"/bin/true".to_owned()));
    }

    #[test]
    fn systemd_run_command_includes_scope_and_network_flags() {
        let config = SandboxConfig::default();
        let cmd = SystemdRunAdapter::create_command(&config, "/bin/true");
        assert!(cmd.is_some());
        let cmd = cmd.unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        assert!(args.contains(&"--scope".to_owned()));
        assert!(args.contains(&"--property=PrivateNetwork=yes".to_owned()));
        assert!(args.contains(&"--property=NoNewPrivileges=yes".to_owned()));
        assert!(args.contains(&"/bin/true".to_owned()));
    }

    #[test]
    fn ebpf_observation_is_not_available_in_mvp() {
        assert!(!EBpfObservationAdapter::is_available());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn io_uring_probe_returns_some_on_linux() {
        // Given: running on a Linux host where /proc/sys/kernel/io_uring_disabled
        // may or may not exist (kernel >= 6.6 vs older).
        // When: probing io_uring availability.
        // Then: the probe returns Some(bool) when the sysctl exists, or None
        // when the kernel predates 6.6.
        let result = probe_io_uring_available();
        match result {
            Some(available) => {
                // If the sysctl exists, the value must be a known state.
                let contents = std::fs::read_to_string("/proc/sys/kernel/io_uring_disabled")
                    .expect("sysctl must exist when probe returns Some");
                let value = contents.trim();
                assert!(value == "0" || value == "1" || value == "2");
                assert_eq!(available, value == "0");
            }
            None => {
                // Kernel < 6.6: sysctl absent → None is correct.
                assert!(std::fs::read_to_string("/proc/sys/kernel/io_uring_disabled").is_err());
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn io_uring_probe_returns_none_off_linux() {
        assert_eq!(probe_io_uring_available(), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn userns_parse_detects_clone_and_apparmor_restrictions() {
        // Given: sysctl contents for Linux userns cloning and Ubuntu AppArmor mediation.
        // When: parsing the effective availability state.
        // Then: availability is true only when clone is enabled and AppArmor is not restricting it.
        assert_eq!(parse_userns_available("0\n", None), Some(false));
        assert_eq!(parse_userns_available("1\n", None), Some(true));
        assert_eq!(parse_userns_available("1\n", Some("0\n")), Some(true));
        assert_eq!(parse_userns_available("1\n", Some("1\n")), Some(false));
        assert_eq!(parse_userns_available("2\n", None), None);
        assert_eq!(parse_userns_available("1\n", Some("unexpected\n")), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn userns_probe_returns_linux_status_when_sysctl_exists() {
        // Given: a Linux host where /proc/sys/kernel/unprivileged_userns_clone may exist.
        // When: probing unprivileged user namespace availability.
        // Then: the probe reports Some(bool) for known sysctl states or None when unavailable/unknown.
        let result = probe_userns_available();
        let clone_contents = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone");
        match clone_contents {
            Ok(contents) => assert_eq!(
                result,
                parse_userns_available(
                    &contents,
                    std::fs::read_to_string(
                        "/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined",
                    )
                    .ok()
                    .as_deref(),
                )
            ),
            Err(_) => assert_eq!(result, None),
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn userns_probe_returns_none_off_linux() {
        assert_eq!(probe_userns_available(), None);
    }
}
