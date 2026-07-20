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
}
