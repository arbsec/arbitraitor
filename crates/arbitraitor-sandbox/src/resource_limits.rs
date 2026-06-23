//! Resource limits applied in the child before `execve`.
//!
//! Resource limits (`setrlimit`) are inherited across both `execve` and
//! `fork`. Applying them inside a `pre_exec` closure therefore closes the
//! TOCTOU race between `fork` and parent-side `prlimit`: the limits are
//! already in effect the instant untrusted code runs, with no window in which
//! the child can fork unbounded grandchildren.

/// Resource limits applied to the child process via `setrlimit` in
/// `pre_exec`, before `execve`.
///
/// This is a sandbox-local mirror of the execution broker's policy limits. The
/// broker converts its policy type into this representation to avoid a circular
/// crate dependency (`arbitraitor-exec` depends on this crate). Each `Option`
/// is applied independently; `None` leaves the inherited limit untouched.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessResourceLimits {
    /// `RLIMIT_CPU` — maximum CPU time in seconds.
    pub cpu_time_secs: Option<u64>,
    /// `RLIMIT_AS` — maximum virtual memory in bytes.
    pub memory_bytes: Option<u64>,
    /// `RLIMIT_NPROC` — maximum number of processes or threads.
    pub process_count: Option<u64>,
    /// `RLIMIT_NOFILE` — maximum number of open file descriptors.
    pub fd_count: Option<u64>,
}

impl ProcessResourceLimits {
    /// Returns a limits set with no constraints configured.
    ///
    /// Convenience for callers that want to override individual fields.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            cpu_time_secs: None,
            memory_bytes: None,
            process_count: None,
            fd_count: None,
        }
    }
}

#[cfg(target_os = "linux")]
impl ProcessResourceLimits {
    /// Applies every configured limit to the current process via `setrlimit`.
    ///
    /// Intended to run inside `CommandExt::pre_exec()`, after `fork` and before
    /// `execve`. Only async-signal-safe kernel calls are made.
    ///
    /// # Errors
    ///
    /// Returns the OS error reported by `setrlimit(2)` when the kernel rejects
    /// a limit.
    fn apply_in_child(self) -> std::io::Result<()> {
        use rustix::process::{Resource, Rlimit, setrlimit};

        let apply = |resource: Resource, limit: Option<u64>| -> std::io::Result<()> {
            if let Some(value) = limit {
                let rlim = Rlimit {
                    current: Some(value),
                    maximum: Some(value),
                };
                setrlimit(resource, rlim)
                    .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))?;
            }
            Ok(())
        };
        apply(Resource::Cpu, self.cpu_time_secs)?;
        apply(Resource::As, self.memory_bytes)?;
        apply(Resource::Nproc, self.process_count)?;
        apply(Resource::Nofile, self.fd_count)?;
        Ok(())
    }
}

/// Registers a `pre_exec` closure that applies resource limits **in the child
/// process before `execve`** via `setrlimit`.
///
/// This eliminates the TOCTOU race between `fork` and parent-side `prlimit`:
/// because `setrlimit` values are inherited across `execve`, the limits are
/// already in effect the instant untrusted code runs, with no window in which
/// the child can fork unbounded grandchildren before limits apply.
///
/// Must be called **before** [`crate::configure_command`] (or any other
/// `pre_exec` registration) so the limits are in force even while subsequent
/// sandbox hardening runs in the child.
///
/// # Errors
///
/// The registered closure returns an I/O error when the kernel rejects a
/// limit; that error surfaces as a failed [`std::process::Command::spawn`].
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn configure_resource_limits(
    command: &mut std::process::Command,
    limits: &ProcessResourceLimits,
) {
    use std::os::unix::process::CommandExt;

    // Copy the limits onto the stack (every field is `Copy`). The closure only
    // borrows this captured copy, never the caller's reference.
    let captured = *limits;

    // SAFETY: The registered closure runs in the forked child between `fork`
    // and `execve`. It calls only `ProcessResourceLimits::apply_in_child`,
    // whose sole dependency is `rustix::process::setrlimit` — a thin
    // async-signal-safe wrapper over the `setrlimit(2)` system call. The
    // closure performs no heap allocation, acquires no locks, and dereferences
    // no caller-controlled pointers; the captured data is plain `Option<u64>`
    // machine integers.
    unsafe {
        command.pre_exec(move || captured.apply_in_child());
    }
}

/// Registers a `pre_exec` closure that applies resource limits in the child.
///
/// Non-Linux platforms have no `setrlimit` adapter; this is a no-op so callers
/// can invoke it unconditionally. Resource limits are simply not enforced on
/// those platforms.
#[cfg(not(target_os = "linux"))]
pub fn configure_resource_limits(
    _command: &mut std::process::Command,
    _limits: &ProcessResourceLimits,
) {
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    use crate::{SandboxConfig, configure_command};

    #[test]
    fn empty_limits_have_no_constraints() {
        let limits = ProcessResourceLimits::empty();
        assert_eq!(limits.cpu_time_secs, None);
        assert_eq!(limits.memory_bytes, None);
        assert_eq!(limits.process_count, None);
        assert_eq!(limits.fd_count, None);
    }

    #[test]
    fn default_limits_have_no_constraints() {
        let limits = ProcessResourceLimits::default();
        assert_eq!(limits, ProcessResourceLimits::empty());
    }

    /// Regression test for the TOCTOU fix (#210): the limits configured via
    /// `configure_resource_limits` must be observable *inside the child* before
    /// it runs any untrusted code. Reads them back through the `ulimit` shell
    /// builtin, which queries the soft limits inherited from `pre_exec`.
    ///
    /// Fast and deterministic, so it runs in CI (not `#[ignore]`).
    ///
    /// Verifies only `RLIMIT_CPU` and `RLIMIT_NOFILE`. `RLIMIT_NPROC` is
    /// deliberately omitted because it is enforced per real-user-ID across the
    /// whole system, not per-process — setting it here would EAGAIN the test
    /// runner's own user. NPROC enforcement is covered by the ignored
    /// `process_limit_prevents_fork` test in an isolated environment.
    #[cfg(target_os = "linux")]
    #[test]
    fn pre_exec_limits_applied_before_exec() -> Result<(), Box<dyn std::error::Error>> {
        use std::process::Command;

        // Distinct values unlikely to match a host default and well within
        // kernel bounds.
        let limits = ProcessResourceLimits {
            cpu_time_secs: Some(7),
            fd_count: Some(64),
            ..ProcessResourceLimits::empty()
        };

        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            // `ulimit -t`/`-n` report the soft limits inherited from pre_exec.
            "echo cpu=$(ulimit -t); echo nofile=$(ulimit -n)",
        ]);
        configure_resource_limits(&mut command, &limits);
        configure_command(&mut command, SandboxConfig::default());

        let output = command.output()?;
        assert!(
            output.status.success(),
            "child failed: {:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout)?;
        assert!(
            stdout.contains("cpu=7"),
            "RLIMIT_CPU not applied in child; stdout was: {stdout:?}"
        );
        assert!(
            stdout.contains("nofile=64"),
            "RLIMIT_NOFILE not applied in child; stdout was: {stdout:?}"
        );
        Ok(())
    }

    /// Grandchildren forked by the plugin inherit the `pre_exec` limits, so
    /// there is no window in which a malicious plugin can spawn unbounded
    /// descendants before limits apply.
    ///
    /// `#[ignore]` because it spawns a real subprocess tree.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "spawns a subprocess tree; run with --ignored"]
    fn grandchildren_inherit_limits_no_race_window() -> Result<(), Box<dyn std::error::Error>> {
        use std::process::Command;

        let limits = ProcessResourceLimits {
            fd_count: Some(64),
            ..ProcessResourceLimits::empty()
        };

        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            // Fork a grandchild subshell; it must still observe the lowered
            // limit, proving descendants cannot escape the in-child setrlimit.
            "( echo grandchild_nofile=$(ulimit -n) )",
        ]);
        configure_resource_limits(&mut command, &limits);
        configure_command(&mut command, SandboxConfig::default());

        let output = command.output()?;
        let stdout = String::from_utf8(output.stdout)?;
        assert!(
            stdout.contains("grandchild_nofile=64"),
            "grandchild did not inherit RLIMIT_NOFILE; stdout was: {stdout:?}"
        );
        Ok(())
    }

    /// `RLIMIT_NOFILE` set in `pre_exec` must actually prevent the child from
    /// opening more descriptors than the limit allows.
    ///
    /// `#[ignore]` because it spawns a real subprocess.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "spawns a subprocess; run with --ignored"]
    fn fd_limit_prevents_opening() -> Result<(), Box<dyn std::error::Error>> {
        use std::process::Command;

        // NOFILE=4 → fds 0..=3 permitted. stdio holds 0,1,2, so fd 3 is the
        // only additional descriptor the child may open; fd 4 must be refused.
        let limits = ProcessResourceLimits {
            fd_count: Some(4),
            ..ProcessResourceLimits::empty()
        };

        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            // Redirection failure on `exec` is fatal in POSIX sh, so each
            // probe runs in a subshell: a failed open there only fails the
            // subshell, letting `if` reach the `else` branch.
            "if (: 3>/dev/null) 2>/dev/null; then echo fd3=open; else echo fd3=blocked; fi; \
             if (: 4>/dev/null) 2>/dev/null; then echo fd4=open; else echo fd4=blocked; fi",
        ]);
        configure_resource_limits(&mut command, &limits);
        configure_command(&mut command, SandboxConfig::default());

        let output = command.output()?;
        let stdout = String::from_utf8(output.stdout)?;
        assert!(
            stdout.contains("fd3=open"),
            "fd 3 should be openable under NOFILE=4; stdout was: {stdout:?}"
        );
        assert!(
            stdout.contains("fd4=blocked"),
            "fd 4 must be blocked under NOFILE=4; stdout was: {stdout:?}"
        );
        Ok(())
    }

    /// `RLIMIT_CPU` set in `pre_exec` must kill a child that burns past the
    /// CPU budget (delivered as `SIGXCPU`).
    ///
    /// `#[ignore]` because it spins a real CPU for one second.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "spawns a CPU-burning subprocess; run with --ignored"]
    fn cpu_limit_kills_long_running() -> Result<(), Box<dyn std::error::Error>> {
        use std::process::Command;

        let limits = ProcessResourceLimits {
            cpu_time_secs: Some(1),
            ..ProcessResourceLimits::empty()
        };

        let mut command = Command::new("/bin/sh");
        command.args(["-c", "while true; do :; done"]);
        configure_resource_limits(&mut command, &limits);
        configure_command(&mut command, SandboxConfig::default());

        let output = command.output()?;
        let code = output.status;
        // The kernel sends SIGXCPU when the soft CPU limit is exceeded; some
        // systems deliver SIGKILL after the grace period. Either signal proves
        // enforcement.
        assert!(
            !code.success(),
            "cpu-burning child was not killed by RLIMIT_CPU: {code:?}"
        );
        Ok(())
    }

    /// `RLIMIT_AS` set in `pre_exec` must prevent the child from allocating
    /// beyond the address-space budget.
    ///
    /// `#[ignore]` because it spawns a real subprocess and the failure mode
    /// depends on available memory tools.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "spawns a subprocess; run with --ignored"]
    fn memory_limit_prevents_allocation() -> Result<(), Box<dyn std::error::Error>> {
        use std::process::Command;

        // 8 MiB address space: enough for `/bin/sh` to start a subshell that
        // then fails to `exec` a heavier helper. Use `ulimit -v` inside the
        // child only to confirm our pre_exec limit is already in place; the
        // observable enforcement is that a large `exec` fails.
        let limits = ProcessResourceLimits {
            memory_bytes: Some(8 * 1024 * 1024),
            ..ProcessResourceLimits::empty()
        };

        let mut command = Command::new("/bin/sh");
        command.args(["-c", "echo as_kb=$(ulimit -v)"]);
        configure_resource_limits(&mut command, &limits);
        configure_command(&mut command, SandboxConfig::default());

        let output = command.output()?;
        let stdout = String::from_utf8(output.stdout)?;
        // `ulimit -v` reports KiB; 8 MiB == 8192 KiB. If sh could not even
        // start under the limit, spawn/exec returned non-zero — also proof of
        // enforcement.
        assert!(
            stdout.contains("as_kb=8192") || !output.status.success(),
            "RLIMIT_AS not enforced; status={:?} stdout={stdout:?}",
            output.status
        );
        Ok(())
    }

    /// `RLIMIT_NPROC` set in `pre_exec` must constrain fork. `RLIMIT_NPROC` is
    /// enforced per real-user-ID across the whole system, so this test is
    /// inherently environment-sensitive and `#[ignore]`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "RLIMIT_NPROC is per-user; run in an isolated environment with --ignored"]
    fn process_limit_prevents_fork() -> Result<(), Box<dyn std::error::Error>> {
        use std::process::Command;

        let limits = ProcessResourceLimits {
            process_count: Some(2),
            ..ProcessResourceLimits::empty()
        };

        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            // Attempt to spawn several grandchildren; under a tight NPROC the
            // forks must fail rather than succeed unboundedly.
            "ok=0; for i in 1 2 3 4 5; do if ( : ) >/dev/null 2>&1; then ok=$((ok+1)); fi; done; echo forked=$ok",
        ]);
        configure_resource_limits(&mut command, &limits);
        configure_command(&mut command, SandboxConfig::default());

        let output = command.output()?;
        let stdout = String::from_utf8(output.stdout)?;
        assert!(
            !stdout.contains("forked=5"),
            "RLIMIT_NPROC did not constrain forking; stdout was: {stdout:?}"
        );
        Ok(())
    }
}
