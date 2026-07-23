//! Linux-specific sandbox adapters (spec §27.3).

use std::process::Command;

use serde::{Deserialize, Serialize};

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

/// Container runtime version information probed from the host (spec §27.3).
///
/// Records the container runtime name, version, and whether the version falls
/// below the patched floor for the 2025-11-05 runc container-escape CVE
/// cluster (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881). Receipt
/// consumers use this to audit whether a contained run executed on a
/// patched runtime.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ContainerRuntime {
    /// Runtime name (e.g. `"runc"`, `"containerd"`).
    pub name: String,
    /// Semver version string (e.g. `"1.2.7"`).
    pub version: String,
    /// `true` when the version is below the patched floor for the
    /// 2025-11-05 runc container-escape CVE cluster. Only set for `runc`;
    /// `containerd` reports `false` because the CVEs are in the `runc`
    /// OCI runtime, not the containerd daemon itself.
    pub cve_vulnerable: bool,
}

/// Parsed semantic version components used for vulnerability comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SemverVersion {
    /// Major version number.
    major: u32,
    /// Minor version number.
    minor: u32,
    /// Patch version number.
    patch: u32,
    /// Optional pre-release identifier (e.g. `"rc.2"`, `"alpha.1"`).
    pre_release: Option<String>,
}

/// Probes the container runtime version on the running host (spec §27.3).
///
/// Arbitraitor records the container runtime version in receipts so auditors
/// can verify a contained run did not execute on a runtime vulnerable to the
/// 2025-11-05 runc container-escape CVE cluster (CVE-2025-31133,
/// CVE-2025-52565, CVE-2025-52881).
///
/// The probe tries `runc --version` first (the CVEs are runc-specific), then
/// falls back to `containerd --version`. When a vulnerable runc version is
/// detected, [`ContainerRuntime::cve_vulnerable`] is `true` and the exec
/// crate emits a `tracing::warn!` recommending upgrade to runc 1.2.8 /
/// 1.3.3 / 1.4.0-rc.3 or later.
///
/// Returns `None` when no container runtime binary is found or on non-Linux
/// platforms.
#[must_use]
#[cfg(target_os = "linux")]
pub fn probe_container_runtime() -> Option<ContainerRuntime> {
    probe_runc_version().or_else(probe_containerd_version)
}

/// Probes the container runtime version.
///
/// Non-Linux platforms have no `runc` / `containerd` binary surface and
/// therefore report `None`.
#[must_use]
#[cfg(not(target_os = "linux"))]
pub const fn probe_container_runtime() -> Option<ContainerRuntime> {
    None
}

/// Probes `runc --version` and checks the version against the CVE cluster.
#[cfg(target_os = "linux")]
fn probe_runc_version() -> Option<ContainerRuntime> {
    for candidate in ["/usr/bin/runc", "/usr/local/bin/runc", "runc"] {
        let output = Command::new(candidate).arg("--version").output();
        if let Ok(output) = output
            && output.status.success()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(version_str) = extract_version_from_output(&stdout) {
                let vulnerable =
                    parse_semver(&version_str).is_some_and(|v| is_runc_version_vulnerable(&v));
                return Some(ContainerRuntime {
                    name: "runc".to_owned(),
                    version: version_str,
                    cve_vulnerable: vulnerable,
                });
            }
        }
    }
    None
}

/// Probes `containerd --version`. The CVEs are runc-specific, so
/// `cve_vulnerable` is always `false` for containerd.
#[cfg(target_os = "linux")]
fn probe_containerd_version() -> Option<ContainerRuntime> {
    for candidate in [
        "/usr/bin/containerd",
        "/usr/local/bin/containerd",
        "containerd",
    ] {
        let output = Command::new(candidate).arg("--version").output();
        if let Ok(output) = output
            && output.status.success()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(version_str) = extract_version_from_output(&stdout) {
                return Some(ContainerRuntime {
                    name: "containerd".to_owned(),
                    version: version_str,
                    cve_vulnerable: false,
                });
            }
        }
    }
    None
}

/// Extracts the first semver-like token from a `--version` output line.
///
/// `runc --version` emits `runc version 1.2.7` on the first line;
/// `containerd --version` emits `containerd github.com/... v1.7.0`. This
/// helper scans the first line's whitespace-separated tokens for the first
/// that looks like `MAJOR.MINOR.PATCH` with an optional `-prerelease` suffix.
fn extract_version_from_output(output: &str) -> Option<String> {
    let first_line = output.lines().next()?;
    for token in first_line.split_whitespace() {
        let candidate = token.trim_start_matches('v').trim_end_matches(',');
        if is_semver_like(candidate) {
            return Some(candidate.to_owned());
        }
    }
    None
}

/// Returns `true` when `s` matches `MAJOR.MINOR.PATCH` with an optional
/// `-prerelease` suffix.
fn is_semver_like(s: &str) -> bool {
    let main = s.split('-').next().unwrap_or(s);
    let parts: Vec<&str> = main.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok())
}

/// Parses a semver string into [`SemverVersion`] components.
fn parse_semver(version: &str) -> Option<SemverVersion> {
    let version = version.trim().trim_start_matches('v');
    let (main, pre_release) = match version.split_once('-') {
        Some((main, pre)) => (main, Some(pre.to_owned())),
        None => (version, None),
    };
    let parts: Vec<&str> = main.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let major = parts[0].parse::<u32>().ok()?;
    let minor = parts[1].parse::<u32>().ok()?;
    let patch = parts[2].parse::<u32>().ok()?;
    Some(SemverVersion {
        major,
        minor,
        patch,
        pre_release,
    })
}

/// Checks whether a parsed runc version is below the patched floor for the
/// 2025-11-05 container-escape CVE cluster.
///
/// Patched floors (issue #458):
/// - runc 1.2.x: patched in 1.2.8
/// - runc 1.3.x: patched in 1.3.3
/// - runc 1.4.x: patched in 1.4.0-rc.3
///
/// Versions in the 1.0.x and 1.1.x series, and all 0.x releases, predate the
/// patched series and are treated as vulnerable. Future major versions (2.x+)
/// are treated as safe.
fn is_runc_version_vulnerable(version: &SemverVersion) -> bool {
    match (version.major, version.minor) {
        // runc 1.2.x: patched in 1.2.8
        (1, 2) => version.patch < 8,
        // runc 1.3.x: patched in 1.3.3
        (1, 3) => version.patch < 3,
        // runc 1.4.x: patched in 1.4.0-rc.3
        (1, 4) => version.patch == 0 && is_prerelease_below_rc3(version.pre_release.as_deref()),
        // runc 1.0.x, 1.1.x, 0.x: predate the patched series
        (1, 0 | 1) | (0, _) => true,
        // Future major versions: treated as safe
        _ => false,
    }
}

/// Returns `true` when a 1.4.0 pre-release identifier is below `rc.3`.
///
/// `None` (the release version 1.4.0) is safe. Pre-release identifiers that
/// are `rc.N` where `N < 3` are vulnerable. Other pre-release types (alpha,
/// beta, dev) predate the rc stage and are vulnerable.
fn is_prerelease_below_rc3(pre_release: Option<&str>) -> bool {
    match pre_release {
        None => false,
        Some(pre) => {
            if let Some(rc_num) = pre.strip_prefix("rc.")
                && let Ok(n) = rc_num.parse::<u32>()
            {
                return n < 3;
            }
            true
        }
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

    #[test]
    fn semver_parse_extracts_major_minor_patch_and_prerelease() {
        // Given: semver strings with and without pre-release suffixes.
        // When: parsing into SemverVersion components.
        // Then: major/minor/patch and pre_release are correctly extracted.
        let v = parse_semver("1.2.7").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (1, 2, 7));
        assert_eq!(v.pre_release, None);

        let v = parse_semver("v1.4.0-rc.2").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (1, 4, 0));
        assert_eq!(v.pre_release.as_deref(), Some("rc.2"));

        let v = parse_semver("2.0.0").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (2, 0, 0));
    }

    #[test]
    fn semver_parse_rejects_non_semver_strings() {
        // Given: strings that are not valid semver.
        // When: parsing.
        // Then: None is returned for each.
        assert_eq!(parse_semver("not-a-version"), None);
        assert_eq!(parse_semver("1.2"), None);
        assert_eq!(parse_semver("1.2.3.4"), None);
        assert_eq!(parse_semver(""), None);
    }

    #[test]
    fn runc_vulnerability_detects_patched_and_unpatched_versions() {
        // Given: runc versions spanning the 2025-11-05 CVE cluster patched floors.
        // When: checking vulnerability status.
        // Then: versions below the floor are vulnerable, at/above are safe.
        // 1.2.x: patched in 1.2.8
        assert!(is_runc_version_vulnerable(&parse_semver("1.2.7").unwrap()));
        assert!(!is_runc_version_vulnerable(&parse_semver("1.2.8").unwrap()));
        assert!(!is_runc_version_vulnerable(&parse_semver("1.2.9").unwrap()));
        // 1.3.x: patched in 1.3.3
        assert!(is_runc_version_vulnerable(&parse_semver("1.3.2").unwrap()));
        assert!(!is_runc_version_vulnerable(&parse_semver("1.3.3").unwrap()));
        // 1.4.x: patched in 1.4.0-rc.3
        assert!(is_runc_version_vulnerable(
            &parse_semver("1.4.0-rc.2").unwrap()
        ));
        assert!(!is_runc_version_vulnerable(
            &parse_semver("1.4.0-rc.3").unwrap()
        ));
        assert!(!is_runc_version_vulnerable(&parse_semver("1.4.0").unwrap()));
        assert!(!is_runc_version_vulnerable(&parse_semver("1.4.1").unwrap()));
        // 1.0.x, 1.1.x, 0.x: predate patched series
        assert!(is_runc_version_vulnerable(&parse_semver("1.1.0").unwrap()));
        assert!(is_runc_version_vulnerable(&parse_semver("1.0.0").unwrap()));
        assert!(is_runc_version_vulnerable(&parse_semver("0.1.0").unwrap()));
        // 2.x+: future, safe
        assert!(!is_runc_version_vulnerable(&parse_semver("2.0.0").unwrap()));
    }

    #[test]
    fn runc_vulnerability_treats_non_rc_prereleases_as_vulnerable() {
        // Given: 1.4.0 pre-release identifiers that predate the rc stage.
        // When: checking vulnerability.
        // Then: alpha/beta/dev are vulnerable; release 1.4.0 is safe.
        assert!(is_runc_version_vulnerable(
            &parse_semver("1.4.0-alpha.1").unwrap()
        ));
        assert!(is_runc_version_vulnerable(
            &parse_semver("1.4.0-beta.1").unwrap()
        ));
        assert!(!is_runc_version_vulnerable(&parse_semver("1.4.0").unwrap()));
    }

    #[test]
    fn extract_version_from_runc_output() {
        // Given: runc --version output with "runc version 1.2.7" on first line.
        // When: extracting the version token.
        // Then: "1.2.7" is returned.
        let output = "runc version 1.2.7\ncommit: abc123\nspec: 1.2.0\n";
        assert_eq!(
            extract_version_from_output(output),
            Some("1.2.7".to_owned())
        );
    }

    #[test]
    fn extract_version_from_containerd_output() {
        // Given: containerd --version output with "v1.7.0" token.
        // When: extracting the version token.
        // Then: "1.7.0" is returned (v prefix stripped).
        let output = "containerd github.com/containerd/containerd v1.7.0\n";
        assert_eq!(
            extract_version_from_output(output),
            Some("1.7.0".to_owned())
        );
    }

    #[test]
    fn extract_version_returns_none_for_garbage_output() {
        // Given: output with no semver-like token.
        // When: extracting.
        // Then: None is returned.
        assert_eq!(extract_version_from_output("no version here\n"), None);
        assert_eq!(extract_version_from_output(""), None);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn container_runtime_probe_returns_none_off_linux() {
        assert_eq!(probe_container_runtime(), None);
    }

    #[test]
    fn container_runtime_serializes_for_receipt() {
        // Given: a ContainerRuntime with a vulnerable runc version.
        // When: serializing to JSON.
        // Then: the JSON contains name, version, and cve_vulnerable fields.
        let runtime = ContainerRuntime {
            name: "runc".to_owned(),
            version: "1.2.7".to_owned(),
            cve_vulnerable: true,
        };
        let json = serde_json::to_string(&runtime).unwrap();
        assert!(json.contains("\"name\":\"runc\""));
        assert!(json.contains("\"version\":\"1.2.7\""));
        assert!(json.contains("\"cve_vulnerable\":true"));
    }
}
