//! Child probes for the tier-4a suite.
//!
//! Each probe runs in its own process, re-executed from this test binary by a
//! parent in [`crate::suite`], under the exact `configure_*` hooks production
//! registers (order per `crates/arbitraitor-plugin-host/src/executor.rs`:
//! resource limits, network isolation, `configure_command`, filesystem
//! isolation). They are `#[ignore]`d so no runner executes them standalone —
//! a probe without its parent's hooks proves nothing.
//!
//! Every probe records integers into the report file named by
//! `TIER4A_REPORT`. No probe asserts on localized text: the parent asserts on
//! `EPERM=1`, `EACCES=13`, `EAGAIN=11` and on the absence of the forbidden
//! effect.

// Test-only raw syscalls. Four probes need operations no safe API exposes
// under the crate's enabled `rustix` feature set: `socket(2)` (which must fail
// by itself, so `std::net` cannot stand in), `connect(2)` on an inherited
// descriptor, and `unshare(CLONE_NEWUSER)`. Each is one syscall with a
// `// SAFETY:` note, all arguments are integers or a stack-local `sockaddr_in`,
// and no pointer outlives its block.
#![allow(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use arbitraitor_sandbox::{
    ProcessResourceLimits, SandboxConfig, apply_sandbox, configure_resource_limits,
};

use crate::harness::{
    CONNECT_PORT_ENV, DUMPABLE_ENV, INSIDE_ENV, OUTSIDE_ENV, REPORT_ENV, Report, WORKDIR_ENV,
    proc_status_field, tasks_in_user_namespace, thread_count,
};

/// Budget for the parent to publish this probe's uid/gid map.
const MAP_TIMEOUT: Duration = Duration::from_secs(10);
/// Poll interval while waiting for the map.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Appends `KEY=value` to this probe's report file.
fn record(key: &str, value: impl fmt::Display) -> Result<(), Box<dyn Error>> {
    let path = std::env::var(REPORT_ENV)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{key}={value}")?;
    file.flush()?;
    Ok(())
}

fn required_env(name: &str) -> Result<String, Box<dyn Error>> {
    Ok(std::env::var(name).map_err(|error| format!("probe is missing `{name}`: {error}"))?)
}

fn required_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    Ok(PathBuf::from(required_env(name)?))
}

/// Seccomp happy path: performs only allowed file I/O and exits 0.
///
/// Discharged assertion: §43.10 seccomp-BPF "a process using only allowed
/// syscalls exits 0".
#[test]
#[ignore = "probe entry point; re-executed by the tier-4a harness"]
fn seccomp_happy() -> Result<(), Box<dyn Error>> {
    let workdir = required_path(WORKDIR_ENV)?;
    let path = workdir.join("happy.txt");
    std::fs::write(&path, b"tier4a")?;
    let read_back = std::fs::read(&path)?;
    record("READBACK", String::from_utf8_lossy(&read_back))?;
    Ok(())
}

/// Seccomp adversarial path: a denied `socket(2)` fails with `EPERM` and the
/// process survives to record that it was still alive afterwards.
///
/// Discharged assertion: §43.10 seccomp-BPF "a process attempting a denied
/// syscall fails with EPERM ... and has no other effect". Death is a contract
/// violation (ADR-0020), so the probe records survival instead of dying.
#[test]
#[ignore = "probe entry point; re-executed by the tier-4a harness"]
fn seccomp_adversarial() -> Result<(), Box<dyn Error>> {
    // SAFETY: `socket(2)` takes three integer constants and returns a fresh
    // descriptor or -1. It dereferences no pointer. Any returned descriptor is
    // intentionally left open: the probe exits immediately afterwards.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        record(
            "SOCKET_ERRNO",
            io::Error::last_os_error().raw_os_error().unwrap_or(-1),
        )?;
    } else {
        // The filter let the call through: record 0 so the parent's `EPERM`
        // assertion fails instead of the probe aborting for a different reason.
        record("SOCKET_ERRNO", 0)?;
    }
    // Only reached when the syscall did not terminate the process.
    record("ALIVE_AFTER_DENIED", 1)?;
    Ok(())
}

/// Connect-back probe: dials `127.0.0.1:<port>` on the descriptor inherited as
/// standard input and records the result.
///
/// The descriptor is a socket the parent created but never connected;
/// `SYS_socket`/`SYS_socketpair` are denied, so the only way to exercise
/// `connect(2)` itself is on a descriptor handed across the fork.
#[test]
#[ignore = "probe entry point; re-executed by the tier-4a harness"]
fn connect_back() -> Result<(), Box<dyn Error>> {
    let port: u16 = required_env(CONNECT_PORT_ENV)?.parse()?;
    let family = libc::sa_family_t::try_from(libc::AF_INET)
        .map_err(|error| format!("`AF_INET` does not fit in `sa_family_t`: {error}"))?;
    let address = libc::sockaddr_in {
        sin_family: family,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(std::net::Ipv4Addr::LOCALHOST.octets()),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: `connect(2)` reads a `sockaddr_in` of exactly the length passed
    // and writes nothing back. The address lives on this stack frame for the
    // duration of the call, and descriptor 0 is a socket inherited from the
    // parent by the harness contract.
    let ret = unsafe {
        libc::connect(
            0,
            (&raw const address).cast::<libc::sockaddr>(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_in>())
                .unwrap_or(libc::socklen_t::MAX),
        )
    };
    if ret == 0 {
        record("CONNECT_ERRNO", 0)?;
    } else {
        record(
            "CONNECT_ERRNO",
            io::Error::last_os_error().raw_os_error().unwrap_or(-1),
        )?;
    }
    Ok(())
}

/// `PR_SET_DUMPABLE` probe: applies the public [`apply_sandbox`] hardening to
/// *this* process, then blocks until the parent lets it go.
///
/// The hardening is applied in-process rather than through
/// `configure_command`'s `pre_exec` hook because `execve` resets the dumpable
/// attribute to 1 for a non-setuid binary; the `pre_exec` arrangement is
/// therefore not observable from the parent. The production-path divergence is
/// tracked in #835.
#[test]
#[ignore = "probe entry point; re-executed by the tier-4a harness"]
fn dumpable() -> Result<(), Box<dyn Error>> {
    let dumpable = required_env(DUMPABLE_ENV)? == "1";
    apply_sandbox(&SandboxConfig {
        no_new_privs: false,
        dumpable,
        close_fds: false,
    })?;
    // Readiness marker: the parent attaches only after the hardening call
    // returned, so a race cannot be read as enforcement.
    record("READY", 1)?;
    let mut buffer = [0_u8; 1];
    let _ignored = io::stdin().read(&mut buffer)?;
    Ok(())
}

/// `PR_SET_NO_NEW_PRIVS` probe: reports the `NoNewPrivs` state the kernel
/// records for this process.
///
/// Discharged assertion: §43.10 prctl hardening "`PR_SET_NO_NEW_PRIVS, 1`".
/// The field is read back from `/proc/self/status`, so the value is the
/// kernel's answer, not an echo of the requested configuration.
#[test]
#[ignore = "probe entry point; re-executed by the tier-4a harness"]
fn no_new_privs() -> Result<(), Box<dyn Error>> {
    let raw = proc_status_field(Path::new("/proc/self/status"), "NoNewPrivs:")?
        .ok_or_else(|| "`/proc/self/status` has no `NoNewPrivs:` field".to_string())?;
    record("NO_NEW_PRIVS", raw)?;
    Ok(())
}

/// Landlock probe: writes inside the permitted directory (must succeed) and
/// outside it (must fail with `EACCES`).
///
/// Discharged assertion: §43.10 Landlock "write outside allowed paths →
/// EACCES; write inside allowed paths → success".
#[test]
#[ignore = "probe entry point; re-executed by the tier-4a harness"]
fn landlock_fs() -> Result<(), Box<dyn Error>> {
    let inside = required_path(INSIDE_ENV)?;
    let outside = required_path(OUTSIDE_ENV)?;

    match std::fs::write(inside.join("allowed.txt"), b"tier4a") {
        Ok(()) => record("INSIDE_ERRNO", 0)?,
        Err(error) => {
            record("INSIDE_ERRNO", error.raw_os_error().unwrap_or(-1))?;
        }
    }
    match std::fs::write(outside.join("denied.txt"), b"tier4a") {
        Ok(()) => record("OUTSIDE_ERRNO", 0)?,
        Err(error) => record("OUTSIDE_ERRNO", error.raw_os_error().unwrap_or(-1))?,
    }
    Ok(())
}

/// Announces that this process already runs inside a fresh user namespace and
/// waits for the parent to publish the uid map.
///
/// The namespace itself is created in the `pre_exec` hook the parent
/// registers (see `userns_probe_command`), because `unshare(CLONE_NEWUSER)`
/// fails with `EINVAL` in a multi-threaded process and the test harness is
/// one.
fn announce_namespace() -> Result<(), Box<dyn Error>> {
    // A namespace with no published mapping runs as `nobody`, so the report
    // file is pre-created world-writable by the parent.
    record("UNSHARED", 1)?;

    let deadline = Instant::now() + MAP_TIMEOUT;
    loop {
        let mapped = std::fs::read_to_string("/proc/self/uid_map")?;
        if !mapped.trim().is_empty() {
            record("UID", rustix::process::getuid().as_raw())?;
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the uid map was not published within {MAP_TIMEOUT:?}; the probe cannot run \
                 inside the namespace"
            )
            .into());
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// User-namespace precondition probe: proves unprivileged user namespaces are
/// creatable and mappable on this host.
#[test]
#[ignore = "probe entry point; re-executed by the tier-4a harness"]
fn userns_inside() -> Result<(), Box<dyn Error>> {
    announce_namespace()?;
    record("USERNS", 1)?;
    Ok(())
}

/// `RLIMIT_NPROC` probe: runs both arms inside a fresh user namespace.
///
/// Discharged assertion: §43.10 `RLIMIT_NPROC` with its binding
/// environment-sensitivity paragraph. The baseline arm proves this namespace
/// can fork at all; the limited arm then proves the *limit* denies the second
/// fork. Without the baseline an ambient `EAGAIN` would be indistinguishable
/// from enforcement.
#[test]
#[ignore = "probe entry point; re-executed by the tier-4a harness"]
fn nproc_inside() -> Result<(), Box<dyn Error>> {
    announce_namespace()?;
    let workdir = required_path(WORKDIR_ENV)?;

    // Baseline arm: no limit at all. Two forks must succeed in this namespace,
    // which is what excludes an ambient `EAGAIN` from the evidence.
    let baseline = run_forker(&workdir, "forker-baseline.report", None)?;
    record("BASELINE_FORK1", baseline.text("FORK1")?)?;
    record("BASELINE_FORK2", baseline.text("FORK2")?)?;
    record(
        "BASELINE_TASKS_BEFORE_FORK",
        baseline.text("TASKS_BEFORE_FORK")?,
    )?;

    // Calibration. `RLIMIT_NPROC` is compared against the number of tasks the
    // namespace's real uid owns: this probe's own threads, the supervisor
    // thread `ChildGuard::wait` holds while it watches the forker, and the
    // forker's threads. Exactly one task of slack leaves room for the first
    // fork, so the *second* one is the one the limit must deny. The forker
    // reports `TASKS_BEFORE_FORK`, so the parent verifies this arithmetic
    // instead of trusting it.
    let probe_tasks = thread_count()?;
    let supervisor_tasks = 1;
    let forker_threads: u32 = baseline.int("FORKER_THREADS")?.try_into()?;
    let limit = probe_tasks
        .checked_add(supervisor_tasks)
        .and_then(|value| value.checked_add(forker_threads))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| "task count overflow while calibrating RLIMIT_NPROC".to_string())?;
    record("LIMIT", limit)?;
    record("PROBE_THREADS", probe_tasks)?;

    // Limited arm: the same forker, with the limit applied by the crate's
    // `configure_resource_limits` hook in `pre_exec`.
    let limited = run_forker(&workdir, "forker-limited.report", Some(limit))?;
    record("FORK1", limited.text("FORK1")?)?;
    record("TASKS_BEFORE_FORK", limited.text("TASKS_BEFORE_FORK")?)?;
    record("TASKS_AFTER_FORK1", limited.text("TASKS_AFTER_FORK1")?)?;
    record("NPROC_LIMIT", limited.text("NPROC_LIMIT")?)?;
    match limited.text("FORK2_ERRNO") {
        Ok(value) => record("FORK2_ERRNO", value)?,
        Err(_) => record("FORK2", limited.text("FORK2")?)?,
    }
    Ok(())
}

/// `RLIMIT_NPROC` forker: attempts two forks that each keep one child alive.
///
/// The second attempt is the one the limit must deny. The first child is kept
/// alive deliberately: `RLIMIT_NPROC` is decremented when a task exits, so
/// reaping it first would hide the limit.
#[test]
#[ignore = "probe entry point; re-executed by the tier-4a harness"]
fn nproc_forker() -> Result<(), Box<dyn Error>> {
    record("FORKER_THREADS", thread_count()?)?;
    record("FORKER_UID", rustix::process::getuid().as_raw())?;
    record("TASKS_BEFORE_FORK", tasks_in_user_namespace()?)?;
    let current = rustix::process::getrlimit(rustix::process::Resource::Nproc).current;
    record(
        "NPROC_LIMIT",
        current.map_or(-1_i64, |value| i64::try_from(value).unwrap_or(-1)),
    )?;

    let mut first = spawn_holder()?;
    record("FORK1", "ok")?;
    record("TASKS_AFTER_FORK1", tasks_in_user_namespace()?)?;
    match spawn_holder() {
        Ok(mut second) => {
            // The limit let the second fork through: recording `FORK2=ok` makes
            // the parent's `EAGAIN` assertion fail where it belongs.
            record("FORK2", "ok")?;
            second.kill()?;
            let _ignored = second.wait()?;
        }
        Err(error) => record("FORK2_ERRNO", error.raw_os_error().unwrap_or(-1))?,
    }
    first.kill()?;
    let _ignored = first.wait()?;
    Ok(())
}

/// Spawns a `sleep` child that stays alive until killed.
fn spawn_holder() -> io::Result<std::process::Child> {
    Command::new("/bin/sleep")
        .arg("5")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
}

/// Runs the forker probe with an optional `RLIMIT_NPROC` applied in `pre_exec`.
fn run_forker(
    workdir: &Path,
    report_name: &str,
    process_count: Option<u32>,
) -> Result<Report, Box<dyn Error>> {
    let report_path = workdir.join(report_name);
    let mut command = crate::harness::probe_command("nproc_forker", &report_path)?;
    command.stdin(std::process::Stdio::null());
    let limits = ProcessResourceLimits {
        process_count: process_count.map(u64::from),
        ..ProcessResourceLimits::empty()
    };
    configure_resource_limits(&mut command, &limits);
    let mut run = crate::harness::ChildGuard::spawn(&mut command)?;
    let status = run.wait("nproc_forker")?;
    if !status.success() {
        return Err(format!(
            "nproc forker `{report_name}` failed with {status:?}; the record it did write is \
             retried below: {}",
            std::fs::read_to_string(&report_path).unwrap_or_default()
        )
        .into());
    }
    Report::read(&report_path)
}
