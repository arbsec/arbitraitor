//! Spawn, supervise, and read back tier-4a child probes.
//!
//! The harness exists so a parent test can assert on *observations* (report
//! integers, exit status, listener state) instead of prose. Two invariants
//! hold for every spawn:
//!
//! * **No unbounded wait.** Every probe runs under a watchdog
//!   ([`ChildGuard::wait`]) that kills and reaps the probe's whole process
//!   group after [`PROBE_TIMEOUT`] and fails the test. A hung probe can never
//!   stall the 40-minute CI job.
//! * **No leaked process.** [`ChildGuard`] kills and reaps on drop, so a panic
//!   in an assertion leaves no zombie behind.
//!
//! The only fixed durations are *negative-assertion windows* (how long the
//! connect-back listener is watched for a connection that must never arrive)
//! and *budgets* for a positive event to show up; both are named constants.

// Test-only raw syscalls: creating the unconnected client socket for the
// connect-back pattern and attaching `ptrace` are the two operations the
// public `arbitraitor-sandbox` API does not wrap, and that no safe API exposes
// under the crate's enabled `rustix` feature set (`net` is not enabled). Each
// use is a single syscall with a `// SAFETY:` note and no pointer escapes.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustix::process::{Pid, Signal, WaitOptions};

/// Result type for a parent test.
pub(crate) type TestResult = Result<(), Box<dyn Error>>;

/// Report-file path handed to a probe.
pub(crate) const REPORT_ENV: &str = "TIER4A_REPORT";
/// Scratch directory handed to a probe that performs allowed file I/O.
pub(crate) const WORKDIR_ENV: &str = "TIER4A_WORKDIR";
/// TCP port the connect-back probe must dial.
pub(crate) const CONNECT_PORT_ENV: &str = "TIER4A_CONNECT_PORT";
/// `PR_SET_DUMPABLE` value the dumpable probe must apply to itself.
pub(crate) const DUMPABLE_ENV: &str = "TIER4A_DUMPABLE";
/// Directory the Landlock probe may write into.
pub(crate) const INSIDE_ENV: &str = "TIER4A_INSIDE";
/// Directory the Landlock probe must be denied.
pub(crate) const OUTSIDE_ENV: &str = "TIER4A_OUTSIDE";

/// Wall-clock budget for a probe to finish before it is killed and the test
/// fails. Generous: a probe that reaches this is hung, not slow.
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
/// Budget for a probe's readiness marker (for example `UNSHARED=1`) to appear.
const READY_TIMEOUT: Duration = Duration::from_secs(10);
/// Budget for a positive event that must happen (a `ptrace` stop).
const EVENT_TIMEOUT: Duration = Duration::from_secs(2);
/// Negative-assertion window: how long a listener is watched for a connection
/// that must never arrive.
const SILENCE_WINDOW: Duration = Duration::from_millis(500);
/// Poll interval for deadline-bounded waits. Never used as a bare sleep.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// A unique scratch directory, removed on drop.
pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates a unique directory under the platform temp directory.
    pub(crate) fn new(prefix: &str) -> io::Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| io::Error::other(error.to_string()))?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "arbitraitor-tier4a-{prefix}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// Returns the directory path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.path);
    }
}

/// Parsed `KEY=value` report written by a probe.
pub(crate) struct Report {
    values: BTreeMap<String, String>,
}

impl Report {
    fn parse(text: &str) -> Self {
        let mut values = BTreeMap::new();
        for line in text.lines() {
            if let Some((key, value)) = line.split_once('=') {
                let _previous = values.insert(key.trim().to_owned(), value.trim().to_owned());
            }
        }
        Self { values }
    }

    /// Reads and parses a report file.
    ///
    /// An unreadable report is a failure: a probe that died before writing
    /// evidence must never be read as a pass.
    pub(crate) fn read(path: &Path) -> Result<Self, Box<dyn Error>> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            format!(
                "probe report `{}` is unreadable ({error}); the probe did not record evidence",
                path.display()
            )
        })?;
        Ok(Self::parse(&text))
    }

    /// Returns a textual value, failing the test when the key is absent.
    pub(crate) fn text(&self, key: &str) -> Result<&str, Box<dyn Error>> {
        self.values.get(key).map(String::as_str).ok_or_else(|| {
            format!("probe report is missing `{key}`; recorded values: {self:?}").into()
        })
    }

    /// Returns an integer value, failing the test when absent or non-numeric.
    pub(crate) fn int(&self, key: &str) -> Result<i32, Box<dyn Error>> {
        let raw = self.text(key)?;
        raw.parse::<i32>().map_err(|error| {
            format!("probe report key `{key}` is not an integer: {raw:?} ({error})").into()
        })
    }
}

impl fmt::Debug for Report {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_map().entries(&self.values).finish()
    }
}

/// Builds the `Command` that re-executes this test binary as `name`.
///
/// The probe names are `#[ignore]`d, so the arguments select exactly one
/// ignored test and run it single-threaded with output captured by the parent
/// test runner.
pub(crate) fn probe_command(name: &str, report_path: &Path) -> Result<Command, Box<dyn Error>> {
    let exe = std::env::current_exe()?;
    let mut command = Command::new(exe);
    command.args([
        "--ignored",
        "--exact",
        &format!("probes::{name}"),
        "--nocapture",
        "--test-threads=1",
    ]);
    command.env(REPORT_ENV, report_path);
    // Own process group: a runaway probe (or a descendant it forked) is killed
    // as a group by the watchdog instead of outliving the test.
    command.process_group(0);
    Ok(command)
}

/// Builds the `Command` that re-executes this test binary as a probe inside a
/// fresh unprivileged user namespace.
///
/// The namespace is created in `pre_exec`: `unshare(CLONE_NEWUSER)` fails with
/// `EINVAL` in a multi-threaded process, and the test harness is one. The
/// pre-exec child is single-threaded, so the syscall is legal there; the
/// namespace then survives the `execve`.
pub(crate) fn userns_probe_command(
    name: &str,
    report_path: &Path,
) -> Result<Command, Box<dyn Error>> {
    let mut command = probe_command(name, report_path)?;
    // SAFETY: the closure runs in the forked child between `fork` and `execve`.
    // It performs one `unshare(2)` syscall with integer arguments, allocates
    // nothing, takes no lock, and dereferences no pointer.
    unsafe {
        command.pre_exec(|| {
            let ret = libc::unshare(libc::CLONE_NEWUSER);
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(command)
}

/// Creates an empty report file the namespace creator can write before its uid
/// map is published (a process with no mapped uid runs as `nobody`).
pub(crate) fn create_writable_report(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    drop(file);
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o666);
    std::fs::set_permissions(path, permissions)
}

/// A spawned probe supervised by this harness.
pub(crate) struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    /// Spawns `command` under supervision.
    pub(crate) fn spawn(command: &mut Command) -> io::Result<Self> {
        Ok(Self {
            child: Some(command.spawn()?),
        })
    }

    /// Returns the probe's process id (also its process-group id).
    pub(crate) fn pid(&self) -> Result<u32, Box<dyn Error>> {
        self.child
            .as_ref()
            .map(Child::id)
            .ok_or_else(|| "probe was already reaped".into())
    }

    /// Takes the probe's stdin pipe so the parent controls when it unblocks.
    pub(crate) fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.as_mut().and_then(|child| child.stdin.take())
    }

    /// Waits for the probe, killing its process group and failing the test
    /// when it exceeds [`PROBE_TIMEOUT`].
    pub(crate) fn wait(&mut self, label: &str) -> Result<ExitStatus, Box<dyn Error>> {
        let Some(mut child) = self.child.take() else {
            return Err(format!("{label}: probe was already reaped").into());
        };
        let pid = child.id();
        let (sender, receiver) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let status = child.wait();
            let _ignored = sender.send(status);
        });

        if let Ok(status) = receiver.recv_timeout(PROBE_TIMEOUT) {
            let _ignored = waiter.join();
            Ok(status?)
        } else {
            // The waiter thread is still blocked in `wait`, so it reaps the
            // probe once the kill lands: no zombie, no leaked group.
            let _ignored = kill_process_group(pid);
            let _ignored = waiter.join();
            Err(format!(
                "{label}: probe exceeded {PROBE_TIMEOUT:?} and was killed; a hung probe is a \
                 test failure, not a slow pass"
            )
            .into())
        }
    }

    /// Kills and reaps the probe group without reporting an outcome.
    pub(crate) fn kill(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ignored = kill_process_group(child.id());
            let _ignored = child.wait();
        }
        self.child = None;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

fn kill_process_group(pid: u32) -> io::Result<()> {
    let raw = i32::try_from(pid).map_err(|_| io::Error::other("pid does not fit in pid_t"))?;
    let pid = Pid::from_raw(raw).ok_or_else(|| io::Error::other("probe pid is not a valid pid"))?;
    rustix::process::kill_process_group(pid, Signal::KILL).map_err(io::Error::from)
}

/// Polls `path` until the report contains `key`, within [`READY_TIMEOUT`].
pub(crate) fn wait_for_report_key(
    path: &Path,
    key: &str,
    timeout: Duration,
) -> Result<Report, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            let report = Report::parse(&text);
            if report.values.contains_key(key) {
                return Ok(report);
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out after {timeout:?} waiting for `{key}` in `{}`",
                path.display()
            )
            .into());
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Polls a non-blocking listener for `window`, reporting whether it accepted.
///
/// This is the negative-assertion window of the connect-back pattern: the
/// absence of a connection is the enforcement evidence.
pub(crate) fn poll_accept(listener: &std::net::TcpListener, window: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + window;
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                drop(stream);
                return Ok(true);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Returns the connect-back silence window.
pub(crate) fn silence_window() -> Duration {
    SILENCE_WINDOW
}

/// Returns the budget for a probe readiness marker.
pub(crate) fn ready_timeout() -> Duration {
    READY_TIMEOUT
}

/// Creates an unconnected TCP socket for the connect-back pattern.
///
/// The child must call `connect()` on a descriptor that is not already
/// listening, and `SYS_socket` is denied inside the filter, so the parent
/// creates the socket and hands it to the child as standard input.
pub(crate) fn unconnected_tcp_socket() -> Result<OwnedFd, Box<dyn Error>> {
    // SAFETY: `socket(2)` takes three integer constants and returns a fresh
    // descriptor owned by this process. It dereferences no pointer and cannot
    // alias any existing descriptor.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: `fd` was just returned by `socket(2)`, is not owned by anything
    // else, and is closed exactly once when the `OwnedFd` is dropped (or moved
    // into `Stdio`).
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Parses one `/proc/<pid>/status` field, returning `None` when absent.
pub(crate) fn proc_status_field(path: &Path, name: &str) -> Result<Option<String>, Box<dyn Error>> {
    let status = std::fs::read_to_string(path)?;
    Ok(status
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .map(|value| value.trim().to_owned()))
}

/// Reads this process's `Threads:` count.
pub(crate) fn thread_count() -> Result<u32, Box<dyn Error>> {
    let raw = proc_status_field(Path::new("/proc/self/status"), "Threads:")?
        .ok_or_else(|| "`/proc/self/status` has no `Threads:` field".to_string())?;
    Ok(raw.parse::<u32>()?)
}

/// Counts the tasks (threads of every process) that `RLIMIT_NPROC` compares
/// against: those of this process's own user namespace.
///
/// The count is per user namespace, not per machine, which is why the tier-4a
/// `RLIMIT_NPROC` assertion calibrates its limit from inside the namespace.
/// Entries this process cannot inspect are skipped; they cannot belong to the
/// same namespace *and* be unreadable to the namespace owner.
pub(crate) fn tasks_in_user_namespace() -> Result<u32, Box<dyn Error>> {
    let ours = std::fs::read_link("/proc/self/ns/user")?;
    let mut total = 0_u32;
    for entry in std::fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Some(pid) = name.to_str() else { continue };
        if !pid.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        if !std::fs::read_link(entry.path().join("ns/user")).is_ok_and(|link| link == ours) {
            continue;
        }
        if let Ok(Some(threads)) = proc_status_field(&entry.path().join("status"), "Threads:") {
            total += threads.parse::<u32>()?;
        }
    }
    Ok(total)
}

/// Reads this process's `NoNewPrivs:` state.
pub(crate) fn no_new_privs_state() -> Result<i32, Box<dyn Error>> {
    let raw = proc_status_field(Path::new("/proc/self/status"), "NoNewPrivs:")?
        .ok_or_else(|| "`/proc/self/status` has no `NoNewPrivs:` field".to_string())?;
    Ok(raw.parse::<i32>()?)
}

/// Renders `kernel.yama.ptrace_scope` for a failure message.
pub(crate) fn ptrace_scope_text() -> String {
    match std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        Ok(value) => value.trim().to_owned(),
        Err(error) => format!("unreadable ({error})"),
    }
}

/// Writes the uid/gid map for a probe that unshared a user namespace.
///
/// A process cannot map its own uid from inside the new namespace, so the
/// parent (the namespace owner) performs the mapping; the probe then polls its
/// own `/proc/self/uid_map` until the mapping is visible.
pub(crate) fn write_userns_maps(pid: u32) -> Result<(), Box<dyn Error>> {
    let base = PathBuf::from(format!("/proc/{pid}"));
    // `setgroups` only exists on kernels that support unprivileged gid maps;
    // its absence is not a failure, any other error is.
    match std::fs::write(base.join("setgroups"), "deny\n") {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!("cannot disable setgroups for probe {pid}: {error}").into());
        }
    }
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    std::fs::write(base.join("uid_map"), format!("0 {uid} 1\n"))
        .map_err(|error| format!("cannot map uid for probe {pid}: {error}"))?;
    std::fs::write(base.join("gid_map"), format!("0 {gid} 1\n"))
        .map_err(|error| format!("cannot map gid for probe {pid}: {error}"))?;
    Ok(())
}

/// Attaches to `pid` with `PTRACE_ATTACH`.
///
/// No safe wrapper exists for `ptrace`, and the tier-4a `PR_SET_DUMPABLE`
/// assertion is defined in terms of this exact request.
pub(crate) fn ptrace_attach(pid: u32) -> io::Result<()> {
    let raw = i32::try_from(pid).map_err(|_| io::Error::other("pid does not fit in pid_t"))?;
    // SAFETY: `ptrace(PTRACE_ATTACH, pid, NULL, NULL)` is the documented attach
    // request. It dereferences no user pointer (both data arguments are null)
    // and acts only on the process identified by `pid`, whose lifetime the
    // supervisor `ChildGuard` owns.
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_ATTACH,
            raw,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Consumes the attach stop notification, returning whether a stop was seen.
///
/// The wait is bounded by [`EVENT_TIMEOUT`] and polled with `WNOHANG` so a
/// missing stop fails the test instead of blocking the runner. `waitpid(2)` is
/// used directly (not `Child::wait`) because the caller must observe
/// `WUNTRACED` *without* reaping the probe; [`ChildGuard::wait`] still performs
/// the final reap after detach.
pub(crate) fn wait_for_ptrace_stop(pid: u32) -> io::Result<bool> {
    let child = Pid::from_raw(
        i32::try_from(pid).map_err(|_| io::Error::other("pid does not fit in pid_t"))?,
    )
    .ok_or_else(|| io::Error::other("pid is not a valid child pid"))?;
    let deadline = Instant::now() + EVENT_TIMEOUT;
    loop {
        // `WNOHANG` never blocks, and `UNTRACED` reports the stop without
        // reaping; the pid is a live child of this process.
        match rustix::process::waitpid(Some(child), WaitOptions::NOHANG | WaitOptions::UNTRACED) {
            Ok(Some((_, status))) => return Ok(status.stopped()),
            Ok(None) => {}
            Err(error) => return Err(io::Error::from(error)),
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "no ptrace stop notification arrived within {EVENT_TIMEOUT:?}"
            )));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Detaches from a stopped `pid`, resuming it.
pub(crate) fn ptrace_detach(pid: u32) -> io::Result<()> {
    let raw = i32::try_from(pid).map_err(|_| io::Error::other("pid does not fit in pid_t"))?;
    // SAFETY: `ptrace(PTRACE_DETACH, pid, NULL, NULL)` detaches a probe this
    // process attached to in `ptrace_attach`. Both data arguments are null, so
    // no pointer is dereferenced.
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_DETACH,
            raw,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
