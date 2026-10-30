//! Tier-4a parent tests: one test per binding assertion in spec §43.10.
//!
//! Each parent spawns a probe from [`crate::probes`] under the hooks
//! production installs and asserts on the *effect* the assertion forbids —
//! never merely on "an error occurred". Where an environment can make an
//! assertion pass for the wrong reason (a blocked `ptrace`, an ambient
//! `EAGAIN`, a kernel without Landlock) the test fails with an explicit
//! message instead: a tier-4a skip is never containment evidence.

use std::error::Error;
use std::io;
use std::net::TcpListener;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Stdio;

use arbitraitor_sandbox::{
    PathRule, SandboxConfig, capture_landlock_install_plan, capture_landlock_probe,
    configure_command, configure_filesystem_isolation_with_plan, configure_network_isolation,
};

use crate::harness::{
    CONNECT_PORT_ENV, ChildGuard, DUMPABLE_ENV, INSIDE_ENV, OUTSIDE_ENV, Report, TempDir,
    TestResult, WORKDIR_ENV, create_writable_report, no_new_privs_state, poll_accept,
    probe_command, proc_status_field, ptrace_attach, ptrace_detach, ptrace_scope_text,
    ready_timeout, silence_window, unconnected_tcp_socket, userns_probe_command,
    wait_for_ptrace_stop, wait_for_report_key, write_userns_maps,
};

/// Spec §43.10, seccomp-BPF happy path: a process using only allowed syscalls
/// exits 0.
#[test]
fn seccomp_happy_path_allowed_io_exits_zero() -> TestResult {
    let dir = TempDir::new("seccomp-happy")?;
    let report_path = dir.path().join("probe.report");
    let mut command = probe_command("seccomp_happy", &report_path)?;
    command.env(WORKDIR_ENV, dir.path());
    configure_network_isolation(&mut command);

    let mut run = ChildGuard::spawn(&mut command)?;
    let status = run.wait("seccomp_happy")?;
    let report = Report::read(&report_path)?;

    assert!(
        status.success(),
        "the seccomp-filtered child performing only allowed file I/O exited with {status:?}; \
         report: {report:?}"
    );
    assert_eq!(
        report.text("READBACK")?,
        "tier4a",
        "the child exited 0 but its allowed write/read round-trip did not complete"
    );
    Ok(())
}

/// Spec §43.10, seccomp-BPF adversarial path: a denied syscall returns `-1`
/// with `errno == EPERM`, has no other effect, and does not kill the process
/// (ADR-0020).
#[test]
fn seccomp_denied_syscall_returns_eperm_and_child_survives() -> TestResult {
    let dir = TempDir::new("seccomp-adversarial")?;
    let report_path = dir.path().join("probe.report");
    let mut command = probe_command("seccomp_adversarial", &report_path)?;
    configure_network_isolation(&mut command);

    let mut run = ChildGuard::spawn(&mut command)?;
    let status = run.wait("seccomp_adversarial")?;
    let report = Report::read(&report_path)?;

    assert_eq!(
        status.signal(),
        None,
        "the child was terminated by a signal ({status:?}); §43.10 requires every denied syscall \
         to return SECCOMP_RET_ERRNO|EPERM, never SECCOMP_RET_KILL (ADR-0020)"
    );
    assert!(
        status.success(),
        "the child did not exit 0 after the denied syscall ({status:?}); report: {report:?}"
    );
    assert_eq!(
        report.int("SOCKET_ERRNO")?,
        libc::EPERM,
        "socket(2) did not fail with EPERM inside the network-isolated child"
    );
    assert_eq!(
        report.int("ALIVE_AFTER_DENIED")?,
        1,
        "the child did not record that it was still alive after the denied syscall"
    );
    Ok(())
}

/// Spec §43.10, connect-back pattern: the sandboxed process receives `EPERM`
/// *and* the listener never accepts a connection.
///
/// The control arm (no seccomp hook) proves the probe itself works, so a
/// silent listener in the denied arm can only mean the filter stopped the
/// connect. Listening silence is the enforcement evidence; the errno pins which
/// failure was observed.
#[test]
fn connect_back_control_accepts_and_denied_listener_stays_silent() -> TestResult {
    let dir = TempDir::new("connect-back")?;

    // Control arm: no sandbox hooks at all.
    let control = run_connect_arm(&dir, "control", false)?;
    assert!(
        control.status.success(),
        "connect-back control arm failed with {:?}; report: {:?}",
        control.status,
        control.report
    );
    assert_eq!(
        control.report.int("CONNECT_ERRNO")?,
        0,
        "connect-back control arm did not connect without the filter; the probe is broken, so \
         the denied arm would prove nothing"
    );
    assert!(
        control.accepted,
        "connect-back control arm: the listener never accepted the probe's connection inside the \
         {silence_window:?} window",
        silence_window = silence_window()
    );

    // Denied arm: network isolation plus the general sandbox hook, in the
    // order production uses (network isolation is registered before
    // `configure_command`'s hardening).
    let denied = run_connect_arm(&dir, "denied", true)?;
    assert_eq!(
        denied.report.int("CONNECT_ERRNO")?,
        libc::EPERM,
        "the sandboxed connect-back did not fail with EPERM (ECONNREFUSED or EACCES would mean the \
         request reached a different layer)"
    );
    assert!(
        !denied.accepted,
        "the listener accepted a connection from the sandboxed child inside the \
         {silence_window:?} silence window: network isolation is not enforcing",
        silence_window = silence_window()
    );
    Ok(())
}

/// Spec §43.10, `PR_SET_DUMPABLE, 0`: `PTRACE_ATTACH` from the parent returns
/// `EPERM`.
///
/// Differential: the dumpable control arm must attach and observe the stop. If
/// it cannot, the test fails naming `ptrace_scope` — an environment that
/// denies ptrace outright can neither confirm nor refute the control.
///
/// Known limit: the assertion drives the hardening in-process because `execve`
/// resets `PR_SET_DUMPABLE` for a non-setuid binary, so the production
/// `pre_exec` path is not observable from the parent. The divergence between
/// the shipped hook order and this §43.10 requirement is tracked in #835.
#[test]
fn pr_set_dumpable_denies_ptrace_attach() -> TestResult {
    let dir = TempDir::new("dumpable")?;

    let control = run_dumpable_arm(&dir, "control", true)?;
    if let Err(error) = &control.attach {
        return Err(format!(
            "ptrace control arm failed: PTRACE_ATTACH on the dumpable child returned `{error}`. \
             The tier-4a dumpable differential needs a ptrace-capable environment \
             (kernel.yama.ptrace_scope <= 1, no LSM ptrace denial); kernel.yama.ptrace_scope={}. \
             Failing instead of passing vacuously: an environment that denies ptrace for everyone \
             cannot demonstrate that PR_SET_DUMPABLE denied it.",
            ptrace_scope_text()
        )
        .into());
    }
    assert_eq!(
        control.stopped,
        Some(true),
        "control arm: waitpid(WUNTRACED) did not observe the ptrace attach stop"
    );
    assert!(
        control.status.success(),
        "control arm: the released probe did not exit 0 ({:?})",
        control.status
    );

    let denied = run_dumpable_arm(&dir, "denied", false)?;
    match &denied.attach {
        Ok(()) => {
            return Err(format!(
                "PR_SET_DUMPABLE=0 did not deny ptrace: PTRACE_ATTACH on the non-dumpable child \
                 succeeded; kernel.yama.ptrace_scope={}. The control arm attached as well, so this \
                 is not an environment artefact.",
                ptrace_scope_text()
            )
            .into());
        }
        Err(error) => assert_eq!(
            error.raw_os_error(),
            Some(libc::EPERM),
            "PTRACE_ATTACH on the non-dumpable child failed with `{error}`; §43.10 requires EPERM \
             and nothing else"
        ),
    }
    Ok(())
}

/// Spec §43.10, `PR_SET_NO_NEW_PRIVS, 1`: the kernel records the flag for the
/// child.
///
/// Differential on the observable knob: `/proc/self/status` reports
/// `NoNewPrivs: 1` when the hook is enabled and `0` when it is disabled, so
/// deleting the hook turns this test red.
#[test]
fn pr_set_no_new_privs_state_is_set_for_the_child() -> TestResult {
    let harness_state = no_new_privs_state()?;
    if harness_state != 0 {
        return Err(format!(
            "environment unsuitable: the harness already runs with NoNewPrivs={harness_state}; the \
             flag cannot be unset once set, so the `no_new_privs: false` arm could not be \
             distinguished from inherited state"
        )
        .into());
    }

    let dir = TempDir::new("no-new-privs")?;
    let enabled = run_no_new_privs_arm(&dir, "enabled", true)?;
    assert_eq!(
        enabled.int("NO_NEW_PRIVS")?,
        1,
        "the child under `no_new_privs: true` did not report NoNewPrivs: 1"
    );

    let disabled = run_no_new_privs_arm(&dir, "disabled", false)?;
    assert_eq!(
        disabled.int("NO_NEW_PRIVS")?,
        0,
        "the child under `no_new_privs: false` reported NoNewPrivs: 1; the differential cannot \
         show that the hook set it"
    );
    Ok(())
}

/// Spec §43.10, `RLIMIT_NPROC = 1` with its binding environment-sensitivity
/// paragraph: the first fork succeeds and the second returns `EAGAIN` inside a
/// user namespace whose process count the test controls.
///
/// The baseline arm runs first and must succeed. An ambient `EAGAIN` is never
/// enforcement evidence, so a failing baseline fails this test as
/// "environment unsuitable" instead of passing.
#[test]
fn rlimit_nproc_denies_second_fork_inside_user_namespace() -> TestResult {
    let dir = TempDir::new("nproc")?;
    let report_path = dir.path().join("nproc.report");
    let mut run = spawn_userns_probe("nproc_inside", &dir, &report_path)?;
    let status = run.wait("nproc_inside")?;
    assert!(
        status.success(),
        "the user-namespace probe exited with {status:?}; unprivileged user namespaces may be \
         restricted on this host. Report so far: {}",
        std::fs::read_to_string(&report_path).unwrap_or_default()
    );
    let report = Report::read(&report_path)?;

    // Baseline arm: the namespace must be able to fork twice at all.
    assert_eq!(
        report.text("BASELINE_FORK1")?,
        "ok",
        "environment unsuitable: the first unbounded fork already failed in a fresh user \
         namespace; an ambient EAGAIN proves nothing about RLIMIT_NPROC (report: {report:?})"
    );
    assert_eq!(
        report.text("BASELINE_FORK2")?,
        "ok",
        "environment unsuitable: the second unbounded fork failed in a fresh user namespace, so \
         the limited arm could not distinguish enforcement from ambient pressure (report: \
         {report:?})"
    );

    // Limited arm: the crate's `pre_exec` hook applies RLIMIT_NPROC in the child.
    assert_eq!(
        report.text("FORK1")?,
        "ok",
        "environment unsuitable: the calibrated RLIMIT_NPROC (limit={:?}, probe threads={:?}) \
         denied the first fork, which the baseline arm proved is possible here",
        report.text("LIMIT").unwrap_or("unrecorded"),
        report.text("PROBE_THREADS").unwrap_or("unrecorded")
    );
    // The forker reports how many tasks the namespace held immediately before
    // its first fork, so the calibration is verified and not merely trusted.
    let tasks_before_fork = report.int("TASKS_BEFORE_FORK")?;
    assert_eq!(
        report.int("LIMIT")?,
        tasks_before_fork + 1,
        "the calibrated RLIMIT_NPROC must allow exactly one task more than the \
         {tasks_before_fork} tasks the namespace held before the forker's first fork; report: \
         {report:?}"
    );
    assert_eq!(
        report.int("TASKS_AFTER_FORK1")?,
        report.int("LIMIT")?,
        "after the first fork the namespace must hold exactly `RLIMIT_NPROC` tasks, which is what \
         makes the second fork the one the limit denies; report: {report:?}"
    );
    assert_eq!(
        report.int("FORK2_ERRNO")?,
        libc::EAGAIN,
        "the second fork inside the user namespace did not fail with EAGAIN under RLIMIT_NPROC; \
         report: {report:?}"
    );
    Ok(())
}

/// Spec §43.10, Landlock: writes inside the allowlist succeed and writes
/// outside it fail with `EACCES`.
///
/// The harness asserts the kernel probe reports `Supported` *before* any
/// ruleset is installed and fails with an explicit message otherwise: on a
/// kernel without Landlock the install hook returns success without installing
/// anything (ADR-0021), so a skipped probe would be a silent pass.
#[test]
fn landlock_write_inside_allowed_outside_eacces() -> TestResult {
    let probe = capture_landlock_probe();
    if !probe.is_supported() {
        return Err(format!(
            "Landlock probe reported {probe:?}: the tier-4a filesystem assertion requires a \
             Landlock-capable kernel (5.13+, LSM enabled). On such a kernel the install hook is a \
             documented no-op, so running the assertion would produce no containment evidence"
        )
        .into());
    }

    let inside = TempDir::new("landlock-inside")?;
    let outside = TempDir::new("landlock-outside")?;
    let exe = std::env::current_exe()?;
    let exe_dir = exe
        .parent()
        .ok_or_else(|| format!("test binary `{}` has no parent directory", exe.display()))?;

    let mut rules = vec![PathRule::read_write_execute(inside.path().to_path_buf())];
    for system_path in [
        exe_dir,
        Path::new("/bin"),
        Path::new("/usr/bin"),
        Path::new("/lib"),
        Path::new("/lib64"),
        Path::new("/usr/lib"),
        Path::new("/usr/lib64"),
    ] {
        rules.push(PathRule::read_execute(system_path.to_path_buf()));
    }

    let plan = capture_landlock_install_plan(&rules);
    assert!(
        plan.probe().is_supported(),
        "the captured install plan lost the supported Landlock probe: {plan:?}"
    );

    // The report lives inside the permitted directory: the probe must be able
    // to record evidence through the ruleset it is confined by.
    let report_path = inside.path().join("probe.report");
    let mut command = probe_command("landlock_fs", &report_path)?;
    command.env(INSIDE_ENV, inside.path());
    command.env(OUTSIDE_ENV, outside.path());
    // Production order: `configure_command` (which sets `no_new_privs`, a
    // precondition for `landlock_restrict_self`) before the filesystem hook.
    configure_command(&mut command, SandboxConfig::default());
    let verdict = configure_filesystem_isolation_with_plan(&mut command, &plan);
    assert!(
        verdict.is_supported(),
        "configure_filesystem_isolation_with_plan reported {verdict:?} after the probe was \
         captured as supported"
    );

    let mut run = ChildGuard::spawn(&mut command)?;
    let status = run.wait("landlock_fs")?;
    let report = Report::read(&report_path)?;

    assert!(
        status.success(),
        "the Landlock-confined child exited with {status:?}; report: {report:?}"
    );
    assert_eq!(
        report.int("INSIDE_ERRNO")?,
        0,
        "the child could not write inside the permitted directory: the ruleset is over-restrictive \
         and the outside denial would prove nothing"
    );
    assert_eq!(
        report.int("OUTSIDE_ERRNO")?,
        libc::EACCES,
        "the child's write outside the allowlist did not fail with EACCES"
    );
    Ok(())
}

/// Spec §43.10 "Kernel-feature precondition": every control the suite depends
/// on must be present on Linux. A missing precondition is a hard failure
/// naming the requirement, never a skip.
#[test]
fn preconditions_required_by_tier4a_are_present() -> TestResult {
    let euid = rustix::process::geteuid().as_raw();
    if euid == 0 {
        return Err(format!(
            "tier-4a precondition missing: effective uid is {euid}; the suite must run unprivileged \
             so that EPERM from PR_SET_DUMPABLE and the user-namespace mapping mean something"
        )
        .into());
    }

    if !cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
        return Err(format!(
            "tier-4a precondition missing: unsupported architecture `{}`; seccomp network isolation \
             is implemented for x86_64 and aarch64 only",
            std::env::consts::ARCH
        )
        .into());
    }

    let probe = capture_landlock_probe();
    if !probe.is_supported() {
        return Err(format!(
            "tier-4a precondition missing: Landlock probe reported {probe:?}; the filesystem \
             assertion needs a Landlock-capable kernel"
        )
        .into());
    }

    proc_status_field(Path::new("/proc/self/status"), "Threads:")?.ok_or_else(|| {
        "tier-4a precondition missing: /proc is not mounted or unreadable".to_string()
    })?;

    let dir = TempDir::new("preconditions")?;
    let report_path = dir.path().join("userns.report");
    let mut run = spawn_userns_probe("userns_inside", &dir, &report_path)?;
    let status = run.wait("userns_inside")?;
    if !status.success() {
        return Err(format!(
            "tier-4a precondition missing: an unprivileged `unshare(CLONE_NEWUSER)` with a \
             published uid/gid map did not succeed (probe exited {status:?}); on Ubuntu the \
             `kernel.apparmor_restrict_unprivileged_userns` and `unprivileged_userns_clone` \
             sysctls govern this"
        )
        .into());
    }
    let report = Report::read(&report_path)?;
    assert_eq!(
        report.int("USERNS")?,
        1,
        "the user-namespace probe exited 0 without recording a created namespace"
    );
    Ok(())
}

struct ConnectArm {
    status: std::process::ExitStatus,
    report: Report,
    accepted: bool,
}

fn run_connect_arm(dir: &TempDir, label: &str, denied: bool) -> Result<ConnectArm, Box<dyn Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let client = unconnected_tcp_socket()?;

    let report_path = dir.path().join(format!("{label}.report"));
    let mut command = probe_command("connect_back", &report_path)?;
    command.env(CONNECT_PORT_ENV, port.to_string());
    // Standard input is preserved by `close_inherited_fds` (it starts at fd 3),
    // so the socket survives the sandbox hook.
    command.stdin(Stdio::from(client));
    if denied {
        configure_network_isolation(&mut command);
        configure_command(&mut command, SandboxConfig::default());
    }

    let mut run = ChildGuard::spawn(&mut command)?;
    let status = run.wait(label)?;
    let report = Report::read(&report_path)?;
    // Negative-assertion window: a connection queued before the probe exited
    // would surface here even though the probe is already reaped.
    let accepted = poll_accept(&listener, silence_window())?;
    Ok(ConnectArm {
        status,
        report,
        accepted,
    })
}

struct DumpableArm {
    status: std::process::ExitStatus,
    attach: io::Result<()>,
    stopped: Option<bool>,
}

fn run_dumpable_arm(
    dir: &TempDir,
    label: &str,
    dumpable: bool,
) -> Result<DumpableArm, Box<dyn Error>> {
    let report_path = dir.path().join(format!("{label}.report"));
    let mut command = probe_command("dumpable", &report_path)?;
    command.env(DUMPABLE_ENV, if dumpable { "1" } else { "0" });
    command.stdin(Stdio::piped());

    let mut run = ChildGuard::spawn(&mut command)?;
    let pid = run.pid()?;
    let stdin = run
        .take_stdin()
        .ok_or_else(|| "the dumpable probe's stdin pipe is unavailable".to_string())?;
    // Readiness handshake: the probe records READY only after `apply_sandbox`
    // returned, so the attach cannot race the hardening.
    let _ready = wait_for_report_key(&report_path, "READY", ready_timeout())?;

    let attach = ptrace_attach(pid);
    let mut stopped = None;
    if attach.is_ok() {
        stopped = Some(wait_for_ptrace_stop(pid)?);
        let _ignored = ptrace_detach(pid);
    }
    // Release the probe; it exits 0 once its stdin reaches EOF.
    drop(stdin);
    let status = run.wait(label)?;
    Ok(DumpableArm {
        status,
        attach,
        stopped,
    })
}

fn run_no_new_privs_arm(
    dir: &TempDir,
    label: &str,
    no_new_privs: bool,
) -> Result<Report, Box<dyn Error>> {
    let report_path = dir.path().join(format!("{label}.report"));
    let mut command = probe_command("no_new_privs", &report_path)?;
    command.stdin(Stdio::null());
    configure_command(
        &mut command,
        SandboxConfig {
            no_new_privs,
            // Isolate the knob under test: leaving the child dumpable keeps
            // `apply_sandbox` from touching any other prctl.
            dumpable: true,
            close_fds: false,
        },
    );
    let mut run = ChildGuard::spawn(&mut command)?;
    let status = run.wait(label)?;
    assert!(
        status.success(),
        "the `no_new_privs: {no_new_privs}` probe exited with {status:?}"
    );
    Report::read(&report_path)
}

/// Spawns a probe that runs inside a fresh user namespace and publishes the
/// map once the probe reports `UNSHARED=1`.
fn spawn_userns_probe(
    name: &str,
    dir: &TempDir,
    report_path: &Path,
) -> Result<ChildGuard, Box<dyn Error>> {
    let mut command = userns_probe_command(name, report_path)?;
    command.env(WORKDIR_ENV, dir.path());
    command.stdin(Stdio::null());
    create_writable_report(report_path)?;
    let run = ChildGuard::spawn(&mut command)?;
    let pid = run.pid()?;
    let _ready = wait_for_report_key(report_path, "UNSHARED", ready_timeout())?;
    write_userns_maps(pid)?;
    Ok(run)
}
