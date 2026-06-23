//! Seccomp-BPF filters for child-process network isolation.
//!
//! The filter installed by this module blocks network socket syscalls while
//! allowing all non-network syscalls. It is intentionally narrow: filesystem,
//! stdio, and process-lifecycle calls remain governed by the rest of the
//! sandbox policy.

use std::io;
use std::process::Command;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7;
const SECCOMP_FILTER_FLAG_NONE: libc::c_uint = 0;
const BLOCKED_SYSCALL_PAIR_LEN: usize = 2;

/// Registers a `pre_exec` closure that installs a seccomp-BPF filter blocking
/// network socket syscalls in the child before `execve`.
///
/// After this filter is installed, the child process cannot create sockets,
/// connect, bind, listen, accept connections, send or receive socket messages,
/// or inspect socket endpoints. Blocked syscalls return `EPERM` rather than
/// killing the process so plugins fail gracefully.
///
/// This enforces ADR-0006's and ADR-0008's "network: none/deny" defaults for
/// subprocess plugins on Linux. Unsupported Linux architectures and non-Linux
/// platforms currently install no filter; callers must treat network isolation
/// as unavailable there.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[allow(unsafe_code)]
pub fn configure_network_isolation(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    let filter = seccomp_bpf_network_filter();

    // SAFETY: The registered closure runs in the forked child between `fork`
    // and `execve`. It calls only `install_seccomp_network_filter`, which
    // performs `prctl(PR_SET_NO_NEW_PRIVS)` and `seccomp(2)` with a pre-built
    // BPF program. The closure allocates no memory, takes no locks, and the
    // captured `Vec` owns the initialized `sock_filter` array for the syscall.
    unsafe {
        command.pre_exec(move || install_seccomp_network_filter(&filter));
    }
}

/// Registers a network-isolation hook for unsupported platforms.
///
/// This is a no-op so callers can invoke it unconditionally. Network isolation
/// is enforced only on Linux `x86_64` and `aarch64` builds.
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub fn configure_network_isolation(_command: &mut Command) {}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[allow(unsafe_code)]
fn install_seccomp_network_filter(filter: &[libc::sock_filter]) -> io::Result<()> {
    set_no_new_privs_for_seccomp()?;

    let Some(len) = u16::try_from(filter.len()).ok() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "seccomp filter has too many instructions",
        ));
    };
    let mut program = libc::sock_fprog {
        len,
        filter: filter.as_ptr().cast_mut(),
    };

    // SAFETY: [Category 8 — FFI Boundary]
    // `program.filter` points to `filter`'s initialized `sock_filter` storage,
    // which is alive for the duration of this syscall. `program.len` was
    // checked to fit the kernel ABI's `u16` length field. The kernel copies and
    // validates the BPF program synchronously before `seccomp(2)` returns.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NONE,
            &raw mut program,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[allow(unsafe_code)]
fn set_no_new_privs_for_seccomp() -> io::Result<()> {
    // SAFETY: [Category 8 — FFI Boundary]
    // `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` is a Linux process-control
    // operation that does not dereference pointers. Setting it is idempotent
    // and is required before an unprivileged process may install a seccomp
    // filter. All arguments are integer constants accepted by the kernel ABI.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn seccomp_bpf_network_filter() -> Vec<libc::sock_filter> {
    let blocked = blocked_network_syscalls();
    let mut filter = Vec::with_capacity(4 + (blocked.len() * BLOCKED_SYSCALL_PAIR_LEN) + 1);

    filter.push(bpf_stmt(
        libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
        SECCOMP_DATA_ARCH_OFFSET,
    ));
    filter.push(bpf_jump(
        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
        native_audit_arch(),
        1,
        0,
    ));
    filter.push(bpf_stmt(libc::BPF_RET | libc::BPF_K, seccomp_errno_perm()));
    filter.push(bpf_stmt(
        libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
        SECCOMP_DATA_NR_OFFSET,
    ));

    for syscall in blocked {
        filter.push(bpf_jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            syscall,
            0,
            1,
        ));
        filter.push(bpf_stmt(libc::BPF_RET | libc::BPF_K, seccomp_errno_perm()));
    }

    filter.push(bpf_stmt(
        libc::BPF_RET | libc::BPF_K,
        libc::SECCOMP_RET_ALLOW,
    ));
    filter
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn blocked_network_syscalls() -> Vec<u32> {
    let mut syscalls = vec![
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_shutdown,
    ];

    #[cfg(target_arch = "x86_64")]
    syscalls.push(libc::SYS_accept);

    syscalls
        .into_iter()
        .map(|syscall| u32::try_from(syscall).unwrap_or(u32::MAX))
        .collect()
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const fn native_audit_arch() -> u32 {
    AUDIT_ARCH_NATIVE
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn seccomp_errno_perm() -> u32 {
    libc::SECCOMP_RET_ERRNO | libc::EPERM.unsigned_abs()
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn bpf_stmt(code: u32, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: bpf_code(code),
        jt: 0,
        jf: 0,
        k,
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn bpf_jump(code: u32, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: bpf_code(code),
        jt,
        jf,
        k,
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn bpf_code(code: u32) -> u16 {
    u16::try_from(code).unwrap_or(u16::MAX)
}

#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;

    #[test]
    fn seccomp_filter_is_valid() {
        let blocked = blocked_network_syscalls();
        let filter = seccomp_bpf_network_filter();
        let expected_len = 4 + (blocked.len() * BLOCKED_SYSCALL_PAIR_LEN) + 1;

        assert_eq!(filter.len(), expected_len);
        assert_eq!(filter[0].k, SECCOMP_DATA_ARCH_OFFSET);
        assert_eq!(filter[1].k, native_audit_arch());
        assert_eq!(filter[2].k, seccomp_errno_perm());
        assert_eq!(filter[3].k, SECCOMP_DATA_NR_OFFSET);
        assert_eq!(
            filter.last().map(|instruction| instruction.k),
            Some(libc::SECCOMP_RET_ALLOW)
        );

        for syscall in blocked {
            assert!(
                filter.windows(BLOCKED_SYSCALL_PAIR_LEN).any(|window| {
                    window[0].k == syscall && window[1].k == seccomp_errno_perm()
                }),
                "missing blocked syscall {syscall}"
            );
        }
    }

    #[test]
    #[ignore = "installs a real seccomp filter in a subprocess"]
    fn seccomp_blocks_socket_creation() -> Result<(), Box<dyn std::error::Error>> {
        let output = run_bash_probe("exec 3<>/dev/tcp/127.0.0.1/1")?;

        assert!(
            !output.status.success(),
            "socket probe unexpectedly succeeded: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Permission denied")
                || String::from_utf8_lossy(&output.stderr).contains("Operation not permitted"),
            "socket probe did not fail with EPERM: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    #[test]
    #[ignore = "installs a real seccomp filter in a subprocess"]
    fn seccomp_blocks_connect() -> Result<(), Box<dyn std::error::Error>> {
        let output = run_bash_probe(
            "python3 - <<'PY'\nimport socket\ns = socket.socket(fileno=0)\ns.connect(('127.0.0.1', 9))\nPY",
        )?;

        assert!(
            !output.status.success(),
            "connect probe unexpectedly succeeded: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("PermissionError")
                || String::from_utf8_lossy(&output.stderr).contains("Operation not permitted"),
            "connect probe did not fail with EPERM: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    #[test]
    #[ignore = "installs a real seccomp filter in a subprocess"]
    fn seccomp_allows_non_network_io() -> Result<(), Box<dyn std::error::Error>> {
        let output = run_bash_probe(
            "path=/tmp/arbitraitor-seccomp-non-network-$$; printf 'ok' > \"$path\" && cat \"$path\" && rm -f \"$path\"",
        )?;

        assert!(
            output.status.success(),
            "non-network probe failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8(output.stdout)?, "ok");
        Ok(())
    }

    fn run_bash_probe(script: &str) -> Result<std::process::Output, Box<dyn std::error::Error>> {
        let mut command = std::process::Command::new("/bin/bash");
        command.arg("-c").arg(script);
        configure_network_isolation(&mut command);
        let output = command.output()?;
        Ok(output)
    }
}
