//! Process hardening and bounded stream helpers for subprocess plugins.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use arbitraitor_exec::ResourceLimits;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_sandbox::PathRule;
use rustix::process::{Pid, Signal, kill_process, kill_process_group};
use sha2::{Digest, Sha256};

use super::ExecutorError;

const CPU_LIMIT_SECS: u64 = 30;
const MEMORY_LIMIT_BYTES: u64 = 256 * 1024 * 1024;
const OUTPUT_LIMIT_BYTES: u64 = 10 * 1024 * 1024;
const PROCESS_LIMIT: u32 = 64;
const FD_LIMIT: u32 = 64;

pub(super) struct BoundedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R> BoundedReader<R> {
    pub(super) const fn with_default_limit(inner: R) -> Self {
        Self {
            inner,
            remaining: OUTPUT_LIMIT_BYTES,
        }
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "plugin output exceeded 10 MiB cap",
            ));
        }
        let cap = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = self.inner.read(&mut buffer[..cap])?;
        self.remaining = self
            .remaining
            .saturating_sub(u64::try_from(read).unwrap_or(u64::MAX));
        Ok(read)
    }
}

pub(super) fn hash_file(path: &Path) -> Result<Sha256Digest, ExecutorError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(Sha256Digest::new(bytes))
}

pub(super) fn plugin_resource_limits() -> ResourceLimits {
    ResourceLimits {
        cpu_time_secs: Some(CPU_LIMIT_SECS),
        memory_bytes: Some(MEMORY_LIMIT_BYTES),
        process_count: Some(PROCESS_LIMIT),
        fd_count: Some(FD_LIMIT),
        output_size_bytes: Some(OUTPUT_LIMIT_BYTES),
    }
}

pub(super) fn plugin_filesystem_rules(
    binary_path: &Path,
    working_directory: Option<&Path>,
) -> Vec<PathRule> {
    let mut rules = Vec::new();
    if let Some(parent) = binary_path.parent() {
        rules.push(PathRule::read_execute(parent.to_path_buf()));
    }
    for path in dynamic_linker_paths() {
        rules.push(PathRule::read_execute(path));
    }
    if let Some(directory) = working_directory {
        rules.push(PathRule::read_write_execute(directory.to_path_buf()));
    }
    rules
}

fn dynamic_linker_paths() -> [PathBuf; 6] {
    [
        PathBuf::from("/bin"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/lib"),
        PathBuf::from("/lib64"),
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/lib64"),
    ]
}

#[cfg(unix)]
pub(super) fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    command.process_group(0);
}

#[cfg(not(unix))]
pub(super) const fn configure_process_group(_command: &mut Command) {}

/// Applies resource limits from the parent via `prlimit` after spawn, fenced
/// by a best-effort `SIGSTOP`.
///
/// **Deprecated for plugin execution.** The [`super::SubprocessExecutor`] now
/// applies limits in the child via `setrlimit` in `pre_exec`
/// ([`arbitraitor_sandbox::configure_resource_limits`]), which is inherited
/// across `execve` and closes the TOCTOU race this parent-side approach has.
///
/// Retained for backward compatibility with callers that apply limits after
/// spawn; new code should register limits via `pre_exec` before calling spawn.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub(super) fn apply_limits_fenced(
    child: &mut Child,
    limits: &ResourceLimits,
) -> Result<(), ExecutorError> {
    let pid = Pid::from_child(child);
    let _stop_result = kill_process(pid, Signal::STOP);
    if let Err(source) = limits.apply_to(child.id()) {
        kill_child_group(child);
        let _kill_result = child.kill();
        let _wait_result = child.wait();
        return Err(ExecutorError::Spawn(io::Error::other(source.to_string())));
    }
    let _continue_result = kill_process(pid, Signal::CONT);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub(super) const fn apply_limits_fenced(
    _child: &mut Child,
    _limits: &ResourceLimits,
) -> Result<(), ExecutorError> {
    Ok(())
}

#[cfg(unix)]
pub(super) fn kill_child_group(child: &Child) {
    let pid = Pid::from_child(child);
    let _group_kill_result = kill_process_group(pid, Signal::KILL);
}

#[cfg(not(unix))]
pub(super) fn kill_child_group(_child: &Child) {}
