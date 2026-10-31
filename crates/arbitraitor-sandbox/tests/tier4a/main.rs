//! Tier-4a host-syscall containment verification suite (spec §43.10).
//!
//! Every control under test is a host-kernel feature applied to a host
//! process, so the assertions run directly on the CI host: no virtual
//! machine, no shell, no locale-dependent `strerror` matching.
//!
//! # Structure
//!
//! One test binary holds both the *parents* (the `#[test]` functions in
//! [`suite`]) and the *probes* (the `#[ignore]`d entry points in [`probes`]).
//! A parent re-executes this same binary with
//! `--ignored --exact probes::<name>` so the probe runs under the exact
//! `pre_exec` hooks production registers, and reads back a `KEY=value` report
//! file rather than parsing human-readable output.
//!
//! # Why assertions are shaped this way
//!
//! The workflow policy forbids claiming that a sandbox test passed because an
//! error occurred: every assertion here pins the *forbidden effect* (the
//! listener never accepted; the denied call returned `EPERM`; the write outside
//! the allowlist failed with `EACCES`) **and** the evidence that the probe was
//! otherwise working (the control arm, the baseline arm). Probes are
//! `#[ignore]`d so a test runner never executes them standalone: they are only
//! meaningful under the hooks the parent installs.

#[cfg(target_os = "linux")]
mod harness;
#[cfg(target_os = "linux")]
mod probes;
#[cfg(target_os = "linux")]
mod suite;

/// Non-Linux marker: a macOS or Windows run is a visible skip, never a silent
/// pass. `clippy::print_stderr` is denied, so the marker is written directly.
#[cfg(not(target_os = "linux"))]
#[test]
fn platform_not_linux() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write as _;

    std::io::stderr()
        .write_all(b"TIER4A SKIP: platform not Linux \xe2\x80\x94 no containment evidence\n")?;
    Ok(())
}
