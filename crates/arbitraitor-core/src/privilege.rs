//! Privilege-separation guards for ADR-0009.
//!
//! Arbitraitor's parsers, scanners, plugin hosts, and policy engine must never
//! run with elevated privileges. This module provides the entry-point guard
//! used by the CLI, daemon, MCP server, and plugin host to refuse root execution
//! before any untrusted content is touched.
//!
//! The executor-layer check in `arbitraitor-exec` remains as a defense-in-depth
//! backstop; the guards here are the primary enforcement at process entry.

#![forbid(unsafe_code)]

use std::io::Write;

use rustix::process::geteuid;

/// Outcome of evaluating the no-root policy at an entry point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RootPolicyOutcome {
    /// Process is not root — proceed normally.
    NotRoot,
    /// Process is root but `--allow-root` bypassed the guard — proceed with a warning.
    AllowedWithWarning,
    /// Process is root and not allowed — caller must abort.
    Refused,
}

/// Returns `true` when the process effective user ID is root (0).
///
/// Uses [`rustix::process::geteuid`], a safe wrapper around the `geteuid`
/// syscall. On non-Unix targets this always returns `false`.
///
/// # Panics
///
/// Never. This function is safe to call at any point, including before
/// logging is initialized.
#[must_use]
pub fn is_running_as_root() -> bool {
    geteuid().as_raw() == 0
}

/// Evaluates the no-root policy given the current privilege state and bypass flag.
fn evaluate_root_policy(running_as_root: bool, allow_root: bool) -> RootPolicyOutcome {
    if !running_as_root {
        return RootPolicyOutcome::NotRoot;
    }
    if allow_root {
        RootPolicyOutcome::AllowedWithWarning
    } else {
        RootPolicyOutcome::Refused
    }
}

/// Refuses to continue when running as root.
///
/// Writes a clear error to stderr and exits with status code 60
/// (`InternalInvariantFailure` per spec §29) if the effective user ID is
/// 0. Call this at the very start of every entry point (`main`, daemon
/// boot, MCP server boot, plugin-host boot) before any untrusted content
/// is parsed, scanned, or executed.
///
/// This is the unconditional form — there is no bypass. For the diagnostic
/// bypass used by `doctor` and integration tests, see
/// [`refuse_root_unless`]. The numeric exit code mirrors the
/// [`arbitraitor_model::exit_code::ExitCode::InternalInvariantFailure`]
/// variant; it is duplicated here as a constant so that `arbitraitor-core`
/// does not depend on `arbitraitor-model` (which sits below it in the
/// crate DAG). If the model value changes, this constant must change in
/// lockstep — guarded by `exit_code_constants_match_spec` test in
/// `arbitraitor-cli`.
pub fn refuse_root() {
    match evaluate_root_policy(is_running_as_root(), false) {
        RootPolicyOutcome::NotRoot | RootPolicyOutcome::AllowedWithWarning => {}
        RootPolicyOutcome::Refused => exit_as_root(),
    }
}

/// Refuses to continue when running as root unless `allow_root` is `true`.
///
/// When `allow_root` is `true` and the process is root, a warning is written
/// to stderr and execution continues. This bypass exists for the `doctor`
/// diagnostic command and integration test harnesses that must run under
/// elevated privileges. Production paths must pass `false`.
pub fn refuse_root_unless(allow_root: bool) {
    match evaluate_root_policy(is_running_as_root(), allow_root) {
        RootPolicyOutcome::NotRoot => {}
        RootPolicyOutcome::AllowedWithWarning => {
            let _ = writeln!(
                std::io::stderr(),
                "warning: running as root with --allow-root; this is a diagnostic mode only"
            );
        }
        RootPolicyOutcome::Refused => exit_as_root(),
    }
}

fn exit_as_root() -> ! {
    let _ = writeln!(
        std::io::stderr(),
        "error: arbitraitor refuses to run as root. Re-run as an unprivileged user, or use \
         --allow-root for the doctor diagnostic command only."
    );
    let _ = std::io::stderr().flush();
    // Spec §29 code 60: Internal integrity invariant failure.
    // Mirrors `arbitraitor_model::exit_code::ExitCode::InternalInvariantFailure`.
    // See the doc comment on `refuse_root` for the rationale on duplicating
    // the constant here instead of taking a model dependency.
    std::process::exit(60);
}

#[cfg(test)]
mod tests {
    use rustix::process::geteuid;

    use super::{RootPolicyOutcome, evaluate_root_policy, is_running_as_root};

    #[test]
    fn is_running_as_root_matches_raw_euid() {
        // CI and developer machines run tests as a non-root user. This locks
        // the detection logic against regressions in the EUID lookup path.
        let raw_euid_is_root = geteuid().as_raw() == 0;
        assert_eq!(
            is_running_as_root(),
            raw_euid_is_root,
            "is_running_as_root must agree with the raw EUID"
        );
    }

    #[test]
    fn policy_allows_non_root_regardless_of_flag() {
        assert_eq!(
            evaluate_root_policy(false, false),
            RootPolicyOutcome::NotRoot
        );
        assert_eq!(
            evaluate_root_policy(false, true),
            RootPolicyOutcome::NotRoot
        );
    }

    #[test]
    fn policy_refuses_root_without_bypass() {
        assert_eq!(
            evaluate_root_policy(true, false),
            RootPolicyOutcome::Refused
        );
    }

    #[test]
    fn policy_warns_root_with_bypass() {
        assert_eq!(
            evaluate_root_policy(true, true),
            RootPolicyOutcome::AllowedWithWarning
        );
    }
}
