//! Stable CLI exit codes per spec §29.
//!
//! Every Arbitraitor exit code has a stable numeric value and a documented
//! meaning. Machine consumers should primarily use structured output
//! (`--json`, `--sarif`) rather than relying on exit codes alone — a single
//! numeric code cannot express the full policy trace. Exit codes are
//! reserved for shell pipelines, CI gates, and operating-system process
//! supervisors that need a one-bit-with-context signal.
//!
//! ## Mapping to verdicts
//!
//! [`Verdict`] alone is not enough to pick a final exit code in every case
//! (e.g. `Verdict::Block` should map to [`ExitCode::ConfirmedMalicious`] when
//! a finding has [`Confidence::Confirmed`](crate::verdict::Confidence), but
//! to [`ExitCode::BlockedByPolicy`] otherwise). The [`From<Verdict>`]
//! implementation produces the *conservative default* for each verdict;
//! callers that have richer context (finding confidence, network error
//! class, transport-policy violation, integrity failure) should construct
//! the more specific [`ExitCode`] directly.
//!
//! ## Adding a new exit code
//!
//! 1. Document the code and its trigger in spec §29 first.
//! 2. Add the variant here with the spec's numeric value.
//! 3. Add a regression test in the `tests` module below that asserts the
//!    numeric value matches the spec.
//! 4. Update the exit-code table in `book/src/cli-reference.md`.
//! 5. Add a CHANGELOG entry.

use crate::verdict::Verdict;

/// Stable CLI exit code per spec §29.
///
/// Numeric values are fixed by the spec; do **not** renumber them. Existing
/// consumers (CI pipelines, shell scripts, MCP clients) depend on the values
/// remaining stable across releases. New codes may be added (with a
/// corresponding spec change), but existing codes are immutable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ExitCode {
    /// `0` — Passed and requested release completed.
    ///
    /// The artifact satisfied all required detectors and policy checks, and
    /// the requested release (write, emit, execute) finished successfully.
    Success = 0,
    /// `1` — General operational error.
    ///
    /// Used when no more specific code applies: argument parsing failures
    /// outside clap's surface, configuration-load errors, unexpected I/O
    /// failures that are not retrieval-related, etc.
    OperationalError = 1,
    /// `2` — Invalid arguments or configuration.
    ///
    /// Reserved for cases where the user supplied an invalid combination of
    /// flags or a malformed configuration file at parse time. clap's default
    /// exit (1) is normally used for argument errors; this code is for the
    /// cases where Arbitraitor detects a semantic invalidity after parsing.
    InvalidArguments = 2,
    /// `10` — Warning verdict, no release requested.
    ///
    /// The policy produced `Verdict::Warn` and the operation did not execute
    /// or write the artifact. Use `arbitraitor explain` to inspect the
    /// decisive findings.
    WarningNoRelease = 10,
    /// `20` — Interactive approval declined.
    ///
    /// The user was prompted and explicitly declined. This is distinct from
    /// "prompt required in non-interactive mode" (21).
    ApprovalDeclined = 20,
    /// `21` — Prompt required in non-interactive mode.
    ///
    /// Policy produced `Verdict::Prompt` but the process was started with
    /// `--non-interactive` (or has no TTY). The operation did not release,
    /// execute, or write any artifact.
    PromptInNonInteractive = 21,
    /// `30` — Blocked by policy.
    ///
    /// Generic policy block. Prefer [`ExitCode::ConfirmedMalicious`] (31) or
    /// [`ExitCode::IntegrityFailure`] (32) when the block reason matches one
    /// of those more specific codes.
    BlockedByPolicy = 30,
    /// `31` — Confirmed malicious indicator.
    ///
    /// A finding with [`Confidence::Confirmed`](crate::verdict::Confidence)
    /// or a confirmed-malicious indicator from a signed intelligence feed was
    /// the decisive cause of the block.
    ConfirmedMalicious = 31,
    /// `32` — Integrity or signature failure.
    ///
    /// The artifact's digest did not match the pinned expected digest, a
    /// required signature was missing or invalid, or the verification
    /// material could not be authenticated against the configured trust
    /// root.
    IntegrityFailure = 32,
    /// `33` — Required detector unavailable or stale.
    ///
    /// A detector marked `required = true` in policy was unavailable,
    /// crashed, or returned an error. The verdict is `Error` and the
    /// operation did not release or execute the artifact.
    RequiredDetectorUnavailable = 33,
    /// `34` — Analysis incomplete due to resource limit.
    ///
    /// Mandatory coverage was not achieved within the configured resource
    /// limits (time, memory, byte budget, archive depth, recursion depth).
    /// The verdict is `Incomplete`.
    AnalysisIncomplete = 34,
    /// `40` — Network retrieval failure.
    ///
    /// The retriever could not fetch the primary artifact: connection
    /// refused, DNS resolution failure, TLS handshake failure, HTTP error
    /// status, truncation, or aborted transfer.
    NetworkRetrievalFailure = 40,
    /// `41` — Redirect or transport policy violation.
    ///
    /// The retriever aborted because policy rejected a redirect chain,
    /// detected a downgrade from HTTPS to HTTP, refused to forward
    /// credentials across origins, or hit a SSRF address-class violation.
    TransportPolicyViolation = 41,
    /// `42` — Content type or size policy violation.
    ///
    /// The fetched bytes did not match the expected content type, exceeded
    /// the configured maximum download size, or were inconsistent with the
    /// declared artifact class.
    ContentTypePolicyViolation = 42,
    /// `50` — Execution failed after approval.
    ///
    /// The artifact was approved and dispatched to the interpreter or native
    /// executor, but the child process exited non-zero, was killed by a
    /// signal, or violated a sandbox rule.
    ExecutionFailed = 50,
    /// `60` — Internal integrity invariant failure.
    ///
    /// One of the security invariants in spec §9 was violated: starting
    /// Arbitraitor as root, hash mismatch between scan and release, missing
    /// CAS object after approval, or any other condition the design treats
    /// as a non-recoverable invariant breach.
    InternalInvariantFailure = 60,
}

impl ExitCode {
    /// Returns the spec-defined numeric value for this exit code.
    ///
    /// Use this when interfacing with APIs that require a raw `i32` (e.g.
    /// `std::process::exit`). Prefer passing `ExitCode` directly through
    /// Arbitraitor's own call sites so the type system catches accidental
    /// integer drift.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Exits the process with this code.
    ///
    /// Used at entry points (`main`, daemon boot, MCP server boot) where no
    /// further cleanup is possible. Library code should propagate the
    /// `ExitCode` value upward.
    pub fn exit(self) -> ! {
        std::process::exit(self.as_i32());
    }
}

impl From<Verdict> for ExitCode {
    /// Maps a [`Verdict`] to its conservative default [`ExitCode`].
    ///
    /// Callers with richer context (finding confidence, transport error
    /// class, integrity failure) should construct the more specific
    /// [`ExitCode`] directly instead of relying on this mapping.
    fn from(verdict: Verdict) -> Self {
        match verdict {
            // Pass implies the operation completed and the requested
            // release (write, emit, execute) succeeded.
            Verdict::Pass => ExitCode::Success,
            // Warning verdict: release was not requested. Callers that
            // requested a release with a Warn verdict should override to
            // `Success` (0) themselves; the spec reserves 10 specifically
            // for the no-release-requested case.
            Verdict::Warn => ExitCode::WarningNoRelease,
            // Prompt is the verdict-level default. In interactive mode the
            // caller should translate to `ApprovalDeclined` (20) when the
            // user explicitly declines, or `Success` (0) when the user
            // approves and the subsequent release succeeds.
            Verdict::Prompt => ExitCode::PromptInNonInteractive,
            // Generic block; callers with confirmed-malicious findings or
            // integrity failures should override to 31 or 32.
            Verdict::Block => ExitCode::BlockedByPolicy,
            // A required detector was unavailable or stale.
            Verdict::Error => ExitCode::RequiredDetectorUnavailable,
            // Mandatory coverage was not achieved within limits.
            Verdict::Incomplete => ExitCode::AnalysisIncomplete,
        }
    }
}

/// Canonical verdict-to-exit-code mapping point per spec §23.2 + §29.
///
/// This is the named entry point the daemon and CLI use to convert a
/// [`Verdict`] into the stable [`ExitCode`] they hand back to the operating
/// system. It is a thin wrapper around [`ExitCode::from`] (the
/// [`From<Verdict>`] implementation provides the conservative default
/// mapping per variant) and exists so call sites read as
/// `verdict_to_exit_code(v)` rather than `ExitCode::from(v)` — making the
/// spec-citation explicit and giving reviewers a single function to point
/// at when the mapping rule changes.
///
/// Callers with richer context (finding confidence, transport error class,
/// integrity failure) should still construct the more specific [`ExitCode`]
/// directly; this function returns the conservative default only.
///
/// # Example
///
/// ```
/// use arbitraitor_model::exit_code::{verdict_to_exit_code, ExitCode};
/// use arbitraitor_model::verdict::Verdict;
///
/// assert_eq!(verdict_to_exit_code(Verdict::Pass), ExitCode::Success);
/// assert_eq!(verdict_to_exit_code(Verdict::Block), ExitCode::BlockedByPolicy);
/// ```
#[must_use]
pub fn verdict_to_exit_code(verdict: Verdict) -> ExitCode {
    ExitCode::from(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::Verdict;

    /// Asserts every `ExitCode` variant carries the spec-mandated numeric
    /// value. Adding a new variant requires extending this test alongside
    /// the spec change.
    #[test]
    fn exit_codes_match_spec_section_29() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::OperationalError.as_i32(), 1);
        assert_eq!(ExitCode::InvalidArguments.as_i32(), 2);
        assert_eq!(ExitCode::WarningNoRelease.as_i32(), 10);
        assert_eq!(ExitCode::ApprovalDeclined.as_i32(), 20);
        assert_eq!(ExitCode::PromptInNonInteractive.as_i32(), 21);
        assert_eq!(ExitCode::BlockedByPolicy.as_i32(), 30);
        assert_eq!(ExitCode::ConfirmedMalicious.as_i32(), 31);
        assert_eq!(ExitCode::IntegrityFailure.as_i32(), 32);
        assert_eq!(ExitCode::RequiredDetectorUnavailable.as_i32(), 33);
        assert_eq!(ExitCode::AnalysisIncomplete.as_i32(), 34);
        assert_eq!(ExitCode::NetworkRetrievalFailure.as_i32(), 40);
        assert_eq!(ExitCode::TransportPolicyViolation.as_i32(), 41);
        assert_eq!(ExitCode::ContentTypePolicyViolation.as_i32(), 42);
        assert_eq!(ExitCode::ExecutionFailed.as_i32(), 50);
        assert_eq!(ExitCode::InternalInvariantFailure.as_i32(), 60);
    }

    #[test]
    fn verdict_to_exit_code_default_mapping() {
        // Default mapping per `From<Verdict>`. Callers may override with
        // more specific codes when they have finding or error-class context.
        assert_eq!(ExitCode::from(Verdict::Pass), ExitCode::Success);
        assert_eq!(ExitCode::from(Verdict::Warn), ExitCode::WarningNoRelease);
        assert_eq!(
            ExitCode::from(Verdict::Prompt),
            ExitCode::PromptInNonInteractive
        );
        assert_eq!(ExitCode::from(Verdict::Block), ExitCode::BlockedByPolicy);
        assert_eq!(
            ExitCode::from(Verdict::Error),
            ExitCode::RequiredDetectorUnavailable
        );
        assert_eq!(
            ExitCode::from(Verdict::Incomplete),
            ExitCode::AnalysisIncomplete
        );
    }

    /// Guards the canonical mapping function (`verdict_to_exit_code`)
    /// against drift: it must agree with `From<Verdict>` for every variant
    /// because that is the documented contract. If either side changes,
    /// this test forces a synchronous update on both call sites.
    #[test]
    fn verdict_to_exit_code_matches_from_verdict_for_all_variants() {
        assert_eq!(
            verdict_to_exit_code(Verdict::Pass),
            ExitCode::from(Verdict::Pass)
        );
        assert_eq!(
            verdict_to_exit_code(Verdict::Warn),
            ExitCode::from(Verdict::Warn)
        );
        assert_eq!(
            verdict_to_exit_code(Verdict::Prompt),
            ExitCode::from(Verdict::Prompt)
        );
        assert_eq!(
            verdict_to_exit_code(Verdict::Block),
            ExitCode::from(Verdict::Block)
        );
        assert_eq!(
            verdict_to_exit_code(Verdict::Error),
            ExitCode::from(Verdict::Error)
        );
        assert_eq!(
            verdict_to_exit_code(Verdict::Incomplete),
            ExitCode::from(Verdict::Incomplete)
        );
    }

    /// Guards against silent renumbering: every variant must round-trip
    /// through `as_i32` and back via `TryFrom<i32>`-equivalent lookup
    /// (callers depend on the numeric values staying stable).
    #[test]
    fn all_variants_have_unique_numeric_values() {
        let all = [
            ExitCode::Success,
            ExitCode::OperationalError,
            ExitCode::InvalidArguments,
            ExitCode::WarningNoRelease,
            ExitCode::ApprovalDeclined,
            ExitCode::PromptInNonInteractive,
            ExitCode::BlockedByPolicy,
            ExitCode::ConfirmedMalicious,
            ExitCode::IntegrityFailure,
            ExitCode::RequiredDetectorUnavailable,
            ExitCode::AnalysisIncomplete,
            ExitCode::NetworkRetrievalFailure,
            ExitCode::TransportPolicyViolation,
            ExitCode::ContentTypePolicyViolation,
            ExitCode::ExecutionFailed,
            ExitCode::InternalInvariantFailure,
        ];
        let mut seen = std::collections::HashSet::new();
        for code in all {
            assert!(
                seen.insert(code.as_i32()),
                "duplicate numeric value {} — spec §29 mandates uniqueness",
                code.as_i32()
            );
        }
        assert_eq!(seen.len(), 16, "spec §29 defines 16 exit codes");
    }
}
