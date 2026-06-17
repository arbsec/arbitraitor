//! Policy rule evaluation and verdicts for Arbitraitor.
//!
//! The policy engine is the decision layer: it consumes detector findings and
//! runtime context, evaluates them against a compiled TOML policy, and
//! produces a [`Verdict`].
//!
//! # Quick start
//!
//! ```no_run
//! use arbitraitor_policy::{PolicyEngine, EvalContext};
//! use arbitraitor_model::verdict::Verdict;
//!
//! let toml = r#"
//! version = 1
//!
//! [defaults]
//! action = "prompt"
//! non_interactive_prompt_action = "block"
//!
//! [[rules]]
//! id = "block-confirmed-malware"
//! action = "block"
//! [rules.when.finding]
//! category = "malware-signature"
//! confidence = "confirmed"
//! "#;
//!
//! let engine = PolicyEngine::load(toml).unwrap();
//! let context = EvalContext::new(true).with_https(true);
//! let verdict = engine.evaluate(&[], &context);
//! assert_eq!(verdict, Verdict::Prompt); // no findings → default prompt
//! ```
//!
//! # Design principles
//!
//! - **Deterministic:** rules are evaluated top-to-bottom; first match wins.
//!   The same policy + findings + context always produce the same verdict.
//! - **Three-valued logic:** when evidence is unavailable (e.g. a condition
//!   references `finding.*` but no finding is provided), the rule is *skipped*
//!   rather than failing.
//! - **Fail-closed:** the default action is `prompt`; in a non-interactive
//!   context prompts are upgraded to `block`.
//! - **Total:** evaluation never panics. Every code path returns a verdict.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod context;
mod engine;
mod error;
mod schema;

pub use context::EvalContext;
pub use engine::PolicyEngine;
pub use error::PolicyError;
pub use schema::{
    Condition, DefaultsConfig, FieldMatch, LimitsConfig, MatchOp, NetworkConfig, Policy,
    PolicyAction, RedirectsConfig, Rule, ScalarValue,
};

#[cfg(test)]
mod tests;
