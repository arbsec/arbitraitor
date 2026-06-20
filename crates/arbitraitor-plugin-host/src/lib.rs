//! Wasmtime and subprocess plugin runtime.
//!
//! This crate currently exposes only the subprocess protocol layer: a
//! deterministic length-prefixed JSON envelope that native plugin processes can
//! use to exchange lifecycle and operation messages with Arbitraitor. Process
//! spawning, sandboxing, timeouts, descriptor hygiene, and kill-tree management
//! are intentionally out of scope for this layer and will be implemented by the
//! executor in a later change.
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod frame;
pub mod protocol;
