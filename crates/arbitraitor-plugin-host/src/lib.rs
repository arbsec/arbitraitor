//! Wasmtime and subprocess plugin runtime.
//!
//! This crate exposes the subprocess protocol layer and a sandboxed subprocess
//! executor for native plugin fallback adapters.
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod executor;
pub mod frame;
pub mod protocol;
pub mod registry;
