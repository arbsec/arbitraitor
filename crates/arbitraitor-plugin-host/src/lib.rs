//! Wasmtime and subprocess plugin runtime.
//!
//! This crate exposes the subprocess protocol layer and a sandboxed subprocess
//! executor for native plugin fallback adapters.
//!
//! See `docs/spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod admission;
pub mod error;
pub mod executor;
pub mod frame;
pub mod manifest;
pub mod protocol;
pub mod registry;
#[cfg(feature = "experimental-wasm")]
pub mod wasm_engine;
#[cfg(feature = "experimental-wasm")]
pub mod wasm_plugin;
