// Generated bindings for the `detector` world from the WIT file.
// Suppressed lints: the macro-generated code is not hand-written
// and triggers various pedantic warnings.
#![allow(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    dead_code,
    unused_imports,
    unused_qualifications,
    non_local_definitions
)]

wasmtime::component::bindgen!({
    path: "../../wit/arbitraitor-plugin.wit",
    world: "detector",
});
