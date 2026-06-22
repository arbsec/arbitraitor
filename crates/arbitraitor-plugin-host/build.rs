//! Build script for `arbitraitor-plugin-host`.
//!
//! Validates that the workspace-root `wit/` package parses cleanly and that
//! all four plugin worlds (`detector`, `wrapper`, `intelligence`, `provenance`)
//! resolve without error. If the WIT is malformed the build script returns an
//! error, failing the build before any host code compiles.
//!
//! Host-side Rust bindings (via `wasmtime::component::bindgen!`) are deferred
//! to #227 / #228 which add the Wasmtime runtime.

use std::error::Error;
use std::path::Path;

use wit_parser::Resolve;

/// Worlds mandated by ADR 0006.
const EXPECTED_WORLDS: [&str; 4] = ["detector", "wrapper", "intelligence", "provenance"];

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let workspace_root = Path::new(&manifest_dir)
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "cannot locate workspace root from manifest dir".to_owned())?;
    let wit_dir = workspace_root.join("wit");

    println!("cargo:rerun-if-changed={}", wit_dir.display());

    let mut resolve = Resolve::default();
    let (package_id, _) = resolve.push_dir(&wit_dir)?;
    let main_packages = vec![package_id];

    for world_name in EXPECTED_WORLDS {
        resolve
            .select_world(&main_packages, Some(world_name))
            .map_err(|error| format!("failed to select world '{world_name}': {error:?}"))?;
    }

    Ok(())
}
