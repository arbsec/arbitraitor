//! Structural validation of the workspace-root WIT package.
//!
//! These tests lock the capability-isolation invariant from ADR 0006: each
//! world grants only the host imports its role needs. A downloader wrapper
//! must not automatically gain artifact-bytes access or detector capabilities.

#![forbid(unsafe_code)]

use std::error::Error;
use std::path::Path;

use wit_parser::{PackageId, Resolve, WorldId, WorldItem};

/// Expected world names mandated by ADR 0006.
const EXPECTED_WORLDS: [&str; 4] = ["detector", "wrapper", "intelligence", "provenance"];

/// Loads and fully resolves the workspace-root `wit/` package.
fn load_wit() -> Result<(Resolve, Vec<PackageId>), Box<dyn Error>> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let manifest_path = Path::new(manifest_dir);
    let wit_dir = manifest_path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "cannot locate workspace root from manifest dir".to_owned())?
        .join("wit");

    let mut resolve = Resolve::default();
    let (package_id, _) = resolve.push_dir(&wit_dir)?;
    Ok((resolve, vec![package_id]))
}

/// Selects a world by name, returning a typed error on failure.
fn world_id(
    resolve: &Resolve,
    packages: &[PackageId],
    name: &str,
) -> Result<WorldId, Box<dyn Error>> {
    resolve
        .select_world(packages, Some(name))
        .map_err(|error| format!("world '{name}' should resolve: {error:?}").into())
}

/// Returns the names of all import functions (excluding type/interface imports)
/// in a world.
fn import_func_names(resolve: &Resolve, world_id: WorldId) -> Vec<String> {
    resolve.worlds[world_id]
        .imports
        .iter()
        .filter_map(|(key, item)| match item {
            WorldItem::Function(_) => Some(resolve.name_world_key(key)),
            WorldItem::Interface { .. } | WorldItem::Type { .. } => None,
        })
        .collect()
}

/// Returns the names of all export functions in a world.
fn export_func_names(resolve: &Resolve, world_id: WorldId) -> Vec<String> {
    resolve.worlds[world_id]
        .exports
        .iter()
        .filter_map(|(key, item)| match item {
            WorldItem::Function(_) => Some(resolve.name_world_key(key)),
            WorldItem::Interface { .. } | WorldItem::Type { .. } => None,
        })
        .collect()
}

#[test]
fn all_four_worlds_exist() -> Result<(), Box<dyn Error>> {
    let (resolve, packages) = load_wit()?;

    for name in EXPECTED_WORLDS {
        assert!(
            resolve.select_world(&packages, Some(name)).is_ok(),
            "world '{name}' should exist in the WIT package"
        );
    }
    Ok(())
}

#[test]
fn detector_world_has_artifact_access() -> Result<(), Box<dyn Error>> {
    let (resolve, packages) = load_wit()?;
    let world = world_id(&resolve, &packages, "detector")?;
    let imports = import_func_names(&resolve, world);

    assert!(
        imports.contains(&"get-artifact-bytes".to_owned()),
        "detector must import get-artifact-bytes; got {imports:?}"
    );
    assert!(
        imports.contains(&"get-artifact-size".to_owned()),
        "detector must import get-artifact-size; got {imports:?}"
    );
    assert!(
        imports.contains(&"log".to_owned()),
        "detector must import log; got {imports:?}"
    );
    Ok(())
}

#[test]
fn wrapper_world_is_isolated_from_artifact_bytes() -> Result<(), Box<dyn Error>> {
    // ADR 0006: a downloader argument parser does not automatically gain
    // detector or network capabilities.
    let (resolve, packages) = load_wit()?;
    let world = world_id(&resolve, &packages, "wrapper")?;
    let imports = import_func_names(&resolve, world);

    assert!(
        !imports.contains(&"get-artifact-bytes".to_owned()),
        "wrapper must NOT import get-artifact-bytes; got {imports:?}"
    );
    assert!(
        !imports.contains(&"get-artifact-size".to_owned()),
        "wrapper must NOT import get-artifact-size; got {imports:?}"
    );
    assert!(
        imports.contains(&"log".to_owned()),
        "wrapper must import log; got {imports:?}"
    );
    Ok(())
}

#[test]
fn intelligence_world_is_isolated_from_artifact_bytes() -> Result<(), Box<dyn Error>> {
    let (resolve, packages) = load_wit()?;
    let world = world_id(&resolve, &packages, "intelligence")?;
    let imports = import_func_names(&resolve, world);

    assert!(
        !imports.contains(&"get-artifact-bytes".to_owned()),
        "intelligence must NOT import get-artifact-bytes; got {imports:?}"
    );
    assert!(
        imports.contains(&"log".to_owned()),
        "intelligence must import log; got {imports:?}"
    );
    Ok(())
}

#[test]
fn provenance_world_has_artifact_bytes_but_not_size() -> Result<(), Box<dyn Error>> {
    let (resolve, packages) = load_wit()?;
    let world = world_id(&resolve, &packages, "provenance")?;
    let imports = import_func_names(&resolve, world);

    assert!(
        imports.contains(&"get-artifact-bytes".to_owned()),
        "provenance must import get-artifact-bytes; got {imports:?}"
    );
    assert!(
        !imports.contains(&"get-artifact-size".to_owned()),
        "provenance does not need get-artifact-size; got {imports:?}"
    );
    Ok(())
}

#[test]
fn every_world_exports_init_and_shutdown() -> Result<(), Box<dyn Error>> {
    let (resolve, packages) = load_wit()?;

    for name in EXPECTED_WORLDS {
        let world = world_id(&resolve, &packages, name)?;
        let exports = export_func_names(&resolve, world);

        assert!(
            exports.contains(&"init".to_owned()),
            "world '{name}' must export init; got {exports:?}"
        );
        assert!(
            exports.contains(&"shutdown".to_owned()),
            "world '{name}' must export shutdown; got {exports:?}"
        );
    }
    Ok(())
}

#[test]
fn each_world_exports_its_role_function() -> Result<(), Box<dyn Error>> {
    let (resolve, packages) = load_wit()?;

    let cases: [(&str, &str); 4] = [
        ("detector", "analyze"),
        ("wrapper", "translate"),
        ("intelligence", "lookup"),
        ("provenance", "verify"),
    ];

    for (world_name, expected_export) in cases {
        let world = world_id(&resolve, &packages, world_name)?;
        let exports = export_func_names(&resolve, world);
        assert!(
            exports.contains(&expected_export.to_owned()),
            "world '{world_name}' must export '{expected_export}'; got {exports:?}"
        );
    }
    Ok(())
}
