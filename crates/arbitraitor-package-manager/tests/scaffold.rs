//! Scaffold smoke tests for the package-manager adapter trait and types.

use arbitraitor_package_manager::{
    AdapterManagerError, AdapterRecipe, InspectionPattern, LifecycleScriptPolicy,
    LifecycleScriptStatus, LockfileFormat, PackageManagerReceipt, ProxyMode, RegistryAdapter,
    RegistryTool,
};

#[derive(Debug)]
struct CargoAdapter;

impl RegistryAdapter for CargoAdapter {
    fn tool(&self) -> RegistryTool {
        RegistryTool::Cargo
    }
    fn recipe(&self) -> AdapterRecipe {
        AdapterRecipe {
            primary: InspectionPattern::LockfilePrescan,
            secondary: vec![
                InspectionPattern::PostInstallScan,
                InspectionPattern::BuildScriptSandbox,
            ],
        }
    }
    fn lockfile_format(&self) -> LockfileFormat {
        LockfileFormat::CargoLock
    }
    fn lifecycle_script_policy(&self) -> LifecycleScriptPolicy {
        LifecycleScriptPolicy::SandboxRequired
    }
}

#[test]
fn cargo_adapter_metadata_matches_spec_recipe() {
    let adapter = CargoAdapter;
    assert_eq!(adapter.tool(), RegistryTool::Cargo);
    assert_eq!(adapter.tool().as_str(), "cargo");
    assert_eq!(adapter.lockfile_format(), LockfileFormat::CargoLock);

    let recipe = adapter.recipe();
    assert_eq!(recipe.primary, InspectionPattern::LockfilePrescan);
    assert_eq!(recipe.secondary.len(), 2);
    assert!(
        recipe
            .secondary
            .contains(&InspectionPattern::BuildScriptSandbox)
    );

    assert!(matches!(
        adapter.lifecycle_script_policy(),
        LifecycleScriptPolicy::SandboxRequired
    ));
}

#[test]
fn all_tools_have_distinct_names() {
    let tools = [
        RegistryTool::Cargo,
        RegistryTool::Uv,
        RegistryTool::Uvx,
        RegistryTool::Npm,
        RegistryTool::Pnpm,
        RegistryTool::YarnClassic,
        RegistryTool::YarnBerry,
        RegistryTool::Bun,
    ];
    let names: Vec<&str> = tools.iter().map(|t| t.as_str()).collect();
    let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
    assert_eq!(names.len(), unique.len(), "tool names must be distinct");
}

#[test]
fn receipt_fields_roundtrip() {
    let receipt = PackageManagerReceipt {
        tool: "cargo".to_owned(),
        tool_version: "1.96.0".to_owned(),
        lockfile_digest: "sha256:abc".to_owned(),
        packages_inspected: 42,
        packages_blocked: 1,
        packages_incomplete: 0,
        lifecycle_scripts: LifecycleScriptStatus::Denied,
        build_sandbox: Some("gvisor".to_owned()),
        proxy_mode: ProxyMode::LockfilePrescan,
    };
    assert_eq!(receipt.tool, "cargo");
    assert_eq!(receipt.packages_inspected, 42);
    assert_eq!(receipt.lifecycle_scripts, LifecycleScriptStatus::Denied);
    assert_eq!(receipt.proxy_mode, ProxyMode::LockfilePrescan);
}

#[test]
fn error_variants_format_correctly() {
    let err = AdapterManagerError::ToolNotFound {
        tool: "cargo".to_owned(),
    };
    assert!(err.to_string().contains("cargo"));

    let err = AdapterManagerError::UnsupportedToolVersion {
        tool: "npm".to_owned(),
        version: "5.x".to_owned(),
    };
    assert!(err.to_string().contains("npm"));
    assert!(err.to_string().contains("5.x"));
}
