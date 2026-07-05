//! Integration coverage for the sandboxed subprocess plugin executor.

#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_plugin_host::executor::{ExecutorError, SubprocessExecutor};
use arbitraitor_plugin_host::protocol::MessageKind;
use serde_json::json;

#[test]
fn network_isolation_enabled_by_default() {
    let executor = SubprocessExecutor::new(mock_plugin());

    assert!(executor.network_isolated());
}

#[test]
fn network_isolation_can_be_disabled() {
    let executor = SubprocessExecutor::new(mock_plugin()).with_network_isolated(false);

    assert!(!executor.network_isolated());
}

#[test]
fn spawn_rejects_missing_binary() {
    let path = env::temp_dir().join("arbitraitor-missing-plugin-binary");

    let result = SubprocessExecutor::new(path.clone()).spawn();

    assert!(matches!(result, Err(ExecutorError::BinaryNotFound(found)) if found == path));
}

#[test]
fn spawn_rejects_relative_binary_path() {
    let path = PathBuf::from("relative-plugin-binary");

    let result = SubprocessExecutor::new(path.clone()).spawn();

    assert!(matches!(result, Err(ExecutorError::BinaryPathNotAbsolute(found)) if found == path));
}

#[test]
fn spawn_rejects_digest_mismatch() {
    let result = SubprocessExecutor::new(mock_plugin())
        .with_expected_digest(Sha256Digest::new([0xAA; 32]))
        .spawn();

    assert!(matches!(result, Err(ExecutorError::DigestMismatch { .. })));
}

#[test]
fn spawn_rejects_denied_environment_variable() {
    let result = SubprocessExecutor::new(mock_plugin())
        .with_env_allowlist(vec!["LD_PRELOAD".to_owned()])
        .spawn();

    assert!(matches!(
        result,
        Err(ExecutorError::DeniedEnvironmentVariable { name })
            if name == "LD_PRELOAD"
    ));
}

#[test]
fn spawn_rejects_denied_environment_prefix() {
    let result = SubprocessExecutor::new(mock_plugin())
        .with_env_allowlist(vec!["DYLD_INSERT_LIBRARIES".to_owned()])
        .spawn();

    assert!(matches!(
        result,
        Err(ExecutorError::DeniedEnvironmentVariable { name })
            if name == "DYLD_INSERT_LIBRARIES"
    ));
}

#[test]
fn spawn_clears_environment() -> Result<(), Box<dyn std::error::Error>> {
    let mut plugin = SubprocessExecutor::new(mock_plugin())
        .with_env_allowlist(Vec::new())
        .spawn()?;

    let manifest = plugin.handshake()?;
    plugin.shutdown()?;

    assert_eq!(manifest.description, "env:<missing>");
    Ok(())
}

#[test]
fn handshake_exchanges_manifest() -> Result<(), Box<dyn std::error::Error>> {
    let mut plugin = SubprocessExecutor::new(mock_plugin()).spawn()?;

    let manifest = plugin.handshake()?;
    plugin.shutdown()?;

    assert_eq!(manifest.identity.id, "plugin.test.mock");
    Ok(())
}

#[tokio::test]
async fn request_times_out() -> Result<(), Box<dyn std::error::Error>> {
    let mut plugin = SubprocessExecutor::new(mock_plugin())
        .with_timeout(Duration::from_millis(100))
        .spawn()?;
    plugin.handshake()?;

    let result = plugin.request(MessageKind::LookupRequest, json!({})).await;

    assert!(matches!(result, Err(ExecutorError::Timeout(_))));
    Ok(())
}

#[test]
fn shutdown_stops_process() -> Result<(), Box<dyn std::error::Error>> {
    let mut plugin = SubprocessExecutor::new(mock_plugin()).spawn()?;
    plugin.handshake()?;

    plugin.shutdown()?;

    assert_eq!(plugin.process_id(), None);
    Ok(())
}

#[test]
fn drop_kills_orphaned_process() -> Result<(), Box<dyn std::error::Error>> {
    let mut plugin = SubprocessExecutor::new(mock_plugin()).spawn()?;
    plugin.handshake()?;
    let pid = plugin.process_id().unwrap_or_default();

    drop(plugin);

    assert_process_exited(pid);
    Ok(())
}

#[test]
fn env_allowlist_passed_through() -> Result<(), Box<dyn std::error::Error>> {
    let mut plugin = SubprocessExecutor::new(mock_plugin())
        .with_env_allowlist(vec!["PATH".to_owned()])
        .spawn()?;

    let manifest = plugin.handshake()?;
    plugin.shutdown()?;

    assert!(manifest.description.starts_with("env:"));
    assert_ne!(manifest.description, "env:<missing>");
    Ok(())
}

#[test]
fn spawn_proceeds_past_root_check_when_unprivileged() {
    // ADR-0009: when the host is NOT root (the normal CI/dev case), the root
    // guard must be a no-op and spawn must advance to the next validation
    // stage. A missing binary surfaces BinaryNotFound, proving the root check
    // did not short-circuit the non-root path.
    if arbitraitor_core::privilege::is_running_as_root() {
        return;
    }
    let path = env::temp_dir().join("arbitraitor-root-guard-probe-binary");
    let result = SubprocessExecutor::new(path.clone()).spawn();
    assert!(
        matches!(result, Err(ExecutorError::BinaryNotFound(found)) if found == path),
        "non-root host must reach binary validation"
    );
}

fn mock_plugin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_arbitraitor-plugin-host-mock-plugin"))
}

fn assert_process_exited(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(1);
    let proc_path = PathBuf::from(format!("/proc/{pid}"));
    while Instant::now() < deadline {
        if !proc_path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!proc_path.exists(), "plugin process {pid} was not reaped");
}
