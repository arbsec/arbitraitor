use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "arb-cli-shim-{label}-{}-{nanos}",
            std::process::id(),
        ));
        std::fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_installs_tool(tool: &str, command: &str) -> Result<(), Box<dyn std::error::Error>> {
    let dir = TestDir::new(tool)?;

    let shim = install_shim_to_dir(tool, dir.path(), "/usr/local/bin/arbitraitor")?;

    let content = std::fs::read_to_string(&shim)?;
    assert_eq!(shim, dir.path().join(tool));
    assert!(content.contains(&format!("Arbitraitor shim for {tool}")));
    assert!(content.contains(command));
    Ok(())
}

#[test]
fn shim_install_curl() -> Result<(), Box<dyn std::error::Error>> {
    assert_installs_tool("curl", "fetch --tool curl")
}

#[test]
fn shim_install_wget() -> Result<(), Box<dyn std::error::Error>> {
    assert_installs_tool("wget", "fetch --tool wget")
}

#[test]
fn shim_real_curl() -> Result<(), Box<dyn std::error::Error>> {
    let shim_dir = TestDir::new("real-shim")?;
    let real_dir = TestDir::new("real-bin")?;
    let shim = install_shim_to_dir("curl", shim_dir.path(), "/usr/local/bin/arbitraitor")?;
    let real = real_dir.path().join("curl");
    std::fs::write(&real, "#!/bin/sh\n")?;
    set_shim_executable(&real)?;
    let path = std::env::join_paths([shim_dir.path(), real_dir.path()])?;

    let resolved = resolve_real_binary_in_path("curl", shim_dir.path(), &path)?;

    assert_eq!(resolved, real);
    assert_ne!(resolved, shim);
    Ok(())
}

#[test]
fn shim_status_shows_all() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TestDir::new("status")?;
    install_shim_to_dir("curl", dir.path(), "/usr/local/bin/arbitraitor")?;

    let statuses = shim_statuses(dir.path());

    assert_eq!(statuses.len(), SUPPORTED_SHIMS.len());
    for tool in SUPPORTED_SHIMS {
        assert!(statuses.iter().any(|status| status.tool == *tool));
    }
    assert!(
        statuses
            .iter()
            .any(|status| status.tool == "curl" && status.state == ShimSlotState::Script)
    );
    assert!(
        statuses
            .iter()
            .any(|status| status.tool == "brew" && status.state == ShimSlotState::NotInstalled)
    );
    Ok(())
}
