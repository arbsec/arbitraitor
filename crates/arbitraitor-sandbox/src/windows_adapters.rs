//! Windows-specific sandbox adapters (spec §27.5).
//!
//! These are stub implementations that document the intended adapter
//! surface for Windows platforms. Actual integration requires Windows
//! APIs (`AppContainer`, `Job Objects`, `WDAC`, `Hyper-V`) which are
//! out of scope for the Linux-focused MVP.

use std::process::Command;

/// Adapter for `Windows Sandbox` (spec §27.5).
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsSandboxAdapter;

impl WindowsSandboxAdapter {
    /// Returns whether `Windows Sandbox` is available.
    #[must_use]
    pub fn is_available() -> bool {
        false
    }
}

/// Adapter for `AppContainer` (spec §27.5).
#[derive(Clone, Copy, Debug, Default)]
pub struct AppContainerAdapter;

impl AppContainerAdapter {
    /// Returns whether `AppContainer` is available.
    #[must_use]
    pub fn is_available() -> bool {
        false
    }
}

/// Adapter for `Job Objects` (spec §27.5).
#[derive(Clone, Copy, Debug, Default)]
pub struct JobObjectsAdapter;

impl JobObjectsAdapter {
    /// Returns a `Command` pre-configured to run under a `Job Object`
    /// with resource limits applied.
    #[must_use]
    pub fn create_command(child: &str) -> Option<Command> {
        let cmd = Command::new(child);
        Some(cmd)
    }
}

/// Adapter for `WDAC` (spec §27.5).
#[derive(Clone, Copy, Debug, Default)]
pub struct WdacAdapter;

impl WdacAdapter {
    /// Returns whether `WDAC` policy enforcement is available.
    #[must_use]
    pub fn is_available() -> bool {
        false
    }
}

/// Adapter for `Hyper-V` disposable VM (spec §27.5).
#[derive(Clone, Copy, Debug, Default)]
pub struct HyperVAdapter;

impl HyperVAdapter {
    /// Returns whether `Hyper-V` is available for disposable VM execution.
    #[must_use]
    pub fn is_available() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_sandbox_not_available_on_linux() {
        assert!(!WindowsSandboxAdapter::is_available());
    }

    #[test]
    fn app_container_not_available_on_linux() {
        assert!(!AppContainerAdapter::is_available());
    }

    #[test]
    fn wdac_not_available_on_linux() {
        assert!(!WdacAdapter::is_available());
    }

    #[test]
    fn hyper_v_not_available_on_linux() {
        assert!(!HyperVAdapter::is_available());
    }
}
