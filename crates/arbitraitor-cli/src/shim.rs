use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, Result};

use crate::commands::{ShimCommand, ShimSubcommand};

const SUPPORTED_SHIMS: &[&str] = &["npm", "curl", "wget", "brew"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShimSlotState {
    Script,
    NotInstalled,
    ForeignFile,
}

#[derive(Debug, Eq, PartialEq)]
struct ShimSlotStatus {
    tool: &'static str,
    state: ShimSlotState,
}

/// Runs the `arbitraitor shim` compatibility-shim command.
pub(crate) fn run(command: &ShimCommand) -> Result<()> {
    match &command.subcommand {
        ShimSubcommand::List => list(),
        ShimSubcommand::Install { tool } => install(tool),
        ShimSubcommand::Remove { tool } | ShimSubcommand::Uninstall { tool } => remove(tool),
        ShimSubcommand::Real { tool } => real(tool),
        ShimSubcommand::Status => status(),
    }
}

fn list() -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "Supported shims: {}", SUPPORTED_SHIMS.join(", ")).into_diagnostic()?;
    writeln!(stdout).into_diagnostic()?;
    let shim_dir = shim_dir_from_home()?;
    if !shim_dir.exists() {
        writeln!(stdout, "No shims installed.").into_diagnostic()?;
        return Ok(());
    }
    for entry in std::fs::read_dir(&shim_dir).into_diagnostic()? {
        let entry = entry.into_diagnostic()?;
        let name = entry.file_name().to_string_lossy().to_string();
        writeln!(stdout, "  {name}").into_diagnostic()?;
    }
    Ok(())
}

fn install(tool: &str) -> Result<()> {
    let shim_dir = shim_dir_from_home()?;
    let arb = current_shim_arbitraitor_binary();
    let shim_path = install_shim_to_dir(tool, &shim_dir, &arb)?;
    writeln!(
        std::io::stdout().lock(),
        "installed: {}",
        shim_path.display()
    )
    .into_diagnostic()
}

fn remove(tool: &str) -> Result<()> {
    ensure_supported_shim(tool)?;
    let shim_dir = shim_dir_from_home()?;
    let shim_path = shim_dir.join(tool);
    if matches!(detect_shim_slot(&shim_path, tool), ShimSlotState::Script) {
        std::fs::remove_file(&shim_path).into_diagnostic()?;
        writeln!(std::io::stdout().lock(), "removed: {}", shim_path.display()).into_diagnostic()?;
    } else {
        writeln!(std::io::stdout().lock(), "not installed: {tool}").into_diagnostic()?;
    }
    Ok(())
}

fn real(tool: &str) -> Result<()> {
    ensure_supported_shim(tool)?;
    let shim_dir = shim_dir_from_home()?;
    let path = std::env::var_os("PATH").unwrap_or_default();
    let real = resolve_real_binary_in_path(tool, &shim_dir, &path)?;
    writeln!(std::io::stdout().lock(), "{}", real.display()).into_diagnostic()
}

fn status() -> Result<()> {
    let shim_dir = shim_dir_from_home()?;
    let statuses = shim_statuses(&shim_dir);
    let mut stdout = std::io::stdout().lock();
    for status in &statuses {
        writeln!(stdout, "{}: {}", status.tool, status.state.label()).into_diagnostic()?;
    }
    Ok(())
}

fn shim_dir_from_home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".arbitraitor").join("shims"))
        .ok_or_else(|| miette::miette!("HOME not set"))
}

fn current_shim_arbitraitor_binary() -> String {
    std::env::current_exe().map_or_else(
        |_| "arbitraitor".to_owned(),
        |path| path.display().to_string(),
    )
}

fn ensure_supported_shim(tool: &str) -> Result<()> {
    if SUPPORTED_SHIMS.contains(&tool) {
        Ok(())
    } else {
        miette::bail!(
            "unsupported shim '{tool}'; supported: {}",
            SUPPORTED_SHIMS.join(", ")
        );
    }
}

fn install_shim_to_dir(tool: &str, shim_dir: &Path, arbitraitor_binary: &str) -> Result<PathBuf> {
    ensure_supported_shim(tool)?;
    std::fs::create_dir_all(shim_dir).into_diagnostic()?;
    let shim_path = shim_dir.join(tool);
    let content = render_shim_script(tool, arbitraitor_binary);
    std::fs::write(&shim_path, content).into_diagnostic()?;
    set_shim_executable(&shim_path)?;
    Ok(shim_path)
}

fn render_shim_script(tool: &str, arbitraitor_binary: &str) -> String {
    let arb = shell_single_quote(arbitraitor_binary);
    let command = shim_dispatch_command(tool);
    format!("#!/bin/sh\n# Arbitraitor shim for {tool}\nexec {arb} {command} -- \"$@\"\n")
}

fn shim_dispatch_command(tool: &str) -> String {
    match tool {
        "npm" => "pm run --tool npm".to_owned(),
        "curl" => "fetch --tool curl".to_owned(),
        "wget" => "fetch --tool wget".to_owned(),
        "brew" => "wrap brew".to_owned(),
        _ => format!("wrap {tool}"),
    }
}

fn shell_single_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn set_shim_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).into_diagnostic()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn resolve_real_binary_in_path(tool: &str, shim_dir: &Path, path: &OsStr) -> Result<PathBuf> {
    for dir in std::env::split_paths(path) {
        if dir == shim_dir {
            continue;
        }
        let candidate = dir.join(tool);
        if is_executable_file(&candidate) {
            return Ok(candidate);
        }
    }
    miette::bail!(
        "could not resolve real binary for '{tool}' outside {}",
        shim_dir.display()
    )
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn shim_statuses(shim_dir: &Path) -> Vec<ShimSlotStatus> {
    SUPPORTED_SHIMS
        .iter()
        .map(|&tool| ShimSlotStatus {
            tool,
            state: detect_shim_slot(&shim_dir.join(tool), tool),
        })
        .collect()
}

fn detect_shim_slot(path: &Path, tool: &str) -> ShimSlotState {
    let Ok(metadata) = std::fs::metadata(path) else {
        return ShimSlotState::NotInstalled;
    };
    if !metadata.is_file() {
        return ShimSlotState::ForeignFile;
    }
    let marker = format!("Arbitraitor shim for {tool}");
    match std::fs::read_to_string(path) {
        Ok(content) if content.contains(&marker) => ShimSlotState::Script,
        _ => ShimSlotState::ForeignFile,
    }
}

impl ShimSlotState {
    const fn label(self) -> &'static str {
        match self {
            Self::Script => "installed",
            Self::NotInstalled => "not installed",
            Self::ForeignFile => "foreign file",
        }
    }
}

#[cfg(test)]
#[path = "shim_tests.rs"]
mod tests;
