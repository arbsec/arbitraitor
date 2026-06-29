//! Shell alias and PATH shim installation for Arbitraitor wrappers.
//!
//! Produces tiny `exec`-based wrapper scripts or symlinks that route `curl` and
//! `wget` invocations through `arbitraitor fetch`, so downloads flow through the
//! inspection pipeline instead of reaching the network directly.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Marker prefix embedded in every generated script shim so [`check_shims`]
/// can distinguish Arbitraitor shims from unrelated files at the same path.
const SHIM_MARKER: &str = "Arbitraitor shim for ";

/// Supported wrapper targets that can be shimmed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WrapperTarget {
    /// HTTP client `curl`.
    Curl,
    /// HTTP client `wget`.
    Wget,
}

impl WrapperTarget {
    /// All supported wrapper targets, in canonical order.
    pub const ALL: &[WrapperTarget] = &[WrapperTarget::Curl, WrapperTarget::Wget];

    /// The binary name that gets shadowed on `PATH`.
    #[must_use]
    pub const fn binary_name(&self) -> &'static str {
        match self {
            Self::Curl => "curl",
            Self::Wget => "wget",
        }
    }

    /// The `arbitraitor` subcommand that handles this wrapper.
    #[must_use]
    pub const fn arbitraitor_subcommand(&self) -> &'static str {
        match self {
            Self::Curl | Self::Wget => "fetch",
        }
    }

    /// Parses a target name (`"curl"` / `"wget"`) into a [`WrapperTarget`].
    ///
    /// Returns `None` for unrecognized names so callers can report the bad
    /// value rather than silently falling back.
    #[must_use]
    pub fn from_binary_name(name: &str) -> Option<Self> {
        match name {
            "curl" => Some(Self::Curl),
            "wget" => Some(Self::Wget),
            _ => None,
        }
    }
}

/// Where and how to install shims.
#[derive(Clone, Debug)]
pub struct ShimConfig {
    /// Directory to install PATH shims (e.g. `~/.arbitraitor/shims`).
    pub shim_dir: PathBuf,
    /// `true` creates symlinks to the arbitraitor binary; `false` writes
    /// standalone wrapper scripts.
    pub use_symlinks: bool,
}

/// Observed state of a single shim slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShimState {
    /// A script shim containing the Arbitraitor marker is installed.
    Script,
    /// A symlink shim pointing at the arbitraitor binary is installed.
    Symlink,
    /// No file occupies the shim slot.
    NotInstalled,
    /// A file exists at the slot but it is not an Arbitraitor shim.
    ForeignFile,
}

/// Result of probing one shim slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShimStatus {
    /// The wrapper target this status describes.
    pub target: WrapperTarget,
    /// Path where the shim would live.
    pub path: PathBuf,
    /// Detected state of the slot.
    pub state: ShimState,
}

/// Errors produced while installing or removing shims.
#[derive(Debug, Error)]
pub enum ShimError {
    /// The shim directory could not be created.
    #[error("failed to create shim directory {path}: {source}")]
    CreateShimDir {
        /// Directory that could not be created.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A script shim file could not be written.
    #[error("failed to write shim {path}: {source}")]
    WriteShim {
        /// Shim path that could not be written.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A symlink shim could not be created.
    #[error("failed to create symlink {path}: {source}")]
    CreateSymlink {
        /// Symlink path that could not be created.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A shim could not be removed.
    #[error("failed to remove shim {path}: {source}")]
    RemoveShim {
        /// Shim path that could not be removed.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The arbitraitor binary path must be absolute so shims resolve correctly
    /// regardless of the caller's working directory.
    #[error("arbitraitor binary path must be absolute: {0}")]
    RelativeArbitraitorPath(PathBuf),
}

/// Installs PATH shims for the specified wrapper targets.
///
/// Each shim is either a minimal `exec`-based shell script or a symlink (per
/// [`ShimConfig::use_symlinks`]) that routes the invocation through
/// `arbitraitor fetch`.
///
/// # Errors
///
/// Returns [`ShimError`] if the shim directory cannot be created, a shim file
/// cannot be written, or `arbitraitor_binary` is not absolute.
pub fn install_shims(
    config: &ShimConfig,
    targets: &[WrapperTarget],
    arbitraitor_binary: &Path,
) -> Result<Vec<PathBuf>, ShimError> {
    if !arbitraitor_binary.is_absolute() {
        return Err(ShimError::RelativeArbitraitorPath(
            arbitraitor_binary.to_path_buf(),
        ));
    }

    std::fs::create_dir_all(&config.shim_dir).map_err(|source| ShimError::CreateShimDir {
        path: config.shim_dir.clone(),
        source,
    })?;

    let mut installed = Vec::with_capacity(targets.len());
    for &target in targets {
        let shim_path = config.shim_dir.join(target.binary_name());
        if config.use_symlinks {
            install_symlink(&shim_path, arbitraitor_binary)?;
        } else {
            install_script(&shim_path, target, arbitraitor_binary)?;
        }
        installed.push(shim_path);
    }
    Ok(installed)
}

/// Removes previously installed shims for the given targets.
///
/// Missing shims are skipped silently — uninstall is idempotent. Files that are
/// neither Arbitraitor scripts nor symlinks are left untouched.
///
/// # Errors
///
/// Returns [`ShimError`] if an existing shim cannot be removed.
pub fn uninstall_shims(config: &ShimConfig, targets: &[WrapperTarget]) -> Result<u32, ShimError> {
    let mut removed = 0u32;
    for &target in targets {
        let shim_path = config.shim_dir.join(target.binary_name());
        match detect_state(&shim_path, target) {
            ShimState::Script | ShimState::Symlink => {
                std::fs::remove_file(&shim_path).map_err(|source| ShimError::RemoveShim {
                    path: shim_path,
                    source,
                })?;
                removed += 1;
            }
            ShimState::NotInstalled | ShimState::ForeignFile => {}
        }
    }
    Ok(removed)
}

/// Checks whether shims are currently installed for the given targets.
///
/// Never errors — every target gets a [`ShimStatus`] describing what (if
/// anything) occupies its slot.
#[must_use]
pub fn check_shims(config: &ShimConfig, targets: &[WrapperTarget]) -> Vec<ShimStatus> {
    targets
        .iter()
        .map(|&target| {
            let path = config.shim_dir.join(target.binary_name());
            ShimStatus {
                target,
                state: detect_state(&path, target),
                path,
            }
        })
        .collect()
}

/// Generates a single shell alias line for `.bashrc` / `.zshrc`.
///
/// The path is single-quoted so spaces and shell metacharacters are preserved
/// literally.
#[must_use]
pub fn generate_alias(target: WrapperTarget, arbitraitor_binary: &Path) -> String {
    let quoted = shell_single_quote(&arbitraitor_binary.to_string_lossy());
    format!(
        "alias {name}='{quoted} {sub}'\n",
        name = target.binary_name(),
        sub = target.arbitraitor_subcommand(),
    )
}

/// Generates the complete shell init snippet for all targets.
///
/// The snippet exports the canonical `$HOME/.arbitraitor/shims` directory on
/// `PATH` so installed shims are found ahead of the real binaries.
#[must_use]
pub fn generate_shell_init(arbitraitor_binary: &Path, targets: &[WrapperTarget]) -> String {
    let names: Vec<&str> = targets.iter().map(WrapperTarget::binary_name).collect();
    let list = if names.is_empty() {
        "curl and wget".to_owned()
    } else {
        names.join(" and ")
    };
    format!(
        "# Arbitraitor wrappers — add to ~/.bashrc or ~/.zshrc\n\
         # Routes {list} through the inspection pipeline via {binary}\n\
         export PATH=\"$HOME/.arbitraitor/shims:$PATH\"\n",
        binary = arbitraitor_binary.display(),
    )
}

// --- internals ---------------------------------------------------------------

fn install_script(
    shim_path: &Path,
    target: WrapperTarget,
    arbitraitor_binary: &Path,
) -> Result<(), ShimError> {
    let quoted = shell_single_quote(&arbitraitor_binary.to_string_lossy());
    let content = format!(
        "#!/bin/sh\n\
         # {marker}{name} — routes through inspection pipeline\n\
         exec {quoted} {sub} --tool {name} -- \"$@\"\n",
        marker = SHIM_MARKER,
        name = target.binary_name(),
        sub = target.arbitraitor_subcommand(),
    );
    // Remove an existing symlink or file first so we atomically replace.
    let _ = std::fs::remove_file(shim_path);
    std::fs::write(shim_path, content).map_err(|source| ShimError::WriteShim {
        path: shim_path.to_path_buf(),
        source,
    })?;
    set_executable(shim_path).map_err(|source| ShimError::WriteShim {
        path: shim_path.to_path_buf(),
        source,
    })
}

fn install_symlink(shim_path: &Path, arbitraitor_binary: &Path) -> Result<(), ShimError> {
    // Remove an existing entry so the new symlink replaces it cleanly.
    let _ = std::fs::remove_file(shim_path);
    create_symlink(arbitraitor_binary, shim_path).map_err(|source| ShimError::CreateSymlink {
        path: shim_path.to_path_buf(),
        source,
    })
}

fn detect_state(path: &Path, target: WrapperTarget) -> ShimState {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return ShimState::NotInstalled;
    };
    if metadata.file_type().is_symlink() {
        return ShimState::Symlink;
    }
    if metadata.is_file() {
        let marker = format!("{SHIM_MARKER}{name}", name = target.binary_name());
        return match std::fs::read_to_string(path) {
            Ok(content) if content.contains(&marker) => ShimState::Script,
            _ => ShimState::ForeignFile,
        };
    }
    ShimState::ForeignFile
}

/// Single-quotes a string for safe embedding in POSIX shell scripts.
///
/// Any embedded single quote is escaped via the standard `'\\''` sequence.
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

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(unix)]
fn set_executable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
fn create_symlink(_target: &Path, _link: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "symlinks are only supported on Unix",
    ))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RAII temp directory that cleans up on drop, even on panic.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Result<Self, std::io::Error> {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let path = std::env::temp_dir().join(format!(
                "arb-wrapper-shim-{label}-{}-{nanos}",
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

    fn script_config(dir: &Path) -> ShimConfig {
        ShimConfig {
            shim_dir: dir.to_path_buf(),
            use_symlinks: false,
        }
    }

    fn symlink_config(dir: &Path) -> ShimConfig {
        ShimConfig {
            shim_dir: dir.to_path_buf(),
            use_symlinks: true,
        }
    }

    const ARB_PATH: &str = "/usr/local/bin/arbitraitor";

    #[test]
    fn wrapper_target_binary_names() {
        assert_eq!(WrapperTarget::Curl.binary_name(), "curl");
        assert_eq!(WrapperTarget::Wget.binary_name(), "wget");
    }

    #[test]
    fn wrapper_target_subcommands_are_fetch() {
        assert_eq!(WrapperTarget::Curl.arbitraitor_subcommand(), "fetch");
        assert_eq!(WrapperTarget::Wget.arbitraitor_subcommand(), "fetch");
    }

    #[test]
    fn wrapper_target_from_binary_name_round_trips() {
        for &target in WrapperTarget::ALL {
            assert_eq!(
                WrapperTarget::from_binary_name(target.binary_name()),
                Some(target),
            );
        }
        assert_eq!(WrapperTarget::from_binary_name("unknown"), None);
    }

    #[test]
    fn install_creates_shim_scripts() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new("install-scripts")?;
        let config = script_config(dir.path());
        let arb = Path::new(ARB_PATH);

        let installed = install_shims(&config, WrapperTarget::ALL, arb)?;

        assert_eq!(installed.len(), 2);
        for &target in WrapperTarget::ALL {
            let shim = dir.path().join(target.binary_name());
            assert!(shim.is_file(), "shim missing for {}", target.binary_name());
        }
        Ok(())
    }

    #[test]
    fn shim_script_invokes_arbitraitor() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new("script-content")?;
        let config = script_config(dir.path());
        let arb = Path::new(ARB_PATH);

        install_shims(&config, &[WrapperTarget::Curl], arb)?;
        let content = std::fs::read_to_string(dir.path().join("curl"))?;

        assert!(content.starts_with("#!/bin/sh\n"));
        assert!(content.contains("Arbitraitor shim for curl"));
        assert!(content.contains(ARB_PATH));
        assert!(content.contains("exec "));
        assert!(content.contains("\"$@\""));
        assert!(content.contains(" fetch "));
        Ok(())
    }

    #[test]
    fn install_scripts_are_executable() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new("script-exec")?;
        let config = script_config(dir.path());
        let arb = Path::new(ARB_PATH);

        install_shims(&config, &[WrapperTarget::Wget], arb)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("wget"))?
                .permissions()
                .mode();
            assert!(mode & 0o111 != 0, "wget shim should be executable");
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn install_with_symlinks_creates_symlinks() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new("symlinks")?;
        let config = symlink_config(dir.path());

        // Use a dummy binary inside the temp dir so we have write access.
        let arb = dir.path().join("arbitraitor");
        std::fs::write(&arb, "#!/bin/sh\n")?;

        let installed = install_shims(&config, WrapperTarget::ALL, &arb)?;
        assert_eq!(installed.len(), 2);

        let curl_link = std::fs::symlink_metadata(dir.path().join("curl"))?;
        assert!(
            curl_link.file_type().is_symlink(),
            "curl should be a symlink",
        );

        let read = std::fs::read_link(dir.path().join("curl"))?;
        assert_eq!(read, arb);
        Ok(())
    }

    #[test]
    fn install_rejects_relative_arbitraitor_path() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new("relative-reject")?;
        let config = script_config(dir.path());

        let result = install_shims(&config, &[WrapperTarget::Curl], Path::new("arbitraitor"));
        assert!(matches!(result, Err(ShimError::RelativeArbitraitorPath(_)),));
        Ok(())
    }

    #[test]
    fn install_overwrites_existing_shim() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new("overwrite")?;
        let config = script_config(dir.path());
        let arb = Path::new(ARB_PATH);

        // Pre-place a stale foreign file at the shim path.
        std::fs::write(dir.path().join("curl"), "stale")?;
        install_shims(&config, &[WrapperTarget::Curl], arb)?;

        let content = std::fs::read_to_string(dir.path().join("curl"))?;
        assert!(content.contains("Arbitraitor shim for curl"));
        assert!(!content.contains("stale"));
        Ok(())
    }

    #[test]
    fn uninstall_removes_shims() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new("uninstall")?;
        let config = script_config(dir.path());
        let arb = Path::new(ARB_PATH);

        install_shims(&config, WrapperTarget::ALL, arb)?;
        let removed = uninstall_shims(&config, WrapperTarget::ALL)?;
        assert_eq!(removed, 2);
        assert!(!dir.path().join("curl").exists());
        assert!(!dir.path().join("wget").exists());
        Ok(())
    }

    #[test]
    fn uninstall_is_idempotent_for_missing_shims() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new("uninstall-idempotent")?;
        let config = script_config(dir.path());
        let removed = uninstall_shims(&config, WrapperTarget::ALL)?;
        assert_eq!(removed, 0);
        Ok(())
    }

    #[test]
    fn uninstall_preserves_foreign_files() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new("uninstall-foreign")?;
        let config = script_config(dir.path());
        let foreign = dir.path().join("curl");
        std::fs::write(&foreign, "user script")?;

        let removed = uninstall_shims(&config, &[WrapperTarget::Curl])?;
        assert_eq!(removed, 0);
        assert_eq!(std::fs::read_to_string(&foreign)?, "user script");
        Ok(())
    }

    #[test]
    fn check_shims_detects_installed_script() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new("check-installed")?;
        let config = script_config(dir.path());
        let arb = Path::new(ARB_PATH);

        install_shims(&config, &[WrapperTarget::Curl], arb)?;
        let statuses = check_shims(&config, &[WrapperTarget::Curl]);
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].target, WrapperTarget::Curl);
        assert_eq!(statuses[0].state, ShimState::Script);
        assert_eq!(statuses[0].path, dir.path().join("curl"));
        Ok(())
    }

    #[test]
    fn check_shims_detects_missing() {
        let config = ShimConfig {
            shim_dir: PathBuf::from("/nonexistent/arbitraitor-test"),
            use_symlinks: false,
        };
        let statuses = check_shims(&config, WrapperTarget::ALL);
        assert_eq!(statuses.len(), 2);
        assert!(statuses.iter().all(|s| s.state == ShimState::NotInstalled));
    }

    #[test]
    fn check_shims_detects_foreign_file() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new("check-foreign")?;
        let config = script_config(dir.path());
        std::fs::write(dir.path().join("curl"), "not our shim")?;

        let statuses = check_shims(&config, &[WrapperTarget::Curl]);
        assert_eq!(statuses[0].state, ShimState::ForeignFile);
        Ok(())
    }

    #[test]
    fn generate_alias_produces_valid_bash() {
        let alias = generate_alias(WrapperTarget::Curl, Path::new("/usr/bin/arbitraitor"));
        assert!(
            alias.starts_with("alias curl='"),
            "alias should start with correct name and opening quote",
        );
        assert!(alias.ends_with("'\n"));
        assert!(alias.contains("/usr/bin/arbitraitor"));
        assert!(alias.contains("fetch"));
    }

    #[test]
    fn generate_alias_quotes_paths_with_spaces() {
        let alias = generate_alias(WrapperTarget::Wget, Path::new("/opt/my apps/arbitraitor"));
        // The path must be safely single-quoted.
        assert!(alias.contains("'/opt/my apps/arbitraitor'"));
    }

    #[test]
    fn generate_alias_escapes_embedded_single_quotes() {
        let alias = generate_alias(WrapperTarget::Curl, Path::new("/it's/arb"));
        // POSIX escaping: close quote, escaped quote, reopen.
        assert!(alias.contains("'\\''"));
    }

    #[test]
    fn generate_shell_init_includes_path_export() {
        let snippet = generate_shell_init(Path::new("/usr/bin/arbitraitor"), WrapperTarget::ALL);
        assert!(snippet.contains("export PATH="));
        assert!(snippet.contains("$HOME/.arbitraitor/shims"));
        assert!(snippet.contains("$PATH"));
        assert!(snippet.contains("/usr/bin/arbitraitor"));
    }

    #[test]
    fn generate_shell_init_handles_empty_targets() {
        let snippet = generate_shell_init(Path::new("/usr/bin/arbitraitor"), &[]);
        assert!(snippet.contains("export PATH="));
        assert!(snippet.contains("curl and wget"));
    }

    #[test]
    fn generate_shell_init_lists_individual_targets() {
        let snippet =
            generate_shell_init(Path::new("/usr/bin/arbitraitor"), &[WrapperTarget::Curl]);
        assert!(snippet.contains("curl"));
        assert!(!snippet.contains("curl and wget"));
    }
}
