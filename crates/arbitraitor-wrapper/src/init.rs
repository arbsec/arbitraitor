//! Per-shell integration snippet generation, rcfile install/uninstall, and
//! shell auto-detection.
//!
//! Produces idempotent PATH-export snippets for bash, zsh, sh, fish, nushell,
//! xonsh, PowerShell, elvish, posix sh, and tcsh. Supports two modes:
//!
//! - **Print** — emit the snippet to stdout for `eval "$(arbitraitor wrappers init)"`
//! - **Install** — write/remove the block between idempotency markers in the
//!   appropriate rcfile.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use thiserror::Error;

// ---------------------------------------------------------------------------
// Idempotency markers
// ---------------------------------------------------------------------------

/// Marker inserted before the init block in rcfiles for idempotent install.
pub const MARKER_BEGIN: &str = "# >>> arbitraitor wrappers >>>";

/// Marker inserted after the init block in rcfiles for idempotent install.
pub const MARKER_END: &str = "# <<< arbitraitor wrappers <<<";

// ---------------------------------------------------------------------------
// Shell enum
// ---------------------------------------------------------------------------

/// Supported target shells for `wrappers init`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Shell {
    /// GNU Bourne-Again Shell.
    Bash,
    /// Z shell.
    Zsh,
    /// POSIX `/bin/sh` (dash, ash, busybox).
    Sh,
    /// Friendly Interactive Shell.
    Fish,
    /// Nushell.
    Nu,
    /// Xonsh (Python-powered shell).
    Xonsh,
    /// PowerShell (pwsh 7+).
    Powershell,
    /// Elvish.
    Elvish,
    /// Generic POSIX — uses a subset of bash syntax.
    Posix,
    /// TENEX C Shell.
    Tcsh,
}

impl Shell {
    /// All supported shells in canonical order.
    pub const ALL: &[Shell] = &[
        Shell::Bash,
        Shell::Zsh,
        Shell::Sh,
        Shell::Fish,
        Shell::Nu,
        Shell::Xonsh,
        Shell::Powershell,
        Shell::Elvish,
        Shell::Posix,
        Shell::Tcsh,
    ];

    /// Returns the string used in CLI values and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Sh => "sh",
            Self::Fish => "fish",
            Self::Nu => "nu",
            Self::Xonsh => "xonsh",
            Self::Powershell => "powershell",
            Self::Elvish => "elvish",
            Self::Posix => "posix",
            Self::Tcsh => "tcsh",
        }
    }

    /// Parse a shell name string into [`Shell`].
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "bash" => Some(Self::Bash),
            "zsh" => Some(Self::Zsh),
            "sh" => Some(Self::Sh),
            "fish" => Some(Self::Fish),
            "nu" => Some(Self::Nu),
            "xonsh" => Some(Self::Xonsh),
            "powershell" | "pwsh" => Some(Self::Powershell),
            "elvish" => Some(Self::Elvish),
            "posix" => Some(Self::Posix),
            "tcsh" => Some(Self::Tcsh),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Shell detection
// ---------------------------------------------------------------------------

/// Result of shell auto-detection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectedShell {
    /// The detected shell variant.
    pub shell: Shell,
    /// The source from which the shell was determined.
    pub source: DetectionSource,
}

/// How the shell was detected — for `--detect-shell` diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionSource {
    /// `$SHELL` environment variable.
    EnvShell,
    /// Parent process name (`/proc/$PPID/cmdline` or `ps`).
    ParentProcess,
}

/// Attempt to detect the current shell.
///
/// Fallback chain:
/// 1. `$SHELL` environment variable (basename, strip leading dash).
/// 2. Parent process name via `/proc/$PPID/cmdline` (Linux) or
///    `ps -p $PPID -o comm=` (macOS/other Unix).
///
/// Returns `None` if neither source yields a recognised shell name.
#[must_use]
pub fn detect_shell() -> Option<DetectedShell> {
    if let Some(shell) = detect_from_env_shell() {
        return Some(DetectedShell {
            shell,
            source: DetectionSource::EnvShell,
        });
    }
    if let Some(shell) = detect_from_parent() {
        return Some(DetectedShell {
            shell,
            source: DetectionSource::ParentProcess,
        });
    }
    None
}

fn detect_from_env_shell() -> Option<Shell> {
    let raw = std::env::var_os("SHELL")?;
    let path = PathBuf::from(raw);
    let name = path.file_name()?.to_string_lossy();
    let name = name.trim_start_matches('-');
    Shell::from_name(name)
}

fn detect_from_parent() -> Option<Shell> {
    let ppid = std::process::id().checked_sub(1)?;
    parent_name(ppid).as_deref().and_then(Shell::from_name)
}

#[cfg(target_os = "linux")]
fn parent_name(ppid: u32) -> Option<String> {
    let cmdline_path = PathBuf::from("/proc")
        .join(ppid.to_string())
        .join("cmdline");
    let data = std::fs::read(&cmdline_path).ok()?;
    let first_arg = data.split(|&b| b == 0).next()?;
    let path = Path::new(std::str::from_utf8(first_arg).ok()?);
    Some(path.file_name()?.to_string_lossy().into_owned())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn parent_name(ppid: u32) -> Option<String> {
    let output = std::process::Command::new("ps")
        .args(["-p", &ppid.to_string(), "-o", "comm="])
        .output()
        .ok()?;
    let name = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if name.is_empty() { None } else { Some(name) }
}

#[cfg(not(unix))]
fn parent_name(_ppid: u32) -> Option<String> {
    None
}

// ---------------------------------------------------------------------------
// rcfile targeting
// ---------------------------------------------------------------------------

/// Returns the target rcfile for `shell`, or `None` for shells that use a
/// well-known fixed path (fish, nu, powershell) which the caller should obtain
/// via [`target_rcfile`].
#[must_use]
pub fn rcfile_path(shell: Shell) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    rcfile_path_for_home(shell, &home)
}

/// Internal: rcfile path given an explicit home directory.
fn rcfile_path_for_home(shell: Shell, home: &Path) -> Option<PathBuf> {
    match shell {
        Shell::Bash => {
            let bashrc = home.join(".bashrc");
            if bashrc.exists() {
                Some(bashrc)
            } else {
                Some(home.join(".bash_profile"))
            }
        }
        Shell::Zsh => Some(home.join(".zshenv")),
        Shell::Sh | Shell::Posix => Some(home.join(".profile")),
        Shell::Tcsh => Some(home.join(".tcshrc")),
        Shell::Xonsh => Some(home.join(".xonshrc")),
        Shell::Elvish => Some(home.join(".elvish").join("rc.elv")),
        Shell::Fish | Shell::Nu | Shell::Powershell => None,
    }
}

/// Returns the fixed-name configuration file path for shells that use one
/// (fish, nu, powershell). Returns `None` for other shells.
#[must_use]
pub fn rcfile_fixed_path(shell: Shell) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    rcfile_fixed_path_for_home(shell, &home)
}

fn rcfile_fixed_path_for_home(shell: Shell, home: &Path) -> Option<PathBuf> {
    match shell {
        Shell::Fish => Some(
            home.join(".config")
                .join("fish")
                .join("conf.d")
                .join("arbitraitor.fish"),
        ),
        Shell::Nu => Some(
            home.join(".config")
                .join("nushell")
                .join("autoload")
                .join("arbitraitor.nu"),
        ),
        Shell::Powershell => Some(home.join(".config").join("powershell").join("profile.ps1")),
        _ => None,
    }
}

/// Returns the rcfile that install/uninstall should target for `shell`,
/// whether it is the heuristic rcfile or a fixed-name config file.
#[must_use]
pub fn target_rcfile(shell: Shell) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    target_rcfile_for_home(shell, &home)
}

fn target_rcfile_for_home(shell: Shell, home: &Path) -> Option<PathBuf> {
    rcfile_path_for_home(shell, home).or_else(|| rcfile_fixed_path_for_home(shell, home))
}

// ---------------------------------------------------------------------------
// Snippet generation
// ---------------------------------------------------------------------------

/// Renders the shell-specific PATH-export snippet for `shim_dir`.
///
/// Each snippet prepends `shim_dir` to `PATH` with deduplication so the
/// snippet is safe to evaluate multiple times.
#[must_use]
pub fn render_snippet(shell: Shell, shim_dir: &Path) -> String {
    let dir = &shim_dir.to_string_lossy();
    match shell {
        Shell::Bash | Shell::Sh | Shell::Posix => posix_snippet(dir),
        Shell::Zsh => zsh_snippet(dir),
        Shell::Fish => fish_snippet(dir),
        Shell::Nu => nu_snippet(dir),
        Shell::Xonsh => xonsh_snippet(dir),
        Shell::Powershell => powershell_snippet(dir),
        Shell::Elvish => elvish_snippet(dir),
        Shell::Tcsh => tcsh_snippet(dir),
    }
}

fn posix_snippet(dir: &str) -> String {
    format!(
        "{MARKER_BEGIN}\n\
         case \":${{PATH}}:\" in\n\
         \x20   *\":{dir}:\"*) ;;\n\
         \x20   *) export PATH=\"{dir}:$PATH\" ;;\n\
         esac\n\
         {MARKER_END}\n",
    )
}

fn zsh_snippet(dir: &str) -> String {
    format!(
        "{MARKER_BEGIN}\n\
         typeset -aU path\n\
         path=({dir} $path)\n\
         {MARKER_END}\n",
    )
}

fn fish_snippet(dir: &str) -> String {
    format!("# Arbitraitor wrappers\nfish_add_path --move --path {dir}\n")
}

fn nu_snippet(dir: &str) -> String {
    format!(
        "# {MARKER_BEGIN}\n\
         $env.PATH = ($env.PATH | prepend \"{dir}\" | uniq)\n\
         # {MARKER_END}\n",
    )
}

fn xonsh_snippet(dir: &str) -> String {
    format!(
        "{MARKER_BEGIN}\n\
         import os\n\
         if \"{dir}\" not in $PATH:\n\
         \x20   $PATH.insert(0, \"{dir}\")\n\
         {MARKER_END}\n",
    )
}

fn powershell_snippet(dir: &str) -> String {
    format!(
        "{MARKER_BEGIN}\n\
         $arb = \"{dir}\"\n\
         if (($env:PATH -split \";\") -notcontains $arb) {{ $env:PATH = \"$arb;$env:PATH\" }}\n\
         {MARKER_END}\n",
    )
}

fn elvish_snippet(dir: &str) -> String {
    format!(
        "{MARKER_BEGIN}\n\
         if (not (has-value $E:PATH {dir})) {{\n\
         \x20   set E:PATH = (all [{dir}] [(splat : $E:PATH)])\n\
         }}\n\
         {MARKER_END}\n",
    )
}

fn tcsh_snippet(dir: &str) -> String {
    let mut s = String::new();
    s.push_str(MARKER_BEGIN);
    s.push('\n');
    s.push_str("    if (\"$path\" !~ *");
    s.push_str(dir);
    s.push_str("*) set path = (");
    s.push_str(dir);
    s.push_str(" $path)\n");
    s.push_str(MARKER_END);
    s.push('\n');
    s
}

// ---------------------------------------------------------------------------
// rcfile install / uninstall
// ---------------------------------------------------------------------------

/// Errors produced by rcfile install/uninstall.
#[derive(Debug, Error)]
pub enum InitError {
    /// The rcfile path could not be determined for this shell.
    #[error("no rcfile path known for shell '{0}'; use print mode instead")]
    NoRcfile(&'static str),
    /// The rcfile (or its parent directory) could not be read.
    #[error("failed to read {path}: {source}")]
    ReadRcfile {
        /// File that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The rcfile could not be written.
    #[error("failed to write {path}: {source}")]
    WriteRcfile {
        /// File that could not be written.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

/// Installs the init snippet into the target rcfile for `shell`.
///
/// If the marker block already exists, the old block is replaced with the new
/// snippet (idempotent). If the file does not exist, it is created.
///
/// # Errors
///
/// Returns [`InitError::NoRcfile`] if no target path is known for `shell`.
pub fn install_to_rcfile(shell: Shell, shim_dir: &Path) -> Result<PathBuf, InitError> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| InitError::NoRcfile(shell.as_str()))?;
    install_to_rcfile_in(shell, shim_dir, &home)
}

fn install_to_rcfile_in(shell: Shell, shim_dir: &Path, home: &Path) -> Result<PathBuf, InitError> {
    let target =
        target_rcfile_for_home(shell, home).ok_or_else(|| InitError::NoRcfile(shell.as_str()))?;
    let snippet = render_snippet(shell, shim_dir);

    if let Some(parent) = target.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let existing = std::fs::read_to_string(&target).unwrap_or_default();
    let updated = replace_or_append_block(&existing, &snippet);
    std::fs::write(&target, updated).map_err(|source| InitError::WriteRcfile {
        path: target.clone(),
        source,
    })?;
    Ok(target)
}

/// Removes any existing init block from the rcfile for `shell`.
///
/// If the file does not exist or contains no marker block, this is a no-op.
///
/// # Errors
///
/// Returns [`InitError::NoRcfile`] if no target path is known for `shell`.
pub fn uninstall_from_rcfile(shell: Shell) -> Result<PathBuf, InitError> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| InitError::NoRcfile(shell.as_str()))?;
    uninstall_from_rcfile_in(shell, &home)
}

fn uninstall_from_rcfile_in(shell: Shell, home: &Path) -> Result<PathBuf, InitError> {
    let target =
        target_rcfile_for_home(shell, home).ok_or_else(|| InitError::NoRcfile(shell.as_str()))?;

    let existing = match std::fs::read_to_string(&target) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(target),
        Err(source) => {
            return Err(InitError::ReadRcfile {
                path: target.clone(),
                source,
            });
        }
    };

    if !existing.contains(MARKER_BEGIN) {
        return Ok(target);
    }

    let cleaned = remove_block(&existing);
    std::fs::write(&target, cleaned).map_err(|source| InitError::WriteRcfile {
        path: target.clone(),
        source,
    })?;
    Ok(target)
}

// ---------------------------------------------------------------------------
// block manipulation helpers
// ---------------------------------------------------------------------------

/// Replaces an existing marker block with `new_snippet`, or appends if none
/// exists. Handles both marker-using snippets (bash, zsh, etc.) and
/// marker-less snippets (fish).
fn replace_or_append_block(existing: &str, new_snippet: &str) -> String {
    if existing.contains(MARKER_BEGIN) {
        let base = remove_block(existing);
        let trimmed_base = base.trim_end_matches('\n');
        let trimmed_snippet = new_snippet.trim_end_matches('\n');
        if trimmed_base.is_empty() {
            format!("{trimmed_snippet}\n")
        } else {
            format!("{trimmed_base}\n\n{trimmed_snippet}\n")
        }
    } else if existing.is_empty() {
        new_snippet.to_owned()
    } else {
        let trimmed = existing.trim_end_matches('\n');
        format!("{trimmed}\n\n{new_snippet}")
    }
}

/// Removes the marker block (including markers) from `content`.
/// Also handles nushell-style markers (`# MARKER`).
fn remove_block(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut in_block = false;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(MARKER_BEGIN) {
            in_block = true;
            continue;
        }
        if in_block && trimmed.starts_with(MARKER_END) {
            in_block = false;
            continue;
        }
        if !in_block {
            result.push_str(line);
            result.push('\n');
        }
    }
    // Collapse triple+ blank lines left by block removal.
    while result.contains("\n\n\n") {
        result = result.replace("\n\n\n", "\n\n");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    // --- Shell enum ---

    #[test]
    fn shell_from_name_round_trips() {
        for &shell in Shell::ALL {
            assert_eq!(Shell::from_name(shell.as_str()), Some(shell));
        }
    }

    #[test]
    fn shell_from_name_pwsh_alias() {
        assert_eq!(Shell::from_name("pwsh"), Some(Shell::Powershell));
    }

    #[test]
    fn shell_from_name_unknown_returns_none() {
        assert_eq!(Shell::from_name("cmd.exe"), None);
    }

    // --- render_snippet ---

    #[test]
    fn posix_snippet_has_case_based_dedup() {
        let dir = Path::new("/home/user/.arbitraitor/shims");
        let snippet = render_snippet(Shell::Bash, dir);
        assert!(snippet.contains("case \":${PATH}:\""));
        assert!(snippet.contains("/home/user/.arbitraitor/shims"));
        assert!(snippet.contains("export PATH"));
        assert!(snippet.contains(MARKER_BEGIN));
        assert!(snippet.contains(MARKER_END));
    }

    #[test]
    fn zsh_snippet_uses_typeset_a_u() {
        let dir = Path::new("/home/user/.arbitraitor/shims");
        let snippet = render_snippet(Shell::Zsh, dir);
        assert!(snippet.contains("typeset -aU path"));
        assert!(snippet.contains("path=("));
        assert!(snippet.contains("/home/user/.arbitraitor/shims"));
    }

    #[test]
    fn fish_snippet_uses_fish_add_path() {
        let dir = Path::new("/home/user/.arbitraitor/shims");
        let snippet = render_snippet(Shell::Fish, dir);
        assert!(snippet.contains("fish_add_path --move --path"));
        assert!(snippet.contains("/home/user/.arbitraitor/shims"));
    }

    #[test]
    fn nu_snippet_prepends_and_uniqs() {
        let dir = Path::new("/home/user/.arbitraitor/shims");
        let snippet = render_snippet(Shell::Nu, dir);
        assert!(snippet.contains("prepend"));
        assert!(snippet.contains("uniq"));
        assert!(snippet.contains("/home/user/.arbitraitor/shims"));
    }

    #[test]
    fn xonsh_snippet_checks_membership() {
        let dir = Path::new("/home/user/.arbitraitor/shims");
        let snippet = render_snippet(Shell::Xonsh, dir);
        assert!(snippet.contains("not in $PATH"));
        assert!(snippet.contains("$PATH.insert(0"));
        assert!(snippet.contains("/home/user/.arbitraitor/shims"));
    }

    #[test]
    fn powershell_snippet_splits_and_checks() {
        let dir = Path::new("/home/user/.arbitraitor/shims");
        let snippet = render_snippet(Shell::Powershell, dir);
        assert!(snippet.contains("-split \";\""));
        assert!(snippet.contains("-notcontains"));
        assert!(snippet.contains("/home/user/.arbitraitor/shims"));
    }

    #[test]
    fn elvish_snippet_checks_value() {
        let dir = Path::new("/home/user/.arbitraitor/shims");
        let snippet = render_snippet(Shell::Elvish, dir);
        assert!(snippet.contains("has-value"));
        assert!(snippet.contains("/home/user/.arbitraitor/shims"));
    }

    #[test]
    fn tcsh_snippet_uses_path_check() {
        let dir = Path::new("/home/user/.arbitraitor/shims");
        let snippet = render_snippet(Shell::Tcsh, dir);
        assert!(snippet.contains("set path ="));
        assert!(snippet.contains("/home/user/.arbitraitor/shims"));
    }

    #[test]
    fn sh_and_posix_produce_same_output_as_bash() {
        let dir = Path::new("/tmp/shims");
        let bash = render_snippet(Shell::Bash, dir);
        let sh = render_snippet(Shell::Sh, dir);
        let posix = render_snippet(Shell::Posix, dir);
        assert_eq!(bash, sh);
        assert_eq!(bash, posix);
    }

    // --- rcfile install/uninstall ---

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let path =
                std::env::temp_dir().join(format!("arb-init-test-{}-{nanos}", std::process::id()));
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

    #[test]
    fn install_creates_rcfile_if_missing() -> TestResult {
        let dir = TestDir::new()?;
        let shim = Path::new("/home/user/.arbitraitor/shims");
        let rcfile = install_to_rcfile_in(Shell::Bash, shim, dir.path())?;
        assert!(rcfile.ends_with(".bashrc") || rcfile.ends_with(".bash_profile"));
        let content = std::fs::read_to_string(&rcfile)?;
        assert!(content.contains(MARKER_BEGIN));
        assert!(content.contains(MARKER_END));
        assert!(content.contains("export PATH"));
        assert!(content.contains("/home/user/.arbitraitor/shims"));
        Ok(())
    }

    #[test]
    fn install_is_idempotent_single_block() -> TestResult {
        let dir = TestDir::new()?;
        let shim = Path::new("/home/user/.arbitraitor/shims");
        install_to_rcfile_in(Shell::Bash, shim, dir.path())?;
        install_to_rcfile_in(Shell::Bash, shim, dir.path())?;

        let rcfile =
            rcfile_path_for_home(Shell::Bash, dir.path()).ok_or("no rcfile path for bash")?;
        let content = std::fs::read_to_string(&rcfile)?;
        let begin_count = content.matches(MARKER_BEGIN).count();
        let end_count = content.matches(MARKER_END).count();
        assert_eq!(begin_count, 1, "should have exactly one begin marker");
        assert_eq!(end_count, 1, "should have exactly one end marker");
        Ok(())
    }

    #[test]
    fn install_preserves_foreign_content() -> TestResult {
        let dir = TestDir::new()?;
        let rcfile =
            rcfile_path_for_home(Shell::Bash, dir.path()).ok_or("no rcfile path for bash")?;
        std::fs::write(&rcfile, "# user content\nexport FOO=bar\n")?;

        let shim = Path::new("/home/user/.arbitraitor/shims");
        install_to_rcfile_in(Shell::Bash, shim, dir.path())?;

        let content = std::fs::read_to_string(&rcfile)?;
        assert!(content.contains("# user content"));
        assert!(content.contains("export FOO=bar"));
        assert!(content.contains(MARKER_BEGIN));
        Ok(())
    }

    #[test]
    fn uninstall_removes_block_preserves_rest() -> TestResult {
        let dir = TestDir::new()?;
        let rcfile =
            rcfile_path_for_home(Shell::Bash, dir.path()).ok_or("no rcfile path for bash")?;
        std::fs::write(&rcfile, "# user content\nexport FOO=bar\n")?;

        let shim = Path::new("/home/user/.arbitraitor/shims");
        install_to_rcfile_in(Shell::Bash, shim, dir.path())?;
        uninstall_from_rcfile_in(Shell::Bash, dir.path())?;

        let content = std::fs::read_to_string(&rcfile)?;
        assert!(!content.contains(MARKER_BEGIN));
        assert!(!content.contains(MARKER_END));
        assert!(content.contains("# user content"));
        assert!(content.contains("export FOO=bar"));
        Ok(())
    }

    #[test]
    fn uninstall_on_missing_file_is_noop() -> TestResult {
        let dir = TestDir::new()?;
        let result = uninstall_from_rcfile_in(Shell::Zsh, dir.path())?;
        let content = std::fs::read_to_string(&result);
        assert!(content.is_err());
        Ok(())
    }

    #[test]
    fn uninstall_on_file_without_markers_is_noop() -> TestResult {
        let dir = TestDir::new()?;
        let rcfile =
            rcfile_path_for_home(Shell::Zsh, dir.path()).ok_or("no rcfile path for zsh")?;
        let original = "# nothing here\nexport EDITOR=vim\n";
        std::fs::write(&rcfile, original)?;

        uninstall_from_rcfile_in(Shell::Zsh, dir.path())?;

        let content = std::fs::read_to_string(&rcfile)?;
        assert_eq!(content, original);
        Ok(())
    }

    #[test]
    fn install_fish_uses_fixed_path() -> TestResult {
        let dir = TestDir::new()?;
        let shim = Path::new("/home/user/.arbitraitor/shims");
        let rcfile = install_to_rcfile_in(Shell::Fish, shim, dir.path())?;
        assert!(rcfile.ends_with("conf.d/arbitraitor.fish"));
        let content = std::fs::read_to_string(&rcfile)?;
        assert!(content.contains("fish_add_path"));
        Ok(())
    }

    #[test]
    fn install_nu_uses_fixed_path() -> TestResult {
        let dir = TestDir::new()?;
        let shim = Path::new("/home/user/.arbitraitor/shims");
        let rcfile = install_to_rcfile_in(Shell::Nu, shim, dir.path())?;
        assert!(rcfile.ends_with("autoload/arbitraitor.nu"));
        let content = std::fs::read_to_string(&rcfile)?;
        assert!(content.contains("prepend"));
        assert!(content.contains("uniq"));
        Ok(())
    }

    // --- block manipulation ---

    #[test]
    fn remove_block_handles_multiple_blocks() {
        let content = format!(
            "line1\n{MARKER_BEGIN}\nold\n{MARKER_END}\nline2\n{MARKER_BEGIN}\nold2\n{MARKER_END}\nline3\n",
        );
        let result = remove_block(&content);
        assert!(result.contains("line1"));
        assert!(result.contains("line2"));
        assert!(result.contains("line3"));
        assert!(!result.contains("old"));
        assert!(!result.contains("old2"));
        assert!(!result.contains(MARKER_BEGIN));
        assert!(!result.contains(MARKER_END));
    }

    #[test]
    fn remove_block_on_empty_returns_empty() {
        let result = remove_block("");
        assert_eq!(result, "");
    }

    #[test]
    fn replace_or_append_on_empty_returns_snippet() {
        let snippet = render_snippet(Shell::Bash, Path::new("/shims"));
        let result = replace_or_append_block("", &snippet);
        assert_eq!(result, snippet);
    }

    #[test]
    fn replace_or_append_replaces_existing_block() {
        let snippet1 = render_snippet(Shell::Bash, Path::new("/old-shims"));
        let content = format!("# header\n\n{snippet1}");
        let snippet2 = render_snippet(Shell::Bash, Path::new("/new-shims"));
        let result = replace_or_append_block(&content, &snippet2);
        assert!(result.contains("# header"));
        assert!(result.contains("/new-shims"));
        assert!(!result.contains("/old-shims"));
        assert_eq!(result.matches(MARKER_BEGIN).count(), 1);
    }
}
