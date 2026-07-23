//! End-to-end CLI tests for `wrappers init --install` / `--uninstall` lifecycle.
//!
//! Spawns the `arbitraitor` binary against a temp `HOME` directory and
//! verifies the marker-block lifecycle: install → re-install (idempotent) →
//! uninstall → re-uninstall (no-op), plus dry-run, backup, multi-shell, and
//! exit-code behaviour. Closes issue #614.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Marker lines must match `arbitraitor_wrapper::init::{MARKER_BEGIN, MARKER_END}`.
const MARKER_BEGIN: &str = "# >>> arbitraitor wrappers >>>";
const MARKER_END: &str = "# <<< arbitraitor wrappers <<<";

/// Absolute shim dir under `home` — satisfies `validate_shim_dir`.
fn shim_dir(home: &Path) -> PathBuf {
    home.join(".arbitraitor").join("shims")
}

/// Bash rcfile path under `home` (matches `rcfile_path_for_home` heuristic).
fn bashrc(home: &Path) -> PathBuf {
    home.join(".bashrc")
}

/// Zsh rcfile path under `home`.
fn zshenv(home: &Path) -> PathBuf {
    home.join(".zshenv")
}

/// Backup path — matches `Path::with_extension("arbitraitor.bak")`.
fn backup_of(rcfile: &Path) -> PathBuf {
    rcfile.with_extension("arbitraitor.bak")
}

/// Builds a `wrappers init` command with `HOME` pointed at `home`.
fn init_cmd(home: &Path) -> Result<Command, Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("arbitraitor")?;
    cmd.env("HOME", home)
        .env("SHELL", "/bin/bash")
        .args(["wrappers", "init"]);
    Ok(cmd)
}

#[test]
fn install_writes_marker_block_to_bashrc() -> TestResult {
    // Given: temp HOME with an empty fixture .bashrc (ensures the bash
    // heuristic targets .bashrc rather than falling back to .bash_profile).
    let home = TempDir::new()?;
    let shim = shim_dir(home.path());
    fs::write(bashrc(home.path()), "")?;

    // When: `wrappers init bash --install --shim-dir <shim>`.
    init_cmd(home.path())?
        .args(["bash", "--install", "--shim-dir"])
        .arg(&shim)
        .assert()
        .success()
        .stdout(predicate::str::contains("installed init snippet"));

    // Then: .bashrc contains the marker block + PATH export.
    let content = fs::read_to_string(bashrc(home.path()))?;
    assert!(content.contains(MARKER_BEGIN));
    assert!(content.contains(MARKER_END));
    assert!(content.contains("export PATH"));
    assert!(content.contains(shim.to_str().ok_or("non-utf-8 shim path")?));
    Ok(())
}

#[test]
fn install_is_idempotent_second_run_unchanged() -> TestResult {
    // Given: .bashrc fixture exists and has the marker block installed.
    let home = TempDir::new()?;
    let shim = shim_dir(home.path());
    fs::write(bashrc(home.path()), "")?;
    init_cmd(home.path())?
        .args(["bash", "--install", "--shim-dir"])
        .arg(&shim)
        .assert()
        .success();
    let after_first = fs::read_to_string(bashrc(home.path()))?;

    // When: second `--install` (idempotent).
    init_cmd(home.path())?
        .args(["bash", "--install", "--shim-dir"])
        .arg(&shim)
        .assert()
        .success();

    // Then: file content is unchanged — exactly one marker pair.
    let after_second = fs::read_to_string(bashrc(home.path()))?;
    assert_eq!(
        after_first, after_second,
        "second install must not change content"
    );
    assert_eq!(after_second.matches(MARKER_BEGIN).count(), 1);
    assert_eq!(after_second.matches(MARKER_END).count(), 1);
    Ok(())
}

#[test]
fn install_dry_run_does_not_modify_file() -> TestResult {
    // Given: temp HOME, no .bashrc exists.
    let home = TempDir::new()?;
    let shim = shim_dir(home.path());

    // When: `--install --dry-run`.
    init_cmd(home.path())?
        .args(["bash", "--install", "--dry-run", "--shim-dir"])
        .arg(&shim)
        .assert()
        .success()
        .stdout(predicate::str::contains("Dry-run"));

    // Then: .bashrc was not created.
    assert!(
        !bashrc(home.path()).exists(),
        "dry-run must not create the rcfile"
    );
    Ok(())
}

#[test]
fn uninstall_removes_block_preserves_foreign_content() -> TestResult {
    // Given: .bashrc with foreign content + installed marker block.
    let home = TempDir::new()?;
    let shim = shim_dir(home.path());
    let rc = bashrc(home.path());
    fs::write(&rc, "# user content\nexport FOO=bar\n")?;
    init_cmd(home.path())?
        .args(["bash", "--install", "--shim-dir"])
        .arg(&shim)
        .assert()
        .success();

    // When: `--uninstall`.
    init_cmd(home.path())?
        .args(["bash", "--uninstall"])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed init block"));

    // Then: markers gone, foreign content preserved.
    let content = fs::read_to_string(&rc)?;
    assert!(!content.contains(MARKER_BEGIN));
    assert!(!content.contains(MARKER_END));
    assert!(content.contains("# user content"));
    assert!(content.contains("export FOO=bar"));
    Ok(())
}

#[test]
fn uninstall_without_prior_install_succeeds() -> TestResult {
    // Given: temp HOME, no .bashrc.
    let home = TempDir::new()?;

    // When/Then: `--uninstall` on missing file exits 0 (no-op per spec).
    init_cmd(home.path())?
        .args(["bash", "--uninstall"])
        .assert()
        .success();
    assert!(!bashrc(home.path()).exists());
    Ok(())
}

#[test]
fn uninstall_twice_second_is_noop() -> TestResult {
    // Given: marker block installed.
    let home = TempDir::new()?;
    let shim = shim_dir(home.path());
    init_cmd(home.path())?
        .args(["bash", "--install", "--shim-dir"])
        .arg(&shim)
        .assert()
        .success();
    init_cmd(home.path())?
        .args(["bash", "--uninstall"])
        .assert()
        .success();

    // When: second `--uninstall` (no block to remove).
    init_cmd(home.path())?
        .args(["bash", "--uninstall"])
        .assert()
        .success();

    // Then: file still has no markers.
    let content = fs::read_to_string(bashrc(home.path())).unwrap_or_default();
    assert!(!content.contains(MARKER_BEGIN));
    Ok(())
}

#[test]
fn install_creates_backup_by_default() -> TestResult {
    // Given: pre-existing .bashrc with foreign content.
    let home = TempDir::new()?;
    let shim = shim_dir(home.path());
    let rc = bashrc(home.path());
    fs::write(&rc, "# original\nexport EDITOR=vim\n")?;

    // When: `--install` (backup defaults to true).
    init_cmd(home.path())?
        .args(["bash", "--install", "--shim-dir"])
        .arg(&shim)
        .assert()
        .success();

    // Then: backup file exists with original content.
    let backup = backup_of(&rc);
    assert!(backup.exists(), "backup file should be created by default");
    let backup_content = fs::read_to_string(&backup)?;
    assert!(backup_content.contains("# original"));
    Ok(())
}

#[test]
fn install_no_backup_flag_skips_backup() -> TestResult {
    // Given: pre-existing .bashrc with foreign content.
    let home = TempDir::new()?;
    let shim = shim_dir(home.path());
    let rc = bashrc(home.path());
    fs::write(&rc, "# original\n")?;

    // When: `--install --no-backup`.
    init_cmd(home.path())?
        .args(["bash", "--install", "--no-backup", "--shim-dir"])
        .arg(&shim)
        .assert()
        .success();

    // Then: no backup file.
    assert!(!backup_of(&rc).exists(), "no backup with --no-backup");
    Ok(())
}

#[test]
fn install_on_bash_then_zsh_updates_both_rcfiles() -> TestResult {
    // Given: temp HOME with a fixture .bashrc.
    let home = TempDir::new()?;
    let shim = shim_dir(home.path());
    fs::write(bashrc(home.path()), "")?;

    // When: install for bash, then install for zsh.
    init_cmd(home.path())?
        .args(["bash", "--install", "--shim-dir"])
        .arg(&shim)
        .assert()
        .success();
    init_cmd(home.path())?
        .args(["zsh", "--install", "--shim-dir"])
        .arg(&shim)
        .assert()
        .success();

    // Then: both rcfiles contain the right snippet.
    let bash_content = fs::read_to_string(bashrc(home.path()))?;
    assert!(bash_content.contains(MARKER_BEGIN));
    assert!(bash_content.contains("export PATH"));
    let zsh_content = fs::read_to_string(zshenv(home.path()))?;
    assert!(zsh_content.contains(MARKER_BEGIN));
    assert!(zsh_content.contains("typeset -aU path"));
    Ok(())
}

#[test]
fn unknown_shell_name_exits_non_zero() -> TestResult {
    // Given: temp HOME.
    let home = TempDir::new()?;
    let shim = shim_dir(home.path());

    // When/Then: unknown shell name → non-zero exit + error message.
    init_cmd(home.path())?
        .args(["cmd.exe", "--install", "--shim-dir"])
        .arg(&shim)
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown shell"));
    Ok(())
}

#[test]
fn detect_shell_prints_shell_and_rcfile() -> TestResult {
    // Given: temp HOME with SHELL=/bin/bash.
    let home = TempDir::new()?;

    // When: `--detect-shell`.
    init_cmd(home.path())?
        .args(["--detect-shell"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bash"))
        .stdout(predicate::str::contains("rcfile:"));

    // Then: .bashrc was not created (detect mode is read-only).
    assert!(!bashrc(home.path()).exists());
    Ok(())
}
