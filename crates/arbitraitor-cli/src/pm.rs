//! `arbitraitor pm` — package-manager advisory scan and gated execution.
//!
//! Implements spec §39.14 Phase 1 (advisory mode) for npm: resolves the
//! dependency tree via the lockfile, detects lifecycle scripts, derives a
//! verdict, and gates the real `npm install` behind it. When execution is
//! allowed, scripts are denied (`--ignore-scripts`) per the npm adapter's
//! `DeniedByDefault` lifecycle policy.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::Path;

use arbitraitor_model::exit_code::ExitCode;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_package_manager::advisory::{self, AdvisoryVerdict, FindingSeverity};
use arbitraitor_package_manager::lifecycle::LifecycleScript;
use arbitraitor_package_manager::npm;
use arbitraitor_package_manager::receipt::{CapabilityGrant, LifecycleScriptStatus};
use clap::{Args, Subcommand};
use miette::{IntoDiagnostic, Result};
use sha2::{Digest, Sha256};

#[derive(Args)]
pub struct PmCommand {
    #[command(subcommand)]
    pub subcommand: PmSubcommand,
}

#[derive(Subcommand)]
pub enum PmSubcommand {
    /// Run a package manager tool through advisory scan, then execute it
    /// if the verdict allows (spec §39.14).
    Run {
        /// Package manager tool to wrap (currently: `npm`).
        #[arg(long)]
        tool: String,
        /// Arguments to pass through to the tool (e.g. `install`, `--save-dev`).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

pub fn run(command: &PmCommand) -> Result<()> {
    let PmSubcommand::Run { tool, args } = &command.subcommand;
    match tool.as_str() {
        "npm" => run_npm(args),
        other => {
            miette::bail!("unsupported package manager tool: '{other}'; currently supported: npm")
        }
    }
}

fn run_npm(args: &[String]) -> Result<()> {
    let work_dir = std::env::current_dir().into_diagnostic()?;
    if !work_dir.join("package.json").exists() {
        miette::bail!(
            "no package.json in {}; run 'arb pm run --tool npm' from a Node.js project root",
            work_dir.display()
        );
    }

    let lock_path = work_dir.join("package-lock.json");
    if !lock_path.exists() {
        let mut stderr = std::io::stderr().lock();
        writeln!(
            stderr,
            "[arbitraitor] no package-lock.json; generating with 'npm install --package-lock-only --ignore-scripts'"
        )
        .into_diagnostic()?;
        drop(stderr);
        spawn_npm(
            &work_dir,
            &["install", "--package-lock-only", "--ignore-scripts"],
        )?;
    }

    let lock_data = std::fs::read(&lock_path).into_diagnostic()?;
    let lock = npm::read_package_lock(&lock_path)
        .map_err(|e| miette::miette!("failed to parse package-lock.json: {e}"))?;
    let lockfile_digest = Sha256Digest::new(Sha256::digest(&lock_data).into());
    let root_scripts = read_root_lifecycle_scripts(&work_dir)?;
    let npm_version = detect_npm_version().unwrap_or_else(|_| "unknown".to_owned());

    let mut outcome = advisory::analyze(&lock, &root_scripts, &npm_version, lockfile_digest);
    print_outcome(&outcome)?;

    if outcome.verdict.allows_execution() {
        outcome.receipt.lifecycle_scripts = LifecycleScriptStatus::Denied;
        outcome.receipt.capabilities.push(CapabilityGrant {
            name: "spawn_tool".to_owned(),
            granted: true,
        });
        let mut npm_args: Vec<String> = if args.is_empty() {
            vec!["install".to_owned()]
        } else {
            args.to_vec()
        };
        npm_args.push("--ignore-scripts".to_owned());
        let arg_refs: Vec<&str> = npm_args.iter().map(String::as_str).collect();
        let exit = spawn_npm(&work_dir, &arg_refs)?;
        outcome.install_exit_code = Some(exit);
        let mut stderr = std::io::stderr().lock();
        writeln!(
            stderr,
            "[arbitraitor] npm exited with code {exit} (scripts denied via --ignore-scripts)"
        )
        .into_diagnostic()?;
    } else {
        let mut stderr = std::io::stderr().lock();
        writeln!(
            stderr,
            "[arbitraitor] verdict {:?}: npm install NOT executed",
            outcome.verdict
        )
        .into_diagnostic()?;
    }

    let exit_code = match outcome.verdict {
        AdvisoryVerdict::Pass => ExitCode::Success,
        AdvisoryVerdict::Warn => ExitCode::WarningNoRelease,
        AdvisoryVerdict::Block => ExitCode::BlockedByPolicy,
    };
    if exit_code != ExitCode::Success {
        std::process::exit(exit_code.as_i32());
    }
    Ok(())
}

fn read_root_lifecycle_scripts(work_dir: &Path) -> Result<Vec<LifecycleScript>> {
    let data = std::fs::read(work_dir.join("package.json")).into_diagnostic()?;
    arbitraitor_package_manager::parse_lifecycle_scripts(&data)
        .map_err(|e| miette::miette!("failed to parse package.json scripts: {e}"))
}

fn detect_npm_version() -> Result<String> {
    let output = std::process::Command::new("npm")
        .arg("--version")
        .output()
        .into_diagnostic()?;
    if !output.status.success() {
        miette::bail!("npm --version exited with {:?}", output.status.code());
    }
    Ok(String::from_utf8(output.stdout)
        .into_diagnostic()?
        .trim()
        .to_owned())
}

fn spawn_npm(work_dir: &Path, args: &[&str]) -> Result<i32> {
    std::process::Command::new("npm")
        .args(args)
        .current_dir(work_dir)
        .status()
        .into_diagnostic()
        .map_err(|e| miette::miette!("failed to spawn npm: {e}; is Node.js installed?"))?
        .code()
        .ok_or_else(|| miette::miette!("npm terminated by signal"))
}

#[allow(clippy::too_many_lines)]
fn print_outcome(outcome: &advisory::NpmAdvisoryOutcome) -> Result<()> {
    let mut stderr = std::io::stderr().lock();
    let r = &outcome.receipt;
    writeln!(stderr, "tool:               {}", r.tool).into_diagnostic()?;
    writeln!(stderr, "tool_version:       {}", r.tool_version).into_diagnostic()?;
    writeln!(stderr, "lockfile_digest:    sha256:{}", r.lockfile_digest).into_diagnostic()?;
    writeln!(stderr, "packages_inspected: {}", r.packages_inspected).into_diagnostic()?;
    writeln!(stderr, "packages_blocked:   {}", r.packages_blocked).into_diagnostic()?;
    writeln!(stderr, "packages_incomplete: {}", r.packages_incomplete).into_diagnostic()?;
    writeln!(stderr, "lifecycle_scripts:  {:?}", r.lifecycle_scripts).into_diagnostic()?;
    writeln!(stderr, "proxy_mode:         {:?}", r.proxy_mode).into_diagnostic()?;
    writeln!(stderr, "verdict:            {:?}", outcome.verdict).into_diagnostic()?;
    writeln!(stderr, "findings:           {}", outcome.findings.len()).into_diagnostic()?;
    for f in &outcome.findings {
        let sev = match f.severity {
            FindingSeverity::Block => "BLOCK",
            FindingSeverity::Warning => "WARN ",
            FindingSeverity::Information => "INFO ",
        };
        let pkg = if f.version.is_empty() {
            f.package.clone()
        } else {
            format!("{}@{}", f.package, f.version)
        };
        writeln!(stderr, "  [{sev}] {} ({pkg}): {}", f.id, f.title).into_diagnostic()?;
        if let Some(detail) = &f.detail {
            writeln!(stderr, "        detail: {detail}").into_diagnostic()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{Cli, Command};
    use clap::Parser;

    #[test]
    fn pm_run_parses_tool_and_args() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "arbitraitor",
            "pm",
            "run",
            "--tool",
            "npm",
            "--",
            "install",
            "--save-dev",
        ])?;
        match cli.command {
            Command::Pm(cmd) => match cmd.subcommand {
                super::PmSubcommand::Run { tool, args } => {
                    assert_eq!(tool, "npm");
                    assert_eq!(args, vec!["install", "--save-dev"]);
                }
            },
            _ => return Err("parsed wrong command".into()),
        }
        Ok(())
    }

    #[test]
    fn pm_run_defaults_args_to_empty() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from(["arbitraitor", "pm", "run", "--tool", "npm"])?;
        match cli.command {
            Command::Pm(cmd) => match cmd.subcommand {
                super::PmSubcommand::Run { tool, args } => {
                    assert_eq!(tool, "npm");
                    assert!(args.is_empty());
                }
            },
            _ => return Err("parsed wrong command".into()),
        }
        Ok(())
    }

    #[test]
    fn pm_run_rejects_missing_tool() {
        let result = Cli::try_parse_from(["arbitraitor", "pm", "run"]);
        assert!(result.is_err());
    }
}
