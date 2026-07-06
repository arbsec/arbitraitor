use std::io::Write;
use std::path::{Path, PathBuf};

use arbitraitor_core::config::Config;
use arbitraitor_core::health::{ComponentHealth, HealthChecker, HealthReport, HealthStatus};
use arbitraitor_wrapper::init::{self as shell_init, DetectionSource, MARKER_BEGIN, MARKER_END};
use arbitraitor_wrapper::shim::{ShimConfig, ShimState, WrapperTarget, check_shims};
use miette::{IntoDiagnostic, Result};

use crate::default_cas_dir;

use super::DoctorCommand;

pub(crate) fn doctor(command: &DoctorCommand, config: &Config) -> Result<()> {
    let cas_dir = command
        .cas_dir
        .clone()
        .or_else(|| config.store.cas_dir.clone())
        .unwrap_or_else(default_cas_dir);
    let shim_dir = default_shim_dir();
    let mut checker = HealthChecker::new().with_store(cas_dir);
    if let Some(rules_dir) = command.rules.as_deref() {
        let versions = crate::rule_pack_versions(rules_dir)?;
        if let Some(first) = versions.first() {
            checker = checker.with_rule_pack(first.clone());
        }
        checker = checker.with_detector_versions(versions);
    }
    let report = checker.check();

    let shell = ShellIntegrationReport::probe(shim_dir.as_deref());
    let healthy = report.overall == HealthStatus::Healthy && shell.healthy();
    if command.json {
        let json = serde_json::to_vec_pretty(&report).into_diagnostic()?;
        std::io::stdout()
            .lock()
            .write_all(&json)
            .into_diagnostic()?;
        writeln!(std::io::stdout().lock()).into_diagnostic()?;
    } else {
        write_doctor_text(&mut std::io::stdout().lock(), &report, &shell)?;
    }
    if !healthy {
        std::process::exit(1);
    }
    Ok(())
}

struct ShellIntegrationReport {
    shell_detection: DoctorCheck,
    shims: DoctorCheck,
    path: DoctorCheck,
    rcfile: DoctorCheck,
}

impl ShellIntegrationReport {
    fn probe(shim_dir: Option<&Path>) -> Self {
        let detected = shell_init::detect_shell();
        Self {
            shell_detection: check_shell_detection(detected.as_ref()),
            shims: check_shims_installed(shim_dir),
            path: check_shim_dir_on_path(shim_dir),
            rcfile: check_rcfile(detected.as_ref(), shim_dir),
        }
    }

    const fn healthy(&self) -> bool {
        self.shell_detection.healthy
            && self.shims.healthy
            && self.path.healthy
            && self.rcfile.healthy
    }

    fn failing_fixups(&self) -> Vec<&'static str> {
        let mut fixups = Vec::new();
        if !self.shell_detection.healthy {
            fixups.push("Set $SHELL or run: arbitraitor wrappers init <shell> --install");
        }
        if !self.shims.healthy {
            fixups.push("Install shims: arbitraitor wrappers install");
        }
        if !self.path.healthy || !self.rcfile.healthy {
            fixups.push("Add shim dir to your shell startup: arbitraitor wrappers init --install");
        }
        fixups
    }
}

struct DoctorCheck {
    healthy: bool,
    message: String,
}

impl DoctorCheck {
    fn pass(message: impl Into<String>) -> Self {
        Self {
            healthy: true,
            message: message.into(),
        }
    }

    fn fail(message: impl Into<String>) -> Self {
        Self {
            healthy: false,
            message: message.into(),
        }
    }
}

fn check_shell_detection(detected: Option<&shell_init::DetectedShell>) -> DoctorCheck {
    match detected {
        Some(detected) => DoctorCheck::pass(format!(
            "{} via {}",
            detected.shell.as_str(),
            detection_source_label(detected.source)
        )),
        None => DoctorCheck::fail("could not detect shell"),
    }
}

fn check_shims_installed(shim_dir: Option<&Path>) -> DoctorCheck {
    let Some(shim_dir) = shim_dir else {
        return DoctorCheck::fail("could not determine shim directory; set $HOME");
    };
    let config = ShimConfig {
        shim_dir: shim_dir.to_path_buf(),
        use_symlinks: true,
    };
    let statuses = check_shims(&config, WrapperTarget::ALL);
    let missing = statuses
        .iter()
        .filter_map(|status| match status.state {
            ShimState::Script | ShimState::Symlink => None,
            ShimState::NotInstalled => Some(format!("{} missing", status.target.binary_name())),
            ShimState::ForeignFile => Some(format!("{} foreign file", status.target.binary_name())),
        })
        .collect::<Vec<_>>();
    if missing.is_empty() {
        DoctorCheck::pass(format!("curl and wget installed in {}", shim_dir.display()))
    } else {
        DoctorCheck::fail(missing.join(", "))
    }
}

fn check_shim_dir_on_path(shim_dir: Option<&Path>) -> DoctorCheck {
    let Some(shim_dir) = shim_dir else {
        return DoctorCheck::fail("could not determine shim directory; set $HOME");
    };
    let Some(path) = std::env::var_os("PATH") else {
        return DoctorCheck::fail(format!("{} not on PATH", shim_dir.display()));
    };
    if std::env::split_paths(&path).any(|entry| entry == shim_dir) {
        DoctorCheck::pass(format!("{} is on PATH", shim_dir.display()))
    } else {
        DoctorCheck::fail(format!("{} not on PATH", shim_dir.display()))
    }
}

fn check_rcfile(
    detected: Option<&shell_init::DetectedShell>,
    shim_dir: Option<&Path>,
) -> DoctorCheck {
    let Some(detected) = detected else {
        return DoctorCheck::fail("shell not detected; rcfile unknown");
    };
    let Some(rcfile) = shell_init::target_rcfile(detected.shell) else {
        return DoctorCheck::fail(format!("no rcfile known for {}", detected.shell.as_str()));
    };
    let content = match std::fs::read_to_string(&rcfile) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return DoctorCheck::fail(format!("{} is missing", rcfile.display()));
        }
        Err(error) => {
            return DoctorCheck::fail(format!("{} unreadable: {error}", rcfile.display()));
        }
    };
    if rcfile_has_integration(&content, detected.shell, shim_dir) {
        DoctorCheck::pass(format!("{} has Arbitraitor block", rcfile.display()))
    } else {
        DoctorCheck::fail(format!("{} has no Arbitraitor block", rcfile.display()))
    }
}

fn rcfile_has_integration(
    content: &str,
    shell: shell_init::Shell,
    shim_dir: Option<&Path>,
) -> bool {
    if matches!(shell, shell_init::Shell::Fish) {
        let Some(shim_dir) = shim_dir else {
            return false;
        };
        return content.contains("fish_add_path --move --path")
            && content.contains(&shim_dir.display().to_string());
    }
    content.contains(MARKER_BEGIN) && content.contains(MARKER_END)
}

const fn detection_source_label(source: DetectionSource) -> &'static str {
    match source {
        DetectionSource::EnvShell => "$SHELL",
        DetectionSource::ParentProcess => "parent process",
    }
}

fn default_shim_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".arbitraitor").join("shims"))
}

fn write_doctor_text(
    writer: &mut impl Write,
    report: &HealthReport,
    shell: &ShellIntegrationReport,
) -> Result<()> {
    writeln!(writer, "Arbitraitor Doctor").into_diagnostic()?;
    write_health_row(
        writer,
        "Version",
        report.checks.get("version"),
        &report.version,
    )?;
    write_health_row(writer, "Store", report.checks.get("store"), "not checked")?;
    write_health_row(
        writer,
        "Rules",
        report.checks.get("detectors"),
        "not checked",
    )?;
    write_check_row(writer, "Shell detection", &shell.shell_detection)?;
    write_check_row(writer, "Shims", &shell.shims)?;
    write_check_row(writer, "PATH", &shell.path)?;
    write_check_row(writer, "Rcfile", &shell.rcfile)?;

    let fixups = shell.failing_fixups();
    if !fixups.is_empty() {
        writeln!(writer).into_diagnostic()?;
        writeln!(writer, "Fix shell integration:").into_diagnostic()?;
        for fixup in fixups {
            writeln!(writer, "  - {fixup}").into_diagnostic()?;
        }
    }
    Ok(())
}

fn write_health_row(
    writer: &mut impl Write,
    label: &str,
    check: Option<&ComponentHealth>,
    fallback: &str,
) -> Result<()> {
    let healthy = check.is_some_and(|component| component.status == HealthStatus::Healthy);
    let message = check.map_or(fallback, |component| component.message.as_str());
    writeln!(writer, "{} {label}: {message}", indicator(healthy)).into_diagnostic()
}

fn write_check_row(writer: &mut impl Write, label: &str, check: &DoctorCheck) -> Result<()> {
    writeln!(
        writer,
        "{} {label}: {}",
        indicator(check.healthy),
        check.message
    )
    .into_diagnostic()
}

const fn indicator(healthy: bool) -> &'static str {
    if healthy { "✓" } else { "✗" }
}
