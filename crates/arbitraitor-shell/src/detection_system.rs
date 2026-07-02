use arbitraitor_model::finding::{Evidence, EvidenceKind, Finding, FindingCategory};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity};

use crate::detection::cwe_for_category;
use crate::{ExtractedCommand, NormalizeResult, SourceSpan};

const DETECTOR_ID: &str = "arbitraitor-shell.system";

/// Detects privilege escalation, persistence, defense evasion, and system manipulation patterns.
#[must_use]
pub fn detect_system_threats(normalize_result: &NormalizeResult, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for command in &normalize_result.commands {
        detect_privilege_escalation(command, &mut findings);
        detect_cron_systemd_launchd(command, &mut findings);
        detect_history_deletion(command, &mut findings);
        detect_security_control_disabling(command, &mut findings);
        detect_obscuring_shell_options(command, &mut findings);
        detect_insecure_tls(command, &mut findings);
        detect_package_repository_changes(command, &mut findings);
    }

    for line in source.lines() {
        detect_source_line_threats(line, &mut findings);
    }

    findings
}

fn detect_privilege_escalation(command: &ExtractedCommand, findings: &mut Vec<Finding>) {
    if !matches!(command.name.as_str(), "sudo" | "su" | "doas" | "pkexec") {
        return;
    }
    if command.name == "sudo" && is_legitimate_sudo_install(command) {
        return;
    }

    findings.push(finding(CommandFinding {
        id: "privilege-escalation-command",
        category: FindingCategory::PrivilegeEscalation,
        severity: Severity::Medium,
        confidence: Confidence::High,
        title: "Shell invokes a privilege escalation tool",
        description: "The script invokes sudo, su, doas, or pkexec. These tools may be legitimate, but they also cross a privilege boundary.",
        evidence_kind: EvidenceKind::Command,
        evidence: command_text(command),
        span: &command.span,
        tag: "privilege-escalation",
    }));
}

fn is_legitimate_sudo_install(command: &ExtractedCommand) -> bool {
    let Some(program) = command.arguments.first() else {
        return false;
    };
    let package_manager = matches!(
        program.as_str(),
        "apt" | "apt-get" | "dnf" | "yum" | "pacman" | "zypper" | "apk" | "brew"
    );
    package_manager
        && command.arguments.iter().any(|argument| {
            matches!(
                argument.as_str(),
                "install" | "update" | "upgrade" | "-S" | "add"
            )
        })
}

fn detect_cron_systemd_launchd(command: &ExtractedCommand, findings: &mut Vec<Finding>) {
    let joined = command_text(command);
    let lower = joined.to_ascii_lowercase();
    let is_crontab_edit =
        command.name == "crontab" && command.arguments.iter().any(|arg| arg == "-e");
    let is_launchctl_load =
        command.name == "launchctl" && command.arguments.iter().any(|arg| arg == "load");
    let has_service_unit = command
        .arguments
        .iter()
        .any(|arg| arg.ends_with(".service"));
    let has_autostart = command.arguments.iter().any(|arg| {
        arg.contains("/autostart/") || arg.ends_with(".desktop") || arg.contains("/etc/cron.")
    });

    if is_crontab_edit || is_launchctl_load || has_service_unit || has_autostart {
        findings.push(finding(CommandFinding {
            id: "persistence-scheduler-or-service",
            category: FindingCategory::Persistence,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Shell modifies scheduled task or service persistence",
            description: "The script edits cron, systemd, launchd, or desktop autostart configuration that can persist execution.",
            evidence_kind: EvidenceKind::Command,
            evidence: lower,
            span: &command.span,
            tag: "persistence",
        }));
    }
}

fn detect_history_deletion(command: &ExtractedCommand, findings: &mut Vec<Finding>) {
    let is_history_clear =
        command.name == "history" && command.arguments.iter().any(|arg| arg == "-c");
    let is_unset_histfile =
        command.name == "unset" && command.arguments.iter().any(|arg| arg == "HISTFILE");
    if is_history_clear || is_unset_histfile {
        findings.push(finding(CommandFinding {
            id: "defense-evasion-history-deletion",
            category: FindingCategory::SuspiciousScriptBehavior,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Shell disables or deletes command history",
            description: "The script clears shell history or unsets HISTFILE to reduce auditability.",
            evidence_kind: EvidenceKind::Command,
            evidence: command_text(command),
            span: &command.span,
            tag: "defense-evasion",
        }));
    }
}

fn detect_security_control_disabling(command: &ExtractedCommand, findings: &mut Vec<Finding>) {
    let joined = command_text(command);
    let lower = joined.to_ascii_lowercase();
    let disables_service = matches!(command.name.as_str(), "systemctl" | "service")
        && command
            .arguments
            .iter()
            .any(|arg| matches!(arg.as_str(), "stop" | "disable"))
        && command
            .arguments
            .iter()
            .any(|arg| security_service_name(arg));
    let flushes_iptables =
        command.name == "iptables" && command.arguments.iter().any(|arg| arg == "-F");
    let disables_ufw =
        command.name == "ufw" && command.arguments.iter().any(|arg| arg == "disable");

    if disables_service || flushes_iptables || disables_ufw {
        findings.push(finding(CommandFinding {
            id: "defense-evasion-security-control-disable",
            category: FindingCategory::SuspiciousScriptBehavior,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Shell disables antivirus or firewall controls",
            description: "The script stops security services or disables firewall filtering.",
            evidence_kind: EvidenceKind::Command,
            evidence: lower,
            span: &command.span,
            tag: "defense-evasion",
        }));
    }
}

fn security_service_name(argument: &str) -> bool {
    let lower = argument.to_ascii_lowercase();
    [
        "clamav",
        "clamd",
        "freshclam",
        "ufw",
        "firewalld",
        "iptables",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn detect_obscuring_shell_options(command: &ExtractedCommand, findings: &mut Vec<Finding>) {
    if command.name != "set" {
        return;
    }
    let disables_errexit = command.arguments.iter().any(|arg| arg == "+e");
    let disables_pipefail = command
        .arguments
        .windows(2)
        .any(|pair| matches!(pair, [first, second] if first == "+o" && second == "pipefail"));
    if disables_errexit || disables_pipefail {
        findings.push(finding(CommandFinding {
            id: "defense-evasion-obscure-shell-failure",
            category: FindingCategory::SuspiciousScriptBehavior,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            title: "Shell disables failure propagation options",
            description: "The script disables errexit or pipefail, which can obscure failed commands during execution.",
            evidence_kind: EvidenceKind::Command,
            evidence: command_text(command),
            span: &command.span,
            tag: "defense-evasion",
        }));
    }
}

fn detect_insecure_tls(command: &ExtractedCommand, findings: &mut Vec<Finding>) {
    let has_insecure_flag = command.arguments.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "--insecure" | "-k" | "--no-check-certificate" | "--tls-max" | "--tls-max=1.1"
        )
    }) || command
        .arguments
        .windows(2)
        .any(|pair| matches!(pair, [first, second] if first == "--tls-max" && second == "1.1"));
    if has_insecure_flag {
        findings.push(finding(CommandFinding {
            id: "insecure-tls-flags",
            category: FindingCategory::Transport,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Shell command weakens TLS verification",
            description: "The script passes flags that disable certificate checks or permit obsolete TLS versions.",
            evidence_kind: EvidenceKind::Command,
            evidence: command_text(command),
            span: &command.span,
            tag: "insecure-tls",
        }));
    }
}

fn detect_package_repository_changes(command: &ExtractedCommand, findings: &mut Vec<Finding>) {
    if command
        .arguments
        .iter()
        .any(|arg| package_repository_path(arg))
    {
        findings.push(finding(CommandFinding {
            id: "persistence-package-repository-modification",
            category: FindingCategory::Persistence,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Shell modifies package repository configuration",
            description: "The script touches package repository configuration, which can redirect future software installation or update trust.",
            evidence_kind: EvidenceKind::FilePath,
            evidence: command_text(command),
            span: &command.span,
            tag: "persistence",
        }));
    }
}

fn package_repository_path(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("/etc/apt/sources.list")
        || lower.contains("/etc/yum.repos.d/")
        || lower.contains("/etc/pacman.conf")
        || lower.contains(".npmrc")
        || lower.contains("npmrc")
        || (lower.contains("npm") && lower.contains("registry"))
}

fn detect_source_line_threats(line: &str, findings: &mut Vec<Finding>) {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return;
    }
    let lower = trimmed.to_ascii_lowercase();
    if modifies_shell_startup(&lower) {
        findings.push(source_finding(
            "persistence-shell-startup-modification",
            Severity::High,
            Confidence::High,
            "Shell modifies startup profile persistence",
            "The script modifies a shell startup file that can execute attacker-controlled commands in future sessions.",
            trimmed,
            "persistence",
        ));
    }
    if modifies_protected_system_path(&lower) {
        findings.push(source_finding(
            "system-manipulation-protected-path-write",
            Severity::Critical,
            Confidence::Confirmed,
            "Shell writes to protected system configuration",
            "The script writes under /etc, /usr, /boot, sudoers, or MAC policy configuration.",
            trimmed,
            "system-manipulation",
        ));
    }
    if modifies_scheduler_or_service_source(&lower) {
        findings.push(source_finding(
            "persistence-service-source-modification",
            Severity::High,
            Confidence::High,
            "Shell writes scheduler or service persistence files",
            "The script writes cron, systemd, launchd, or desktop autostart files.",
            trimmed,
            "persistence",
        ));
    }
    if package_repository_path(&lower) {
        findings.push(source_finding(
            "persistence-package-repository-source-modification",
            Severity::High,
            Confidence::High,
            "Shell writes package repository configuration",
            "The script modifies repository configuration that controls future package trust.",
            trimmed,
            "persistence",
        ));
    }
    if lower.contains("histsize=0")
        || lower.contains("histfile=/dev/null")
        || lower.contains("set +o history")
    {
        findings.push(source_finding(
            "defense-evasion-history-source",
            Severity::Medium,
            Confidence::High,
            "Shell disables command history",
            "The script changes history settings to reduce auditability.",
            trimmed,
            "defense-evasion",
        ));
    }
}

fn modifies_shell_startup(lower: &str) -> bool {
    has_write_operator(lower)
        && [
            ".bashrc",
            ".zshrc",
            ".profile",
            ".bash_profile",
            "/etc/profile.d/",
        ]
        .iter()
        .any(|path| lower.contains(path))
}

fn modifies_protected_system_path(lower: &str) -> bool {
    has_write_operator(lower)
        && [
            "/etc/",
            "/usr/",
            "/boot/",
            "/etc/sudoers",
            "/etc/selinux/",
            "/etc/sysconfig/selinux",
        ]
        .iter()
        .any(|path| lower.contains(path))
}

fn modifies_scheduler_or_service_source(lower: &str) -> bool {
    has_write_operator(lower)
        && [
            "/etc/cron.",
            ".service",
            "/library/launchagents/",
            "/library/launchdaemons/",
            "/autostart/",
            ".desktop",
        ]
        .iter()
        .any(|path| lower.contains(path))
}

fn has_write_operator(lower: &str) -> bool {
    lower.contains('>')
        || lower.contains(" tee ")
        || lower.starts_with("tee ")
        || lower.contains(" install ")
        || lower.starts_with("install ")
        || lower.contains(" cp ")
        || lower.starts_with("cp ")
        || lower.contains("mv ")
}

fn command_text(command: &ExtractedCommand) -> String {
    let mut text = command.name.clone();
    for argument in &command.arguments {
        text.push(' ');
        text.push_str(argument);
    }
    text
}

fn source_finding(
    id: &str,
    severity: Severity,
    confidence: Confidence,
    title: &str,
    description: &str,
    evidence: &str,
    tag: &str,
) -> Finding {
    Finding {
        id: id.to_owned(),
        detector: DETECTOR_ID.to_owned(),
        category: FindingCategory::Persistence,
        severity,
        confidence,
        title: title.to_owned(),
        description: description.to_owned(),
        evidence: vec![Evidence {
            kind: EvidenceKind::SourceSnippet,
            description: "matched shell source".to_owned(),
            content: Some(evidence.to_owned()),
        }],
        artifact_sha256: Sha256Digest::new([0; 32]),
        location: None,
        remediation: None,
        references: Vec::new(),
        tags: vec!["shell-system".to_owned(), tag.to_owned()],
        taxonomies: cwe_for_category(FindingCategory::Persistence)
            .into_iter()
            .collect(),
    }
}

struct CommandFinding<'span> {
    id: &'static str,
    category: FindingCategory,
    severity: Severity,
    confidence: Confidence,
    title: &'static str,
    description: &'static str,
    evidence_kind: EvidenceKind,
    evidence: String,
    span: &'span SourceSpan,
    tag: &'static str,
}

fn finding(input: CommandFinding<'_>) -> Finding {
    Finding {
        id: input.id.to_owned(),
        detector: DETECTOR_ID.to_owned(),
        category: input.category,
        severity: input.severity,
        confidence: input.confidence,
        title: input.title.to_owned(),
        description: input.description.to_owned(),
        evidence: vec![Evidence {
            kind: input.evidence_kind,
            description: "matched normalized command".to_owned(),
            content: Some(input.evidence),
        }],
        artifact_sha256: Sha256Digest::new([0; 32]),
        location: Some(input.span.location.clone()),
        remediation: None,
        references: Vec::new(),
        tags: vec!["shell-system".to_owned(), input.tag.to_owned()],
        taxonomies: cwe_for_category(input.category).into_iter().collect(),
    }
}
