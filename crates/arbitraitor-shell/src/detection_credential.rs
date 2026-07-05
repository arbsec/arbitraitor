//! Detection rules for shell credential access and network threat patterns.

use arbitraitor_model::finding::{Evidence, EvidenceKind, Finding, FindingCategory};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity};

use crate::detection::cwe_for_category;
use crate::{ExtractedCommand, NormalizeResult, SourceSpan};

const DETECTOR_ID: &str = "arbitraitor-shell.credential";

/// Detects credential access, environment exfiltration, and suspicious network shell patterns.
#[must_use]
pub fn detect_credential_threats(normalize_result: &NormalizeResult, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for command in &normalize_result.commands {
        detect_environment_exfiltration_command(command, normalize_result, &mut findings);
        detect_netcat_reverse_shell(command, &mut findings);
        detect_socat_reverse_shell(command, &mut findings);
        detect_non_https_retrieval(command, &mut findings);
    }

    for line in source.lines() {
        detect_source_line_threats(line, &mut findings);
    }

    findings
}

fn detect_environment_exfiltration_command(
    command: &ExtractedCommand,
    normalize_result: &NormalizeResult,
    findings: &mut Vec<Finding>,
) {
    if !is_remote_exfiltration_sink(command) {
        return;
    }
    let Some(sink_index) = normalize_result
        .commands
        .iter()
        .position(|candidate| candidate.span.byte_range == command.span.byte_range)
    else {
        return;
    };
    if normalize_result.data_flow.edges.iter().any(|(from, to)| {
        *to == sink_index && is_environment_source(&normalize_result.commands[*from])
    }) {
        findings.push(finding(CommandFinding {
            id: "credential-environment-exfiltration",
            category: FindingCategory::CredentialAccess,
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            title: "Shell pipes environment variables to a remote endpoint",
            description: "The script sends output from env or printenv into a network client, exposing tokens and other secrets stored in environment variables.",
            evidence_kind: EvidenceKind::Command,
            evidence: command_text(command),
            span: &command.span,
            tag: "environment-exfiltration",
        }));
    }
}

fn detect_netcat_reverse_shell(command: &ExtractedCommand, findings: &mut Vec<Finding>) {
    if !matches!(
        command_basename(&command.name).as_str(),
        "nc" | "ncat" | "netcat"
    ) {
        return;
    }
    let has_exec_flag = command.arguments.iter().any(|argument| {
        let stripped = strip_quotes(argument);
        stripped == "-e" || stripped == "-c" || stripped.contains('e') && stripped.starts_with('-')
    });
    let has_suspicious_port = command
        .arguments
        .iter()
        .any(|argument| suspicious_reverse_shell_port(&strip_quotes(argument)));
    if has_exec_flag || has_suspicious_port {
        findings.push(finding(CommandFinding {
            id: "network-netcat-reverse-shell",
            category: FindingCategory::NetworkBehavior,
            severity: Severity::Critical,
            confidence: Confidence::High,
            title: "Netcat command resembles a reverse shell",
            description: "The script invokes nc, ncat, or netcat with command execution flags or ports commonly used by reverse shells.",
            evidence_kind: EvidenceKind::Command,
            evidence: command_text(command),
            span: &command.span,
            tag: "netcat-reverse-shell",
        }));
    }
}

fn detect_socat_reverse_shell(command: &ExtractedCommand, findings: &mut Vec<Finding>) {
    if command_basename(&command.name) != "socat" {
        return;
    }
    let joined = command_text(command).to_ascii_lowercase();
    let executes_program = joined.contains("exec:") || joined.contains("system:");
    let suspicious_connect = joined.contains("tcp:")
        && ["4444", "8080", "9001", "1337", "5555"]
            .iter()
            .any(|port| joined.contains(port));
    if executes_program || suspicious_connect {
        findings.push(finding(CommandFinding {
            id: "network-socat-reverse-shell",
            category: FindingCategory::NetworkBehavior,
            severity: Severity::Critical,
            confidence: Confidence::High,
            title: "Socat command resembles a reverse shell",
            description: "The script invokes socat with EXEC, SYSTEM, or a suspicious outbound TCP pattern commonly used for reverse shells.",
            evidence_kind: EvidenceKind::Command,
            evidence: command_text(command),
            span: &command.span,
            tag: "socat-reverse-shell",
        }));
    }
}

fn detect_non_https_retrieval(command: &ExtractedCommand, findings: &mut Vec<Finding>) {
    if !is_download_command(command) {
        return;
    }
    if command
        .arguments
        .iter()
        .map(|argument| strip_quotes(argument))
        .any(|argument| is_http_url(&argument) || is_direct_ip_url(&argument))
    {
        findings.push(finding(CommandFinding {
            id: "transport-raw-ip-or-non-https-retrieval",
            category: FindingCategory::Transport,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Download command uses a raw IP or non-HTTPS URL",
            description: "The script retrieves content over plaintext HTTP or from a direct IP URL, reducing origin authenticity and transport confidentiality.",
            evidence_kind: EvidenceKind::NetworkEndpoint,
            evidence: command_text(command),
            span: &command.span,
            tag: "raw-ip-or-non-https-retrieval",
        }));
    }
}

fn detect_source_line_threats(line: &str, findings: &mut Vec<Finding>) {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return;
    }
    let lower = trimmed.to_ascii_lowercase();
    if contains_credential_path(&lower) {
        findings.push(source_finding(SourceFinding {
            id: "credential-file-access",
            category: FindingCategory::CredentialAccess,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Shell accesses credential or key material",
            description: "The script references SSH, cloud, registry, Kubernetes, Git, or netrc credential files.",
            evidence: trimmed,
            tag: "credential-file-access",
        }));
    }
    if lower.contains("ssh_auth_sock") || contains_ssh_agent_socket(&lower) {
        findings.push(source_finding(SourceFinding {
            id: "credential-ssh-agent-socket-access",
            category: FindingCategory::CredentialAccess,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Shell accesses an SSH agent socket",
            description: "The script references SSH_AUTH_SOCK or a /tmp/ssh-* agent socket, which can allow credential-backed authentication.",
            evidence: trimmed,
            tag: "ssh-agent-access",
        }));
    }
    if lower.contains("169.254.169.254") {
        findings.push(source_finding(SourceFinding {
            id: "credential-cloud-metadata-access",
            category: FindingCategory::CredentialAccess,
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            title: "Shell accesses a cloud instance metadata endpoint",
            description: "The script contacts 169.254.169.254, a cloud metadata service endpoint that can expose instance identity credentials and tokens.",
            evidence: trimmed,
            tag: "cloud-metadata-access",
        }));
    }
    if contains_environment_exfiltration_source(&lower) {
        findings.push(source_finding(SourceFinding {
            id: "credential-environment-exfiltration-source",
            category: FindingCategory::CredentialAccess,
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            title: "Shell sends environment variables to a remote endpoint",
            description: "The script pipes environment variable output into a network client, exposing tokens and other secrets stored in the environment.",
            evidence: trimmed,
            tag: "environment-exfiltration",
        }));
    }
    if lower.contains("/dev/tcp/") || lower.contains("/dev/udp/") {
        findings.push(source_finding(SourceFinding {
            id: "network-dev-tcp-udp-usage",
            category: FindingCategory::NetworkBehavior,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Shell uses bash /dev/tcp or /dev/udp networking",
            description: "The script uses shell pseudo-device networking, which can bypass normal tool-based network policy and is common in reverse-shell payloads.",
            evidence: trimmed,
            tag: "dev-tcp-udp",
        }));
    }
    if contains_url_shortener(&lower) {
        findings.push(source_finding(SourceFinding {
            id: "transport-url-shortener-usage",
            category: FindingCategory::Transport,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            title: "Shell references a URL shortener",
            description: "The script uses a shortened URL, obscuring the final destination until runtime.",
            evidence: trimmed,
            tag: "url-shortener",
        }));
    }
}

fn contains_credential_path(lower: &str) -> bool {
    [
        "~/.ssh/id_",
        "/.ssh/id_",
        "~/.aws/credentials",
        "~/.aws/config",
        "/.aws/credentials",
        "/.aws/config",
        "~/.gnupg/",
        "/.gnupg/",
        "~/.docker/config.json",
        "/.docker/config.json",
        "~/.kube/config",
        "/.kube/config",
        "~/.npmrc",
        "/.npmrc",
        "~/.gitconfig",
        "/.gitconfig",
        "~/.netrc",
        "/.netrc",
    ]
    .iter()
    .any(|path| lower.contains(path))
}

fn contains_ssh_agent_socket(lower: &str) -> bool {
    lower.contains("/tmp/ssh-") && lower.contains("/agent.")
}

fn contains_environment_exfiltration_source(lower: &str) -> bool {
    (lower.contains("env |") || lower.contains("printenv |"))
        && ["curl", "wget", "nc", "ncat", "netcat", "socat"]
            .iter()
            .any(|sink| lower.contains(sink))
}

fn contains_url_shortener(lower: &str) -> bool {
    [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
    ]
    .iter()
    .any(|domain| lower.contains(domain))
}

fn is_environment_source(command: &ExtractedCommand) -> bool {
    matches!(command_basename(&command.name).as_str(), "env" | "printenv")
}

fn is_remote_exfiltration_sink(command: &ExtractedCommand) -> bool {
    matches!(
        command_basename(&command.name).as_str(),
        "curl" | "wget" | "nc" | "ncat" | "netcat" | "socat"
    )
}

fn is_download_command(command: &ExtractedCommand) -> bool {
    matches!(
        command_basename(&command.name).as_str(),
        "curl" | "wget" | "fetch" | "aria2c"
    )
}

fn is_http_url(value: &str) -> bool {
    value.to_ascii_lowercase().starts_with("http://")
}

fn is_direct_ip_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let Some(rest) = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
    else {
        return false;
    };
    let host = rest.split(['/', ':', '?', '#']).next().unwrap_or_default();
    is_ipv4_literal(host)
}

fn is_ipv4_literal(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.parse::<u8>().is_ok())
}

fn suspicious_reverse_shell_port(value: &str) -> bool {
    matches!(value, "4444" | "8080" | "9001" | "1337" | "5555")
}

fn command_basename(name: &str) -> String {
    strip_quotes(name)
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn strip_quotes(value: &str) -> String {
    value
        .trim()
        .chars()
        .filter(|character| !matches!(character, '\'' | '"'))
        .collect()
}

fn command_text(command: &ExtractedCommand) -> String {
    let mut text = command.name.clone();
    for argument in &command.arguments {
        text.push(' ');
        text.push_str(argument);
    }
    text
}

#[derive(Clone, Copy)]
struct SourceFinding<'evidence> {
    id: &'static str,
    category: FindingCategory,
    severity: Severity,
    confidence: Confidence,
    title: &'static str,
    description: &'static str,
    evidence: &'evidence str,
    tag: &'static str,
}

fn source_finding(input: SourceFinding<'_>) -> Finding {
    Finding {
        id: input.id.to_owned(),
        detector: DETECTOR_ID.to_owned(),
        category: input.category,
        severity: input.severity,
        confidence: input.confidence,
        title: input.title.to_owned(),
        description: input.description.to_owned(),
        evidence: vec![Evidence {
            kind: EvidenceKind::SourceSnippet,
            description: "matched shell source".to_owned(),
            content: Some(input.evidence.to_owned()),
        }],
        artifact_sha256: Sha256Digest::new([0; 32]),
        location: None,
        remediation: None,
        references: Vec::new(),
        tags: vec!["shell-credential".to_owned(), input.tag.to_owned()],
        taxonomies: cwe_for_category(input.category).into_iter().collect(),
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
        tags: vec!["shell-credential".to_owned(), input.tag.to_owned()],
        taxonomies: cwe_for_category(input.category).into_iter().collect(),
    }
}
