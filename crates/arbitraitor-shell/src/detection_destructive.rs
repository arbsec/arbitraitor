//! Detection rules for destructive and obfuscated shell behavior.

use std::collections::BTreeSet;
use std::path::Path;

use arbitraitor_model::finding::{Evidence, EvidenceKind, Finding, FindingCategory};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity};

use crate::{ExtractedCommand, NormalizeResult};

const DETECTOR_ID: &str = "arbitraitor-shell.destructive";

/// Detects destructive commands, detached network execution, generated scripts,
/// shell obfuscation, and executable Unicode deception patterns.
#[must_use]
pub fn detect_destructive_threats(
    normalize_result: &NormalizeResult,
    source: &str,
) -> Vec<Finding> {
    let mut state = DetectionState {
        normalize_result,
        source,
        findings: Vec::new(),
        emitted: BTreeSet::new(),
    };

    state.detect_destructive_commands();
    state.detect_hidden_network_execution();
    state.detect_heredoc_generated_scripts();
    state.detect_string_obfuscation();
    state.detect_unicode_deception();
    state.findings
}

struct DetectionState<'a> {
    normalize_result: &'a NormalizeResult,
    source: &'a str,
    findings: Vec<Finding>,
    emitted: BTreeSet<String>,
}

impl DetectionState<'_> {
    fn detect_destructive_commands(&mut self) {
        let commands = self.normalize_result.commands.clone();
        for (index, command) in commands.iter().enumerate() {
            if destructive_rm(command) {
                self.push_command(CommandFinding {
                    id: format!("destructive-rm-{index}"),
                    category: FindingCategory::DestructiveBehavior,
                    severity: Severity::Critical,
                    confidence: Confidence::Confirmed,
                    title: "Shell recursively deletes root or home directory",
                    description: "The script invokes rm with recursive and force flags against /, /*, ~, or $HOME, which can destroy the host filesystem or user home.",
                    evidence_kind: EvidenceKind::Command,
                    command,
                    tag: "destructive-rm",
                });
            }
            if destructive_mkfs(command) {
                self.push_command(CommandFinding {
                    id: format!("destructive-mkfs-{index}"),
                    category: FindingCategory::DestructiveBehavior,
                    severity: Severity::Critical,
                    confidence: Confidence::Confirmed,
                    title: "Shell formats a block device",
                    description: "The script invokes mkfs against a block device path such as /dev/sd*, /dev/nvme*, or /dev/vd*, which destroys existing data.",
                    evidence_kind: EvidenceKind::Command,
                    command,
                    tag: "destructive-mkfs",
                });
            }
            if destructive_dd_wipe(command) {
                self.push_command(CommandFinding {
                    id: format!("destructive-dd-wipe-{index}"),
                    category: FindingCategory::DestructiveBehavior,
                    severity: Severity::Critical,
                    confidence: Confidence::Confirmed,
                    title: "Shell overwrites a disk with zeroes",
                    description: "The script uses dd with if=/dev/zero and a block-device output path, a direct disk wipe pattern.",
                    evidence_kind: EvidenceKind::Command,
                    command,
                    tag: "destructive-dd-wipe",
                });
            }
            if destructive_chmod_root(command) {
                self.push_command(CommandFinding {
                    id: format!("destructive-chmod-root-{index}"),
                    category: FindingCategory::DestructiveBehavior,
                    severity: Severity::Critical,
                    confidence: Confidence::Confirmed,
                    title: "Shell removes permissions recursively from root",
                    description: "The script invokes chmod -R 000 /, which can render the system unusable.",
                    evidence_kind: EvidenceKind::Command,
                    command,
                    tag: "destructive-chmod-root",
                });
            }
        }

        for (line_index, line) in executable_lines(self.source).enumerate() {
            if looks_like_fork_bomb(line) {
                self.push_source(SourceFinding {
                    id: format!("destructive-fork-bomb-{line_index}"),
                    category: FindingCategory::DestructiveBehavior,
                    severity: Severity::Critical,
                    confidence: Confidence::Confirmed,
                    title: "Shell defines and launches a fork bomb",
                    description: "The script contains a recursive function that backgrounds copies of itself, exhausting process table resources.",
                    evidence_kind: EvidenceKind::SourceSnippet,
                    evidence: line,
                    tag: "fork-bomb",
                });
            }
        }
    }

    fn detect_hidden_network_execution(&mut self) {
        let commands = self.normalize_result.commands.clone();
        for (index, command) in commands.iter().enumerate() {
            if hidden_network_wrapper(command, "nohup") {
                self.push_command(hidden_execution_finding(
                    format!("hidden-nohup-network-{index}"),
                    "nohup starts network retrieval as a detached process",
                    command,
                    "nohup-network",
                ));
            }
            if hidden_network_wrapper(command, "setsid") {
                self.push_command(hidden_execution_finding(
                    format!("hidden-setsid-network-{index}"),
                    "setsid starts network retrieval outside the current session",
                    command,
                    "setsid-network",
                ));
            }
        }

        let lines: Vec<&str> = executable_lines(self.source).collect();
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if line_ends_backgrounded_network(trimmed) {
                self.push_source(hidden_execution_source_finding(
                    format!("hidden-background-network-{index}"),
                    "Network retrieval runs in the background",
                    trimmed,
                    "background-network",
                ));
            }
            if index > 0
                && starts_with_command(trimmed, "disown")
                && previous_background(&lines, index)
            {
                self.push_source(hidden_execution_source_finding(
                    format!("hidden-disown-background-{index}"),
                    "Shell disowns a background process",
                    trimmed,
                    "disown-background",
                ));
            }
        }
    }

    fn detect_heredoc_generated_scripts(&mut self) {
        let writes = heredoc_script_writes(self.source);
        for (line_index, path, evidence) in writes {
            if later_executes_path(self.source, line_index, &path) {
                self.push_source(SourceFinding {
                    id: format!("heredoc-generated-script-{line_index}"),
                    category: FindingCategory::DynamicCodeExecution,
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    title: "Shell executes a script generated from a heredoc",
                    description: "The script writes heredoc content to a file and later executes that generated file, hiding executable content behind file creation.",
                    evidence_kind: EvidenceKind::SourceSnippet,
                    evidence: &evidence,
                    tag: "heredoc-generated-script",
                });
            }
        }
    }

    fn detect_string_obfuscation(&mut self) {
        for (index, line) in executable_lines(self.source).enumerate() {
            let trimmed = line.trim();
            if variable_concatenates_command_name(trimmed) {
                self.push_source(obfuscation_finding(
                    format!("obfuscation-variable-command-concat-{index}"),
                    "Shell builds a command name from concatenated variables",
                    trimmed,
                    "variable-command-concat",
                ));
            }
            if command_name_uses_hex_printf(trimmed) {
                self.push_source(obfuscation_finding(
                    format!("obfuscation-hex-printf-command-{index}"),
                    "Shell command name is produced from hexadecimal character escapes",
                    trimmed,
                    "hex-printf-command",
                ));
            }
            if command_name_uses_ansi_c_hex(trimmed) {
                self.push_source(obfuscation_finding(
                    format!("obfuscation-ansi-c-command-{index}"),
                    "Shell command name uses ANSI-C hexadecimal escapes",
                    trimmed,
                    "ansi-c-hex-command",
                ));
            }
        }
    }

    fn detect_unicode_deception(&mut self) {
        for (index, line) in executable_lines(self.source).enumerate() {
            let Some(command_word) = executable_command_word(line) else {
                continue;
            };
            if unicode_deceptive_command_word(command_word) {
                self.push_source(SourceFinding {
                    id: format!("unicode-deceptive-command-{index}"),
                    category: FindingCategory::Obfuscation,
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    title: "Shell command name contains deceptive Unicode characters",
                    description: "The executable command position contains homoglyphs, zero-width controls, right-to-left override, or excessive non-ASCII characters that can conceal the invoked program.",
                    evidence_kind: EvidenceKind::SourceSnippet,
                    evidence: line.trim(),
                    tag: "unicode-deception",
                });
            }
        }
    }

    fn push_command(&mut self, input: CommandFinding<'_>) {
        if self.emitted.insert(input.id.clone()) {
            self.findings.push(command_finding(input));
        }
    }

    fn push_source(&mut self, input: SourceFinding<'_>) {
        if self.emitted.insert(input.id.clone()) {
            self.findings.push(source_finding(input));
        }
    }
}

fn destructive_rm(command: &ExtractedCommand) -> bool {
    command_basename(&command.name) == "rm"
        && has_recursive_force_flags(&command.arguments)
        && command.arguments.iter().any(|argument| {
            matches!(
                strip_quotes(argument).as_str(),
                "/" | "/*" | "~" | "$HOME" | "${HOME}"
            )
        })
}

fn destructive_mkfs(command: &ExtractedCommand) -> bool {
    command_basename(&command.name).starts_with("mkfs")
        && command
            .arguments
            .iter()
            .any(|argument| is_block_device(&strip_quotes(argument)))
}

fn destructive_dd_wipe(command: &ExtractedCommand) -> bool {
    command_basename(&command.name) == "dd"
        && command
            .arguments
            .iter()
            .any(|argument| strip_quotes(argument) == "if=/dev/zero")
        && command.arguments.iter().any(|argument| {
            strip_quotes(argument)
                .strip_prefix("of=")
                .is_some_and(is_block_device)
        })
}

fn destructive_chmod_root(command: &ExtractedCommand) -> bool {
    command_basename(&command.name) == "chmod"
        && command.arguments.iter().any(|argument| argument == "-R")
        && command
            .arguments
            .iter()
            .any(|argument| strip_quotes(argument) == "000")
        && command
            .arguments
            .iter()
            .any(|argument| strip_quotes(argument) == "/")
}

fn has_recursive_force_flags(arguments: &[String]) -> bool {
    arguments.iter().any(|argument| {
        let stripped = strip_quotes(argument);
        stripped.starts_with('-') && stripped.contains('r') && stripped.contains('f')
    }) || arguments
        .iter()
        .any(|argument| matches!(argument.as_str(), "-r" | "-R" | "--recursive"))
        && arguments
            .iter()
            .any(|argument| matches!(argument.as_str(), "-f" | "--force"))
}

fn is_block_device(value: &str) -> bool {
    value.starts_with("/dev/sd") || value.starts_with("/dev/nvme") || value.starts_with("/dev/vd")
}

fn looks_like_fork_bomb(line: &str) -> bool {
    let compact: String = line
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    compact.contains(":(){:|:&};:") || compact.contains("bomb(){bomb|bomb&};bomb")
}

fn hidden_network_wrapper(command: &ExtractedCommand, wrapper: &str) -> bool {
    command_basename(&command.name) == wrapper
        && command
            .arguments
            .iter()
            .any(|argument| matches!(command_basename(argument).as_str(), "curl" | "wget"))
        && command.arguments.iter().any(|argument| is_url(argument))
}

fn hidden_execution_finding<'a>(
    id: String,
    title: &'static str,
    command: &'a ExtractedCommand,
    tag: &'static str,
) -> CommandFinding<'a> {
    CommandFinding {
        id,
        category: FindingCategory::Persistence,
        severity: Severity::High,
        confidence: Confidence::High,
        title,
        description: "The script combines network retrieval with detached or hidden process execution, which can persist activity after the parent shell exits.",
        evidence_kind: EvidenceKind::Command,
        command,
        tag,
    }
}

fn hidden_execution_source_finding<'a>(
    id: String,
    title: &'static str,
    evidence: &'a str,
    tag: &'static str,
) -> SourceFinding<'a> {
    SourceFinding {
        id,
        category: FindingCategory::Persistence,
        severity: Severity::High,
        confidence: Confidence::High,
        title,
        description: "The script combines background process control with network behavior, hiding execution from the invoking shell session.",
        evidence_kind: EvidenceKind::SourceSnippet,
        evidence,
        tag,
    }
}

fn line_ends_backgrounded_network(line: &str) -> bool {
    line.ends_with('&') && contains_network_retrieval(line)
}

fn previous_background(lines: &[&str], index: usize) -> bool {
    lines[..index]
        .iter()
        .rev()
        .find(|line| !line.trim().is_empty())
        .is_some_and(|line| line.trim().ends_with('&'))
}

fn contains_network_retrieval(line: &str) -> bool {
    (contains_command_word(line, "curl") || contains_command_word(line, "wget"))
        && (line.contains("http://") || line.contains("https://"))
}

fn heredoc_script_writes(source: &str) -> Vec<(usize, String, String)> {
    let mut writes = Vec::new();
    for (line_index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.contains("<<") || !trimmed.contains('>') {
            continue;
        }
        if let Some(path) = redirected_path(trimmed).filter(|path| executable_script_path(path)) {
            writes.push((line_index, path.to_owned(), trimmed.to_owned()));
        }
    }
    writes
}

fn redirected_path(line: &str) -> Option<&str> {
    let (_, tail) = line.rsplit_once('>')?;
    tail.split_whitespace().next().map(strip_quotes_ref)
}

fn later_executes_path(source: &str, line_index: usize, path: &str) -> bool {
    source
        .lines()
        .skip(line_index.saturating_add(1))
        .any(|line| {
            let trimmed = line.trim();
            starts_with_command_then_arg(trimmed, "bash", path)
                || starts_with_command_then_arg(trimmed, "sh", path)
                || starts_with_command(trimmed, path)
                || trimmed.contains(&format!("&& {path}"))
                || trimmed.contains(&format!("; {path}"))
        })
}

fn executable_script_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("sh"))
        || path.starts_with("/tmp/")
        || path.starts_with("./")
}

fn variable_concatenates_command_name(line: &str) -> bool {
    let has_assignment = line
        .split(';')
        .any(|part| part.trim().contains('=') && !part.trim().starts_with('$'));
    has_assignment
        && command_segments(line)
            .into_iter()
            .any(|segment| starts_with_adjacent_variable_expansions(segment.trim()))
}

fn command_name_uses_hex_printf(line: &str) -> bool {
    command_segments(line).into_iter().any(|segment| {
        let trimmed = segment.trim_start();
        trimmed.starts_with("$(printf") && trimmed.contains("\\x")
    })
}

fn command_name_uses_ansi_c_hex(line: &str) -> bool {
    command_segments(line).into_iter().any(|segment| {
        let trimmed = segment.trim_start();
        trimmed.starts_with("$'\\x") || trimmed.starts_with("$\"\\x")
    })
}

fn starts_with_adjacent_variable_expansions(segment: &str) -> bool {
    let rest = segment.strip_prefix('$');
    let Some(rest) = rest else {
        return false;
    };
    if let Some(close) = rest.strip_prefix('{').and_then(|value| value.find('}')) {
        return rest
            .get(close.saturating_add(2)..)
            .is_some_and(|tail| tail.starts_with('$'));
    }
    rest.chars()
        .position(|character| !is_shell_name_char(character))
        .is_some_and(|position| {
            rest.get(position..)
                .is_some_and(|tail| tail.starts_with('$'))
        })
}

fn obfuscation_finding<'a>(
    id: String,
    title: &'static str,
    evidence: &'a str,
    tag: &'static str,
) -> SourceFinding<'a> {
    SourceFinding {
        id,
        category: FindingCategory::Obfuscation,
        severity: Severity::High,
        confidence: Confidence::Medium,
        title,
        description: "The script constructs executable command text through shell string obfuscation, reducing static readability and bypassing simple command-name matching.",
        evidence_kind: EvidenceKind::SourceSnippet,
        evidence,
        tag,
    }
}

fn unicode_deceptive_command_word(command_word: &str) -> bool {
    let non_ascii_count = command_word
        .chars()
        .filter(|character| !character.is_ascii())
        .count();
    has_zero_width_or_bidi(command_word)
        || command_word.chars().any(is_confusable_cyrillic)
        || (non_ascii_count >= 2 && command_word.chars().count() >= 3)
}

fn has_zero_width_or_bidi(value: &str) -> bool {
    value.chars().any(|character| {
        matches!(
            character,
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{202E}'
        )
    })
}

fn is_confusable_cyrillic(character: char) -> bool {
    matches!(character, 'а' | 'е' | 'о' | 'р' | 'с' | 'у' | 'х')
}

fn executable_command_word(line: &str) -> Option<&str> {
    let segment = command_segments(line).into_iter().next()?;
    let trimmed = segment.trim_start();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with("echo ")
        || trimmed.starts_with("printf ")
    {
        return None;
    }
    let first = trimmed.split_whitespace().next()?;
    if first.contains('=') && !first.starts_with('$') {
        return trimmed.split_whitespace().nth(1);
    }
    Some(first)
}

fn executable_lines(source: &str) -> impl Iterator<Item = &str> {
    source.lines().filter(|line| {
        let trimmed = line.trim();
        !trimmed.is_empty() && !trimmed.starts_with('#')
    })
}

fn command_segments(line: &str) -> Vec<&str> {
    line.split([';', '|']).collect()
}

fn starts_with_command(line: &str, command: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed == command
        || trimmed
            .strip_prefix(command)
            .is_some_and(|tail| tail.starts_with(char::is_whitespace))
}

fn starts_with_command_then_arg(line: &str, command: &str, argument: &str) -> bool {
    let mut words = line.split_whitespace();
    matches!((words.next(), words.next()), (Some(first), Some(second)) if first == command && strip_quotes_ref(second) == argument)
}

fn contains_command_word(line: &str, command: &str) -> bool {
    line.split(|character: char| !is_shell_name_char(character) && character != '/')
        .any(|word| command_basename(word) == command)
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
        .trim_matches(|character| matches!(character, '\'' | '"'))
        .to_owned()
}

fn strip_quotes_ref(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, '\'' | '"'))
}

fn is_shell_name_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

fn is_url(value: &str) -> bool {
    let stripped = strip_quotes(value);
    stripped.starts_with("http://") || stripped.starts_with("https://")
}

fn command_text(command: &ExtractedCommand) -> String {
    let mut text = command.name.clone();
    for argument in &command.arguments {
        text.push(' ');
        text.push_str(argument);
    }
    text
}

struct CommandFinding<'command> {
    id: String,
    category: FindingCategory,
    severity: Severity,
    confidence: Confidence,
    title: &'static str,
    description: &'static str,
    evidence_kind: EvidenceKind,
    command: &'command ExtractedCommand,
    tag: &'static str,
}

fn command_finding(input: CommandFinding<'_>) -> Finding {
    Finding {
        id: input.id,
        detector: DETECTOR_ID.to_owned(),
        category: input.category,
        severity: input.severity,
        confidence: input.confidence,
        title: input.title.to_owned(),
        description: input.description.to_owned(),
        evidence: vec![Evidence {
            kind: input.evidence_kind,
            description: "matched normalized command".to_owned(),
            content: Some(command_text(input.command)),
        }],
        artifact_sha256: Sha256Digest::new([0; 32]),
        location: Some(input.command.span.location.clone()),
        remediation: None,
        references: Vec::new(),
        tags: vec!["shell-destructive".to_owned(), input.tag.to_owned()],
    }
}

struct SourceFinding<'evidence> {
    id: String,
    category: FindingCategory,
    severity: Severity,
    confidence: Confidence,
    title: &'static str,
    description: &'static str,
    evidence_kind: EvidenceKind,
    evidence: &'evidence str,
    tag: &'static str,
}

fn source_finding(input: SourceFinding<'_>) -> Finding {
    Finding {
        id: input.id,
        detector: DETECTOR_ID.to_owned(),
        category: input.category,
        severity: input.severity,
        confidence: input.confidence,
        title: input.title.to_owned(),
        description: input.description.to_owned(),
        evidence: vec![Evidence {
            kind: input.evidence_kind,
            description: "matched shell source".to_owned(),
            content: Some(input.evidence.to_owned()),
        }],
        artifact_sha256: Sha256Digest::new([0; 32]),
        location: None,
        remediation: None,
        references: Vec::new(),
        tags: vec!["shell-destructive".to_owned(), input.tag.to_owned()],
    }
}
