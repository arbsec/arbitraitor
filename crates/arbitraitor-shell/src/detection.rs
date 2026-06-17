//! Detection rules for suspicious shell execution chains.

use std::collections::BTreeSet;

use arbitraitor_model::finding::{Evidence, EvidenceKind, Finding, FindingCategory};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity};

use crate::{DecodeKind, ExtractedCommand, NormalizationResult, SourceSpan};

const DETECTOR_ID: &str = "arbitraitor-shell.detection";

/// Detects dynamic execution and decode-to-execute shell patterns.
#[must_use]
pub fn detect(normalize_result: &NormalizationResult, source: &str) -> Vec<Finding> {
    let mut state = DetectionState {
        normalize_result,
        source,
        findings: Vec::new(),
        emitted: BTreeSet::new(),
    };
    state.detect_eval_usage();
    state.detect_source_from_risky_inputs();
    state.detect_process_substitution_network_retrieval();
    state.detect_variable_command_execution();
    state.detect_decode_to_execute();
    state.detect_download_to_execute();
    state.detect_chmod_then_execute_download();
    state.findings
}

struct DetectionState<'a> {
    normalize_result: &'a NormalizationResult,
    source: &'a str,
    findings: Vec<Finding>,
    emitted: BTreeSet<String>,
}

impl DetectionState<'_> {
    fn detect_eval_usage(&mut self) {
        let commands = self.commands().to_vec();
        for (index, command) in commands.iter().enumerate() {
            if command.name == "eval" {
                self.push(CommandFinding {
                    id: format!("dynamic-eval-{index}"),
                    category: FindingCategory::DynamicCodeExecution,
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    title: "Shell eval executes dynamically constructed code",
                    description: "The script invokes eval, which reparses attacker-controlled strings as shell code and can bypass static inspection boundaries.",
                    command: command.clone(),
                    evidence_kind: EvidenceKind::Command,
                    tag: "eval",
                });
            }
        }
    }

    fn detect_source_from_risky_inputs(&mut self) {
        let downloaded_paths = self.downloaded_paths();
        let commands = self.commands().to_vec();
        for (index, command) in commands.iter().enumerate() {
            if !is_source_command(&command.name) {
                continue;
            }
            if command.arguments.iter().any(|argument| {
                is_writable_path(argument)
                    || downloaded_paths.contains(argument)
                    || looks_like_process_substitution(argument)
            }) {
                self.push(CommandFinding {
                    id: format!("dynamic-source-risky-{index}"),
                    category: FindingCategory::DynamicCodeExecution,
                    severity: Severity::High,
                    confidence: Confidence::High,
                    title: "Shell source loads code from a writable or downloaded path",
                    description: "The script sources another shell file from a location that may be attacker-controlled, causing that file to execute in the current shell context.",
                    command: command.clone(),
                    evidence_kind: EvidenceKind::Command,
                    tag: "source-risky-input",
                });
            }
        }
    }

    fn detect_process_substitution_network_retrieval(&mut self) {
        let commands = self.commands().to_vec();
        for (index, command) in commands.iter().enumerate() {
            if is_network_retrieval(command)
                && command_starts_in_process_substitution(self.source, command)
            {
                self.push(CommandFinding {
                    id: format!("dynamic-process-substitution-network-{index}"),
                    category: FindingCategory::DynamicCodeExecution,
                    severity: Severity::Critical,
                    confidence: Confidence::Confirmed,
                    title: "Process substitution retrieves network content",
                    description: "The script feeds content fetched by curl or wget through process substitution, a shell data-flow mechanism that can hide download-to-execute behavior from simple pipe analysis.",
                    command: command.clone(),
                    evidence_kind: EvidenceKind::Command,
                    tag: "process-substitution-network",
                });
            }
        }
    }

    fn detect_variable_command_execution(&mut self) {
        let commands = self.commands().to_vec();
        for (index, command) in commands.iter().enumerate() {
            if command_invoked_from_variable(self.source, command)
                && command_name_looks_constructed(&command.name)
            {
                self.push(CommandFinding {
                    id: format!("dynamic-variable-command-{index}"),
                    category: FindingCategory::DynamicCodeExecution,
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    title: "Shell command is constructed through variables before execution",
                    description: "The command position expands a variable whose value appears to contain executable shell words, making the executed program depend on prior string construction.",
                    command: command.clone(),
                    evidence_kind: EvidenceKind::Command,
                    tag: "variable-command-construction",
                });
            }
        }
    }

    fn detect_decode_to_execute(&mut self) {
        let artifacts = self.normalize_result.decoded_artifacts.clone();
        for artifact in &artifacts {
            if !is_executable_decode_kind(artifact.kind) {
                continue;
            }
            let Some(decoder_index) = artifact.source_command_index else {
                continue;
            };
            if let Some(executor) = self.decode_executor(decoder_index, &artifact.parent_span) {
                let executor_command = executor.clone();
                self.push(CommandFinding {
                    id: format!("decode-to-execute-{decoder_index}"),
                    category: FindingCategory::DynamicCodeExecution,
                    severity: Severity::Critical,
                    confidence: Confidence::Confirmed,
                    title: "Decoded payload is executed by the shell",
                    description: "The script decodes base64, hexadecimal, or OpenSSL-encoded content and immediately passes the decoded bytes to a shell execution primitive.",
                    command: executor_command,
                    evidence_kind: EvidenceKind::DecodedContent,
                    tag: "decode-to-execute",
                });
            }
        }
    }

    fn detect_download_to_execute(&mut self) {
        let edges = self.normalize_result.data_flow.edges.clone();
        for (from, to) in &edges {
            let Some(producer) = self.commands().get(*from).cloned() else {
                continue;
            };
            let Some(consumer) = self.commands().get(*to).cloned() else {
                continue;
            };
            if is_network_retrieval(&producer) && is_shell_executor(&consumer.name) {
                self.push(CommandFinding {
                    id: format!("download-pipe-execute-{from}-{to}"),
                    category: FindingCategory::DynamicCodeExecution,
                    severity: Severity::High,
                    confidence: Confidence::High,
                    title: "Downloaded content is piped directly to a shell",
                    description: "The script streams content from curl or wget into a shell interpreter, collapsing retrieval, inspection, and execution into one operation.",
                    command: consumer,
                    evidence_kind: EvidenceKind::Command,
                    tag: "download-to-execute",
                });
            }
        }

        let downloaded_paths = self.downloaded_paths();
        let commands = self.commands().to_vec();
        for (index, command) in commands.iter().enumerate() {
            if command_executes_path(command, &downloaded_paths) {
                self.push(CommandFinding {
                    id: format!("downloaded-file-execute-{index}"),
                    category: FindingCategory::DynamicCodeExecution,
                    severity: Severity::High,
                    confidence: Confidence::High,
                    title: "Downloaded file is executed",
                    description: "The script executes a file path that was previously written by curl or wget, bypassing an explicit inspection step between download and execution.",
                    command: command.clone(),
                    evidence_kind: EvidenceKind::Command,
                    tag: "downloaded-file-execution",
                });
            }
        }
    }

    fn detect_chmod_then_execute_download(&mut self) {
        let downloaded_paths = self.downloaded_paths();
        let chmod_paths = chmod_executable_paths(self.commands(), &downloaded_paths);
        let commands = self.commands().to_vec();
        for (index, command) in commands.iter().enumerate() {
            if command_executes_path(command, &chmod_paths) {
                self.push(CommandFinding {
                    id: format!("download-chmod-execute-{index}"),
                    category: FindingCategory::DynamicCodeExecution,
                    severity: Severity::High,
                    confidence: Confidence::High,
                    title: "Downloaded file is made executable and run",
                    description: "The script downloads a file, marks it executable with chmod +x, then runs it. This is a common installer and malware execution chain.",
                    command: command.clone(),
                    evidence_kind: EvidenceKind::Command,
                    tag: "download-chmod-execute",
                });
            }
        }
    }

    fn decode_executor(
        &self,
        decoder_index: usize,
        decoder_span: &SourceSpan,
    ) -> Option<&ExtractedCommand> {
        self.reachable_shell_executor(decoder_index)
            .or_else(|| self.containing_eval(decoder_span))
    }

    fn reachable_shell_executor(&self, start: usize) -> Option<&ExtractedCommand> {
        let mut stack = vec![start];
        let mut seen = BTreeSet::new();
        while let Some(index) = stack.pop() {
            if !seen.insert(index) {
                continue;
            }
            for (from, to) in &self.normalize_result.data_flow.edges {
                if *from != index {
                    continue;
                }
                let command = self.commands().get(*to)?;
                if is_shell_executor(&command.name) || command.name == "eval" {
                    return Some(command);
                }
                stack.push(*to);
            }
        }
        None
    }

    fn containing_eval(&self, span: &SourceSpan) -> Option<&ExtractedCommand> {
        self.commands().iter().find(|command| {
            command.name == "eval"
                && command.span.byte_range.start <= span.byte_range.start
                && command.span.byte_range.end >= span.byte_range.end
        })
    }

    fn downloaded_paths(&self) -> BTreeSet<String> {
        let mut paths = BTreeSet::new();
        for command in self
            .commands()
            .iter()
            .filter(|command| is_network_retrieval(command))
        {
            paths.extend(download_output_paths(command));
        }
        paths
    }

    fn commands(&self) -> &[ExtractedCommand] {
        &self.normalize_result.commands
    }

    fn push(&mut self, input: CommandFinding<'_>) {
        if !self.emitted.insert(input.id.clone()) {
            return;
        }
        let snippet = source_for_span(self.source, &input.command.span);
        self.findings.push(Finding {
            id: input.id,
            detector: DETECTOR_ID.to_owned(),
            category: input.category,
            severity: input.severity,
            confidence: input.confidence,
            title: input.title.to_owned(),
            description: input.description.to_owned(),
            evidence: vec![Evidence {
                kind: input.evidence_kind,
                description: evidence_description(&input.command.span),
                content: Some(snippet),
            }],
            artifact_sha256: Sha256Digest::new([0; 32]),
            location: Some(input.command.span.location.clone()),
            remediation: None,
            references: Vec::new(),
            tags: vec!["shell-detection".to_owned(), input.tag.to_owned()],
        });
    }
}

struct CommandFinding<'a> {
    id: String,
    category: FindingCategory,
    severity: Severity,
    confidence: Confidence,
    title: &'a str,
    description: &'a str,
    command: ExtractedCommand,
    evidence_kind: EvidenceKind,
    tag: &'a str,
}

fn source_for_span(source: &str, span: &SourceSpan) -> String {
    source
        .get(span.byte_range.clone())
        .map_or_else(|| format_command_fallback(span), ToOwned::to_owned)
}

fn format_command_fallback(span: &SourceSpan) -> String {
    format!(
        "source bytes {}..{}",
        span.byte_range.start, span.byte_range.end
    )
}

fn evidence_description(span: &SourceSpan) -> String {
    format!(
        "source line {}, column {}, bytes {}..{}",
        span.location.line, span.location.column, span.byte_range.start, span.byte_range.end
    )
}

fn is_source_command(name: &str) -> bool {
    matches!(name, "source" | ".")
}

fn is_shell_executor(name: &str) -> bool {
    matches!(name, "sh" | "bash" | "dash" | "ash" | "zsh" | "ksh")
}

fn is_network_retrieval(command: &ExtractedCommand) -> bool {
    matches!(command.name.as_str(), "curl" | "wget")
        && command.arguments.iter().any(|argument| is_url(argument))
}

fn is_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

fn is_writable_path(value: &str) -> bool {
    let path = strip_quotes(value);
    path.starts_with("/tmp/")
        || path == "/tmp"
        || path.starts_with("/var/tmp/")
        || path == "/var/tmp"
        || path.starts_with("/dev/shm/")
        || path == "/dev/shm"
}

fn looks_like_process_substitution(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("<(") || trimmed.starts_with(">(")
}

fn command_starts_in_process_substitution(source: &str, command: &ExtractedCommand) -> bool {
    let Some(prefix) = source.get(..command.span.byte_range.start) else {
        return false;
    };
    let trimmed = prefix.trim_end();
    trimmed.ends_with("<(") || trimmed.ends_with(">(")
}

fn command_invoked_from_variable(source: &str, command: &ExtractedCommand) -> bool {
    source
        .get(command.span.byte_range.clone())
        .is_some_and(|text| text.trim_start().starts_with('$'))
}

fn command_name_looks_constructed(name: &str) -> bool {
    name.chars().any(char::is_whitespace)
        || name.contains(';')
        || name.contains('|')
        || name.contains("&&")
        || name.contains('$')
}

fn is_executable_decode_kind(kind: DecodeKind) -> bool {
    matches!(
        kind,
        DecodeKind::Base64 | DecodeKind::Hex | DecodeKind::OpenSsl
    )
}

fn download_output_paths(command: &ExtractedCommand) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    let mut iter = command.arguments.iter().peekable();
    while let Some(argument) = iter.next() {
        if argument == "-o"
            || argument == "--output"
            || argument == "-O"
            || argument == "--output-document"
        {
            if let Some(path) = iter.peek() {
                insert_download_path(&mut paths, path);
            }
            continue;
        }
        if let Some(path) = argument.strip_prefix("-o") {
            insert_download_path(&mut paths, path);
        }
        if let Some(path) = argument.strip_prefix("--output=") {
            insert_download_path(&mut paths, path);
        }
        if let Some(path) = argument.strip_prefix("--output-document=") {
            insert_download_path(&mut paths, path);
        }
    }
    paths
}

fn insert_download_path(paths: &mut BTreeSet<String>, path: &str) {
    let stripped = strip_quotes(path);
    if !stripped.is_empty() && stripped != "-" {
        paths.insert(stripped);
    }
}

fn strip_quotes(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        if matches!(
            (bytes[0], bytes[trimmed.len() - 1]),
            (b'\'', b'\'') | (b'"', b'"')
        ) {
            return trimmed[1..trimmed.len() - 1].to_owned();
        }
    }
    trimmed.to_owned()
}

fn command_executes_path(command: &ExtractedCommand, paths: &BTreeSet<String>) -> bool {
    if paths.is_empty() {
        return false;
    }
    if paths.contains(command.name.as_str()) {
        return true;
    }
    is_shell_executor(&command.name)
        && command.arguments.iter().any(|argument| {
            let stripped = strip_quotes(argument);
            paths.contains(stripped.as_str())
        })
}

fn chmod_executable_paths(
    commands: &[ExtractedCommand],
    paths: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut executable_paths = BTreeSet::new();
    for command in commands.iter().filter(|command| command.name == "chmod") {
        if !command
            .arguments
            .iter()
            .any(|argument| chmod_adds_execute(argument))
        {
            continue;
        }
        for argument in &command.arguments {
            let path = strip_quotes(argument);
            if paths.contains(path.as_str()) {
                executable_paths.insert(path);
            }
        }
    }
    executable_paths
}

fn chmod_adds_execute(argument: &str) -> bool {
    argument.contains("+x") || argument.contains("+X") || argument == "755" || argument == "0755"
}
