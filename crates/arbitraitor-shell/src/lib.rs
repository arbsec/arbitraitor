//! POSIX shell script static analysis
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use core::fmt;
use core::num::NonZeroU32;
use std::ops::Range;

use arbitraitor_model::finding::{
    Evidence, EvidenceKind, Finding, FindingCategory, SourceLocation,
};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity};
use thiserror::Error;
use tracing::{debug, warn};
use tree_sitter::{LanguageError, Node, Parser, Point, Tree};

pub mod detection;
pub mod detection_credential;
pub mod detection_destructive;
mod detection_system;
pub mod explain;
mod normalization;
pub mod process_sub;
pub mod shellcheck;
mod templates;

pub use detection::detect;
pub use detection_credential::detect_credential_threats;
pub use detection_destructive::detect_destructive_threats;
pub use detection_system::detect_system_threats;
pub use explain::{ExplainabilityReport, FindingExplanation, explain_finding};
pub use normalization::{
    DecodeKind, DecodedArtifact, ExtractedCommand, ExtractedUrl, NormalizationResult,
    NormalizeError, PipeGraph, ShellAst, normalize,
};
pub use process_sub::{
    DataFlowEdge, DataFlowGraph, DataFlowMethod, ProcessSubstitution, ProcessSubstitutionRisk,
    RiskLevel, RiskPattern, SubstitutionDirection,
};
pub use shellcheck::{
    ShellCheckComment, ShellCheckFix, ShellCheckReplacement, ShellCheckReport, to_shellcheck_json,
};

/// Compatibility alias for the shell normalization output consumed by detectors.
pub type NormalizeResult = NormalizationResult;

const DEFAULT_MAX_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_MAX_DEPTH: usize = 128;
const DEFAULT_MAX_NODES: usize = 100_000;
const DETECTOR_ID: &str = "arbitraitor-shell.parser";

/// Shell dialect selected for parsing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ShellDialect {
    /// POSIX `sh` syntax.
    Sh,
    /// GNU Bash syntax.
    Bash,
    /// Zsh syntax; parsed with the Bash grammar fallback.
    Zsh,
    /// Dialect could not be inferred from the script.
    #[default]
    Unknown,
}

impl fmt::Display for ShellDialect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sh => formatter.write_str("sh"),
            Self::Bash => formatter.write_str("bash"),
            Self::Zsh => formatter.write_str("zsh"),
            Self::Unknown => formatter.write_str("unknown"),
        }
    }
}

/// Configuration for bounded shell parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParserConfig {
    /// Maximum input bytes accepted for parsing; larger inputs are rejected before parsing.
    pub max_bytes: usize,
    /// Maximum AST traversal depth.
    pub max_depth: usize,
    /// Maximum AST nodes visited while collecting typed wrappers and errors.
    pub max_nodes: usize,
    /// Artifact digest attached to parser findings when the caller has one.
    pub artifact_sha256: Sha256Digest,
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_nodes: DEFAULT_MAX_NODES,
            artifact_sha256: Sha256Digest::new([0; 32]),
        }
    }
}

/// Error returned when constructing a parser fails.
#[derive(Debug, Error)]
pub enum ParseSetupError {
    /// Tree-sitter rejected the configured shell grammar.
    #[error("tree-sitter rejected the bash grammar: {0}")]
    Grammar(#[from] LanguageError),
}

/// Reusable Tree-sitter shell parser.
pub struct ShellParser {
    parser: Parser,
    config: ParserConfig,
}

impl ShellParser {
    /// Builds a parser with default resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error if the embedded Bash grammar is incompatible with the
    /// linked Tree-sitter runtime.
    pub fn new() -> Result<Self, ParseSetupError> {
        Self::with_config(ParserConfig::default())
    }

    /// Builds a parser with explicit resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error if the embedded Bash grammar is incompatible with the
    /// linked Tree-sitter runtime.
    pub fn with_config(config: ParserConfig) -> Result<Self, ParseSetupError> {
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_bash::LANGUAGE.into())?;
        Ok(Self { parser, config })
    }

    /// Returns the active parser configuration.
    #[must_use]
    pub const fn config(&self) -> &ParserConfig {
        &self.config
    }

    /// Parses UTF-8 shell source.
    #[must_use]
    pub fn parse_str(&mut self, source: &str) -> ParseResult {
        self.parse_bytes(source.as_bytes())
    }

    /// Parses arbitrary shell bytes after strict UTF-8 validation and NUL handling.
    #[must_use]
    pub fn parse_bytes(&mut self, input: &[u8]) -> ParseResult {
        let mut findings = Vec::new();
        if input.len() > self.config.max_bytes {
            findings.push(input_too_large_finding(&self.config, input.len()));
            return rejected_result(findings, SourceStats::rejected_too_large(input.len()));
        }

        let sanitized = match sanitize_input(input, &self.config, &mut findings) {
            Ok(sanitized) => sanitized,
            Err(stats) => return rejected_result(findings, stats),
        };

        let dialect = detect_dialect(&sanitized.bytes);
        debug!(
            dialect = %dialect,
            raw_bytes = input.len(),
            parsed_bytes = sanitized.bytes.len(),
            "parsing shell source"
        );

        let tree = self.parser.parse(&sanitized.bytes, None);
        let Some(tree) = tree else {
            findings.push(make_finding(
                &self.config,
                FindingInput::new(
                    "parser-no-tree",
                    FindingCategory::ParserError,
                    Severity::Medium,
                    "Tree-sitter did not produce a parse tree",
                    "The shell parser failed to return a parse tree for this input.",
                ),
            ));
            return ParseResult {
                ast: Vec::new(),
                parse_errors: findings,
                detected_dialect: dialect,
                source_stats: sanitized.stats,
            };
        };

        let ast = collect_ast(&tree, &self.config, &mut findings);
        ParseResult {
            ast,
            parse_errors: findings,
            detected_dialect: dialect,
            source_stats: sanitized.stats,
        }
    }
}

/// Complete output from a shell parse operation.
#[derive(Clone, Debug, PartialEq)]
pub struct ParseResult {
    /// Bounded, typed AST node wrappers collected from the Tree-sitter tree.
    pub ast: Vec<ShellNode>,
    /// Parser, recovery, encoding, and resource-limit findings.
    pub parse_errors: Vec<Finding>,
    /// Dialect inferred from attacker-controlled source metadata for informational parser context only.
    ///
    /// Security policy must not trust this value; callers that need dialect-sensitive enforcement must
    /// require an explicit, trusted dialect selection and fail closed when it is absent.
    pub detected_dialect: ShellDialect,
    /// Statistics about the raw and sanitized source.
    pub source_stats: SourceStats,
}

/// Source size and sanitation statistics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceStats {
    /// Original input byte length.
    pub raw_bytes: usize,
    /// Bytes passed to Tree-sitter after bounded sanitization.
    pub parsed_bytes: usize,
    /// Number of NUL bytes replaced before parsing.
    pub nul_bytes_replaced: usize,
    /// Whether invalid UTF-8 caused parsing to be rejected.
    pub invalid_utf8_rejected: bool,
    /// Whether input exceeded [`ParserConfig::max_bytes`].
    pub truncated: bool,
    /// Count of line breaks in the sanitized source plus one for non-empty input.
    pub line_count: usize,
}

/// Common source span carried by every typed AST wrapper.
#[derive(Clone, Debug, PartialEq)]
pub struct SourceSpan {
    /// Zero-based byte range in the sanitized parsed source.
    pub byte_range: Range<usize>,
    /// One-based source location for explainability output.
    pub location: SourceLocation,
}

impl fmt::Display for SourceSpan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}@{}..{}",
            self.location.line, self.location.column, self.byte_range.start, self.byte_range.end
        )
    }
}

/// Typed shell AST node wrapper.
#[derive(Clone, Debug, PartialEq)]
pub enum ShellNode {
    /// Simple command, command, or declaration command.
    Command(CommandNode),
    /// Pipeline expression.
    Pipeline(PipelineNode),
    /// Redirection expression.
    Redirect(RedirectNode),
    /// Variable assignment expression.
    Assignment(AssignmentNode),
    /// Conditional expression.
    Conditional(ConditionalNode),
    /// Loop expression.
    Loop(LoopNode),
    /// Shell function definition.
    Function(FunctionNode),
    /// Heredoc redirection or body.
    Heredoc(HeredocNode),
    /// Process substitution expression.
    ProcessSubstitution(ProcessSubstitutionNode),
    /// Command substitution expression.
    CommandSubstitution(CommandSubstitutionNode),
}

impl ShellNode {
    /// Returns this node's span.
    #[must_use]
    pub const fn span(&self) -> &SourceSpan {
        match self {
            Self::Command(node) => &node.span,
            Self::Pipeline(node) => &node.span,
            Self::Redirect(node) => &node.span,
            Self::Assignment(node) => &node.span,
            Self::Conditional(node) => &node.span,
            Self::Loop(node) => &node.span,
            Self::Function(node) => &node.span,
            Self::Heredoc(node) => &node.span,
            Self::ProcessSubstitution(node) => &node.span,
            Self::CommandSubstitution(node) => &node.span,
        }
    }
}

impl fmt::Display for ShellNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command(node) => node.fmt(formatter),
            Self::Pipeline(node) => node.fmt(formatter),
            Self::Redirect(node) => node.fmt(formatter),
            Self::Assignment(node) => node.fmt(formatter),
            Self::Conditional(node) => node.fmt(formatter),
            Self::Loop(node) => node.fmt(formatter),
            Self::Function(node) => node.fmt(formatter),
            Self::Heredoc(node) => node.fmt(formatter),
            Self::ProcessSubstitution(node) => node.fmt(formatter),
            Self::CommandSubstitution(node) => node.fmt(formatter),
        }
    }
}

macro_rules! ast_node {
    ($name:ident, $doc:literal, $display:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq)]
        pub struct $name {
            /// Tree-sitter node kind.
            pub kind: String,
            /// Node source span.
            pub span: SourceSpan,
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    concat!($display, "({} {})"),
                    self.kind, self.span
                )
            }
        }
    };
}

ast_node!(CommandNode, "A shell command node.", "command");
ast_node!(PipelineNode, "A shell pipeline node.", "pipeline");
ast_node!(RedirectNode, "A shell redirect node.", "redirect");
ast_node!(AssignmentNode, "A shell assignment node.", "assignment");
ast_node!(ConditionalNode, "A shell conditional node.", "conditional");
ast_node!(LoopNode, "A shell loop node.", "loop");
ast_node!(
    FunctionNode,
    "A shell function definition node.",
    "function"
);
ast_node!(HeredocNode, "A shell heredoc node.", "heredoc");
ast_node!(
    ProcessSubstitutionNode,
    "A shell process substitution node.",
    "process-substitution"
);
ast_node!(
    CommandSubstitutionNode,
    "A shell command substitution node.",
    "command-substitution"
);

fn detect_dialect(input: &[u8]) -> ShellDialect {
    let Some(first_line) = input.split(|byte| *byte == b'\n').next() else {
        return ShellDialect::Unknown;
    };
    if !first_line.starts_with(b"#!") {
        return ShellDialect::Unknown;
    }

    let shebang = String::from_utf8_lossy(first_line).to_ascii_lowercase();
    let words: Vec<&str> = shebang[2..].split_whitespace().collect();
    let command = if words
        .first()
        .is_some_and(|word| word.ends_with("/env") || *word == "env")
    {
        words
            .iter()
            .skip(1)
            .find(|word| !word.starts_with('-') && !word.contains('='))
            .copied()
    } else {
        words.first().copied()
    };

    command.map_or(ShellDialect::Unknown, |value| {
        let executable = value.rsplit('/').next().unwrap_or(value);
        match executable {
            "sh" | "dash" | "ash" | "busybox" => ShellDialect::Sh,
            "bash" => ShellDialect::Bash,
            "zsh" => ShellDialect::Zsh,
            _ => ShellDialect::Unknown,
        }
    })
}

struct SanitizedInput {
    bytes: Vec<u8>,
    stats: SourceStats,
}

fn sanitize_input(
    input: &[u8],
    config: &ParserConfig,
    findings: &mut Vec<Finding>,
) -> Result<SanitizedInput, SourceStats> {
    let source = match String::from_utf8(input.to_vec()) {
        Ok(source) => source,
        Err(error) => {
            findings.push(make_finding(
                config,
                FindingInput::new(
                    "encoding-invalid-utf8",
                    FindingCategory::ParserError,
                    Severity::Medium,
                    "Shell input contained invalid UTF-8",
                    "Input was rejected before parsing because byte offsets would be unreliable.",
                )
                .with_evidence(format!(
                    "invalid UTF-8 at byte {}",
                    error.utf8_error().valid_up_to()
                )),
            ));
            return Err(SourceStats {
                raw_bytes: input.len(),
                parsed_bytes: 0,
                nul_bytes_replaced: 0,
                invalid_utf8_rejected: true,
                truncated: false,
                line_count: 0,
            });
        }
    };

    let mut nul_bytes_replaced = 0_usize;
    for byte in source.as_bytes() {
        if *byte == 0 {
            nul_bytes_replaced = nul_bytes_replaced.saturating_add(1);
        }
    }
    let bytes = if nul_bytes_replaced == 0 {
        source.into_bytes()
    } else {
        let mut copy = source.into_bytes();
        for byte in &mut copy {
            if *byte == 0 {
                *byte = b' ';
            }
        }
        copy
    };

    if nul_bytes_replaced > 0 {
        findings.push(make_finding(
            config,
            FindingInput::new(
                "encoding-nul-bytes",
                FindingCategory::ParserError,
                Severity::Low,
                "Shell input contained NUL bytes",
                "NUL bytes were replaced with spaces before parsing.",
            )
            .with_evidence(format!("{nul_bytes_replaced} NUL byte(s) replaced")),
        ));
    }

    let line_count = if bytes.is_empty() {
        0
    } else {
        let mut newlines = 0_usize;
        for byte in &bytes {
            if *byte == b'\n' {
                newlines = newlines.saturating_add(1);
            }
        }
        newlines.saturating_add(1)
    };

    Ok(SanitizedInput {
        stats: SourceStats {
            raw_bytes: input.len(),
            parsed_bytes: bytes.len(),
            nul_bytes_replaced,
            invalid_utf8_rejected: false,
            truncated: false,
            line_count,
        },
        bytes,
    })
}

impl SourceStats {
    fn rejected_too_large(raw_bytes: usize) -> Self {
        Self {
            raw_bytes,
            parsed_bytes: 0,
            nul_bytes_replaced: 0,
            invalid_utf8_rejected: false,
            truncated: true,
            line_count: 0,
        }
    }
}

fn rejected_result(findings: Vec<Finding>, source_stats: SourceStats) -> ParseResult {
    ParseResult {
        ast: Vec::new(),
        parse_errors: findings,
        detected_dialect: ShellDialect::Unknown,
        source_stats,
    }
}

fn input_too_large_finding(config: &ParserConfig, raw_bytes: usize) -> Finding {
    warn!(
        raw_bytes,
        max_bytes = config.max_bytes,
        "shell input rejected before parsing"
    );
    make_finding(
        config,
        FindingInput::new(
            "resource-input-too-large",
            FindingCategory::ResourceLimitEvent,
            Severity::Medium,
            "Shell input exceeded parser byte limit",
            "Input was rejected before parsing to keep shell analysis bounded.",
        )
        .with_evidence(format!(
            "{raw_bytes} byte(s) exceeds limit of {}",
            config.max_bytes
        )),
    )
}

fn collect_ast(tree: &Tree, config: &ParserConfig, findings: &mut Vec<Finding>) -> Vec<ShellNode> {
    let root = tree.root_node();
    let mut ast = Vec::new();
    let mut stack = vec![(root, 0_usize)];
    let mut visited = 0_usize;
    let mut depth_limit_reported = false;

    while let Some((node, depth)) = stack.pop() {
        if visited >= config.max_nodes {
            findings.push(make_finding(
                config,
                FindingInput::new(
                    "resource-node-limit",
                    FindingCategory::ResourceLimitEvent,
                    Severity::Medium,
                    "Shell AST node limit reached",
                    "AST traversal stopped before visiting every node to keep parsing bounded.",
                )
                .with_span(span_for_node(node))
                .with_evidence(format!("visited {} node(s)", config.max_nodes)),
            ));
            break;
        }
        visited = visited.saturating_add(1);

        if node.is_error() || node.is_missing() {
            findings.push(parse_error_finding(config, node));
        }

        if let Some(shell_node) = classify_node(node) {
            ast.push(shell_node);
        }

        if depth >= config.max_depth {
            if !depth_limit_reported {
                findings.push(make_finding(
                    config,
                    FindingInput::new(
                        "resource-depth-limit",
                        FindingCategory::ResourceLimitEvent,
                        Severity::Medium,
                        "Shell AST depth limit reached",
                        "Nested shell syntax exceeded the parser traversal depth limit.",
                    )
                    .with_span(span_for_node(node))
                    .with_evidence(format!("maximum depth {} reached", config.max_depth)),
                ));
                depth_limit_reported = true;
            }
            continue;
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.children(&mut cursor).collect();
        while let Some(child) = children.pop() {
            stack.push((child, depth.saturating_add(1)));
        }
    }

    debug!(
        visited,
        ast_nodes = ast.len(),
        findings = findings.len(),
        "collected shell AST"
    );
    ast
}

fn classify_node(node: Node<'_>) -> Option<ShellNode> {
    let kind = node.kind();
    let span = span_for_node(node)?;
    let kind_string = kind.to_owned();
    match kind {
        "command" | "simple_command" | "declaration_command" => {
            Some(ShellNode::Command(CommandNode {
                kind: kind_string,
                span,
            }))
        }
        "pipeline" => Some(ShellNode::Pipeline(PipelineNode {
            kind: kind_string,
            span,
        })),
        "redirected_statement" | "file_redirect" | "heredoc_redirect" | "herestring_redirect" => {
            if kind == "heredoc_redirect" {
                Some(ShellNode::Heredoc(HeredocNode {
                    kind: kind_string,
                    span,
                }))
            } else {
                Some(ShellNode::Redirect(RedirectNode {
                    kind: kind_string,
                    span,
                }))
            }
        }
        "variable_assignment" => Some(ShellNode::Assignment(AssignmentNode {
            kind: kind_string,
            span,
        })),
        "if_statement" | "elif_clause" | "else_clause" | "case_statement" | "test_command"
        | "binary_expression" | "unary_expression" => {
            Some(ShellNode::Conditional(ConditionalNode {
                kind: kind_string,
                span,
            }))
        }
        "for_statement"
        | "c_style_for_statement"
        | "while_statement"
        | "until_statement"
        | "select_statement" => Some(ShellNode::Loop(LoopNode {
            kind: kind_string,
            span,
        })),
        "function_definition" => Some(ShellNode::Function(FunctionNode {
            kind: kind_string,
            span,
        })),
        "heredoc_body" => Some(ShellNode::Heredoc(HeredocNode {
            kind: kind_string,
            span,
        })),
        "process_substitution" => Some(ShellNode::ProcessSubstitution(ProcessSubstitutionNode {
            kind: kind_string,
            span,
        })),
        "command_substitution" => Some(ShellNode::CommandSubstitution(CommandSubstitutionNode {
            kind: kind_string,
            span,
        })),
        _ => None,
    }
}

fn parse_error_finding(config: &ParserConfig, node: Node<'_>) -> Finding {
    make_finding(
        config,
        FindingInput::new(
            format!("parse-error-{}-{}", node.start_byte(), node.end_byte()),
            FindingCategory::ParserError,
            Severity::Medium,
            "Shell syntax parse error",
            "Tree-sitter recovered from malformed shell syntax and marked an error node.",
        )
        .with_span(span_for_node(node))
        .with_evidence(node.kind().to_owned()),
    )
}

struct FindingInput {
    id: String,
    category: FindingCategory,
    severity: Severity,
    title: String,
    description: String,
    span: Option<SourceSpan>,
    evidence_content: Option<String>,
}

impl FindingInput {
    fn new(
        id: impl Into<String>,
        category: FindingCategory,
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            category,
            severity,
            title: title.into(),
            description: description.into(),
            span: None,
            evidence_content: None,
        }
    }

    fn with_span(mut self, span: Option<SourceSpan>) -> Self {
        self.span = span;
        self
    }

    fn with_evidence(mut self, evidence_content: impl Into<String>) -> Self {
        self.evidence_content = Some(evidence_content.into());
        self
    }
}

fn make_finding(config: &ParserConfig, input: FindingInput) -> Finding {
    Finding {
        id: input.id,
        detector: DETECTOR_ID.to_owned(),
        category: input.category,
        severity: input.severity,
        confidence: Confidence::Confirmed,
        title: input.title,
        description: input.description,
        evidence: input.evidence_content.map_or_else(Vec::new, |content| {
            vec![Evidence {
                kind: EvidenceKind::Other,
                description: "parser diagnostic".to_owned(),
                content: Some(content),
            }]
        }),
        artifact_sha256: config.artifact_sha256.clone(),
        location: input.span.map(|value| value.location),
        remediation: None,
        references: Vec::new(),
        tags: vec!["shell-parser".to_owned()],
        taxonomies: Vec::new(),
    }
}

fn span_for_node(node: Node<'_>) -> Option<SourceSpan> {
    Some(SourceSpan {
        byte_range: node.start_byte()..node.end_byte(),
        location: location_from_points(
            node.start_position(),
            node.end_position(),
            node.start_byte(),
        )?,
    })
}

fn location_from_points(start: Point, end: Point, start_byte: usize) -> Option<SourceLocation> {
    let line = one_based_u32(start.row)?;
    let column = one_based_u32(start.column)?;
    let end_line = one_based_u32(end.row)?;
    let end_column = one_based_u32(end.column)?;
    let byte_offset = u64::try_from(start_byte).ok();

    SourceLocation::new(line, column, Some(end_line), Some(end_column), byte_offset).ok()
}

fn one_based_u32(zero_based: usize) -> Option<NonZeroU32> {
    let value = u32::try_from(zero_based).ok()?.checked_add(1)?;
    NonZeroU32::new(value)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
