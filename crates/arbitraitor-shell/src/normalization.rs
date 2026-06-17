//! Semantic normalization post-pass for parsed shell source.

use std::collections::{BTreeMap, BTreeSet};

use arbitraitor_model::ids::Sha256Digest;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tree_sitter::LanguageError;

use crate::{ShellNode, SourceSpan};

const MAX_DECODED_BYTES: usize = 32 * 1024;
const MAX_TOTAL_DECODED_BYTES: usize = 256 * 1024;
const MAX_DECODE_ARTIFACTS: usize = 64;
const MAX_NORMALIZE_DEPTH: usize = 50;
const MAX_NORMALIZE_NODES: usize = 10_000;

/// Borrowed shell AST collected by [`crate::ShellParser`].
pub type ShellAst = [ShellNode];

/// Output from semantic shell normalization.
#[derive(Clone, Debug, PartialEq)]
pub struct NormalizationResult {
    /// Commands extracted from tree-sitter command nodes in source order.
    pub commands: Vec<ExtractedCommand>,
    /// Pipe edges between extracted commands.
    pub data_flow: PipeGraph,
    /// Constant decoded payloads and heredoc bodies discovered during normalization.
    pub decoded_artifacts: Vec<DecodedArtifact>,
    /// URLs found in constant command names, arguments, and variable bindings.
    pub urls: Vec<ExtractedUrl>,
    /// Final constant variable bindings proven by the post-pass.
    pub variable_bindings: BTreeMap<String, String>,
    /// Whether shell data-flow mechanisms outside [`PipeGraph`] scope were observed.
    pub has_unmodeled_flow: bool,
    /// Notes about bounded normalization, including any truncation events.
    pub notes: Vec<String>,
}

/// Command extracted from the shell AST.
#[derive(Clone, Debug, PartialEq)]
pub struct ExtractedCommand {
    /// Normalized command name.
    pub name: String,
    /// Normalized command arguments.
    pub arguments: Vec<String>,
    /// Source span of the command node.
    pub span: SourceSpan,
}

/// Decoded constant payload or heredoc body emitted for recursive scanning.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedArtifact {
    /// SHA-256 digest of [`Self::content`].
    pub digest: Sha256Digest,
    /// Decoder or extraction mechanism that produced this child artifact.
    pub kind: DecodeKind,
    /// Decoded byte length.
    pub size: usize,
    /// Span of the command or heredoc that produced the child artifact.
    pub parent_span: SourceSpan,
    /// Command index that consumed source bytes for this artifact, when known.
    pub source_command_index: Option<usize>,
    /// Decoded bytes for the recursive scanner.
    pub content: Vec<u8>,
}

/// Decode or extraction mechanism for a child artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeKind {
    /// Base64 decoding through `base64 -d` or `--decode`.
    Base64,
    /// Hex decoding through `xxd -r -p`.
    Hex,
    // TODO: Add Gzip and Xz variants when bounded decompression is implemented
    // with proper size/depth limits. See issue #38 for tracking.
    /// OpenSSL base64 decoding through `openssl enc -d -base64`.
    OpenSsl,
    /// Heredoc body extraction.
    Heredoc,
}

/// Directed graph of data flow between commands connected by shell pipes (`|`).
///
/// # Scope Limitations
///
/// This graph ONLY captures pipe-based data flow. The following data flow
/// mechanisms are NOT modeled:
/// - File redirections (`>`, `>>`, `<`)
/// - Process substitution (`<(...)`, `>(...)`)
/// - Named pipes (`mkfifo`)
/// - Temp-file handoffs
///
/// Downstream policy must treat this graph as advisory, not exhaustive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PipeGraph {
    /// Command-index edges from producer to consumer.
    pub edges: Vec<(usize, usize)>,
}

/// URL extracted from a normalized constant value.
#[derive(Clone, Debug, PartialEq)]
pub struct ExtractedUrl {
    /// URL text.
    pub url: String,
    /// Source span where the URL-bearing constant appeared.
    pub span: SourceSpan,
}

/// Error returned by semantic normalization.
#[derive(Debug, Error)]
pub enum NormalizeError {
    /// Tree-sitter rejected the configured shell grammar.
    #[error("tree-sitter rejected the bash grammar: {0}")]
    Grammar(#[from] LanguageError),
    /// Tree-sitter did not produce a parse tree for the source.
    #[error("tree-sitter did not produce a parse tree for shell normalization")]
    NoTree,
}

#[derive(Clone, Debug, PartialEq)]
struct ConstantBytes {
    bytes: Vec<u8>,
    span: SourceSpan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventKind {
    Command,
    Assignment,
    Pipeline,
    Heredoc,
}

#[derive(Clone, Debug)]
struct AstEvent {
    kind: EventKind,
    span: SourceSpan,
    node_kind: String,
    depth: usize,
}

/// Runs semantic normalization as a post-pass over parsed shell source.
///
/// The original artifact is not modified. Derived decoded artifacts are bounded
/// to 32 KiB each, 256 KiB aggregate, and 64 total artifacts.
///
/// # Errors
///
/// This post-pass uses the already parsed [`ShellAst`] and does not reparse.
/// The result type remains fallible for API compatibility with earlier
/// normalization implementations.
pub fn normalize(ast: &ShellAst, source: &str) -> Result<NormalizationResult, NormalizeError> {
    let mut state = NormalizerState {
        source,
        bindings: BTreeMap::new(),
        commands: Vec::with_capacity(ast.len()),
        command_spans: Vec::new(),
        command_source_indexes: BTreeMap::new(),
        pipe_edges: Vec::new(),
        decoded_artifacts: Vec::new(),
        urls: Vec::new(),
        seen_urls: BTreeSet::new(),
        total_decoded_bytes: 0,
        artifact_count: 0,
        max_depth: MAX_NORMALIZE_DEPTH,
        visited_nodes: 0,
        notes: Vec::new(),
        has_unmodeled_flow: false,
    };

    let events = collect_events(ast, &mut state);
    state.visit(&events);
    state.extract_pipeline_edges(&events);
    state.detect_decode_chains(&events);
    state.decode_heredocs(&events);

    Ok(NormalizationResult {
        commands: state.commands,
        data_flow: PipeGraph {
            edges: state.pipe_edges,
        },
        decoded_artifacts: state.decoded_artifacts,
        urls: state.urls,
        variable_bindings: state.bindings,
        has_unmodeled_flow: state.has_unmodeled_flow,
        notes: state.notes,
    })
}

struct NormalizerState<'source> {
    source: &'source str,
    bindings: BTreeMap<String, String>,
    commands: Vec<ExtractedCommand>,
    command_spans: Vec<SourceSpan>,
    command_source_indexes: BTreeMap<usize, usize>,
    pipe_edges: Vec<(usize, usize)>,
    decoded_artifacts: Vec<DecodedArtifact>,
    urls: Vec<ExtractedUrl>,
    seen_urls: BTreeSet<(String, usize)>,
    total_decoded_bytes: usize,
    artifact_count: usize,
    max_depth: usize,
    visited_nodes: usize,
    notes: Vec<String>,
    has_unmodeled_flow: bool,
}

impl NormalizerState<'_> {
    fn visit(&mut self, events: &[AstEvent]) {
        let command_local_assignments = command_local_assignment_starts(events, self.source);
        let mut seen_commands = BTreeSet::new();

        for event in events {
            if self.should_truncate(event) {
                continue;
            }

            match event.kind {
                EventKind::Command => {
                    if seen_commands
                        .insert((event.span.byte_range.start, event.span.byte_range.end))
                    {
                        self.record_command(event);
                    }
                }
                EventKind::Assignment => {
                    if !command_local_assignments.contains(&event.span.byte_range.start) {
                        self.record_assignment(&event.span);
                    }
                }
                EventKind::Pipeline | EventKind::Heredoc => {}
            }
        }
    }

    fn should_truncate(&mut self, event: &AstEvent) -> bool {
        if self.visited_nodes >= MAX_NORMALIZE_NODES {
            if !self
                .notes
                .iter()
                .any(|note| note == "normalization truncated at node limit")
            {
                self.notes
                    .push("normalization truncated at node limit".to_owned());
            }
            return true;
        }
        self.visited_nodes = self.visited_nodes.saturating_add(1);

        if event.depth > self.max_depth {
            if !self
                .notes
                .iter()
                .any(|note| note == "normalization truncated at depth limit")
            {
                self.notes
                    .push("normalization truncated at depth limit".to_owned());
            }
            return true;
        }
        false
    }

    fn record_assignment(&mut self, span: &SourceSpan) {
        let Some(text) = self.source.get(span.byte_range.clone()) else {
            return;
        };
        let Some((name, value)) = split_assignment(text) else {
            return;
        };
        let Some(resolved) = resolve_token(value, &self.bindings) else {
            self.bindings.remove(name);
            return;
        };
        self.extract_urls_from_value(&resolved, span);
        self.bindings.insert(name.to_owned(), resolved);
    }

    fn record_command(&mut self, event: &AstEvent) {
        let Some(text) = self.source.get(event.span.byte_range.clone()) else {
            return;
        };
        let words = lex_shell_words(text);
        if words.is_empty() {
            return;
        }

        let snapshot = self.bindings.clone();
        let mut word_iter = words.iter().peekable();
        while let Some(word) = word_iter.peek() {
            let Some((_, value)) = split_assignment(word.raw.as_str()) else {
                break;
            };
            if let Some(resolved) = resolve_token(value, &snapshot) {
                self.extract_urls_from_value(&resolved, &event.span);
            }
            word_iter.next();
        }

        let mut tokens = Vec::new();
        for word in word_iter {
            if let Some(token) = resolve_token(&word.raw, &snapshot)
                && !token.is_empty()
            {
                tokens.push(token);
            }
        }

        if tokens.is_empty() {
            return;
        }

        let name = canonical_command_name(&tokens.remove(0));
        self.extract_urls_from_value(&name, &event.span);
        for argument in &tokens {
            self.extract_urls_from_value(argument, &event.span);
        }

        let command_index = self.commands.len();
        self.command_spans.push(event.span.clone());
        self.command_source_indexes
            .insert(event.span.byte_range.start, command_index);
        self.commands.push(ExtractedCommand {
            name,
            arguments: tokens,
            span: event.span.clone(),
        });
    }

    fn extract_pipeline_edges(&mut self, events: &[AstEvent]) {
        for event in events
            .iter()
            .filter(|event| event.kind == EventKind::Pipeline && event.depth <= self.max_depth)
        {
            let mut command_indexes = Vec::new();
            for (index, span) in self.command_spans.iter().enumerate() {
                if span.byte_range.start >= event.span.byte_range.start
                    && span.byte_range.end <= event.span.byte_range.end
                {
                    command_indexes.push(index);
                }
            }
            command_indexes.sort_unstable();
            command_indexes.dedup();
            for pair in command_indexes.windows(2) {
                if let [left, right] = pair {
                    self.pipe_edges.push((*left, *right));
                }
            }
        }
        for (index, pair) in self.command_spans.windows(2).enumerate() {
            let [left, right] = pair else {
                continue;
            };
            if left.byte_range.end > right.byte_range.start {
                continue;
            }
            let Some(between) = self.source.get(left.byte_range.end..right.byte_range.start) else {
                continue;
            };
            if between.contains('|') {
                self.pipe_edges.push((index, index.saturating_add(1)));
            }
        }
        self.pipe_edges.sort_unstable();
        self.pipe_edges.dedup();
    }

    fn detect_decode_chains(&mut self, events: &[AstEvent]) {
        let mut produced = BTreeMap::new();
        for (index, command) in self.commands.iter().enumerate() {
            if let Some(bytes) = command_constant_output(command) {
                produced.insert(index, bytes);
            }
        }
        for (index, content) in self.heredoc_command_contents(events) {
            produced.insert(index, content);
        }

        let edges = self.pipe_edges.clone();
        for (from, to) in edges {
            let Some(input) = produced.get(&from).cloned() else {
                continue;
            };
            let Some(command) = self.commands.get(to) else {
                continue;
            };
            let Some((kind, bytes)) = decode_command(command, &input.bytes) else {
                produced.insert(to, input);
                continue;
            };
            let constant = ConstantBytes {
                bytes: bytes.clone(),
                span: command.span.clone(),
            };
            self.push_decoded(kind, bytes, command.span.clone(), Some(to));
            produced.insert(to, constant);
        }
    }

    fn decode_heredocs(&mut self, events: &[AstEvent]) {
        let heredocs: Vec<&AstEvent> = events
            .iter()
            .filter(|event| event.kind == EventKind::Heredoc && event.node_kind == "heredoc_body")
            .collect();

        for heredoc in heredocs {
            let Some(body) = self.source.get(heredoc.span.byte_range.clone()) else {
                continue;
            };
            let content = if heredoc_uses_tab_stripping(self.source, heredoc.span.byte_range.start)
            {
                strip_leading_tabs(body).into_bytes()
            } else {
                body.as_bytes().to_vec()
            };
            let source_command_index = self.heredoc_body_command_index(events, heredoc);
            self.push_decoded(
                DecodeKind::Heredoc,
                content.clone(),
                heredoc.span.clone(),
                source_command_index,
            );

            let Some(command_index) = source_command_index else {
                continue;
            };
            let Some(command) = self.commands.get(command_index) else {
                continue;
            };
            let command_span = command.span.clone();
            let Some((kind, bytes)) = decode_command(command, &content) else {
                continue;
            };
            self.push_decoded(kind, bytes, command_span, Some(command_index));
        }
    }

    fn heredoc_command_contents(&self, events: &[AstEvent]) -> BTreeMap<usize, ConstantBytes> {
        let mut contents = BTreeMap::new();
        for heredoc in events
            .iter()
            .filter(|event| event.kind == EventKind::Heredoc && event.node_kind == "heredoc_body")
        {
            let Some(body) = self.source.get(heredoc.span.byte_range.clone()) else {
                continue;
            };
            let bytes = if heredoc_uses_tab_stripping(self.source, heredoc.span.byte_range.start) {
                strip_leading_tabs(body).into_bytes()
            } else {
                body.as_bytes().to_vec()
            };
            let Some(command_index) = self.heredoc_body_command_index(events, heredoc) else {
                continue;
            };
            contents.insert(
                command_index,
                ConstantBytes {
                    bytes,
                    span: heredoc.span.clone(),
                },
            );
        }
        contents
    }

    fn nearest_consuming_command(&self, heredoc_start: usize) -> Option<usize> {
        self.command_spans
            .iter()
            .enumerate()
            .filter(|(_, span)| span.byte_range.start < heredoc_start)
            .max_by_key(|(_, span)| span.byte_range.start)
            .map(|(index, _)| index)
    }

    fn heredoc_body_command_index(&self, events: &[AstEvent], body: &AstEvent) -> Option<usize> {
        let heredoc_redirect_start = events
            .iter()
            .filter(|event| {
                event.kind == EventKind::Heredoc
                    && event.node_kind != "heredoc_body"
                    && event.span.byte_range.start < body.span.byte_range.start
            })
            .max_by_key(|event| event.span.byte_range.start)
            .map_or(body.span.byte_range.start, |event| {
                event.span.byte_range.start
            });
        self.nearest_consuming_command(heredoc_redirect_start)
    }

    fn push_decoded(
        &mut self,
        kind: DecodeKind,
        content: Vec<u8>,
        parent_span: SourceSpan,
        source_command_index: Option<usize>,
    ) {
        if content.len() > MAX_DECODED_BYTES {
            self.notes
                .push("decoded artifact skipped: per-artifact byte limit exceeded".to_owned());
            return;
        }
        if self.artifact_count >= MAX_DECODE_ARTIFACTS {
            self.notes
                .push("decoded artifact skipped: artifact count limit exceeded".to_owned());
            return;
        }
        if self.total_decoded_bytes.saturating_add(content.len()) > MAX_TOTAL_DECODED_BYTES {
            self.notes
                .push("decoded artifact skipped: aggregate byte limit exceeded".to_owned());
            return;
        }

        self.total_decoded_bytes = self.total_decoded_bytes.saturating_add(content.len());
        self.artifact_count = self.artifact_count.saturating_add(1);
        let digest = Sha256Digest::new(Sha256::digest(&content).into());
        self.decoded_artifacts.push(DecodedArtifact {
            digest,
            kind,
            size: content.len(),
            parent_span,
            source_command_index,
            content,
        });
    }

    fn extract_urls_from_value(&mut self, value: &str, span: &SourceSpan) {
        for url in extract_urls(value) {
            if self.seen_urls.insert((url.clone(), span.byte_range.start)) {
                self.urls.push(ExtractedUrl {
                    url,
                    span: span.clone(),
                });
            }
        }
    }
}

fn resolve_token(token: &str, bindings: &BTreeMap<String, String>) -> Option<String> {
    let unquoted = strip_outer_quotes(token);
    expand_escapes_and_variables(&unquoted, bindings)
}

fn canonical_command_name(name: &str) -> String {
    name.chars()
        .filter(|character| !matches!(character, '\'' | '"'))
        .collect()
}

fn collect_events(ast: &ShellAst, state: &mut NormalizerState<'_>) -> Vec<AstEvent> {
    let mut sorted_nodes: Vec<&ShellNode> = ast.iter().collect();
    sorted_nodes.sort_by_key(|node| (node.span().byte_range.start, node.span().byte_range.end));

    let mut stack: Vec<SourceSpan> = Vec::new();
    let mut events = Vec::new();
    for node in sorted_nodes {
        let span = node.span().clone();
        while stack
            .last()
            .is_some_and(|parent| span.byte_range.start >= parent.byte_range.end)
        {
            stack.pop();
        }
        let depth = stack.len();
        if span.byte_range.end > span.byte_range.start {
            stack.push(span.clone());
        }

        match node {
            ShellNode::Command(command) => events.push(AstEvent {
                kind: EventKind::Command,
                span,
                node_kind: command.kind.clone(),
                depth,
            }),
            ShellNode::Assignment(assignment) => events.push(AstEvent {
                kind: EventKind::Assignment,
                span,
                node_kind: assignment.kind.clone(),
                depth,
            }),
            ShellNode::Pipeline(pipeline) => events.push(AstEvent {
                kind: EventKind::Pipeline,
                span,
                node_kind: pipeline.kind.clone(),
                depth,
            }),
            ShellNode::Heredoc(heredoc) => {
                state.has_unmodeled_flow = true;
                events.push(AstEvent {
                    kind: EventKind::Heredoc,
                    span,
                    node_kind: heredoc.kind.clone(),
                    depth,
                });
            }
            ShellNode::Redirect(_) | ShellNode::ProcessSubstitution(_) => {
                state.has_unmodeled_flow = true;
            }
            ShellNode::Conditional(_)
            | ShellNode::Loop(_)
            | ShellNode::Function(_)
            | ShellNode::CommandSubstitution(_) => {}
        }
    }
    events.sort_by_key(|event| (event.span.byte_range.start, event.span.byte_range.end));
    events
}

fn command_local_assignment_starts(events: &[AstEvent], source: &str) -> BTreeSet<usize> {
    let mut starts = BTreeSet::new();
    for command in events
        .iter()
        .filter(|event| event.kind == EventKind::Command)
    {
        let Some(text) = source.get(command.span.byte_range.clone()) else {
            continue;
        };
        let words = lex_shell_words(text);
        let prefix_assignment_count = words
            .iter()
            .take_while(|word| split_assignment(word.raw.as_str()).is_some())
            .count();
        if prefix_assignment_count == 0 || prefix_assignment_count == words.len() {
            continue;
        }
        for word in words.iter().take(prefix_assignment_count) {
            starts.insert(command.span.byte_range.start.saturating_add(word.start));
        }
    }
    starts
}

#[derive(Clone, Debug)]
struct ShellWord {
    raw: String,
    start: usize,
}

fn lex_shell_words(input: &str) -> Vec<ShellWord> {
    let mut words = Vec::new();
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index = index.saturating_add(1);
        }
        if index >= bytes.len() {
            break;
        }
        if matches!(bytes[index], b'|' | b';' | b'&') {
            index = index.saturating_add(1);
            continue;
        }
        if matches!(bytes[index], b'<' | b'>') {
            index = skip_redirect(input, index);
            continue;
        }

        let start = index;
        let mut raw = String::new();
        while index < bytes.len() {
            let byte = bytes[index];
            if byte.is_ascii_whitespace() || matches!(byte, b'|' | b';' | b'&') {
                break;
            }
            if matches!(byte, b'<' | b'>') {
                break;
            }
            if byte == b'\'' || byte == b'"' {
                let quote = byte;
                raw.push(char::from(byte));
                index = index.saturating_add(1);
                while index < bytes.len() {
                    raw.push(char::from(bytes[index]));
                    if bytes[index] == quote {
                        index = index.saturating_add(1);
                        break;
                    }
                    index = index.saturating_add(1);
                }
                continue;
            }
            if byte == b'`' {
                raw.push('`');
                index = index.saturating_add(1);
                while index < bytes.len() {
                    raw.push(char::from(bytes[index]));
                    if bytes[index] == b'`' {
                        index = index.saturating_add(1);
                        break;
                    }
                    index = index.saturating_add(1);
                }
                continue;
            }
            if byte == b'$' && bytes.get(index.saturating_add(1)) == Some(&b'(') {
                raw.push_str("$()");
                index = skip_balanced(input, index.saturating_add(2));
                continue;
            }
            raw.push(char::from(byte));
            index = index.saturating_add(1);
        }
        if !raw.is_empty() {
            words.push(ShellWord { raw, start });
        }
    }
    words
}

fn skip_redirect(input: &str, mut index: usize) -> usize {
    let bytes = input.as_bytes();
    while index < bytes.len() && matches!(bytes[index], b'<' | b'>' | b'&' | b'-') {
        index = index.saturating_add(1);
    }
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index = index.saturating_add(1);
    }
    if index < bytes.len() && bytes[index] == b'(' {
        return skip_balanced(input, index.saturating_add(1));
    }
    while index < bytes.len()
        && !bytes[index].is_ascii_whitespace()
        && !matches!(bytes[index], b'|' | b';' | b'&')
    {
        index = index.saturating_add(1);
    }
    index
}

fn skip_balanced(input: &str, mut index: usize) -> usize {
    let bytes = input.as_bytes();
    let mut depth = 1_usize;
    while index < bytes.len() && depth > 0 {
        match bytes[index] {
            b'(' => depth = depth.saturating_add(1),
            b')' => depth = depth.saturating_sub(1),
            b'\'' | b'"' => {
                let quote = bytes[index];
                index = index.saturating_add(1);
                while index < bytes.len() && bytes[index] != quote {
                    index = index.saturating_add(1);
                }
            }
            _ => {}
        }
        index = index.saturating_add(1);
    }
    index
}

fn split_assignment(text: &str) -> Option<(&str, &str)> {
    let (name, value) = text.split_once('=')?;
    if is_shell_name(name) {
        Some((name, value))
    } else {
        None
    }
}

fn is_shell_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn strip_outer_quotes(token: &str) -> String {
    let trimmed = token.trim();
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

fn expand_escapes_and_variables(
    token: &str,
    bindings: &BTreeMap<String, String>,
) -> Option<String> {
    let mut output = String::new();
    let mut chars = token.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '\\' => match chars.peek().copied() {
                Some('x') => {
                    chars.next();
                    let high = chars.next()?;
                    let low = chars.next()?;
                    let byte = decode_hex_pair(high, low)?;
                    output.push(char::from(byte));
                }
                Some('n') => {
                    chars.next();
                    output.push('\n');
                }
                Some('t') => {
                    chars.next();
                    output.push('\t');
                }
                Some(next) => {
                    chars.next();
                    output.push(next);
                }
                None => output.push('\\'),
            },
            '$' => {
                if chars.peek().is_some_and(|character| *character == '(') {
                    return None;
                }
                match read_variable_reference(&mut chars) {
                    Some(reference) => {
                        if let Some(value) = bindings.get(&reference.name) {
                            output.push_str(value);
                        } else {
                            output.push_str(&reference.original);
                        }
                    }
                    None => output.push('$'),
                }
            }
            '`' => return None,
            _ => output.push(character),
        }
    }
    Some(output)
}

struct VariableReference {
    name: String,
    original: String,
}

fn read_variable_reference<I>(chars: &mut std::iter::Peekable<I>) -> Option<VariableReference>
where
    I: Iterator<Item = char>,
{
    let mut braced = false;
    let mut original = String::from("$");
    if chars.peek().is_some_and(|character| *character == '{') {
        braced = true;
        original.push('{');
        chars.next();
    }
    let mut name = String::new();
    while let Some(character) = chars.peek().copied() {
        if character == '}' && braced {
            original.push('}');
            chars.next();
            break;
        }
        if character == '_' || character.is_ascii_alphanumeric() {
            name.push(character);
            original.push(character);
            chars.next();
        } else {
            break;
        }
    }
    if name.is_empty() {
        return None;
    }
    Some(VariableReference { name, original })
}

fn decode_hex_pair(high: char, low: char) -> Option<u8> {
    let high = high.to_digit(16)?;
    let low = low.to_digit(16)?;
    u8::try_from((high << 4) | low).ok()
}

fn command_constant_output(command: &ExtractedCommand) -> Option<ConstantBytes> {
    match command.name.as_str() {
        "echo" => {
            let arguments = echo_payload_arguments(&command.arguments);
            Some(ConstantBytes {
                bytes: arguments.join(" ").into_bytes(),
                span: command.span.clone(),
            })
        }
        "printf"
            if command
                .arguments
                .first()
                .is_some_and(|format| format == "%s") =>
        {
            Some(ConstantBytes {
                bytes: command
                    .arguments
                    .iter()
                    .skip(1)
                    .cloned()
                    .collect::<String>()
                    .into_bytes(),
                span: command.span.clone(),
            })
        }
        _ => None,
    }
}

fn echo_payload_arguments(arguments: &[String]) -> &[String] {
    let mut start = 0;
    while let Some(argument) = arguments.get(start) {
        if argument == "-n" {
            start = start.saturating_add(1);
        } else {
            break;
        }
    }
    &arguments[start..]
}

fn decode_command(command: &ExtractedCommand, input: &[u8]) -> Option<(DecodeKind, Vec<u8>)> {
    match command.name.as_str() {
        "base64" if base64_decode_flags(&command.arguments) => {
            decode_base64(input).map(|bytes| (DecodeKind::Base64, bytes))
        }
        "openssl" if is_openssl_base64_decode(&command.arguments) => {
            decode_base64(input).map(|bytes| (DecodeKind::OpenSsl, bytes))
        }
        "xxd" if xxd_reverse_plain_flags(&command.arguments) => {
            decode_hex(input).map(|bytes| (DecodeKind::Hex, bytes))
        }
        _ => None,
    }
}

fn base64_decode_flags(arguments: &[String]) -> bool {
    arguments.iter().any(|argument| {
        let lower = argument.to_ascii_lowercase();
        lower == "--decode"
            || lower == "-d"
            || argument == "-D"
            || (lower.starts_with('-')
                && !lower.starts_with("--")
                && lower.chars().skip(1).any(|flag| flag == 'd'))
    })
}

fn xxd_reverse_plain_flags(arguments: &[String]) -> bool {
    let mut reverse = false;
    let mut plain = false;
    for argument in arguments {
        if !argument.starts_with('-') || argument.starts_with("--") {
            continue;
        }
        for flag in argument.chars().skip(1) {
            match flag {
                'r' => reverse = true,
                'p' => plain = true,
                _ => {}
            }
        }
    }
    reverse && plain
}

fn is_openssl_base64_decode(arguments: &[String]) -> bool {
    arguments.iter().any(|argument| argument == "enc")
        && arguments.iter().any(|argument| argument == "-d")
        && arguments
            .iter()
            .any(|argument| argument == "-base64" || argument == "-a")
}

fn decode_base64(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() > MAX_DECODED_BYTES.saturating_mul(2) {
        return None;
    }
    let text = std::str::from_utf8(input).ok()?;
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .ok()
}

fn decode_hex(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() > MAX_DECODED_BYTES.saturating_mul(2) {
        return None;
    }
    let text = std::str::from_utf8(input).ok()?;
    let digits: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if !digits
        .chars()
        .all(|character| character.is_ascii_hexdigit())
    {
        return Some(input.to_vec());
    }
    let mut output = Vec::with_capacity(digits.len() / 2);
    let mut chars = digits.chars();
    while let Some(high) = chars.next() {
        let low = chars.next()?;
        output.push(decode_hex_pair(high, low)?);
    }
    Some(output)
}

fn heredoc_uses_tab_stripping(source: &str, body_start: usize) -> bool {
    // Tree-sitter already strips leading tabs from <<- bodies at the AST level,
    // so this function is defensive. We use rfind("<<") to locate the nearest
    // heredoc redirect marker before the body start. This is syntactically
    // naive (could match << in comments/strings or pick the wrong marker for
    // same-command multiple heredocs), but worst case is a no-op
    // strip_leading_tabs call on already-stripped content.
    let prefix = &source[..body_start.min(source.len())];
    prefix
        .rfind("<<")
        .is_some_and(|pos| prefix[pos..].starts_with("<<-"))
}

fn strip_leading_tabs(body: &str) -> String {
    let mut stripped = String::new();
    for segment in body.split_inclusive('\n') {
        stripped.push_str(segment.trim_start_matches('\t'));
    }
    if !body.ends_with('\n')
        && let Some(last) = body.rsplit('\n').next()
        && body == last
    {
        return body.trim_start_matches('\t').to_owned();
    }
    stripped
}

fn extract_urls(value: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for piece in value.split(|character: char| {
        character.is_whitespace() || matches!(character, '"' | '\'' | '<' | '>' | '(' | ')')
    }) {
        let trimmed = piece.trim_matches(|character: char| matches!(character, ',' | ';' | '.'));
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            urls.push(trimmed.to_owned());
        }
    }
    urls
}

#[cfg(test)]
mod tests {
    use super::heredoc_uses_tab_stripping;

    #[test]
    fn detects_dash_heredoc_before_body() {
        let source = "cat <<-EOF\n\t\tcontent\nEOF\n";
        assert!(heredoc_uses_tab_stripping(source, 12));
    }

    #[test]
    fn rejects_non_dash_heredoc_before_body() {
        let source = "cat <<EOF\ncontent\nEOF\n";
        assert!(!heredoc_uses_tab_stripping(source, 8));
    }

    #[test]
    fn picks_nearest_heredoc_marker() {
        let source = "cat <<FIRST\nx\nFIRST\ncat <<-SECOND\n\ty\nSECOND\n";
        assert!(heredoc_uses_tab_stripping(source, 34));
        assert!(!heredoc_uses_tab_stripping(source, 12));
    }
}
