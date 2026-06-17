//! Semantic normalization post-pass for parsed shell source.

use std::collections::{BTreeMap, BTreeSet};

use arbitraitor_model::ids::Sha256Digest;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tree_sitter::{LanguageError, Node, Parser};

use crate::{ShellNode, SourceSpan, span_for_node};

const MAX_DECODED_BYTES: usize = 1024 * 1024;

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
    /// Gzip decompression through `gunzip`.
    Gzip,
    /// Xz decompression through `xz -d`.
    Xz,
    /// OpenSSL base64 decoding through `openssl enc -d -base64`.
    OpenSsl,
    /// Heredoc body extraction.
    Heredoc,
}

/// Directed command data-flow graph.
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

/// Runs semantic normalization as a post-pass over parsed shell source.
///
/// The original artifact is not modified. Derived decoded artifacts are bounded
/// to one MiB until the limit is policy-controlled.
///
/// # Errors
///
/// Returns an error if the embedded Bash grammar cannot be configured or if
/// tree-sitter fails to produce a parse tree for `source`.
pub fn normalize(ast: &ShellAst, source: &str) -> Result<NormalizationResult, NormalizeError> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_bash::LANGUAGE.into())?;
    let tree = parser
        .parse(source.as_bytes(), None)
        .ok_or(NormalizeError::NoTree)?;

    let root = tree.root_node();
    let mut state = NormalizerState {
        source,
        bindings: BTreeMap::new(),
        commands: Vec::with_capacity(ast.len()),
        command_spans: Vec::new(),
        pipe_edges: Vec::new(),
        decoded_artifacts: Vec::new(),
        urls: Vec::new(),
        seen_urls: BTreeSet::new(),
    };
    state.visit(root);
    state.extract_pipeline_edges(root);
    state.detect_decode_chains();

    Ok(NormalizationResult {
        commands: state.commands,
        data_flow: PipeGraph {
            edges: state.pipe_edges,
        },
        decoded_artifacts: state.decoded_artifacts,
        urls: state.urls,
        variable_bindings: state.bindings,
    })
}

struct NormalizerState<'source> {
    source: &'source str,
    bindings: BTreeMap<String, String>,
    commands: Vec<ExtractedCommand>,
    command_spans: Vec<SourceSpan>,
    pipe_edges: Vec<(usize, usize)>,
    decoded_artifacts: Vec<DecodedArtifact>,
    urls: Vec<ExtractedUrl>,
    seen_urls: BTreeSet<(String, usize)>,
}

impl NormalizerState<'_> {
    fn visit(&mut self, node: Node<'_>) {
        if node.kind() == "heredoc_body" {
            self.extract_heredoc(node);
            return;
        }

        if node.kind() == "variable_assignment" {
            self.record_assignment(node);
            return;
        }

        if is_command_node(node) {
            self.record_command(node);
            return;
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.visit(child);
        }
    }

    fn record_assignment(&mut self, node: Node<'_>) {
        let Some(text) = node_text(self.source, node) else {
            return;
        };
        let Some((name, value)) = split_assignment(text) else {
            return;
        };
        let Some(resolved) = self.resolve_token(value) else {
            self.bindings.remove(name);
            return;
        };
        if let Some(span) = span_for_node(node) {
            self.extract_urls_from_value(&resolved, &span);
        }
        self.bindings.insert(name.to_owned(), resolved);
    }

    fn record_command(&mut self, node: Node<'_>) {
        let Some(span) = span_for_node(node) else {
            return;
        };
        let mut tokens = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "variable_assignment"
                | "file_redirect"
                | "heredoc_redirect"
                | "herestring_redirect" => {
                    self.visit(child);
                }
                _ => {
                    if let Some(token) = self.resolve_word_like(child)
                        && !token.is_empty()
                    {
                        tokens.push(token);
                    }
                }
            }
        }

        if tokens.is_empty() {
            return;
        }

        let name = tokens.remove(0);
        self.extract_urls_from_value(&name, &span);
        for argument in &tokens {
            self.extract_urls_from_value(argument, &span);
        }
        self.command_spans.push(span.clone());
        self.commands.push(ExtractedCommand {
            name,
            arguments: tokens,
            span,
        });
    }

    fn extract_heredoc(&mut self, node: Node<'_>) {
        let Some(span) = span_for_node(node) else {
            return;
        };
        let Some(text) = node_text(self.source, node) else {
            return;
        };
        self.push_decoded(DecodeKind::Heredoc, text.as_bytes().to_vec(), span);
    }

    fn resolve_word_like(&self, node: Node<'_>) -> Option<String> {
        match node.kind() {
            "command_name" | "word" | "string" | "raw_string" | "concatenation"
            | "simple_expansion" | "ansi_c_string" | "number" => {
                node_text(self.source, node).and_then(|text| self.resolve_token(text))
            }
            _ => {
                let mut value = String::new();
                let mut saw_child = false;
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    saw_child = true;
                    if let Some(piece) = self.resolve_word_like(child) {
                        value.push_str(&piece);
                    } else {
                        return None;
                    }
                }
                saw_child.then_some(value)
            }
        }
    }

    fn resolve_token(&self, token: &str) -> Option<String> {
        let unquoted = strip_outer_quotes(token);
        expand_escapes_and_variables(&unquoted, &self.bindings)
    }

    fn extract_pipeline_edges(&mut self, node: Node<'_>) {
        if node.kind() == "pipeline" {
            let mut command_indexes = Vec::new();
            for (index, span) in self.command_spans.iter().enumerate() {
                if span.byte_range.start >= node.start_byte()
                    && span.byte_range.end <= node.end_byte()
                {
                    command_indexes.push(index);
                }
            }
            command_indexes.sort_unstable();
            for pair in command_indexes.windows(2) {
                if let [left, right] = pair {
                    self.pipe_edges.push((*left, *right));
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.extract_pipeline_edges(child);
        }
    }

    fn detect_decode_chains(&mut self) {
        let mut produced = BTreeMap::new();
        for (index, command) in self.commands.iter().enumerate() {
            if let Some(bytes) = command_constant_output(command) {
                produced.insert(index, bytes);
            }
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
            if bytes.len() > MAX_DECODED_BYTES {
                continue;
            }
            let constant = ConstantBytes {
                bytes: bytes.clone(),
                span: command.span.clone(),
            };
            self.push_decoded(kind, bytes, command.span.clone());
            produced.insert(to, constant);
        }
    }

    fn push_decoded(&mut self, kind: DecodeKind, content: Vec<u8>, parent_span: SourceSpan) {
        if content.len() > MAX_DECODED_BYTES {
            return;
        }
        let digest = Sha256Digest::new(Sha256::digest(&content).into());
        self.decoded_artifacts.push(DecodedArtifact {
            digest,
            kind,
            size: content.len(),
            parent_span,
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

fn is_command_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "command" | "simple_command" | "declaration_command"
    )
}

fn node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    source.get(node.start_byte()..node.end_byte())
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
            '$' => match read_variable_reference(&mut chars) {
                Some(reference) => {
                    if let Some(value) = bindings.get(&reference.name) {
                        output.push_str(value);
                    } else {
                        output.push_str(&reference.original);
                    }
                }
                None => output.push('$'),
            },
            '`' | '(' | ')' if token.contains("$(") || token.contains('`') => return None,
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
        "echo" => Some(ConstantBytes {
            bytes: command.arguments.join(" ").into_bytes(),
            span: command.span.clone(),
        }),
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

fn decode_command(command: &ExtractedCommand, input: &[u8]) -> Option<(DecodeKind, Vec<u8>)> {
    match command.name.as_str() {
        "base64"
            if command
                .arguments
                .iter()
                .any(|argument| argument == "-d" || argument == "--decode") =>
        {
            decode_base64(input).map(|bytes| (DecodeKind::Base64, bytes))
        }
        "openssl" if is_openssl_base64_decode(&command.arguments) => {
            decode_base64(input).map(|bytes| (DecodeKind::OpenSsl, bytes))
        }
        "xxd"
            if command.arguments.iter().any(|argument| argument == "-r")
                && command.arguments.iter().any(|argument| argument == "-p") =>
        {
            decode_hex(input).map(|bytes| (DecodeKind::Hex, bytes))
        }
        _ => None,
    }
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
