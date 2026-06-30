//! Downloader and tool wrapper plugin implementations
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod init;
pub mod shim;
pub mod wget;

use arbitraitor_plugin_api::{
    CapabilitySet, FilesystemCapability, NetworkCapability, OPERATION_PLAN_PROTOCOL_VERSION,
    OperationPlan, PlannedOperation, PluginIdentity, PluginTrustClass, ProcessCapability,
    SemanticConfidence,
};
use thiserror::Error;

/// Parsed subset of a curl invocation supported by the download wrapper.
#[allow(
    clippy::struct_excessive_bools,
    reason = "curl exposes independent boolean flags that must remain visible to confidence assessment"
)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CurlArgs {
    /// URL to retrieve.
    pub url: Option<String>,
    /// Output path from `-o` or `--output`.
    pub output: Option<String>,
    /// Whether redirects are followed (`-L`, `--location`).
    pub follow_redirects: bool,
    /// Whether curl silent mode was requested (`-s`, `--silent`).
    pub silent: bool,
    /// Whether errors should be shown with silent mode (`-S`, `--show-error`).
    pub show_error: bool,
    /// Whether HTTP failures should fail the command (`-f`, `--fail`).
    pub fail: bool,
    /// Request headers from `-H` or `--header`.
    pub headers: Vec<(String, String)>,
    /// Whether TLS verification is disabled (`-k`, `--insecure`).
    pub insecure: bool,
    /// Retry count from `--retry`.
    pub retry: Option<u32>,
    /// User-Agent header from `-A` or `--user-agent`.
    pub user_agent: Option<String>,
    /// Request body from `-d` or `--data`.
    pub data: Option<String>,
    /// Whether output should use the remote file name (`-O`, `--remote-name`).
    pub remote_name: bool,
    /// Whether compressed transfer decoding was requested (`--compressed`).
    pub compressed: bool,
    /// Explicit HTTP method from `-X` or `--request`.
    pub request_method: Option<String>,
    /// Unsupported options observed while parsing.
    pub unsupported_options: Vec<String>,
}

/// Errors produced while parsing or translating curl invocations.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum WrapperError {
    /// The curl command line is empty or missing a required option value.
    #[error("invalid curl arguments: {reason}")]
    InvalidArguments {
        /// Safe diagnostic reason.
        reason: String,
    },
    /// The curl invocation cannot be represented by a non-opaque operation plan.
    #[error("opaque curl translation rejected: {reason}")]
    OpaqueTranslation {
        /// Safe diagnostic reason.
        reason: String,
    },
}

/// Parses curl command-line arguments into the wrapper-supported subset.
///
/// # Errors
///
/// Returns [`WrapperError`] when an option that requires a value is missing or a
/// numeric option cannot be parsed.
pub fn parse_curl_args(argv: &[String]) -> Result<CurlArgs, WrapperError> {
    let mut parser = CurlParser::new(argv);
    parser.parse()
}
/// Converts parsed curl arguments to an Arbitraitor operation plan.
///
/// # Errors
///
/// Returns [`WrapperError`] if the invocation is opaque or does not contain a
/// supported download URL.
pub fn curl_to_operation_plan(args: &CurlArgs) -> Result<OperationPlan, WrapperError> {
    let url = args
        .url
        .as_ref()
        .ok_or_else(|| WrapperError::InvalidArguments {
            reason: "curl invocation does not contain a URL".to_owned(),
        })?;
    let confidence = assess_semantic_confidence(args)?;
    let release_path = release_path(args, url)?;

    let mut operations = vec![PlannedOperation::Retrieve {
        url: url.clone(),
        headers: request_headers(args),
    }];
    if let Some(path) = release_path {
        operations.push(PlannedOperation::ReleaseToFile { path });
    }

    Ok(OperationPlan {
        protocol_version: OPERATION_PLAN_PROTOCOL_VERSION,
        plugin: curl_plugin_identity(),
        original_tool: "curl".to_owned(),
        operations,
        requested_capabilities: requested_capabilities(
            url,
            args.output.is_some() || args.remote_name,
        ),
        semantic_confidence: confidence,
    })
}

fn assess_semantic_confidence(args: &CurlArgs) -> Result<SemanticConfidence, WrapperError> {
    if let Some(reason) = opaque_reason(args) {
        return Err(WrapperError::OpaqueTranslation { reason });
    }

    if args.retry.is_some() || args.compressed {
        return Ok(SemanticConfidence::Equivalent);
    }

    if args.unsupported_options.is_empty()
        && args.output.is_some()
        && args.fail
        && args.silent
        && args.show_error
        && args.follow_redirects
    {
        return Ok(SemanticConfidence::Exact);
    }

    Ok(SemanticConfidence::Partial)
}

fn opaque_reason(args: &CurlArgs) -> Option<String> {
    let url = args.url.as_deref()?;
    if url.starts_with("ftp://") || url.starts_with("ftps://") {
        return Some("FTP URLs are outside the download wrapper model".to_owned());
    }
    if args.data.is_some() {
        return Some("request bodies are unsupported by the download wrapper".to_owned());
    }
    if args.insecure {
        return Some("TLS verification disabling cannot be represented safely".to_owned());
    }
    if let Some(method) = args.request_method.as_deref() {
        let normalized = method.to_ascii_uppercase();
        if matches!(normalized.as_str(), "POST" | "PUT" | "DELETE" | "PATCH") {
            return Some("state-changing HTTP methods are unsupported".to_owned());
        }
    }
    args.unsupported_options
        .iter()
        .find(|option| is_critical_unsupported_option(option))
        .map(|option| format!("critical unsupported option {option}"))
}

fn is_critical_unsupported_option(option: &str) -> bool {
    matches!(
        option,
        "-F" | "--form"
            | "-T"
            | "--upload-file"
            | "-u"
            | "--user"
            | "--proxy"
            | "--connect-to"
            | "--resolve"
            | "--interface"
            | "--unix-socket"
            | "--config"
    )
}
fn request_headers(args: &CurlArgs) -> Vec<(String, String)> {
    let mut headers = args
        .headers
        .iter()
        .map(|(name, value)| (name.clone(), redact_header_value(name, value)))
        .collect::<Vec<_>>();
    if let Some(user_agent) = &args.user_agent {
        headers.push(("user-agent".to_owned(), user_agent.clone()));
    }
    headers
}

fn redact_header_value(name: &str, value: &str) -> String {
    if is_sensitive_header(name) {
        "<redacted>".to_owned()
    } else {
        value.to_owned()
    }
}

fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "authorization" | "cookie" | "proxy-authorization" | "set-cookie"
    )
}

fn release_path(args: &CurlArgs, url: &str) -> Result<Option<String>, WrapperError> {
    if let Some(output) = &args.output {
        return Ok(Some(output.clone()));
    }
    if args.remote_name {
        return remote_name_from_url(url).map(Some);
    }
    Ok(None)
}

/// Derives a filename from the last path segment of a URL, stripping
/// query and fragment components.
///
/// # Errors
///
/// Returns [`WrapperError::InvalidArguments`] if the URL has no
/// filename component (e.g. `https://example.com/`).
pub fn remote_name_from_url(url: &str) -> Result<String, WrapperError> {
    let path_without_query = url.split(['?', '#']).next().unwrap_or(url);
    let name = path_without_query
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .ok_or_else(|| WrapperError::InvalidArguments {
            reason: "--remote-name URL does not contain a file name".to_owned(),
        })?;
    Ok(name.to_owned())
}

fn requested_capabilities(url: &str, writes_file: bool) -> CapabilitySet {
    CapabilitySet {
        network: if url.starts_with("https://") {
            NetworkCapability::OutboundHttps
        } else {
            NetworkCapability::Full
        },
        filesystem: if writes_file {
            FilesystemCapability::ReadWrite
        } else {
            FilesystemCapability::None
        },
        process: ProcessCapability::None,
        max_memory_bytes: None,
        max_cpu_ms: None,
    }
}

fn curl_plugin_identity() -> PluginIdentity {
    PluginIdentity {
        id: "arbitraitor.wrapper.curl".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        trust_class: PluginTrustClass::BuiltIn,
    }
}

struct CurlParser<'a> {
    argv: &'a [String],
    index: usize,
    args: CurlArgs,
}
impl<'a> CurlParser<'a> {
    fn new(argv: &'a [String]) -> Self {
        let index = usize::from(argv.first().is_some_and(|arg| arg == "curl"));
        Self {
            argv,
            index,
            args: CurlArgs::default(),
        }
    }

    fn parse(&mut self) -> Result<CurlArgs, WrapperError> {
        while let Some(token) = self.next_token() {
            if token == "--" {
                self.parse_positionals_after_separator();
            } else if token.starts_with("--") {
                self.parse_long_option(&token)?;
            } else if token.starts_with('-') && token != "-" {
                self.parse_short_options(&token)?;
            } else {
                self.set_positional_url(token);
            }
        }
        Ok(std::mem::take(&mut self.args))
    }

    fn next_token(&mut self) -> Option<String> {
        let token = self.argv.get(self.index)?.clone();
        self.index += 1;
        Some(token)
    }

    fn parse_positionals_after_separator(&mut self) {
        while let Some(token) = self.next_token() {
            self.set_positional_url(token);
        }
    }

    fn parse_long_option(&mut self, token: &str) -> Result<(), WrapperError> {
        let (name, inline_value) = split_long_option(token);
        match name {
            "--output" => self.args.output = Some(self.option_value(name, inline_value)?),
            "--location" => self.args.follow_redirects = true,
            "--silent" => self.args.silent = true,
            "--show-error" => self.args.show_error = true,
            "--fail" => self.args.fail = true,
            "--header" => {
                let header = self.option_value(name, inline_value)?;
                self.args.headers.push(parse_header(&header));
            }
            "--insecure" => self.args.insecure = true,
            "--retry" => self.args.retry = Some(self.parse_retry(name, inline_value)?),
            "--user-agent" => self.args.user_agent = Some(self.option_value(name, inline_value)?),
            "--data" | "--data-raw" | "--data-binary" | "--data-urlencode" => {
                self.args.data = Some(self.option_value(name, inline_value)?);
            }
            "--remote-name" => self.args.remote_name = true,
            "--compressed" => self.args.compressed = true,
            "--request" => self.args.request_method = Some(self.option_value(name, inline_value)?),
            "--url" => self.args.url = Some(self.option_value(name, inline_value)?),
            "--form" | "--upload-file" | "--user" | "--proxy" | "--connect-to" | "--resolve"
            | "--interface" | "--unix-socket" | "--config" => {
                self.args.unsupported_options.push(name.to_owned());
                if inline_value.is_none() {
                    let _ = self.next_token();
                }
            }
            _ => self.args.unsupported_options.push(name.to_owned()),
        }
        Ok(())
    }

    fn parse_retry(&mut self, name: &str, inline_value: Option<&str>) -> Result<u32, WrapperError> {
        let value = self.option_value(name, inline_value)?;
        value
            .parse::<u32>()
            .map_err(|_| WrapperError::InvalidArguments {
                reason: format!("{name} requires a non-negative integer"),
            })
    }
    fn parse_short_options(&mut self, token: &str) -> Result<(), WrapperError> {
        let mut chars = token[1..].char_indices().peekable();
        while let Some((offset, flag)) = chars.next() {
            match flag {
                'o' | 'H' | 'A' | 'd' | 'X' | 'F' | 'T' | 'u' => {
                    let value = if let Some((next_offset, _)) = chars.peek().copied() {
                        token[(next_offset + 1)..].to_owned()
                    } else {
                        self.required_next_value(&format!("-{flag}"))?
                    };
                    self.apply_short_option_with_value(flag, value);
                    break;
                }
                'L' => self.args.follow_redirects = true,
                's' => self.args.silent = true,
                'S' => self.args.show_error = true,
                'f' => self.args.fail = true,
                'k' => self.args.insecure = true,
                'O' => self.args.remote_name = true,
                _ => self.args.unsupported_options.push(format!("-{flag}")),
            }
            let _ = offset;
        }
        Ok(())
    }

    fn apply_short_option_with_value(&mut self, flag: char, value: String) {
        match flag {
            'o' => self.args.output = Some(value),
            'H' => self.args.headers.push(parse_header(&value)),
            'A' => self.args.user_agent = Some(value),
            'd' => self.args.data = Some(value),
            'X' => self.args.request_method = Some(value),
            'F' | 'T' | 'u' => self.args.unsupported_options.push(format!("-{flag}")),
            _ => {}
        }
    }

    fn option_value(
        &mut self,
        name: &str,
        inline_value: Option<&str>,
    ) -> Result<String, WrapperError> {
        match inline_value {
            Some(value) => Ok(value.to_owned()),
            None => self.required_next_value(name),
        }
    }

    fn required_next_value(&mut self, option: &str) -> Result<String, WrapperError> {
        self.next_token()
            .ok_or_else(|| WrapperError::InvalidArguments {
                reason: format!("{option} requires a value"),
            })
    }

    fn set_positional_url(&mut self, token: String) {
        if self.args.url.is_none() {
            self.args.url = Some(token);
        } else {
            self.args.unsupported_options.push("extra-url".to_owned());
        }
    }
}

fn split_long_option(token: &str) -> (&str, Option<&str>) {
    token
        .split_once('=')
        .map_or((token, None), |(name, value)| (name, Some(value)))
}

fn parse_header(header: &str) -> (String, String) {
    header.split_once(':').map_or_else(
        || (header.trim().to_owned(), String::new()),
        |(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()),
    )
}
#[cfg(test)]
mod tests {
    use super::{
        CurlArgs, WrapperError, curl_to_operation_plan, parse_curl_args, remote_name_from_url,
    };
    use arbitraitor_plugin_api::{
        FilesystemCapability, NetworkCapability, PlannedOperation, SemanticConfidence,
    };

    #[test]
    fn fs_sl_output_translates_to_exact_plan() -> Result<(), WrapperError> {
        let args = parse(&["curl", "-fsSL", "https://example.com/file", "-o", "output"])?;
        let plan = curl_to_operation_plan(&args)?;

        assert_eq!(plan.semantic_confidence, SemanticConfidence::Exact);
        assert_eq!(
            plan.requested_capabilities.network,
            NetworkCapability::OutboundHttps
        );
        assert_eq!(
            plan.requested_capabilities.filesystem,
            FilesystemCapability::ReadWrite
        );
        assert_eq!(
            plan.operations,
            vec![
                PlannedOperation::Retrieve {
                    url: "https://example.com/file".to_owned(),
                    headers: Vec::new(),
                },
                PlannedOperation::ReleaseToFile {
                    path: "output".to_owned(),
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn plain_url_translates_to_partial_retrieve_only_plan() -> Result<(), WrapperError> {
        let args = parse(&["curl", "https://example.com"])?;
        let plan = curl_to_operation_plan(&args)?;

        assert_eq!(plan.semantic_confidence, SemanticConfidence::Partial);
        assert_eq!(
            plan.operations,
            vec![PlannedOperation::Retrieve {
                url: "https://example.com".to_owned(),
                headers: Vec::new(),
            }]
        );
        Ok(())
    }
    #[test]
    fn post_data_is_rejected_as_opaque() -> Result<(), WrapperError> {
        let args = parse(&["curl", "-X", "POST", "-d", "data", "https://example.com"])?;

        assert_eq!(
            curl_to_operation_plan(&args),
            Err(WrapperError::OpaqueTranslation {
                reason: "request bodies are unsupported by the download wrapper".to_owned(),
            })
        );
        Ok(())
    }

    #[test]
    fn retry_translates_to_equivalent_plan() -> Result<(), WrapperError> {
        let args = parse(&["curl", "--retry", "3", "https://example.com", "-o", "file"])?;
        let plan = curl_to_operation_plan(&args)?;

        assert_eq!(args.retry, Some(3));
        assert_eq!(plan.semantic_confidence, SemanticConfidence::Equivalent);
        Ok(())
    }

    #[test]
    fn parses_long_options_with_inline_values() -> Result<(), WrapperError> {
        let args = parse(&[
            "curl",
            "--output=artifact.bin",
            "--header=Accept: application/octet-stream",
            "--user-agent=ArbitraitorTest/1",
            "--retry=2",
            "--compressed",
            "--url=https://example.com/artifact.bin",
        ])?;

        assert_eq!(args.output.as_deref(), Some("artifact.bin"));
        assert_eq!(
            args.headers,
            vec![("accept".to_owned(), "application/octet-stream".to_owned())]
        );
        assert_eq!(args.user_agent.as_deref(), Some("ArbitraitorTest/1"));
        assert_eq!(args.retry, Some(2));
        assert!(args.compressed);
        assert_eq!(
            args.url.as_deref(),
            Some("https://example.com/artifact.bin")
        );
        Ok(())
    }

    #[test]
    fn parses_short_options_with_attached_values() -> Result<(), WrapperError> {
        let args = parse(&[
            "curl",
            "-fsSLoartifact.bin",
            "-HAccept: application/json",
            "-ATestAgent",
            "https://example.com/artifact.bin",
        ])?;

        assert!(args.fail);
        assert!(args.silent);
        assert!(args.show_error);
        assert!(args.follow_redirects);
        assert_eq!(args.output.as_deref(), Some("artifact.bin"));
        assert_eq!(
            args.headers,
            vec![("accept".to_owned(), "application/json".to_owned())]
        );
        assert_eq!(args.user_agent.as_deref(), Some("TestAgent"));
        Ok(())
    }
    #[test]
    fn redacts_sensitive_headers_in_operation_plan() -> Result<(), WrapperError> {
        let args = parse(&[
            "curl",
            "https://example.com/file",
            "-H",
            "Authorization: Bearer secret",
            "-H",
            "X-Test: visible",
        ])?;
        let plan = curl_to_operation_plan(&args)?;

        assert_eq!(
            plan.operations[0],
            PlannedOperation::Retrieve {
                url: "https://example.com/file".to_owned(),
                headers: vec![
                    ("authorization".to_owned(), "<redacted>".to_owned()),
                    ("x-test".to_owned(), "visible".to_owned()),
                ],
            }
        );
        Ok(())
    }

    #[test]
    fn remote_name_derives_release_path_from_url() -> Result<(), WrapperError> {
        let args = parse(&[
            "curl",
            "-O",
            "https://example.com/downloads/tool.tar.gz?x=1",
        ])?;
        let plan = curl_to_operation_plan(&args)?;

        assert_eq!(remote_name_from_url("https://example.com/a/b")?, "b");
        assert_eq!(
            plan.operations[1],
            PlannedOperation::ReleaseToFile {
                path: "tool.tar.gz".to_owned(),
            }
        );
        Ok(())
    }

    #[test]
    fn unsupported_noncritical_option_yields_partial_confidence() -> Result<(), WrapperError> {
        let args = parse(&[
            "curl",
            "--verbose",
            "https://example.com/file",
            "-o",
            "file",
        ])?;
        let plan = curl_to_operation_plan(&args)?;

        assert_eq!(args.unsupported_options, vec!["--verbose".to_owned()]);
        assert_eq!(plan.semantic_confidence, SemanticConfidence::Partial);
        Ok(())
    }

    #[test]
    fn critical_options_and_ftp_are_rejected_as_opaque() -> Result<(), WrapperError> {
        let critical = CurlArgs {
            url: Some("https://example.com".to_owned()),
            unsupported_options: vec!["--proxy".to_owned()],
            ..CurlArgs::default()
        };
        let ftp = parse(&["curl", "ftp://example.com/file"])?;

        assert!(matches!(
            curl_to_operation_plan(&critical),
            Err(WrapperError::OpaqueTranslation { .. })
        ));
        assert!(matches!(
            curl_to_operation_plan(&ftp),
            Err(WrapperError::OpaqueTranslation { .. })
        ));
        Ok(())
    }
    #[test]
    fn missing_required_value_is_an_error() {
        assert_eq!(
            parse(&["curl", "-o"]),
            Err(WrapperError::InvalidArguments {
                reason: "-o requires a value".to_owned(),
            })
        );
        assert!(matches!(
            parse(&["curl", "--retry", "not-a-number"]),
            Err(WrapperError::InvalidArguments { .. })
        ));
    }

    #[test]
    fn separator_treats_following_token_as_url() -> Result<(), WrapperError> {
        let args = parse(&["curl", "--", "-not-an-option"])?;

        assert_eq!(args.url.as_deref(), Some("-not-an-option"));
        Ok(())
    }

    fn parse(args: &[&str]) -> Result<CurlArgs, WrapperError> {
        parse_curl_args(&args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>())
    }
}
