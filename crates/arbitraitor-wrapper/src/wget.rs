//! wget command-line argument translator.
//!
//! Converts a subset of the wget command-line interface into Arbitraitor's
//! fetch model. Only retrieval-relevant flags are translated. Output-control
//! flags that Arbitraitor owns (`-q`/`--quiet`, `-v`/`--verbose`) are ignored.
//! Unknown flags are collected into [`WgetRequest::unsupported_options`] so
//! callers can reject security-critical options (via
//! [`is_critical_wget_option`]) while passing through non-critical ones with
//! reduced confidence.
//!
//! Flags that disable transport safety guarantees (currently
//! `--no-check-certificate`) are surfaced as [`arbitraitor_model::Finding`]
//! entries on the returned [`WgetRequest`] instead of being silently dropped,
//! so the wrapper caller can raise the appropriate verdict.

use std::path::PathBuf;

use arbitraitor_model::{
    finding::{Evidence, EvidenceKind, Finding, FindingCategory},
    ids::Sha256Digest,
    verdict::{Confidence, Severity},
};

pub use crate::error::WrapperError;

/// Detector identifier reported on findings produced by this wrapper.
pub const WGET_WRAPPER_DETECTOR: &str = "arbitraitor-wrapper";

/// Stable finding identifier for `--no-check-certificate` detections.
const WGET_NO_CHECK_CERTIFICATE_FINDING_ID: &str = "wget-no-check-certificate";

/// Returns `true` if an unsupported wget option is security-critical — i.e. it
/// can bypass the inspection boundary (proxy redirection, config file reads,
/// credential injection, TLS trust store manipulation, etc.).
///
/// Callers use this to decide whether to hard-reject an invocation instead of
/// allowing the option to pass through with reduced confidence.
#[must_use]
pub fn is_critical_wget_option(option: &str) -> bool {
    matches!(
        option,
        // Post data / upload semantics
        "--post-data"
            | "--post-file"
            // Credentials
            | "--http-user"
            | "--http-password"
            | "--ftp-user"
            | "--ftp-password"
            // Proxy / routing bypass
            | "-e"
            | "--execute"
            | "--no-proxy"
            | "--input-file"
            // Config / trust store manipulation
            | "--config"
            | "--load-cookies"
            | "--save-cookies"
            | "--ca-certificate"
            | "--ca-directory"
            | "--crl-file"
            | "--certificate"
            | "--private-key"
            | "--random-file"
            | "--egd-file"
    )
}

/// Parsed wget arguments translated to Arbitraitor's fetch model.
#[derive(Debug, Clone, PartialEq)]
pub struct WgetRequest {
    /// First URL to retrieve.
    pub url: String,
    /// All positional URLs observed on the command line.
    ///
    /// Multi-URL invocations must create independent artifact identities and
    /// verdicts. The first entry mirrors `url`; subsequent entries are
    /// additional URLs that wget would fetch independently.
    pub urls: Vec<String>,
    /// Output file path from `-O` / `--output-document`.
    pub output_path: Option<PathBuf>,
    /// Custom request headers from repeatable `--header` flags.
    pub headers: Vec<(String, String)>,
    /// User-Agent string from `-U` / `--user-agent`.
    pub user_agent: Option<String>,
    /// Network timeout in seconds from `-T` / `--timeout`.
    pub timeout_secs: Option<u64>,
    /// Maximum redirect hops from `--max-redirect`.
    pub max_redirect: Option<u32>,
    /// Whether `--no-check-certificate` disabled TLS verification.
    pub no_check_certificate: bool,
    /// Findings produced during argv translation. Callers must
    /// surface these so dangerous flags cannot be silently dropped.
    pub findings: Vec<Finding>,
    /// Unsupported options observed while parsing. Non-critical options are
    /// collected here so callers can decide whether to reject or pass through
    /// with reduced confidence.
    pub unsupported_options: Vec<String>,
}

/// Translates wget CLI arguments into an Arbitraitor fetch request.
///
/// Accepts the argv slice with or without a leading `wget` program name.
///
/// # Errors
///
/// Returns [`WrapperError::MissingUrl`] when no positional URL is present,
/// or [`WrapperError::InvalidValue`] when a value-taking flag is missing its
/// value or receives a non-numeric value where a number is required.
/// Unsupported flags are collected into [`WgetRequest::unsupported_options`]
/// instead of returning an error.
pub fn translate_wget_args(args: &[String]) -> Result<WgetRequest, WrapperError> {
    WgetParser::new(args).parse()
}

/// Converts a [`WgetRequest`] into an Arbitraitor fetch URL and header list.
///
/// The returned vector contains the caller-supplied headers followed by a
/// `user-agent` entry when `-U` / `--user-agent` was provided.
#[must_use]
pub fn to_fetch_request(wget: &WgetRequest) -> (String, Vec<(String, String)>) {
    let mut headers = wget.headers.clone();
    if let Some(user_agent) = &wget.user_agent {
        headers.push(("user-agent".to_owned(), user_agent.clone()));
    }
    (wget.url.clone(), headers)
}

/// Stateful wget argv parser.
struct WgetParser<'a> {
    args: &'a [String],
    index: usize,
    url: Option<String>,
    urls: Vec<String>,
    output_path: Option<PathBuf>,
    headers: Vec<(String, String)>,
    user_agent: Option<String>,
    timeout_secs: Option<u64>,
    max_redirect: Option<u32>,
    no_check_certificate: bool,
    after_separator: bool,
    unsupported_options: Vec<String>,
}

impl<'a> WgetParser<'a> {
    fn new(args: &'a [String]) -> Self {
        let index = usize::from(args.first().is_some_and(|arg| arg == "wget"));
        Self {
            args,
            index,
            url: None,
            urls: Vec::new(),
            output_path: None,
            headers: Vec::new(),
            user_agent: None,
            timeout_secs: None,
            max_redirect: None,
            no_check_certificate: false,
            after_separator: false,
            unsupported_options: Vec::new(),
        }
    }

    fn parse(mut self) -> Result<WgetRequest, WrapperError> {
        while let Some(token) = self.next_token() {
            if self.after_separator {
                self.set_url(token);
            } else if token == "--" {
                self.after_separator = true;
            } else if let Some(body) = token.strip_prefix("--") {
                self.parse_long_option(body)?;
            } else if token.len() > 1 && token.starts_with('-') {
                self.parse_short_options(&token[1..])?;
            } else if looks_like_url(&token) {
                self.set_url(token);
            }
        }
        let url = self.url.clone().ok_or(WrapperError::MissingUrl)?;
        let findings = build_findings(&self);
        Ok(WgetRequest {
            url: url.clone(),
            urls: self.urls,
            output_path: self.output_path,
            headers: self.headers,
            user_agent: self.user_agent,
            timeout_secs: self.timeout_secs,
            max_redirect: self.max_redirect,
            no_check_certificate: self.no_check_certificate,
            findings,
            unsupported_options: self.unsupported_options,
        })
    }

    fn next_token(&mut self) -> Option<String> {
        let token = self.args.get(self.index)?.clone();
        self.index += 1;
        Some(token)
    }

    fn set_url(&mut self, token: String) {
        if self.url.is_none() {
            self.url = Some(token.clone());
        }
        self.urls.push(token);
    }

    fn parse_long_option(&mut self, body: &str) -> Result<(), WrapperError> {
        let (name, inline_value) = match body.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (body, None),
        };
        let canonical = format!("--{name}");
        match name {
            "output-document" => {
                let value = self.require_value(&canonical, inline_value)?;
                self.output_path = Some(PathBuf::from(value));
            }
            "header" => {
                let value = self.require_value(&canonical, inline_value)?;
                self.headers.push(parse_header(&value));
            }
            "user-agent" => {
                let value = self.require_value(&canonical, inline_value)?;
                self.user_agent = Some(value);
            }
            "timeout" => {
                let value = self.require_value(&canonical, inline_value)?;
                self.timeout_secs = Some(parse_u64(&canonical, &value)?);
            }
            "max-redirect" => {
                let value = self.require_value(&canonical, inline_value)?;
                self.max_redirect = Some(parse_u32(&canonical, &value)?);
            }
            "no-check-certificate" => {
                reject_inline_value(&canonical, inline_value)?;
                self.no_check_certificate = true;
            }
            "quiet" | "verbose" => {
                reject_inline_value(&canonical, inline_value)?;
            }
            _ => {
                self.unsupported_options.push(canonical);
                if inline_value.is_none() {
                    self.consume_unknown_value();
                }
            }
        }
        Ok(())
    }

    fn parse_short_options(&mut self, body: &str) -> Result<(), WrapperError> {
        for (offset, flag) in body.char_indices() {
            let rest = &body[offset + flag.len_utf8()..];
            match flag {
                'O' => {
                    let value = self.consume_short_value("-O", rest)?;
                    self.output_path = Some(PathBuf::from(value));
                    return Ok(());
                }
                'U' => {
                    let value = self.consume_short_value("-U", rest)?;
                    self.user_agent = Some(value);
                    return Ok(());
                }
                'T' => {
                    let value = self.consume_short_value("-T", rest)?;
                    self.timeout_secs = Some(parse_u64("-T", &value)?);
                    return Ok(());
                }
                'q' | 'v' => {}
                other => {
                    self.unsupported_options.push(format!("-{other}"));
                    if rest.is_empty() {
                        self.consume_unknown_value();
                    }
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn consume_unknown_value(&mut self) {
        if let Some(next) = self.args.get(self.index)
            && !is_flag_like(next)
            && !looks_like_url(next)
        {
            let _ = self.next_token();
        }
    }

    fn consume_short_value(&mut self, flag: &str, rest: &str) -> Result<String, WrapperError> {
        if rest.is_empty() {
            self.next_token().ok_or(WrapperError::InvalidValue {
                flag: flag.to_owned(),
                message: "missing value".to_owned(),
            })
        } else {
            Ok(rest.to_owned())
        }
    }

    fn require_value(&mut self, flag: &str, inline: Option<&str>) -> Result<String, WrapperError> {
        match inline {
            Some(value) => Ok(value.to_owned()),
            None => self.next_token().ok_or(WrapperError::InvalidValue {
                flag: flag.to_owned(),
                message: "missing value".to_owned(),
            }),
        }
    }
}

/// Splits a `Name: Value` header string into trimmed name and value.
fn parse_header(raw: &str) -> (String, String) {
    match raw.split_once(':') {
        Some((name, value)) => (name.trim().to_ascii_lowercase(), value.trim().to_owned()),
        None => (raw.trim().to_ascii_lowercase(), String::new()),
    }
}

fn looks_like_url(token: &str) -> bool {
    token.starts_with("http://")
        || token.starts_with("https://")
        || token.starts_with("ftp://")
        || token.starts_with("ftps://")
}

fn is_flag_like(token: &str) -> bool {
    token.starts_with('-') && token != "-"
}

/// Parses a non-negative integer, returning a safe error on failure.
fn parse_u64(flag: &str, value: &str) -> Result<u64, WrapperError> {
    value
        .parse::<u64>()
        .map_err(|_| WrapperError::InvalidValue {
            flag: flag.to_owned(),
            message: "expected a non-negative integer".to_owned(),
        })
}

/// Parses a non-negative integer that fits in `u32`.
fn parse_u32(flag: &str, value: &str) -> Result<u32, WrapperError> {
    value
        .parse::<u32>()
        .map_err(|_| WrapperError::InvalidValue {
            flag: flag.to_owned(),
            message: "expected a non-negative integer".to_owned(),
        })
}

/// Rejects an inline value for a boolean flag.
fn reject_inline_value(flag: &str, inline: Option<&str>) -> Result<(), WrapperError> {
    if inline.is_some() {
        return Err(WrapperError::InvalidValue {
            flag: flag.to_owned(),
            message: "flag does not take a value".to_owned(),
        });
    }
    Ok(())
}

/// Builds the list of [`Finding`]s reported for a parsed invocation.
///
/// The wrapper must surface dangerous transport-affecting flags
/// instead of silently dropping them. The artifact digest is a zero placeholder
/// because translation happens before any bytes are retrieved.
fn build_findings(parser: &WgetParser<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    if parser.no_check_certificate {
        findings.push(no_check_certificate_finding());
    }
    findings
}

/// Builds the [`Finding`] emitted when `--no-check-certificate` disables TLS
/// certificate verification.
fn no_check_certificate_finding() -> Finding {
    Finding {
        id: WGET_NO_CHECK_CERTIFICATE_FINDING_ID.to_owned(),
        detector: WGET_WRAPPER_DETECTOR.to_owned(),
        category: FindingCategory::Transport,
        severity: Severity::High,
        confidence: Confidence::High,
        title: "TLS certificate verification disabled via --no-check-certificate".to_owned(),
        description:
            "The wget wrapper detected --no-check-certificate which disables TLS certificate \
             verification. This removes transport encryption guarantees and may allow \
             man-in-the-middle attacks."
                .to_owned(),
        evidence: vec![Evidence {
            kind: EvidenceKind::Command,
            description: "wget flag observed in argv".to_owned(),
            content: Some("--no-check-certificate".to_owned()),
        }],
        artifact_sha256: Sha256Digest::new([0; 32]),
        location: None,
        remediation: Some(
            "Remove --no-check-certificate so wget validates the server certificate against \
             the system trust store before transferring bytes."
                .to_owned(),
        ),
        references: Vec::new(),
        tags: vec!["wrapper".to_owned(), "tls-disable".to_owned()],
        taxonomies: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        WgetRequest, WrapperError, is_critical_wget_option, to_fetch_request, translate_wget_args,
    };
    use arbitraitor_model::{
        finding::FindingCategory,
        ids::Sha256Digest,
        verdict::{Confidence, Severity},
    };

    fn parse(args: &[&str]) -> Result<WgetRequest, WrapperError> {
        translate_wget_args(&args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn translates_simple_url() -> Result<(), WrapperError> {
        let result = parse(&["wget", "https://example.com/file"])?;
        assert_eq!(result.url, "https://example.com/file");
        assert_eq!(result.output_path, None);
        assert!(result.headers.is_empty());
        assert_eq!(result.user_agent, None);
        assert_eq!(result.timeout_secs, None);
        assert_eq!(result.max_redirect, None);
        assert!(!result.no_check_certificate);
        assert!(result.findings.is_empty());
        Ok(())
    }

    #[test]
    fn translates_output_document() -> Result<(), WrapperError> {
        let result = parse(&["wget", "-O", "/tmp/file", "https://example.com/file"])?;
        assert_eq!(result.url, "https://example.com/file");
        assert_eq!(result.output_path.as_deref(), Some(Path::new("/tmp/file")));

        // Long form with inline value.
        let result = parse(&[
            "wget",
            "--output-document=/var/out",
            "https://example.com/file",
        ])?;
        assert_eq!(result.output_path.as_deref(), Some(Path::new("/var/out")));
        Ok(())
    }

    #[test]
    fn translates_headers() -> Result<(), WrapperError> {
        let result = parse(&[
            "wget",
            "--header",
            "Authorization: Bearer xxx",
            "https://example.com/file",
        ])?;
        assert_eq!(
            result.headers,
            vec![("authorization".to_owned(), "Bearer xxx".to_owned())]
        );
        Ok(())
    }

    #[test]
    fn translates_user_agent() -> Result<(), WrapperError> {
        let result = parse(&["wget", "-U", "MyAgent", "https://example.com/file"])?;
        assert_eq!(result.user_agent.as_deref(), Some("MyAgent"));

        let result = parse(&[
            "wget",
            "--user-agent=CustomAgent/2",
            "https://example.com/file",
        ])?;
        assert_eq!(result.user_agent.as_deref(), Some("CustomAgent/2"));
        Ok(())
    }

    #[test]
    fn translates_timeout() -> Result<(), WrapperError> {
        let result = parse(&["wget", "-T", "30", "https://example.com/file"])?;
        assert_eq!(result.timeout_secs, Some(30));

        let result = parse(&["wget", "--timeout=60", "https://example.com/file"])?;
        assert_eq!(result.timeout_secs, Some(60));
        Ok(())
    }

    #[test]
    fn translates_multiple_headers() -> Result<(), WrapperError> {
        let result = parse(&[
            "wget",
            "--header",
            "Authorization: Bearer xxx",
            "--header",
            "X-Custom: value",
            "--header",
            "Accept: application/json",
            "https://example.com/file",
        ])?;
        assert_eq!(
            result.headers,
            vec![
                ("authorization".to_owned(), "Bearer xxx".to_owned()),
                ("x-custom".to_owned(), "value".to_owned()),
                ("accept".to_owned(), "application/json".to_owned()),
            ]
        );
        Ok(())
    }

    #[test]
    fn rejects_no_url() {
        assert_eq!(parse(&["wget", "-q"]), Err(WrapperError::MissingUrl));
    }

    #[test]
    fn handles_double_dash() -> Result<(), WrapperError> {
        let result = parse(&["wget", "--", "https://example.com"])?;
        assert_eq!(result.url, "https://example.com");

        // Everything after `--` is positional even if it looks like a flag.
        let result = parse(&["wget", "--", "-O"])?;
        assert_eq!(result.url, "-O");
        Ok(())
    }

    #[test]
    fn flags_no_check_certificate() -> Result<(), WrapperError> {
        let result = parse(&["wget", "--no-check-certificate", "https://example.com/file"])?;
        assert!(result.no_check_certificate);

        let result = parse(&["wget", "https://example.com/file"])?;
        assert!(!result.no_check_certificate);
        Ok(())
    }

    #[test]
    fn no_check_certificate_produces_transport_finding() -> Result<(), WrapperError> {
        let result = parse(&["wget", "--no-check-certificate", "https://example.com/file"])?;
        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert_eq!(finding.detector, "arbitraitor-wrapper");
        assert_eq!(finding.category, FindingCategory::Transport);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::High);
        assert!(finding.title.contains("--no-check-certificate"));
        assert!(finding.description.contains("TLS"));
        assert!(
            finding
                .tags
                .iter()
                .any(|tag| tag == "wrapper" || tag == "tls-disable"),
            "finding must carry wrapper/tls-disable tags: {:?}",
            finding.tags,
        );
        assert_eq!(finding.artifact_sha256, Sha256Digest::new([0; 32]));
        Ok(())
    }

    #[test]
    fn plain_invocation_produces_no_findings() -> Result<(), WrapperError> {
        let result = parse(&["wget", "https://example.com/file"])?;
        assert!(result.findings.is_empty());
        Ok(())
    }

    #[test]
    fn no_check_certificate_produces_finding_alongside_other_flags() -> Result<(), WrapperError> {
        let result = parse(&[
            "wget",
            "-q",
            "--no-check-certificate",
            "--timeout=30",
            "-O",
            "/tmp/out",
            "https://example.com/file",
        ])?;
        assert!(result.no_check_certificate);
        assert_eq!(result.timeout_secs, Some(30));
        assert_eq!(result.output_path.as_deref(), Some(Path::new("/tmp/out")));
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].category, FindingCategory::Transport);
        assert_eq!(result.findings[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn to_fetch_request_produces_correct_output() {
        let request = WgetRequest {
            url: "https://example.com/file".to_owned(),
            urls: vec!["https://example.com/file".to_owned()],
            output_path: None,
            headers: vec![("accept".to_owned(), "application/json".to_owned())],
            user_agent: Some("TestAgent/1".to_owned()),
            timeout_secs: Some(30),
            max_redirect: Some(5),
            no_check_certificate: true,
            findings: Vec::new(),
            unsupported_options: Vec::new(),
        };
        let (url, headers) = to_fetch_request(&request);
        assert_eq!(url, "https://example.com/file");
        assert_eq!(
            headers,
            vec![
                ("accept".to_owned(), "application/json".to_owned()),
                ("user-agent".to_owned(), "TestAgent/1".to_owned()),
            ]
        );
    }

    #[test]
    fn unsupported_flags_are_collected_not_rejected() -> Result<(), WrapperError> {
        let result = parse(&["wget", "--post-data=secret", "https://example.com"])?;
        assert!(
            result
                .unsupported_options
                .contains(&"--post-data".to_owned())
        );
        assert!(
            result
                .unsupported_options
                .iter()
                .any(|opt| is_critical_wget_option(opt))
        );

        let result = parse(&["wget", "-x", "https://example.com"])?;
        assert!(result.unsupported_options.contains(&"-x".to_owned()));

        let result = parse(&["wget", "--unknown-flag", "val", "https://example.com"])?;
        assert!(
            result
                .unsupported_options
                .contains(&"--unknown-flag".to_owned())
        );
        assert_eq!(result.url, "https://example.com");
        assert!(!result.urls.contains(&"val".to_owned()));
        Ok(())
    }

    #[test]
    fn rejects_invalid_timeout() {
        assert!(matches!(
            parse(&["wget", "-T", "abc", "https://example.com"]),
            Err(WrapperError::InvalidValue { flag, .. }) if flag == "-T"
        ));
        assert!(matches!(
            parse(&["wget", "--timeout=-1", "https://example.com"]),
            Err(WrapperError::InvalidValue { flag, .. }) if flag == "--timeout"
        ));
    }

    #[test]
    fn rejects_missing_value_for_short_option() {
        assert!(matches!(
            parse(&["wget", "-O"]),
            Err(WrapperError::InvalidValue { flag, .. }) if flag == "-O"
        ));
    }

    #[test]
    fn translates_max_redirect() -> Result<(), WrapperError> {
        let result = parse(&["wget", "--max-redirect=5", "https://example.com/file"])?;
        assert_eq!(result.max_redirect, Some(5));
        Ok(())
    }

    #[test]
    fn works_without_leading_wget() -> Result<(), WrapperError> {
        let result = parse(&["-O", "/tmp/out", "https://example.com"])?;
        assert_eq!(result.url, "https://example.com");
        assert_eq!(result.output_path.as_deref(), Some(Path::new("/tmp/out")));
        Ok(())
    }

    #[test]
    fn bundles_short_boolean_flags() -> Result<(), WrapperError> {
        // `-qv` are both ignored; URL is still captured.
        let result = parse(&["wget", "-qv", "https://example.com"])?;
        assert_eq!(result.url, "https://example.com");
        Ok(())
    }

    #[test]
    fn attached_short_value_parses() -> Result<(), WrapperError> {
        let result = parse(&["wget", "-O/tmp/out", "https://example.com"])?;
        assert_eq!(result.output_path.as_deref(), Some(Path::new("/tmp/out")));

        let result = parse(&["wget", "-T30", "https://example.com"])?;
        assert_eq!(result.timeout_secs, Some(30));
        Ok(())
    }

    #[test]
    fn multiple_urls_are_collected_not_ignored() -> Result<(), WrapperError> {
        let result = parse(&[
            "wget",
            "https://example.com/a",
            "https://example.com/b",
            "https://example.com/c",
        ])?;

        assert_eq!(result.url, "https://example.com/a");
        assert_eq!(
            result.urls,
            [
                "https://example.com/a",
                "https://example.com/b",
                "https://example.com/c"
            ]
        );
        Ok(())
    }

    #[test]
    fn single_url_populates_both_url_and_urls() -> Result<(), WrapperError> {
        let result = parse(&["wget", "https://example.com/only"])?;

        assert_eq!(result.url, "https://example.com/only");
        assert_eq!(result.urls, ["https://example.com/only"]);
        Ok(())
    }

    #[test]
    fn unknown_long_option_value_not_treated_as_url() -> Result<(), WrapperError> {
        let result = parse(&[
            "wget",
            "--unknown-flag",
            "not-a-url",
            "https://example.com/file",
        ])?;

        assert!(
            result
                .unsupported_options
                .contains(&"--unknown-flag".to_owned())
        );
        assert_eq!(result.url, "https://example.com/file");
        assert!(!result.urls.contains(&"not-a-url".to_owned()));
        Ok(())
    }

    #[test]
    fn unknown_short_option_consumes_value() -> Result<(), WrapperError> {
        let result = parse(&["wget", "-z", "value", "https://example.com/file"])?;

        assert!(result.unsupported_options.contains(&"-z".to_owned()));
        assert_eq!(result.url, "https://example.com/file");
        assert!(!result.urls.contains(&"value".to_owned()));
        Ok(())
    }

    #[test]
    fn critical_wget_options_are_flagged() -> Result<(), WrapperError> {
        let result = parse(&["wget", "--post-data=secret", "https://example.com/file"])?;

        assert!(
            result
                .unsupported_options
                .iter()
                .any(|opt| is_critical_wget_option(opt))
        );
        Ok(())
    }

    #[test]
    fn non_critical_wget_options_are_passthrough() -> Result<(), WrapperError> {
        let result = parse(&[
            "wget",
            "--unknown-option",
            "val",
            "https://example.com/file",
        ])?;

        assert!(
            result
                .unsupported_options
                .contains(&"--unknown-option".to_owned())
        );
        assert!(
            !result
                .unsupported_options
                .iter()
                .any(|opt| is_critical_wget_option(opt))
        );
        assert_eq!(result.url, "https://example.com/file");
        Ok(())
    }

    #[test]
    fn critical_wget_option_consumes_value() -> Result<(), WrapperError> {
        let result = parse(&[
            "wget",
            "--http-user",
            "admin",
            "--http-password",
            "secret",
            "https://example.com/file",
        ])?;

        assert!(
            result
                .unsupported_options
                .contains(&"--http-user".to_owned())
        );
        assert!(
            result
                .unsupported_options
                .contains(&"--http-password".to_owned())
        );
        assert!(
            result
                .unsupported_options
                .iter()
                .all(|opt| { !opt.contains("admin") && !opt.contains("secret") })
        );
        assert_eq!(result.url, "https://example.com/file");
        Ok(())
    }
}
