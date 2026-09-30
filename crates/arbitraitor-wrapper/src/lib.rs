//! Downloader and tool wrapper plugin implementations
//!
//! See `docs/spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod init;
pub mod shim;
pub mod wget;

use thiserror::Error;

/// Parsed subset of a curl invocation supported by the download wrapper.
#[allow(
    clippy::struct_excessive_bools,
    reason = "curl exposes independent boolean flags that must remain visible to confidence assessment"
)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CurlArgs {
    /// First URL to retrieve (backward-compatible single-URL accessor).
    pub url: Option<String>,
    /// All positional URLs observed on the command line.
    ///
    /// Multi-URL invocations must create independent artifact identities and
    /// verdicts. The first entry mirrors `url`; subsequent entries are
    /// additional URLs that curl would fetch independently.
    pub urls: Vec<String>,
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
    /// Whether a header-only request was requested (`-I`, `--head`).
    ///
    /// Header-only responses cannot be represented by the download wrapper
    /// model (a single Retrieve operation returning artifact bytes), so
    /// invocations carrying this flag are rejected explicitly instead of
    /// being silently downgraded to a full GET.
    pub head: bool,
    /// Unsupported options observed while parsing.
    ///
    /// This field is the enforcement channel for security-critical options:
    /// the CLI's `bail_on_critical` path filters these strings through
    /// [`is_critical_unsupported_option`] and hard-rejects the invocation
    /// before any network access. TLS-verification-disabling flags
    /// (`-k`/`--insecure`) are both parsed into [`CurlArgs::insecure`] and
    /// recorded here so that rejection fires — parsing alone is not
    /// enforcement. Mirrors `WgetRequest::unsupported_options` on the wget
    /// side.
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
/// Returns `true` if an unsupported curl option is security-critical — i.e. it
/// can bypass the inspection boundary (TLS verification disabling, proxy
/// redirection, config file reads, credential injection, socket binding, etc.).
///
/// Callers use this to decide whether to hard-reject an invocation instead of
/// allowing the option to pass through with reduced confidence.
#[must_use]
pub fn is_critical_unsupported_option(option: &str) -> bool {
    matches!(
        option,
        // Upload / state-changing semantics
        "-F" | "--form"
            | "-T"
            | "--upload-file"
            // Credentials
            | "-u"
            | "--user"
            | "-U"
            | "--proxy-user"
            // Proxy / routing bypass
            | "-x"
            | "--proxy"
            | "--preproxy"
            | "--proxy1.0"
            | "--socks5"
            | "--socks5-hostname"
            | "--socks4"
            | "--socks4a"
            | "--proxy-header"
            | "--connect-to"
            | "--resolve"
            | "--interface"
            | "--unix-socket"
            | "--abstract-unix-socket"
            // TLS verification disabling — removes the boundary's
            // man-in-the-middle protection guarantee (§4.3, §39.9)
            | "-k"
            | "--insecure"
            // Config / trust store manipulation
            | "-K"
            | "--config"
            | "--cacert"
            | "--capath"
            | "--crlfile"
            | "-E"
            | "--cert"
            | "--key"
            | "--pass"
            | "--proxy-cacert"
            | "--proxy-capath"
            | "--proxy-cert"
            | "--proxy-key"
            | "--proxy-pass"
            | "--proxy-crlfile"
    )
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

/// How a parsed URL was sourced, tracked so a scheme-qualified URL outranks
/// an earlier scheme-less one for the single-URL accessor. Decided on raw
/// tokens because normalization erases the distinction (a scheme-less
/// `host:8080/x` becomes `http://…`-prefixed).
#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum UrlExplicitness {
    /// A scheme-less positional, normalized to `http://…`.
    #[default]
    Schemeless,
    /// A token with an explicit scheme prefix.
    Explicit,
}

impl UrlExplicitness {
    /// Classifies a raw token by whether it carries an explicit scheme
    /// prefix. Must be called before normalization, which erases the
    /// scheme-less/explicit distinction for `http://` results.
    fn from_raw(token: &str) -> Self {
        if looks_like_explicit_url(token) {
            Self::Explicit
        } else {
            Self::Schemeless
        }
    }
}

struct CurlParser<'a> {
    argv: &'a [String],
    index: usize,
    args: CurlArgs,
    /// How the URL in `args.url` was sourced, tracked so a scheme-qualified
    /// URL outranks an earlier scheme-less one for the single-URL accessor.
    url_explicit: UrlExplicitness,
}
impl<'a> CurlParser<'a> {
    fn new(argv: &'a [String]) -> Self {
        let index = usize::from(argv.first().is_some_and(|arg| arg == "curl"));
        Self {
            argv,
            index,
            args: CurlArgs::default(),
            url_explicit: UrlExplicitness::default(),
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
            } else if looks_like_url(&token) {
                self.set_positional_url(&token);
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
            self.set_positional_url(&token);
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
            "--insecure" => {
                self.args.insecure = true;
                self.args.unsupported_options.push("--insecure".to_owned());
            }
            "--retry" => self.args.retry = Some(self.parse_retry(name, inline_value)?),
            "--user-agent" => self.args.user_agent = Some(self.option_value(name, inline_value)?),
            "--data" | "--data-raw" | "--data-binary" | "--data-urlencode" => {
                self.args.data = Some(self.option_value(name, inline_value)?);
            }
            "--remote-name" => self.args.remote_name = true,
            "--compressed" => self.args.compressed = true,
            "--request" => self.args.request_method = Some(self.option_value(name, inline_value)?),
            "--head" => self.args.head = true,
            "--url" => {
                let value = self.option_value(name, inline_value)?;
                self.args.url = Some(normalize_wrapper_url(&value));
            }
            "--form"
            | "--upload-file"
            | "--user"
            | "--proxy"
            | "--connect-to"
            | "--resolve"
            | "--interface"
            | "--unix-socket"
            | "--config"
            | "--preproxy"
            | "--proxy1.0"
            | "--socks5"
            | "--socks5-hostname"
            | "--socks4"
            | "--socks4a"
            | "--proxy-header"
            | "--proxy-user"
            | "--abstract-unix-socket"
            | "--cacert"
            | "--capath"
            | "--crlfile"
            | "--cert"
            | "--key"
            | "--pass"
            | "--proxy-cacert"
            | "--proxy-capath"
            | "--proxy-cert"
            | "--proxy-key"
            | "--proxy-pass"
            | "--proxy-crlfile" => {
                self.args.unsupported_options.push(name.to_owned());
                if inline_value.is_none() {
                    let _ = self.next_token();
                }
            }
            _ => {
                self.args.unsupported_options.push(name.to_owned());
                if inline_value.is_none() {
                    self.consume_unknown_option_value();
                }
            }
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
                'o' | 'H' | 'A' | 'd' | 'X' | 'F' | 'T' | 'u' | 'x' | 'U' | 'K' | 'E' => {
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
                'I' => self.args.head = true,
                'k' => {
                    self.args.insecure = true;
                    self.args.unsupported_options.push("-k".to_owned());
                }
                'O' => self.args.remote_name = true,
                _ => {
                    self.args.unsupported_options.push(format!("-{flag}"));
                    if chars.peek().is_none() {
                        self.consume_unknown_option_value();
                    }
                }
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
            'F' | 'T' | 'u' | 'x' | 'U' | 'K' | 'E' => {
                self.args.unsupported_options.push(format!("-{flag}"));
            }
            _ => {}
        }
    }

    fn consume_unknown_option_value(&mut self) {
        if let Some(next) = self.argv.get(self.index)
            && !is_flag_like(next)
            && !looks_like_explicit_url(next)
        {
            let _ = self.next_token();
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

    fn set_positional_url(&mut self, token: &str) {
        // Explicitness is decided on the RAW token: after normalization a
        // scheme-less `host:8080/x` is also `http://…`-prefixed and would
        // be indistinguishable from an explicit `http://` URL.
        let url_explicit = UrlExplicitness::from_raw(token);
        let url = normalize_wrapper_url(token);
        // A scheme-qualified URL always wins the single-URL accessor, even
        // if a scheme-less positional appeared first (`curl host:8080/x
        // https://real/x` mirrors curl fetching both, with `url` reporting
        // the explicitly-schemed one). Two scheme-less positionals keep
        // first-wins.
        let replaces = self.args.url.is_none()
            || (url_explicit == UrlExplicitness::Explicit
                && self.url_explicit != UrlExplicitness::Explicit);
        if replaces {
            self.url_explicit = url_explicit;
            self.args.url = Some(url.clone());
        }
        self.args.urls.push(url);
    }
}

fn split_long_option(token: &str) -> (&str, Option<&str>) {
    token
        .split_once('=')
        .map_or((token, None), |(name, value)| (name, Some(value)))
}

fn looks_like_url(token: &str) -> bool {
    token.starts_with("http://")
        || token.starts_with("https://")
        || token.starts_with("ftp://")
        || token.starts_with("ftps://")
        || is_schemeless_host_url(token)
}

/// Conservative URL predicate for *option-value consumption* decisions.
///
/// Unknown options consume their value unless it is flag-like or a
/// scheme-qualified URL. The scheme-less heuristic is deliberately excluded
/// here: an unknown option's value (e.g. `-o download.log`, `-Z file.txt`)
/// must be consumed as a value, never mistaken for a fetch target, even
/// though the same token in a genuine positional slot would be a URL.
fn looks_like_explicit_url(token: &str) -> bool {
    token.starts_with("http://")
        || token.starts_with("https://")
        || token.starts_with("ftp://")
        || token.starts_with("ftps://")
}

/// True when `token` is a scheme-less `host[:port][/path]` argument that real
/// `curl`/`wget` would treat as an `http://` URL (curl's default protocol).
///
/// Recognizes dotted hosts (`example.com`), `localhost`, port syntax
/// (`host:8080`), and bracketed IPv6 (`[::1]:8080/x`). userinfo form
/// (`user:pass@host`) is deliberately NOT recognized — the parser cannot
/// reliably separate credentials from `host:port` shape, and such URLs are
/// rare in wrapper invocations; callers needing them should use an explicit
/// `http://` prefix.
///
/// Deliberately conservative to avoid misclassifying plain option values:
/// the token must carry one of the shapes above. A bare single label
/// without separators (`5`) is left alone even though real curl would
/// resolve it as a hostname — the parser cannot distinguish that from an
/// unknown option's value, and failing to fetch is safer than consuming an
/// option value as a fetch target. Tokens with an explicit `scheme:` prefix
/// are excluded here; they are handled by the exact prefix checks in
/// [`looks_like_url`] / [`looks_like_explicit_url`] or by the fetch layer's
/// own scheme policy.
fn is_schemeless_host_url(token: &str) -> bool {
    if token.contains("://") {
        return false;
    }
    let authority = token.split(['/', '?', '#']).next().unwrap_or("");
    // Bracketed IPv6 literal: `[addr]` or `[addr]:port`. The address itself
    // may contain colons, so the host is the bracketed span, not the text
    // before the last colon.
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((addr, port_part)) = rest.split_once(']') else {
            return false;
        };
        if addr.is_empty()
            || !addr
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        {
            return false;
        }
        // Optional `:port` after the closing bracket must be numeric.
        return port_part.is_empty()
            || port_part
                .strip_prefix(':')
                .is_some_and(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    }
    if authority.contains('@') {
        return false;
    }
    // Port syntax requires an actual port after the colon (`host:8080`); a
    // bare trailing colon (`8080:`) does not carry the host:port signal on
    // its own.
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(h, p)| (h, Some(p)));
    let has_port = port.is_some_and(|p| !p.is_empty());
    let plausible_host = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '[' | ']' | '%'));
    plausible_host && (has_port || host.contains('.') || host.eq_ignore_ascii_case("localhost"))
}

/// Normalizes a scheme-less `host[:port][/path]` argument to the `http://`
/// URL that real `curl`/`wget` would fetch (their default protocol), so the
/// argument flows through the same parse/FetchPolicy/SSRF pipeline as an
/// explicit `http://` URL. Scheme-qualified URLs pass through unchanged;
/// whether plaintext `http` is fetchable remains governed by fetch policy.
#[must_use]
pub fn normalize_wrapper_url(url: &str) -> String {
    if looks_like_url(url) && !url.contains("://") {
        format!("http://{url}")
    } else {
        url.to_owned()
    }
}

fn is_flag_like(token: &str) -> bool {
    token.starts_with('-') && token != "-"
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
        CurlArgs, WrapperError, is_critical_unsupported_option, is_schemeless_host_url,
        normalize_wrapper_url, parse_curl_args, remote_name_from_url,
    };

    #[test]
    fn head_short_flag_is_parsed_and_rejected_explicitly() -> Result<(), WrapperError> {
        let args = parse(&["curl", "-sI", "--max-time", "20", "https://example.com"])?;

        assert!(args.head);
        assert!(args.silent);
        assert!(
            !args
                .unsupported_options
                .iter()
                .any(|opt| opt == "-I" || opt == "--head"),
            "-I must be recognized, not fall into the unsupported catch-all"
        );
        Ok(())
    }

    #[test]
    fn head_long_option_is_parsed() -> Result<(), WrapperError> {
        let args = parse(&["curl", "--head", "https://example.com"])?;
        assert!(args.head);
        Ok(())
    }

    #[test]
    fn explicit_head_method_is_parsed() -> Result<(), WrapperError> {
        for method in ["HEAD", "head", "Head"] {
            let args = parse(&["curl", "-X", method, "https://example.com"])?;
            assert_eq!(args.request_method.as_deref(), Some(method));
        }
        Ok(())
    }

    #[test]
    fn head_flag_in_cluster_is_parsed() -> Result<(), WrapperError> {
        let args = parse(&["curl", "-sSIfL", "https://example.com"])?;

        assert!(args.head);
        assert!(args.fail);
        assert!(args.silent);
        assert!(args.show_error);
        assert!(args.follow_redirects);
        Ok(())
    }

    #[test]
    fn schemeless_host_url_is_normalized_to_http() -> Result<(), WrapperError> {
        // Real curl defaults a scheme-less argument to http; the wrapper
        // must do the same so the URL flows through the normal
        // FetchPolicy/SSRF pipeline instead of being rejected outright.
        let args: Vec<String> = ["localhost:8123/health"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let parsed = parse_curl_args(&args)?;
        assert_eq!(parsed.url.as_deref(), Some("http://localhost:8123/health"));
        assert_eq!(parsed.urls, ["http://localhost:8123/health"]);

        let dotted: Vec<String> = ["example.com/path?q=1"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let parsed = parse_curl_args(&dotted)?;
        assert_eq!(parsed.url.as_deref(), Some("http://example.com/path?q=1"));

        // Scheme-qualified URLs pass through byte-for-byte.
        let explicit: Vec<String> = ["https://example.com/x"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let parsed = parse_curl_args(&explicit)?;
        assert_eq!(parsed.url.as_deref(), Some("https://example.com/x"));

        // The --url= form is normalized too.
        let inline: Vec<String> = ["--url=example.com:8080/x"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let parsed = parse_curl_args(&inline)?;
        assert_eq!(parsed.url.as_deref(), Some("http://example.com:8080/x"));
        Ok(())
    }

    #[test]
    fn schemeless_normalization_stays_conservative() {
        use super::{is_schemeless_host_url, normalize_wrapper_url};

        // Accepted shapes: port syntax, dotted host, localhost.
        assert!(is_schemeless_host_url("host:8080/path"));
        assert!(is_schemeless_host_url("example.com"));
        assert!(is_schemeless_host_url("localhost"));
        assert_eq!(
            normalize_wrapper_url("host:8080/path"),
            "http://host:8080/path"
        );
        assert_eq!(normalize_wrapper_url("example.com"), "http://example.com");

        // Not URL-shaped: unknown-option values must never become fetch
        // targets. A bare token with no dot/port (`5`) is left untouched;
        // dotted tokens like `install.sh` look like a hostname to curl too
        // (same recognition risk the pre-existing ftp:// prefix check
        // carried), so they are accepted as URLs.
        assert!(!is_schemeless_host_url("5"));
        assert!(is_schemeless_host_url("install.sh"));
        assert_eq!(normalize_wrapper_url("5"), "5");
        assert_eq!(normalize_wrapper_url("install.sh"), "http://install.sh");

        // Explicit non-default schemes are never rewritten; the fetch
        // layer's scheme policy governs them (ftp:// stays opaque).
        assert_eq!(
            normalize_wrapper_url("ftp://example.com/f"),
            "ftp://example.com/f"
        );
        assert_eq!(
            normalize_wrapper_url("https://example.com/x"),
            "https://example.com/x"
        );
        assert_eq!(
            normalize_wrapper_url("http://example.com/x"),
            "http://example.com/x"
        );
    }

    #[test]
    fn unknown_option_values_are_never_mistaken_for_schemeless_urls() -> Result<(), WrapperError> {
        // Regression (review round 1, HIGH-1): the scheme-less heuristic
        // must not apply to option-value consumption — `-o download.log` is
        // a value, and the later scheme-qualified positional must survive
        // as the parsed URL.
        let args: Vec<String> = ["-o", "download.log", "https://real/x"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let parsed = parse_curl_args(&args)?;
        assert_eq!(parsed.output.as_deref(), Some("download.log"));
        assert_eq!(parsed.url.as_deref(), Some("https://real/x"));
        assert_eq!(parsed.urls, ["https://real/x"]);
        Ok(())
    }

    #[test]
    fn scheme_qualified_url_outranks_earlier_schemeless_positional() -> Result<(), WrapperError> {
        // When both appear, the single-URL accessor reports the
        // explicitly-schemed URL; all positionals stay in urls[].
        let args: Vec<String> = ["host:8080/x", "https://real/x"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let parsed = parse_curl_args(&args)?;
        assert_eq!(parsed.url.as_deref(), Some("https://real/x"));
        assert_eq!(parsed.urls, ["http://host:8080/x", "https://real/x"]);

        // Scheme-less remains the URL when it is the only positional.
        let only: Vec<String> = ["host:8080/x"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let parsed = parse_curl_args(&only)?;
        assert_eq!(parsed.url.as_deref(), Some("http://host:8080/x"));
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
    fn remote_name_from_url_strips_query_and_fragment() -> Result<(), WrapperError> {
        // Query and fragments (which may carry secrets) must not leak into
        // the derived filename. Fragment '#' stripping was previously
        // covered by no test anywhere.
        assert_eq!(
            remote_name_from_url("https://example.com/file.bin?token=secret#frag")?,
            "file.bin"
        );
        assert_eq!(
            remote_name_from_url("https://example.com/a/b/tool.tar.gz?x=1")?,
            "tool.tar.gz"
        );
        assert_eq!(
            remote_name_from_url("https://example.com/plain.tar.gz#frag")?,
            "plain.tar.gz"
        );
        Ok(())
    }

    #[test]
    fn remote_name_flag_is_parsed() -> Result<(), WrapperError> {
        let args = parse(&[
            "curl",
            "-O",
            "https://example.com/downloads/tool.tar.gz?x=1",
        ])?;
        assert!(args.remote_name);
        assert_eq!(remote_name_from_url("https://example.com/a/b")?, "b");
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

    #[test]
    fn multiple_urls_are_collected_not_rejected() -> Result<(), WrapperError> {
        let args = parse(&[
            "curl",
            "-fsSL",
            "https://example.com/a",
            "https://example.com/b",
            "https://example.com/c",
        ])?;

        assert_eq!(args.url.as_deref(), Some("https://example.com/a"));
        assert_eq!(
            args.urls,
            [
                "https://example.com/a",
                "https://example.com/b",
                "https://example.com/c"
            ]
        );
        assert!(
            !args
                .unsupported_options
                .iter()
                .any(|opt| opt == "extra-url"),
            "multi-URL must not surface as unsupported option"
        );
        Ok(())
    }

    #[test]
    fn single_url_populates_both_url_and_urls() -> Result<(), WrapperError> {
        let args = parse(&["curl", "https://example.com/only"])?;

        assert_eq!(args.url.as_deref(), Some("https://example.com/only"));
        assert_eq!(args.urls, ["https://example.com/only"]);
        Ok(())
    }

    #[test]
    fn unknown_short_flag_value_not_treated_as_url() -> Result<(), WrapperError> {
        let args = parse(&[
            "curl",
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "5",
            "http://127.0.0.1:4200/",
        ])?;

        assert!(args.silent);
        assert_eq!(args.output.as_deref(), Some("/dev/null"));
        assert!(args.unsupported_options.contains(&"-w".to_owned()));
        assert!(args.unsupported_options.contains(&"--max-time".to_owned()));
        assert_eq!(args.url.as_deref(), Some("http://127.0.0.1:4200/"));
        assert_eq!(args.urls, ["http://127.0.0.1:4200/"]);
        Ok(())
    }

    #[test]
    fn unknown_long_option_value_not_treated_as_url() -> Result<(), WrapperError> {
        let args = parse(&[
            "curl",
            "--connect-timeout",
            "3",
            "--max-time",
            "5",
            "https://example.com/file",
        ])?;

        assert!(
            args.unsupported_options
                .contains(&"--connect-timeout".to_owned())
        );
        assert!(args.unsupported_options.contains(&"--max-time".to_owned()));
        assert_eq!(args.url.as_deref(), Some("https://example.com/file"));
        assert_eq!(args.urls, ["https://example.com/file"]);
        Ok(())
    }

    #[test]
    fn non_critical_unsupported_options_are_passthrough() -> Result<(), WrapperError> {
        let args = parse(&[
            "curl",
            "--verbose",
            "--write-out",
            "fmt",
            "https://example.com/",
        ])?;

        assert!(args.unsupported_options.contains(&"--verbose".to_owned()));
        assert!(args.unsupported_options.contains(&"--write-out".to_owned()));
        assert_eq!(args.url.as_deref(), Some("https://example.com/"));
        assert!(
            !args
                .unsupported_options
                .iter()
                .any(|opt| is_critical_unsupported_option(opt))
        );
        Ok(())
    }

    #[test]
    fn critical_unsupported_options_are_flagged() -> Result<(), WrapperError> {
        let args = parse(&[
            "curl",
            "--proxy",
            "http://proxy:3128",
            "https://example.com/",
        ])?;

        assert!(
            args.unsupported_options
                .iter()
                .any(|opt| is_critical_unsupported_option(opt))
        );
        Ok(())
    }

    #[test]
    fn unknown_long_option_url_value_collected_as_url() -> Result<(), WrapperError> {
        let args = parse(&[
            "curl",
            "--some-unknown-proxy",
            "http://decoy.example.com",
            "https://real.example.com",
        ])?;

        assert!(
            args.unsupported_options
                .contains(&"--some-unknown-proxy".to_owned())
        );
        assert!(
            !args
                .unsupported_options
                .iter()
                .any(|opt| is_critical_unsupported_option(opt))
        );
        assert_eq!(
            args.urls,
            ["http://decoy.example.com", "https://real.example.com"]
        );
        Ok(())
    }

    #[test]
    fn short_proxy_flag_consumes_value_not_treated_as_url() -> Result<(), WrapperError> {
        let args = parse(&[
            "curl",
            "-x",
            "http://proxy:3128",
            "https://example.com/file",
        ])?;

        assert!(args.unsupported_options.contains(&"-x".to_owned()));
        assert!(
            args.unsupported_options
                .iter()
                .any(|opt| is_critical_unsupported_option(opt))
        );
        assert_eq!(args.url.as_deref(), Some("https://example.com/file"));
        assert!(!args.urls.contains(&"http://proxy:3128".to_owned()));
        Ok(())
    }

    #[test]
    fn short_config_flag_is_critical() -> Result<(), WrapperError> {
        let args = parse(&["curl", "-K", "curlrc", "https://example.com/"])?;

        assert!(args.unsupported_options.contains(&"-K".to_owned()));
        assert!(
            args.unsupported_options
                .iter()
                .any(|opt| is_critical_unsupported_option(opt))
        );
        Ok(())
    }

    #[test]
    fn tls_cert_option_is_critical() -> Result<(), WrapperError> {
        let args = parse(&[
            "curl",
            "--cacert",
            "/tmp/evil-ca.pem",
            "https://example.com/",
        ])?;

        assert!(args.unsupported_options.contains(&"--cacert".to_owned()));
        assert!(
            args.unsupported_options
                .iter()
                .any(|opt| is_critical_unsupported_option(opt))
        );
        Ok(())
    }

    #[test]
    fn insecure_long_option_is_parsed_and_critical() -> Result<(), WrapperError> {
        let args = parse(&["curl", "--insecure", "https://example.com/"])?;

        assert!(args.insecure);
        assert!(
            args.unsupported_options.contains(&"--insecure".to_owned()),
            "--insecure must be both parsed and recorded as an unsupported \
             option so the critical-option bail can fire"
        );
        assert!(
            args.unsupported_options
                .iter()
                .any(|opt| is_critical_unsupported_option(opt))
        );
        Ok(())
    }

    #[test]
    fn insecure_short_flag_is_parsed_and_critical() -> Result<(), WrapperError> {
        let args = parse(&["curl", "-ksSL", "https://example.com/"])?;

        assert!(args.insecure);
        assert!(args.silent);
        assert!(args.show_error);
        assert!(args.follow_redirects);
        assert!(
            args.unsupported_options.contains(&"-k".to_owned()),
            "-k must be both parsed and recorded as an unsupported option so \
             the critical-option bail can fire"
        );
        assert!(
            args.unsupported_options
                .iter()
                .any(|opt| is_critical_unsupported_option(opt))
        );
        Ok(())
    }

    #[test]
    fn non_tls_invocation_does_not_trip_insecure_critical_check() -> Result<(), WrapperError> {
        let args = parse(&["curl", "-fsSL", "https://example.com/file"])?;

        assert!(!args.insecure);
        assert!(
            !args
                .unsupported_options
                .iter()
                .any(|opt| is_critical_unsupported_option(opt)),
            "negative control: plain -fsSL must pass the critical check"
        );
        Ok(())
    }

    #[test]
    fn unknown_short_flag_in_cluster_does_not_consume() -> Result<(), WrapperError> {
        let args = parse(&["curl", "-vw", "fmt", "https://example.com/"])?;

        assert!(args.unsupported_options.contains(&"-v".to_owned()));
        assert!(args.unsupported_options.contains(&"-w".to_owned()));
        assert_eq!(args.url.as_deref(), Some("https://example.com/"));
        assert!(!args.urls.contains(&"fmt".to_owned()));
        Ok(())
    }

    fn parse(args: &[&str]) -> Result<CurlArgs, WrapperError> {
        parse_curl_args(&args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>())
    }

    mod url_normalization_proptests {
        use super::{is_schemeless_host_url, normalize_wrapper_url};
        use proptest::prelude::*;
        proptest! {
            /// Scheme-qualified URLs pass through normalization byte-for-byte,
            /// regardless of scheme spelling (including case, which URL
            /// parsing would canonicalize — the wrapper does not).
            #[test]
            fn scheme_qualified_urls_pass_through_unchanged(
                scheme in "(?:http|https|ftp|ftps|HTTP|HTTPS|Ftp)",
                rest in "[A-Za-z0-9._~:/?#@!$&'()*+,;=%\\[\\]-]{0,80}",
            ) {
                let url = format!("{scheme}://{rest}");
                prop_assert_eq!(normalize_wrapper_url(&url), url);
            }

            /// Normalization is idempotent: the normalized form of a
            /// normalized URL is itself.
            #[test]
            fn normalization_is_idempotent(
                host in "[a-z0-9][a-z0-9.-]{0,40}",
                port in 1u16..=65535,
                path in "[a-z0-9/._-]{0,40}",
            ) {
                let url = format!("{host}:{port}/{path}");
                let once = normalize_wrapper_url(&url);
                prop_assert_eq!(normalize_wrapper_url(&once), once);
            }

            /// No host rewriting: normalization only prepends the default
            /// scheme to recognized host[:port] shapes; the authority
            /// substring is preserved byte-for-byte after the prefix.
            #[test]
            fn authority_preserved_byte_for_byte(
                host in "[a-z0-9][a-z0-9-]*(\\.[a-z0-9][a-z0-9-]*)+",
                port in proptest::option::of(1u16..=65535u16),
                path in "[a-z0-9/._?-]{0,40}",
            ) {
                let authority = match port {
                    Some(p) => format!("{host}:{p}"),
                    None => host.clone(),
                };
                let url = format!("{authority}{path}");
                let normalized = normalize_wrapper_url(&url);
                prop_assert_eq!(&normalized, &format!("http://{url}"));
                prop_assert!(normalized[7..].starts_with(&authority));
            }

            /// Recognition is conservative: tokens are classified as
            /// scheme-less URLs exactly when they carry port syntax, a
            /// dotted host, or the localhost label (digits-only tokens are
            /// ports-or-numbers: `5` is not, `host:5` is).
            #[test]
            fn bare_labels_without_url_shape_are_not_urls(
                token in "(?:[a-z][a-z0-9_-]{0,20}|[0-9]{1,5}|[a-z]+\\.(?:txt|log|json|bin))",
            ) {
                let dotted = token.contains('.');
                let is_localhost = token == "localhost";
                prop_assert_eq!(is_schemeless_host_url(&token), dotted || is_localhost);
            }
        }

        /// Pinned edge shapes from adversarial review round 1: IPv6
        /// literals, userinfo, and colon-heavy ambiguity.
        #[test]
        fn pinned_edge_shapes() {
            // Bracketed IPv6 is recognized and normalized.
            assert!(is_schemeless_host_url("[::1]:8080/x"));
            assert_eq!(normalize_wrapper_url("[::1]:8080/x"), "http://[::1]:8080/x");
            assert_eq!(normalize_wrapper_url("[::1]/x"), "http://[::1]/x");
            // Malformed brackets are not URLs.
            assert!(!is_schemeless_host_url("[::1:8080/x"));
            assert!(!is_schemeless_host_url("[]:8080/x"));
            assert!(!is_schemeless_host_url("[zz]:8080/x"));
            // Non-numeric port after bracket rejected.
            assert!(!is_schemeless_host_url("[::1]:port/x"));
            // userinfo form is deliberately unsupported (documented); use
            // an explicit http:// prefix instead.
            assert!(!is_schemeless_host_url("user:pass@host/x"));
            assert_eq!(
                normalize_wrapper_url("user:pass@host/x"),
                "user:pass@host/x"
            );
            // Ambiguous colon shapes are not URLs.
            assert!(!is_schemeless_host_url(":8080"));
            assert!(!is_schemeless_host_url(":"));
            assert!(!is_schemeless_host_url("a:b:c"));
            // Trailing-colon shapes: the pre-colon text is the host, and the
            // host's own dotted/localhost shape decides. `8080:` (bare
            // numeric label) is not recognized; `example.com:` is (a real
            // curl would parse it as `example.com` with an empty port).
            assert!(!is_schemeless_host_url("8080:"));
            assert!(is_schemeless_host_url("example.com:"));
        }
    }
}
