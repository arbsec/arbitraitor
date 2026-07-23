//! URL discovery beyond shell literals (spec §20.2).
//!
//! Extracts URLs from Python and JavaScript string constants, configuration
//! files (JSON, TOML), and HTML/JSON responses. The extractor is intentionally
//! simple and dependency-free: the analysis crate does not depend on `regex`,
//! so URL schemes are located via byte scanning, consistent with the
//! [`crate::pyjs`] detector approach.
//!
//! All extractors enforce bounded processing (spec invariant 4): source size,
//! URL count, and individual URL length are capped to prevent resource
//! exhaustion through hostile inputs.

#![forbid(unsafe_code)]

use serde_json::Value;

/// Maximum source size accepted by any extractor (1 MiB).
const MAX_SOURCE_SIZE: usize = 1_048_576;

/// Maximum number of URLs a single extractor will return.
const MAX_URLS: usize = 1000;

/// Maximum length of a single discovered URL in bytes.
const MAX_URL_LENGTH: usize = 2048;

/// URL schemes the extractors recognize.
const URL_SCHEMES: &[&str] = &["https://", "http://", "ftp://"];

/// HTML attributes whose values commonly contain URLs.
const HTML_URL_ATTRIBUTES: &[&str] = &["href", "src", "action"];

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Provenance of a discovered URL — which extraction source produced it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UrlSource {
    /// Python source string literal.
    Python,
    /// JavaScript source string literal.
    JavaScript,
    /// JSON document string value.
    Json,
    /// HTML document attribute value.
    Html,
    /// Configuration file (JSON or TOML).
    Config,
    /// Shell AST literal argument.
    ShellAst,
}

/// A URL discovered during content analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredUrl {
    /// The extracted URL string.
    pub url: String,
    /// Where the URL was discovered.
    pub source: UrlSource,
    /// Optional location hint (e.g. JSON path, attribute name, line number).
    pub location: Option<String>,
}

/// Configuration file format for [`extract_urls_from_config`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigFormat {
    /// JSON configuration file.
    Json,
    /// TOML configuration file.
    Toml,
}

/// Retrieval policy governing which discovered URLs are fetched for further
/// analysis (spec §20.3).
///
/// The policy forms a strict escalation ladder: each mode retrieves a superset
/// of the previous mode's URLs, bounded by resource limits.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RetrievalPolicy {
    /// No URL retrieval. Discovered URLs are recorded but never fetched.
    #[default]
    Off,
    /// Report discovered URLs in findings without fetching.
    Report,
    /// Fetch only URLs on the same origin as the parent artifact.
    SameOrigin,
    /// Fetch only URLs referenced by artifacts that were themselves executed.
    KnownExecuted,
    /// Fetch all discovered URLs within resource limits.
    AllWithinLimits,
}

/// A dynamic URL expression containing an unresolved template variable
/// (spec §20.4).
///
/// URLs containing `${...}`, `{{...}}`, or `#{...}` cannot be resolved at
/// analysis time and are reported so operators can inspect the construction
/// logic manually.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicUrlExpression {
    /// The URL string containing the template expression.
    pub url: String,
    /// Where the expression was discovered.
    pub source: UrlSource,
    /// The unresolved template expression (e.g. `${BASE}`, `{{host}}`).
    pub unresolved_expression: String,
}

// ---------------------------------------------------------------------------
// Public extractors
// ---------------------------------------------------------------------------

/// Extracts URLs from Python source string literals.
///
/// Scans for `http://`, `https://`, and `ftp://` scheme prefixes. Each URL
/// token extends from the scheme to the next whitespace, quote character, or
/// end of input. Consistent with the [`crate::pyjs`] detector, no Python AST
/// parser is used — the scan is byte-level and dependency-free.
#[must_use]
pub fn extract_urls_from_python(source: &str) -> Vec<DiscoveredUrl> {
    scan_source_for_urls(source, UrlSource::Python)
}

/// Extracts URLs from JavaScript source string literals.
///
/// Same scanning approach as [`extract_urls_from_python`], applied to
/// JavaScript source. Template literals (backtick strings) are handled
/// naturally because backtick is treated as a delimiter.
#[must_use]
pub fn extract_urls_from_javascript(source: &str) -> Vec<DiscoveredUrl> {
    scan_source_for_urls(source, UrlSource::JavaScript)
}

/// Extracts URLs from a JSON document by parsing with `serde_json` and
/// recursively scanning all string values.
///
/// Each discovered URL carries its JSON pointer path (e.g. `$.downloads.url`)
/// as the location. Invalid JSON returns an empty vector.
#[must_use]
pub fn extract_urls_from_json(data: &str) -> Vec<DiscoveredUrl> {
    if data.len() > MAX_SOURCE_SIZE {
        return Vec::new();
    }
    let Ok(parsed) = serde_json::from_str::<Value>(data) else {
        return Vec::new();
    };
    let mut urls = Vec::new();
    walk_json(&parsed, "$", &mut urls);
    urls
}

/// Extracts URLs from HTML by scanning `href`, `src`, and `action` attribute
/// values.
///
/// Both quoted (`"..."` and `'...'`) and unquoted attribute values are
/// handled. Attribute name matching is case-sensitive (lowercase only, which
/// covers the vast majority of real-world HTML). Each discovered URL carries
/// the attribute name as its location.
#[must_use]
pub fn extract_urls_from_html(data: &str) -> Vec<DiscoveredUrl> {
    if data.len() > MAX_SOURCE_SIZE {
        return Vec::new();
    }
    let mut urls = Vec::new();
    for attr in HTML_URL_ATTRIBUTES {
        let pattern = format!("{attr}=");
        let mut search_from = 0;
        while urls.len() < MAX_URLS {
            let Some(rest) = data.get(search_from..) else {
                break;
            };
            let Some(rel) = rest.find(&pattern) else {
                break;
            };
            let value_start = search_from + rel + pattern.len();
            search_from = value_start;
            let Some(value) = extract_attribute_value(data, value_start) else {
                continue;
            };
            for url in scan_for_url_tokens(&value) {
                if urls.len() >= MAX_URLS {
                    break;
                }
                urls.push(DiscoveredUrl {
                    url,
                    source: UrlSource::Html,
                    location: Some((*attr).to_owned()),
                });
            }
        }
    }
    urls
}

/// Extracts URLs from a configuration file.
///
/// JSON config is parsed with `serde_json` (delegating to
/// [`extract_urls_from_json`]). TOML config is scanned for URL schemes in
/// quoted strings. All discovered URLs are tagged with [`UrlSource::Config`].
#[must_use]
pub fn extract_urls_from_config(data: &str, format: ConfigFormat) -> Vec<DiscoveredUrl> {
    match format {
        ConfigFormat::Json => {
            let mut urls = extract_urls_from_json(data);
            for url in &mut urls {
                url.source = UrlSource::Config;
            }
            urls
        }
        ConfigFormat::Toml => scan_source_for_urls(data, UrlSource::Config),
    }
}

/// Detects dynamic URL expressions containing unresolved template variables
/// (spec §20.4).
///
/// Scans `source` for URL tokens, then checks each for `${...}`, `{{...}}`,
/// or `#{...}` template syntax. Each match is reported with the unresolved
/// expression so operators can inspect the construction logic.
#[must_use]
pub fn detect_dynamic_url_expressions(
    source: &str,
    source_kind: UrlSource,
) -> Vec<DynamicUrlExpression> {
    if source.len() > MAX_SOURCE_SIZE {
        return Vec::new();
    }
    let mut expressions = Vec::new();
    let mut search_from = 0;
    while expressions.len() < MAX_URLS {
        let Some(offset) = find_next_scheme(source, search_from) else {
            break;
        };
        if let Some(url) = extract_url_token(source, offset)
            && let Some(expr) = find_template_expression(&url)
        {
            expressions.push(DynamicUrlExpression {
                url,
                source: source_kind,
                unresolved_expression: expr,
            });
        }
        search_from = offset + 1;
    }
    expressions
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Scans source text for URL scheme prefixes, returning bounded results.
fn scan_source_for_urls(source: &str, source_kind: UrlSource) -> Vec<DiscoveredUrl> {
    if source.len() > MAX_SOURCE_SIZE {
        return Vec::new();
    }
    let mut urls = Vec::new();
    let mut search_from = 0;
    while urls.len() < MAX_URLS {
        let Some(offset) = find_next_scheme(source, search_from) else {
            break;
        };
        if let Some(url) = extract_url_token(source, offset) {
            urls.push(DiscoveredUrl {
                url,
                source: source_kind,
                location: Some(line_location(source, offset)),
            });
        }
        search_from = offset + 1;
    }
    urls
}

/// Scans a single string for URL tokens (no bounding — caller bounds the total).
fn scan_for_url_tokens(s: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut search_from = 0;
    while let Some(offset) = find_next_scheme(s, search_from) {
        if let Some(url) = extract_url_token(s, offset) {
            urls.push(url);
        }
        search_from = offset + 1;
    }
    urls
}

/// Recursively walks a JSON value tree, collecting URLs from string values.
fn walk_json(value: &Value, path: &str, urls: &mut Vec<DiscoveredUrl>) {
    if urls.len() >= MAX_URLS {
        return;
    }
    match value {
        Value::String(s) => {
            for url in scan_for_url_tokens(s) {
                if urls.len() >= MAX_URLS {
                    break;
                }
                urls.push(DiscoveredUrl {
                    url,
                    source: UrlSource::Json,
                    location: Some(path.to_owned()),
                });
            }
        }
        Value::Object(map) => {
            for (key, val) in map {
                let child_path = format!("{path}.{key}");
                walk_json(val, &child_path, urls);
                if urls.len() >= MAX_URLS {
                    break;
                }
            }
        }
        Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let child_path = format!("{path}[{i}]");
                walk_json(val, &child_path, urls);
                if urls.len() >= MAX_URLS {
                    break;
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Finds the earliest offset of any recognized URL scheme at or after `from`.
fn find_next_scheme(source: &str, from: usize) -> Option<usize> {
    let rest = source.get(from..)?;
    URL_SCHEMES
        .iter()
        .filter_map(|scheme| rest.find(scheme).map(|pos| from + pos))
        .min()
}

/// Extracts a URL token starting at `start`, extending to the next delimiter.
fn extract_url_token(source: &str, start: usize) -> Option<String> {
    let rest = source.get(start..)?;
    let end = rest.find(is_url_delimiter).unwrap_or(rest.len());
    let url = rest.get(..end)?;
    Some(truncate_url(url).to_owned())
}

/// Truncates a URL to [`MAX_URL_LENGTH`] bytes on a character boundary.
fn truncate_url(url: &str) -> &str {
    if url.len() <= MAX_URL_LENGTH {
        return url;
    }
    let mut cut = MAX_URL_LENGTH;
    while cut > 0 && !url.is_char_boundary(cut) {
        cut -= 1;
    }
    url.get(..cut).unwrap_or("")
}

/// Extracts an HTML attribute value (quoted or unquoted) starting at `start`.
fn extract_attribute_value(data: &str, start: usize) -> Option<String> {
    let rest = data.get(start..)?;
    let first = rest.chars().next()?;
    if first == '"' || first == '\'' {
        let inner = rest.get(1..)?;
        Some(inner.get(..inner.find(first)?)?.to_owned())
    } else {
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '>')
            .unwrap_or(rest.len());
        rest.get(..end).filter(|s| !s.is_empty()).map(str::to_owned)
    }
}

/// Returns `true` if `c` terminates a URL token.
fn is_url_delimiter(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\'' | '"' | '`' | '<' | '>' | '|')
}

/// Finds the first template expression (`${...}`, `{{...}}`, `#{...}`) in `url`.
fn find_template_expression(url: &str) -> Option<String> {
    [("${", "}"), ("{{", "}}"), ("#{", "}")]
        .into_iter()
        .find_map(|(open, close)| {
            let start = url.find(open)?;
            let end = url[start..].find(close)?;
            url.get(start..start + end + close.len()).map(str::to_owned)
        })
}

/// Returns a `"line N"` location string for byte `offset` within `source`.
fn line_location(source: &str, offset: usize) -> String {
    let prefix = source.get(..offset).unwrap_or("");
    let line = prefix.matches('\n').count().saturating_add(1);
    format!("line {line}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    // --- Python ----------------------------------------------------------

    #[test]
    fn extracts_url_from_python_single_quoted_string() {
        let source = r"url = 'https://example.com/install.sh'";
        let urls = extract_urls_from_python(source);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://example.com/install.sh");
        assert_eq!(urls[0].source, UrlSource::Python);
        assert!(urls[0].location.as_ref().is_some_and(|l| l == "line 1"));
    }

    #[test]
    fn extracts_url_from_python_double_quoted_string() {
        let source = r#"url = "https://example.com/path""#;
        let urls = extract_urls_from_python(source);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://example.com/path");
    }

    #[test]
    fn extracts_url_from_python_triple_quoted_string() {
        let source = "url = '''https://example.com/triple'''";
        let urls = extract_urls_from_python(source);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://example.com/triple");
    }

    #[test]
    fn extracts_multiple_urls_from_python() {
        let source = r#"
base = "https://example.com"
api = 'https://api.example.com/v1'
ftp = 'ftp://mirror.example.org/pub'
"#;
        let urls = extract_urls_from_python(source);
        assert_eq!(urls.len(), 3);
        assert_eq!(urls[0].url, "https://example.com");
        assert_eq!(urls[1].url, "https://api.example.com/v1");
        assert_eq!(urls[2].url, "ftp://mirror.example.org/pub");
    }

    #[test]
    fn python_source_with_no_urls_returns_empty() {
        let urls = extract_urls_from_python("def hello():\n    return 'hi'\n");
        assert!(urls.is_empty());
    }

    // --- JavaScript ------------------------------------------------------

    #[test]
    fn extracts_url_from_javascript_string() {
        let source = r#"const url = "https://example.com/script.js";"#;
        let urls = extract_urls_from_javascript(source);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://example.com/script.js");
        assert_eq!(urls[0].source, UrlSource::JavaScript);
    }

    #[test]
    fn extracts_url_from_javascript_template_literal() {
        let source = "const url = `https://example.com/endpoint`;";
        let urls = extract_urls_from_javascript(source);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://example.com/endpoint");
    }

    #[test]
    fn javascript_source_with_no_urls_returns_empty() {
        let urls = extract_urls_from_javascript("const x = 42;\n");
        assert!(urls.is_empty());
    }

    // --- JSON ------------------------------------------------------------

    #[test]
    fn extracts_url_from_json_string_value() {
        let json = r#"{"url": "https://example.com/download"}"#;
        let urls = extract_urls_from_json(json);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://example.com/download");
        assert_eq!(urls[0].source, UrlSource::Json);
        assert_eq!(urls[0].location.as_deref(), Some("$.url"));
    }

    #[test]
    fn extracts_url_from_nested_json() {
        let json = r#"{"config": {"mirror": "https://mirror.example.com/repo"}}"#;
        let urls = extract_urls_from_json(json);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://mirror.example.com/repo");
        assert_eq!(urls[0].location.as_deref(), Some("$.config.mirror"));
    }

    #[test]
    fn extracts_url_from_json_array() {
        let json = r#"{"mirrors": ["https://a.example.com", "https://b.example.com"]}"#;
        let urls = extract_urls_from_json(json);
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0].location.as_deref(), Some("$.mirrors[0]"));
        assert_eq!(urls[1].location.as_deref(), Some("$.mirrors[1]"));
    }

    #[test]
    fn invalid_json_returns_empty() {
        let urls = extract_urls_from_json("{not valid json}");
        assert!(urls.is_empty());
    }

    #[test]
    fn empty_json_returns_empty() {
        let urls = extract_urls_from_json("{}");
        assert!(urls.is_empty());
    }

    // --- HTML ------------------------------------------------------------

    #[test]
    fn extracts_url_from_html_href() {
        let html = r#"<a href="https://example.com/page">link</a>"#;
        let urls = extract_urls_from_html(html);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://example.com/page");
        assert_eq!(urls[0].source, UrlSource::Html);
        assert_eq!(urls[0].location.as_deref(), Some("href"));
    }

    #[test]
    fn extracts_url_from_html_src() {
        let html = r#"<img src="https://example.com/image.png">"#;
        let urls = extract_urls_from_html(html);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://example.com/image.png");
        assert_eq!(urls[0].location.as_deref(), Some("src"));
    }

    #[test]
    fn extracts_url_from_html_action() {
        let html = r#"<form action="https://example.com/submit">"#;
        let urls = extract_urls_from_html(html);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://example.com/submit");
        assert_eq!(urls[0].location.as_deref(), Some("action"));
    }

    #[test]
    fn extracts_url_from_html_single_quoted_attribute() {
        let html = r"<a href='https://example.com/single'>link</a>";
        let urls = extract_urls_from_html(html);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://example.com/single");
    }

    #[test]
    fn html_with_no_urls_returns_empty() {
        let urls = extract_urls_from_html("<p>no links here</p>");
        assert!(urls.is_empty());
    }

    // --- Config ----------------------------------------------------------

    #[test]
    fn extracts_url_from_json_config() {
        let config = r#"{"download": {"url": "https://example.com/pkg.tar.gz"}}"#;
        let urls = extract_urls_from_config(config, ConfigFormat::Json);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://example.com/pkg.tar.gz");
        assert_eq!(urls[0].source, UrlSource::Config);
    }

    #[test]
    fn extracts_url_from_toml_config() {
        let config = r#"
[server]
url = "https://example.com/api"
"#;
        let urls = extract_urls_from_config(config, ConfigFormat::Toml);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://example.com/api");
        assert_eq!(urls[0].source, UrlSource::Config);
    }

    #[test]
    fn empty_config_returns_empty() {
        assert!(extract_urls_from_config("", ConfigFormat::Json).is_empty());
        assert!(extract_urls_from_config("", ConfigFormat::Toml).is_empty());
    }

    // --- Dynamic URL expressions -----------------------------------------

    #[test]
    fn detects_dollar_brace_template_expression() {
        let source = r#"url = "https://${HOST}/path""#;
        let exprs = detect_dynamic_url_expressions(source, UrlSource::Python);
        assert_eq!(exprs.len(), 1);
        assert_eq!(exprs[0].unresolved_expression, "${HOST}");
        assert_eq!(exprs[0].source, UrlSource::Python);
    }

    #[test]
    fn detects_double_brace_template_expression() {
        let source = r#"url = "https://{{host}}/path""#;
        let exprs = detect_dynamic_url_expressions(source, UrlSource::JavaScript);
        assert_eq!(exprs.len(), 1);
        assert_eq!(exprs[0].unresolved_expression, "{{host}}");
    }

    #[test]
    fn detects_hash_brace_template_expression() {
        let source = r#"url = "https://#{host}/path""#;
        let exprs = detect_dynamic_url_expressions(source, UrlSource::Python);
        assert_eq!(exprs.len(), 1);
        assert_eq!(exprs[0].unresolved_expression, "#{host}");
    }

    #[test]
    fn static_url_produces_no_dynamic_expressions() {
        let source = r#"url = "https://example.com/static""#;
        let exprs = detect_dynamic_url_expressions(source, UrlSource::Python);
        assert!(exprs.is_empty());
    }

    // --- Bounded extraction ----------------------------------------------

    #[test]
    fn source_exceeding_max_size_returns_empty() {
        let huge = "https://example.com ".repeat(MAX_SOURCE_SIZE);
        let urls = extract_urls_from_python(&huge);
        assert!(urls.is_empty());
    }

    #[test]
    fn url_count_is_capped() {
        // Each line has one URL; we add more than MAX_URLS lines.
        let line = "https://example.com/path\n";
        let source = line.repeat(MAX_URLS + 50);
        let urls = extract_urls_from_python(&source);
        assert_eq!(urls.len(), MAX_URLS);
    }

    #[test]
    fn empty_input_returns_empty() {
        assert!(extract_urls_from_python("").is_empty());
        assert!(extract_urls_from_javascript("").is_empty());
        assert!(extract_urls_from_json("").is_empty());
        assert!(extract_urls_from_html("").is_empty());
    }

    // --- RetrievalPolicy -------------------------------------------------

    #[test]
    fn retrieval_policy_default_is_off() {
        assert_eq!(RetrievalPolicy::default(), RetrievalPolicy::Off);
    }

    #[test]
    fn retrieval_policy_has_five_variants() {
        let all = [
            RetrievalPolicy::Off,
            RetrievalPolicy::Report,
            RetrievalPolicy::SameOrigin,
            RetrievalPolicy::KnownExecuted,
            RetrievalPolicy::AllWithinLimits,
        ];
        assert_eq!(all.len(), 5);
        // All variants are distinct.
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "variants {i} and {j} are equal");
                }
            }
        }
    }

    // --- ConfigFormat ----------------------------------------------------

    #[test]
    fn config_format_variants_are_distinct() {
        assert_ne!(ConfigFormat::Json, ConfigFormat::Toml);
    }

    // --- UrlSource --------------------------------------------------------

    #[test]
    fn url_source_has_six_variants() {
        let all = [
            UrlSource::Python,
            UrlSource::JavaScript,
            UrlSource::Json,
            UrlSource::Html,
            UrlSource::Config,
            UrlSource::ShellAst,
        ];
        assert_eq!(all.len(), 6);
    }
}
