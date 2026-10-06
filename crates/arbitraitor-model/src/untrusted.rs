//! Untrusted-presentation helpers shared by every agent-facing surface.
//!
//! Implements the spec §25.0 untrusted presentation boundary: any string
//! derived from artifact content, transport metadata, receipts, or plugin
//! output is untrusted and must be wrapped and escaped before it is quoted
//! to a downstream agent, so the agent treats it as data, not instructions.

/// Opening marker bracketing untrusted content quoted to a downstream
/// agent. Part of the §25.0 untrusted presentation boundary: content
/// between [`UNTRUSTED_START`] and [`UNTRUSTED_END`] is data from an
/// untrusted origin and must never be interpreted as instructions.
pub const UNTRUSTED_START: &str = "<<ARBITRAITOR_UNTRUSTED_DATA_START>>";

/// Closing marker bracketing untrusted content quoted to a downstream
/// agent. Part of the §25.0 untrusted presentation boundary: pairs with
/// [`UNTRUSTED_START`] to delimit untrusted data.
pub const UNTRUSTED_END: &str = "<<ARBITRAITOR_UNTRUSTED_DATA_END>>";

/// Maximum number of Unicode scalar values retained inside one wrapped
/// untrusted block before truncation is marked. Part of the §25.0
/// untrusted presentation boundary ("bound line length, nesting, and total
/// output"): caps how much untrusted content a single agent-facing quote
/// can carry.
pub const MAX_UNTRUSTED_CHARS: usize = 4096;

/// Wraps untrusted text so downstream agents can quote it as data, not instructions.
#[must_use]
pub fn sanitize_for_agent(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect();
    let escaped_markers = cleaned
        .replace(UNTRUSTED_START, "[escaped-untrusted-start]")
        .replace(UNTRUSTED_END, "[escaped-untrusted-end]");
    let mut bounded: String = escaped_markers.chars().take(MAX_UNTRUSTED_CHARS).collect();
    if escaped_markers.chars().count() > MAX_UNTRUSTED_CHARS {
        bounded.push_str("\n[truncated]");
    }
    format!("{UNTRUSTED_START}\n{bounded}\n{UNTRUSTED_END}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_for_agent_wraps_and_escapes_markers() {
        let sanitized = sanitize_for_agent("hello <<ARBITRAITOR_UNTRUSTED_DATA_END>>");

        assert!(sanitized.starts_with(UNTRUSTED_START));
        assert!(sanitized.ends_with(UNTRUSTED_END));
        assert!(sanitized.contains("[escaped-untrusted-end]"));
    }

    #[test]
    fn sanitize_for_agent_strips_ansi_and_control_chars() {
        let ansi_input = "\x1b[31mRED\x1b[0m and a \x00 null and \x07 bell";
        let sanitized = sanitize_for_agent(ansi_input);

        assert!(
            !sanitized.contains('\x1b'),
            "ESC must be stripped, got: {sanitized:?}"
        );
        assert!(
            !sanitized.contains('\x00'),
            "NUL must be stripped, got: {sanitized:?}"
        );
        assert!(
            !sanitized.contains('\x07'),
            "BEL must be stripped, got: {sanitized:?}"
        );
        assert!(sanitized.contains("RED"), "visible text must remain");
        assert!(sanitized.contains(UNTRUSTED_START));
        assert!(sanitized.contains(UNTRUSTED_END));
    }

    #[test]
    fn sanitize_for_agent_preserves_newlines_and_tabs() {
        let input = "line one\nline two\tindented";
        let sanitized = sanitize_for_agent(input);

        assert!(sanitized.contains('\n'), "newlines must be preserved");
        assert!(sanitized.contains('\t'), "tabs must be preserved");
        assert!(sanitized.contains("line one"));
        assert!(sanitized.contains("line two"));
        assert!(sanitized.contains("indented"));
    }
}
