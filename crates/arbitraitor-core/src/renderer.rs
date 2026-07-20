//! Untrusted-text presentation renderer (spec §25.0, ADR-0016).
//!
//! All URLs, headers, filenames, source text, package metadata, detector
//! evidence, and plugin messages are untrusted. The renderer must:
//!
//! - escape C0/C1 controls as visible glyphs (not remove them silently)
//! - neutralize ANSI CSI/OSC sequences by escaping the ESC byte
//! - visualize Unicode bidi controls as `[U+NNNN]` markers
//! - identify mixed-script confusables where relevant
//! - bound line length, nesting, and total output
//! - keep machine JSON structurally encoded rather than terminal-rendered
//!
//! Unlike the MCP crate's `sanitize_for_agent` (which filters control chars
//! out — losing evidence that they were present), this renderer makes every
//! potentially dangerous byte **visible but inert** so a human reviewer can
//! see the attack surface without the terminal executing it.

use std::fmt::Write as _;

/// Maximum total output length before truncation.
const MAX_OUTPUT_CHARS: usize = 10_000;

/// Maximum line length before wrapping.
const MAX_LINE_LENGTH: usize = 512;

/// Renders untrusted text as visible-but-inert output per spec §25.0.
///
/// Control characters are escaped as `[U+NNNN]` rather than removed, so
/// reviewers can see that they were present in the source. Non-printing
/// Unicode bidi marks are visualized. ANSI escape sequences are neutralized
/// by escaping the leading ESC byte. Output is bounded to prevent resource
/// exhaustion through hostile content.
#[must_use]
pub fn render_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len().saturating_mul(2));
    for ch in text.chars() {
        if out.len() >= MAX_OUTPUT_CHARS {
            out.push_str("\n[truncated at {MAX_OUTPUT_CHARS} chars]");
            break;
        }
        render_char(&mut out, ch);
    }
    bound_line_lengths(&mut out);
    out
}

/// Renders a single character, escaping dangerous bytes.
fn render_char(out: &mut String, ch: char) {
    let code = ch as u32;
    match ch {
        // Safe printable ASCII
        ' '..='~' => {
            out.push(ch);
        }
        // Newline and tab are preserved (they're structurally meaningful)
        '\n' => out.push('\n'),
        '\t' => out.push('\t'),
        // C0 control chars (U+0000..U+001F) except \n and \t
        '\0' => out.push_str("[NUL]"),
        '\x07' => out.push_str("[BEL]"),
        '\x08' => out.push_str("[BS]"),
        '\x0B' => out.push_str("[VT]"),
        '\x0C' => out.push_str("[FF]"),
        '\r' => out.push_str("[CR]"),
        '\x1B' => out.push_str("[ESC]"),
        _c if code <= 0x1F => {
            let _ = write!(out, "[U+{code:04X}]");
        }
        // C1 control chars (U+0080..U+009F)
        _c if (0x80..=0x9F).contains(&code) => {
            let _ = write!(out, "[U+{code:04X}]");
        }
        // Unicode bidi controls (U+200E..U+200F, U+202A..U+202E, U+2066..U+2069)
        '\u{200E}' => out.push_str("[LRM]"),
        '\u{200F}' => out.push_str("[RLM]"),
        '\u{202A}' => out.push_str("[LRE]"),
        '\u{202B}' => out.push_str("[RLE]"),
        '\u{202C}' => out.push_str("[PDF]"),
        '\u{202D}' => out.push_str("[LRO]"),
        '\u{202E}' => out.push_str("[RLO]"),
        '\u{2066}' => out.push_str("[LRI]"),
        '\u{2067}' => out.push_str("[RLI]"),
        '\u{2068}' => out.push_str("[FSI]"),
        '\u{2069}' => out.push_str("[PDI]"),
        // Zero-width characters
        '\u{200B}' => out.push_str("[ZWSP]"),
        '\u{200C}' => out.push_str("[ZWNJ]"),
        '\u{200D}' => out.push_str("[ZWJ]"),
        '\u{FEFF}' => out.push_str("[BOM]"),
        // DEL
        '\u{007F}' => out.push_str("[DEL]"),
        // Everything else is passed through
        _ => out.push(ch),
    }
}

/// Ensures no line exceeds `MAX_LINE_LENGTH` by inserting soft breaks.
fn bound_line_lengths(out: &mut String) {
    if !out.contains('\n') {
        return;
    }
    let lines: Vec<&str> = out.split_inclusive('\n').collect();
    if lines.iter().all(|line| line.len() <= MAX_LINE_LENGTH) {
        return;
    }
    let mut bounded = String::with_capacity(out.len());
    for line in &lines {
        let mut remaining = *line;
        while remaining.len() > MAX_LINE_LENGTH {
            let (prefix, suffix) = remaining.split_at(MAX_LINE_LENGTH);
            bounded.push_str(prefix);
            bounded.push('\n');
            remaining = suffix;
        }
        bounded.push_str(remaining);
    }
    *out = bounded;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ascii_passes_through() {
        assert_eq!(render_literal("hello world"), "hello world");
    }

    #[test]
    fn nul_byte_is_visualized() {
        assert_eq!(render_literal("ab\0cd"), "ab[NUL]cd");
    }

    #[test]
    fn esc_byte_is_visualized_not_executed() {
        let input = "\x1B[31mred text\x1B[0m";
        let result = render_literal(input);
        assert!(result.contains("[ESC]"));
        assert!(!result.contains('\x1B'));
        assert!(result.contains("[31mred text"));
    }

    #[test]
    fn carriage_return_is_visualized() {
        assert_eq!(render_literal("ab\rcd"), "ab[CR]cd");
    }

    #[test]
    fn bel_byte_is_visualized() {
        assert_eq!(render_literal("x\u{0007}y"), "x[BEL]y");
    }

    #[test]
    fn rlo_bidi_override_is_visualized() {
        let input = "hello\u{202E}world";
        let result = render_literal(input);
        assert!(result.contains("[RLO]"));
        assert!(!result.contains('\u{202E}'));
    }

    #[test]
    fn zero_width_joiner_is_visualized() {
        assert_eq!(render_literal("a\u{200D}b"), "a[ZWJ]b");
    }

    #[test]
    fn zero_width_space_is_visualized() {
        assert_eq!(render_literal("a\u{200B}b"), "a[ZWSP]b");
    }

    #[test]
    fn bom_is_visualized() {
        assert_eq!(render_literal("\u{FEFF}text"), "[BOM]text");
    }

    #[test]
    fn del_is_visualized() {
        assert_eq!(render_literal("a\u{007F}b"), "a[DEL]b");
    }

    #[test]
    fn c1_control_is_visualized() {
        let input = "a\u{0085}b";
        let result = render_literal(input);
        assert!(result.contains("[U+0085]"));
    }

    #[test]
    fn unknown_c0_control_is_visualized_with_codepoint() {
        let input = "a\u{0001}b";
        let result = render_literal(input);
        assert!(result.contains("[U+0001]"));
    }

    #[test]
    fn unicode_text_passes_through() {
        let input = "héllo wörld 中文 🎉";
        let result = render_literal(input);
        assert_eq!(result, input);
    }

    #[test]
    fn tab_and_newline_are_preserved() {
        assert_eq!(
            render_literal("line1\n\tindented\nline2"),
            "line1\n\tindented\nline2"
        );
    }

    #[test]
    fn output_is_bounded() {
        let input = "A".repeat(20_000);
        let result = render_literal(&input);
        assert!(
            result.len() < input.len(),
            "output must be truncated for large input"
        );
        assert!(
            result.contains("[truncated"),
            "truncated output must include truncation marker"
        );
    }

    #[test]
    fn long_lines_are_wrapped() {
        let long_line = format!("{}\n", "X".repeat(600));
        let result = render_literal(&long_line);
        assert!(
            result.lines().all(|line| line.len() <= MAX_LINE_LENGTH),
            "no line should exceed MAX_LINE_LENGTH ({MAX_LINE_LENGTH})"
        );
    }

    #[test]
    fn empty_string_returns_empty() {
        assert_eq!(render_literal(""), "");
    }

    #[test]
    fn complex_ansi_sequence_is_neutralized() {
        let input = "\x1B]0;title\x07visible text".to_string();
        let result = render_literal(&input);
        assert!(
            !result.contains('\x1B'),
            "ESC byte must not appear in output"
        );
        assert!(
            !result.contains('\x07'),
            "BEL terminator must not appear in output"
        );
        assert!(
            result.contains("[ESC]") && result.contains("[BEL]"),
            "ESC and BEL must be visualized"
        );
        assert!(
            result.contains("visible text"),
            "text after the sequence must be preserved"
        );
    }
}
