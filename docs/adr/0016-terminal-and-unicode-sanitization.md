# ADR 0016: Terminal and Unicode sanitization renderer

**Status:** Accepted
**Date:** 2026-06-16
**Issue:** #11

## Context

URLs, headers, filenames, source snippets, package metadata, YARA matched
strings, detector evidence, and plugin messages are **untrusted content** that
Arbitraitor displays to users. The adversarial review (H-02) identified that
this content may contain:

- ANSI CSI sequences (cursor movement, color, erase).
- OSC sequences (set window title, clipboard operations, hyperlinks).
- Carriage returns and line rewriting.
- Control characters (bell, backspace, etc.).
- Unicode bidi controls (RLO, LRO, PDF — UTS #9).
- Mixed-script confusable characters (UTS #39).
- Extremely long combining sequences.
- Null bytes and other non-printable characters.

These can be used for terminal injection attacks, reviewer confusion,
log-injection, and clipboard hijacking.

## Decision

Implement **one core-owned strict renderer** through which all untrusted text
must pass before reaching the terminal. Plugins **never** render terminal
output directly.

### Renderer rules

| Category | Treatment |
|----------|-----------|
| C0 controls (0x00–0x1F) except `\t`, `\n` | Escaped or stripped |
| C1 controls (0x80–0x9F) | Escaped or stripped |
| ANSI CSI (`ESC [`) | Escaped, never interpreted |
| ANSI OSC (`ESC ]`) | Escaped, never interpreted |
| Terminal hyperlinks (`ESC ]8;;`) | Disabled |
| Carriage return (`\r`) | Escaped |
| Unicode bidi (RLO U+202E, LRO U+202D, PDF U+202C, etc.) | Visualized |
| Mixed-script confusables (UTS #39) | Labeled with both Unicode and escaped forms |
| Invisible/suspicious characters (ZWSP, ZWNJ, etc.) | Visualized |
| Line length | Capped (default 2000 chars per line) |
| Total output volume | Bounded |

### Display rules

- When displaying source code, filenames, or URLs that contain suspicious
  Unicode, show **both** the Unicode form and the escaped form:

```text
Filename: caⅰc.o  [U+2170 SMALL ROMAN NUMERAL I → U+0069 LATIN SMALL LETTER I]
```

- When displaying text with bidi controls, show a visual indicator:

```text
⚠ Bidirectional override detected; rendered left-to-right:
  curl https://example.com/install.sh
```

### Architecture

```rust
pub trait TerminalRenderer {
    /// Render untrusted text safely for terminal display.
    fn render_text(&self, text: &str, context: RenderContext) -> RenderedText;

    /// Render a source code snippet with safe highlighting.
    fn render_source(&self, source: &str, language: &str, spans: &[SourceSpan]) -> RenderedText;

    /// Render a URL with redaction.
    fn render_url(&self, url: &RedactedUrl) -> RenderedText;
}

pub struct RenderContext {
    pub max_line_length: usize,
    pub max_total_chars: usize,
    pub show_unicode_escapes: bool,
    pub show_bidi_warnings: bool,
    pub show_confusable_warnings: bool,
}
```

The renderer is owned by `arbitraitor-cli` and used for all human-facing output.
Machine output (`--json`, `--sarif`) is structurally encoded (valid JSON), not
terminal-rendered.

### Plugin output

Plugins return **structured data** (typed fields, findings, evidence). The core
renderer converts structured data into terminal-safe output. Plugins cannot
emit raw terminal bytes.

### JSON output

JSON output uses standard JSON string encoding. ANSI sequences, control
characters, and invalid Unicode are represented as escape sequences (`\u001b`,
etc.). This is safe because JSON consumers parse the structure, not render it
as a terminal.

## Consequences

- Terminal injection, clipboard hijacking, and reviewer confusion attacks are
  neutralized.
- Mixed-script homograph attacks (e.g., `caⅰc.org` vs `caic.org`) are visually
  flagged.
- Plugins cannot inject terminal control sequences.
- The renderer adds a small amount of overhead to every output operation.

### Implementation notes

Rust crates to evaluate for the renderer:
- `vte` or `strip-ansi-escapes` for ANSI sequence stripping.
- Custom UTS #39 confusable detection (the `unicode-security` crate if
  available, or a focused implementation).
- `unicode-bidi` for bidi analysis (already a dependency of many crates).

The renderer must be fuzzed with adversarial input containing every category
of dangerous content.

## Alternatives considered

- **Trust plugin output:** Rejected. Creates terminal injection and phishing
  channels.
- **Strip all non-ASCII:** Rejected. Punishes legitimate international content;
  users need to see real filenames and URLs.
- **Per-output ad-hoc escaping:** Rejected. Inconsistent; easy to miss a path.

## References

- `.spec/arbitraitor-adversarial-review-and-gap-analysis.md` H-02
- `.spec/arbitraitor-comprehensive-spec-v0.4.md` §25.0 (Untrusted presentation
  boundary)
- [UTS #39 — Unicode Security Mechanisms](https://www.unicode.org/reports/tr39/)
- [UTS #9 — Unicode Bidirectional Algorithm](https://www.unicode.org/reports/tr9/)
- [Terminal escape sequence injection](https://www.vidarholen.net/contents/blog/?p=878)
