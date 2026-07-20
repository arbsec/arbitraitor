//! Windows Shortcut (`.lnk`) parser for MS-SHLLINK.
//!
//! The parser extracts only the bounded metadata needed for content
//! classification and CVE-2025-9491 detection. It is not a validating
//! loader and never executes the shortcut target. The implementation is
//! pure byte manipulation over the MS-SHLLINK binary format so it works
//! on Linux and macOS without Windows API calls.
//!
//! See ADR-0034 for the detection rationale and CVE-2025-9491 reference.

#![forbid(unsafe_code)]

use core::fmt;

use arbitraitor_model::finding::{Evidence, EvidenceKind, Finding, FindingCategory};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity};
use sha2::{Digest, Sha256};

use crate::DETECTOR_ID;

/// MS-SHLLINK `ShellLinkHeader` size in bytes (fixed at `0x4C` per spec).
const SHELL_LINK_HEADER_SIZE: u32 = 0x0000_004C;

/// Offset of the `Flags` field within `ShellLinkHeader`.
const FLAGS_OFFSET: usize = 0x14;

/// Flag bit: `LinkTargetIDList` section is present.
const FLAG_HAS_LINK_TARGET_ID_LIST: u32 = 0x0000_0001;

/// Flag bit: `LinkInfo` section is present.
const FLAG_HAS_LINK_INFO: u32 = 0x0000_0002;

/// Flag bit: `NAME_STRING` is present in `StringData`.
const FLAG_HAS_NAME: u32 = 0x0000_0004;

/// Flag bit: `RELATIVE_PATH` is present in `StringData`.
const FLAG_HAS_RELATIVE_PATH: u32 = 0x0000_0008;

/// Flag bit: `WORKING_DIR` is present in `StringData`.
const FLAG_HAS_WORKING_DIR: u32 = 0x0000_0010;

/// Flag bit: `COMMAND_LINE_ARGUMENTS` is present in `StringData`.
const FLAG_HAS_ARGUMENTS: u32 = 0x0000_0020;

/// Flag bit: `ICON_LOCATION` is present in `StringData`.
const FLAG_HAS_ICON_LOCATION: u32 = 0x0000_0040;

/// Flag bit: `StringData` strings are Unicode (`UTF-16LE`).
const FLAG_UNICODE: u32 = 0x0000_0080;

/// Flag bit: `LinkInfo` section is suppressed even if `HasLinkInfo` is set.
const FLAG_FORCE_NO_LINK_INFO: u32 = 0x0000_0100;

/// Minimum leading whitespace run that triggers CVE-2025-9491 detection.
///
/// Windows Explorer's Properties dialog truncates the arguments field display
/// near this width, so 260+ whitespace characters push the real command out of
/// the visible area. The threshold matches the ACROS Security 0patch analysis.
const CVE_2025_9491_PADDING_THRESHOLD: usize = 260;

/// Maximum total `StringData` bytes the parser will walk. Bounds untrusted
/// input per spec invariant 4 (bounded parsing).
const MAX_STRING_DATA_BYTES: usize = 64 * 1024;

/// Maximum `LinkInfo` size the parser will accept. Bounds untrusted input.
const MAX_LINK_INFO_BYTES: usize = 64 * 1024;

/// Maximum `LinkTargetIDList` size the parser will accept.
const MAX_ID_LIST_BYTES: usize = 64 * 1024;

/// Stable finding identifier for CVE-2025-9491 whitespace-padding detection.
const FINDING_ID: &str = "artifact.lnk-argument-padding";

/// CVE-2025-9491 reference URL included in findings.
const CVE_2025_9491_REF: &str = "https://nvd.nist.gov/vuln/detail/CVE-2025-9491";

/// Error returned when LNK parsing fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LnkParseError {
    /// Input is shorter than the `ShellLinkHeader` (76 bytes).
    TruncatedHeader,
    /// `HeaderSize` field does not equal `0x0000004C`.
    InvalidHeaderSize(u32),
    /// A section size field exceeds the remaining input or the parser bound.
    SectionOverflow {
        /// Section that overflowed.
        section: &'static str,
        /// Declared size in bytes.
        declared: usize,
        /// Bytes remaining from the section start.
        available: usize,
    },
    /// A `StringData` `CountCharacters` field exceeds the remaining input.
    StringCountOverflow {
        /// Declared character count.
        declared: usize,
        /// Bytes remaining after the count field.
        available: usize,
    },
}

impl fmt::Display for LnkParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => {
                formatter.write_str("lnk input is shorter than the 76-byte ShellLinkHeader")
            }
            Self::InvalidHeaderSize(value) => formatter.write_fmt(format_args!(
                "lnk HeaderSize {value:#010x} does not equal 0x0000004c"
            )),
            Self::SectionOverflow {
                section,
                declared,
                available,
            } => formatter.write_fmt(format_args!(
                "lnk {section} declared {declared} bytes but only {available} remain"
            )),
            Self::StringCountOverflow {
                declared,
                available,
            } => formatter.write_fmt(format_args!(
                "lnk StringData CountCharacters {declared} exceeds {available} remaining bytes"
            )),
        }
    }
}

impl std::error::Error for LnkParseError {}

/// Parsed `COMMAND_LINE_ARGUMENTS` from an MS-SHLLINK shortcut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LnkArguments {
    /// Raw decoded argument string (UTF-8, lossy for non-Unicode shortcuts).
    pub value: String,
    /// Whether the shortcut declared Unicode `StringData`.
    pub unicode: bool,
}

/// Returns `true` when `data` begins with a valid MS-SHLLINK header.
///
/// The header magic is the 4-byte little-endian `HeaderSize` field equal to
/// `0x0000004C` at offset 0. This is the canonical LNK signature per
/// MS-SHLLINK §2.1.
#[must_use]
pub fn is_lnk(data: &[u8]) -> bool {
    data.len() >= 4
        && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == SHELL_LINK_HEADER_SIZE
}

/// Parses an MS-SHLLINK shortcut and returns the `COMMAND_LINE_ARGUMENTS` field
/// when present.
///
/// The parser walks the `ShellLinkHeader`, optional `LinkTargetIDList`,
/// optional `LinkInfo`, and the `StringData` section in spec order. It is
/// bounded: section sizes exceeding [`MAX_STRING_DATA_BYTES`],
/// [`MAX_LINK_INFO_BYTES`], or [`MAX_ID_LIST_BYTES`] return
/// [`LnkParseError::SectionOverflow`].
///
/// # Errors
///
/// Returns [`LnkParseError`] when the input is truncated, the header size is
/// invalid, or a section size field exceeds the remaining input.
pub fn parse_arguments(data: &[u8]) -> Result<Option<LnkArguments>, LnkParseError> {
    if data.len() < 4 {
        return Err(LnkParseError::TruncatedHeader);
    }
    let header_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if header_size != SHELL_LINK_HEADER_SIZE {
        return Err(LnkParseError::InvalidHeaderSize(header_size));
    }
    if data.len() < SHELL_LINK_HEADER_SIZE as usize {
        return Err(LnkParseError::TruncatedHeader);
    }

    let flags = u32::from_le_bytes([
        data[FLAGS_OFFSET],
        data[FLAGS_OFFSET + 1],
        data[FLAGS_OFFSET + 2],
        data[FLAGS_OFFSET + 3],
    ]);

    let mut cursor = SHELL_LINK_HEADER_SIZE as usize;

    if flags & FLAG_HAS_LINK_TARGET_ID_LIST != 0 {
        cursor = skip_link_target_id_list(data, cursor)?;
    }

    if flags & FLAG_HAS_LINK_INFO != 0 && flags & FLAG_FORCE_NO_LINK_INFO == 0 {
        cursor = skip_link_info(data, cursor)?;
    }

    let arguments = read_string_data(data, cursor, flags, FLAG_HAS_ARGUMENTS)?;
    Ok(arguments.map(|value| LnkArguments {
        value,
        unicode: flags & FLAG_UNICODE != 0,
    }))
}

/// Inspects an MS-SHLLINK shortcut for CVE-2025-9491 whitespace padding.
///
/// Returns a finding when the `COMMAND_LINE_ARGUMENTS` field contains a run
/// of 260 or more consecutive whitespace characters. The finding references
/// CVE-2025-9491 and carries the `suspicious-script-behavior` category per
/// spec §15.3.
///
/// Returns an empty vector when the shortcut is clean, has no arguments field,
/// or does not parse as a valid LNK.
#[must_use]
pub fn inspect(data: &[u8]) -> Vec<Finding> {
    let Some(arguments) = parse_arguments(data).ok().flatten() else {
        return Vec::new();
    };
    let Some(padding_len) = detect_whitespace_padding(&arguments.value) else {
        return Vec::new();
    };
    let sha256 = Sha256Digest::new(Sha256::digest(data).into());
    vec![cve_2025_9491_finding(&arguments.value, padding_len, sha256)]
}

/// Returns the length of the leading whitespace run when it meets the
/// CVE-2025-9491 threshold, or `None` otherwise.
fn detect_whitespace_padding(value: &str) -> Option<usize> {
    let leading = value.chars().take_while(|ch| ch.is_whitespace()).count();
    if leading >= CVE_2025_9491_PADDING_THRESHOLD {
        Some(leading)
    } else {
        None
    }
}

/// Advances the cursor past the `LinkTargetIDList` section.
fn skip_link_target_id_list(data: &[u8], cursor: usize) -> Result<usize, LnkParseError> {
    let count_field_end = cursor
        .checked_add(2)
        .ok_or(LnkParseError::SectionOverflow {
            section: "LinkTargetIDList",
            declared: 2,
            available: data.len().saturating_sub(cursor),
        })?;
    if count_field_end > data.len() {
        return Err(LnkParseError::SectionOverflow {
            section: "LinkTargetIDList",
            declared: 2,
            available: data.len().saturating_sub(cursor),
        });
    }
    let id_list_size = u16::from_le_bytes([data[cursor], data[cursor + 1]]) as usize;
    if id_list_size > MAX_ID_LIST_BYTES {
        return Err(LnkParseError::SectionOverflow {
            section: "LinkTargetIDList",
            declared: id_list_size,
            available: data.len().saturating_sub(count_field_end),
        });
    }
    let section_end =
        count_field_end
            .checked_add(id_list_size)
            .ok_or(LnkParseError::SectionOverflow {
                section: "LinkTargetIDList",
                declared: id_list_size,
                available: data.len().saturating_sub(count_field_end),
            })?;
    if section_end > data.len() {
        return Err(LnkParseError::SectionOverflow {
            section: "LinkTargetIDList",
            declared: id_list_size,
            available: data.len().saturating_sub(count_field_end),
        });
    }
    Ok(section_end)
}

/// Advances the cursor past the `LinkInfo` section.
fn skip_link_info(data: &[u8], cursor: usize) -> Result<usize, LnkParseError> {
    let size_field_end = cursor
        .checked_add(4)
        .ok_or(LnkParseError::SectionOverflow {
            section: "LinkInfo",
            declared: 4,
            available: data.len().saturating_sub(cursor),
        })?;
    if size_field_end > data.len() {
        return Err(LnkParseError::SectionOverflow {
            section: "LinkInfo",
            declared: 4,
            available: data.len().saturating_sub(cursor),
        });
    }
    let link_info_size = u32::from_le_bytes([
        data[cursor],
        data[cursor + 1],
        data[cursor + 2],
        data[cursor + 3],
    ]) as usize;
    if link_info_size > MAX_LINK_INFO_BYTES {
        return Err(LnkParseError::SectionOverflow {
            section: "LinkInfo",
            declared: link_info_size,
            available: data.len().saturating_sub(cursor),
        });
    }
    let section_end = cursor
        .checked_add(link_info_size)
        .ok_or(LnkParseError::SectionOverflow {
            section: "LinkInfo",
            declared: link_info_size,
            available: data.len().saturating_sub(cursor),
        })?;
    if section_end > data.len() {
        return Err(LnkParseError::SectionOverflow {
            section: "LinkInfo",
            declared: link_info_size,
            available: data.len().saturating_sub(cursor),
        });
    }
    Ok(section_end)
}

/// Reads the `StringData` section and returns the string for the target flag.
///
/// Strings appear in spec order: `NAME_STRING`, `RELATIVE_PATH`,
/// `WORKING_DIR`, `COMMAND_LINE_ARGUMENTS`, `ICON_LOCATION`. This function
/// walks each present string before the target and returns the target's
/// decoded value.
fn read_string_data(
    data: &[u8],
    mut cursor: usize,
    flags: u32,
    target_flag: u32,
) -> Result<Option<String>, LnkParseError> {
    let string_order = [
        (FLAG_HAS_NAME, "NAME_STRING"),
        (FLAG_HAS_RELATIVE_PATH, "RELATIVE_PATH"),
        (FLAG_HAS_WORKING_DIR, "WORKING_DIR"),
        (FLAG_HAS_ARGUMENTS, "COMMAND_LINE_ARGUMENTS"),
        (FLAG_HAS_ICON_LOCATION, "ICON_LOCATION"),
    ];

    let unicode = flags & FLAG_UNICODE != 0;
    let mut target_found = false;

    for (flag, section_name) in string_order {
        if flags & flag == 0 {
            continue;
        }
        if flag == target_flag {
            target_found = true;
        }
        let decoded = read_counted_string(data, &mut cursor, unicode, section_name)?;
        if target_found {
            return Ok(decoded);
        }
    }

    Ok(None)
}

/// Reads a single counted string from `StringData`.
///
/// Each string is prefixed by a 2-byte little-endian `CountCharacters` field.
/// For Unicode shortcuts, the payload is `CountCharacters * 2` bytes of
/// `UTF-16LE`; for non-Unicode shortcuts, it is `CountCharacters` bytes of
/// ASCII. The function advances `cursor` past the string.
fn read_counted_string(
    data: &[u8],
    cursor: &mut usize,
    unicode: bool,
    section: &'static str,
) -> Result<Option<String>, LnkParseError> {
    let count_field_end = cursor
        .checked_add(2)
        .ok_or(LnkParseError::SectionOverflow {
            section,
            declared: 2,
            available: data.len().saturating_sub(*cursor),
        })?;
    if count_field_end > data.len() {
        return Err(LnkParseError::SectionOverflow {
            section,
            declared: 2,
            available: data.len().saturating_sub(*cursor),
        });
    }
    let count_characters = u16::from_le_bytes([data[*cursor], data[*cursor + 1]]) as usize;
    let payload_bytes = if unicode {
        count_characters
            .checked_mul(2)
            .ok_or(LnkParseError::StringCountOverflow {
                declared: count_characters,
                available: data.len().saturating_sub(count_field_end),
            })?
    } else {
        count_characters
    };

    if payload_bytes > MAX_STRING_DATA_BYTES {
        return Err(LnkParseError::StringCountOverflow {
            declared: payload_bytes,
            available: data.len().saturating_sub(count_field_end),
        });
    }

    let payload_end =
        count_field_end
            .checked_add(payload_bytes)
            .ok_or(LnkParseError::StringCountOverflow {
                declared: payload_bytes,
                available: data.len().saturating_sub(count_field_end),
            })?;
    if payload_end > data.len() {
        return Err(LnkParseError::StringCountOverflow {
            declared: payload_bytes,
            available: data.len().saturating_sub(count_field_end),
        });
    }

    *cursor = payload_end;

    let payload = &data[count_field_end..payload_end];
    let value = if unicode {
        decode_utf16le_lossy(payload)
    } else {
        String::from_utf8_lossy(payload).into_owned()
    };
    Ok(Some(value))
}

/// Decodes a `UTF-16LE` byte slice into a String, replacing invalid sequences
/// with the replacement character.
fn decode_utf16le_lossy(payload: &[u8]) -> String {
    let units: Vec<u16> = payload
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Builds the CVE-2025-9491 finding for whitespace-padded arguments.
fn cve_2025_9491_finding(
    arguments: &str,
    padding_len: usize,
    artifact_sha256: Sha256Digest,
) -> Finding {
    let preview_len = arguments.len().min(120);
    let preview = &arguments[..preview_len];
    Finding {
        id: FINDING_ID.to_owned(),
        detector: DETECTOR_ID.to_owned(),
        category: FindingCategory::SuspiciousScriptBehavior,
        severity: Severity::High,
        confidence: Confidence::Confirmed,
        title: "LNK argument field whitespace padding (CVE-2025-9491)".to_owned(),
        description: format!(
            "COMMAND_LINE_ARGUMENTS begins with {padding_len} whitespace characters, \
             which exceeds the {CVE_2025_9491_PADDING_THRESHOLD}-character Windows Explorer \
             Properties dialog truncation point. This is the CVE-2025-9491 UI-misrepresentation \
             pattern: the real command is pushed out of the visible area, hiding the true \
             invocation from manual review."
        ),
        evidence: vec![Evidence {
            kind: EvidenceKind::DecodedContent,
            description: "COMMAND_LINE_ARGUMENTS field preview".to_owned(),
            content: Some(format!("{preview}…")),
        }],
        artifact_sha256,
        location: None,
        remediation: Some(
            "Reject the shortcut or strip the padding before review. \
             Apply the ACROS Security 0patch micropatch or the June 2025 Microsoft partial \
             mitigation on hosts that must render .lnk properties."
                .to_owned(),
        ),
        references: vec![CVE_2025_9491_REF.to_owned()],
        tags: vec![
            "cve-2025-9491".to_owned(),
            "lnk".to_owned(),
            "ui-misrepresentation".to_owned(),
        ],
        taxonomies: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_SIZE_BYTES: [u8; 4] = 0x0000_004Cu32.to_le_bytes();
    const LINK_CLSID: [u8; 16] = [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];

    /// Builds a minimal LNK byte vector with the given flags and optional
    /// `COMMAND_LINE_ARGUMENTS` payload.
    fn build_lnk(flags: u32, arguments: Option<&str>) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&HEADER_SIZE_BYTES);
        data.extend_from_slice(&LINK_CLSID);
        data.extend_from_slice(&flags.to_le_bytes());
        data.resize(SHELL_LINK_HEADER_SIZE as usize, 0);
        if let Some(args) = arguments {
            let unicode = flags & FLAG_UNICODE != 0;
            if unicode {
                let units: Vec<u16> = args.encode_utf16().collect();
                let count = u16::try_from(units.len()).unwrap_or(u16::MAX);
                data.extend_from_slice(&count.to_le_bytes());
                for unit in units {
                    data.extend_from_slice(&unit.to_le_bytes());
                }
            } else {
                let bytes = args.as_bytes();
                let count = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
                data.extend_from_slice(&count.to_le_bytes());
                data.extend_from_slice(bytes);
            }
        }
        data
    }

    #[test]
    fn is_lnk_rejects_non_lnk_magic() {
        assert!(!is_lnk(b"PK\x03\x04rest"));
        assert!(!is_lnk(b"\x7fELF"));
        assert!(!is_lnk(b""));
        assert!(!is_lnk(&[0x4c]));
    }

    #[test]
    fn is_lnk_accepts_valid_header() {
        let data = build_lnk(0, None);
        assert!(is_lnk(&data));
    }

    #[test]
    fn parse_arguments_returns_none_when_no_arguments_flag()
    -> Result<(), Box<dyn std::error::Error>> {
        let data = build_lnk(0, None);
        let result = parse_arguments(&data)?;
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    fn parse_arguments_extracts_unicode_arguments() -> Result<(), Box<dyn std::error::Error>> {
        let data = build_lnk(FLAG_HAS_ARGUMENTS | FLAG_UNICODE, Some("--help"));
        let args = parse_arguments(&data)?.ok_or("arguments should be present")?;
        assert_eq!(args.value, "--help");
        assert!(args.unicode);
        Ok(())
    }

    #[test]
    fn parse_arguments_extracts_non_unicode_arguments() -> Result<(), Box<dyn std::error::Error>> {
        let data = build_lnk(FLAG_HAS_ARGUMENTS, Some("--version"));
        let args = parse_arguments(&data)?.ok_or("arguments should be present")?;
        assert_eq!(args.value, "--version");
        assert!(!args.unicode);
        Ok(())
    }

    #[test]
    fn parse_arguments_skips_name_and_working_dir_before_arguments()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut data = Vec::new();
        data.extend_from_slice(&HEADER_SIZE_BYTES);
        data.extend_from_slice(&LINK_CLSID);
        let flags = FLAG_HAS_NAME | FLAG_HAS_WORKING_DIR | FLAG_HAS_ARGUMENTS | FLAG_UNICODE;
        data.extend_from_slice(&flags.to_le_bytes());
        data.resize(SHELL_LINK_HEADER_SIZE as usize, 0);

        for s in ["notepad.exe", "C:\\Windows", "--clean"] {
            let units: Vec<u16> = s.encode_utf16().collect();
            let count = u16::try_from(units.len()).unwrap_or(u16::MAX);
            data.extend_from_slice(&count.to_le_bytes());
            for unit in units {
                data.extend_from_slice(&unit.to_le_bytes());
            }
        }

        let args = parse_arguments(&data)?.ok_or("arguments should be present")?;
        assert_eq!(args.value, "--clean");
        Ok(())
    }

    #[test]
    fn parse_arguments_rejects_truncated_header() -> Result<(), Box<dyn std::error::Error>> {
        let err = parse_arguments(&[0x4c, 0x00]).err().ok_or("should error")?;
        assert_eq!(err, LnkParseError::TruncatedHeader);
        Ok(())
    }

    #[test]
    fn parse_arguments_rejects_invalid_header_size() -> Result<(), Box<dyn std::error::Error>> {
        let mut data = vec![0xff, 0xff, 0xff, 0xff];
        data.resize(SHELL_LINK_HEADER_SIZE as usize, 0);
        let err = parse_arguments(&data).err().ok_or("should error")?;
        assert_eq!(err, LnkParseError::InvalidHeaderSize(0xffff_ffff));
        Ok(())
    }

    #[test]
    fn parse_arguments_rejects_overflowing_id_list() -> Result<(), Box<dyn std::error::Error>> {
        let mut data = Vec::new();
        data.extend_from_slice(&HEADER_SIZE_BYTES);
        data.extend_from_slice(&LINK_CLSID);
        data.extend_from_slice(&(FLAG_HAS_LINK_TARGET_ID_LIST).to_le_bytes());
        data.resize(SHELL_LINK_HEADER_SIZE as usize, 0);
        data.extend_from_slice(&0xFFFFu16.to_le_bytes());

        let err = parse_arguments(&data).err().ok_or("should error")?;
        assert!(matches!(
            err,
            LnkParseError::SectionOverflow {
                section: "LinkTargetIDList",
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn inspect_returns_no_findings_for_clean_lnk() {
        let data = build_lnk(FLAG_HAS_ARGUMENTS | FLAG_UNICODE, Some("--help"));
        let findings = inspect(&data);
        assert!(findings.is_empty());
    }

    #[test]
    fn inspect_returns_no_findings_when_arguments_absent() {
        let data = build_lnk(0, None);
        let findings = inspect(&data);
        assert!(findings.is_empty());
    }

    #[test]
    fn inspect_detects_cve_2025_9491_padding() {
        let padding = " ".repeat(300);
        let args = format!("{padding}malware.exe --silent");
        let data = build_lnk(FLAG_HAS_ARGUMENTS | FLAG_UNICODE, Some(&args));
        let findings = inspect(&data);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.id, "artifact.lnk-argument-padding");
        assert_eq!(finding.category, FindingCategory::SuspiciousScriptBehavior);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert!(
            finding
                .references
                .iter()
                .any(|r| r.contains("CVE-2025-9491"))
        );
        assert!(finding.tags.contains(&"cve-2025-9491".to_owned()));
    }

    #[test]
    fn inspect_does_not_flag_short_whitespace() {
        let args = " ".repeat(100) + "notepad.exe";
        let data = build_lnk(FLAG_HAS_ARGUMENTS | FLAG_UNICODE, Some(&args));
        let findings = inspect(&data);
        assert!(findings.is_empty());
    }

    #[test]
    fn inspect_returns_empty_for_non_lnk() {
        let findings = inspect(b"PK\x03\x04not a lnk file");
        assert!(findings.is_empty());
    }

    #[test]
    fn inspect_returns_empty_for_truncated_lnk() {
        let findings = inspect(&[0x4c, 0x00]);
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_whitespace_padding_threshold_is_260() {
        assert_eq!(detect_whitespace_padding(&" ".repeat(259)), None);
        assert!(detect_whitespace_padding(&" ".repeat(260)).is_some());
        assert!(detect_whitespace_padding(&" ".repeat(300)).is_some());
    }

    #[test]
    fn detect_whitespace_padding_ignores_non_leading_whitespace() {
        let value = "notepad.exe ".repeat(30);
        assert_eq!(detect_whitespace_padding(&value), None);
    }
}
