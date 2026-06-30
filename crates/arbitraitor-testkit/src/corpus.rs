//! Threat corpus helpers for test fixtures.
//!
//! Provides structured access to synthetic test samples organized by
//! detection category. All samples are safe, synthetic, and committed
//! to the repository — no real malware is stored.

/// EICAR test string (68 bytes). The universal AV baseline sample.
pub const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Expected SHA-256 of the EICAR test file.
pub const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

/// Returns the EICAR test string as a byte vector.
#[must_use]
pub fn eicar_plain() -> Vec<u8> {
    EICAR.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use sha2::{Digest, Sha256};

    #[test]
    fn eicar_string_is_68_bytes() {
        assert_eq!(EICAR.len(), 68);
    }

    #[test]
    fn eicar_sha256_constant_is_correct() {
        let computed = Sha256::digest(EICAR);
        let hex_str = hex::encode(computed);
        assert_eq!(
            hex_str, EICAR_SHA256,
            "EICAR_SHA256 constant must match actual SHA-256 of EICAR bytes"
        );
    }
}
