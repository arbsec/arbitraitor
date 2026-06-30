//! Threat corpus helpers for test fixtures.
//!
//! Provides structured access to synthetic test samples organized by
//! detection category. All samples are safe, synthetic, and committed
//! to the repository — no real malware is stored.

/// EICAR test string (68 bytes). The universal AV baseline sample.
pub const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Expected SHA-256 of the EICAR test file.
pub const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf65cfd7a";

/// Returns the EICAR test string as a byte vector.
#[must_use]
pub fn eicar_plain() -> Vec<u8> {
    EICAR.to_vec()
}
