//! `xtask mint-github-token`: mint a short-lived GitHub App installation
//! token for the `arbsec-agent` service identity.
//!
//! AGENTS.md forbids agent-driven GitHub operations as a personal account.
//! This subcommand implements the runbook mechanics (orchestraitor
//! `.omo/drafts/github-app-setup.md` §5): resolve the App private key
//! (PEM), sign an RS256 JWT with `iss` set to the App **client ID** (the
//! App ID is rejected with 401), exchange it at the installation token
//! endpoint, and print the token to stdout — and nothing else — so callers
//! can run `GH_TOKEN="$(cargo run -p xtask -- mint-github-token)" gh ...`.
//!
//! Tokens expire after 1 hour; callers MUST re-mint per operation. The
//! token is never cached on disk and never written to stderr or logs.
//!
//! Design note (dependency policy): the workspace carries no RS256-signing
//! crate, and admitting one (e.g. `jsonwebtoken` + a crypto backend) would
//! require the full dependency admission checklist for a developer-only
//! tool. xtask stays zero-dependency: the JWT is assembled in pure Rust
//! and the RSA signature is produced by the system `openssl` binary; the
//! token request goes through the system `curl` binary. On unix the PEM
//! travels to `openssl` via a 0600 file in a 0700 private temp directory
//! (never argv/env, never inside the repo) and is removed when the command
//! ends; non-unix platforms fail closed — they cannot enforce POSIX file
//! modes and are therefore unsupported for secret material handling.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

/// App client ID for `arbsec-agent` (issuer of the minting JWT; the App ID
/// is rejected by GitHub — verified 2026-09-26, runbook §5/§9-F3).
const APP_CLIENT_ID: &str = "Iv23linxUDbcc53QbFVK";
/// arbsec org installation of the App (env-overridable via
/// `ARBSEC_INSTALLATION_ID`).
const DEFAULT_INSTALLATION_ID: u64 = 165_043_398;
/// JWT lifetime: 10 minutes, per runbook §5.
const JWT_TTL_SECS: u64 = 600;
/// Environment variables holding the App PEM, tried in order before the
/// keyring (mirrors `secret://env/` over `secret://keyring/` precedence).
const PEM_ENV_VARS: [&str; 2] = ["ARBSEC_APP_PEM", "ORCHESTRAITOR_APP_PEM"];
/// Keyring entry backing `secret://keyring/orchestraitor-app-pem`.
const KEYRING_SERVICE: &str = "orchestraitor";
const KEYRING_USER: &str = "orchestraitor-app-pem";

const GITHUB_API: &str = "https://api.github.com";

/// Entry point for the `mint-github-token` subcommand. On success the
/// installation token is printed to stdout (with trailing newline, which
/// command substitution strips). All diagnostics go to stderr and carry no
/// secret material.
pub fn run() -> ExitCode {
    match mint() {
        Ok(token) => {
            println!("{token}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Mint one installation token. Fails closed: if the PEM cannot be loaded
/// from the environment or the keyring, no token is minted and no
/// personal-account fallback is attempted here (the labelled fallback is
/// the caller's explicit decision, per AGENTS.md).
fn mint() -> Result<String, String> {
    let pem = load_pem()?;
    let installation_id = installation_id()?;
    let dir = TempDir::create()?;
    // Guards remove their files even on error paths.
    let pem_file = SecretFile::create(dir.path(), "app.pem", pem.as_bytes())?;
    drop(pem); // PEM lives only in the guarded temp file from here on.

    let signing_input = build_signing_input(unix_now()?, APP_CLIENT_ID);
    let signature = sign_rs256(&signing_input, pem_file.path(), dir.path())?;
    let jwt = format!("{signing_input}.{signature}");

    request_token(&jwt, installation_id, dir.path())
}

// ---------------------------------------------------------------------------
// PEM resolution (fail closed, secrets never logged)
// ---------------------------------------------------------------------------

fn load_pem() -> Result<String, String> {
    for var in PEM_ENV_VARS {
        if let Ok(value) = std::env::var(var) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
    }
    let out = Command::new("secret-tool")
        .args([
            "lookup",
            "service",
            KEYRING_SERVICE,
            "username",
            KEYRING_USER,
        ])
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "secret-tool: command not found (install libsecret: secret-tool is required to \
                 read the arbsec-agent App key from the keyring)"
                    .to_string()
            } else {
                format!("secret-tool: {e}")
            }
        })?;
    let pem = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() && !pem.is_empty() {
        return Ok(pem);
    }
    Err(format!(
        "could not load the arbsec-agent App private key: {PEM_ENV_VARS:?} are unset and \
         `secret-tool lookup service {KEYRING_SERVICE} username {KEYRING_USER}` returned \
         nothing (status {}); minting fails closed — use the labelled personal-account \
         fallback per AGENTS.md only if you must, and note it in the PR body",
        out.status
    ))
}

fn installation_id() -> Result<u64, String> {
    match std::env::var("ARBSEC_INSTALLATION_ID") {
        Ok(raw) => raw
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("ARBSEC_INSTALLATION_ID: not a number: {raw:?}")),
        Err(_) => Ok(DEFAULT_INSTALLATION_ID),
    }
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system clock before 1970: {e}"))
}

// ---------------------------------------------------------------------------
// JWT assembly (pure Rust) + RS256 signing (system openssl)
// ---------------------------------------------------------------------------

/// Build the `<header>.<payload>` signing input. Both parts are fixed-shape
/// JSON over trusted constants (a numeric timestamp and the compile-time
/// client ID), so no escaping is possible.
fn build_signing_input(iat: u64, client_id: &str) -> String {
    let header = base64url(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = format!(
        r#"{{"iat":{iat},"exp":{},"iss":"{client_id}"}}"#,
        iat + JWT_TTL_SECS
    );
    format!("{}.{}", header, base64url(claims.as_bytes()))
}

/// URL-safe base64 without padding (RFC 4648 §5, as required for JWT).
fn base64url(data: &[u8]) -> String {
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[(n >> 18) as usize & 63] as char);
        out.push(CHARS[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(CHARS[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(CHARS[(n & 63) as usize] as char);
        }
    }
    out
}

/// Sign `signing_input` with the PEM at `pem_file` via the system openssl
/// binary (RS256 / PKCS#1 v1.5). The signature is returned base64url-encoded.
/// Both inputs reach openssl as 0600 temp files (never argv/env), within the
/// private temp `dir` that outlives this call.
fn sign_rs256(signing_input: &str, pem_file: &Path, dir: &Path) -> Result<String, String> {
    let input_file = SecretFile::create(dir, "signing-input", signing_input.as_bytes())?;
    let out = Command::new("openssl")
        .args(["dgst", "-sha256", "-sign"])
        .arg(pem_file)
        .arg(input_file.path())
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "openssl: command not found (openssl is required to sign the minting JWT)"
                    .to_string()
            } else {
                format!("openssl: {e}")
            }
        })?;
    if !out.status.success() {
        // openssl diagnostics never contain key material; the temp PEM path
        // is not included (stderr text only).
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(format!("openssl signing failed: {stderr}"));
    }
    Ok(base64url(&out.stdout))
}

// ---------------------------------------------------------------------------
// Token request (system curl; JWT in a 0600 header file, never argv/env)
// ---------------------------------------------------------------------------

fn request_token(jwt: &str, installation_id: u64, dir: &Path) -> Result<String, String> {
    let header_file = SecretFile::create(
        dir,
        "authorization",
        format!("Authorization: Bearer {jwt}").as_bytes(),
    )?;
    let url = format!("{GITHUB_API}/app/installations/{installation_id}/access_tokens");
    let out = Command::new("curl")
        .args(["-sS", "--fail-with-body", "-X", "POST", "-H"])
        .arg(format!("@{}", header_file.path().display()))
        .args(["-H", "Accept: application/vnd.github+json", "--data", "{}"])
        .arg(&url)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "curl: command not found (curl is required to reach the GitHub API)".to_string()
            } else {
                format!("curl: {e}")
            }
        })?;
    let body = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        // --fail-with-body prints the JSON error body on failure; its
        // `message` field is safe diagnostics (GitHub error text only).
        // The body may be empty when the failing binary is not real curl
        // (e.g. an arbitraitor shim on PATH), so the exit code and a shim
        // hint are surfaced too. Neither carries secret material.
        let detail = crate::extract_json_string_field(&body, "message")
            .unwrap_or_else(|| "no detail returned".to_string());
        return Err(format!(
            "token request failed (curl exit {}): {detail}. If a curl shim is on PATH \
             (arbitraitor wrappers), it may intercept this request — invoke /usr/bin/curl \
             or disable the shim for this command",
            out.status.code().unwrap_or(-1)
        ));
    }
    let token = crate::extract_json_string_field(&body, "token")
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            "GitHub response contained no installation token (check the App installation id and \
             permissions)"
                .to_string()
        })?;
    Ok(token)
}

// ---------------------------------------------------------------------------
// Guarded secret files (0700 dir, 0600 files, removed on drop)
// ---------------------------------------------------------------------------

/// Private temp directory, removed (recursively) when dropped.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn create() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!("arbitraitor-mint-{}", std::process::id()));
        // The PID-derived name is predictable, but on a sticky-bit /tmp
        // (the standard for every unix multi-user tmpdir) another user can
        // neither read nor replace this user's directory, so pre-creation
        // removal of own leftovers is safe. The dir is recreated 0700
        // immediately after.
        // A leftover from a crashed run must never carry stale secrets into
        // a new run; it is removed before the fresh (empty) dir is created.
        let _ = fs::remove_dir_all(&path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .map_err(|e| format!("cannot create private temp dir {}: {e}", path.display()))?;
        }
        #[cfg(not(unix))]
        {
            // Fail closed: without POSIX modes there is no way to enforce
            // the 0700 directory guarantee required for secret material.
            let _ = fs::remove_dir_all(&path);
            return Err(
                "non-unix platforms are unsupported for secret material handling \
                 (no POSIX file modes to enforce 0700/0600)"
                    .to_string(),
            );
        }
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A 0600 file (unix) holding secret bytes for the duration of one
/// subprocess call, removed on drop (all error paths included). Only
/// reachable on unix: `TempDir::create` fails closed elsewhere.
struct SecretFile {
    path: PathBuf,
}

impl SecretFile {
    fn create(dir: &Path, name: &str, contents: &[u8]) -> Result<Self, String> {
        use std::io::Write;
        let path = dir.join(name);
        let mut file = fs::OpenOptions::new();
        let file = file.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            file.mode(0o600);
        }
        let mut file = file
            .open(&path)
            .map_err(|e| format!("cannot create secret file {}: {e}", path.display()))?;
        file.write_all(contents)
            .map_err(|e| format!("cannot write secret file {}: {e}", path.display()))?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SecretFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_rfc4648_vectors() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(base64url(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64url_is_url_safe_and_unpadded() {
        // 0xFB 0xFF exercises both alternate characters and the 2-byte tail.
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
        assert_eq!(base64url(&[0xff]), "_w");
        assert!(!base64url(&[0xff, 0xff, 0xff]).contains(['+', '/', '=']));
    }

    #[test]
    fn signing_input_has_fixed_shape_and_ttl() {
        let input = build_signing_input(1_700_000_000, "Iv23test");
        let parts: Vec<&str> = input.split('.').collect();
        assert_eq!(parts.len(), 2);
        // header = base64url({"alg":"RS256","typ":"JWT"})
        assert_eq!(parts[0], base64url(br#"{"alg":"RS256","typ":"JWT"}"#));
        // payload carries iat, exp = iat + 600, and the client ID as iss.
        let payload = base64url_decode(parts[1]);
        let payload = String::from_utf8(payload).unwrap();
        assert_eq!(
            payload,
            r#"{"iat":1700000000,"exp":1700000600,"iss":"Iv23test"}"#
        );
    }

    #[test]
    fn token_is_extracted_from_github_response_shape() {
        let body = r#"{"token":"ghs_example","expires_at":"2026-09-30T22:59:44Z","permissions":{"contents":"write"}}"#;
        assert_eq!(
            crate::extract_json_string_field(body, "token").as_deref(),
            Some("ghs_example")
        );
        // A body without a token extracts to nothing (caller fails closed).
        assert_eq!(crate::extract_json_string_field(body, "missing"), None);
    }

    #[test]
    fn secret_file_is_removed_on_drop() {
        let dir = TempDir::create().unwrap();
        let path;
        {
            let file = SecretFile::create(dir.path(), "probe", b"secret").unwrap();
            path = file.path().to_path_buf();
            assert!(path.exists());
        }
        assert!(!path.exists());
    }

    /// Minimal base64url decoder for test assertions only.
    fn base64url_decode(s: &str) -> Vec<u8> {
        let mut acc: u32 = 0;
        let mut bits = 0u32;
        let mut out = Vec::new();
        for ch in s.chars() {
            let v = match ch {
                'A'..='Z' => ch as u32 - 'A' as u32,
                'a'..='z' => ch as u32 - 'a' as u32 + 26,
                '0'..='9' => ch as u32 - '0' as u32 + 52,
                '-' => 62,
                '_' => 63,
                _ => panic!("invalid base64url char {ch}"),
            };
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        out
    }
}
