//! Secret reference resolution and redaction for Arbitraitor configuration.
//!
//! Configuration values may reference external secrets via the `secret://`
//! URI scheme. The [`SecretResolver`] resolves these references at load time
//! from the process environment or from files confined to a configured root.
//!
//! Resolved secrets are never logged; wrap them in [`RedactedString`] to
//! prevent accidental disclosure in `Debug` or `Display` output.
//!
//! # Supported reference forms
//!
//! | Reference | Backend | Resolves to |
//! |---|---|---|
//! | `secret://env/VAR_NAME` | environment | value of `VAR_NAME` |
//! | `secret://file/relative/path` | file | contents of `file_root/relative/path` |
//!
//! # Security properties
//!
//! - File secrets are confined to `file_root`. Path traversal (`..`, absolute
//!   paths) and symlinks are rejected.
//! - The resolver is fail-closed: both backends are disabled by default.
//! - [`RedactedString`] never reveals its inner value through `Debug` or
//!   `Display`. The value is only accessible via [`RedactedString::reveal`].

#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

/// URI scheme prefix marking a secret reference.
const SECRET_SCHEME: &str = "secret://";

/// Errors produced while resolving secret references.
#[derive(Debug, Error)]
pub enum SecretError {
    /// The reference named a backend other than `env` or `file`.
    #[error("unsupported secret backend `{backend}` in reference `{reference}`")]
    UnsupportedBackend {
        /// The unrecognized backend identifier.
        backend: String,
        /// The full reference string.
        reference: String,
    },

    /// The referenced environment variable was not set.
    #[error("environment variable `{name}` not set for reference `{reference}`")]
    EnvNotSet {
        /// The missing variable name.
        name: String,
        /// The full reference string.
        reference: String,
    },

    /// The referenced file secret was not found.
    #[error("secret file not found at `{path}` for reference `{reference}`")]
    FileNotFound {
        /// The resolved filesystem path.
        path: PathBuf,
        /// The full reference string.
        reference: String,
    },

    /// The reference attempted to escape the configured file root.
    #[error("secret reference `{reference}` escapes the configured file root")]
    PathTraversal {
        /// The full reference string.
        reference: String,
    },

    /// The reference resolved to a symlink, which is not permitted.
    #[error("secret reference `{reference}` resolves to a symlink")]
    SymlinkRejected {
        /// The full reference string.
        reference: String,
    },

    /// File secrets are disabled.
    #[error("file secrets are disabled; reference `{reference}` rejected")]
    FilesDisabled {
        /// The full reference string.
        reference: String,
    },

    /// Environment secrets are disabled.
    #[error("environment secrets are disabled; reference `{reference}` rejected")]
    EnvDisabled {
        /// The full reference string.
        reference: String,
    },

    /// No file root was configured.
    #[error("no file root configured for reference `{reference}`")]
    NoFileRoot {
        /// The full reference string.
        reference: String,
    },

    /// A secret file could not be read.
    #[error("failed to read secret file `{path}`: {source}")]
    FileRead {
        /// The path that failed.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// A string wrapper that never reveals its value through `Debug` or `Display`.
///
/// Carry resolved secret values inside this type so that accidental logging,
/// error interpolation, or `{:?}` formatting produces `REDACTED` rather than
/// the secret itself. The value is only accessible via [`RedactedString::reveal`].
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedString(String);

impl RedactedString {
    /// Wraps `value` so it cannot be accidentally logged.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the underlying secret value.
    ///
    /// Callers are responsible for not logging or otherwise disclosing the
    /// returned string.
    #[must_use]
    pub fn reveal(&self) -> &str {
        &self.0
    }

    /// Returns the constant `"REDACTED"`.
    #[must_use]
    pub fn redacted(&self) -> &'static str {
        "REDACTED"
    }
}

impl fmt::Debug for RedactedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RedactedString(REDACTED)")
    }
}

impl fmt::Display for RedactedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("REDACTED")
    }
}

impl From<String> for RedactedString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Resolves `secret://` references against environment variables and files.
///
/// Both backends are disabled by default (fail-closed). Enable them with
/// [`SecretResolver::with_env`] and [`SecretResolver::with_files`].
#[derive(Clone, Debug)]
pub struct SecretResolver {
    /// Whether `secret://env/...` references are permitted.
    allow_env: bool,
    /// Whether `secret://file/...` references are permitted.
    allow_file: bool,
    /// Directory under which file secrets must live.
    file_root: Option<PathBuf>,
}

impl Default for SecretResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretResolver {
    /// Creates a resolver with both backends disabled.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            allow_env: false,
            allow_file: false,
            file_root: None,
        }
    }

    /// Enables or disables the environment variable backend.
    #[must_use]
    pub const fn with_env(mut self, allow: bool) -> Self {
        self.allow_env = allow;
        self
    }

    /// Enables or disables the file backend.
    ///
    /// When `root` is `None`, file references are rejected even if `allow`
    /// is `true`.
    #[must_use]
    pub fn with_files(mut self, allow: bool, root: Option<PathBuf>) -> Self {
        self.allow_file = allow;
        self.file_root = root;
        self
    }

    /// Returns `true` if `value` is a `secret://` reference.
    #[must_use]
    pub fn is_secret_ref(value: &str) -> bool {
        value.starts_with(SECRET_SCHEME)
    }

    /// Resolves `value` if it is a secret reference; otherwise returns it unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError`] if the reference is malformed, its backend is
    /// disabled, the backing store cannot provide the value, or a file
    /// reference attempts to escape the configured root.
    pub fn resolve(&self, value: &str) -> Result<String, SecretError> {
        if !Self::is_secret_ref(value) {
            return Ok(value.to_owned());
        }
        let body = &value[SECRET_SCHEME.len()..];
        let (backend, rest) = body.split_once('/').unwrap_or((body, ""));
        match backend {
            "env" => self.resolve_env(value, rest),
            "file" => self.resolve_file(value, rest),
            other => Err(SecretError::UnsupportedBackend {
                backend: other.to_owned(),
                reference: value.to_owned(),
            }),
        }
    }

    fn resolve_env(&self, reference: &str, name: &str) -> Result<String, SecretError> {
        if !self.allow_env {
            return Err(SecretError::EnvDisabled {
                reference: reference.to_owned(),
            });
        }
        std::env::var(name).map_err(|_| SecretError::EnvNotSet {
            name: name.to_owned(),
            reference: reference.to_owned(),
        })
    }

    fn resolve_file(&self, reference: &str, relative: &str) -> Result<String, SecretError> {
        if !self.allow_file {
            return Err(SecretError::FilesDisabled {
                reference: reference.to_owned(),
            });
        }
        let root = self
            .file_root
            .as_deref()
            .ok_or_else(|| SecretError::NoFileRoot {
                reference: reference.to_owned(),
            })?;

        // Lexical traversal rejection before touching the filesystem.
        // Only normal and current-dir components are permitted.
        let relative_path = Path::new(relative);
        if relative_path
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
        {
            return Err(SecretError::PathTraversal {
                reference: reference.to_owned(),
            });
        }

        // Canonicalize the root to resolve symlink components within the root
        // path itself and to obtain an absolute anchor for containment checks.
        let canonical_root = fs::canonicalize(root).map_err(|source| SecretError::FileRead {
            path: root.to_path_buf(),
            source,
        })?;

        let candidate = canonical_root.join(relative_path);

        // Symlink rejection: the final path component must not be a symlink.
        // `symlink_metadata` inspects the entry without following the link.
        let metadata = fs::symlink_metadata(&candidate).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                SecretError::FileNotFound {
                    path: candidate.clone(),
                    reference: reference.to_owned(),
                }
            } else {
                SecretError::FileRead {
                    path: candidate.clone(),
                    source: err,
                }
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(SecretError::SymlinkRejected {
                reference: reference.to_owned(),
            });
        }

        // Containment: canonicalize the parent directory and verify it remains
        // within the root. This catches intermediate directory symlinks that
        // would escape the root.
        let parent = candidate
            .parent()
            .ok_or_else(|| SecretError::PathTraversal {
                reference: reference.to_owned(),
            })?;
        let canonical_parent =
            fs::canonicalize(parent).map_err(|source| SecretError::FileRead {
                path: parent.to_path_buf(),
                source,
            })?;
        if !canonical_parent.starts_with(&canonical_root) {
            return Err(SecretError::PathTraversal {
                reference: reference.to_owned(),
            });
        }

        fs::read_to_string(&candidate).map_err(|source| SecretError::FileRead {
            path: candidate,
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn temp_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "arbitraitor-secret-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// Generates a process-unique environment variable name for parallel-safe tests.
    fn unique_env_name(base: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        format!("ARBITRAITOR_TEST_{base}_{nanos}")
    }

    #[test]
    fn env_secret_resolved() -> TestResult {
        // Read a standard env var that is already set in the test environment.
        // This avoids `std::env::set_var`, which is `unsafe` in Rust 2024.
        let (name, expected) = ["PATH", "HOME", "USER", "PWD", "LANG", "SHLVL"]
            .iter()
            .find_map(|n| std::env::var(n).ok().map(|v| (*n, v)))
            .ok_or("no standard environment variable available")?;

        let reference = format!("secret://env/{name}");
        let resolver = SecretResolver::new().with_env(true);
        let result = resolver.resolve(&reference)?;

        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn file_secret_resolved() -> TestResult {
        let root = temp_dir("file_resolved")?;
        fs::write(root.join("test.txt"), "file-secret-value")?;

        let resolver = SecretResolver::new().with_files(true, Some(root.clone()));
        let result = resolver.resolve("secret://file/test.txt");

        assert_eq!(result?, "file-secret-value");
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn non_secret_passes_through() -> TestResult {
        let resolver = SecretResolver::new();
        let result = resolver.resolve("just-a-regular-string");
        assert_eq!(result?, "just-a-regular-string");
        Ok(())
    }

    #[test]
    fn env_secret_not_found() {
        let var_name = unique_env_name("NOT_SET");
        let reference = format!("secret://env/{var_name}");
        let resolver = SecretResolver::new().with_env(true);

        let result = resolver.resolve(&reference);

        assert!(matches!(result, Err(SecretError::EnvNotSet { .. })));
    }

    #[test]
    fn file_secret_path_traversal_rejected() -> TestResult {
        let root = temp_dir("traversal")?;
        let resolver = SecretResolver::new().with_files(true, Some(root.clone()));

        // Parent-directory traversal.
        let result = resolver.resolve("secret://file/../../../etc/passwd");
        assert!(matches!(result, Err(SecretError::PathTraversal { .. })));

        // Absolute path (leading slash produces a RootDir component).
        let result = resolver.resolve("secret://file//etc/passwd");
        assert!(matches!(result, Err(SecretError::PathTraversal { .. })));

        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn file_secret_outside_root_rejected() -> TestResult {
        use std::os::unix::fs::symlink;

        let root = temp_dir("symlink_root")?;
        let outside = temp_dir("outside")?;
        let target = outside.join("real.txt");
        fs::write(&target, "escaped")?;

        let link = root.join("link.txt");
        symlink(&target, &link)?;

        let resolver = SecretResolver::new().with_files(true, Some(root.clone()));
        let result = resolver.resolve("secret://file/link.txt");

        assert!(matches!(result, Err(SecretError::SymlinkRejected { .. })));

        fs::remove_dir_all(&root)?;
        fs::remove_dir_all(&outside)?;
        Ok(())
    }

    #[test]
    fn env_disabled_rejects_env_refs() {
        // `new()` disables both backends by default (fail-closed).
        let resolver = SecretResolver::new();

        let result = resolver.resolve("secret://env/SOME_VAR");

        assert!(matches!(result, Err(SecretError::EnvDisabled { .. })));
    }

    #[test]
    fn redacted_string_debug_shows_redacted() {
        let redacted = RedactedString::new("super-secret-value");

        // Debug never reveals the value.
        assert_eq!(format!("{redacted:?}"), "RedactedString(REDACTED)");

        // Display never reveals the value.
        assert_eq!(format!("{redacted}"), "REDACTED");

        // The redacted() helper returns the constant.
        assert_eq!(redacted.redacted(), "REDACTED");

        // Only reveal() provides the actual value.
        assert_eq!(redacted.reveal(), "super-secret-value");
    }
}
