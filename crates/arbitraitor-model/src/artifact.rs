//! Artifact classification types.

use serde::{Deserialize, Serialize};

/// Shell dialect identified for a shell script artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShellDialect {
    /// POSIX-compatible shell script.
    Posix,
    /// Bash shell script.
    Bash,
    /// Z shell script.
    Zsh,
}

/// Compression applied to a tar archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TarCompression {
    /// Uncompressed tar archive.
    None,
    /// Gzip-compressed tar archive.
    Gzip,
    /// Bzip2-compressed tar archive.
    Bzip2,
    /// Xz-compressed tar archive.
    Xz,
    /// Zstandard-compressed tar archive.
    Zstd,
}

/// Initial artifact class used by scanners and policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    /// Shell script with an identified dialect.
    ShellScript(ShellDialect),
    /// PowerShell script.
    PowerShellScript,
    /// Python script or source distribution entry point.
    PythonScript,
    /// JavaScript or TypeScript source.
    JavaScript,
    /// Windows Portable Executable.
    PeExecutable,
    /// Executable and Linkable Format binary.
    ElfExecutable,
    /// Mach-O executable.
    MachOExecutable,
    /// WebAssembly module.
    WebAssembly,
    /// ZIP or ZIP-derived archive.
    Zip,
    /// Tar archive with optional compression.
    Tar(TarCompression),
    /// Debian package.
    DebianPackage,
    /// RPM package.
    RpmPackage,
    /// npm package tarball.
    NpmTarball,
    /// Python wheel artifact.
    PythonWheel,
    /// Java archive.
    Jar,
    /// Generic text content.
    GenericText,
    /// Generic binary content.
    GenericBinary,
    /// HTML or XML document.
    Html,
    /// JSON document.
    Json,
    /// PDF document.
    PdfDocument,
    /// Office document.
    OfficeDocument,
}

#[cfg(test)]
mod tests {
    use super::{ArtifactKind, ShellDialect, TarCompression};

    #[test]
    fn shell_dialect_round_trips_edge_variant() -> Result<(), Box<dyn std::error::Error>> {
        let value = ShellDialect::Zsh;
        assert_eq!(
            serde_json::from_str::<ShellDialect>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }

    #[test]
    fn tar_compression_round_trips_edge_variant() -> Result<(), Box<dyn std::error::Error>> {
        let value = TarCompression::None;
        assert_eq!(
            serde_json::from_str::<TarCompression>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }
    #[test]
    fn artifact_kind_round_trips_nested_shell_variant() -> Result<(), Box<dyn std::error::Error>> {
        let value = ArtifactKind::ShellScript(ShellDialect::Bash);
        assert_eq!(
            serde_json::from_str::<ArtifactKind>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }

    #[test]
    fn artifact_kind_round_trips_tar_edge_variant() -> Result<(), Box<dyn std::error::Error>> {
        let value = ArtifactKind::Tar(TarCompression::Zstd);
        assert_eq!(
            serde_json::from_str::<ArtifactKind>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }

    #[test]
    fn artifact_kind_round_trips_plain_variant() -> Result<(), Box<dyn std::error::Error>> {
        let value = ArtifactKind::OfficeDocument;
        assert_eq!(
            serde_json::from_str::<ArtifactKind>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }
}
