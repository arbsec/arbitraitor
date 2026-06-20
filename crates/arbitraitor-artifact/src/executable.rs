//! Native executable format analysis.
//!
//! The parser intentionally extracts only bounded metadata needed for artifact
//! classification and host compatibility checks. It is not a validating loader.

use thiserror::Error;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;
const ET_DYN: u16 = 3;
const EM_386: u16 = 3;
const EM_X86_64: u16 = 62;
const EM_ARM: u16 = 40;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;

const PE_MAGIC: &[u8; 2] = b"MZ";
const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";
const PE32_MAGIC: u16 = 0x10b;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

const MACHO_MAGIC_32_BE: u32 = 0xfeed_face;
const MACHO_MAGIC_32_LE: u32 = 0xcefa_edfe;
const MACHO_MAGIC_64_BE: u32 = 0xfeed_facf;
const MACHO_MAGIC_64_LE: u32 = 0xcffa_edfe;
const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_ARM: u32 = 12;
const CPU_ARCH_ABI64: u32 = 0x0100_0000;
const CPU_TYPE_X86_64: u32 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
const CPU_TYPE_ARM64: u32 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_LOAD_DYLIB: u32 = 0x0c;
const LC_LOAD_WEAK_DYLIB: u32 = 0x18;
const LC_REEXPORT_DYLIB: u32 = 0x1f;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x23;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;

/// Metadata extracted from a native executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableInfo {
    /// Container executable format.
    pub format: ExecutableFormat,
    /// Target CPU architecture.
    pub architecture: Architecture,
    /// Executable bitness.
    pub bits: Bitness,
    /// Whether the executable uses loader-managed dynamic linking.
    pub linking: Linking,
    /// Dynamic loader or interpreter path, when declared by the format.
    pub interpreter: Option<String>,
    /// Declared library/runtime dependencies found in bounded metadata.
    pub dependencies: Vec<String>,
    /// Whether the executable carries a platform signature directory/command.
    pub signed: bool,
}

/// Native executable container format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutableFormat {
    /// ELF executable.
    Elf,
    /// Windows Portable Executable.
    Pe,
    /// Mach-O executable.
    MachO,
}

/// CPU architecture identified from executable headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Architecture {
    /// x86-64 / AMD64.
    X86_64,
    /// `AArch64` / ARM64.
    Aarch64,
    /// 32-bit ARM.
    Arm,
    /// 32-bit x86.
    X86,
    /// Another recognized-but-not-modeled architecture.
    Other,
}

/// Executable pointer width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bitness {
    /// 32-bit executable.
    Bits32,
    /// 64-bit executable.
    Bits64,
}

/// Linking mode inferred from loader metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Linking {
    /// No dynamic loader metadata was found.
    Static,
    /// Dynamic loader/import metadata was found.
    Dynamic,
}

/// Executable analysis failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AnalyzeError {
    /// Bytes do not start with a supported native executable magic value.
    #[error("unsupported or unrecognized executable format")]
    UnsupportedFormat,
    /// Header fields were truncated, inconsistent, or impossible to address safely.
    #[error("malformed {format} executable: {reason}")]
    Malformed {
        /// Format whose parser rejected the bytes.
        format: &'static str,
        /// Safe parser diagnostic.
        reason: &'static str,
    },
}

/// Analyzes ELF, PE, or Mach-O executable bytes.
///
/// # Errors
///
/// Returns [`AnalyzeError::UnsupportedFormat`] when the magic bytes do not match
/// a supported native executable format, or [`AnalyzeError::Malformed`] when
/// mandatory header data is absent or internally inconsistent.
pub fn analyze_executable(data: &[u8]) -> Result<ExecutableInfo, AnalyzeError> {
    if data.starts_with(ELF_MAGIC) {
        return analyze_elf(data);
    }
    if data.starts_with(PE_MAGIC) {
        return analyze_pe(data);
    }
    if macho_kind(data).is_some() {
        return analyze_macho(data);
    }
    Err(AnalyzeError::UnsupportedFormat)
}

/// Returns whether an executable matches the current host OS and architecture.
#[must_use]
pub fn is_compatible(info: &ExecutableInfo) -> bool {
    let host_arch = std::env::consts::ARCH;
    let host_os = std::env::consts::OS;
    matches!(
        (info.format, info.architecture, host_os, host_arch),
        (
            ExecutableFormat::Elf,
            Architecture::X86_64,
            "linux",
            "x86_64"
        ) | (
            ExecutableFormat::Elf,
            Architecture::Aarch64,
            "linux",
            "aarch64"
        ) | (ExecutableFormat::Elf, Architecture::Arm, "linux", "arm")
            | (ExecutableFormat::Elf, Architecture::X86, "linux", "x86")
            | (
                ExecutableFormat::Pe,
                Architecture::X86_64,
                "windows",
                "x86_64"
            )
            | (
                ExecutableFormat::Pe,
                Architecture::Aarch64,
                "windows",
                "aarch64"
            )
            | (ExecutableFormat::Pe, Architecture::Arm, "windows", "arm")
            | (ExecutableFormat::Pe, Architecture::X86, "windows", "x86")
            | (
                ExecutableFormat::MachO,
                Architecture::X86_64,
                "macos",
                "x86_64"
            )
            | (
                ExecutableFormat::MachO,
                Architecture::Aarch64,
                "macos",
                "aarch64"
            )
            | (ExecutableFormat::MachO, Architecture::Arm, "macos", "arm")
            | (ExecutableFormat::MachO, Architecture::X86, "macos", "x86")
    )
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

#[derive(Clone, Copy)]
struct ElfHeader {
    endian: Endian,
    bits: Bitness,
    ty: u16,
    machine: u16,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
}

#[derive(Clone, Copy)]
struct ProgramHeader {
    ty: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
}

fn analyze_elf(data: &[u8]) -> Result<ExecutableInfo, AnalyzeError> {
    let header = elf_header(data)?;
    let architecture = elf_architecture(header.machine);
    let program_headers = elf_program_headers(data, header)?;
    let interpreter = elf_interpreter(data, &program_headers)?;
    let dynamic = program_headers.iter().any(|header| header.ty == PT_DYNAMIC);
    let dependencies = elf_dependencies(data, header.endian, &program_headers)?;

    Ok(ExecutableInfo {
        format: ExecutableFormat::Elf,
        architecture,
        bits: header.bits,
        linking: if interpreter.is_some() || dynamic || header.ty == ET_DYN {
            Linking::Dynamic
        } else {
            Linking::Static
        },
        interpreter,
        dependencies,
        signed: false,
    })
}

fn elf_header(data: &[u8]) -> Result<ElfHeader, AnalyzeError> {
    let ident = data
        .get(..16)
        .ok_or_else(|| malformed("ELF", "truncated ELF identification"))?;
    let bits = match ident[4] {
        ELFCLASS32 => Bitness::Bits32,
        ELFCLASS64 => Bitness::Bits64,
        _ => return Err(malformed("ELF", "unsupported ELF class")),
    };
    let endian = match ident[5] {
        ELFDATA2LSB => Endian::Little,
        ELFDATA2MSB => Endian::Big,
        _ => return Err(malformed("ELF", "unsupported ELF endian marker")),
    };
    let min_header = match bits {
        Bitness::Bits32 => 52,
        Bitness::Bits64 => 64,
    };
    require_bytes_len(data, min_header, "ELF")?;
    Ok(match bits {
        Bitness::Bits32 => ElfHeader {
            endian,
            bits,
            ty: read_u16(data, 16, endian, "ELF")?,
            machine: read_u16(data, 18, endian, "ELF")?,
            phoff: u64::from(read_u32(data, 28, endian, "ELF")?),
            phentsize: read_u16(data, 42, endian, "ELF")?,
            phnum: read_u16(data, 44, endian, "ELF")?,
        },
        Bitness::Bits64 => ElfHeader {
            endian,
            bits,
            ty: read_u16(data, 16, endian, "ELF")?,
            machine: read_u16(data, 18, endian, "ELF")?,
            phoff: read_u64(data, 32, endian, "ELF")?,
            phentsize: read_u16(data, 54, endian, "ELF")?,
            phnum: read_u16(data, 56, endian, "ELF")?,
        },
    })
}

fn elf_program_headers(data: &[u8], header: ElfHeader) -> Result<Vec<ProgramHeader>, AnalyzeError> {
    if header.phnum == 0 {
        return Ok(Vec::new());
    }
    let minimum = match header.bits {
        Bitness::Bits32 => 32,
        Bitness::Bits64 => 56,
    };
    if usize::from(header.phentsize) < minimum {
        return Err(malformed("ELF", "program header entry too small"));
    }
    let mut headers = Vec::with_capacity(usize::from(header.phnum));
    for index in 0..header.phnum {
        let offset =
            checked_table_offset(header.phoff, header.phentsize, index, data.len(), "ELF")?;
        headers.push(match header.bits {
            Bitness::Bits32 => ProgramHeader {
                ty: read_u32(data, offset, header.endian, "ELF")?,
                offset: u64::from(read_u32(data, offset + 4, header.endian, "ELF")?),
                vaddr: u64::from(read_u32(data, offset + 8, header.endian, "ELF")?),
                filesz: u64::from(read_u32(data, offset + 16, header.endian, "ELF")?),
            },
            Bitness::Bits64 => ProgramHeader {
                ty: read_u32(data, offset, header.endian, "ELF")?,
                offset: read_u64(data, offset + 8, header.endian, "ELF")?,
                vaddr: read_u64(data, offset + 16, header.endian, "ELF")?,
                filesz: read_u64(data, offset + 32, header.endian, "ELF")?,
            },
        });
    }
    Ok(headers)
}

fn elf_interpreter(data: &[u8], headers: &[ProgramHeader]) -> Result<Option<String>, AnalyzeError> {
    let Some(header) = headers.iter().find(|header| header.ty == PT_INTERP) else {
        return Ok(None);
    };
    let bytes = read_range(data, header.offset, header.filesz, "ELF")?;
    Ok(trim_nul_utf8(bytes).map(ToOwned::to_owned))
}

fn elf_dependencies(
    data: &[u8],
    endian: Endian,
    headers: &[ProgramHeader],
) -> Result<Vec<String>, AnalyzeError> {
    let Some(dynamic) = headers.iter().find(|header| header.ty == PT_DYNAMIC) else {
        return Ok(Vec::new());
    };
    let dynamic_data = read_range(data, dynamic.offset, dynamic.filesz, "ELF")?;
    let entry_size = if dynamic_data.len() % 16 == 0 { 16 } else { 8 };
    let mut needed = Vec::new();
    let mut strtab = None;
    let mut strsz = None;
    for entry in dynamic_data.chunks_exact(entry_size) {
        let tag = if entry_size == 16 {
            read_u64(entry, 0, endian, "ELF")?
        } else {
            u64::from(read_u32(entry, 0, endian, "ELF")?)
        };
        let value = if entry_size == 16 {
            read_u64(entry, 8, endian, "ELF")?
        } else {
            u64::from(read_u32(entry, 4, endian, "ELF")?)
        };
        match tag {
            DT_NEEDED => needed.push(value),
            DT_STRTAB => strtab = Some(value),
            DT_STRSZ => strsz = Some(value),
            0 => break,
            _ => {}
        }
    }
    let Some(strtab_addr) = strtab else {
        return Ok(Vec::new());
    };
    let Some(strtab_size) = strsz else {
        return Ok(Vec::new());
    };
    let Some(strtab_offset) = virtual_to_file_offset(headers, strtab_addr) else {
        return Ok(Vec::new());
    };
    let strings = read_range(data, strtab_offset, strtab_size, "ELF")?;
    Ok(needed
        .into_iter()
        .filter_map(|offset| string_at(strings, offset))
        .map(ToOwned::to_owned)
        .collect())
}

fn virtual_to_file_offset(headers: &[ProgramHeader], address: u64) -> Option<u64> {
    headers
        .iter()
        .filter(|header| header.ty == PT_LOAD)
        .find_map(|header| {
            let end = header.vaddr.checked_add(header.filesz)?;
            if (header.vaddr..end).contains(&address) {
                Some(header.offset + (address - header.vaddr))
            } else {
                None
            }
        })
}

fn analyze_pe(data: &[u8]) -> Result<ExecutableInfo, AnalyzeError> {
    require_bytes_len(data, 64, "PE")?;
    let pe_offset = usize::try_from(read_u32(data, 0x3c, Endian::Little, "PE")?)
        .map_err(|_| malformed("PE", "PE header offset overflows address space"))?;
    if data.get(pe_offset..pe_offset + 4) != Some(PE_SIGNATURE) {
        return Err(malformed("PE", "missing PE signature"));
    }
    let coff_offset = pe_offset + 4;
    require_bytes_len(data, coff_offset + 20, "PE")?;
    let machine = read_u16(data, coff_offset, Endian::Little, "PE")?;
    let optional_size = usize::from(read_u16(data, coff_offset + 16, Endian::Little, "PE")?);
    let optional_offset = coff_offset + 20;
    require_bytes_len(data, optional_offset + optional_size, "PE")?;
    let optional_magic = read_u16(data, optional_offset, Endian::Little, "PE")?;
    let (bits, data_directory_offset) = match optional_magic {
        PE32_MAGIC => (Bitness::Bits32, optional_offset + 96),
        PE32_PLUS_MAGIC => (Bitness::Bits64, optional_offset + 112),
        _ => return Err(malformed("PE", "unknown optional header magic")),
    };
    let security = pe_data_directory(data, data_directory_offset, IMAGE_DIRECTORY_ENTRY_SECURITY)?;
    let clr = pe_data_directory(
        data,
        data_directory_offset,
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
    )?;
    let signed = pe_has_pkcs7_certificate(data, security);
    let dependencies = clr
        .filter(|(_, size)| *size > 0)
        .map_or_else(Vec::new, |_| vec!["clr".to_owned()]);

    Ok(ExecutableInfo {
        format: ExecutableFormat::Pe,
        architecture: pe_architecture(machine),
        bits,
        linking: Linking::Dynamic,
        interpreter: None,
        dependencies,
        signed,
    })
}

fn pe_data_directory(
    data: &[u8],
    data_directory_offset: usize,
    index: usize,
) -> Result<Option<(u32, u32)>, AnalyzeError> {
    let offset = data_directory_offset
        .checked_add(
            index
                .checked_mul(8)
                .ok_or_else(|| malformed("PE", "data directory index overflows address space"))?,
        )
        .ok_or_else(|| malformed("PE", "data directory offset overflows address space"))?;
    if offset + 8 > data.len() {
        return Ok(None);
    }
    let address = read_u32(data, offset, Endian::Little, "PE")?;
    let size = read_u32(data, offset + 4, Endian::Little, "PE")?;
    Ok((address != 0 && size != 0).then_some((address, size)))
}

fn pe_has_pkcs7_certificate(data: &[u8], directory: Option<(u32, u32)>) -> bool {
    let Some((offset, size)) = directory else {
        return false;
    };
    let Ok(certificate) = read_range(data, u64::from(offset), u64::from(size), "PE") else {
        return false;
    };
    certificate.len() >= 8
        && u32::try_from(certificate.len()).is_ok_and(|actual| actual >= size)
        && read_u16(certificate, 6, Endian::Little, "PE") == Ok(WIN_CERT_TYPE_PKCS_SIGNED_DATA)
}

#[derive(Clone, Copy)]
struct MachOKind {
    endian: Endian,
    bits: Bitness,
}

fn analyze_macho(data: &[u8]) -> Result<ExecutableInfo, AnalyzeError> {
    let kind = macho_kind(data).ok_or(AnalyzeError::UnsupportedFormat)?;
    let header_size = match kind.bits {
        Bitness::Bits32 => 28,
        Bitness::Bits64 => 32,
    };
    require_bytes_len(data, header_size, "Mach-O")?;
    let cpu_type = read_u32(data, 4, kind.endian, "Mach-O")?;
    let command_count = read_u32(data, 16, kind.endian, "Mach-O")?;
    let command_size = read_u32(data, 20, kind.endian, "Mach-O")?;
    let commands_end = u64::try_from(header_size)
        .ok()
        .and_then(|offset| offset.checked_add(u64::from(command_size)))
        .ok_or_else(|| malformed("Mach-O", "load commands overflow address space"))?;
    require_bytes_len(
        data,
        usize::try_from(commands_end)
            .map_err(|_| malformed("Mach-O", "load commands exceed address space"))?,
        "Mach-O",
    )?;
    let mut signed = false;
    let mut dependencies = Vec::new();
    let mut command_offset = header_size;
    for _ in 0..command_count {
        require_bytes_len(data, command_offset + 8, "Mach-O")?;
        let command = read_u32(data, command_offset, kind.endian, "Mach-O")?;
        let size = usize::try_from(read_u32(data, command_offset + 4, kind.endian, "Mach-O")?)
            .map_err(|_| malformed("Mach-O", "load command size overflows address space"))?;
        if size < 8 || command_offset + size > data.len() {
            return Err(malformed("Mach-O", "invalid load command size"));
        }
        match command {
            LC_CODE_SIGNATURE => signed = true,
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LOAD_UPWARD_DYLIB
            | LC_LAZY_LOAD_DYLIB => {
                if let Some(name) = macho_dylib_name(data, command_offset, size, kind.endian)? {
                    dependencies.push(name.to_owned());
                }
            }
            _ => {}
        }
        command_offset += size;
    }

    Ok(ExecutableInfo {
        format: ExecutableFormat::MachO,
        architecture: macho_architecture(cpu_type),
        bits: kind.bits,
        linking: if dependencies.is_empty() {
            Linking::Static
        } else {
            Linking::Dynamic
        },
        interpreter: None,
        dependencies,
        signed,
    })
}

fn macho_kind(data: &[u8]) -> Option<MachOKind> {
    let magic = u32::from_be_bytes(data.get(..4)?.try_into().ok()?);
    match magic {
        MACHO_MAGIC_32_BE => Some(MachOKind {
            endian: Endian::Big,
            bits: Bitness::Bits32,
        }),
        MACHO_MAGIC_32_LE => Some(MachOKind {
            endian: Endian::Little,
            bits: Bitness::Bits32,
        }),
        MACHO_MAGIC_64_BE => Some(MachOKind {
            endian: Endian::Big,
            bits: Bitness::Bits64,
        }),
        MACHO_MAGIC_64_LE => Some(MachOKind {
            endian: Endian::Little,
            bits: Bitness::Bits64,
        }),
        _ => None,
    }
}

fn macho_dylib_name(
    data: &[u8],
    command_offset: usize,
    command_size: usize,
    endian: Endian,
) -> Result<Option<&str>, AnalyzeError> {
    if command_size < 24 {
        return Ok(None);
    }
    let name_offset = usize::try_from(read_u32(data, command_offset + 8, endian, "Mach-O")?)
        .map_err(|_| malformed("Mach-O", "dylib name offset overflows address space"))?;
    if name_offset >= command_size {
        return Ok(None);
    }
    Ok(trim_nul_utf8(
        &data[command_offset + name_offset..command_offset + command_size],
    ))
}

fn elf_architecture(machine: u16) -> Architecture {
    match machine {
        EM_X86_64 => Architecture::X86_64,
        EM_AARCH64 => Architecture::Aarch64,
        EM_ARM => Architecture::Arm,
        EM_386 => Architecture::X86,
        _ => Architecture::Other,
    }
}

fn pe_architecture(machine: u16) -> Architecture {
    match machine {
        IMAGE_FILE_MACHINE_AMD64 => Architecture::X86_64,
        IMAGE_FILE_MACHINE_ARM64 => Architecture::Aarch64,
        IMAGE_FILE_MACHINE_ARMNT => Architecture::Arm,
        IMAGE_FILE_MACHINE_I386 => Architecture::X86,
        _ => Architecture::Other,
    }
}

fn macho_architecture(cpu_type: u32) -> Architecture {
    match cpu_type {
        CPU_TYPE_X86_64 => Architecture::X86_64,
        CPU_TYPE_ARM64 => Architecture::Aarch64,
        CPU_TYPE_ARM => Architecture::Arm,
        CPU_TYPE_X86 => Architecture::X86,
        _ => Architecture::Other,
    }
}

fn read_u16(
    data: &[u8],
    offset: usize,
    endian: Endian,
    format: &'static str,
) -> Result<u16, AnalyzeError> {
    let bytes: [u8; 2] = data
        .get(offset..offset + 2)
        .ok_or_else(|| malformed(format, "truncated integer field"))?
        .try_into()
        .map_err(|_| malformed(format, "invalid integer field"))?;
    Ok(match endian {
        Endian::Little => u16::from_le_bytes(bytes),
        Endian::Big => u16::from_be_bytes(bytes),
    })
}

fn read_u32(
    data: &[u8],
    offset: usize,
    endian: Endian,
    format: &'static str,
) -> Result<u32, AnalyzeError> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or_else(|| malformed(format, "truncated integer field"))?
        .try_into()
        .map_err(|_| malformed(format, "invalid integer field"))?;
    Ok(match endian {
        Endian::Little => u32::from_le_bytes(bytes),
        Endian::Big => u32::from_be_bytes(bytes),
    })
}

fn read_u64(
    data: &[u8],
    offset: usize,
    endian: Endian,
    format: &'static str,
) -> Result<u64, AnalyzeError> {
    let bytes: [u8; 8] = data
        .get(offset..offset + 8)
        .ok_or_else(|| malformed(format, "truncated integer field"))?
        .try_into()
        .map_err(|_| malformed(format, "invalid integer field"))?;
    Ok(match endian {
        Endian::Little => u64::from_le_bytes(bytes),
        Endian::Big => u64::from_be_bytes(bytes),
    })
}

fn checked_table_offset(
    base: u64,
    entry_size: u16,
    index: u16,
    data_len: usize,
    format: &'static str,
) -> Result<usize, AnalyzeError> {
    let offset = base
        .checked_add(u64::from(entry_size) * u64::from(index))
        .ok_or_else(|| malformed(format, "table offset overflows address space"))?;
    let offset = usize::try_from(offset)
        .map_err(|_| malformed(format, "table offset exceeds address space"))?;
    require_total_len(data_len, offset + usize::from(entry_size), format)?;
    Ok(offset)
}

fn read_range<'data>(
    data: &'data [u8],
    offset: u64,
    size: u64,
    format: &'static str,
) -> Result<&'data [u8], AnalyzeError> {
    let start = usize::try_from(offset)
        .map_err(|_| malformed(format, "range offset exceeds address space"))?;
    let size =
        usize::try_from(size).map_err(|_| malformed(format, "range size exceeds address space"))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| malformed(format, "range end overflows address space"))?;
    data.get(start..end)
        .ok_or_else(|| malformed(format, "range exceeds file length"))
}

fn require_bytes_len(
    data: &[u8],
    required: usize,
    format: &'static str,
) -> Result<(), AnalyzeError> {
    require_total_len(data.len(), required, format)
}

fn require_total_len(
    actual: usize,
    required: usize,
    format: &'static str,
) -> Result<(), AnalyzeError> {
    if actual < required {
        return Err(malformed(format, "truncated header"));
    }
    Ok(())
}

fn trim_nul_utf8(data: &[u8]) -> Option<&str> {
    let end = data
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(data.len());
    core::str::from_utf8(&data[..end])
        .ok()
        .filter(|value| !value.is_empty())
}

fn string_at(data: &[u8], offset: u64) -> Option<&str> {
    let offset = usize::try_from(offset).ok()?;
    trim_nul_utf8(data.get(offset..)?)
}

fn malformed(format: &'static str, reason: &'static str) -> AnalyzeError {
    AnalyzeError::Malformed { format, reason }
}

#[cfg(test)]
mod tests {
    use super::{
        AnalyzeError, Architecture, Bitness, ExecutableFormat, Linking, analyze_executable,
    };

    #[test]
    fn analyzes_elf_x86_64_dynamic_interpreter() -> Result<(), Box<dyn std::error::Error>> {
        let info = analyze_executable(&elf_x86_64_dynamic())?;

        assert_eq!(info.format, ExecutableFormat::Elf);
        assert_eq!(info.architecture, Architecture::X86_64);
        assert_eq!(info.bits, Bitness::Bits64);
        assert_eq!(info.linking, Linking::Dynamic);
        assert_eq!(
            info.interpreter.as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
        assert!(!info.signed);
        Ok(())
    }

    #[test]
    fn analyzes_pe_amd64() -> Result<(), Box<dyn std::error::Error>> {
        let info = analyze_executable(&pe_amd64())?;

        assert_eq!(info.format, ExecutableFormat::Pe);
        assert_eq!(info.architecture, Architecture::X86_64);
        assert_eq!(info.bits, Bitness::Bits64);
        assert_eq!(info.linking, Linking::Dynamic);
        assert!(!info.signed);
        Ok(())
    }

    #[test]
    fn analyzes_macho_arm64_signature_command() -> Result<(), Box<dyn std::error::Error>> {
        let info = analyze_executable(&macho_arm64_signed())?;

        assert_eq!(info.format, ExecutableFormat::MachO);
        assert_eq!(info.architecture, Architecture::Aarch64);
        assert_eq!(info.bits, Bitness::Bits64);
        assert!(info.signed);
        Ok(())
    }

    #[test]
    fn rejects_non_executable_bytes() {
        assert_eq!(
            analyze_executable(b"not an executable"),
            Err(AnalyzeError::UnsupportedFormat)
        );
    }

    fn elf_x86_64_dynamic() -> Vec<u8> {
        let interpreter = b"/lib64/ld-linux-x86-64.so.2\0";
        let mut data = vec![0_u8; 256];
        data[..4].copy_from_slice(b"\x7fELF");
        data[4] = 2;
        data[5] = 1;
        put_u16(&mut data, 16, 3);
        put_u16(&mut data, 18, 62);
        put_u64(&mut data, 32, 64);
        put_u16(&mut data, 54, 56);
        put_u16(&mut data, 56, 2);
        put_u32(&mut data, 64, 3);
        put_u64(&mut data, 72, 176);
        put_u64(&mut data, 80, 0x0040_0000);
        put_u64(&mut data, 96, u64::try_from(interpreter.len()).unwrap_or(0));
        put_u32(&mut data, 120, 2);
        put_u64(&mut data, 128, 208);
        put_u64(&mut data, 136, 0x0040_1000);
        put_u64(&mut data, 152, 16);
        data[176..176 + interpreter.len()].copy_from_slice(interpreter);
        data
    }

    fn pe_amd64() -> Vec<u8> {
        let mut data = vec![0_u8; 512];
        data[..2].copy_from_slice(b"MZ");
        put_u32(&mut data, 0x3c, 0x80);
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        put_u16(&mut data, 0x84, 0x8664);
        put_u16(&mut data, 0x94, 240);
        put_u16(&mut data, 0x98, 0x20b);
        data
    }

    fn macho_arm64_signed() -> Vec<u8> {
        let mut data = vec![0_u8; 48];
        data[..4].copy_from_slice(&0xcffa_edfe_u32.to_be_bytes());
        put_u32(&mut data, 4, 0x0100_000c);
        put_u32(&mut data, 16, 1);
        put_u32(&mut data, 20, 16);
        put_u32(&mut data, 32, 0x1d);
        put_u32(&mut data, 36, 16);
        data
    }

    fn put_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
