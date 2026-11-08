//! Fixed ELF header, table declarations, and program/section header records.
//!
//! Each reader decodes fixed words only; consumers own range admission,
//! extended numbering, and names.
//!
//! Upstream reference: `upstream:src/domain/elfFixedHeader.ts`,
//! `upstream:src/domain/elfRawTableDeclarations.ts`,
//! `upstream:src/domain/elfProgramHeader.ts`, and
//! `upstream:src/domain/elfSectionHeader.ts`.

/// ELF file class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ElfClass {
    Elf32,
    Elf64,
}

impl ElfClass {
    pub(crate) const fn is_wide(self) -> bool {
        matches!(self, Self::Elf64)
    }

    pub(crate) const fn bits(self) -> u32 {
        match self {
            Self::Elf32 => 32,
            Self::Elf64 => 64,
        }
    }

    pub(crate) const fn header_bytes(self) -> u16 {
        match self {
            Self::Elf32 => 52,
            Self::Elf64 => 64,
        }
    }

    pub(crate) const fn program_header_bytes(self) -> u16 {
        match self {
            Self::Elf32 => 32,
            Self::Elf64 => 56,
        }
    }

    pub(crate) const fn section_header_bytes(self) -> u16 {
        match self {
            Self::Elf32 => 40,
            Self::Elf64 => 64,
        }
    }
}

/// Byte-order aware fixed-width reads that never panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Endian {
    pub(crate) little: bool,
}

impl Endian {
    pub(crate) fn u16(self, bytes: &[u8], at: usize) -> Option<u16> {
        let word = *bytes.get(at..)?.first_chunk::<2>()?;
        Some(if self.little {
            u16::from_le_bytes(word)
        } else {
            u16::from_be_bytes(word)
        })
    }

    pub(crate) fn u32(self, bytes: &[u8], at: usize) -> Option<u32> {
        let word = *bytes.get(at..)?.first_chunk::<4>()?;
        Some(if self.little {
            u32::from_le_bytes(word)
        } else {
            u32::from_be_bytes(word)
        })
    }

    pub(crate) fn i32(self, bytes: &[u8], at: usize) -> Option<i32> {
        self.u32(bytes, at)
            .map(|word| i32::from_ne_bytes(word.to_ne_bytes()))
    }

    pub(crate) fn u64(self, bytes: &[u8], at: usize) -> Option<u64> {
        let word = *bytes.get(at..)?.first_chunk::<8>()?;
        Some(if self.little {
            u64::from_le_bytes(word)
        } else {
            u64::from_be_bytes(word)
        })
    }

    /// A class-sized word widened to `u64`.
    pub(crate) fn word(self, class: ElfClass, bytes: &[u8], at: usize) -> Option<u64> {
        match class {
            ElfClass::Elf32 => self.u32(bytes, at).map(u64::from),
            ElfClass::Elf64 => self.u64(bytes, at),
        }
    }
}

/// Admitted fixed-header facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ElfFixedHeader {
    pub(crate) class: ElfClass,
    pub(crate) endian: Endian,
    pub(crate) header_size: u16,
    pub(crate) machine: u16,
    pub(crate) object_type: u16,
}

const EM_CUDA: u16 = 190;
const ELFOSABI_CUDA: u8 = 0x33;

/// Decode common ELF framing and admit the version and declared header size.
///
/// `bytes` may be a bounded prefix of a `total_bytes` file; both must hold a
/// complete fixed header, and the declared header size is admitted against
/// the whole file.
pub(crate) fn read_elf_fixed_header(
    bytes: &[u8],
    total_bytes: usize,
) -> Result<ElfFixedHeader, String> {
    if bytes.len() >= 4 && !bytes.starts_with(b"\x7fELF") {
        return Err("not an ELF image".to_owned());
    }
    let Some(ident) = bytes.first_chunk::<16>() else {
        return Err("ELF identification is truncated".to_owned());
    };
    let class = match ident[4] {
        1 => ElfClass::Elf32,
        2 => ElfClass::Elf64,
        _ => return Err("unsupported ELF class".to_owned()),
    };
    let endian = match ident[5] {
        1 => Endian { little: true },
        2 => Endian { little: false },
        _ => return Err("unsupported ELF endianness".to_owned()),
    };
    if ident[6] != 1 {
        return Err("unsupported ELF identification version".to_owned());
    }
    let os_abi = ident[7];
    let minimum = class.header_bytes();
    let truncated = || {
        format!(
            "truncated ELF header: an ELF{} header needs {minimum} bytes; the file has {}",
            class.bits(),
            total_bytes
        )
    };
    if total_bytes < bytes.len()
        || total_bytes < usize::from(minimum)
        || bytes.len() < usize::from(minimum)
    {
        return Err(truncated());
    }
    let read16 = |at| endian.u16(bytes, at).ok_or_else(truncated);
    let object_type = read16(16)?;
    let machine = read16(18)?;
    let version = endian.u32(bytes, 20).ok_or_else(truncated)?;
    let header_size = read16(if class.is_wide() { 52 } else { 40 })?;
    // NVIDIA CUBIN uses ELFOSABI_CUDA and a vendor ABI version in e_version.
    if version != 1 && !(machine == EM_CUDA && os_abi == ELFOSABI_CUDA) {
        return Err("unsupported ELF header version".to_owned());
    }
    if header_size < minimum || usize::from(header_size) > total_bytes {
        return Err("invalid ELF header size".to_owned());
    }
    Ok(ElfFixedHeader {
        class,
        endian,
        header_size,
        machine,
        object_type,
    })
}

/// Fixed-header table words before extended numbering or range admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ElfTableDeclarations {
    pub(crate) program_offset: u64,
    pub(crate) program_width: u16,
    pub(crate) program_count: u16,
    pub(crate) section_offset: u64,
    pub(crate) section_width: u16,
    pub(crate) section_count: u16,
    pub(crate) section_names_index: u16,
}

pub(crate) fn read_elf_table_declarations(
    bytes: &[u8],
    header: &ElfFixedHeader,
) -> Result<ElfTableDeclarations, String> {
    let (class, endian) = (header.class, header.endian);
    let wide = class.is_wide();
    let read = || -> Option<ElfTableDeclarations> {
        Some(ElfTableDeclarations {
            program_offset: endian.word(class, bytes, if wide { 32 } else { 28 })?,
            program_width: endian.u16(bytes, if wide { 54 } else { 42 })?,
            program_count: endian.u16(bytes, if wide { 56 } else { 44 })?,
            section_offset: endian.word(class, bytes, if wide { 40 } else { 32 })?,
            section_width: endian.u16(bytes, if wide { 58 } else { 46 })?,
            section_count: endian.u16(bytes, if wide { 60 } else { 48 })?,
            section_names_index: endian.u16(bytes, if wide { 62 } else { 50 })?,
        })
    };
    read().ok_or_else(|| "ELF table declarations are truncated".to_owned())
}

/// A name index or extended count cannot refer to an absent section table.
///
/// Upstream reference: `validateElfSectionTablePresence` in
/// `upstream:src/domain/elfDeclaredRanges.ts`.
pub(crate) fn validate_elf_section_table_presence(
    tables: &ElfTableDeclarations,
) -> Result<(), String> {
    if tables.section_offset == 0
        && (tables.section_count != 0
            || tables.section_names_index != 0
            || tables.program_count == 0xffff)
    {
        return Err("ELF section table is missing".to_owned());
    }
    Ok(())
}

/// Fixed program-header words this crate consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ElfProgramHeader {
    pub(crate) program_type: u32,
    pub(crate) offset: u64,
    pub(crate) virtual_address: u64,
    pub(crate) file_size: u64,
    pub(crate) memory_size: u64,
    pub(crate) alignment: u64,
}

pub(crate) fn read_elf_program_header(
    bytes: &[u8],
    class: ElfClass,
    endian: Endian,
) -> Result<ElfProgramHeader, String> {
    let wide = class.is_wide();
    let read = || -> Option<ElfProgramHeader> {
        if bytes.len() < usize::from(class.program_header_bytes()) {
            return None;
        }
        Some(ElfProgramHeader {
            program_type: endian.u32(bytes, 0)?,
            offset: endian.word(class, bytes, if wide { 8 } else { 4 })?,
            virtual_address: endian.word(class, bytes, if wide { 16 } else { 8 })?,
            file_size: endian.word(class, bytes, if wide { 32 } else { 16 })?,
            memory_size: endian.word(class, bytes, if wide { 40 } else { 20 })?,
            alignment: endian.word(class, bytes, if wide { 48 } else { 28 })?,
        })
    };
    read().ok_or_else(|| "ELF program header is truncated".to_owned())
}

/// Fixed section-header words this crate consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ElfSectionHeader {
    pub(crate) name_offset: u32,
    pub(crate) section_type: u32,
    pub(crate) flags: u64,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) link: u32,
    pub(crate) info: u32,
    pub(crate) alignment: u64,
}

pub(crate) fn read_elf_section_header(
    bytes: &[u8],
    class: ElfClass,
    endian: Endian,
) -> Result<ElfSectionHeader, String> {
    let wide = class.is_wide();
    let read = || -> Option<ElfSectionHeader> {
        if bytes.len() < usize::from(class.section_header_bytes()) {
            return None;
        }
        Some(ElfSectionHeader {
            name_offset: endian.u32(bytes, 0)?,
            section_type: endian.u32(bytes, 4)?,
            flags: endian.word(class, bytes, 8)?,
            offset: endian.word(class, bytes, if wide { 24 } else { 16 })?,
            size: endian.word(class, bytes, if wide { 32 } else { 20 })?,
            link: endian.u32(bytes, if wide { 40 } else { 24 })?,
            info: endian.u32(bytes, if wide { 44 } else { 28 })?,
            alignment: endian.word(class, bytes, if wide { 48 } else { 32 })?,
        })
    };
    read().ok_or_else(|| "ELF section header is truncated".to_owned())
}
