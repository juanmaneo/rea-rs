//! The ELF section directory and admitted load segments of one in-memory
//! image.
//!
//! Every structural read passes the same range and 16 MiB structural budget
//! checks upstream applies to positional reads, and each check runs in
//! upstream order so the first failure matches.
//!
//! Upstream reference: `readElfSectionDirectory` in
//! `upstream:src/native/metadata/NativeSectionDirectory.ts`, `readElfImage`
//! in `upstream:src/native/metadata/ElfImage.ts`, and
//! `readElfTableDeclarations` in `upstream:src/domain/elfDeclaredRanges.ts`.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Range;

use super::header::{
    ElfClass, ElfFixedHeader, Endian, read_elf_fixed_header, read_elf_program_header,
    read_elf_section_header, read_elf_table_declarations, validate_elf_section_table_presence,
};
use super::section_names::{
    SHF_COMPRESSED, SectionNameTable, SectionNameTableFailure, StringTableEntry,
    decode_elf_section_name_table, observe_string_table_entry,
};

/// The structural decoding allowance for headers, tables, and section names.
pub(crate) const STRUCTURE_BYTES: usize = 16 * 1024 * 1024;
const PT_LOAD: u32 = 1;
const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
pub(crate) const SHT_NOBITS: u32 = 8;
const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;
const MAX_SECTION_NAME_BYTES: usize = 65_536;

/// Why the image directory could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ElfImageFailure {
    /// The bytes violate the format.
    Malformed(String),
    /// The 16 MiB structural decoding allowance is exhausted.
    Structure(String),
}

fn malformed(message: impl Into<String>) -> ElfImageFailure {
    ElfImageFailure::Malformed(message.into())
}

fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// `offset..offset + size` when it lies inside `length` bytes.
pub(crate) fn file_range(length: usize, offset: u64, size: u64) -> Option<Range<usize>> {
    let available = as_u64(length);
    if offset > available || size > available - offset {
        return None;
    }
    let start = usize::try_from(offset).ok()?;
    Some(start..start + usize::try_from(size).ok()?)
}

/// One positional structural read.
fn request(bytes: &[u8], offset: u64, size: u128) -> Result<&[u8], ElfImageFailure> {
    let range = u64::try_from(size)
        .ok()
        .and_then(|size| file_range(bytes.len(), offset, size))
        .and_then(|range| bytes.get(range))
        .ok_or_else(|| malformed("Native directory range is truncated or outside the file"))?;
    if range.len() > STRUCTURE_BYTES {
        return Err(ElfImageFailure::Structure(
            "Native directory exceeds the 16777216-byte (16 MiB) structural decoding budget. This release has no runtime override.".to_owned(),
        ));
    }
    Ok(range)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TableKind {
    Program,
    Section,
}

impl TableKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Program => "program header table",
            Self::Section => "section header table",
        }
    }

    const fn minimum_width(self, class: ElfClass) -> u16 {
        match self {
            Self::Program => class.program_header_bytes(),
            Self::Section => class.section_header_bytes(),
        }
    }
}

/// Zero-count tables own no bytes; others need a usable width, must follow
/// the fixed header, and must lie inside the file.
fn table_failure(
    kind: TableKind,
    (offset, count, width): (u64, u64, u16),
    class: ElfClass,
    file_bytes: usize,
) -> Result<(), ElfImageFailure> {
    if count == 0 {
        return Ok(());
    }
    let label = kind.label();
    if width < kind.minimum_width(class) {
        return Err(malformed(format!("invalid ELF {label} entry width")));
    }
    if offset < u64::from(class.header_bytes()) {
        return Err(malformed(format!("ELF {label} overlaps the fixed header")));
    }
    let size = u128::from(count) * u128::from(width);
    let file = u128::from(as_u64(file_bytes));
    if size != 0 && (u128::from(offset) > file || size > file - u128::from(offset)) {
        return Err(malformed(format!(
            "truncated ELF {label}: declared file range {offset}..{} exceeds the {file_bytes}-byte file",
            u128::from(offset) + size
        )));
    }
    Ok(())
}

/// Table declarations after extended numbering and range admission.
struct Tables {
    program_offset: u64,
    program_count: u64,
    program_width: u16,
    section_offset: u64,
    section_count: u64,
    section_width: u16,
    names_index: u32,
}

fn read_tables(
    bytes: &[u8],
    header_bytes: &[u8],
    header: &ElfFixedHeader,
) -> Result<Tables, ElfImageFailure> {
    let (class, endian) = (header.class, header.endian);
    let raw = read_elf_table_declarations(header_bytes, header).map_err(malformed)?;
    validate_elf_section_table_presence(&raw).map_err(malformed)?;
    let mut tables = Tables {
        program_offset: raw.program_offset,
        program_count: u64::from(raw.program_count),
        program_width: raw.program_width,
        section_offset: raw.section_offset,
        section_count: u64::from(raw.section_count),
        section_width: raw.section_width,
        names_index: u32::from(raw.section_names_index),
    };
    if tables.section_offset != 0
        && (tables.section_count == 0
            || tables.names_index == 0xffff
            || tables.program_count == 0xffff)
    {
        table_failure(
            TableKind::Section,
            (tables.section_offset, 1, tables.section_width),
            class,
            bytes.len(),
        )?;
        let first = file_range(
            bytes.len(),
            tables.section_offset,
            u64::from(class.section_header_bytes()),
        )
        .and_then(|range| bytes.get(range))
        .ok_or_else(|| malformed("truncated ELF extended section-zero header"))?;
        let zero = read_elf_section_header(first, class, endian).map_err(malformed)?;
        if zero.section_type != SHT_NULL {
            return Err(malformed(
                "ELF extended numbering requires an inactive SHT_NULL section zero",
            ));
        }
        if tables.section_count == 0 {
            tables.section_count = zero.size;
            if tables.section_count < 0xff00 {
                return Err(malformed("invalid ELF extended section count"));
            }
        }
        if tables.names_index == 0xffff {
            tables.names_index = zero.link;
            if tables.names_index < 0xff00 {
                return Err(malformed("invalid ELF extended section-name index"));
            }
        }
        if tables.program_count == 0xffff {
            tables.program_count = u64::from(zero.info);
            if tables.program_count < 0xffff {
                return Err(malformed("invalid ELF extended program count"));
            }
        }
    }
    table_failure(
        TableKind::Program,
        (
            tables.program_offset,
            tables.program_count,
            tables.program_width,
        ),
        class,
        bytes.len(),
    )?;
    table_failure(
        TableKind::Section,
        (
            tables.section_offset,
            tables.section_count,
            tables.section_width,
        ),
        class,
        bytes.len(),
    )?;
    if tables.section_count != 0 && u64::from(tables.names_index) >= tables.section_count {
        return Err(malformed(
            "ELF section-name index lies outside the declared section table",
        ));
    }
    Ok(tables)
}

/// A retained section: it has a non-empty name or is file-backed read-only
/// data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageSection {
    /// The name's range within [`ElfImage::names`], when the name is known.
    name: Option<Range<usize>>,
    pub(crate) section_type: u32,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    /// `SHF_COMPRESSED` storage.
    pub(crate) compressed: bool,
}

/// The section directory of one ELF image.
#[derive(Debug)]
pub(crate) struct ElfImage<'a> {
    pub(crate) class: ElfClass,
    pub(crate) endian: Endian,
    pub(crate) machine: u16,
    pub(crate) object_type: u16,
    /// The decoded section-name table that section names borrow from.
    names: Cow<'a, [u8]>,
    pub(crate) sections: Vec<ImageSection>,
    /// The first reason some section names are unavailable.
    pub(crate) section_names_limitation: Option<String>,
}

impl ElfImage<'_> {
    /// The section's name bytes, without a Latin-1 projection, when known.
    pub(crate) fn name(&self, section: &ImageSection) -> Option<&[u8]> {
        section
            .name
            .as_ref()
            .and_then(|range| self.names.get(range.clone()))
    }
}

/// A `PT_LOAD` declaration, admitted after the whole directory is read.
struct LoadSegment {
    offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
}

fn admit_load_segment(
    segment: &LoadSegment,
    class: ElfClass,
    file_bytes: usize,
) -> Result<(), ElfImageFailure> {
    let end = u128::from(segment.virtual_address) + u128::from(segment.memory_size);
    if segment.file_size > segment.memory_size || end > 1_u128 << class.bits() {
        return Err(malformed("ELF load segment sizes or addresses are invalid"));
    }
    if segment.file_size != 0 && file_range(file_bytes, segment.offset, segment.file_size).is_none()
    {
        return Err(malformed("ELF load segment range is outside the file"));
    }
    Ok(())
}

/// A section-name lookup, cached by name offset so repeated names are
/// examined and charged once.
#[derive(Clone)]
enum CachedName {
    Known(Range<usize>),
    Truncated,
}

/// Read the section directory and admit `PT_LOAD` segments.
pub(crate) fn read_elf_image(bytes: &[u8]) -> Result<ElfImage<'_>, ElfImageFailure> {
    let prefix = request(bytes, 0, 16)?;
    let header_size = if prefix.get(4) == Some(&1) { 52 } else { 64 };
    let header_bytes = request(bytes, 0, header_size)?;
    let header = read_elf_fixed_header(header_bytes, bytes.len()).map_err(malformed)?;
    let (class, endian) = (header.class, header.endian);
    let tables = read_tables(bytes, header_bytes, &header)?;

    let mut loads = Vec::new();
    if tables.program_count != 0 {
        let width = usize::from(tables.program_width);
        let table = request(
            bytes,
            tables.program_offset,
            u128::from(tables.program_count) * u128::from(tables.program_width),
        )?;
        for record in table.chunks_exact(width) {
            let program = read_elf_program_header(record, class, endian).map_err(malformed)?;
            if program.program_type == PT_LOAD {
                loads.push(LoadSegment {
                    offset: program.offset,
                    virtual_address: program.virtual_address,
                    file_size: program.file_size,
                    memory_size: program.memory_size,
                });
            }
        }
    }

    let mut names: Cow<'_, [u8]> = Cow::Borrowed(&[]);
    let mut names_available = false;
    let mut section_names_limitation = None;
    let mut sections = Vec::new();
    if tables.section_count != 0 {
        let width = usize::from(tables.section_width);
        let table = request(
            bytes,
            tables.section_offset,
            u128::from(tables.section_count) * u128::from(tables.section_width),
        )?;
        if tables.names_index != 0 {
            let at = usize::try_from(tables.names_index)
                .unwrap_or(usize::MAX)
                .saturating_mul(width);
            let record = table.get(at..).unwrap_or_default();
            let names_section =
                read_elf_section_header(record, class, endian).map_err(malformed)?;
            if names_section.section_type != SHT_STRTAB {
                return Err(malformed("ELF section name table is not a string table"));
            }
            let raw = request(bytes, names_section.offset, u128::from(names_section.size))?;
            let allowance = as_u64(STRUCTURE_BYTES - raw.len());
            match decode_elf_section_name_table(
                raw,
                names_section.flags,
                class,
                endian,
                Some(allowance),
            ) {
                Err(SectionNameTableFailure::Malformed(message)) => return Err(malformed(message)),
                Err(SectionNameTableFailure::Limit { required_bytes }) => {
                    return Err(ElfImageFailure::Structure(format!(
                        "Decoded ELF section names require {required_bytes} bytes, above the {allowance}-byte remaining structural budget"
                    )));
                }
                Ok(SectionNameTable::Unsupported { compression_type }) => {
                    section_names_limitation = Some(format!(
                        "ELF section names are unavailable because compression type {compression_type} is unsupported"
                    ));
                }
                Ok(SectionNameTable::Available { bytes, .. }) => {
                    names = bytes;
                    names_available = true;
                }
            }
        } else if tables.section_count > 1 {
            section_names_limitation = Some(
                "ELF section names are unavailable because no section-name string table is declared"
                    .to_owned(),
            );
        }
        let mut cache: HashMap<u32, CachedName> = HashMap::new();
        let mut name_bytes = 0_usize;
        for record in table.chunks_exact(width) {
            let section = read_elf_section_header(record, class, endian).map_err(malformed)?;
            let mut name = None;
            if names_available {
                let cached = match cache.get(&section.name_offset) {
                    Some(cached) => Some(cached.clone()),
                    None => {
                        let start = usize::try_from(section.name_offset).unwrap_or(usize::MAX);
                        let observed =
                            observe_string_table_entry(&names, start, MAX_SECTION_NAME_BYTES);
                        name_bytes = name_bytes.saturating_add(observed.examined_bytes());
                        if name_bytes > STRUCTURE_BYTES {
                            return Err(ElfImageFailure::Structure(
                                "Decoded ELF section names exceed the 16 MiB structural budget"
                                    .to_owned(),
                            ));
                        }
                        let decoded = match observed {
                            StringTableEntry::Outside => {
                                section_names_limitation.get_or_insert_with(|| {
                                    "ELF section names are incomplete because a name offset is outside its string table".to_owned()
                                });
                                None
                            }
                            StringTableEntry::Terminated(text) => {
                                Some(CachedName::Known(start..start + text.len()))
                            }
                            StringTableEntry::Truncated { .. } => {
                                section_names_limitation.get_or_insert_with(|| {
                                    "ELF section names are unavailable because a name is not NUL-terminated".to_owned()
                                });
                                Some(CachedName::Truncated)
                            }
                        };
                        if let Some(decoded) = &decoded {
                            cache.insert(section.name_offset, decoded.clone());
                        }
                        decoded
                    }
                };
                if let Some(CachedName::Known(range)) = cached {
                    name = Some(range);
                }
            }
            let range = file_range(bytes.len(), section.offset, section.size);
            let file_backed =
                section.section_type != SHT_NOBITS && section.size > 0 && range.is_some();
            let compressed = section.flags & SHF_COMPRESSED != 0;
            let read_only = section.section_type == SHT_PROGBITS
                && file_backed
                && !compressed
                && section.flags & SHF_WRITE == 0
                && section.flags & SHF_EXECINSTR == 0
                && section.flags & SHF_ALLOC != 0;
            if name.as_ref().is_none_or(Range::is_empty) && !read_only {
                continue;
            }
            sections.push(ImageSection {
                name,
                section_type: section.section_type,
                offset: section.offset,
                size: section.size,
                compressed,
            });
        }
    }

    for segment in &loads {
        admit_load_segment(segment, class, bytes.len())?;
    }
    Ok(ElfImage {
        class,
        endian,
        machine: header.machine,
        object_type: header.object_type,
        names,
        sections,
        section_names_limitation,
    })
}
