//! `PT_NOTE` and `SHT_NOTE` table decoding.
//!
//! Upstream reference: `parseElfNotes` in `upstream:src/native/elf/ElfNoteParser.ts`
//! and `upstream:src/domain/native/elfNoteLayout.ts`.

use std::borrow::Cow;

use rea_domain::digest::Sha256Digest;
use rea_domain::native::elf_notes::{
    ElfByteOrder, ElfFileRange, ElfNoteDescriptor, ElfNoteEntry, ElfNoteTable, ElfNoteTableKind,
    ElfNoteTypeName, ElfNotes, ElfNotesArtifact, ElfNotesCoverage, ElfNotesCoverageStatus,
    ElfNotesFormat, ElfObjectTypeName, HexBytes, InspectElfNotesInput,
    MAX_INSPECT_ELF_NOTE_FILE_BYTES,
};

use super::budget::{Counter, TextBudget};
use super::descriptors::{Descriptor, decode_core, decode_gnu, latin1};
use super::header::{
    ElfClass, ElfFixedHeader, Endian, read_elf_fixed_header, read_elf_program_header,
    read_elf_section_header, read_elf_table_declarations, validate_elf_section_table_presence,
};
use super::section_names::{
    SHF_COMPRESSED, SectionNameTable, SectionNameTableFailure, StringTableEntry,
    decode_elf_section_name_table, observe_string_table_entry,
};
use super::{ElfNotesFailure, ElfNotesLimitBoundary};

const PT_NOTE: u32 = 4;
const SHT_STRTAB: u32 = 3;
const SHT_NOTE: u32 = 7;
const NOTE_HEADER_BYTES: u64 = 12;
const HEX_DESCRIPTOR_LIMIT: u32 = 64;
/// JavaScript `Number.MAX_SAFE_INTEGER`; upstream refuses larger declared
/// offsets and sizes before range checks, so its messages take precedence.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

const LIMITATIONS: [&str; 2] = [
    "This workflow does not execute the image, resolve runtime notes, or verify GNU build-id uniqueness against package catalogs.",
    "PT_NOTE and SHT_NOTE are examined independently; the same file range may appear twice when both tables declare it.",
];

const ABSENT_LIMITATIONS: [&str; 2] = [
    "No PT_NOTE program header or SHT_NOTE section was declared. That is not proof the image never carried notes in another container or overlay.",
    "This workflow does not execute the image, resolve runtime notes, or verify GNU build-id uniqueness against package catalogs.",
];

const NAME_OUTSIDE_LIMITATION: &str =
    "ELF section names are incomplete because a name offset is outside its string table.";
const NAME_UNTERMINATED_LIMITATION: &str =
    "ELF section names are incomplete because a name is not NUL-terminated.";
const NO_NAME_TABLE_LIMITATION: &str =
    "ELF section names are unavailable because no section-name string table is declared.";

fn unsafe_integer() -> ElfNotesFailure {
    ElfNotesFailure::malformed("ELF offset or size exceeds a safe integer.")
}

fn admit_safe(values: &[u64]) -> Result<(), ElfNotesFailure> {
    if values.iter().any(|&value| value > MAX_SAFE_INTEGER) {
        return Err(unsafe_integer());
    }
    Ok(())
}

/// Every reported offset and size lies within the admitted image, which the
/// input ceiling keeps below `u32::MAX`.
fn uint(value: u64) -> Result<u32, ElfNotesFailure> {
    u32::try_from(value).map_err(|_| unsafe_integer())
}

fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn as_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// ELF note padding follows binutils: only a declared alignment of 8 uses 8.
fn note_alignment(declared: u64) -> u64 {
    if declared == 8 { 8 } else { 4 }
}

/// Descriptor and next-note offsets relative to the note's 12-byte header.
///
/// Offsets align from the note start: rounding `namesz` and `descsz`
/// independently disagrees with binutils for 8-byte alignment because the
/// header is not 8-aligned.
fn note_layout(namesz: u32, descsz: u32, alignment: u64) -> (u64, u64) {
    let descriptor = (NOTE_HEADER_BYTES + u64::from(namesz)).next_multiple_of(alignment);
    let next = (descriptor + u64::from(descsz)).next_multiple_of(alignment);
    (descriptor, next)
}

struct ElfReader<'a> {
    bytes: &'a [u8],
    endian: Endian,
}

impl<'a> ElfReader<'a> {
    fn slice(&self, offset: u64, length: u64) -> Result<&'a [u8], ElfNotesFailure> {
        let leaves = || {
            ElfNotesFailure::malformed(format!(
                "ELF range {offset} + {length} leaves the artifact."
            ))
        };
        let available = as_u64(self.bytes.len());
        if length > available || offset > available - length {
            return Err(leaves());
        }
        self.bytes
            .get(as_usize(offset)..as_usize(offset + length))
            .ok_or_else(leaves)
    }

    fn require(&self, offset: u64, length: u64) -> Result<(), ElfNotesFailure> {
        self.slice(offset, length).map(drop)
    }
}

struct ParsedNote<'a> {
    offset: u64,
    bytes: u64,
    namesz: u32,
    descsz: u32,
    note_type: u32,
    owner: &'a [u8],
    name_bytes: &'a [u8],
    descriptor: Descriptor<'a>,
}

/// Note-entry admission shared by every table.
struct EntryBudget {
    max_entries: u64,
    examined: u64,
}

fn parse_note_stream<'a>(
    reader: &ElfReader<'a>,
    offset: u64,
    size: u64,
    alignment: u64,
    entries: &mut EntryBudget,
    text: &mut TextBudget,
) -> Result<Vec<ParsedNote<'a>>, ElfNotesFailure> {
    // Alignment padding is not read when a note's aligned size equals the
    // declared table, so a short file must fail on the whole table first.
    reader.require(offset, size)?;
    let mut notes = Vec::new();
    let mut at = 0u64;
    while at + NOTE_HEADER_BYTES <= size {
        entries.examined += 1;
        if entries.examined > entries.max_entries {
            return Err(ElfNotesFailure::Limit {
                boundary: ElfNotesLimitBoundary::Capacity,
                message: format!(
                    "ELF note tables exceed the {}-entry budget.",
                    entries.max_entries
                ),
            });
        }
        let header = offset + at;
        let words = reader.slice(header, NOTE_HEADER_BYTES)?;
        let endian = reader.endian;
        let (Some(namesz), Some(descsz), Some(note_type)) = (
            endian.u32(words, 0),
            endian.u32(words, 4),
            endian.u32(words, 8),
        ) else {
            return Err(ElfNotesFailure::malformed("ELF note header is truncated"));
        };
        let (descriptor_at, next_at) = note_layout(namesz, descsz, alignment);
        let next = at + next_at;
        if next > size {
            return Err(ElfNotesFailure::malformed(
                "ELF note entry exceeds its table.",
            ));
        }
        let name_bytes = reader.slice(header + NOTE_HEADER_BYTES, u64::from(namesz))?;
        let descriptor_offset = header + descriptor_at;
        let descriptor = reader.slice(descriptor_offset, u64::from(descsz))?;
        let owner = name_bytes
            .iter()
            .position(|&byte| byte == 0)
            .and_then(|end| name_bytes.get(..end))
            .unwrap_or(name_bytes);
        text.charge_text(as_u64(owner.len()) + u64::from(namesz) * 2)?;
        notes.push(ParsedNote {
            offset: header,
            bytes: next - at,
            namesz,
            descsz,
            note_type,
            owner,
            name_bytes,
            descriptor: Descriptor {
                bytes: descriptor,
                offset: as_usize(descriptor_offset),
            },
        });
        at = next;
    }
    if at < size
        && reader
            .slice(offset + at, size - at)?
            .iter()
            .any(|&byte| byte != 0)
    {
        return Err(ElfNotesFailure::malformed(
            "ELF note table has trailing non-zero bytes.",
        ));
    }
    Ok(notes)
}

/// Image facts every entry decoder needs.
struct ImageContext {
    class: ElfClass,
    endian: Endian,
    machine: u16,
}

fn to_entry(
    note: &ParsedNote<'_>,
    table_kind: ElfNoteTableKind,
    table_index: u32,
    index: u32,
    image: &ImageContext,
    text: &mut TextBudget,
) -> Result<ElfNoteEntry, ElfNotesFailure> {
    let descriptor = note.descriptor;
    let sha256 = match text.hashes.get(&descriptor.range()) {
        Some(&digest) => digest,
        None => {
            text.charge(as_u64(descriptor.bytes.len()), Counter::Hashed)?;
            let digest = Sha256Digest::of(descriptor.bytes);
            text.hashes.insert(descriptor.range(), digest);
            digest
        }
    };
    let gnu_owner = note.owner == b"GNU";
    let core_owner = note.owner == b"CORE";
    let type_name = if gnu_owner {
        ElfNoteTypeName::gnu(note.note_type)
    } else if core_owner {
        ElfNoteTypeName::core(note.note_type)
    } else {
        ElfNoteTypeName::Unknown
    };
    let gnu = if gnu_owner {
        Some(decode_gnu(note.note_type, descriptor, image.endian, text)?)
    } else {
        None
    };
    let core = if core_owner {
        decode_core(
            note.note_type,
            descriptor,
            image.endian,
            image.class,
            image.machine,
            text,
        )?
    } else {
        None
    };
    Ok(ElfNoteEntry {
        index,
        table_kind,
        table_index,
        location: ElfFileRange {
            offset: uint(note.offset)?,
            bytes: uint(note.bytes)?,
        },
        namesz: note.namesz,
        descsz: note.descsz,
        note_type: note.note_type,
        type_name,
        owner: latin1(note.owner),
        owner_bytes_hex: HexBytes(note.name_bytes.to_vec()),
        descriptor: ElfNoteDescriptor {
            location: ElfFileRange {
                offset: uint(as_u64(descriptor.offset))?,
                bytes: note.descsz,
            },
            bytes: note.descsz,
            sha256,
            hex: (note.descsz <= HEX_DESCRIPTOR_LIMIT).then(|| HexBytes(descriptor.bytes.to_vec())),
        },
        gnu,
        core,
    })
}

/// Look up one section name, charging the examined bytes.
fn section_name(
    table: &[u8],
    offset: u32,
    text: &mut TextBudget,
) -> Result<(Option<String>, Option<&'static str>), ElfNotesFailure> {
    let window = as_usize(text.remaining_text().saturating_add(1));
    let observed = observe_string_table_entry(table, as_usize(u64::from(offset)), window);
    if observed == StringTableEntry::Outside {
        return Ok((None, Some(NAME_OUTSIDE_LIMITATION)));
    }
    text.charge_text(as_u64(observed.content_bytes()))?;
    Ok(match observed {
        StringTableEntry::Terminated(name) => (Some(latin1(name)), None),
        _ => (None, Some(NAME_UNTERMINATED_LIMITATION)),
    })
}

/// Collects the declared tables and their entries in report order.
struct Report {
    image: ImageContext,
    tables: Vec<ElfNoteTable>,
    entries: Vec<ElfNoteEntry>,
}

impl Report {
    fn push_table(
        &mut self,
        kind: ElfNoteTableKind,
        index: u16,
        name: Option<String>,
        (offset, size, alignment): (u64, u64, u64),
        notes: &[ParsedNote<'_>],
        text: &mut TextBudget,
    ) -> Result<(), ElfNotesFailure> {
        let table_index = u32::from(index);
        self.tables.push(ElfNoteTable {
            kind,
            index: table_index,
            name,
            location: ElfFileRange {
                offset: uint(offset)?,
                bytes: uint(size)?,
            },
            alignment: uint(alignment)?,
        });
        for note in notes {
            let entry_index = uint(as_u64(self.entries.len()))?;
            let entry = to_entry(note, kind, table_index, entry_index, &self.image, text)?;
            self.entries.push(entry);
        }
        Ok(())
    }
}

/// Decode `PT_NOTE` and `SHT_NOTE` tables from one in-memory ELF image.
///
/// `artifact` identifies `bytes` in the result. Failures leave no partial
/// result. Images larger than [`MAX_INSPECT_ELF_NOTE_FILE_BYTES`] are refused
/// before parsing; the stable artifact reader already bounds them by the
/// caller's `max_file_bytes`, so that refusal only guards direct callers.
pub fn parse_elf_notes(
    bytes: &[u8],
    artifact: ElfNotesArtifact,
    input: &InspectElfNotesInput,
) -> Result<ElfNotes, ElfNotesFailure> {
    let length = as_u64(bytes.len());
    if length > MAX_INSPECT_ELF_NOTE_FILE_BYTES {
        return Err(ElfNotesFailure::Limit {
            boundary: ElfNotesLimitBoundary::FileSize,
            message: format!(
                "Selected artifact exceeds {MAX_INSPECT_ELF_NOTE_FILE_BYTES} bytes: {}",
                artifact.path
            ),
        });
    }
    let header: ElfFixedHeader =
        read_elf_fixed_header(bytes).map_err(ElfNotesFailure::malformed)?;
    let (class, endian) = (header.class, header.endian);
    let reader = ElfReader { bytes, endian };
    let declared =
        read_elf_table_declarations(bytes, &header).map_err(ElfNotesFailure::malformed)?;
    admit_safe(&[declared.program_offset, declared.section_offset])?;
    validate_elf_section_table_presence(&declared).map_err(ElfNotesFailure::malformed)?;
    let phoff = declared.program_offset;
    let shoff = declared.section_offset;
    let phentsize = u64::from(declared.program_width);
    let shentsize = u64::from(declared.section_width);
    let phnum = declared.program_count;
    let shnum = declared.section_count;
    let shstrndx = declared.section_names_index;
    if phnum == 0xffff || shnum == 0xffff || shstrndx == 0xffff || (shoff != 0 && shnum == 0) {
        return Err(ElfNotesFailure::unsupported(
            "ELF extended numbering is unsupported.",
        ));
    }
    if phnum != 0 {
        if declared.program_width < class.program_header_bytes() {
            return Err(ElfNotesFailure::malformed(
                "ELF program header width is invalid.",
            ));
        }
        reader.require(phoff, u64::from(phnum) * phentsize)?;
    }
    if shnum != 0 {
        if declared.section_width < class.section_header_bytes() {
            return Err(ElfNotesFailure::malformed(
                "ELF section header width is invalid.",
            ));
        }
        reader.require(shoff, u64::from(shnum) * shentsize)?;
    }

    let mut text = TextBudget::new(length.min(input.max_file_bytes));
    let mut names: Option<Cow<'_, [u8]>> = None;
    let mut name_limitations: Vec<String> = Vec::new();
    if shnum != 0 && shstrndx != 0 {
        if shstrndx >= shnum {
            return Err(ElfNotesFailure::malformed(
                "ELF section name index is out of range.",
            ));
        }
        let at = shoff + u64::from(shstrndx) * shentsize;
        let names_section = read_elf_section_header(reader.slice(at, shentsize)?, class, endian)
            .map_err(ElfNotesFailure::malformed)?;
        if names_section.section_type != SHT_STRTAB {
            return Err(ElfNotesFailure::malformed(
                "ELF section name table is not a string table.",
            ));
        }
        admit_safe(&[names_section.offset, names_section.size])?;
        let raw = reader.slice(names_section.offset, names_section.size)?;
        match decode_elf_section_name_table(
            raw,
            names_section.flags,
            class,
            endian,
            input.max_file_bytes.checked_sub(length),
        ) {
            Err(SectionNameTableFailure::Malformed(message)) => {
                return Err(ElfNotesFailure::malformed(message));
            }
            Err(SectionNameTableFailure::Limit { required_bytes }) => {
                return Err(ElfNotesFailure::SectionNameBudget {
                    minimum_max_file_bytes: u128::from(length) + u128::from(required_bytes),
                    selected_max_file_bytes: input.max_file_bytes,
                });
            }
            Ok(SectionNameTable::Unsupported { compression_type }) => {
                name_limitations.push(format!(
                    "ELF section names are unavailable because compression type {compression_type} is unsupported."
                ));
            }
            Ok(SectionNameTable::Available { bytes, compressed }) => {
                if compressed {
                    text.limit = length + as_u64(bytes.len());
                }
                names = Some(bytes);
            }
        }
    } else if shnum != 0 {
        name_limitations.push(NO_NAME_TABLE_LIMITATION.to_owned());
    }

    let mut entry_budget = EntryBudget {
        max_entries: input.max_entries,
        examined: 0,
    };
    let mut report = Report {
        image: ImageContext {
            class,
            endian,
            machine: header.machine,
        },
        tables: Vec::new(),
        entries: Vec::new(),
    };
    let header_size = u64::from(header.header_size);
    if phnum != 0 {
        if phoff < header_size {
            return Err(ElfNotesFailure::malformed(
                "ELF program header table overlaps the native header.",
            ));
        }
        for index in 0..phnum {
            let at = phoff + u64::from(index) * phentsize;
            let program = read_elf_program_header(reader.slice(at, phentsize)?, class, endian)
                .map_err(ElfNotesFailure::malformed)?;
            if program.program_type != PT_NOTE {
                continue;
            }
            admit_safe(&[program.offset, program.file_size, program.alignment])?;
            let alignment = note_alignment(program.alignment);
            let notes = parse_note_stream(
                &reader,
                program.offset,
                program.file_size,
                alignment,
                &mut entry_budget,
                &mut text,
            )?;
            report.push_table(
                ElfNoteTableKind::Program,
                index,
                None,
                (program.offset, program.file_size, alignment),
                &notes,
                &mut text,
            )?;
        }
    }
    if shnum != 0 {
        if shoff < header_size {
            return Err(ElfNotesFailure::malformed(
                "ELF section header table overlaps the native header.",
            ));
        }
        for index in 0..shnum {
            let at = shoff + u64::from(index) * shentsize;
            let section = read_elf_section_header(reader.slice(at, shentsize)?, class, endian)
                .map_err(ElfNotesFailure::malformed)?;
            if section.section_type != SHT_NOTE {
                continue;
            }
            admit_safe(&[section.offset, section.size])?;
            reader.require(section.offset, section.size)?;
            // The compression header is storage metadata, not a note header,
            // and decoded notes would have no physical descriptor offsets.
            if section.flags & SHF_COMPRESSED != 0 {
                return Err(ElfNotesFailure::unsupported(
                    "Compressed ELF note sections are unsupported; descriptor file offsets require uncompressed note storage.",
                ));
            }
            admit_safe(&[section.alignment])?;
            let alignment = note_alignment(section.alignment);
            let (name, limitation) = match &names {
                Some(table) => section_name(table, section.name_offset, &mut text)?,
                None => (None, None),
            };
            if let Some(limitation) = limitation
                && !name_limitations.iter().any(|known| known == limitation)
            {
                name_limitations.push(limitation.to_owned());
            }
            let notes = parse_note_stream(
                &reader,
                section.offset,
                section.size,
                alignment,
                &mut entry_budget,
                &mut text,
            )?;
            report.push_table(
                ElfNoteTableKind::Section,
                index,
                name,
                (section.offset, section.size, alignment),
                &notes,
                &mut text,
            )?;
        }
    }

    let base = if report.tables.is_empty() {
        ABSENT_LIMITATIONS
    } else {
        LIMITATIONS
    };
    let limitations = base
        .into_iter()
        .map(str::to_owned)
        .chain(name_limitations)
        .collect();
    Ok(ElfNotes {
        artifact,
        format: if class.is_wide() {
            ElfNotesFormat::Elf64
        } else {
            ElfNotesFormat::Elf32
        },
        byte_order: if endian.little {
            ElfByteOrder::Little
        } else {
            ElfByteOrder::Big
        },
        machine: u32::from(header.machine),
        object_type: u32::from(header.object_type),
        type_name: ElfObjectTypeName::from_e_type(u32::from(header.object_type)),
        coverage: ElfNotesCoverage {
            status: ElfNotesCoverageStatus::Complete,
            examined_tables: uint(as_u64(report.tables.len()))?,
            examined_entries: uint(entry_budget.examined)?,
        },
        tables: report.tables,
        entries: report.entries,
        limitations,
    })
}
