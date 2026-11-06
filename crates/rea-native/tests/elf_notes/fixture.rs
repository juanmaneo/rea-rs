//! ELF note byte builders ported from `upstream:src/native/elf/ElfNotes.fixture.ts`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use ruzstd::encoding::{CompressionLevel, compress_to_vec};

pub const DEFAULT_BUILD_ID: &str = "0123456789abcdef0123456789abcdef01234567";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bits {
    Elf32,
    Elf64,
}

impl Bits {
    pub const ALL: [Self; 2] = [Self::Elf32, Self::Elf64];

    pub fn wide(self) -> bool {
        self == Self::Elf64
    }

    pub fn header_bytes(self) -> usize {
        if self.wide() { 64 } else { 52 }
    }

    pub fn program_bytes(self) -> usize {
        if self.wide() { 56 } else { 32 }
    }

    pub fn section_bytes(self) -> usize {
        if self.wide() { 64 } else { 40 }
    }

    pub fn word_bytes(self) -> usize {
        if self.wide() { 8 } else { 4 }
    }

    pub fn shstrndx_at(self) -> usize {
        if self.wide() { 0x3e } else { 0x32 }
    }
}

pub fn latin1(text: &str) -> Vec<u8> {
    text.chars()
        .map(|character| u8::try_from(u32::from(character)).unwrap())
        .collect()
}

pub fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

pub fn put16(bytes: &mut [u8], at: usize, value: u16, little: bool) {
    let raw = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    bytes[at..at + 2].copy_from_slice(&raw);
}

pub fn put32(bytes: &mut [u8], at: usize, value: u32, little: bool) {
    let raw = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    bytes[at..at + 4].copy_from_slice(&raw);
}

pub fn put64(bytes: &mut [u8], at: usize, value: u64, little: bool) {
    let raw = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    bytes[at..at + 8].copy_from_slice(&raw);
}

pub fn put_word(bytes: &mut [u8], at: usize, value: u64, bits: Bits, little: bool) {
    match bits {
        Bits::Elf64 => put64(bytes, at, value, little),
        Bits::Elf32 => put32(bytes, at, u32::try_from(value).unwrap(), little),
    }
}

pub fn get16(bytes: &[u8], at: usize, little: bool) -> u16 {
    let raw = bytes[at..at + 2].try_into().unwrap();
    if little {
        u16::from_le_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    }
}

pub fn get_word(bytes: &[u8], at: usize, bits: Bits, little: bool) -> u64 {
    match bits {
        Bits::Elf64 => {
            let raw = bytes[at..at + 8].try_into().unwrap();
            if little {
                u64::from_le_bytes(raw)
            } else {
                u64::from_be_bytes(raw)
            }
        }
        Bits::Elf32 => {
            let raw = bytes[at..at + 4].try_into().unwrap();
            u64::from(if little {
                u32::from_le_bytes(raw)
            } else {
                u32::from_be_bytes(raw)
            })
        }
    }
}

pub fn get64le(bytes: &[u8], at: usize) -> u64 {
    get_word(bytes, at, Bits::Elf64, true)
}

fn len32(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).unwrap()
}

fn len64(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap()
}

/// Effective namesz/descsz padding: 8 stays 8; 0, 1, 4, and other values use 4.
fn note_padding(declared: u64) -> usize {
    if declared == 8 { 8 } else { 4 }
}

/// Encode one ELF note, padding name/descriptor to the table alignment.
pub fn elf_note_with(
    owner: &str,
    note_type: u32,
    descriptor: &[u8],
    little: bool,
    alignment: u64,
) -> Vec<u8> {
    let mut name = latin1(owner);
    name.push(0);
    let pad = note_padding(alignment);
    let desc_off = (12 + name.len()).next_multiple_of(pad);
    let mut bytes = vec![0; (desc_off + descriptor.len()).next_multiple_of(pad)];
    put32(&mut bytes, 0, len32(&name), little);
    put32(&mut bytes, 4, len32(descriptor), little);
    put32(&mut bytes, 8, note_type, little);
    bytes[12..12 + name.len()].copy_from_slice(&name);
    bytes[desc_off..desc_off + descriptor.len()].copy_from_slice(descriptor);
    bytes
}

/// Little-endian, 4-aligned note.
pub fn elf_note(owner: &str, note_type: u32, descriptor: &[u8]) -> Vec<u8> {
    elf_note_with(owner, note_type, descriptor, true, 4)
}

/// GNU `NT_GNU_BUILD_ID` note.
pub fn gnu_build_id_note(build_id: &str, little: bool) -> Vec<u8> {
    elf_note_with("GNU", 3, &hex(build_id), little, 4)
}

/// GNU `NT_GNU_ABI_TAG` note: Linux 3.2.0.
pub fn gnu_abi_tag_note(little: bool) -> Vec<u8> {
    let mut descriptor = vec![0; 16];
    put32(&mut descriptor, 0, 0, little);
    put32(&mut descriptor, 4, 3, little);
    put32(&mut descriptor, 8, 2, little);
    put32(&mut descriptor, 12, 0, little);
    elf_note_with("GNU", 1, &descriptor, little, 4)
}

/// GNU `NT_GNU_PROPERTY_TYPE_0` note with 8-byte table padding.
pub fn gnu_property_note(little: bool) -> Vec<u8> {
    let mut descriptor = vec![0; 32];
    put32(&mut descriptor, 0, 0xc000_0002, little);
    put32(&mut descriptor, 4, 4, little);
    put32(&mut descriptor, 8, 3, little);
    put32(&mut descriptor, 16, 0xc000_8002, little);
    put32(&mut descriptor, 20, 4, little);
    put32(&mut descriptor, 24, 1, little);
    elf_note_with("GNU", 5, &descriptor, little, 8)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    Program,
    Section,
    Both,
    None,
}

#[derive(Debug, Clone)]
pub struct ImageOptions {
    pub bits: Bits,
    pub little: bool,
    pub notes: Option<Vec<u8>>,
    pub ownership: Ownership,
    pub machine: u16,
    pub object_type: u16,
    pub alignment: u64,
    pub section_name: String,
}

impl Default for ImageOptions {
    fn default() -> Self {
        Self {
            bits: Bits::Elf64,
            little: true,
            notes: None,
            ownership: Ownership::Both,
            machine: 62,
            object_type: 3,
            alignment: 4,
            section_name: ".note.gnu.build-id".to_owned(),
        }
    }
}

/// Minimal ELF32/ELF64 image declaring `PT_NOTE` and/or `SHT_NOTE`.
///
/// Layout: header, program header, section headers (null, note,
/// `.shstrtab`), notes, then the section-name table.
pub fn elf_note_fixture(options: &ImageOptions) -> Vec<u8> {
    let ImageOptions {
        bits,
        little,
        ownership,
        alignment,
        ..
    } = *options;
    let notes = options.notes.clone().unwrap_or_else(|| {
        [
            gnu_build_id_note(DEFAULT_BUILD_ID, little),
            gnu_abi_tag_note(little),
        ]
        .concat()
    });
    let wide = bits.wide();
    let pad = note_padding(alignment);
    let header = bits.header_bytes();
    let phent = bits.program_bytes();
    let shent = bits.section_bytes();
    let program = matches!(ownership, Ownership::Program | Ownership::Both);
    let section = matches!(ownership, Ownership::Section | Ownership::Both);
    let phnum = usize::from(program);
    let shstrtab = latin1(&format!("\0{}\0.shstrtab\0", options.section_name));
    let shnum = if section { 3 } else { 0 };
    let phoff = header;
    let shoff = phoff + phnum * phent;
    let note_off = (shoff + shnum * shent).next_multiple_of(pad);
    let str_off = note_off + notes.len();
    let mut bytes = vec![0; str_off + if section { shstrtab.len() } else { 0 }];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = if wide { 2 } else { 1 };
    bytes[5] = if little { 1 } else { 2 };
    bytes[6] = 1;
    let word = |value: usize| u64::try_from(value).unwrap();
    let half = |value: usize| u16::try_from(value).unwrap();
    put16(&mut bytes, 0x10, options.object_type, little);
    put16(&mut bytes, 0x12, options.machine, little);
    put32(&mut bytes, 0x14, 1, little);
    put16(
        &mut bytes,
        if wide { 0x34 } else { 0x28 },
        half(header),
        little,
    );
    put_word(
        &mut bytes,
        if wide { 0x20 } else { 0x1c },
        if phnum == 0 { 0 } else { word(phoff) },
        bits,
        little,
    );
    put16(
        &mut bytes,
        if wide { 0x36 } else { 0x2a },
        half(phent),
        little,
    );
    put16(
        &mut bytes,
        if wide { 0x38 } else { 0x2c },
        half(phnum),
        little,
    );
    put_word(
        &mut bytes,
        if wide { 0x28 } else { 0x20 },
        if shnum == 0 { 0 } else { word(shoff) },
        bits,
        little,
    );
    put16(
        &mut bytes,
        if wide { 0x3a } else { 0x2e },
        half(shent),
        little,
    );
    put16(
        &mut bytes,
        if wide { 0x3c } else { 0x30 },
        half(shnum),
        little,
    );
    put16(
        &mut bytes,
        bits.shstrndx_at(),
        if section { 2 } else { 0 },
        little,
    );
    let notes_len = len64(&notes);
    if program {
        let ph = phoff;
        put32(&mut bytes, ph, 4, little);
        if wide {
            put32(&mut bytes, ph + 4, 4, little);
            put_word(&mut bytes, ph + 8, word(note_off), bits, little);
            put_word(&mut bytes, ph + 32, notes_len, bits, little);
            put_word(&mut bytes, ph + 40, notes_len, bits, little);
            put_word(&mut bytes, ph + 48, alignment, bits, little);
        } else {
            put_word(&mut bytes, ph + 4, word(note_off), bits, little);
            put_word(&mut bytes, ph + 16, notes_len, bits, little);
            put_word(&mut bytes, ph + 20, notes_len, bits, little);
            put32(&mut bytes, ph + 24, 4, little);
            put_word(&mut bytes, ph + 28, alignment, bits, little);
        }
    }
    if section {
        let str_name = u32::try_from(options.section_name.chars().count() + 2).unwrap();
        let note_sh = shoff + shent;
        let str_sh = shoff + 2 * shent;
        put32(&mut bytes, note_sh, 1, little);
        put32(&mut bytes, note_sh + 4, 7, little);
        put_word(
            &mut bytes,
            note_sh + if wide { 24 } else { 16 },
            word(note_off),
            bits,
            little,
        );
        put_word(
            &mut bytes,
            note_sh + if wide { 32 } else { 20 },
            notes_len,
            bits,
            little,
        );
        put_word(
            &mut bytes,
            note_sh + if wide { 48 } else { 32 },
            alignment,
            bits,
            little,
        );
        put32(&mut bytes, str_sh, str_name, little);
        put32(&mut bytes, str_sh + 4, 3, little);
        put_word(
            &mut bytes,
            str_sh + if wide { 24 } else { 16 },
            word(str_off),
            bits,
            little,
        );
        put_word(
            &mut bytes,
            str_sh + if wide { 32 } else { 20 },
            len64(&shstrtab),
            bits,
            little,
        );
        bytes[str_off..].copy_from_slice(&shstrtab);
    }
    bytes[note_off..note_off + notes.len()].copy_from_slice(&notes);
    bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameDamage {
    Outside,
    Unterminated,
}

/// A valid GNU note whose `SHT_NOTE` section-name lookup cannot be completed.
pub fn elf_note_with_unreadable_section_name_fixture(reason: NameDamage) -> Vec<u8> {
    let mut bytes = elf_note_fixture(&ImageOptions {
        ownership: Ownership::Section,
        notes: Some(gnu_build_id_note(DEFAULT_BUILD_ID, true)),
        ..ImageOptions::default()
    });
    let note_section = 64 + 64;
    let names_section = 64 + 2 * 64;
    let names_offset = usize::try_from(get64le(&bytes, names_section + 24)).unwrap();
    let names_size = usize::try_from(get64le(&bytes, names_section + 32)).unwrap();
    match reason {
        NameDamage::Outside => put32(
            &mut bytes,
            note_section,
            u32::try_from(names_size).unwrap(),
            true,
        ),
        NameDamage::Unterminated => {
            bytes[names_offset + 1..names_offset + names_size].fill(0x41);
        }
    }
    bytes
}

pub fn zlib(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

pub fn zstd(bytes: &[u8]) -> Vec<u8> {
    compress_to_vec(bytes, CompressionLevel::Fastest)
}

/// A non-allocated `SHT_NOTE` whose stored bytes include an ELF compression header.
pub fn compressed_elf_note_section_fixture(bits: Bits, little: bool) -> Vec<u8> {
    let notes = [
        gnu_build_id_note(DEFAULT_BUILD_ID, little),
        gnu_abi_tag_note(little),
    ]
    .concat();
    let wide = bits.wide();
    let mut header = vec![0; if wide { 24 } else { 12 }];
    put32(&mut header, 0, 1, little);
    put_word(
        &mut header,
        if wide { 8 } else { 4 },
        len64(&notes),
        bits,
        little,
    );
    put_word(&mut header, if wide { 16 } else { 8 }, 4, bits, little);
    let mut bytes = elf_note_fixture(&ImageOptions {
        bits,
        little,
        object_type: 1,
        ownership: Ownership::Section,
        section_name: ".debug.notes".to_owned(),
        alignment: if wide { 8 } else { 4 },
        notes: Some([header, zlib(&notes)].concat()),
        ..ImageOptions::default()
    });
    let note_section = bits.header_bytes() + bits.section_bytes();
    put_word(&mut bytes, note_section + 8, 0x800, bits, little);
    bytes
}

/// Valid ELF64 section count stored in section header zero per the gABI.
pub fn elf_extended_section_count_fixture() -> Vec<u8> {
    let count = 0xff00usize;
    let section_offset = 0x200usize;
    let note_offset = 0x100usize;
    let names_offset = 0x180usize;
    let note = gnu_build_id_note("12345678", true);
    let names = latin1("\0.note.gnu.build-id\0.shstrtab\0");
    let mut bytes = vec![0; section_offset + count * 64];
    bytes[..7].copy_from_slice(&[0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
    put16(&mut bytes, 16, 1, true);
    put16(&mut bytes, 18, 62, true);
    put32(&mut bytes, 20, 1, true);
    put64(&mut bytes, 40, 0x200, true);
    put16(&mut bytes, 52, 64, true);
    put16(&mut bytes, 54, 56, true);
    put16(&mut bytes, 58, 64, true);
    put16(&mut bytes, 60, 0, true);
    put16(&mut bytes, 62, 2, true);
    put64(&mut bytes, section_offset + 32, 0xff00, true);

    let note_section = section_offset + 64;
    put32(&mut bytes, note_section, 1, true);
    put32(&mut bytes, note_section + 4, 7, true);
    put64(&mut bytes, note_section + 24, 0x100, true);
    put64(&mut bytes, note_section + 32, len64(&note), true);
    put64(&mut bytes, note_section + 48, 4, true);

    let names_section = section_offset + 2 * 64;
    put32(&mut bytes, names_section, 20, true);
    put32(&mut bytes, names_section + 4, 3, true);
    put64(&mut bytes, names_section + 24, 0x180, true);
    put64(&mut bytes, names_section + 32, len64(&names), true);
    put64(&mut bytes, names_section + 48, 1, true);

    bytes[note_offset..note_offset + note.len()].copy_from_slice(&note);
    bytes[names_offset..names_offset + names.len()].copy_from_slice(&names);
    bytes
}

/// ELF note fixture with a compressed section-name string table.
///
/// Compression type 2 uses Zstandard; every other type stores zlib bytes.
pub fn compressed_elf_note_fixture(
    bits: Bits,
    little: bool,
    compression_type: u32,
    section_name: &str,
) -> Vec<u8> {
    let image = elf_note_fixture(&ImageOptions {
        bits,
        little,
        ownership: Ownership::Section,
        section_name: section_name.to_owned(),
        ..ImageOptions::default()
    });
    let wide = bits.wide();
    let index = |value: u64| usize::try_from(value).unwrap();
    let shoff = index(get_word(&image, if wide { 40 } else { 32 }, bits, little));
    let shentsize = usize::from(get16(&image, if wide { 58 } else { 46 }, little));
    let names_index = usize::from(get16(&image, if wide { 62 } else { 50 }, little));
    let names_header = shoff + names_index * shentsize;
    let names_offset = index(get_word(
        &image,
        names_header + if wide { 24 } else { 16 },
        bits,
        little,
    ));
    let names_size = index(get_word(
        &image,
        names_header + if wide { 32 } else { 20 },
        bits,
        little,
    ));
    let names = &image[names_offset..names_offset + names_size];
    let compressed = if compression_type == 2 {
        zstd(names)
    } else {
        zlib(names)
    };
    let compression_header_bytes = if wide { 24 } else { 12 };
    let mut replacement = vec![0; compression_header_bytes];
    put32(&mut replacement, 0, compression_type, little);
    put_word(
        &mut replacement,
        if wide { 8 } else { 4 },
        len64(names),
        bits,
        little,
    );
    put_word(&mut replacement, if wide { 16 } else { 8 }, 1, bits, little);
    let mut result = [
        &image[..names_offset],
        &replacement,
        &compressed,
        &image[names_offset + names_size..],
    ]
    .concat();
    let flags_at = names_header + 8;
    let flags = get_word(&result, flags_at, bits, little);
    put_word(&mut result, flags_at, flags | 0x800, bits, little);
    put_word(
        &mut result,
        names_header + if wide { 32 } else { 20 },
        u64::try_from(compression_header_bytes + compressed.len()).unwrap(),
        bits,
        little,
    );
    put_word(
        &mut result,
        names_header + if wide { 48 } else { 32 },
        1,
        bits,
        little,
    );
    result
}

/// ELF64 whose only `PT_NOTE` declares 20 bytes. The file holds the 12-byte
/// header, 4-byte name, and 1-byte descriptor; the 3 alignment bytes are absent.
pub fn elf_note_table_past_end() -> Vec<u8> {
    let mut note = vec![0; 17];
    put32(&mut note, 0, 4, true);
    put32(&mut note, 4, 1, true);
    put32(&mut note, 8, 1, true);
    note[12..16].copy_from_slice(b"GNU\0");
    note[16] = 0x2a;
    let mut header = vec![0; 64];
    header[..4].copy_from_slice(b"\x7fELF");
    header[4] = 2;
    header[5] = 1;
    header[6] = 1;
    put16(&mut header, 0x10, 3, true);
    put16(&mut header, 0x12, 62, true);
    put32(&mut header, 0x14, 1, true);
    put16(&mut header, 0x34, 64, true);
    put64(&mut header, 0x20, 64, true);
    put16(&mut header, 0x36, 56, true);
    put16(&mut header, 0x38, 1, true);
    let mut program = vec![0; 56];
    put32(&mut program, 0, 4, true);
    put64(&mut program, 8, 120, true);
    put64(&mut program, 32, 20, true);
    put64(&mut program, 48, 4, true);
    [header, program, note].concat()
}

#[derive(Debug, Clone)]
pub struct PrpsinfoOptions {
    pub bits: Bits,
    pub little: bool,
    pub state: u8,
    pub sname: u8,
    pub zomb: u8,
    pub nice: u8,
    pub flag: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
    pub ppid: i32,
    pub pgrp: i32,
    pub sid: i32,
    pub fname: &'static str,
    pub psargs: &'static str,
}

impl Default for PrpsinfoOptions {
    fn default() -> Self {
        Self {
            bits: Bits::Elf64,
            little: true,
            state: 0,
            sname: b'R',
            zomb: 0,
            nice: 0,
            flag: 0,
            uid: 1000,
            gid: 1000,
            pid: 1234,
            ppid: 1,
            pgrp: 1234,
            sid: 1234,
            fname: "app",
            psargs: "./app --flag",
        }
    }
}

fn put_i32(bytes: &mut [u8], at: usize, value: i32, little: bool) {
    put32(bytes, at, u32::from_ne_bytes(value.to_ne_bytes()), little);
}

fn copy_truncated(target: &mut [u8], at: usize, text: &str, limit: usize) {
    let mut source = latin1(text);
    source.push(0);
    let length = source.len().min(limit);
    target[at..at + length].copy_from_slice(&source[..length]);
}

/// Linux CORE `NT_PRPSINFO` note (type 3).
pub fn core_prpsinfo_note(options: &PrpsinfoOptions) -> Vec<u8> {
    let little = options.little;
    let wide = options.bits.wide();
    let mut desc = vec![0; if wide { 136 } else { 124 }];
    desc[0] = options.state;
    desc[1] = options.sname;
    desc[2] = options.zomb;
    desc[3] = options.nice;
    let (ids, fname, psargs) = if wide {
        put64(&mut desc, 8, options.flag, little);
        put32(&mut desc, 16, options.uid, little);
        put32(&mut desc, 20, options.gid, little);
        (24, 40, 56)
    } else {
        put32(&mut desc, 4, u32::try_from(options.flag).unwrap(), little);
        put16(&mut desc, 8, u16::try_from(options.uid).unwrap(), little);
        put16(&mut desc, 10, u16::try_from(options.gid).unwrap(), little);
        (12, 28, 44)
    };
    put_i32(&mut desc, ids, options.pid, little);
    put_i32(&mut desc, ids + 4, options.ppid, little);
    put_i32(&mut desc, ids + 8, options.pgrp, little);
    put_i32(&mut desc, ids + 12, options.sid, little);
    copy_truncated(&mut desc, fname, options.fname, 16);
    copy_truncated(&mut desc, psargs, options.psargs, 80);
    elf_note_with("CORE", 3, &desc, little, 4)
}

#[derive(Debug, Clone, Copy)]
pub struct CoreMapping {
    pub start: u64,
    pub end: u64,
    pub file_ofs: u64,
    pub path: &'static str,
}

/// Linux CORE `NT_FILE` note (type `0x46494c45`).
pub fn core_file_note(
    mappings: &[CoreMapping],
    page_size: u64,
    bits: Bits,
    little: bool,
) -> Vec<u8> {
    let word_bytes = bits.word_bytes();
    let header_bytes = 2 * word_bytes;
    let map_entry_bytes = 3 * word_bytes;
    let filenames: Vec<u8> = mappings
        .iter()
        .flat_map(|mapping| {
            let mut path = latin1(mapping.path);
            path.push(0);
            path
        })
        .collect();
    let mut desc = vec![0; header_bytes + mappings.len() * map_entry_bytes + filenames.len()];
    put_word(
        &mut desc,
        0,
        u64::try_from(mappings.len()).unwrap(),
        bits,
        little,
    );
    put_word(&mut desc, word_bytes, page_size, bits, little);
    let mut offset = header_bytes;
    for mapping in mappings {
        put_word(&mut desc, offset, mapping.start, bits, little);
        put_word(&mut desc, offset + word_bytes, mapping.end, bits, little);
        put_word(
            &mut desc,
            offset + 2 * word_bytes,
            mapping.file_ofs,
            bits,
            little,
        );
        offset += map_entry_bytes;
    }
    desc[offset..].copy_from_slice(&filenames);
    elf_note_with("CORE", 0x4649_4c45, &desc, little, 4)
}

/// Linux CORE `NT_SIGINFO` note (type `0x53494749`).
pub fn core_siginfo_note(signo: i32, code: i32, errno: i32, little: bool) -> Vec<u8> {
    let mut desc = vec![0; 128];
    put_i32(&mut desc, 0, signo, little);
    put_i32(&mut desc, 4, errno, little);
    put_i32(&mut desc, 8, code, little);
    elf_note_with("CORE", 0x5349_4749, &desc, little, 4)
}

/// Linux CORE `NT_AUXV` note (type 6), terminated by `AT_NULL`.
pub fn core_auxv_note(entries: &[(u64, u64)], bits: Bits, little: bool) -> Vec<u8> {
    let word_bytes = bits.word_bytes();
    let mut desc = vec![0; (entries.len() + 1) * 2 * word_bytes];
    let mut offset = 0;
    for &(key, value) in entries {
        put_word(&mut desc, offset, key, bits, little);
        put_word(&mut desc, offset + word_bytes, value, bits, little);
        offset += 2 * word_bytes;
    }
    elf_note_with("CORE", 6, &desc, little, 4)
}
