//! GNU and Linux CORE note descriptor decoders.
//!
//! Descriptors that do not match their type's layout decode to null facts;
//! only budget exhaustion fails. Text is decoded as Latin-1 so every source
//! byte stays distinguishable without inferring an encoding.
//!
//! Upstream reference: `decodeGnu` and `decodeCore*` in
//! `upstream:src/native/elf/ElfNoteParser.ts`.

use rea_domain::native::elf_notes::{
    CoreAuxvEntry, CoreFile, CoreFileMapping, CorePrpsinfo, CoreSiginfo, ElfCoreNote, ElfGnuNote,
    GnuAbiTag, HexBytes, HexWord,
};

use super::ElfNotesFailure;
use super::budget::{Counter, DescriptorRange, TextBudget};
use super::header::{ElfClass, Endian};

const NT_GNU_ABI_TAG: u32 = 1;
const NT_GNU_BUILD_ID: u32 = 3;
const NT_GNU_GOLD_VERSION: u32 = 4;
const NT_PRPSINFO: u32 = 3;
const NT_AUXV: u32 = 6;
const NT_FILE: u32 = 0x4649_4c45;
const NT_SIGINFO: u32 = 0x5349_4749;
const EM_MIPS: u16 = 8;
const EM_MIPS_RS3_LE: u16 = 10;

/// Decode bytes as Latin-1: each byte is the code point of the same value.
pub(crate) fn latin1(bytes: &[u8]) -> String {
    bytes.iter().copied().map(char::from).collect()
}

fn until_nul(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .position(|&byte| byte == 0)
        .and_then(|end| bytes.get(..end))
        .unwrap_or(bytes)
}

fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// One descriptor and its file range.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Descriptor<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) offset: usize,
}

impl Descriptor<'_> {
    pub(crate) fn range(&self) -> DescriptorRange {
        (self.offset, self.bytes.len())
    }
}

fn gnu_os_name(os: u32) -> Option<&'static str> {
    Some(match os {
        0 => "linux",
        1 => "hurd",
        2 => "solaris",
        3 => "freebsd",
        4 => "netbsd",
        5 => "syllable",
        6 => "nacl",
        _ => return None,
    })
}

/// GNU-owner facts; members stay null unless the type and layout match.
pub(crate) fn decode_gnu(
    note_type: u32,
    descriptor: Descriptor<'_>,
    endian: Endian,
    text: &mut TextBudget,
) -> Result<ElfGnuNote, ElfNotesFailure> {
    let bytes = descriptor.bytes;
    let mut gnu = ElfGnuNote {
        build_id_hex: None,
        abi_tag: None,
        gold_version: None,
    };
    match note_type {
        NT_GNU_BUILD_ID if !bytes.is_empty() => {
            text.charge_text(as_u64(bytes.len()).saturating_mul(2))?;
            gnu.build_id_hex = Some(HexBytes(bytes.to_vec()));
        }
        NT_GNU_ABI_TAG if bytes.len() == 16 => {
            let read = |at| endian.u32(bytes, at);
            if let (Some(os), Some(major), Some(minor), Some(subminor)) =
                (read(0), read(4), read(8), read(12))
            {
                gnu.abi_tag = Some(GnuAbiTag {
                    os,
                    os_name: gnu_os_name(os).map(str::to_owned),
                    major,
                    minor,
                    subminor,
                });
            }
        }
        NT_GNU_GOLD_VERSION => {
            let end = match text.gold_scans.get(&descriptor.range()) {
                Some(&end) => end,
                None => {
                    text.charge(as_u64(bytes.len()), Counter::Scanned)?;
                    let end = bytes
                        .iter()
                        .rposition(|&byte| byte != 0)
                        .map_or(0, |last| last + 1);
                    text.gold_scans.insert(descriptor.range(), end);
                    end
                }
            };
            text.charge_text(as_u64(end))?;
            gnu.gold_version = Some(latin1(bytes.get(..end).unwrap_or_default()));
        }
        _ => {}
    }
    Ok(gnu)
}

/// CORE-owner facts for the decoded types; other types stay null.
pub(crate) fn decode_core(
    note_type: u32,
    descriptor: Descriptor<'_>,
    endian: Endian,
    class: ElfClass,
    machine: u16,
    text: &mut TextBudget,
) -> Result<Option<ElfCoreNote>, ElfNotesFailure> {
    let empty = ElfCoreNote {
        prpsinfo: None,
        file: None,
        siginfo: None,
        auxv: None,
    };
    Ok(match note_type {
        NT_PRPSINFO => {
            decode_prpsinfo(descriptor.bytes, endian, class, text)?.map(|prpsinfo| ElfCoreNote {
                prpsinfo: Some(prpsinfo),
                ..empty
            })
        }
        NT_FILE => decode_file(descriptor, endian, class, text)?.map(|file| ElfCoreNote {
            file: Some(file),
            ..empty
        }),
        NT_SIGINFO => {
            decode_siginfo(descriptor.bytes, endian, machine).map(|siginfo| ElfCoreNote {
                siginfo: Some(siginfo),
                ..empty
            })
        }
        NT_AUXV => decode_auxv(descriptor, endian, class, text)?.map(|auxv| ElfCoreNote {
            auxv: Some(auxv),
            ..empty
        }),
        _ => None,
    })
}

/// Linux `elf_prpsinfo` / `compat_elf_prpsinfo`.
fn decode_prpsinfo(
    bytes: &[u8],
    endian: Endian,
    class: ElfClass,
    text: &mut TextBudget,
) -> Result<Option<CorePrpsinfo>, ElfNotesFailure> {
    let wide = class.is_wide();
    if bytes.len() < if wide { 136 } else { 124 } {
        return Ok(None);
    }
    let words = || -> Option<[u32; 2]> {
        Some(if wide {
            [endian.u32(bytes, 16)?, endian.u32(bytes, 20)?]
        } else {
            [
                u32::from(endian.u16(bytes, 8)?),
                u32::from(endian.u16(bytes, 10)?),
            ]
        })
    };
    let ids_at = if wide { 24 } else { 12 };
    let ids = || -> Option<[i32; 4]> {
        Some([
            endian.i32(bytes, ids_at)?,
            endian.i32(bytes, ids_at + 4)?,
            endian.i32(bytes, ids_at + 8)?,
            endian.i32(bytes, ids_at + 12)?,
        ])
    };
    let (Some(&state), Some([uid, gid]), Some([pid, ppid, pgrp, sid])) =
        (bytes.first(), words(), ids())
    else {
        return Ok(None);
    };
    let fname_at = if wide { 40 } else { 28 };
    let psargs_at = if wide { 56 } else { 44 };
    let field = |at: usize, len: usize| until_nul(bytes.get(at..at + len).unwrap_or_default());
    let filename = field(fname_at, 16);
    text.charge_text(as_u64(filename.len()))?;
    let psargs = field(psargs_at, 80);
    text.charge_text(as_u64(psargs.len()))?;
    Ok(Some(CorePrpsinfo {
        state: u32::from(state),
        pid,
        ppid,
        pgrp,
        sid,
        uid,
        gid,
        filename: latin1(filename),
        psargs: latin1(psargs),
    }))
}

/// Total path bytes for `count` NUL-terminated strings starting at `start`,
/// or `None` when a string is missing or unterminated.
fn scan_file_paths(bytes: &[u8], start: usize, count: u64) -> Option<u64> {
    let mut position = start;
    let mut total = 0u64;
    for _ in 0..count {
        let rest = bytes.get(position..).filter(|rest| !rest.is_empty())?;
        let length = rest.iter().position(|&byte| byte == 0)?;
        total += as_u64(length);
        position += length + 1;
    }
    Some(total)
}

/// Linux `NT_FILE`: count, page size, `count` (start, end, offset) triples,
/// then `count` NUL-terminated paths.
fn decode_file(
    descriptor: Descriptor<'_>,
    endian: Endian,
    class: ElfClass,
    text: &mut TextBudget,
) -> Result<Option<CoreFile>, ElfNotesFailure> {
    let bytes = descriptor.bytes;
    let wide = class.is_wide();
    let word_bytes: usize = if wide { 8 } else { 4 };
    let header_bytes = word_bytes * 2;
    let read = |at| endian.word(class, bytes, at);
    let (Some(count), Some(page_size)) = (read(0), read(word_bytes)) else {
        return Ok(None);
    };
    let (Ok(count32), Ok(page_size)) = (u32::try_from(count), u32::try_from(page_size)) else {
        return Ok(None);
    };
    if page_size == 0 {
        return Ok(None);
    }
    let entry_bytes = as_u64(word_bytes * 3);
    let needed = as_u64(header_bytes) + count * entry_bytes;
    if as_u64(bytes.len()) < needed {
        return Ok(None);
    }
    // `needed` fits: it is at most the descriptor length.
    let table_bytes = usize::try_from(needed).unwrap_or(usize::MAX);
    let row_bytes = count * if wide { 54 } else { 30 };
    if row_bytes > text.remaining_text() {
        return Err(text.exceeded());
    }
    let range = descriptor.range();
    let path_bytes = match text.file_scans.get(&range) {
        Some(&scan) => scan,
        None => {
            text.charge(as_u64(bytes.len() - table_bytes), Counter::Scanned)?;
            let scan = scan_file_paths(bytes, table_bytes, count);
            text.file_scans.insert(range, scan);
            scan
        }
    };
    let Some(path_bytes) = path_bytes else {
        return Ok(None);
    };
    text.charge_text(row_bytes + path_bytes * 3)?;

    let mut mappings = Vec::with_capacity(usize::try_from(count).unwrap_or_default());
    let mut paths = bytes.get(table_bytes..).unwrap_or_default();
    for index in 0..usize::try_from(count).unwrap_or_default() {
        let at = header_bytes + index * word_bytes * 3;
        let (Some(start), Some(end), Some(offset)) =
            (read(at), read(at + word_bytes), read(at + 2 * word_bytes))
        else {
            return Ok(None);
        };
        let path = until_nul(paths);
        paths = paths.get(path.len() + 1..).unwrap_or_default();
        mappings.push(CoreFileMapping {
            start_address: HexWord(start),
            end_address: HexWord(end),
            file_offset_pages: HexWord(offset),
            path: latin1(path),
            path_hex: HexBytes(path.to_vec()),
        });
    }
    Ok(Some(CoreFile {
        count: count32,
        page_size,
        mappings,
    }))
}

/// Linux `siginfo_t` prefix; MIPS swaps `si_code` and `si_errno`.
fn decode_siginfo(bytes: &[u8], endian: Endian, machine: u16) -> Option<CoreSiginfo> {
    if bytes.len() < 12 {
        return None;
    }
    let mips = machine == EM_MIPS || machine == EM_MIPS_RS3_LE;
    let (errno_at, code_at) = if mips { (8, 4) } else { (4, 8) };
    Some(CoreSiginfo {
        signo: endian.i32(bytes, 0)?,
        code: endian.i32(bytes, code_at)?,
        errno: endian.i32(bytes, errno_at)?,
    })
}

fn auxv_type_name(entry_type: u32) -> Option<&'static str> {
    Some(match entry_type {
        0 => "AT_NULL",
        1 => "AT_IGNORE",
        2 => "AT_EXECFD",
        3 => "AT_PHDR",
        4 => "AT_PHENT",
        5 => "AT_PHNUM",
        6 => "AT_PAGESZ",
        7 => "AT_BASE",
        8 => "AT_FLAGS",
        9 => "AT_ENTRY",
        11 => "AT_UID",
        12 => "AT_EUID",
        13 => "AT_GID",
        14 => "AT_EGID",
        15 => "AT_PLATFORM",
        16 => "AT_HWCAP",
        17 => "AT_CLKTCK",
        23 => "AT_SECURE",
        25 => "AT_RANDOM",
        26 => "AT_HWCAP2",
        31 => "AT_EXECFN",
        33 => "AT_SYSINFO_EHDR",
        _ => return None,
    })
}

/// Index of the `AT_NULL` pair when every earlier tag fits 32 bits and every
/// byte after the terminator is zero.
fn scan_auxv(bytes: &[u8], endian: Endian, class: ElfClass) -> Option<usize> {
    let word_bytes = if class.is_wide() { 8 } else { 4 };
    let pair_bytes = word_bytes * 2;
    for (index, pair) in bytes.chunks_exact(pair_bytes).enumerate() {
        let tag = endian.word(class, pair, 0)?;
        if tag > u64::from(u32::MAX) {
            return None;
        }
        if tag == 0 {
            let tail = bytes.get((index + 1) * pair_bytes..)?;
            return tail.iter().all(|&byte| byte == 0).then_some(index);
        }
    }
    None
}

/// Linux `NT_AUXV`: (type, value) word pairs ending at `AT_NULL`.
fn decode_auxv(
    descriptor: Descriptor<'_>,
    endian: Endian,
    class: ElfClass,
    text: &mut TextBudget,
) -> Result<Option<Vec<CoreAuxvEntry>>, ElfNotesFailure> {
    let bytes = descriptor.bytes;
    let wide = class.is_wide();
    let word_bytes = if wide { 8 } else { 4 };
    let pair_bytes = word_bytes * 2;
    if bytes.len() < pair_bytes || !bytes.len().is_multiple_of(pair_bytes) {
        return Ok(None);
    }
    let range = descriptor.range();
    let terminator = match text.auxv_scans.get(&range) {
        Some(&scan) => scan,
        None => {
            text.charge(as_u64(bytes.len()), Counter::Scanned)?;
            let scan = scan_auxv(bytes, endian, class);
            text.auxv_scans.insert(range, scan);
            scan
        }
    };
    let Some(terminator) = terminator else {
        return Ok(None);
    };
    text.charge_text(as_u64(terminator) * if wide { 38 } else { 30 })?;
    let entries = bytes
        .chunks_exact(pair_bytes)
        .take(terminator)
        .map(|pair| {
            let entry_type = u32::try_from(endian.word(class, pair, 0)?).ok()?;
            Some(CoreAuxvEntry {
                entry_type,
                type_name: auxv_type_name(entry_type).map(str::to_owned),
                value: HexWord(endian.word(class, pair, word_bytes)?),
            })
        })
        .collect::<Option<Vec<_>>>();
    Ok(entries)
}
