//! ELF section-name string tables, including `SHF_COMPRESSED` storage.
//!
//! Decoded output is bounded by the caller's remaining byte allowance before
//! it is allocated; declared sizes only select the bound. Decoder failure
//! causes mirror the zlib/libzstd texts Node.js reports where the cause is
//! identifiable.
//!
//! Upstream reference: `upstream:src/native/metadata/ElfSectionNameTable.ts`
//! and `upstream:src/domain/elfStringTable.ts`.

use std::borrow::Cow;

use flate2::{Decompress, FlushDecompress, Status};
use ruzstd::decoding::errors::{FrameDecoderError, FrameHeaderError, ReadFrameHeaderError};
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};

use super::header::{ElfClass, Endian};

pub(crate) const SHF_COMPRESSED: u64 = 0x800;
const ELFCOMPRESS_ZLIB: u32 = 1;
const ELFCOMPRESS_ZSTD: u32 = 2;
/// libzstd's default `ZSTD_d_windowLogMax` (27), which upstream retains.
pub(crate) const ZSTD_MAX_WINDOW_BYTES: u64 = 1 << 27;
const INFLATE_CHUNK_BYTES: usize = 64 * 1024;

/// A decoded section-name table.
#[derive(Debug)]
pub(crate) enum SectionNameTable<'a> {
    Available {
        bytes: Cow<'a, [u8]>,
        compressed: bool,
    },
    Unsupported {
        compression_type: u32,
    },
}

/// Why a section-name table could not be decoded.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SectionNameTableFailure {
    Malformed(String),
    /// The declared decoded size exceeds the remaining allowance.
    Limit {
        required_bytes: u64,
    },
}

/// Decode the section-name table once for consumers that need its names.
///
/// `maximum_decoded_bytes` is `None` when no allowance remains at all, which
/// upstream expresses as a negative number.
pub(crate) fn decode_elf_section_name_table(
    bytes: &[u8],
    flags: u64,
    class: ElfClass,
    endian: Endian,
    maximum_decoded_bytes: Option<u64>,
) -> Result<SectionNameTable<'_>, SectionNameTableFailure> {
    if flags & SHF_COMPRESSED == 0 {
        return Ok(SectionNameTable::Available {
            bytes: Cow::Borrowed(bytes),
            compressed: false,
        });
    }
    let malformed_header = || {
        SectionNameTableFailure::Malformed(
            "ELF compressed section-name table header is truncated".to_owned(),
        )
    };
    let header_bytes = if class.is_wide() { 24 } else { 12 };
    if bytes.len() < header_bytes {
        return Err(malformed_header());
    }
    let compression_type = endian.u32(bytes, 0).ok_or_else(malformed_header)?;
    if compression_type != ELFCOMPRESS_ZLIB && compression_type != ELFCOMPRESS_ZSTD {
        return Ok(SectionNameTable::Unsupported { compression_type });
    }
    let declared = match class {
        ElfClass::Elf64 => endian.u64(bytes, 8),
        ElfClass::Elf32 => endian.u32(bytes, 4).map(u64::from),
    }
    .ok_or_else(malformed_header)?;
    let expected = match maximum_decoded_bytes {
        Some(maximum) if declared <= maximum => usize::try_from(declared).ok(),
        _ => None,
    }
    .ok_or(SectionNameTableFailure::Limit {
        required_bytes: declared,
    })?;
    let payload = bytes.get(header_bytes..).unwrap_or_default();
    let max_output = expected.max(1);
    let decoded = if compression_type == ELFCOMPRESS_ZSTD {
        decompress_zstd(payload, max_output)
    } else {
        inflate_zlib(payload, max_output)
    }
    .map_err(|cause| {
        SectionNameTableFailure::Malformed(format!(
            "ELF compressed section-name table could not be decompressed: {cause}"
        ))
    })?;
    if decoded.len() != expected {
        return Err(SectionNameTableFailure::Malformed(
            "ELF compressed section-name table size is inconsistent".to_owned(),
        ));
    }
    Ok(SectionNameTable::Available {
        bytes: Cow::Owned(decoded),
        compressed: true,
    })
}

/// Node's `ERR_BUFFER_TOO_LARGE` text for `maxOutputLength`.
fn output_too_large(max_output: usize) -> String {
    format!("Cannot create a Buffer larger than {max_output} bytes")
}

/// Grow `out` geometrically without exceeding `max_output + 1` bytes, which
/// is enough to observe an overflow.
fn reserve_output(out: &mut Vec<u8>, max_output: usize) -> Result<(), String> {
    let ceiling = max_output.saturating_add(1);
    if out.len() >= ceiling {
        return Err(output_too_large(max_output));
    }
    let target = out
        .capacity()
        .saturating_mul(2)
        .max(INFLATE_CHUNK_BYTES)
        .min(ceiling);
    out.reserve_exact(target - out.len());
    Ok(())
}

/// zlib stream decoding with the checks and messages zlib's `inflate` reports.
fn inflate_zlib(payload: &[u8], max_output: usize) -> Result<Vec<u8>, String> {
    const UNEXPECTED_END: &str = "unexpected end of file";
    let Some(&[cmf, flg]) = payload.first_chunk::<2>() else {
        return Err(UNEXPECTED_END.to_owned());
    };
    if (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
        return Err("incorrect header check".to_owned());
    }
    if cmf & 0x0f != 8 {
        return Err("unknown compression method".to_owned());
    }
    if (cmf >> 4) + 8 > 15 {
        return Err("invalid window size".to_owned());
    }
    if flg & 0x20 != 0 {
        return Err(if payload.len() < 6 {
            UNEXPECTED_END
        } else {
            "Missing dictionary"
        }
        .to_owned());
    }
    let mut input = payload.get(2..).unwrap_or_default();
    let mut inflater = Decompress::new(false);
    let mut out = Vec::new();
    loop {
        if out.len() == out.capacity() {
            reserve_output(&mut out, max_output)?;
        }
        let (in_before, out_before) = (inflater.total_in(), out.len());
        let status = inflater
            .decompress_vec(input, &mut out, FlushDecompress::None)
            .map_err(|_| "invalid compressed data".to_owned())?;
        let consumed = usize::try_from(inflater.total_in() - in_before).unwrap_or(usize::MAX);
        input = input.get(consumed..).unwrap_or_default();
        if out.len() > max_output {
            return Err(output_too_large(max_output));
        }
        match status {
            Status::StreamEnd => break,
            Status::Ok | Status::BufError => {
                if consumed == 0 && out.len() == out_before && out.len() < out.capacity() {
                    return Err(UNEXPECTED_END.to_owned());
                }
            }
        }
    }
    let Some(trailer) = input.first_chunk::<4>() else {
        return Err(UNEXPECTED_END.to_owned());
    };
    if u32::from_be_bytes(*trailer) != adler32(&out) {
        return Err("incorrect data check".to_owned());
    }
    Ok(out)
}

fn adler32(bytes: &[u8]) -> u32 {
    const MODULUS: u32 = 65_521;
    // 5552 is zlib's NMAX: the most bytes before `b` can overflow 32 bits.
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in bytes.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= MODULUS;
        b %= MODULUS;
    }
    (b << 16) | a
}

/// libzstd error-name texts for the causes ruzstd can distinguish.
mod zstd_error {
    pub(super) const UNKNOWN_FRAME: &str = "Unknown frame descriptor";
    pub(super) const WINDOW_TOO_LARGE: &str = "Frame requires too much memory for decoding";
    pub(super) const UNSUPPORTED_PARAMETER: &str = "Unsupported frame parameter";
    pub(super) const DICTIONARY: &str = "Dictionary mismatch";
    pub(super) const CORRUPTION: &str = "Data corruption detected";
    pub(super) const CHECKSUM: &str = "Restored data doesn't match checksum";
}

enum ZstdStop {
    /// Input ended inside a frame; libzstd waits for more input, so Node
    /// returns what was flushed and the size check reports the shortfall.
    Truncated,
    Failed(&'static str),
}

fn classify_zstd(error: &FrameDecoderError, input_exhausted: bool) -> ZstdStop {
    match error {
        FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::BadMagicNumber(_)) => {
            ZstdStop::Failed(zstd_error::UNKNOWN_FRAME)
        }
        FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::InvalidFrameDescriptor(
            _,
        )) => ZstdStop::Failed(zstd_error::UNSUPPORTED_PARAMETER),
        FrameDecoderError::WindowSizeTooBig { .. }
        | FrameDecoderError::FrameHeaderError(FrameHeaderError::WindowTooBig { .. })
        | FrameDecoderError::FailedToInitialize(FrameHeaderError::WindowTooBig { .. }) => {
            ZstdStop::Failed(zstd_error::WINDOW_TOO_LARGE)
        }
        FrameDecoderError::DictNotProvided { .. } => ZstdStop::Failed(zstd_error::DICTIONARY),
        _ if input_exhausted => ZstdStop::Truncated,
        _ => ZstdStop::Failed(zstd_error::CORRUPTION),
    }
}

/// Zstandard decoding of every frame in `payload`, skipping skippable frames.
///
/// Each frame's window is limited to [`ZSTD_MAX_WINDOW_BYTES`] before its
/// buffers are allocated. Decoded bytes the decoder must retain as window
/// history count toward that same allowance until they are collected.
fn decompress_zstd(payload: &[u8], max_output: usize) -> Result<Vec<u8>, String> {
    let mut input = payload;
    let mut out = Vec::new();
    let collect = |decoder: &mut FrameDecoder, out: &mut Vec<u8>| -> Result<(), String> {
        if decoder.can_collect() > max_output.saturating_sub(out.len()) {
            return Err(output_too_large(max_output));
        }
        decoder
            .collect_to_writer(out)
            .map(drop)
            .map_err(|_| zstd_error::CORRUPTION.to_owned())
    };
    while !input.is_empty() {
        let mut decoder = FrameDecoder::new();
        decoder.set_max_window_size(ZSTD_MAX_WINDOW_BYTES);
        match decoder.init(&mut input) {
            Ok(()) => {}
            Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame {
                length,
                ..
            })) => {
                match usize::try_from(length)
                    .ok()
                    .and_then(|length| input.get(length..))
                {
                    Some(rest) => {
                        input = rest;
                        continue;
                    }
                    None => break,
                }
            }
            Err(error) => match classify_zstd(&error, input.is_empty()) {
                ZstdStop::Truncated => break,
                ZstdStop::Failed(cause) => return Err(cause.to_owned()),
            },
        }
        loop {
            if let Err(error) =
                decoder.decode_blocks(&mut input, BlockDecodingStrategy::UptoBlocks(1))
            {
                match classify_zstd(&error, input.is_empty()) {
                    ZstdStop::Truncated => return Ok(out),
                    ZstdStop::Failed(cause) => return Err(cause.to_owned()),
                }
            }
            collect(&mut decoder, &mut out)?;
            if decoder.is_finished() {
                collect(&mut decoder, &mut out)?;
                if let Some(stored) = decoder.get_checksum_from_data()
                    && decoder.get_calculated_checksum() != Some(stored)
                {
                    return Err(zstd_error::CHECKSUM.to_owned());
                }
                break;
            }
        }
    }
    Ok(out)
}

/// One string-table entry, bounded by the consumer's scan allowance.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StringTableEntry<'a> {
    /// The offset lies outside the table.
    Outside,
    /// A NUL ends the entry within the window.
    Terminated(&'a [u8]),
    /// No NUL within the examined window of `examined_bytes`.
    Truncated { examined_bytes: usize },
}

impl StringTableEntry<'_> {
    /// Bytes the consumer must charge for this observation.
    pub(crate) fn content_bytes(&self) -> usize {
        match self {
            Self::Outside => 0,
            Self::Terminated(bytes) => bytes.len(),
            Self::Truncated { examined_bytes } => *examined_bytes,
        }
    }

    /// Bytes examined, including the terminating NUL when one was found.
    pub(crate) fn examined_bytes(&self) -> usize {
        match self {
            Self::Outside => 0,
            Self::Terminated(bytes) => bytes.len() + 1,
            Self::Truncated { examined_bytes } => *examined_bytes,
        }
    }
}

/// Observe one entry without treating a bounded missing NUL as absence.
pub(crate) fn observe_string_table_entry(
    table: &[u8],
    offset: usize,
    maximum_bytes: usize,
) -> StringTableEntry<'_> {
    let Some(rest) = table.get(offset..).filter(|rest| !rest.is_empty()) else {
        return StringTableEntry::Outside;
    };
    let window = rest.get(..maximum_bytes).unwrap_or(rest);
    match window.iter().position(|&byte| byte == 0) {
        Some(end) => StringTableEntry::Terminated(window.get(..end).unwrap_or_default()),
        None => StringTableEntry::Truncated {
            examined_bytes: window.len(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_matches_reference_values() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
        let long = vec![0xffu8; 100_000];
        let (mut a, mut b) = (1u64, 0u64);
        for &byte in &long {
            a = (a + u64::from(byte)) % 65_521;
            b = (b + a) % 65_521;
        }
        assert_eq!(u64::from(adler32(&long)), (b << 16) | a);
    }

    #[test]
    fn refuses_a_zstd_frame_requiring_more_than_the_window_allowance() {
        let mut table = vec![0u8; 24];
        table[0] = 2;
        table[16] = 1;
        // An empty last raw block with Window_Descriptor 0x90: a 2^28-byte window.
        table.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x90, 0x01, 0x00, 0x00]);
        let failure = decode_elf_section_name_table(
            &table,
            SHF_COMPRESSED,
            ElfClass::Elf64,
            Endian { little: true },
            Some(0),
        )
        .unwrap_err();
        let SectionNameTableFailure::Malformed(message) = failure else {
            panic!("expected a malformed table, got {failure:?}");
        };
        assert!(message.to_lowercase().contains("memory"), "{message}");
    }
}
