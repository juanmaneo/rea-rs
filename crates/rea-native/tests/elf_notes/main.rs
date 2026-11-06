//! `parse_elf_notes` behavior ported from
//! `upstream:src/native/elf/ElfNoteParser.test.ts` and the parser semantics
//! of `upstream:tests/acceptance/elfNotes*.test.ts`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fixture;

use fixture::{
    Bits, CoreMapping, DEFAULT_BUILD_ID, ImageOptions, NameDamage, Ownership, PrpsinfoOptions,
    compressed_elf_note_fixture, compressed_elf_note_section_fixture, core_auxv_note,
    core_file_note, core_prpsinfo_note, core_siginfo_note, elf_extended_section_count_fixture,
    elf_note, elf_note_fixture, elf_note_table_past_end, elf_note_with,
    elf_note_with_unreadable_section_name_fixture, get16, get64le, gnu_abi_tag_note,
    gnu_build_id_note, gnu_property_note, hex, latin1, put16, put32, put64,
};
use rea_domain::digest::Sha256Digest;
use rea_domain::native::elf_notes::{
    CoreAuxvEntry, CoreFile, CoreFileMapping, CorePrpsinfo, CoreSiginfo, ElfByteOrder, ElfCoreNote,
    ElfFileRange, ElfNoteEntry, ElfNoteTableKind, ElfNoteTypeName, ElfNotes, ElfNotesArtifact,
    ElfNotesCoverage, ElfNotesCoverageStatus, ElfNotesFormat, ElfObjectTypeName, GnuAbiTag,
    HexBytes, HexWord, InspectElfNotesInput,
};
use rea_native::elf::{
    BinaryFormatFailureKind, ElfNotesFailure, ElfNotesLimitBoundary, parse_elf_notes,
};
use serde_json::Value;

const PATH: &str = "/artifacts/app";

const SCOPE_LIMITATIONS: [&str; 2] = [
    "This workflow does not execute the image, resolve runtime notes, or verify GNU build-id uniqueness against package catalogs.",
    "PT_NOTE and SHT_NOTE are examined independently; the same file range may appear twice when both tables declare it.",
];
const ABSENT_LIMITATIONS: [&str; 2] = [
    "No PT_NOTE program header or SHT_NOTE section was declared. That is not proof the image never carried notes in another container or overlay.",
    "This workflow does not execute the image, resolve runtime notes, or verify GNU build-id uniqueness against package catalogs.",
];
const NAME_OUTSIDE: &str =
    "ELF section names are incomplete because a name offset is outside its string table.";
const NAME_UNTERMINATED: &str =
    "ELF section names are incomplete because a name is not NUL-terminated.";
const COMPRESSED_NOTES: &str = "Compressed ELF note sections are unsupported; descriptor file offsets require uncompressed note storage.";
const UNSAFE_INTEGER: &str = "ELF offset or size exceeds a safe integer.";

fn input_with(max_file_bytes: Option<u64>, max_entries: Option<u64>) -> InspectElfNotesInput {
    let mut input = InspectElfNotesInput::new(PATH);
    if let Some(max_file_bytes) = max_file_bytes {
        input.max_file_bytes = max_file_bytes;
    }
    if let Some(max_entries) = max_entries {
        input.max_entries = max_entries;
    }
    let raw = serde_json::to_value(&input).unwrap();
    assert_eq!(InspectElfNotesInput::parse(Some(&raw)), Ok(input.clone()));
    input
}

fn try_parse_with(bytes: &[u8], input: &InspectElfNotesInput) -> Result<ElfNotes, ElfNotesFailure> {
    let artifact = ElfNotesArtifact {
        path: input.path.clone(),
        sha256: Sha256Digest::of(bytes),
        bytes: u32::try_from(bytes.len()).unwrap(),
    };
    parse_elf_notes(bytes, artifact, input)
}

fn try_parse(bytes: &[u8]) -> Result<ElfNotes, ElfNotesFailure> {
    try_parse_with(bytes, &input_with(None, None))
}

fn parse(bytes: &[u8]) -> ElfNotes {
    try_parse(bytes).unwrap_or_else(|failure| panic!("parse failed: {failure:?}"))
}

fn failure(bytes: &[u8]) -> ElfNotesFailure {
    try_parse(bytes).expect_err("parse unexpectedly succeeded")
}

fn malformed(message: impl Into<String>) -> ElfNotesFailure {
    ElfNotesFailure::Format {
        kind: BinaryFormatFailureKind::Malformed,
        message: message.into(),
    }
}

fn unsupported(message: impl Into<String>) -> ElfNotesFailure {
    ElfNotesFailure::Format {
        kind: BinaryFormatFailureKind::Unsupported,
        message: message.into(),
    }
}

fn memory_limit(limit: usize) -> ElfNotesFailure {
    ElfNotesFailure::Limit {
        boundary: ElfNotesLimitBoundary::Memory,
        message: format!("ELF note text exceeds the {limit}-byte budget."),
    }
}

fn image(options: ImageOptions) -> Vec<u8> {
    elf_note_fixture(&options)
}

fn program_image(notes: Vec<u8>) -> Vec<u8> {
    image(ImageOptions {
        ownership: Ownership::Program,
        notes: Some(notes),
        ..ImageOptions::default()
    })
}

fn find(report: &ElfNotes, type_name: ElfNoteTypeName) -> &ElfNoteEntry {
    report
        .entries
        .iter()
        .find(|entry| entry.type_name == type_name)
        .unwrap_or_else(|| panic!("no {type_name:?} entry"))
}

fn build_id(entry: &ElfNoteEntry) -> String {
    entry
        .gnu
        .as_ref()
        .and_then(|gnu| gnu.build_id_hex.as_ref())
        .map(ToString::to_string)
        .unwrap_or_default()
}

fn linux_3_2_0() -> GnuAbiTag {
    GnuAbiTag {
        os: 0,
        os_name: Some("linux".to_owned()),
        major: 3,
        minor: 2,
        subminor: 0,
    }
}

#[derive(Default)]
struct Elf64Fields {
    phoff: u64,
    shoff: u64,
    phnum: u16,
    shnum: u16,
    phentsize: Option<u16>,
    shentsize: Option<u16>,
}

fn elf64(fields: &Elf64Fields, tail: &[u8]) -> Vec<u8> {
    let mut header = vec![0u8; 64];
    header[..4].copy_from_slice(b"\x7fELF");
    header[4] = 2;
    header[5] = 1;
    header[6] = 1;
    put16(&mut header, 16, 2, true);
    put16(&mut header, 18, 62, true);
    put32(&mut header, 20, 1, true);
    put64(&mut header, 32, fields.phoff, true);
    put64(&mut header, 40, fields.shoff, true);
    put16(&mut header, 52, 64, true);
    put16(&mut header, 54, fields.phentsize.unwrap_or(56), true);
    put16(&mut header, 56, fields.phnum, true);
    put16(&mut header, 58, fields.shentsize.unwrap_or(64), true);
    put16(&mut header, 60, fields.shnum, true);
    [header.as_slice(), tail].concat()
}

/// `sections` empty `SHT_NOTE` sections whose names all start at offset 0 of
/// a `name_bytes`-byte table of `A`s.
fn unterminated_note_sections(sections: usize, name_bytes: usize) -> Vec<u8> {
    let shnum = sections + 2;
    let table_offset = u64::try_from(64 + shnum * 64).unwrap();
    let shdr = |section_type: u32, offset: u64, size: u64| {
        let mut header = vec![0u8; 64];
        put32(&mut header, 4, section_type, true);
        put64(&mut header, 24, offset, true);
        put64(&mut header, 32, size, true);
        header
    };
    let mut image = elf64(
        &Elf64Fields {
            shoff: 64,
            shnum: u16::try_from(shnum).unwrap(),
            ..Elf64Fields::default()
        },
        &[],
    );
    image.extend(shdr(0, 0, 0));
    image.extend(shdr(3, table_offset, u64::try_from(name_bytes).unwrap()));
    for _ in 0..sections {
        image.extend(shdr(7, table_offset, 0));
    }
    image.extend(std::iter::repeat_n(0x41, name_bytes));
    put16(&mut image, 62, 1, true);
    image
}

fn repeated_notes(count: usize, notes: &[u8]) -> Vec<u8> {
    let mut headers = vec![0u8; 56 * count];
    let offset = u64::try_from(64 + headers.len()).unwrap();
    for index in 0..count {
        let at = index * 56;
        put32(&mut headers, at, 4, true);
        put64(&mut headers, at + 8, offset, true);
        put64(
            &mut headers,
            at + 32,
            u64::try_from(notes.len()).unwrap(),
            true,
        );
        put64(&mut headers, at + 48, 4, true);
    }
    let fields = Elf64Fields {
        phoff: 64,
        phnum: u16::try_from(count).unwrap(),
        ..Elf64Fields::default()
    };
    [elf64(&fields, &headers), notes.to_vec()].concat()
}

#[test]
fn reads_gnu_build_id_and_abi_tag_notes_from_elf32_and_elf64() {
    for bits in Bits::ALL {
        let report = parse(&image(ImageOptions {
            bits,
            ownership: Ownership::Program,
            ..ImageOptions::default()
        }));
        let format = if bits.wide() {
            ElfNotesFormat::Elf64
        } else {
            ElfNotesFormat::Elf32
        };
        assert_eq!(report.format, format);
        assert_eq!(report.byte_order, ElfByteOrder::Little);
        assert_eq!(report.tables.len(), 1);
        assert_eq!(report.tables[0].kind, ElfNoteTableKind::Program);
        assert_eq!(
            build_id(find(&report, ElfNoteTypeName::GnuBuildId)),
            DEFAULT_BUILD_ID
        );
        let abi = find(&report, ElfNoteTypeName::GnuAbiTag);
        assert_eq!(
            abi.gnu.as_ref().unwrap().abi_tag.as_ref(),
            Some(&linux_3_2_0())
        );
    }
}

#[test]
fn reads_the_same_notes_from_an_sht_note_section_including_its_name() {
    let report = parse(&image(ImageOptions {
        ownership: Ownership::Section,
        ..ImageOptions::default()
    }));
    assert_eq!(report.tables.len(), 1);
    assert_eq!(report.tables[0].kind, ElfNoteTableKind::Section);
    assert_eq!(report.tables[0].name.as_deref(), Some(".note.gnu.build-id"));
    find(&report, ElfNoteTypeName::GnuBuildId);
    assert_eq!(report.limitations, SCOPE_LIMITATIONS);
}

#[test]
fn refuses_compressed_note_storage_without_parsing_its_compression_header() {
    for bits in Bits::ALL {
        for little in [true, false] {
            assert_eq!(
                failure(&compressed_elf_note_section_fixture(bits, little)),
                unsupported(COMPRESSED_NOTES),
                "{bits:?} little={little}"
            );
        }
    }
}

#[test]
fn does_not_allocate_the_declared_decoded_note_size_but_validates_stored_ranges() {
    let mut bytes = compressed_elf_note_section_fixture(Bits::Elf64, true);
    let note_section = 64 + 64;
    let stored_offset = usize::try_from(get64le(&bytes, note_section + 24)).unwrap();
    put64(&mut bytes, stored_offset + 8, u64::MAX, true);
    assert_eq!(failure(&bytes), unsupported(COMPRESSED_NOTES));
    put64(&mut bytes, note_section + 32, 0, true);
    assert_eq!(failure(&bytes), unsupported(COMPRESSED_NOTES));
    let length = bytes.len();
    put64(
        &mut bytes,
        note_section + 32,
        u64::try_from(length).unwrap(),
        true,
    );
    assert_eq!(
        failure(&bytes),
        malformed(format!(
            "ELF range {stored_offset} + {length} leaves the artifact."
        ))
    );
}

#[test]
fn preserves_unknown_elf64_section_flag_bits_without_treating_them_as_file_sizes() {
    let mut bytes = image(ImageOptions {
        ownership: Ownership::Section,
        ..ImageOptions::default()
    });
    put64(&mut bytes, 64 + 64 + 8, 0x8000_0000_0000_0000, true);
    put64(&mut bytes, 64 + 2 * 64 + 8, 0x8000_0000_0000_0000, true);
    assert_eq!(build_id(&parse(&bytes).entries[0]), DEFAULT_BUILD_ID);
}

#[test]
fn decompresses_zlib_and_zstd_section_name_tables() {
    for compression_type in [1, 2] {
        for bits in Bits::ALL {
            for little in [true, false] {
                let bytes = compressed_elf_note_fixture(
                    bits,
                    little,
                    compression_type,
                    ".note.gnu.build-id",
                );
                let report = parse(&bytes);
                let context = format!("{bits:?} little={little} type={compression_type}");
                assert_eq!(report.tables.len(), 1, "{context}");
                assert_eq!(report.tables[0].kind, ElfNoteTableKind::Section);
                assert_eq!(
                    report.tables[0].name.as_deref(),
                    Some(".note.gnu.build-id"),
                    "{context}"
                );
                assert_eq!(build_id(&report.entries[0]), DEFAULT_BUILD_ID, "{context}");
                assert_eq!(report.limitations, SCOPE_LIMITATIONS, "{context}");
            }
        }
    }
}

#[test]
fn admits_a_decoded_section_name_larger_than_its_compressed_storage() {
    let name = "n".repeat(512);
    for compression_type in [1, 2] {
        let bytes = compressed_elf_note_fixture(Bits::Elf64, true, compression_type, &name);
        assert!(bytes.len() < name.len(), "image is {} bytes", bytes.len());
        assert_eq!(parse(&bytes).tables[0].name.as_deref(), Some(name.as_str()));
    }
}

#[test]
fn rejects_malformed_compressed_section_name_storage() {
    #[derive(Debug, Clone, Copy)]
    enum Damage {
        Corrupt,
        Truncated,
        TooLarge,
        TooSmall,
    }
    for compression_type in [1, 2] {
        for damage in [
            Damage::Corrupt,
            Damage::Truncated,
            Damage::TooLarge,
            Damage::TooSmall,
        ] {
            let mut bytes = compressed_elf_note_fixture(
                Bits::Elf64,
                true,
                compression_type,
                ".note.gnu.build-id",
            );
            let section_offset = usize::try_from(get64le(&bytes, 40)).unwrap();
            let name_header = section_offset + usize::from(get16(&bytes, 62, true)) * 64;
            let names_offset = usize::try_from(get64le(&bytes, name_header + 24)).unwrap();
            match damage {
                Damage::Corrupt => bytes[names_offset + 24] = 0,
                Damage::Truncated => {
                    let size = get64le(&bytes, name_header + 32);
                    put64(&mut bytes, name_header + 32, size - 1, true);
                }
                Damage::TooLarge | Damage::TooSmall => {
                    let size = get64le(&bytes, names_offset + 8);
                    let size = if matches!(damage, Damage::TooLarge) {
                        size + 1
                    } else {
                        size - 1
                    };
                    put64(&mut bytes, names_offset + 8, size, true);
                }
            }
            let context = format!("type={compression_type} {damage:?}");
            match failure(&bytes) {
                ElfNotesFailure::Format {
                    kind: BinaryFormatFailureKind::Malformed,
                    message,
                } => assert!(
                    message.starts_with("ELF compressed section-name table "),
                    "{context}: {message}"
                ),
                other => panic!("{context}: unexpected {other:?}"),
            }
        }
    }
}

#[test]
fn reports_libz_causes_for_damaged_zlib_section_names() {
    let mut bytes = compressed_elf_note_fixture(Bits::Elf64, true, 1, ".note.gnu.build-id");
    let section_offset = usize::try_from(get64le(&bytes, 40)).unwrap();
    let name_header = section_offset + 2 * 64;
    let names_offset = usize::try_from(get64le(&bytes, name_header + 24)).unwrap();
    let pristine = bytes.clone();
    bytes[names_offset + 24] = 0;
    assert_eq!(
        failure(&bytes),
        malformed(
            "ELF compressed section-name table could not be decompressed: incorrect header check"
        )
    );
    bytes.clone_from(&pristine);
    let size = get64le(&bytes, name_header + 32);
    put64(&mut bytes, name_header + 32, size - 1, true);
    assert_eq!(
        failure(&bytes),
        malformed(
            "ELF compressed section-name table could not be decompressed: unexpected end of file"
        )
    );
    bytes.clone_from(&pristine);
    let decoded = get64le(&bytes, names_offset + 8);
    put64(&mut bytes, names_offset + 8, decoded + 1, true);
    assert_eq!(
        failure(&bytes),
        malformed("ELF compressed section-name table size is inconsistent")
    );
    bytes.clone_from(&pristine);
    let last = names_offset + usize::try_from(size).unwrap() - 1;
    bytes[last] ^= 0xff;
    assert_eq!(
        failure(&bytes),
        malformed(
            "ELF compressed section-name table could not be decompressed: incorrect data check"
        )
    );
}

#[test]
fn reports_an_unknown_zstd_frame_for_damaged_magic() {
    let mut bytes = compressed_elf_note_fixture(Bits::Elf64, true, 2, ".note.gnu.build-id");
    let name_header = usize::try_from(get64le(&bytes, 40)).unwrap() + 2 * 64;
    let names_offset = usize::try_from(get64le(&bytes, name_header + 24)).unwrap();
    bytes[names_offset + 24] = 0;
    assert_eq!(
        failure(&bytes),
        malformed(
            "ELF compressed section-name table could not be decompressed: Unknown frame descriptor"
        )
    );
}

#[test]
fn refuses_a_zstd_window_above_the_allowance_inside_an_image() {
    let mut bytes = compressed_elf_note_fixture(Bits::Elf64, true, 2, ".note.gnu.build-id");
    let name_header = usize::try_from(get64le(&bytes, 40)).unwrap() + 2 * 64;
    let names_offset = usize::try_from(get64le(&bytes, name_header + 24)).unwrap();
    let mut table = vec![0u8; 24];
    put32(&mut table, 0, 2, true);
    put64(&mut table, 16, 1, true);
    table.extend(hex("28b52ffd0090010000"));
    bytes.truncate(names_offset);
    bytes.extend(&table);
    put64(
        &mut bytes,
        name_header + 32,
        u64::try_from(table.len()).unwrap(),
        true,
    );
    assert_eq!(
        failure(&bytes),
        malformed(
            "ELF compressed section-name table could not be decompressed: Frame requires too much memory for decoding"
        )
    );
}

#[test]
fn keeps_note_facts_but_marks_section_names_unavailable_for_unknown_compression() {
    let report = parse(&compressed_elf_note_fixture(
        Bits::Elf64,
        true,
        3,
        ".note.gnu.build-id",
    ));
    assert_eq!(report.tables[0].name, None);
    assert_eq!(build_id(&report.entries[0]), DEFAULT_BUILD_ID);
    assert!(report.limitations.contains(
        &"ELF section names are unavailable because compression type 3 is unsupported.".to_owned()
    ));
}

#[test]
fn admits_compressed_section_names_when_max_file_bytes_includes_expansion() {
    for compression_type in [1, 2] {
        let bytes =
            compressed_elf_note_fixture(Bits::Elf64, true, compression_type, ".note.gnu.build-id");
        let section_offset = usize::try_from(get64le(&bytes, 40)).unwrap();
        let name_header = section_offset + usize::from(get16(&bytes, 62, true)) * 64;
        let names_offset = usize::try_from(get64le(&bytes, name_header + 24)).unwrap();
        let decoded = get64le(&bytes, names_offset + 8);
        let length = u64::try_from(bytes.len()).unwrap();
        let minimum = length + decoded;
        let refused = try_parse_with(&bytes, &input_with(Some(length + 1), None)).unwrap_err();
        assert_eq!(
            refused,
            ElfNotesFailure::SectionNameBudget {
                minimum_max_file_bytes: u128::from(minimum),
                selected_max_file_bytes: length + 1,
            }
        );
        assert_eq!(
            refused.to_string(),
            format!(
                "ELF source and decoded section names require {minimum} bytes, above the selected max_file_bytes ({}).",
                length + 1
            )
        );
        let admitted = try_parse_with(&bytes, &input_with(Some(minimum), None)).unwrap();
        assert_eq!(
            admitted.tables[0].name.as_deref(),
            Some(".note.gnu.build-id")
        );
    }
}

#[test]
fn reports_independent_pt_note_and_sht_note_declarations_of_the_same_bytes() {
    let report = parse(&image(ImageOptions::default()));
    let kinds: Vec<_> = report.tables.iter().map(|table| table.kind).collect();
    assert_eq!(
        kinds,
        [ElfNoteTableKind::Program, ElfNoteTableKind::Section]
    );
    assert_eq!(report.tables[0].location, report.tables[1].location);
    let build_ids = report
        .entries
        .iter()
        .filter(|entry| entry.type_name == ElfNoteTypeName::GnuBuildId)
        .count();
    assert_eq!(build_ids, 2);
    let indexes: Vec<_> = report.entries.iter().map(|entry| entry.index).collect();
    assert_eq!(indexes, [0, 1, 2, 3]);
    let tables: Vec<_> = report
        .entries
        .iter()
        .map(|entry| (entry.table_kind, entry.table_index))
        .collect();
    assert_eq!(
        tables,
        [
            (ElfNoteTableKind::Program, 0),
            (ElfNoteTableKind::Program, 0),
            (ElfNoteTableKind::Section, 1),
            (ElfNoteTableKind::Section, 1),
        ]
    );
    assert_eq!(
        report.coverage,
        ElfNotesCoverage {
            status: ElfNotesCoverageStatus::Complete,
            examined_tables: 2,
            examined_entries: 4,
        }
    );
}

#[test]
fn reports_missing_note_tables_without_claiming_notes_never_existed() {
    let report = parse(&image(ImageOptions {
        ownership: Ownership::None,
        ..ImageOptions::default()
    }));
    assert!(report.tables.is_empty());
    assert!(report.entries.is_empty());
    assert_eq!(report.limitations, ABSENT_LIMITATIONS);
    assert_eq!(report.coverage.examined_tables, 0);
    assert_eq!(report.coverage.examined_entries, 0);
}

#[test]
fn fails_a_truncated_note_payload_without_partial_success() {
    let mut notes = gnu_build_id_note(DEFAULT_BUILD_ID, true);
    put32(&mut notes, 0, 64, true);
    assert_eq!(
        failure(&program_image(notes)),
        malformed("ELF note entry exceeds its table.")
    );
}

#[test]
fn keeps_non_gnu_owners_as_unknown_types_with_descriptor_hashes() {
    let payload = b"hello";
    let report = parse(&program_image(elf_note("CORE", 1, payload)));
    let entry = &report.entries[0];
    assert_eq!(entry.owner, "CORE");
    assert_eq!(entry.type_name, ElfNoteTypeName::Unknown);
    assert_eq!(entry.gnu, None);
    assert_eq!(entry.descriptor.sha256, Sha256Digest::of(payload));
    assert_eq!(entry.descriptor.hex, Some(HexBytes(payload.to_vec())));
    assert_eq!(entry.owner_bytes_hex, HexBytes(b"CORE\0".to_vec()));
}

#[test]
fn reads_a_big_endian_elf32_gnu_build_id() {
    let report = parse(&image(ImageOptions {
        bits: Bits::Elf32,
        little: false,
        machine: 20,
        ownership: Ownership::Program,
        notes: Some(gnu_build_id_note(DEFAULT_BUILD_ID, false)),
        ..ImageOptions::default()
    }));
    assert_eq!(report.byte_order, ElfByteOrder::Big);
    assert_eq!(report.machine, 20);
    assert_eq!(build_id(&report.entries[0]), DEFAULT_BUILD_ID);
}

#[test]
fn reads_an_8_aligned_gnu_property_note_from_a_pt_note_program_header() {
    let notes = gnu_property_note(true);
    assert_eq!(notes.len(), 48);
    let report = parse(&image(ImageOptions {
        ownership: Ownership::Program,
        notes: Some(notes),
        alignment: 8,
        ..ImageOptions::default()
    }));
    assert_eq!(report.tables.len(), 1);
    assert_eq!(report.tables[0].kind, ElfNoteTableKind::Program);
    assert_eq!(report.tables[0].alignment, 8);
    assert_eq!(report.entries.len(), 1);
    let entry = &report.entries[0];
    assert_eq!(entry.owner, "GNU");
    assert_eq!(entry.note_type, 5);
    assert_eq!(entry.type_name, ElfNoteTypeName::GnuProperty);
    assert_eq!((entry.namesz, entry.descsz), (4, 32));
    assert_eq!(entry.descriptor.location.offset, entry.location.offset + 16);
}

#[test]
fn reads_an_8_aligned_gnu_property_note_from_an_sht_note_section() {
    let report = parse(&image(ImageOptions {
        ownership: Ownership::Section,
        notes: Some(gnu_property_note(true)),
        alignment: 8,
        section_name: ".note.gnu.property".to_owned(),
        ..ImageOptions::default()
    }));
    assert_eq!(report.tables.len(), 1);
    assert_eq!(report.tables[0].kind, ElfNoteTableKind::Section);
    assert_eq!(report.tables[0].name.as_deref(), Some(".note.gnu.property"));
    assert_eq!(report.tables[0].alignment, 8);
    assert_eq!(report.entries[0].type_name, ElfNoteTypeName::GnuProperty);
    assert_eq!(report.entries[0].descriptor.bytes, 32);
}

#[test]
fn treats_declared_note_alignment_0_and_1_as_4_byte_padding() {
    for alignment in [0, 1] {
        let report = parse(&image(ImageOptions {
            ownership: Ownership::Program,
            alignment,
            ..ImageOptions::default()
        }));
        assert_eq!(report.tables[0].alignment, 4);
        find(&report, ElfNoteTypeName::GnuBuildId);
        find(&report, ElfNoteTypeName::GnuAbiTag);
    }
}

#[test]
fn parses_a_host_elf_without_requiring_it_to_contain_notes() {
    let host = ["/bin/ls", "/usr/bin/ls", "/usr/bin/env"]
        .into_iter()
        .filter_map(|path| std::fs::read(path).ok())
        .find(|bytes| bytes.len() > 64 && bytes.starts_with(b"\x7fELF"));
    let Some(bytes) = host else {
        eprintln!("skipped: no host ELF found");
        return;
    };
    let report = parse(&bytes);
    assert_eq!(report.coverage.status, ElfNotesCoverageStatus::Complete);
    if let Some(entry) = report
        .entries
        .iter()
        .find(|entry| entry.type_name == ElfNoteTypeName::GnuBuildId)
    {
        let id = build_id(entry);
        assert!(!id.is_empty() && id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}

#[test]
fn retains_section_name_offsets_consistently() {
    for (offset, name) in [(2, Some("é")), (3, Some("")), (4, None)] {
        let mut bytes = unterminated_note_sections(1, 4);
        let at = bytes.len() - 4;
        bytes[at..].copy_from_slice(&[0x41, 0x42, 0xe9, 0]);
        put32(&mut bytes, 64 + 2 * 64, offset, true);
        let report = parse(&bytes);
        assert_eq!(report.tables[0].name.as_deref(), name, "offset {offset}");
        if name.is_none() {
            assert_eq!(report.coverage.status, ElfNotesCoverageStatus::Complete);
            assert!(report.limitations.contains(&NAME_OUTSIDE.to_owned()));
        }
    }
}

#[test]
fn reads_section_names_with_a_nul_beyond_64_kib() {
    for terminator in [65_535, 65_536] {
        let mut bytes = unterminated_note_sections(1, terminator + 1);
        let last = bytes.len() - 1;
        bytes[last] = 0;
        let report = parse(&bytes);
        assert_eq!(
            report.tables[0].name.as_deref(),
            Some("A".repeat(terminator).as_str())
        );
        assert_eq!(report.coverage.status, ElfNotesCoverageStatus::Complete);
    }
}

#[test]
fn bounds_repeated_scans_of_an_unterminated_section_name() {
    let report = parse(&unterminated_note_sections(2, 64));
    let names: Vec<_> = report
        .tables
        .iter()
        .map(|table| table.name.clone())
        .collect();
    assert_eq!(names, [None, None]);
    assert_eq!(report.coverage.status, ElfNotesCoverageStatus::Complete);
    let unterminated: Vec<_> = report
        .limitations
        .iter()
        .filter(|value| value.contains("not NUL-terminated"))
        .collect();
    assert_eq!(unterminated, [NAME_UNTERMINATED]);
    let bytes = unterminated_note_sections(3, 400);
    assert_eq!(failure(&bytes), memory_limit(bytes.len()));
}

#[test]
fn rejects_note_text_that_repeats_beyond_the_shared_byte_budget() {
    let notes = elf_note(&"A".repeat(40), 1, &[]);
    let once = program_image(notes.clone());
    let twice = image(ImageOptions {
        ownership: Ownership::Both,
        notes: Some(notes),
        ..ImageOptions::default()
    });
    let input = input_with(Some(200), None);
    assert_eq!(try_parse_with(&once, &input).unwrap().entries.len(), 1);
    assert_eq!(
        try_parse_with(&twice, &input).unwrap_err(),
        memory_limit(200)
    );
}

#[test]
fn rejects_program_and_section_header_tables_that_do_not_fit() {
    let program = elf64(
        &Elf64Fields {
            phoff: 64,
            phnum: 1,
            ..Elf64Fields::default()
        },
        &[1, 0, 0, 0],
    );
    assert_eq!(
        failure(&program),
        malformed("ELF range 64 + 56 leaves the artifact.")
    );
    let section = elf64(
        &Elf64Fields {
            shoff: 64,
            shnum: 1,
            shentsize: Some(64),
            ..Elf64Fields::default()
        },
        &[0, 0, 0, 0],
    );
    assert_eq!(
        failure(&section),
        malformed("ELF range 64 + 64 leaves the artifact.")
    );
}

#[test]
fn rejects_an_extended_section_count_stored_in_section_zero() {
    let bytes = elf64(
        &Elf64Fields {
            shoff: 64,
            ..Elf64Fields::default()
        },
        &[],
    );
    assert_eq!(
        failure(&bytes),
        unsupported("ELF extended numbering is unsupported.")
    );
    assert_eq!(
        failure(&elf_extended_section_count_fixture()),
        unsupported("ELF extended numbering is unsupported.")
    );
}

#[test]
fn reuses_one_descriptor_hash_and_gnu_nul_scan_across_note_headers() {
    let payload = vec![0u8; 400];
    let hashed = parse(&repeated_notes(6, &elf_note("X", 1, &payload)));
    assert_eq!(hashed.entries.len(), 6);
    assert!(
        hashed
            .entries
            .iter()
            .all(|entry| entry.descriptor.sha256 == Sha256Digest::of(&payload))
    );
    assert!(
        hashed
            .entries
            .iter()
            .all(|entry| entry.descriptor.hex.is_none())
    );
    let gold = parse(&repeated_notes(6, &elf_note("GNU", 4, &payload)));
    assert_eq!(gold.entries.len(), 6);
    assert!(gold.entries.iter().all(|entry| {
        entry
            .gnu
            .as_ref()
            .and_then(|gnu| gnu.gold_version.as_deref())
            == Some("")
    }));
    let distinct = [elf_note("X", 1, &payload), elf_note("X", 1, &[1u8; 400])].concat();
    assert_eq!(
        try_parse_with(&program_image(distinct), &input_with(Some(560), None)).unwrap_err(),
        memory_limit(560)
    );
}

#[test]
fn decodes_a_gnu_gold_version_by_scanning_trailing_nuls() {
    let gold = |report: ElfNotes| {
        report.entries[0]
            .gnu
            .as_ref()
            .and_then(|gnu| gnu.gold_version.clone())
    };
    let trailing = elf_note("GNU", 4, b"gold\0\0x\0");
    assert_eq!(
        gold(parse(&program_image(trailing))).as_deref(),
        Some("gold\0\0x")
    );
    let mut descriptor = vec![0u8; 131_072];
    descriptor.push(b'x');
    let expected = format!("{}x", "\0".repeat(131_072));
    assert_eq!(
        gold(parse(&program_image(elf_note("GNU", 4, &descriptor)))),
        Some(expected)
    );
}

#[test]
fn rejects_a_declared_note_table_that_extends_past_the_file() {
    let truncated = elf_note_table_past_end();
    assert_eq!(truncated.len(), 137);
    assert_eq!(
        failure(&truncated),
        malformed("ELF range 120 + 20 leaves the artifact.")
    );
    let present = [truncated, vec![0; 3]].concat();
    let report = parse(&present);
    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.tables[0].location,
        ElfFileRange {
            offset: 120,
            bytes: 20
        }
    );
}

#[test]
fn fails_when_the_entry_budget_is_exhausted() {
    let notes = [
        gnu_build_id_note(DEFAULT_BUILD_ID, true),
        gnu_abi_tag_note(true),
        elf_note("GNU", 4, b"gold"),
    ]
    .concat();
    let bytes = program_image(notes);
    assert_eq!(
        try_parse_with(&bytes, &input_with(None, Some(1))).unwrap_err(),
        ElfNotesFailure::Limit {
            boundary: ElfNotesLimitBoundary::Capacity,
            message: "ELF note tables exceed the 1-entry budget.".to_owned(),
        }
    );
    let admitted = try_parse_with(&bytes, &input_with(None, Some(3))).unwrap();
    assert_eq!(admitted.coverage.examined_entries, 3);
}

#[test]
fn keeps_unsafe_table_offsets_ahead_of_unsupported_extended_numbering() {
    let mut bytes = elf_extended_section_count_fixture();
    put64(&mut bytes, 32, u64::MAX, true);
    assert_eq!(failure(&bytes), malformed(UNSAFE_INTEGER));
}

#[test]
fn does_not_apply_note_precision_admission_to_unrelated_program_records() {
    let mut bytes = elf64(
        &Elf64Fields {
            phoff: 64,
            phnum: 1,
            ..Elf64Fields::default()
        },
        &[0; 56],
    );
    put32(&mut bytes, 64, 0x7000_0001, true);
    for relative in [8, 16, 24, 32, 40, 48] {
        put64(&mut bytes, 64 + relative, u64::MAX, true);
    }
    assert!(parse(&bytes).tables.is_empty());
    put32(&mut bytes, 64, 4, true);
    assert_eq!(failure(&bytes), malformed(UNSAFE_INTEGER));
}

#[test]
fn keeps_compressed_note_refusal_ahead_of_alignment_precision_admission() {
    let mut bytes = compressed_elf_note_section_fixture(Bits::Elf64, true);
    let section_table = usize::try_from(get64le(&bytes, 40)).unwrap();
    put64(&mut bytes, section_table + 64 + 48, u64::MAX, true);
    assert_eq!(failure(&bytes), unsupported(COMPRESSED_NOTES));
}

#[test]
fn rejects_dangling_section_names_with_and_without_notes() {
    for bits in Bits::ALL {
        for little in [true, false] {
            for ownership in [Ownership::Program, Ownership::None] {
                let mut bytes = image(ImageOptions {
                    bits,
                    little,
                    ownership,
                    ..ImageOptions::default()
                });
                let before = parse(&bytes);
                put16(&mut bytes, bits.shstrndx_at(), 5, little);
                assert_eq!(
                    failure(&bytes),
                    malformed("ELF section table is missing"),
                    "{bits:?} little={little} {ownership:?}"
                );
                put16(&mut bytes, bits.shstrndx_at(), 0, little);
                assert_eq!(parse(&bytes), before);
                let tables = usize::from(ownership == Ownership::Program);
                assert_eq!(before.tables.len(), tables);
            }
        }
    }
}

fn core_entry(entry: &ElfNoteEntry) -> &ElfCoreNote {
    assert_eq!(entry.owner, "CORE");
    assert_eq!(entry.gnu, None);
    entry.core.as_ref().unwrap()
}

fn auxv(entries: &[(u32, Option<&str>, u64)]) -> Vec<CoreAuxvEntry> {
    entries
        .iter()
        .map(|&(entry_type, type_name, value)| CoreAuxvEntry {
            entry_type,
            type_name: type_name.map(str::to_owned),
            value: HexWord(value),
        })
        .collect()
}

fn mapping(start: u64, end: u64, pages: u64, path: &str) -> CoreFileMapping {
    CoreFileMapping {
        start_address: HexWord(start),
        end_address: HexWord(end),
        file_offset_pages: HexWord(pages),
        path: path.to_owned(),
        path_hex: HexBytes(latin1(path)),
    }
}

#[test]
fn decodes_linux_core_notes_for_64_bit_little_endian() {
    let notes = [
        core_prpsinfo_note(&PrpsinfoOptions {
            pid: 4242,
            ppid: 1,
            pgrp: 4242,
            sid: 4242,
            uid: 1001,
            gid: 1002,
            fname: "test-proc",
            psargs: "/usr/bin/test-proc --daemon -v",
            ..PrpsinfoOptions::default()
        }),
        core_file_note(
            &[
                CoreMapping {
                    start: 0x40_0000,
                    end: 0x40_5000,
                    file_ofs: 0,
                    path: "/usr/bin/test-proc",
                },
                CoreMapping {
                    start: 0x7fff_0000,
                    end: 0x7fff_2000,
                    file_ofs: 10,
                    path: "/lib/x86_64-linux-gnu/libc.so.6",
                },
            ],
            4096,
            Bits::Elf64,
            true,
        ),
        core_siginfo_note(11, 1, 0, true),
        core_auxv_note(
            &[(6, 4096), (3, 0x40_0040), (9, 0x40_1000), (999, 0x1234)],
            Bits::Elf64,
            true,
        ),
    ]
    .concat();
    let report = parse(&image(ImageOptions {
        object_type: 4,
        ownership: Ownership::Program,
        notes: Some(notes),
        ..ImageOptions::default()
    }));
    assert_eq!(report.type_name, ElfObjectTypeName::Core);
    assert_eq!(report.entries.len(), 4);

    let types: Vec<_> = report
        .entries
        .iter()
        .map(|entry| (entry.note_type, entry.type_name))
        .collect();
    assert_eq!(
        types,
        [
            (3, ElfNoteTypeName::CorePrpsinfo),
            (0x4649_4c45, ElfNoteTypeName::CoreFile),
            (0x5349_4749, ElfNoteTypeName::CoreSiginfo),
            (6, ElfNoteTypeName::CoreAuxv),
        ]
    );
    assert_eq!(
        core_entry(&report.entries[0]),
        &ElfCoreNote {
            prpsinfo: Some(CorePrpsinfo {
                state: 0,
                pid: 4242,
                ppid: 1,
                pgrp: 4242,
                sid: 4242,
                uid: 1001,
                gid: 1002,
                filename: "test-proc".to_owned(),
                psargs: "/usr/bin/test-proc --daemon -v".to_owned(),
            }),
            file: None,
            siginfo: None,
            auxv: None,
        }
    );
    assert_eq!(
        core_entry(&report.entries[1]),
        &ElfCoreNote {
            prpsinfo: None,
            file: Some(CoreFile {
                count: 2,
                page_size: 4096,
                mappings: vec![
                    mapping(0x40_0000, 0x40_5000, 0, "/usr/bin/test-proc"),
                    mapping(
                        0x7fff_0000,
                        0x7fff_2000,
                        10,
                        "/lib/x86_64-linux-gnu/libc.so.6"
                    ),
                ],
            }),
            siginfo: None,
            auxv: None,
        }
    );
    assert_eq!(
        core_entry(&report.entries[2]),
        &ElfCoreNote {
            prpsinfo: None,
            file: None,
            siginfo: Some(CoreSiginfo {
                signo: 11,
                code: 1,
                errno: 0,
            }),
            auxv: None,
        }
    );
    assert_eq!(
        core_entry(&report.entries[3]),
        &ElfCoreNote {
            prpsinfo: None,
            file: None,
            siginfo: None,
            auxv: Some(auxv(&[
                (6, Some("AT_PAGESZ"), 0x1000),
                (3, Some("AT_PHDR"), 0x40_0040),
                (9, Some("AT_ENTRY"), 0x40_1000),
                (999, None, 0x1234),
            ])),
        }
    );
}

#[test]
fn decodes_linux_core_notes_for_32_bit_big_endian() {
    let notes = [
        core_prpsinfo_note(&PrpsinfoOptions {
            bits: Bits::Elf32,
            little: false,
            state: 1,
            pid: 123,
            ppid: 1,
            pgrp: 123,
            sid: 123,
            uid: 500,
            gid: 500,
            fname: "proc32",
            psargs: "proc32 arg",
            ..PrpsinfoOptions::default()
        }),
        core_file_note(
            &[CoreMapping {
                start: 0x1_0000,
                end: 0x1_2000,
                file_ofs: 0,
                path: "/bin/proc32",
            }],
            4096,
            Bits::Elf32,
            false,
        ),
        core_auxv_note(&[(6, 4096), (11, 500)], Bits::Elf32, false),
    ]
    .concat();
    let report = parse(&image(ImageOptions {
        bits: Bits::Elf32,
        little: false,
        object_type: 4,
        ownership: Ownership::Program,
        notes: Some(notes),
        ..ImageOptions::default()
    }));
    assert_eq!(report.entries.len(), 3);
    assert_eq!(
        core_entry(&report.entries[0]).prpsinfo,
        Some(CorePrpsinfo {
            state: 1,
            pid: 123,
            ppid: 1,
            pgrp: 123,
            sid: 123,
            uid: 500,
            gid: 500,
            filename: "proc32".to_owned(),
            psargs: "proc32 arg".to_owned(),
        })
    );
    assert_eq!(
        core_entry(&report.entries[1]).file,
        Some(CoreFile {
            count: 1,
            page_size: 4096,
            mappings: vec![mapping(0x1_0000, 0x1_2000, 0, "/bin/proc32")],
        })
    );
    assert_eq!(
        core_entry(&report.entries[2]).auxv,
        Some(auxv(&[
            (6, Some("AT_PAGESZ"), 0x1000),
            (11, Some("AT_UID"), 0x1f4),
        ]))
    );
}

#[test]
fn tolerates_malformed_core_notes_by_returning_null() {
    let notes = [
        elf_note("CORE", 3, &[0; 20]),
        elf_note(
            "CORE",
            0x4649_4c45,
            &hex("00000000000000010000000000001000"),
        ),
        elf_note("CORE", 0x5349_4749, &[0; 4]),
        elf_note("CORE", 6, &hex("00000000000000060000000000001000")),
        elf_note("CORE", 6, &[0; 7]),
    ]
    .concat();
    let report = parse(&program_image(notes));
    let decoded: Vec<_> = report
        .entries
        .iter()
        .map(|entry| (entry.type_name, entry.core.is_some()))
        .collect();
    assert_eq!(
        decoded,
        [
            (ElfNoteTypeName::CorePrpsinfo, false),
            (ElfNoteTypeName::CoreFile, false),
            (ElfNoteTypeName::CoreSiginfo, false),
            (ElfNoteTypeName::CoreAuxv, false),
            (ElfNoteTypeName::CoreAuxv, false),
        ]
    );
}

#[test]
fn decodes_siginfo_using_the_mips_target_abi() {
    let mut desc = vec![0u8; 128];
    put32(&mut desc, 0, 11, true);
    put32(&mut desc, 4, 1, true);
    put32(&mut desc, 8, 0, true);
    let report = parse(&image(ImageOptions {
        bits: Bits::Elf32,
        machine: 8,
        ownership: Ownership::Program,
        notes: Some(elf_note_with("CORE", 0x5349_4749, &desc, true, 4)),
        ..ImageOptions::default()
    }));
    assert_eq!(
        core_entry(&report.entries[0]).siginfo,
        Some(CoreSiginfo {
            signo: 11,
            code: 1,
            errno: 0,
        })
    );
}

#[test]
fn preserves_negative_process_ids_and_signal_numbers() {
    let notes = [
        core_prpsinfo_note(&PrpsinfoOptions {
            pid: -1,
            ppid: -1,
            pgrp: -1,
            sid: -1,
            ..PrpsinfoOptions::default()
        }),
        core_siginfo_note(-1, -2, -3, true),
    ]
    .concat();
    let report = parse(&program_image(notes));
    let prpsinfo = core_entry(&report.entries[0]).prpsinfo.clone().unwrap();
    assert_eq!(
        (prpsinfo.pid, prpsinfo.ppid, prpsinfo.pgrp, prpsinfo.sid),
        (-1, -1, -1, -1)
    );
    assert_eq!(
        core_entry(&report.entries[1]).siginfo,
        Some(CoreSiginfo {
            signo: -1,
            code: -2,
            errno: -3,
        })
    );
}

#[test]
fn rejects_64_bit_auxv_tags_and_out_of_range_page_sizes_with_null_core() {
    let mut wide_tag_auxv = core_auxv_note(&[(6, 4096)], Bits::Elf64, true);
    put64(&mut wide_tag_auxv, 20, 0x1_0000_0000, true);
    let mut wide_page_size_file = core_file_note(
        &[CoreMapping {
            start: 0x40_0000,
            end: 0x40_1000,
            file_ofs: 0,
            path: "/bin/app",
        }],
        4096,
        Bits::Elf64,
        true,
    );
    put64(&mut wide_page_size_file, 28, 0x1_0000_0000, true);
    let report = parse(&program_image(
        [wide_tag_auxv, wide_page_size_file].concat(),
    ));
    assert_eq!(report.entries[0].core, None);
    assert_eq!(report.entries[1].core, None);
}

#[test]
fn does_not_spend_text_budget_on_malformed_nt_file_paths() {
    let mut header = vec![0u8; 16];
    put64(&mut header, 0, 2, true);
    put64(&mut header, 8, 4096, true);
    let descriptor = [
        header,
        vec![0; 48],
        latin1("/bin/app\0unterminated_path_without_null"),
    ]
    .concat();
    let report = parse(&program_image(elf_note("CORE", 0x4649_4c45, &descriptor)));
    assert_eq!(report.entries[0].core, None);
}

/// `upstream:tests/acceptance/elfNotesAbiEndian.test.ts`.
#[test]
fn preserves_big_endian_abi_facts() {
    let known = hex("00000000010203041020304080010203");
    let unknown = hex("01000000010203041020304080010203");
    let extended = [known.clone(), hex("01020304")].concat();
    let short = known[..12].to_vec();
    let descriptors = [&known, &unknown, &short, &extended, &known];
    for (bits, ownership, machine) in [
        (Bits::Elf32, Ownership::Program, 20),
        (Bits::Elf64, Ownership::Section, 21),
    ] {
        let mut notes: Vec<u8> = descriptors[..4]
            .iter()
            .flat_map(|descriptor| elf_note_with("GNU", 1, descriptor, false, 4))
            .collect();
        notes.extend(elf_note_with("OTHER", 1, &known, false, 4));
        let report = parse(&image(ImageOptions {
            bits,
            ownership,
            machine,
            little: false,
            notes: Some(notes),
            ..ImageOptions::default()
        }));
        assert_eq!(report.byte_order, ElfByteOrder::Big);
        assert_eq!(report.machine, u32::from(machine));
        assert_eq!(
            report.coverage,
            ElfNotesCoverage {
                status: ElfNotesCoverageStatus::Complete,
                examined_tables: 1,
                examined_entries: 5,
            }
        );
        let abi = |index: usize| {
            report.entries[index]
                .gnu
                .as_ref()
                .and_then(|gnu| gnu.abi_tag.clone())
        };
        assert_eq!(
            abi(0),
            Some(GnuAbiTag {
                os: 0,
                os_name: Some("linux".to_owned()),
                major: 0x0102_0304,
                minor: 0x1020_3040,
                subminor: 0x8001_0203,
            })
        );
        assert_eq!(
            abi(1),
            Some(GnuAbiTag {
                os: 0x0100_0000,
                os_name: None,
                major: 0x0102_0304,
                minor: 0x1020_3040,
                subminor: 0x8001_0203,
            })
        );
        assert_eq!(abi(2), None);
        assert_eq!(abi(3), None);
        assert!(report.entries[2].gnu.is_some());
        let other = &report.entries[4];
        assert_eq!(other.owner, "OTHER");
        assert_eq!(other.type_name, ElfNoteTypeName::Unknown);
        assert_eq!(other.gnu, None);
        for (entry, descriptor) in report.entries.iter().zip(descriptors) {
            assert_eq!(
                entry.descriptor.bytes,
                u32::try_from(descriptor.len()).unwrap()
            );
            assert_eq!(entry.descriptor.sha256, Sha256Digest::of(descriptor));
        }
    }
}

/// `upstream:tests/acceptance/elfNotesCore.test.ts`.
#[test]
fn decodes_core_dump_notes_end_to_end() {
    let notes = [
        core_prpsinfo_note(&PrpsinfoOptions {
            pid: 31337,
            ppid: 1,
            pgrp: 31337,
            sid: 31337,
            uid: 1000,
            gid: 1000,
            fname: "target-service",
            psargs: "/opt/target-service --worker 1",
            ..PrpsinfoOptions::default()
        }),
        core_file_note(
            &[
                CoreMapping {
                    start: 0x5555_5555_4000,
                    end: 0x5555_5555_8000,
                    file_ofs: 0,
                    path: "/opt/target-service",
                },
                CoreMapping {
                    start: 0x7fff_f7dc_0000,
                    end: 0x7fff_f7de_0000,
                    file_ofs: 0,
                    path: "/lib/x86_64-linux-gnu/libc.so.6",
                },
            ],
            4096,
            Bits::Elf64,
            true,
        ),
        core_siginfo_note(11, 1, 0, true),
        core_auxv_note(&[(6, 4096), (3, 0x5555_5555_4040)], Bits::Elf64, true),
    ]
    .concat();
    let bytes = image(ImageOptions {
        object_type: 4,
        ownership: Ownership::Program,
        notes: Some(notes),
        ..ImageOptions::default()
    });
    let report = parse(&bytes);
    assert_eq!(report.artifact.sha256, Sha256Digest::of(&bytes));
    assert_eq!(report.format, ElfNotesFormat::Elf64);
    assert_eq!(report.byte_order, ElfByteOrder::Little);
    assert_eq!(report.machine, 62);
    assert_eq!(
        report.coverage,
        ElfNotesCoverage {
            status: ElfNotesCoverageStatus::Complete,
            examined_tables: 1,
            examined_entries: 4,
        }
    );
    let file = core_entry(&report.entries[1]).file.clone().unwrap();
    assert_eq!(
        file.mappings,
        [
            mapping(0x5555_5555_4000, 0x5555_5555_8000, 0, "/opt/target-service"),
            mapping(
                0x7fff_f7dc_0000,
                0x7fff_f7de_0000,
                0,
                "/lib/x86_64-linux-gnu/libc.so.6"
            ),
        ]
    );
    let json = serde_json::to_value(&report.entries[1].core).unwrap();
    assert_eq!(
        json["file"]["mappings"][0]["start_address"],
        "0x555555554000"
    );
    assert_eq!(
        core_entry(&report.entries[3]).auxv,
        Some(auxv(&[
            (6, Some("AT_PAGESZ"), 0x1000),
            (3, Some("AT_PHDR"), 0x5555_5555_4040),
        ]))
    );
    let prpsinfo = core_entry(&report.entries[0]).prpsinfo.clone().unwrap();
    assert_eq!(prpsinfo.filename, "target-service");
    assert_eq!(prpsinfo.psargs, "/opt/target-service --worker 1");
    assert_eq!(
        core_entry(&report.entries[2]).siginfo,
        Some(CoreSiginfo {
            signo: 11,
            code: 1,
            errno: 0,
        })
    );
}

/// `upstream:tests/acceptance/elfNotesCli.test.ts`.
#[test]
fn keeps_gnu_notes_when_a_section_name_is_unreadable() {
    for (damage, limitation) in [
        (NameDamage::Outside, NAME_OUTSIDE),
        (NameDamage::Unterminated, NAME_UNTERMINATED),
    ] {
        let report = parse(&elf_note_with_unreadable_section_name_fixture(damage));
        assert_eq!(report.tables[0].name, None, "{damage:?}");
        assert_eq!(
            report.limitations,
            [SCOPE_LIMITATIONS[0], SCOPE_LIMITATIONS[1], limitation]
        );
        assert_eq!(build_id(&report.entries[0]), DEFAULT_BUILD_ID);
        assert_eq!(
            report.coverage,
            ElfNotesCoverage {
                status: ElfNotesCoverageStatus::Complete,
                examined_tables: 1,
                examined_entries: 1,
            }
        );
    }
}

/// `upstream:tests/acceptance/elfNotesCli.test.ts`.
#[test]
fn reports_a_truncated_elf_identification_as_malformed() {
    assert_eq!(
        failure(b"\x7fELF"),
        malformed("ELF identification is truncated")
    );
}

/// The reported artifact is the caller's, and every member serializes in
/// upstream's `elfNotesSchema` shape order.
#[test]
fn serializes_a_full_report_in_upstream_member_order() {
    let notes = [
        gnu_build_id_note(DEFAULT_BUILD_ID, true),
        gnu_abi_tag_note(true),
        elf_note("GNU", 4, b"gold 1.16\0"),
        core_prpsinfo_note(&PrpsinfoOptions::default()),
        core_file_note(
            &[CoreMapping {
                start: 0x40_0000,
                end: 0x40_1000,
                file_ofs: 0,
                path: "/bin/app",
            }],
            4096,
            Bits::Elf64,
            true,
        ),
        core_siginfo_note(11, 1, 0, true),
        core_auxv_note(&[(6, 4096)], Bits::Elf64, true),
    ]
    .concat();
    let bytes = image(ImageOptions {
        ownership: Ownership::Section,
        notes: Some(notes),
        ..ImageOptions::default()
    });
    let report = parse(&bytes);
    let json = serde_json::to_value(&report).unwrap();

    fn keys(value: &Value) -> Vec<&str> {
        value
            .as_object()
            .unwrap_or_else(|| panic!("not an object: {value}"))
            .keys()
            .map(String::as_str)
            .collect()
    }
    let range = ["offset", "bytes"];
    assert_eq!(
        keys(&json),
        [
            "artifact",
            "format",
            "byte_order",
            "machine",
            "type",
            "type_name",
            "tables",
            "entries",
            "coverage",
            "limitations",
        ]
    );
    assert_eq!(keys(&json["artifact"]), ["path", "sha256", "bytes"]);
    assert_eq!(json["artifact"]["path"], PATH);
    assert_eq!(
        json["artifact"]["sha256"],
        Sha256Digest::of(&bytes).to_string()
    );
    assert_eq!(json["format"], "elf64");
    assert_eq!(json["type_name"], "shared");
    let table = &json["tables"][0];
    assert_eq!(
        keys(table),
        ["kind", "index", "name", "location", "alignment"]
    );
    assert_eq!(keys(&table["location"]), range);
    assert_eq!(
        keys(&json["coverage"]),
        ["status", "examined_tables", "examined_entries"]
    );
    assert_eq!(json["coverage"]["status"], "complete");

    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 7);
    for entry in entries {
        assert_eq!(
            keys(entry),
            [
                "index",
                "table_kind",
                "table_index",
                "location",
                "namesz",
                "descsz",
                "type",
                "type_name",
                "owner",
                "owner_bytes_hex",
                "descriptor",
                "gnu",
                "core",
            ]
        );
        assert_eq!(keys(&entry["location"]), range);
        assert_eq!(
            keys(&entry["descriptor"]),
            ["location", "bytes", "sha256", "hex"]
        );
        assert_eq!(keys(&entry["descriptor"]["location"]), range);
        if entry["gnu"].is_object() {
            assert_eq!(
                keys(&entry["gnu"]),
                ["build_id_hex", "abi_tag", "gold_version"]
            );
            assert!(entry["core"].is_null());
        }
        if entry["core"].is_object() {
            assert_eq!(
                keys(&entry["core"]),
                ["prpsinfo", "file", "siginfo", "auxv"]
            );
            assert!(entry["gnu"].is_null());
        }
    }
    assert_eq!(entries[0]["gnu"]["build_id_hex"], DEFAULT_BUILD_ID);
    assert!(entries[0]["gnu"]["abi_tag"].is_null());
    assert!(entries[0]["gnu"]["gold_version"].is_null());
    assert_eq!(
        keys(&entries[1]["gnu"]["abi_tag"]),
        ["os", "os_name", "major", "minor", "subminor"]
    );
    assert_eq!(entries[2]["gnu"]["gold_version"], "gold 1.16");
    assert_eq!(entries[2]["type_name"], "gnu_gold_version");
    assert_eq!(
        keys(&entries[3]["core"]["prpsinfo"]),
        [
            "state", "pid", "ppid", "pgrp", "sid", "uid", "gid", "filename", "psargs"
        ]
    );
    assert_eq!(
        keys(&entries[4]["core"]["file"]),
        ["count", "page_size", "mappings"]
    );
    assert_eq!(
        keys(&entries[4]["core"]["file"]["mappings"][0]),
        [
            "start_address",
            "end_address",
            "file_offset_pages",
            "path",
            "path_hex"
        ]
    );
    assert_eq!(
        keys(&entries[5]["core"]["siginfo"]),
        ["signo", "code", "errno"]
    );
    assert_eq!(
        keys(&entries[6]["core"]["auxv"][0]),
        ["type", "type_name", "value"]
    );
    assert_eq!(entries[6]["core"]["auxv"][0]["value"], "0x1000");
    assert_eq!(entries[0]["owner_bytes_hex"], "474e5500");
    assert_eq!(
        entries[0]["descriptor"]["hex"], DEFAULT_BUILD_ID,
        "descriptors of at most 64 bytes carry hex"
    );
    assert!(entries[3]["descriptor"]["hex"].is_null());

    let round_trip: ElfNotes = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(round_trip, report);
    assert_eq!(serde_json::to_value(&round_trip).unwrap(), json);
}
