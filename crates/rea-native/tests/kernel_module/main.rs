//! `parse_kernel_module` behavior ported from
//! `upstream:src/native/elf/KernelModuleParser.test.ts`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fixture;

use std::time::{Duration, Instant};

use fixture::{
    Bits, DEFAULT_PKCS7, KernelModuleOptions, Part, compressed_kernel_module_container,
    kernel_module_fixture, module_signature_trailer, modversion_entry,
};
use rea_domain::digest::Sha256Digest;
use rea_domain::native::elf::{
    ElfByteOrder, ElfFormat, ElfObjectTypeName, HexBytes, InspectedArtifact,
};
use rea_domain::native::kernel_module::{
    CompressionStatus, InspectKernelModuleInput, KernelModule, KernelModuleApplicability,
    KernelModuleCodec, KernelModuleCompression, KernelModuleCoverage, KernelModuleCoverageStatus,
    KernelModuleEntryStatus, KernelModuleSectionStatus, KernelModuleVersionLayout, KernelSymbolCrc,
    KsymtabSectionReason, MODULE_SIGNATURE_MAGIC, ModinfoEntryReason, ModinfoSectionReason,
    ModuleSignatureStatus, NextProbeOperation, SignatureReason, SizedSectionStatus,
    ThisModuleStatus, UndecodedLayout, VersionEntryReason, VersionSectionReason,
};
use rea_native::elf::{KernelModuleFailure, parse_kernel_module};

const PATH: &str = "/artifacts/demo.ko";

fn input(max_entries: Option<u64>) -> InspectKernelModuleInput {
    let mut input = InspectKernelModuleInput::new(PATH);
    if let Some(max_entries) = max_entries {
        input.max_entries = max_entries;
    }
    let raw = serde_json::to_value(&input).unwrap();
    assert_eq!(
        InspectKernelModuleInput::parse(Some(&raw)),
        Ok(input.clone())
    );
    input
}

fn try_parse(bytes: &[u8], max_entries: Option<u64>) -> Result<KernelModule, KernelModuleFailure> {
    let artifact = InspectedArtifact {
        path: PATH.into(),
        sha256: Sha256Digest::of(b"artifact"),
        bytes: u32::try_from(bytes.len()).unwrap(),
    };
    let report = parse_kernel_module(bytes, artifact, &input(max_entries))?;
    // The contract round-trip stands in for upstream's `kernelModuleSchema.parse`.
    let value = serde_json::to_value(&report).unwrap();
    let reparsed: KernelModule = serde_json::from_value(value).unwrap();
    assert_eq!(reparsed, report);
    Ok(report)
}

fn parse(bytes: &[u8]) -> KernelModule {
    try_parse(bytes, None).unwrap_or_else(|failure| panic!("parse failed: {failure:?}"))
}

fn module(options: KernelModuleOptions) -> Vec<u8> {
    kernel_module_fixture(&options)
}

fn default_module() -> Vec<u8> {
    module(KernelModuleOptions::default())
}

fn put32le(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64le(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// ELF64 section header `index` of a default fixture.
fn section_header(index: usize) -> usize {
    64 + 64 * index
}

fn modinfo_pairs(report: &KernelModule) -> Vec<(Option<String>, Option<String>)> {
    report
        .modinfo
        .as_ref()
        .unwrap()
        .entries
        .iter()
        .map(|entry| (entry.key.clone(), entry.value.clone()))
        .collect()
}

fn pair(key: &str, value: &str) -> (Option<String>, Option<String>) {
    (Some(key.into()), Some(value.into()))
}

fn first_modinfo_key(report: &KernelModule) -> Option<String> {
    report.modinfo.as_ref().unwrap().entries[0].key.clone()
}

#[test]
fn preserves_parameter_duplicates_embedded_equals_and_original_entry_bytes() {
    let records = [
        "parm=level:verbosity=a",
        "parmtype=level:int",
        "parm=level:again",
    ];
    let modinfo = format!("{}\0", records.join("\0")).into_bytes();
    let report = parse(&module(KernelModuleOptions {
        modinfo: Part::Bytes(modinfo),
        ..Default::default()
    }));
    let observed: Vec<_> = report
        .modinfo
        .unwrap()
        .entries
        .into_iter()
        .map(|entry| (entry.key, entry.value, entry.raw_hex))
        .collect();
    let expected: Vec<_> = records
        .iter()
        .map(|record| {
            let (key, value) = record.split_once('=').unwrap();
            (
                Some(key.to_owned()),
                Some(value.to_owned()),
                Some(HexBytes(format!("{record}\0").into_bytes())),
            )
        })
        .collect();
    assert_eq!(observed, expected);
}

#[test]
fn distinguishes_absent_metadata_from_unavailable_section_names() {
    let absent = parse(&module(KernelModuleOptions {
        modinfo: Part::Omitted,
        versions: Part::Omitted,
        ..Default::default()
    }));
    assert_eq!(
        absent.modinfo.unwrap().status,
        KernelModuleSectionStatus::Absent
    );
    assert_eq!(
        absent.versions.unwrap().status,
        KernelModuleSectionStatus::Absent
    );
    let mut bytes = default_module();
    bytes[62..64].copy_from_slice(&0_u16.to_le_bytes());
    let unknown = parse(&bytes);
    assert_eq!(
        unknown.modinfo.unwrap().status,
        KernelModuleSectionStatus::Unknown
    );
    assert_eq!(
        unknown.versions.unwrap().status,
        KernelModuleSectionStatus::Unknown
    );
}

#[test]
fn reports_et_rel_modules_for_every_class_and_byte_order() {
    for (bits, little) in [
        (Bits::Elf64, true),
        (Bits::Elf64, false),
        (Bits::Elf32, true),
        (Bits::Elf32, false),
    ] {
        let report = parse(&module(KernelModuleOptions {
            bits,
            little,
            ..Default::default()
        }));
        let wide = bits == Bits::Elf64;
        assert_eq!(
            report.format,
            Some(if wide {
                ElfFormat::Elf64
            } else {
                ElfFormat::Elf32
            })
        );
        assert_eq!(
            report.byte_order,
            Some(if little {
                ElfByteOrder::Little
            } else {
                ElfByteOrder::Big
            })
        );
        assert_eq!(report.machine, Some(if wide { 62 } else { 20 }));
        assert_eq!(report.object_type, Some(1));
        assert_eq!(report.type_name, Some(ElfObjectTypeName::Relocatable));
        assert_eq!(report.applicability, KernelModuleApplicability::Applicable);
        assert_eq!(report.compression, None);
        assert_eq!(report.next_probe, None);
        assert_eq!(
            report.coverage,
            KernelModuleCoverage {
                status: KernelModuleCoverageStatus::Complete,
                examined_entries: 9,
            }
        );
        assert_eq!(
            modinfo_pairs(&report),
            [
                pair("license", "GPL"),
                pair("vermagic", "5.15.0 SMP mod_unload"),
                pair("alias", "pci:v1"),
                pair("alias", "pci:v2"),
                pair("name", "demo"),
                pair("depends", ""),
            ]
        );
        let modinfo = report.modinfo.as_ref().unwrap();
        assert!(
            modinfo
                .entries
                .iter()
                .all(|entry| entry.status == KernelModuleEntryStatus::Observed)
        );
        let versions = report.versions.as_ref().unwrap();
        assert_eq!(
            versions.layout,
            Some(if wide {
                KernelModuleVersionLayout::Elf64UnsignedLongName56
            } else {
                KernelModuleVersionLayout::Elf32UnsignedLongName60
            })
        );
        let crcs: Vec<_> = versions
            .entries
            .iter()
            .map(|entry| (entry.crc_hex.to_string(), entry.name.clone().unwrap()))
            .collect();
        let width = if wide { 16 } else { 8 };
        assert_eq!(
            crcs,
            [
                (format!("{:0>width$}", "12345678"), "printk".to_owned()),
                (
                    format!("{:0>width$}", "90abcdef"),
                    "module_layout".to_owned()
                ),
            ]
        );
        let this_module = report.this_module.as_ref().unwrap();
        assert_eq!(this_module.status, ThisModuleStatus::Present);
        assert_eq!(this_module.layout, UndecodedLayout::Unknown);
        assert_eq!(this_module.location.unwrap().bytes, 8);
        let ksymtab = report.ksymtab.as_ref().unwrap();
        let names: Vec<_> = ksymtab.sections.iter().map(|s| s.name.as_deref()).collect();
        assert_eq!(names, [Some("__ksymtab")]);
        let init_text = report.init_text.as_ref().unwrap();
        assert_eq!(
            (init_text.status, init_text.bytes),
            (SizedSectionStatus::Present, Some(4))
        );
        let exit_text = report.exit_text.as_ref().unwrap();
        assert_eq!(
            (exit_text.status, exit_text.bytes),
            (SizedSectionStatus::Present, Some(1))
        );
        let signature = report.signature.as_ref().unwrap();
        assert_eq!(signature.status, ModuleSignatureStatus::Present);
        assert_eq!(signature.reason, None);
        let pkcs7 = signature.pkcs7.as_ref().unwrap();
        assert_eq!(pkcs7.location.bytes as usize, DEFAULT_PKCS7.len());
        assert_eq!(pkcs7.sha256, Sha256Digest::of(DEFAULT_PKCS7));
        let info = signature.info.as_ref().unwrap();
        assert_eq!(
            (info.algo, info.hash, info.id_type, info.sig_len as usize),
            (0, 0, 2, DEFAULT_PKCS7.len())
        );
    }
}

#[test]
fn keeps_earlier_modinfo_entries_when_the_last_span_is_unterminated() {
    let report = parse(&module(KernelModuleOptions {
        modinfo: Part::Bytes(b"license=GPL\0alias=pci:v3".to_vec()),
        ..Default::default()
    }));
    let modinfo = report.modinfo.unwrap();
    assert_eq!(modinfo.status, KernelModuleSectionStatus::Present);
    let reasons: Vec<_> = modinfo.entries.iter().map(|entry| entry.reason).collect();
    assert_eq!(
        reasons,
        [None, Some(ModinfoEntryReason::UnterminatedModinfoEntry)]
    );
    let last = &modinfo.entries[1];
    assert_eq!(last.status, KernelModuleEntryStatus::Malformed);
    assert_eq!(last.key.as_deref(), Some("alias"));
    assert_eq!(last.value.as_deref(), Some("pci:v3"));
}

#[test]
fn reports_a_missing_separator_an_empty_key_and_an_over_long_field_per_entry() {
    let modinfo = [
        b"license\0=GPL\0".to_vec(),
        format!("{}=x\0", "k".repeat(257)).into_bytes(),
        format!("name={}\0", "v".repeat(4097)).into_bytes(),
    ]
    .concat();
    let report = parse(&module(KernelModuleOptions {
        modinfo: Part::Bytes(modinfo),
        ..Default::default()
    }));
    let entries = report.modinfo.unwrap().entries;
    let reasons: Vec<_> = entries.iter().map(|entry| entry.reason).collect();
    assert_eq!(
        reasons,
        [
            Some(ModinfoEntryReason::ModinfoMissingSeparator),
            Some(ModinfoEntryReason::ModinfoEmptyKey),
            Some(ModinfoEntryReason::ModinfoFieldExceedsLimit),
            Some(ModinfoEntryReason::ModinfoFieldExceedsLimit),
        ]
    );
    assert_eq!(
        (entries[1].key.as_deref(), entries[1].value.as_deref()),
        (None, Some("GPL"))
    );
    assert_eq!(
        (entries[2].key.as_deref(), entries[2].value.as_deref()),
        (None, Some("x"))
    );
    assert_eq!(
        (entries[3].key.as_deref(), entries[3].value.as_deref()),
        (Some("name"), None)
    );
}

#[test]
fn closes_versions_when_the_section_size_is_not_a_multiple_of_64() {
    let report = parse(&module(KernelModuleOptions {
        versions: Part::Bytes(vec![0; 63]),
        ..Default::default()
    }));
    let versions = report.versions.as_ref().unwrap();
    assert_eq!(versions.status, KernelModuleSectionStatus::Malformed);
    assert!(versions.entries.is_empty());
    assert_eq!(
        versions.reason,
        Some(VersionSectionReason::VersionsSizeNotMultiple)
    );
    assert_eq!(
        versions.layout,
        Some(KernelModuleVersionLayout::Elf64UnsignedLongName56)
    );
    assert_eq!(
        serde_json::to_value(versions.entry_bytes).unwrap(),
        serde_json::json!(64)
    );
    assert_eq!(
        report.coverage.examined_entries as usize,
        report.modinfo.unwrap().entries.len() + report.ksymtab.unwrap().sections.len()
    );
}

#[test]
fn observes_a_version_name_with_nonzero_padding_and_rejects_a_missing_nul() {
    let mut padded = modversion_entry(0x1234_5678, "printk", Bits::Elf64, true);
    padded[8 + "printk".len() + 1] = 0x7f;
    let mut unterminated = vec![0x41; 64];
    put64le(&mut unterminated, 0, 0x11);
    let report = parse(&module(KernelModuleOptions {
        versions: Part::Bytes([padded, unterminated].concat()),
        ..Default::default()
    }));
    let entries = report.versions.unwrap().entries;
    assert_eq!(entries[0].status, KernelModuleEntryStatus::Observed);
    assert_eq!(entries[0].name.as_deref(), Some("printk"));
    assert_eq!(entries[0].reason, None);
    assert_eq!(entries[0].crc_hex, KernelSymbolCrc::Elf64(0x1234_5678));
    assert_eq!(entries[0].crc_hex.to_string(), "0000000012345678");
    assert_eq!(entries[1].status, KernelModuleEntryStatus::Malformed);
    assert_eq!(entries[1].name, None);
    assert_eq!(
        entries[1].reason,
        Some(VersionEntryReason::VersionNameUnterminated)
    );
    assert_eq!(entries[1].crc_hex.to_string(), "0000000000000011");
}

#[test]
fn reports_an_inconsistent_signature_length_without_a_pkcs7_range() {
    let report = parse(&module(KernelModuleOptions {
        signature: Part::Bytes(module_signature_trailer(b"abcd", Some(50_000))),
        ..Default::default()
    }));
    let signature = report.signature.as_ref().unwrap();
    assert_eq!(signature.status, ModuleSignatureStatus::Malformed);
    assert_eq!(
        signature.reason,
        Some(SignatureReason::SignatureLengthInconsistent)
    );
    assert_eq!(signature.pkcs7, None);
    let info = signature.info.as_ref().unwrap();
    assert_eq!((info.sig_len, info.id_type), (50_000, 2));
    assert_eq!(first_modinfo_key(&report).as_deref(), Some("license"));
}

#[test]
fn withholds_pkcs7_bytes_for_nonzero_signature_parameters_and_a_non_pkcs7_id() {
    let mut nonzero = [0_u8; 12];
    nonzero[0] = 1;
    nonzero[2] = 2;
    nonzero[8..12].copy_from_slice(&4_u32.to_be_bytes());
    let mut other_id = [0_u8; 12];
    other_id[0] = 1;
    other_id[3] = 2;
    other_id[2] = 1;
    other_id[8..12].copy_from_slice(&4_u32.to_be_bytes());
    let signed = |info: &[u8]| {
        parse(&module(KernelModuleOptions {
            signature: Part::Bytes([b"abcd", info, MODULE_SIGNATURE_MAGIC].concat()),
            ..Default::default()
        }))
        .signature
        .unwrap()
    };
    let nonzero = signed(&nonzero);
    assert_eq!(nonzero.status, ModuleSignatureStatus::Malformed);
    assert_eq!(
        nonzero.reason,
        Some(SignatureReason::SignatureParametersNonzero)
    );
    assert_eq!(nonzero.pkcs7, None);
    let other_id = signed(&other_id);
    assert_eq!(other_id.status, ModuleSignatureStatus::Unsupported);
    assert_eq!(
        other_id.reason,
        Some(SignatureReason::SignatureIdTypeNotPkcs7)
    );
    assert_eq!(other_id.pkcs7, None);
    assert_eq!(other_id.info.unwrap().id_type, 1);
}

#[test]
fn does_not_examine_kernel_metadata_on_a_non_relocatable_elf() {
    let report = parse(&module(KernelModuleOptions {
        object_type: 2,
        ..Default::default()
    }));
    assert_eq!(
        report.applicability,
        KernelModuleApplicability::NotApplicable
    );
    assert_eq!(report.object_type, Some(2));
    assert_eq!(report.type_name, Some(ElfObjectTypeName::Executable));
    assert_eq!(report.modinfo, None);
    assert_eq!(report.versions, None);
    assert_eq!(report.signature, None);
    assert_eq!(
        report.coverage,
        KernelModuleCoverage {
            status: KernelModuleCoverageStatus::NotApplicable,
            examined_entries: 0,
        }
    );
}

#[test]
fn recommends_external_decompression_for_compressed_containers() {
    for codec in [
        KernelModuleCodec::Gzip,
        KernelModuleCodec::Xz,
        KernelModuleCodec::Zstd,
    ] {
        let report = parse(&compressed_kernel_module_container(codec));
        assert_eq!(report.applicability, KernelModuleApplicability::Unsupported);
        assert_eq!(report.format, None);
        assert_eq!(
            report.compression,
            Some(KernelModuleCompression {
                codec,
                status: CompressionStatus::Unsupported,
            })
        );
        let next_probe = report.next_probe.as_ref().unwrap();
        assert_eq!(
            next_probe.operation,
            NextProbeOperation::ExternalDecompression
        );
        assert_eq!(report.modinfo, None);
        assert_eq!(
            report.coverage,
            KernelModuleCoverage {
                status: KernelModuleCoverageStatus::Unsupported,
                examined_entries: 0,
            }
        );
        let rationale = &next_probe.rationale;
        assert!(rationale.contains(codec.as_str()), "{rationale}");
        assert!(rationale.contains("external"), "{rationale}");
        assert!(
            rationale.contains("call inspect_kernel_module on the decompressed file"),
            "{rationale}"
        );
        let mut value = serde_json::to_value(&report).unwrap();
        value["next_probe"]["operation"] = "extract_artifact".into();
        assert!(serde_json::from_value::<KernelModule>(value).is_err());
    }
}

#[test]
fn fails_closed_when_the_combined_entry_budget_is_exhausted() {
    assert_eq!(
        try_parse(&default_module(), Some(7)),
        Err(KernelModuleFailure::Capacity { max_entries: 7 })
    );
}

#[test]
fn examines_the_first_of_two_modinfo_sections_and_records_the_duplicate() {
    let report = parse(&module(KernelModuleOptions {
        repeat_modinfo: true,
        ..Default::default()
    }));
    assert_eq!(report.modinfo.unwrap().entries.len(), 6);
    assert!(
        report
            .limitations
            .join("\n")
            .contains("Multiple .modinfo sections are declared; the first is examined.")
    );
}

#[test]
fn does_not_decode_compressed_nobits_or_out_of_file_metadata_sections() {
    let modinfo = section_header(1);
    let versions = section_header(2);
    let this_module = section_header(3);

    let mut compressed = default_module();
    put64le(&mut compressed, modinfo + 8, 0x800);
    let report = parse(&compressed).modinfo.unwrap();
    assert_eq!(report.status, KernelModuleSectionStatus::Unsupported);
    assert!(report.entries.is_empty());
    assert_eq!(
        report.reason,
        Some(ModinfoSectionReason::ModinfoSectionCompressed)
    );

    let mut nobits = default_module();
    put32le(&mut nobits, modinfo + 4, 8);
    let report = parse(&nobits).modinfo.unwrap();
    assert_eq!(report.status, KernelModuleSectionStatus::Malformed);
    assert_eq!(report.location, None);
    assert!(report.entries.is_empty());
    assert_eq!(
        report.reason,
        Some(ModinfoSectionReason::ModinfoSectionNotFileBacked)
    );

    let mut outside = default_module();
    put64le(&mut outside, modinfo + 24, 1_000_000);
    let report = parse(&outside).modinfo.unwrap();
    assert_eq!(report.status, KernelModuleSectionStatus::Malformed);
    assert_eq!(
        report.reason,
        Some(ModinfoSectionReason::ModinfoSectionNotFileBacked)
    );

    let mut versions_outside = default_module();
    put64le(&mut versions_outside, versions + 24, 1_000_000);
    let report = parse(&versions_outside).versions.unwrap();
    assert_eq!(report.status, KernelModuleSectionStatus::Malformed);
    assert!(report.entries.is_empty());
    assert_eq!(
        report.reason,
        Some(VersionSectionReason::VersionsSectionNotFileBacked)
    );

    let mut versions_compressed = default_module();
    put64le(&mut versions_compressed, versions + 8, 0x800);
    let report = parse(&versions_compressed).versions.unwrap();
    assert_eq!(report.status, KernelModuleSectionStatus::Unsupported);
    assert!(report.entries.is_empty());
    assert_eq!(
        report.reason,
        Some(VersionSectionReason::VersionsSectionCompressed)
    );

    let mut versions_nobits = default_module();
    put32le(&mut versions_nobits, versions + 4, 8);
    let report = parse(&versions_nobits).versions.unwrap();
    assert_eq!(report.status, KernelModuleSectionStatus::Malformed);
    assert_eq!(report.location, None);
    assert!(report.entries.is_empty());
    assert_eq!(
        report.reason,
        Some(VersionSectionReason::VersionsSectionNotFileBacked)
    );

    let mut module_section = default_module();
    put32le(&mut module_section, this_module + 4, 8);
    let report = parse(&module_section).this_module.unwrap();
    assert_eq!(report.status, ThisModuleStatus::Present);
    assert_eq!(report.location, None);
    assert_eq!(report.layout, UndecodedLayout::Unknown);
}

#[test]
fn rejects_a_non_elf_file_that_is_not_a_recognized_container() {
    assert_eq!(
        try_parse(b"not an elf", None),
        Err(KernelModuleFailure::Malformed {
            message: "Native directory range is truncated or outside the file".into(),
        })
    );
}

#[test]
fn rejects_elf_bytes_preceding_a_bare_signature_magic_as_an_inconsistent_trailer() {
    let report = parse(&module(KernelModuleOptions {
        signature: Part::Bytes(MODULE_SIGNATURE_MAGIC.to_vec()),
        ..Default::default()
    }));
    let signature = report.signature.as_ref().unwrap();
    assert_eq!(signature.status, ModuleSignatureStatus::Malformed);
    assert_eq!(
        signature.reason,
        Some(SignatureReason::SignatureLengthInconsistent)
    );
    assert_eq!(signature.pkcs7, None);
    assert_eq!(first_modinfo_key(&report).as_deref(), Some("license"));
}

#[test]
fn records_a_missing_trailer_as_observed_absence() {
    let report = parse(&module(KernelModuleOptions {
        signature: Part::Omitted,
        ..Default::default()
    }));
    let signature = report.signature.as_ref().unwrap();
    assert_eq!(signature.status, ModuleSignatureStatus::Absent);
    assert_eq!(signature.magic, None);
    assert_eq!(signature.info, None);
    assert_eq!(signature.pkcs7, None);
    assert_eq!(signature.reason, None);
    assert!(
        report
            .limitations
            .join("\n")
            .contains("not proof the module is unsigned")
    );
}

#[test]
fn names_a_non_file_backed_ksymtab_section_without_dropping_the_module() {
    let mut bytes = default_module();
    put32le(&mut bytes, section_header(4) + 4, 8);
    let report = parse(&bytes);
    assert!(report.ksymtab.as_ref().unwrap().sections.is_empty());
    assert!(
        report
            .limitations
            .join("\n")
            .contains("1 __ksymtab* section(s) are declared but not file-backed")
    );
    assert_eq!(first_modinfo_key(&report).as_deref(), Some("license"));
}

#[test]
fn charges_many_sections_sharing_one_huge_ksymtab_name_to_the_entry_budget() {
    let name = format!("__ksymtab_{}", "x".repeat(65_490)).into_bytes();
    let bytes = module(KernelModuleOptions {
        shared_name_sections: Some((name, 8192)),
        ..Default::default()
    });
    let started = Instant::now();
    assert_eq!(
        try_parse(&bytes, None),
        Err(KernelModuleFailure::Capacity { max_entries: 8192 })
    );
    let report = try_parse(&bytes, Some(65_536)).unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    let ksymtab = report.ksymtab.as_ref().unwrap();
    let huge = &ksymtab.sections[1..];
    assert_eq!(huge.len(), 8192);
    assert!(huge.iter().all(|section| section.name.is_none()
        && section.reason == Some(KsymtabSectionReason::KsymtabNameExceedsLimit)));
    assert_eq!(ksymtab.sections[0].name.as_deref(), Some("__ksymtab"));
    assert_eq!(ksymtab.sections[0].reason, None);
    assert_eq!(report.coverage.examined_entries, 6 + 2 + 1 + 8192);
    assert!(serde_json::to_string(&report).unwrap().len() < 2 * 1024 * 1024);
}
