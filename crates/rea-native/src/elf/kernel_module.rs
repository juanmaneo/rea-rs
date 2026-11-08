//! Linux kernel-module metadata from one in-memory `ET_REL` image.
//!
//! Upstream reference: `upstream:src/native/elf/KernelModuleParser.ts`.

use rea_domain::digest::Sha256Digest;
use rea_domain::native::elf::{
    ElfByteOrder, ElfFileRange, ElfFormat, ElfObjectTypeName, HexBytes, InspectedArtifact,
};
use rea_domain::native::kernel_module::{
    CompressionStatus, InspectKernelModuleInput, KERNEL_MODULE_VERSION_ENTRY_BYTES, KernelModule,
    KernelModuleApplicability, KernelModuleCodec, KernelModuleCompression, KernelModuleCoverage,
    KernelModuleCoverageStatus, KernelModuleEntryStatus, KernelModuleKsymtab, KernelModuleModinfo,
    KernelModuleNextProbe, KernelModuleSectionStatus, KernelModuleSizedSection,
    KernelModuleThisModule, KernelModuleVersionEntry, KernelModuleVersionEntryBytes,
    KernelModuleVersionLayout, KernelModuleVersions, KernelSymbolCrc, KsymtabSection,
    KsymtabSectionReason, KsymtabStatus, MAX_INSPECT_KERNEL_MODULE_FILE_BYTES,
    MAX_KERNEL_MODULE_KEY_BYTES, MAX_KERNEL_MODULE_RAW_BYTES, MAX_KERNEL_MODULE_SECTION_NAME_BYTES,
    MAX_KERNEL_MODULE_VALUE_BYTES, MODULE_SIGNATURE_INFO_BYTES, MODULE_SIGNATURE_MAGIC,
    MODULE_SIGNATURE_PKCS7_ID_TYPE, ModinfoEntry, ModinfoEntryReason, ModinfoSectionReason,
    ModuleSignature, ModuleSignatureInfo, ModuleSignaturePkcs7, ModuleSignatureStatus,
    NextProbeOperation, SignatureReason, SizedSectionStatus, ThisModuleStatus, UndecodedLayout,
    VersionEntryReason, VersionSectionReason,
};

use super::KernelModuleFailure;
use super::descriptors::latin1;
use super::header::ElfClass;
use super::image::{
    ElfImage, ElfImageFailure, ImageSection, SHT_NOBITS, file_range, read_elf_image,
};

const ET_REL: u16 = 1;
const GZIP: &[u8] = &[0x1f, 0x8b];
const XZ: &[u8] = &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
const ZSTD: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];

const BASE_LIMITATIONS: [&str; 5] = [
    "This workflow does not execute the module, resolve imported symbols, or validate an appended signature.",
    "struct module in .gnu.linkonce.this_module is kernel-version specific and is not decoded.",
    "__ksymtab entry layout is kernel-version specific and is not decoded.",
    "Only classic __versions records are decoded. Their absence does not establish the absence of CONFIG_EXTENDED_MODVERSIONS metadata in __version_ext_names and __version_ext_crcs.",
    "Metadata strings use a byte-preserving Latin1 projection; their original text encoding is unobserved.",
];

fn base_limitations() -> Vec<String> {
    BASE_LIMITATIONS
        .iter()
        .map(|&text| text.to_owned())
        .collect()
}

/// Offsets and lengths inside the image; `parse_kernel_module` refuses images
/// above the 512 MiB input ceiling first, so saturation is unreachable.
fn as_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

impl From<ElfImageFailure> for KernelModuleFailure {
    fn from(failure: ElfImageFailure) -> Self {
        match failure {
            ElfImageFailure::Malformed(message) => Self::Malformed { message },
            ElfImageFailure::Structure(message) => Self::Structure { message },
        }
    }
}

/// The shared `.modinfo`, `__versions`, and `__ksymtab*` entry budget.
struct Examined {
    count: u64,
    max_entries: u64,
}

impl Examined {
    fn admit(&self, count: u64) -> Result<(), KernelModuleFailure> {
        if count > self.max_entries {
            return Err(KernelModuleFailure::Capacity {
                max_entries: self.max_entries,
            });
        }
        Ok(())
    }
}

/// The section's file range, when it lies inside the image.
fn location(section: &ImageSection, file_bytes: usize) -> Option<ElfFileRange> {
    let range = file_range(file_bytes, section.offset, section.size)?;
    Some(ElfFileRange {
        offset: u32::try_from(range.start).ok()?,
        bytes: u32::try_from(range.len()).ok()?,
    })
}

fn stored(bytes: &[u8], range: ElfFileRange) -> &[u8] {
    let start = range.offset as usize;
    bytes
        .get(start..start + range.bytes as usize)
        .unwrap_or_default()
}

fn compression_codec(bytes: &[u8]) -> Option<KernelModuleCodec> {
    if bytes.starts_with(GZIP) {
        Some(KernelModuleCodec::Gzip)
    } else if bytes.starts_with(XZ) {
        Some(KernelModuleCodec::Xz)
    } else if bytes.starts_with(ZSTD) {
        Some(KernelModuleCodec::Zstd)
    } else {
        None
    }
}

/// Every member except the header facts, coverage, and limitations is null.
fn closed_report(
    artifact: InspectedArtifact,
    applicability: KernelModuleApplicability,
    coverage: KernelModuleCoverageStatus,
    limitations: Vec<String>,
) -> KernelModule {
    KernelModule {
        artifact,
        format: None,
        byte_order: None,
        machine: None,
        object_type: None,
        type_name: None,
        applicability,
        compression: None,
        next_probe: None,
        modinfo: None,
        versions: None,
        this_module: None,
        ksymtab: None,
        init_text: None,
        exit_text: None,
        signature: None,
        coverage: KernelModuleCoverage {
            status: coverage,
            examined_entries: 0,
        },
        limitations,
    }
}

fn unsupported_compression(artifact: InspectedArtifact, codec: KernelModuleCodec) -> KernelModule {
    let mut limitations = base_limitations();
    limitations.extend([
        "gzip, xz, and zstd kernel-module containers are not decoded. The existing ELF section decoder does not cover these whole-file codecs.".to_owned(),
        "A compressed container is not proof the payload is a kernel module.".to_owned(),
    ]);
    let name = codec.as_str();
    KernelModule {
        compression: Some(KernelModuleCompression {
            codec,
            status: CompressionStatus::Unsupported,
        }),
        next_probe: Some(KernelModuleNextProbe {
            operation: NextProbeOperation::ExternalDecompression,
            rationale: format!(
                "Decompress this {name} container with an external {name} utility into a separate file, then call inspect_kernel_module on the decompressed file. REA does not decode {name} containers."
            ),
        }),
        ..closed_report(
            artifact,
            KernelModuleApplicability::Unsupported,
            KernelModuleCoverageStatus::Unsupported,
            limitations,
        )
    }
}

fn absent_or_unknown(names_complete: bool) -> KernelModuleSectionStatus {
    if names_complete {
        KernelModuleSectionStatus::Absent
    } else {
        KernelModuleSectionStatus::Unknown
    }
}

fn parse_modinfo(
    bytes: &[u8],
    section: Option<&ImageSection>,
    names_complete: bool,
    examined: &mut Examined,
) -> Result<KernelModuleModinfo, KernelModuleFailure> {
    let closed = |status, location, sha256, reason| KernelModuleModinfo {
        status,
        location,
        sha256,
        entries: Vec::new(),
        reason: Some(reason),
    };
    let Some(section) = section else {
        return Ok(KernelModuleModinfo {
            status: absent_or_unknown(names_complete),
            location: None,
            sha256: None,
            entries: Vec::new(),
            reason: None,
        });
    };
    let found = location(section, bytes.len()).filter(|_| section.section_type != SHT_NOBITS);
    let Some(location) = found else {
        return Ok(closed(
            KernelModuleSectionStatus::Malformed,
            None,
            None,
            ModinfoSectionReason::ModinfoSectionNotFileBacked,
        ));
    };
    let stored = stored(bytes, location);
    if section.compressed {
        return Ok(closed(
            KernelModuleSectionStatus::Unsupported,
            Some(location),
            Some(Sha256Digest::of(stored)),
            ModinfoSectionReason::ModinfoSectionCompressed,
        ));
    }
    let mut entries = Vec::new();
    let mut at = 0;
    while let Some(rest) = stored.get(at..).filter(|rest| !rest.is_empty()) {
        if rest.first() == Some(&0) {
            at += 1;
            continue;
        }
        let end = rest.iter().position(|&byte| byte == 0);
        let (record, raw) = match end {
            Some(end) => (rest.split_at(end).0, rest.split_at(end + 1).0),
            None => (rest, rest),
        };
        examined.count += 1;
        examined.admit(examined.count)?;
        let mut reason = end
            .is_none()
            .then_some(ModinfoEntryReason::UnterminatedModinfoEntry);
        let (mut key, mut value) = (None, None);
        match record.iter().position(|&byte| byte == b'=') {
            None => {
                reason.get_or_insert(ModinfoEntryReason::ModinfoMissingSeparator);
            }
            Some(separator) => {
                let (key_bytes, rest) = record.split_at(separator);
                let value_bytes = rest.get(1..).unwrap_or_default();
                if key_bytes.is_empty() {
                    reason.get_or_insert(ModinfoEntryReason::ModinfoEmptyKey);
                }
                if key_bytes.len() > MAX_KERNEL_MODULE_KEY_BYTES
                    || value_bytes.len() > MAX_KERNEL_MODULE_VALUE_BYTES
                {
                    reason.get_or_insert(ModinfoEntryReason::ModinfoFieldExceedsLimit);
                }
                if (1..=MAX_KERNEL_MODULE_KEY_BYTES).contains(&key_bytes.len()) {
                    key = Some(latin1(key_bytes));
                }
                if value_bytes.len() <= MAX_KERNEL_MODULE_VALUE_BYTES {
                    value = Some(latin1(value_bytes));
                }
            }
        }
        entries.push(ModinfoEntry {
            index: as_u32(entries.len()),
            location: ElfFileRange {
                offset: location.offset + as_u32(at),
                bytes: as_u32(raw.len()),
            },
            key,
            value,
            raw_sha256: Sha256Digest::of(raw),
            raw_hex: (raw.len() <= MAX_KERNEL_MODULE_RAW_BYTES).then(|| HexBytes(raw.to_vec())),
            status: if reason.is_none() {
                KernelModuleEntryStatus::Observed
            } else {
                KernelModuleEntryStatus::Malformed
            },
            reason,
        });
        match end {
            Some(end) => at += end + 1,
            None => break,
        }
    }
    Ok(KernelModuleModinfo {
        status: KernelModuleSectionStatus::Present,
        location: Some(location),
        sha256: Some(Sha256Digest::of(stored)),
        entries,
        reason: None,
    })
}

fn parse_versions(
    bytes: &[u8],
    section: Option<&ImageSection>,
    image: &ElfImage<'_>,
    names_complete: bool,
    examined: &mut Examined,
) -> Result<KernelModuleVersions, KernelModuleFailure> {
    let (layout, crc_bytes) = match image.class {
        ElfClass::Elf64 => (KernelModuleVersionLayout::Elf64UnsignedLongName56, 8),
        ElfClass::Elf32 => (KernelModuleVersionLayout::Elf32UnsignedLongName60, 4),
    };
    let report = |status, location, sha256, entries, reason| KernelModuleVersions {
        status,
        layout: Some(layout),
        entry_bytes: Some(KernelModuleVersionEntryBytes),
        location,
        sha256,
        entries,
        reason,
    };
    let Some(section) = section else {
        return Ok(report(
            absent_or_unknown(names_complete),
            None,
            None,
            Vec::new(),
            None,
        ));
    };
    let found = location(section, bytes.len()).filter(|_| section.section_type != SHT_NOBITS);
    let Some(location) = found else {
        return Ok(report(
            KernelModuleSectionStatus::Malformed,
            None,
            None,
            Vec::new(),
            Some(VersionSectionReason::VersionsSectionNotFileBacked),
        ));
    };
    let stored = stored(bytes, location);
    let sha256 = Some(Sha256Digest::of(stored));
    if section.compressed {
        return Ok(report(
            KernelModuleSectionStatus::Unsupported,
            Some(location),
            sha256,
            Vec::new(),
            Some(VersionSectionReason::VersionsSectionCompressed),
        ));
    }
    let entry_bytes = KERNEL_MODULE_VERSION_ENTRY_BYTES as usize;
    if !stored.len().is_multiple_of(entry_bytes) {
        return Ok(report(
            KernelModuleSectionStatus::Malformed,
            Some(location),
            sha256,
            Vec::new(),
            Some(VersionSectionReason::VersionsSizeNotMultiple),
        ));
    }
    let count = (stored.len() / entry_bytes) as u64;
    examined.admit(examined.count + count)?;
    let endian = image.endian;
    let entries = stored
        .chunks_exact(entry_bytes)
        .enumerate()
        .map(|(index, record)| {
            let crc = match image.class {
                ElfClass::Elf64 => KernelSymbolCrc::Elf64(endian.u64(record, 0).unwrap_or(0)),
                ElfClass::Elf32 => KernelSymbolCrc::Elf32(endian.u32(record, 0).unwrap_or(0)),
            };
            let field = record.get(crc_bytes..).unwrap_or_default();
            let name = field
                .iter()
                .position(|&byte| byte == 0)
                .map(|end| latin1(field.split_at(end).0));
            KernelModuleVersionEntry {
                index: as_u32(index),
                location: ElfFileRange {
                    offset: location.offset + as_u32(index * entry_bytes),
                    bytes: KERNEL_MODULE_VERSION_ENTRY_BYTES,
                },
                crc_hex: crc,
                status: if name.is_some() {
                    KernelModuleEntryStatus::Observed
                } else {
                    KernelModuleEntryStatus::Malformed
                },
                reason: name
                    .is_none()
                    .then_some(VersionEntryReason::VersionNameUnterminated),
                name,
            }
        })
        .collect();
    examined.count += count;
    Ok(report(
        KernelModuleSectionStatus::Present,
        Some(location),
        sha256,
        entries,
        None,
    ))
}

fn this_module(
    section: Option<&ImageSection>,
    names_complete: bool,
    file_bytes: usize,
) -> KernelModuleThisModule {
    let (status, location) = match section {
        None if names_complete => (ThisModuleStatus::Absent, None),
        None => (ThisModuleStatus::Unknown, None),
        Some(section) => match location(section, file_bytes)
            .filter(|_| section.section_type != SHT_NOBITS)
        {
            None => (ThisModuleStatus::Present, None),
            Some(location) if section.compressed => (ThisModuleStatus::Unsupported, Some(location)),
            Some(location) => (ThisModuleStatus::Present, Some(location)),
        },
    };
    KernelModuleThisModule {
        status,
        location,
        layout: UndecodedLayout::Unknown,
    }
}

fn sized(
    section: Option<&ImageSection>,
    names_complete: bool,
    file_bytes: usize,
    limitations: &mut Vec<String>,
    label: &str,
) -> KernelModuleSizedSection {
    let Some(section) = section else {
        return KernelModuleSizedSection {
            status: if names_complete {
                SizedSectionStatus::Absent
            } else {
                SizedSectionStatus::Unknown
            },
            location: None,
            bytes: None,
            compressed: None,
        };
    };
    let Some(location) =
        location(section, file_bytes).filter(|_| section.section_type != SHT_NOBITS)
    else {
        limitations.push(format!(
            "{label} is declared but not file-backed, so its size is unknown."
        ));
        return KernelModuleSizedSection {
            status: SizedSectionStatus::Present,
            location: None,
            bytes: None,
            compressed: None,
        };
    };
    if section.compressed {
        limitations.push(format!(
            "{label} is stored compressed. The reported size is the file-backed storage size; the decoded size is unknown."
        ));
    }
    KernelModuleSizedSection {
        status: SizedSectionStatus::Present,
        location: Some(location),
        bytes: Some(location.bytes),
        compressed: Some(section.compressed),
    }
}

fn parse_signature(bytes: &[u8]) -> ModuleSignature {
    let report = |status, magic, info, pkcs7, reason| ModuleSignature {
        status,
        magic,
        info,
        pkcs7,
        reason,
    };
    if !bytes.ends_with(MODULE_SIGNATURE_MAGIC) {
        return report(ModuleSignatureStatus::Absent, None, None, None, None);
    }
    let magic_offset = bytes.len() - MODULE_SIGNATURE_MAGIC.len();
    let magic = Some(ElfFileRange {
        offset: as_u32(magic_offset),
        bytes: as_u32(MODULE_SIGNATURE_MAGIC.len()),
    });
    let info_bytes = MODULE_SIGNATURE_INFO_BYTES as usize;
    let Some(info_offset) = magic_offset.checked_sub(info_bytes) else {
        return report(
            ModuleSignatureStatus::Malformed,
            magic,
            None,
            None,
            Some(SignatureReason::SignatureTrailerTruncated),
        );
    };
    let field = bytes.get(info_offset..magic_offset).unwrap_or_default();
    let byte = |at: usize| field.get(at).copied().unwrap_or(0);
    let sig_len = field
        .get(8..12)
        .and_then(|word| word.first_chunk::<4>())
        .map_or(0, |word| u32::from_be_bytes(*word));
    let info = ModuleSignatureInfo {
        location: ElfFileRange {
            offset: as_u32(info_offset),
            bytes: MODULE_SIGNATURE_INFO_BYTES,
        },
        algo: byte(0),
        hash: byte(1),
        id_type: byte(2),
        signer_len: byte(3),
        key_id_len: byte(4),
        pad: [byte(5), byte(6), byte(7)],
        sig_len,
    };
    let Some(pkcs7_offset) = info_offset
        .checked_sub(sig_len as usize)
        .filter(|_| (sig_len as usize) < info_offset)
    else {
        return report(
            ModuleSignatureStatus::Malformed,
            magic,
            Some(info),
            None,
            Some(SignatureReason::SignatureLengthInconsistent),
        );
    };
    if info.id_type != MODULE_SIGNATURE_PKCS7_ID_TYPE {
        return report(
            ModuleSignatureStatus::Unsupported,
            magic,
            Some(info),
            None,
            Some(SignatureReason::SignatureIdTypeNotPkcs7),
        );
    }
    let parameters_nonzero = info.algo != 0
        || info.hash != 0
        || info.signer_len != 0
        || info.key_id_len != 0
        || info.pad.iter().any(|&value| value != 0);
    if parameters_nonzero {
        return report(
            ModuleSignatureStatus::Malformed,
            magic,
            Some(info),
            None,
            Some(SignatureReason::SignatureParametersNonzero),
        );
    }
    let pkcs7 = bytes.get(pkcs7_offset..info_offset).unwrap_or_default();
    report(
        ModuleSignatureStatus::Present,
        magic,
        Some(info),
        Some(ModuleSignaturePkcs7 {
            location: ElfFileRange {
                offset: as_u32(pkcs7_offset),
                bytes: sig_len,
            },
            sha256: Sha256Digest::of(pkcs7),
        }),
        None,
    )
}

fn signature_limitation(signature: &ModuleSignature) -> &'static str {
    match signature.status {
        ModuleSignatureStatus::Absent => {
            "No '~Module signature appended~' trailer was present. That is not proof the module is unsigned in another container."
        }
        ModuleSignatureStatus::Present => {
            "PKCS#7 bytes are identified by the module_signature trailer and hashed. Certificate chain, signer, and digest coverage are unobserved."
        }
        ModuleSignatureStatus::Malformed | ModuleSignatureStatus::Unsupported => {
            "The appended signature trailer was not accepted as an unvalidated PKCS#7 range."
        }
    }
}

/// Decode kernel-module metadata from one in-memory image.
///
/// `artifact` identifies `bytes` in the result. gzip, xz, and zstd
/// containers are recognized and not decoded; ELF types other than `ET_REL`
/// are not applicable. Failures leave no partial result. Images larger than
/// [`MAX_INSPECT_KERNEL_MODULE_FILE_BYTES`] are refused before parsing; the
/// stable artifact reader already bounds them by the caller's
/// `max_file_bytes`, so that refusal only guards direct callers.
pub fn parse_kernel_module(
    bytes: &[u8],
    artifact: InspectedArtifact,
    input: &InspectKernelModuleInput,
) -> Result<KernelModule, KernelModuleFailure> {
    if !u64::try_from(bytes.len())
        .is_ok_and(|length| length <= MAX_INSPECT_KERNEL_MODULE_FILE_BYTES)
    {
        return Err(KernelModuleFailure::FileSize {
            message: format!(
                "Selected artifact exceeds {MAX_INSPECT_KERNEL_MODULE_FILE_BYTES} bytes: {}",
                artifact.path
            ),
        });
    }
    if let Some(codec) = compression_codec(bytes) {
        return Ok(unsupported_compression(artifact, codec));
    }
    let image = read_elf_image(bytes)?;
    let header_facts = |report: KernelModule| KernelModule {
        format: Some(match image.class {
            ElfClass::Elf32 => ElfFormat::Elf32,
            ElfClass::Elf64 => ElfFormat::Elf64,
        }),
        byte_order: Some(if image.endian.little {
            ElfByteOrder::Little
        } else {
            ElfByteOrder::Big
        }),
        machine: Some(u32::from(image.machine)),
        object_type: Some(u32::from(image.object_type)),
        type_name: Some(ElfObjectTypeName::from_e_type(u32::from(image.object_type))),
        ..report
    };
    if image.object_type != ET_REL {
        let mut limitations = base_limitations();
        limitations.push("Kernel module metadata is defined for ET_REL objects. This ELF type is not applicable, so .modinfo, __versions, and the signature trailer were not examined.".to_owned());
        return Ok(header_facts(closed_report(
            artifact,
            KernelModuleApplicability::NotApplicable,
            KernelModuleCoverageStatus::NotApplicable,
            limitations,
        )));
    }
    let file_bytes = bytes.len();
    let names_complete = image.section_names_limitation.is_none()
        && image
            .sections
            .iter()
            .all(|section| image.name(section).is_some());
    let mut limitations = base_limitations();
    limitations.extend(image.section_names_limitation.clone());
    let mut examined = Examined {
        count: 0,
        max_entries: input.max_entries,
    };
    let named = |name: &str| -> Vec<&ImageSection> {
        image
            .sections
            .iter()
            .filter(|section| image.name(section) == Some(name.as_bytes()))
            .collect()
    };
    let modinfo_sections = named(".modinfo");
    let version_sections = named("__versions");
    let module_sections = named(".gnu.linkonce.this_module");
    for (name, found) in [
        (".modinfo", &modinfo_sections),
        ("__versions", &version_sections),
        (".gnu.linkonce.this_module", &module_sections),
    ] {
        if found.len() > 1 {
            limitations.push(format!(
                "Multiple {name} sections are declared; the first is examined."
            ));
        }
    }
    let modinfo = parse_modinfo(
        bytes,
        modinfo_sections.first().copied(),
        names_complete,
        &mut examined,
    )?;
    let versions = parse_versions(
        bytes,
        version_sections.first().copied(),
        &image,
        names_complete,
        &mut examined,
    )?;
    let this_module = this_module(module_sections.first().copied(), names_complete, file_bytes);

    let ksymtab_named = image.sections.iter().filter_map(|section| {
        image
            .name(section)
            .filter(|name| name.starts_with(b"__ksymtab"))
            .map(|name| (section, name))
    });
    let mut unbacked = 0_usize;
    let mut ksymtab = Vec::new();
    for (section, name) in ksymtab_named {
        let found = location(section, file_bytes).filter(|_| section.section_type != SHT_NOBITS);
        let Some(location) = found else {
            unbacked += 1;
            continue;
        };
        let fits_name = name.len() <= MAX_KERNEL_MODULE_SECTION_NAME_BYTES;
        ksymtab.push(KsymtabSection {
            name: fits_name.then(|| latin1(name)),
            location,
            compressed: section.compressed,
            reason: (!fits_name).then_some(KsymtabSectionReason::KsymtabNameExceedsLimit),
        });
    }
    if unbacked > 0 {
        limitations.push(format!(
            "{unbacked} __ksymtab* section(s) are declared but not file-backed, so their ranges are unknown."
        ));
    }
    // Each listed section repeats its name, so the list shares the entry budget.
    examined.count += ksymtab.len() as u64;
    examined.admit(examined.count)?;
    if !names_complete {
        limitations.push("Section names are incomplete, so a missing .modinfo, __versions, this_module, __ksymtab, .init.text, or .exit.text section is unknown rather than absent.".to_owned());
    }
    let signature = parse_signature(bytes);
    if modinfo.status == KernelModuleSectionStatus::Absent {
        limitations.push("No .modinfo section was declared.".to_owned());
    }
    if versions.status == KernelModuleSectionStatus::Absent {
        limitations.push("No __versions section was declared.".to_owned());
    }
    limitations.push(signature_limitation(&signature).to_owned());
    let init_text = sized(
        named(".init.text").first().copied(),
        names_complete,
        file_bytes,
        &mut limitations,
        ".init.text",
    );
    let exit_text = sized(
        named(".exit.text").first().copied(),
        names_complete,
        file_bytes,
        &mut limitations,
        ".exit.text",
    );
    let examined_entries = as_u32(usize::try_from(examined.count).unwrap_or(usize::MAX));
    Ok(header_facts(KernelModule {
        applicability: KernelModuleApplicability::Applicable,
        modinfo: Some(modinfo),
        versions: Some(versions),
        this_module: Some(this_module),
        ksymtab: Some(KernelModuleKsymtab {
            status: if names_complete {
                KsymtabStatus::Observed
            } else {
                KsymtabStatus::Unknown
            },
            sections: ksymtab,
        }),
        init_text: Some(init_text),
        exit_text: Some(exit_text),
        signature: Some(signature),
        coverage: KernelModuleCoverage {
            status: KernelModuleCoverageStatus::Complete,
            examined_entries,
        },
        ..closed_report(
            artifact,
            KernelModuleApplicability::Applicable,
            KernelModuleCoverageStatus::Complete,
            limitations,
        )
    }))
}
