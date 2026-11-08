//! `inspect_kernel_module`: caller validation, output checks, and Evidence
//! provenance shared by the CLI and MCP adapters.
//!
//! Upstream reference:
//! `upstream:src/application/binaryDiagnostics/KernelModuleService.ts` and
//! `KernelModulePort.ts`.

use std::path::Path;

use rea_domain::cancellation::CancellationSignal;
use rea_domain::error::{AnalysisError, InputIssue, InputIssueReason};
use rea_domain::evidence::{
    BinaryArchitecture, Evidence, EvidenceLocation, EvidenceObservation, EvidenceSubjectTarget,
    SubjectFormat,
};
use rea_domain::native::elf::{ElfFileRange, ElfObjectTypeName};
use rea_domain::native::kernel_module::{
    InspectKernelModuleInput, KERNEL_MODULE_VERSION_ENTRY_BYTES, KernelModule,
    KernelModuleApplicability, KernelModuleCoverageStatus, KernelModuleEntryStatus,
    KernelModuleModinfo, KernelModuleSectionStatus, KernelModuleSizedSection,
    KernelModuleVersionLayout, KernelModuleVersions, KernelSymbolCrc, MAX_KERNEL_MODULE_RAW_BYTES,
    MAX_KERNEL_MODULE_SECTION_NAME_BYTES, MODULE_SIGNATURE_INFO_BYTES, MODULE_SIGNATURE_MAGIC,
    MODULE_SIGNATURE_PKCS7_ID_TYPE, ModuleSignature, ModuleSignatureStatus, SignatureReason,
    SizedSectionStatus,
};
use rea_domain::providers::ProviderIdentity;
use rea_native::elf::KernelModuleProvider;
use serde_json::Value;

use crate::evidence::complete_provider_evidence;

/// Public operation name.
pub const OPERATION: &str = "inspect_kernel_module";

const MALFORMED_OUTPUT: &str =
    "Kernel module provider returned malformed output or changed artifact identity.";

/// Stable read and kernel-module metadata decoding, independent of a
/// disassembler session.
pub trait KernelModulePort {
    /// The provider's Evidence identity.
    fn identity(&self) -> ProviderIdentity;

    /// Decode the kernel-module metadata of the admitted input.
    fn inspect(
        &self,
        input: &InspectKernelModuleInput,
        signal: &CancellationSignal,
    ) -> Result<KernelModule, AnalysisError>;
}

impl KernelModulePort for KernelModuleProvider {
    fn identity(&self) -> ProviderIdentity {
        Self::IDENTITY
    }

    fn inspect(
        &self,
        input: &InspectKernelModuleInput,
        signal: &CancellationSignal,
    ) -> Result<KernelModule, AnalysisError> {
        KernelModuleProvider::inspect(self, input, signal)
    }
}

/// The `inspect_kernel_module` workflow over one provider.
#[derive(Debug, Clone, Default)]
pub struct KernelModuleService<P = KernelModuleProvider> {
    provider: P,
}

impl<P: KernelModulePort> KernelModuleService<P> {
    /// A service over `provider`.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Validate raw caller arguments, run the provider, and record Evidence.
    ///
    /// `raw` of `None` means the caller supplied no arguments.
    pub fn inspect(
        &self,
        raw: Option<&Value>,
        signal: &CancellationSignal,
    ) -> Result<Evidence, AnalysisError> {
        if signal.is_cancelled() {
            return Err(AnalysisError::cancelled(OPERATION));
        }
        let input = InspectKernelModuleInput::parse(raw)
            .map_err(|issues| AnalysisError::input(OPERATION, issues))?;
        if !Path::new(&input.path).is_absolute() {
            return Err(AnalysisError::input(
                OPERATION,
                [InputIssue::new(["path"], InputIssueReason::InvalidFormat)
                    .with_message("Expected an absolute filesystem path on this host.")],
            ));
        }
        let report = self.provider.inspect(&input, signal)?;
        if report.artifact.path != input.path || !valid_report(&report, &input) {
            return Err(AnalysisError::output(OPERATION, MALFORMED_OUTPUT));
        }
        let evidence = evidence(&report, &input, self.provider.identity())?;
        complete_provider_evidence(evidence, signal)
    }
}

fn evidence(
    report: &KernelModule,
    input: &InspectKernelModuleInput,
    provider: ProviderIdentity,
) -> Result<Evidence, AnalysisError> {
    let malformed = |_| AnalysisError::output(OPERATION, MALFORMED_OUTPUT);
    let Value::Object(parameters) = serde_json::to_value(input).map_err(malformed)? else {
        return Err(AnalysisError::output(OPERATION, MALFORMED_OUTPUT));
    };
    let result = serde_json::to_value(report).map_err(malformed)?;
    let mut observation = EvidenceObservation::new(OPERATION, parameters, result);
    observation.limitations = report.limitations.clone();
    observation.locations = std::iter::once(EvidenceLocation::ArtifactPath {
        path: report.artifact.path.clone(),
    })
    .chain(
        ranges(report)
            .into_iter()
            .map(|range| EvidenceLocation::FileOffsetRange {
                start: u64::from(range.offset),
                end: u64::from(range.offset) + u64::from(range.bytes),
            }),
    )
    .collect();
    let target = EvidenceSubjectTarget {
        path: report.artifact.path.clone(),
        sha256: report.artifact.sha256,
        format: if report.applicability == KernelModuleApplicability::Unsupported {
            SubjectFormat::File
        } else {
            SubjectFormat::Elf
        },
        architecture: report
            .machine
            .and_then(|machine| u16::try_from(machine).ok())
            .and_then(BinaryArchitecture::from_elf_machine),
    };
    Evidence::create(Some(&target), &provider.to_evidence_provider(), observation)
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))
}

/// Every reported file range, in the upstream Evidence location order.
fn ranges(report: &KernelModule) -> Vec<ElfFileRange> {
    let modinfo = report.modinfo.as_ref();
    let versions = report.versions.as_ref();
    let signature = report.signature.as_ref();
    modinfo
        .and_then(|modinfo| modinfo.location)
        .into_iter()
        .chain(
            modinfo
                .into_iter()
                .flat_map(|modinfo| modinfo.entries.iter().map(|entry| entry.location)),
        )
        .chain(versions.and_then(|versions| versions.location))
        .chain(
            versions
                .into_iter()
                .flat_map(|versions| versions.entries.iter().map(|entry| entry.location)),
        )
        .chain(
            report
                .this_module
                .as_ref()
                .and_then(|section| section.location),
        )
        .chain(
            report
                .init_text
                .as_ref()
                .and_then(|section| section.location),
        )
        .chain(
            report
                .exit_text
                .as_ref()
                .and_then(|section| section.location),
        )
        .chain(
            report
                .ksymtab
                .iter()
                .flat_map(|ksymtab| ksymtab.sections.iter().map(|section| section.location)),
        )
        .chain(signature.and_then(|signature| signature.magic))
        .chain(signature.and_then(|signature| signature.info.as_ref().map(|info| info.location)))
        .chain(signature.and_then(|signature| signature.pkcs7.as_ref().map(|pkcs7| pkcs7.location)))
        .collect()
}

/// Section reasons appear exactly on closed sections, and absent or unknown
/// sections carry no stored facts.
fn section_consistent(
    status: KernelModuleSectionStatus,
    has_reason: bool,
    has_location: bool,
    has_sha256: bool,
    entries: usize,
) -> bool {
    use KernelModuleSectionStatus::{Absent, Malformed, Present, Unknown, Unsupported};
    let closed_ok = match status {
        Malformed | Unsupported => has_reason && entries == 0,
        Present | Absent | Unknown => !has_reason,
    };
    let stored_ok = match status {
        Absent | Unknown => !has_location && !has_sha256 && entries == 0,
        Present => has_location && has_sha256,
        Malformed | Unsupported => true,
    };
    closed_ok && stored_ok
}

fn modinfo_consistent(modinfo: &KernelModuleModinfo) -> bool {
    section_consistent(
        modinfo.status,
        modinfo.reason.is_some(),
        modinfo.location.is_some(),
        modinfo.sha256.is_some(),
        modinfo.entries.len(),
    ) && modinfo.entries.iter().enumerate().all(|(index, entry)| {
        let bytes = entry.location.bytes as usize;
        let raw_ok = match &entry.raw_hex {
            Some(raw) => bytes <= MAX_KERNEL_MODULE_RAW_BYTES && raw.0.len() == bytes,
            None => bytes > MAX_KERNEL_MODULE_RAW_BYTES,
        };
        let status_ok = match entry.status {
            KernelModuleEntryStatus::Observed => {
                entry.reason.is_none() && entry.key.is_some() && entry.value.is_some()
            }
            KernelModuleEntryStatus::Malformed => entry.reason.is_some(),
        };
        entry.index as usize == index && raw_ok && status_ok
    })
}

fn versions_consistent(versions: &KernelModuleVersions) -> bool {
    let Some(layout) = versions.layout else {
        return false;
    };
    versions.entry_bytes.is_some()
        && section_consistent(
            versions.status,
            versions.reason.is_some(),
            versions.location.is_some(),
            versions.sha256.is_some(),
            versions.entries.len(),
        )
        && versions.entries.iter().enumerate().all(|(index, entry)| {
            let width_ok = matches!(
                (layout, entry.crc_hex),
                (
                    KernelModuleVersionLayout::Elf64UnsignedLongName56,
                    KernelSymbolCrc::Elf64(_)
                ) | (
                    KernelModuleVersionLayout::Elf32UnsignedLongName60,
                    KernelSymbolCrc::Elf32(_)
                )
            );
            let status_ok = match entry.status {
                KernelModuleEntryStatus::Observed => entry.reason.is_none() && entry.name.is_some(),
                KernelModuleEntryStatus::Malformed => {
                    entry.reason.is_some() && entry.name.is_none()
                }
            };
            entry.index as usize == index
                && width_ok
                && entry.location.bytes == KERNEL_MODULE_VERSION_ENTRY_BYTES
                && status_ok
        })
}

fn signature_consistent(signature: &ModuleSignature) -> bool {
    let magic = signature.magic;
    let info = signature.info.as_ref();
    let pkcs7 = signature.pkcs7.as_ref();
    match signature.status {
        ModuleSignatureStatus::Absent => {
            signature.reason.is_none() && magic.is_none() && info.is_none() && pkcs7.is_none()
        }
        ModuleSignatureStatus::Present => {
            let (None, Some(magic), Some(info), Some(pkcs7)) =
                (signature.reason, magic, info, pkcs7)
            else {
                return false;
            };
            let info_end = u64::from(info.location.offset) + u64::from(info.location.bytes);
            let pkcs7_end = u64::from(pkcs7.location.offset) + u64::from(pkcs7.location.bytes);
            info.id_type == MODULE_SIGNATURE_PKCS7_ID_TYPE
                && info.algo == 0
                && info.hash == 0
                && info.signer_len == 0
                && info.key_id_len == 0
                && info.pad == [0; 3]
                && info.sig_len == pkcs7.location.bytes
                && pkcs7_end == u64::from(info.location.offset)
                && u64::from(magic.offset) == info_end
                && magic.bytes as usize == MODULE_SIGNATURE_MAGIC.len()
                && info.location.bytes == MODULE_SIGNATURE_INFO_BYTES
                && info.sig_len < info.location.offset
        }
        ModuleSignatureStatus::Malformed | ModuleSignatureStatus::Unsupported => {
            let Some(reason) = signature.reason else {
                return false;
            };
            if magic.is_none() || pkcs7.is_some() {
                return false;
            }
            match (signature.status, reason) {
                (ModuleSignatureStatus::Unsupported, reason) => {
                    reason == SignatureReason::SignatureIdTypeNotPkcs7 && info.is_some()
                }
                (_, SignatureReason::SignatureTrailerTruncated) => info.is_none(),
                _ => info.is_some(),
            }
        }
    }
}

fn sized_consistent(section: &KernelModuleSizedSection) -> bool {
    match (section.status, section.location) {
        (SizedSectionStatus::Absent | SizedSectionStatus::Unknown, _) => {
            section.location.is_none() && section.bytes.is_none() && section.compressed.is_none()
        }
        (SizedSectionStatus::Present, None) => section.bytes.is_none(),
        (SizedSectionStatus::Present, Some(location)) => {
            section.bytes == Some(location.bytes) && section.compressed.is_some()
        }
    }
}

fn metadata_absent(report: &KernelModule) -> bool {
    report.modinfo.is_none()
        && report.versions.is_none()
        && report.this_module.is_none()
        && report.ksymtab.is_none()
        && report.init_text.is_none()
        && report.exit_text.is_none()
        && report.signature.is_none()
}

/// Counts, ranges, and per-applicability shapes stay within the admitted
/// budgets and artifact.
fn valid_report(report: &KernelModule, input: &InspectKernelModuleInput) -> bool {
    let artifact_bytes = report.artifact.bytes;
    let inside = |range: &ElfFileRange| {
        range.bytes <= artifact_bytes && range.offset <= artifact_bytes - range.bytes
    };
    let coverage = report.coverage;
    if u64::from(artifact_bytes) > input.max_file_bytes
        || u64::from(coverage.examined_entries) > input.max_entries
        || !ranges(report).iter().all(inside)
    {
        return false;
    }
    let elf_facts = (
        report.format,
        report.byte_order,
        report.machine,
        report.object_type,
        report.type_name,
    );
    if report.applicability == KernelModuleApplicability::Unsupported {
        return coverage.status == KernelModuleCoverageStatus::Unsupported
            && coverage.examined_entries == 0
            && report.compression.is_some()
            && report.next_probe.is_some()
            && elf_facts == (None, None, None, None, None)
            && metadata_absent(report);
    }
    let (Some(_), Some(_), Some(_), Some(object_type), Some(type_name)) = elf_facts else {
        return false;
    };
    if type_name != ElfObjectTypeName::from_e_type(object_type)
        || report.compression.is_some()
        || report.next_probe.is_some()
    {
        return false;
    }
    if report.applicability == KernelModuleApplicability::NotApplicable {
        return coverage.status == KernelModuleCoverageStatus::NotApplicable
            && coverage.examined_entries == 0
            && object_type != 1
            && metadata_absent(report);
    }
    let (
        KernelModuleCoverageStatus::Complete,
        Some(modinfo),
        Some(versions),
        Some(_),
        Some(ksymtab),
        Some(init_text),
        Some(exit_text),
        Some(signature),
    ) = (
        coverage.status,
        &report.modinfo,
        &report.versions,
        &report.this_module,
        &report.ksymtab,
        &report.init_text,
        &report.exit_text,
        &report.signature,
    )
    else {
        return false;
    };
    let examined = modinfo.entries.len() + versions.entries.len() + ksymtab.sections.len();
    coverage.examined_entries as usize == examined
        && ksymtab.sections.iter().all(|section| {
            let name_ok = section.name.as_ref().is_none_or(|name| {
                (1..=MAX_KERNEL_MODULE_SECTION_NAME_BYTES).contains(&name.chars().count())
            });
            name_ok && section.name.is_none() == section.reason.is_some()
        })
        && object_type == 1
        && modinfo_consistent(modinfo)
        && versions_consistent(versions)
        && signature_consistent(signature)
        && sized_consistent(init_text)
        && sized_consistent(exit_text)
}
