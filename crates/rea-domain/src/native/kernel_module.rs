//! Kernel-module result contract and `inspect_kernel_module` input.
//!
//! Struct fields are declared in the upstream zod shape order so serialized
//! JSON members match upstream output member order. Nullable members are
//! `Option` values that serialize as `null`; none are omitted.
//!
//! Upstream reference: `upstream:src/domain/native/kernelModule.ts`.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::digest::Sha256Digest;
use crate::error::InputIssue;
use crate::input::InputObject;

use super::elf::{
    ElfByteOrder, ElfFileRange, ElfFormat, ElfObjectTypeName, HexBytes, InspectedArtifact,
    lower_hex_value,
};

/// Hard ceiling on the caller-selected input read budget (512 MiB).
pub const MAX_INSPECT_KERNEL_MODULE_FILE_BYTES: u64 = 536_870_912;
/// Smallest accepted `max_file_bytes`.
pub const MIN_INSPECT_KERNEL_MODULE_FILE_BYTES: u64 = 64;
/// Default `max_file_bytes` (64 MiB).
pub const DEFAULT_INSPECT_KERNEL_MODULE_FILE_BYTES: u64 = 67_108_864;
/// Hard ceiling on decoded `.modinfo` and `__versions` entries plus listed
/// file-backed `__ksymtab*` sections combined.
pub const MAX_INSPECT_KERNEL_MODULE_ENTRIES: u64 = 65_536;
/// Smallest accepted `max_entries`.
pub const MIN_INSPECT_KERNEL_MODULE_ENTRIES: u64 = 1;
/// Default `max_entries`.
pub const DEFAULT_INSPECT_KERNEL_MODULE_ENTRIES: u64 = 8192;
/// Retained `.modinfo` key length. Longer keys stay malformed per entry and
/// are not copied into the result.
pub const MAX_KERNEL_MODULE_KEY_BYTES: usize = 256;
/// Retained `.modinfo` value length. Longer values stay malformed per entry
/// and are not copied into the result.
pub const MAX_KERNEL_MODULE_VALUE_BYTES: usize = 4096;
/// Retained `__ksymtab*` section-name length. Longer names stay listed with
/// a null name and are not copied into the result.
pub const MAX_KERNEL_MODULE_SECTION_NAME_BYTES: usize = 256;
/// Inline raw-entry hex ceiling. Longer entries keep only their SHA-256.
pub const MAX_KERNEL_MODULE_RAW_BYTES: usize = 4096;
/// `struct modversion_info` is `unsigned long crc` plus
/// `char name[64 - sizeof(unsigned long)]`, so every entry is 64 bytes.
pub const KERNEL_MODULE_VERSION_ENTRY_BYTES: u32 = 64;
/// `struct module_signature` is 12 bytes, with `sig_len` big-endian.
pub const MODULE_SIGNATURE_INFO_BYTES: u32 = 12;
/// Trailer magic, including the trailing newline, from `MODULE_SIG_STRING`.
pub const MODULE_SIGNATURE_MAGIC: &[u8] = b"~Module signature appended~\n";
/// `PKEY_ID_PKCS7` from the kernel public-key identifier enum.
pub const MODULE_SIGNATURE_PKCS7_ID_TYPE: u8 = 2;

/// Caller input for `inspect_kernel_module`.
///
/// [`InspectKernelModuleInput::parse`] is the only admission from raw caller
/// arguments; it applies the upstream defaults, ranges, and strictness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectKernelModuleInput {
    /// Absolute filesystem path to an ELF kernel module or a compressed
    /// `.ko` container.
    pub path: String,
    /// Maximum stable artifact bytes to read.
    pub max_file_bytes: u64,
    /// Maximum `.modinfo` and `__versions` entries plus file-backed
    /// `__ksymtab*` sections to examine; exceeding the budget fails without
    /// partial success.
    pub max_entries: u64,
}

impl InspectKernelModuleInput {
    /// Input for `path` with the upstream default budgets.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            max_file_bytes: DEFAULT_INSPECT_KERNEL_MODULE_FILE_BYTES,
            max_entries: DEFAULT_INSPECT_KERNEL_MODULE_ENTRIES,
        }
    }

    /// Admit raw caller arguments (`inspectKernelModuleInputSchema`); `None`
    /// means no arguments were supplied.
    pub fn parse(raw: Option<&Value>) -> Result<Self, Vec<InputIssue>> {
        let mut object = InputObject::new(raw)?;
        let path = object.local_path("path");
        let max_file_bytes = object.integer(
            "max_file_bytes",
            MIN_INSPECT_KERNEL_MODULE_FILE_BYTES,
            MAX_INSPECT_KERNEL_MODULE_FILE_BYTES,
            DEFAULT_INSPECT_KERNEL_MODULE_FILE_BYTES,
        );
        let max_entries = object.integer(
            "max_entries",
            MIN_INSPECT_KERNEL_MODULE_ENTRIES,
            MAX_INSPECT_KERNEL_MODULE_ENTRIES,
            DEFAULT_INSPECT_KERNEL_MODULE_ENTRIES,
        );
        object.finish()?;
        match (path, max_file_bytes, max_entries) {
            (Some(path), Some(max_file_bytes), Some(max_entries)) => Ok(Self {
                path,
                max_file_bytes,
                max_entries,
            }),
            // `finish` reports an issue for every member that produced `None`.
            _ => Err(Vec::new()),
        }
    }
}

/// Whether kernel-module metadata applies to the artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelModuleApplicability {
    /// An `ET_REL` ELF image.
    Applicable,
    /// Another ELF object type.
    NotApplicable,
    /// A whole-file compressed container.
    Unsupported,
}

/// Why one `.modinfo` entry is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModinfoEntryReason {
    /// The last span has no NUL terminator.
    UnterminatedModinfoEntry,
    /// No `=` separates key and value.
    ModinfoMissingSeparator,
    /// The key before `=` is empty.
    ModinfoEmptyKey,
    /// The key or value exceeds its retained length.
    ModinfoFieldExceedsLimit,
}

/// Why `.modinfo` was not decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModinfoSectionReason {
    /// `SHF_COMPRESSED` storage.
    ModinfoSectionCompressed,
    /// `SHT_NOBITS` or a range outside the file.
    ModinfoSectionNotFileBacked,
}

/// Why one `__versions` entry is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionEntryReason {
    /// The fixed name field has no NUL.
    VersionNameUnterminated,
}

/// Why `__versions` was not decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionSectionReason {
    /// The size is not a multiple of the 64-byte entry.
    VersionsSizeNotMultiple,
    /// `SHF_COMPRESSED` storage.
    VersionsSectionCompressed,
    /// `SHT_NOBITS` or a range outside the file.
    VersionsSectionNotFileBacked,
}

/// Why a listed `__ksymtab*` section has no name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KsymtabSectionReason {
    /// The name exceeds its retained length.
    KsymtabNameExceedsLimit,
}

/// Why the appended signature trailer was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureReason {
    /// The magic leaves no room for `struct module_signature`.
    SignatureTrailerTruncated,
    /// `sig_len` reaches past the start of the file.
    SignatureLengthInconsistent,
    /// A PKCS#7 trailer declares nonzero unused parameters.
    SignatureParametersNonzero,
    /// `id_type` is not `PKEY_ID_PKCS7`.
    SignatureIdTypeNotPkcs7,
}

/// `struct modversion_info` layout for the ELF class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KernelModuleVersionLayout {
    /// u32 CRC and a 60-byte name.
    #[serde(rename = "elf32_unsigned_long_name60")]
    Elf32UnsignedLongName60,
    /// u64 CRC and a 56-byte name.
    #[serde(rename = "elf64_unsigned_long_name56")]
    Elf64UnsignedLongName56,
}

/// Observation state of a decoded metadata section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelModuleSectionStatus {
    /// Declared and decoded.
    Present,
    /// Not declared while every section name is known.
    Absent,
    /// Not found while some section names are unknown.
    Unknown,
    /// Declared but not decodable.
    Malformed,
    /// Declared with a storage form this reader refuses.
    Unsupported,
}

/// Observation state of one decoded entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelModuleEntryStatus {
    /// Decoded.
    Observed,
    /// Retained with a reason.
    Malformed,
}

/// One NUL-separated `.modinfo` record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModinfoEntry {
    /// Position within the section.
    pub index: u32,
    /// Record file range, including its NUL when terminated.
    pub location: ElfFileRange,
    /// Key before the first `=` (Latin-1 decoded), when retained.
    pub key: Option<String>,
    /// Value after the first `=` (Latin-1 decoded), when retained.
    pub value: Option<String>,
    /// SHA-256 of the raw record bytes.
    pub raw_sha256: Sha256Digest,
    /// Raw record bytes when at most 4096.
    pub raw_hex: Option<HexBytes>,
    /// Entry state.
    pub status: KernelModuleEntryStatus,
    /// Why the entry is malformed.
    pub reason: Option<ModinfoEntryReason>,
}

/// The `.modinfo` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelModuleModinfo {
    /// Section state.
    pub status: KernelModuleSectionStatus,
    /// Section file range.
    pub location: Option<ElfFileRange>,
    /// SHA-256 of the stored section bytes.
    pub sha256: Option<Sha256Digest>,
    /// Records in section order; duplicates are preserved.
    pub entries: Vec<ModinfoEntry>,
    /// Why the section was not decoded.
    pub reason: Option<ModinfoSectionReason>,
}

/// A symbol CRC: an ELF32 u32 or an ELF64 u64, rendered as zero-padded
/// lowercase hex of 8 or 16 digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KernelSymbolCrc {
    /// ELF32 `unsigned long`.
    Elf32(u32),
    /// ELF64 `unsigned long`.
    Elf64(u64),
}

impl fmt::Display for KernelSymbolCrc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf32(crc) => write!(f, "{crc:08x}"),
            Self::Elf64(crc) => write!(f, "{crc:016x}"),
        }
    }
}

impl Serialize for KernelSymbolCrc {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for KernelSymbolCrc {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let invalid = || serde::de::Error::custom("expected 8 or 16 lowercase hex digits");
        let value = text.bytes().try_fold(0_u64, |value, digit| {
            lower_hex_value(digit).map(|digit| (value << 4) | u64::from(digit))
        });
        match (text.len(), value) {
            (8, Some(value)) => u32::try_from(value).map(Self::Elf32).map_err(|_| invalid()),
            (16, Some(value)) => Ok(Self::Elf64(value)),
            _ => Err(invalid()),
        }
    }
}

/// One `struct modversion_info` record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelModuleVersionEntry {
    /// Position within the section.
    pub index: u32,
    /// Record file range.
    pub location: ElfFileRange,
    /// Symbol CRC.
    pub crc_hex: KernelSymbolCrc,
    /// Symbol name up to its NUL (Latin-1 decoded).
    pub name: Option<String>,
    /// Entry state.
    pub status: KernelModuleEntryStatus,
    /// Why the entry is malformed.
    pub reason: Option<VersionEntryReason>,
}

/// The literal 64-byte `__versions` entry width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct KernelModuleVersionEntryBytes;

impl Serialize for KernelModuleVersionEntryBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(KERNEL_MODULE_VERSION_ENTRY_BYTES)
    }
}

impl<'de> Deserialize<'de> for KernelModuleVersionEntryBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if u32::deserialize(deserializer)? == KERNEL_MODULE_VERSION_ENTRY_BYTES {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom("expected 64"))
        }
    }
}

/// The `__versions` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelModuleVersions {
    /// Section state.
    pub status: KernelModuleSectionStatus,
    /// Record layout for the ELF class.
    pub layout: Option<KernelModuleVersionLayout>,
    /// Record width.
    pub entry_bytes: Option<KernelModuleVersionEntryBytes>,
    /// Section file range.
    pub location: Option<ElfFileRange>,
    /// SHA-256 of the stored section bytes.
    pub sha256: Option<Sha256Digest>,
    /// Records in section order.
    pub entries: Vec<KernelModuleVersionEntry>,
    /// Why the section was not decoded.
    pub reason: Option<VersionSectionReason>,
}

/// Presence of `.gnu.linkonce.this_module`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThisModuleStatus {
    /// Declared.
    Present,
    /// Not declared while every section name is known.
    Absent,
    /// Not found while some section names are unknown.
    Unknown,
    /// Declared with compressed storage.
    Unsupported,
}

/// `struct module` changes with the kernel version and is not decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UndecodedLayout {
    /// The only value.
    #[default]
    Unknown,
}

/// The `.gnu.linkonce.this_module` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelModuleThisModule {
    /// Section state.
    pub status: ThisModuleStatus,
    /// Section file range when file-backed.
    pub location: Option<ElfFileRange>,
    /// Always unknown.
    pub layout: UndecodedLayout,
}

/// Presence of a sized text section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SizedSectionStatus {
    /// Declared.
    Present,
    /// Not declared while every section name is known.
    Absent,
    /// Not found while some section names are unknown.
    Unknown,
}

/// `.init.text` or `.exit.text`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelModuleSizedSection {
    /// Section state.
    pub status: SizedSectionStatus,
    /// Section file range when file-backed.
    pub location: Option<ElfFileRange>,
    /// Observed file-backed size. Null when the section is not file-backed.
    pub bytes: Option<u32>,
    /// `SHF_COMPRESSED` storage, when file-backed.
    pub compressed: Option<bool>,
}

/// Whether section names establish the `__ksymtab*` listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KsymtabStatus {
    /// Every section name is known.
    Observed,
    /// Some section names are unknown.
    Unknown,
}

/// One file-backed `__ksymtab*` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KsymtabSection {
    /// Section name (Latin-1 decoded), when retained.
    pub name: Option<String>,
    /// Section file range.
    pub location: ElfFileRange,
    /// `SHF_COMPRESSED` storage.
    pub compressed: bool,
    /// Why the name was not retained.
    pub reason: Option<KsymtabSectionReason>,
}

/// File-backed `__ksymtab*` sections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelModuleKsymtab {
    /// Listing state.
    pub status: KsymtabStatus,
    /// Sections in header order.
    pub sections: Vec<KsymtabSection>,
}

/// `struct module_signature`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSignatureInfo {
    /// Structure file range.
    pub location: ElfFileRange,
    /// `algo`.
    pub algo: u8,
    /// `hash`.
    pub hash: u8,
    /// `id_type`.
    pub id_type: u8,
    /// `signer_len`.
    pub signer_len: u8,
    /// `key_id_len`.
    pub key_id_len: u8,
    /// `__pad`.
    pub pad: [u8; 3],
    /// Big-endian `sig_len`.
    pub sig_len: u32,
}

/// Acceptance of the appended signature trailer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleSignatureStatus {
    /// No trailer magic.
    Absent,
    /// A consistent PKCS#7 trailer.
    Present,
    /// An inconsistent trailer.
    Malformed,
    /// A trailer with a non-PKCS#7 identifier.
    Unsupported,
}

/// The PKCS#7 bytes a trailer identifies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSignaturePkcs7 {
    /// PKCS#7 file range.
    pub location: ElfFileRange,
    /// SHA-256 of the PKCS#7 bytes.
    pub sha256: Sha256Digest,
}

/// The appended module signature trailer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSignature {
    /// Trailer state.
    pub status: ModuleSignatureStatus,
    /// Magic file range.
    pub magic: Option<ElfFileRange>,
    /// Decoded `struct module_signature`.
    pub info: Option<ModuleSignatureInfo>,
    /// Identified PKCS#7 bytes.
    pub pkcs7: Option<ModuleSignaturePkcs7>,
    /// Why the trailer was not accepted.
    pub reason: Option<SignatureReason>,
}

/// Whole-file codecs recognized and not decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelModuleCodec {
    /// gzip (`1f 8b`).
    Gzip,
    /// xz (`fd 37 7a 58 5a 00`).
    Xz,
    /// Zstandard (`28 b5 2f fd`).
    Zstd,
}

impl KernelModuleCodec {
    /// The codec's lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
        }
    }
}

/// The literal `unsupported` compression status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionStatus {
    /// The only value.
    #[default]
    Unsupported,
}

/// A recognized whole-file container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelModuleCompression {
    /// Container codec.
    pub codec: KernelModuleCodec,
    /// Always unsupported.
    pub status: CompressionStatus,
}

/// The literal `external_decompression` operation: a codec utility, not a
/// REA tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextProbeOperation {
    /// The only value.
    #[default]
    ExternalDecompression,
}

/// The suggested next step for an unsupported container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelModuleNextProbe {
    /// External decompression with a codec utility.
    pub operation: NextProbeOperation,
    /// Why and how.
    #[serde(deserialize_with = "super::elf::non_empty_string")]
    pub rationale: String,
}

/// Coverage status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelModuleCoverageStatus {
    /// Every applicable section and entry was examined.
    Complete,
    /// The ELF type is not a kernel module.
    NotApplicable,
    /// The container was not decoded.
    Unsupported,
}

/// Examined coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelModuleCoverage {
    /// Coverage status.
    pub status: KernelModuleCoverageStatus,
    /// `.modinfo` and `__versions` entries plus listed `__ksymtab*` sections.
    pub examined_entries: u32,
}

/// Observed kernel-module metadata. `ET_REL` images are applicable. Other
/// ELF types are not applicable. gzip, xz, and zstd containers are
/// unsupported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelModule {
    /// Inspected artifact.
    pub artifact: InspectedArtifact,
    /// ELF class.
    pub format: Option<ElfFormat>,
    /// ELF data encoding.
    pub byte_order: Option<ElfByteOrder>,
    /// `e_machine`.
    pub machine: Option<u32>,
    /// `e_type`.
    #[serde(rename = "type")]
    pub object_type: Option<u32>,
    /// Name for `e_type`.
    pub type_name: Option<ElfObjectTypeName>,
    /// Whether kernel-module metadata applies.
    pub applicability: KernelModuleApplicability,
    /// Recognized whole-file container.
    pub compression: Option<KernelModuleCompression>,
    /// Suggested next step for a container.
    pub next_probe: Option<KernelModuleNextProbe>,
    /// `.modinfo`.
    pub modinfo: Option<KernelModuleModinfo>,
    /// `__versions`.
    pub versions: Option<KernelModuleVersions>,
    /// `.gnu.linkonce.this_module`.
    pub this_module: Option<KernelModuleThisModule>,
    /// `__ksymtab*` sections.
    pub ksymtab: Option<KernelModuleKsymtab>,
    /// `.init.text`.
    pub init_text: Option<KernelModuleSizedSection>,
    /// `.exit.text`.
    pub exit_text: Option<KernelModuleSizedSection>,
    /// Appended signature trailer.
    pub signature: Option<ModuleSignature>,
    /// Examined coverage.
    pub coverage: KernelModuleCoverage,
    /// Scope and unavailable-fact limitations.
    pub limitations: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::error::InputIssueReason;
    use serde_json::json;

    #[test]
    fn input_rejects_extra_arguments_and_applies_kernel_module_budgets() {
        assert_eq!(
            InspectKernelModuleInput::parse(Some(
                &json!({"path": "/artifacts/demo.ko", "extra": true})
            )),
            Err(vec![InputIssue::new(
                ["extra"],
                InputIssueReason::UnknownArgument
            )])
        );
        let input =
            InspectKernelModuleInput::parse(Some(&json!({"path": "/artifacts/demo.ko"}))).unwrap();
        assert_eq!(input, InspectKernelModuleInput::new("/artifacts/demo.ko"));
        assert_eq!(
            serde_json::to_string(&input).unwrap(),
            r#"{"path":"/artifacts/demo.ko","max_file_bytes":67108864,"max_entries":8192}"#
        );
    }

    #[test]
    fn symbol_crcs_keep_their_class_width() {
        assert_eq!(
            serde_json::to_string(&KernelSymbolCrc::Elf32(0x1234)).unwrap(),
            r#""00001234""#
        );
        assert_eq!(
            serde_json::to_string(&KernelSymbolCrc::Elf64(0x11)).unwrap(),
            r#""0000000000000011""#
        );
        assert_eq!(
            serde_json::from_str::<KernelSymbolCrc>(r#""90abcdef""#).unwrap(),
            KernelSymbolCrc::Elf32(0x90ab_cdef)
        );
        for invalid in [r#""1234""#, r#""90ABCDEF""#, r#""0000000000000000a""#] {
            assert!(
                serde_json::from_str::<KernelSymbolCrc>(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn literal_members_refuse_other_values() {
        assert!(
            serde_json::from_value::<KernelModuleNextProbe>(
                json!({"operation": "extract_artifact", "rationale": "x"})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<KernelModuleVersionEntryBytes>(json!(63)).is_err());
        assert_eq!(
            serde_json::to_value(KernelModuleVersionLayout::Elf32UnsignedLongName60).unwrap(),
            json!("elf32_unsigned_long_name60")
        );
        assert_eq!(MODULE_SIGNATURE_MAGIC.len(), 28);
    }
}
