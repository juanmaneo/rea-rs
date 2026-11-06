//! ELF note table result contract and `inspect_elf_notes` input.
//!
//! Struct fields are declared in the upstream zod shape order so serialized
//! JSON members match upstream output member order. Nullable members are
//! `Option` values that serialize as `null`; none are omitted.
//!
//! Upstream reference: `upstream:src/domain/native/elfNotes.ts`.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::digest::Sha256Digest;
use crate::error::InputIssue;
use crate::input::InputObject;

/// Hard ceiling on the caller-selected input read budget (512 MiB).
pub const MAX_INSPECT_ELF_NOTE_FILE_BYTES: u64 = 536_870_912;
/// Smallest accepted `max_file_bytes`.
pub const MIN_INSPECT_ELF_NOTE_FILE_BYTES: u64 = 64;
/// Default `max_file_bytes` (64 MiB).
pub const DEFAULT_INSPECT_ELF_NOTE_FILE_BYTES: u64 = 67_108_864;
/// Hard ceiling on decoded note entries across every declared table.
pub const MAX_INSPECT_ELF_NOTE_ENTRIES: u64 = 256;
/// Smallest accepted `max_entries`.
pub const MIN_INSPECT_ELF_NOTE_ENTRIES: u64 = 1;
/// Default `max_entries`.
pub const DEFAULT_INSPECT_ELF_NOTE_ENTRIES: u64 = 32;

/// Caller input for `inspect_elf_notes`.
///
/// [`InspectElfNotesInput::parse`] is the only admission from raw caller
/// arguments; it applies the upstream defaults, ranges, and strictness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectElfNotesInput {
    /// Absolute filesystem path to an ELF image.
    pub path: String,
    /// Maximum stable artifact bytes to read.
    pub max_file_bytes: u64,
    /// Maximum note entries to examine across every table; exceeding the
    /// budget fails without partial success.
    pub max_entries: u64,
}

impl InspectElfNotesInput {
    /// Input for `path` with the upstream default budgets.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            max_file_bytes: DEFAULT_INSPECT_ELF_NOTE_FILE_BYTES,
            max_entries: DEFAULT_INSPECT_ELF_NOTE_ENTRIES,
        }
    }

    /// Admit raw caller arguments (`inspectElfNotesInputSchema`); `None`
    /// means no arguments were supplied.
    pub fn parse(raw: Option<&Value>) -> Result<Self, Vec<InputIssue>> {
        let mut object = InputObject::new(raw)?;
        let path = object.local_path("path");
        let max_file_bytes = object.integer(
            "max_file_bytes",
            MIN_INSPECT_ELF_NOTE_FILE_BYTES,
            MAX_INSPECT_ELF_NOTE_FILE_BYTES,
            DEFAULT_INSPECT_ELF_NOTE_FILE_BYTES,
        );
        let max_entries = object.integer(
            "max_entries",
            MIN_INSPECT_ELF_NOTE_ENTRIES,
            MAX_INSPECT_ELF_NOTE_ENTRIES,
            DEFAULT_INSPECT_ELF_NOTE_ENTRIES,
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

/// Bytes rendered as lowercase hex without a prefix (`^[0-9a-f]*$`).
///
/// Deserialization additionally requires an even digit count, since odd
/// counts cannot denote bytes and the producer never emits them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct HexBytes(pub Vec<u8>);

impl fmt::Display for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl Serialize for HexBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let (pairs, rest) = text.as_bytes().as_chunks::<2>();
        if !rest.is_empty() {
            return Err(serde::de::Error::custom(
                "expected an even number of lowercase hex digits",
            ));
        }
        pairs
            .iter()
            .map(|[high, low]| Some((lower_hex_value(*high)? << 4) | lower_hex_value(*low)?))
            .collect::<Option<Vec<u8>>>()
            .map(Self)
            .ok_or_else(|| serde::de::Error::custom("expected lowercase hex digits"))
    }
}

/// A target word rendered as `0x` plus lowercase hex without leading zeros.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HexWord(pub u64);

impl fmt::Display for HexWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

impl Serialize for HexWord {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HexWord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let invalid = || serde::de::Error::custom("expected 0x followed by lowercase hex digits");
        let digits = text.strip_prefix("0x").ok_or_else(invalid)?;
        if digits.is_empty() {
            return Err(invalid());
        }
        digits
            .bytes()
            .try_fold(0u64, |value, digit| {
                let digit = lower_hex_value(digit).ok_or_else(invalid)?;
                value
                    .checked_mul(16)
                    .map(|value| value | u64::from(digit))
                    .ok_or_else(|| serde::de::Error::custom("hex word exceeds 64 bits"))
            })
            .map(Self)
    }
}

const fn lower_hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// ELF class of the inspected image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElfNotesFormat {
    /// ELFCLASS32.
    Elf32,
    /// ELFCLASS64.
    Elf64,
}

/// ELF data encoding of the inspected image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElfByteOrder {
    /// ELFDATA2LSB.
    Little,
    /// ELFDATA2MSB.
    Big,
}

/// Object kind named by `e_type`; unknown kinds are not invented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElfObjectTypeName {
    /// `ET_REL`.
    Relocatable,
    /// `ET_EXEC`.
    Executable,
    /// `ET_DYN`.
    Shared,
    /// `ET_CORE`.
    Core,
    /// Any other `e_type`.
    Unknown,
}

impl ElfObjectTypeName {
    /// Map `e_type`.
    pub const fn from_e_type(object_type: u32) -> Self {
        match object_type {
            1 => Self::Relocatable,
            2 => Self::Executable,
            3 => Self::Shared,
            4 => Self::Core,
            _ => Self::Unknown,
        }
    }
}

/// Note type name; only GNU and CORE owners have named types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElfNoteTypeName {
    /// GNU `NT_GNU_ABI_TAG`.
    GnuAbiTag,
    /// GNU `NT_GNU_HWCAP`.
    GnuHwcap,
    /// GNU `NT_GNU_BUILD_ID`.
    GnuBuildId,
    /// GNU `NT_GNU_GOLD_VERSION`.
    GnuGoldVersion,
    /// GNU `NT_GNU_PROPERTY_TYPE_0`.
    GnuProperty,
    /// CORE `NT_PRPSINFO`.
    CorePrpsinfo,
    /// CORE `NT_FILE`.
    CoreFile,
    /// CORE `NT_SIGINFO`.
    CoreSiginfo,
    /// CORE `NT_AUXV`.
    CoreAuxv,
    /// Any other owner or type.
    Unknown,
}

impl ElfNoteTypeName {
    /// Map `n_type` for a GNU-owned note.
    pub const fn gnu(note_type: u32) -> Self {
        match note_type {
            1 => Self::GnuAbiTag,
            2 => Self::GnuHwcap,
            3 => Self::GnuBuildId,
            4 => Self::GnuGoldVersion,
            5 => Self::GnuProperty,
            _ => Self::Unknown,
        }
    }

    /// Map `n_type` for a CORE-owned note.
    pub const fn core(note_type: u32) -> Self {
        match note_type {
            3 => Self::CorePrpsinfo,
            6 => Self::CoreAuxv,
            0x4649_4c45 => Self::CoreFile,
            0x5349_4749 => Self::CoreSiginfo,
            _ => Self::Unknown,
        }
    }
}

/// Which declaration owns a note table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElfNoteTableKind {
    /// A `PT_NOTE` program header.
    Program,
    /// An `SHT_NOTE` section header.
    Section,
}

/// A physical file range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfFileRange {
    /// File offset.
    pub offset: u32,
    /// Length in bytes.
    pub bytes: u32,
}

/// The inspected artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfNotesArtifact {
    /// Caller-selected path, preserved as given.
    #[serde(deserialize_with = "non_empty_string")]
    pub path: String,
    /// SHA-256 of the inspected bytes.
    pub sha256: Sha256Digest,
    /// Inspected byte length.
    pub bytes: u32,
}

fn non_empty_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let text = String::deserialize(deserializer)?;
    if text.is_empty() {
        return Err(serde::de::Error::custom("expected a non-empty string"));
    }
    Ok(text)
}

/// One declared note table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfNoteTable {
    /// Declaring header kind.
    pub kind: ElfNoteTableKind,
    /// Index within the program or section header table.
    pub index: u32,
    /// Section name, when a readable section-name table names it.
    pub name: Option<String>,
    /// Declared file range.
    pub location: ElfFileRange,
    /// Effective note padding: 8 when declared 8, otherwise 4.
    pub alignment: u32,
}

/// GNU `NT_GNU_ABI_TAG` fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnuAbiTag {
    /// OS word.
    pub os: u32,
    /// Known OS name for `os`.
    pub os_name: Option<String>,
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Subminor version.
    pub subminor: u32,
}

/// GNU-owner descriptor facts; members stay null unless the type matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfGnuNote {
    /// `NT_GNU_BUILD_ID` descriptor bytes.
    pub build_id_hex: Option<HexBytes>,
    /// `NT_GNU_ABI_TAG` fields for a 16-byte descriptor.
    pub abi_tag: Option<GnuAbiTag>,
    /// `NT_GNU_GOLD_VERSION` text without trailing NULs (Latin-1 decoded).
    pub gold_version: Option<String>,
}

/// CORE `NT_PRPSINFO` fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorePrpsinfo {
    /// `pr_state`.
    pub state: u32,
    /// `pr_pid`.
    pub pid: i32,
    /// `pr_ppid`.
    pub ppid: i32,
    /// `pr_pgrp`.
    pub pgrp: i32,
    /// `pr_sid`.
    pub sid: i32,
    /// `pr_uid`.
    pub uid: u32,
    /// `pr_gid`.
    pub gid: u32,
    /// `pr_fname` up to its first NUL (Latin-1 decoded).
    pub filename: String,
    /// `pr_psargs` up to its first NUL (Latin-1 decoded).
    pub psargs: String,
}

/// One CORE `NT_FILE` mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreFileMapping {
    /// Mapping start address.
    pub start_address: HexWord,
    /// Mapping end address.
    pub end_address: HexWord,
    /// File offset in pages.
    pub file_offset_pages: HexWord,
    /// Mapped path (Latin-1 decoded).
    pub path: String,
    /// Mapped path bytes.
    pub path_hex: HexBytes,
}

/// CORE `NT_FILE` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreFile {
    /// Declared mapping count.
    pub count: u32,
    /// Declared page size.
    pub page_size: u32,
    /// Mappings in declaration order.
    pub mappings: Vec<CoreFileMapping>,
}

/// CORE `NT_SIGINFO` fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreSiginfo {
    /// `si_signo`.
    pub signo: i32,
    /// `si_code`.
    pub code: i32,
    /// `si_errno`.
    pub errno: i32,
}

/// One CORE `NT_AUXV` entry before `AT_NULL`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreAuxvEntry {
    /// `a_type`.
    #[serde(rename = "type")]
    pub entry_type: u32,
    /// Known `AT_*` name for `type`.
    pub type_name: Option<String>,
    /// `a_val`.
    pub value: HexWord,
}

/// CORE-owner descriptor facts; exactly the decoded member is non-null.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfCoreNote {
    /// `NT_PRPSINFO`.
    pub prpsinfo: Option<CorePrpsinfo>,
    /// `NT_FILE`.
    pub file: Option<CoreFile>,
    /// `NT_SIGINFO`.
    pub siginfo: Option<CoreSiginfo>,
    /// `NT_AUXV`.
    pub auxv: Option<Vec<CoreAuxvEntry>>,
}

/// A note descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfNoteDescriptor {
    /// Descriptor file range.
    pub location: ElfFileRange,
    /// Descriptor length (`descsz`).
    pub bytes: u32,
    /// SHA-256 of the descriptor bytes.
    pub sha256: Sha256Digest,
    /// Descriptor bytes when `descsz` is at most 64.
    pub hex: Option<HexBytes>,
}

/// One examined note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfNoteEntry {
    /// Position across every examined table.
    pub index: u32,
    /// Declaring table kind.
    pub table_kind: ElfNoteTableKind,
    /// Declaring table index.
    pub table_index: u32,
    /// Note file range, including padding.
    pub location: ElfFileRange,
    /// `n_namesz`.
    pub namesz: u32,
    /// `n_descsz`.
    pub descsz: u32,
    /// `n_type`.
    #[serde(rename = "type")]
    pub note_type: u32,
    /// Owner-specific type name.
    pub type_name: ElfNoteTypeName,
    /// Owner name up to its first NUL (Latin-1 decoded).
    pub owner: String,
    /// All `namesz` owner-name bytes.
    pub owner_bytes_hex: HexBytes,
    /// Descriptor facts.
    pub descriptor: ElfNoteDescriptor,
    /// GNU facts; null for other owners.
    pub gnu: Option<ElfGnuNote>,
    /// CORE facts; null for other owners or undecoded notes.
    pub core: Option<ElfCoreNote>,
}

/// Coverage status; a result is only produced when complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElfNotesCoverageStatus {
    /// Every declared table and note was examined.
    Complete,
}

/// Examined coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfNotesCoverage {
    /// Coverage status.
    pub status: ElfNotesCoverageStatus,
    /// Examined note tables.
    pub examined_tables: u32,
    /// Examined note entries.
    pub examined_entries: u32,
}

/// Observed ELF note tables; absence is an empty list, not proof notes never existed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfNotes {
    /// Inspected artifact.
    pub artifact: ElfNotesArtifact,
    /// ELF class.
    pub format: ElfNotesFormat,
    /// ELF data encoding.
    pub byte_order: ElfByteOrder,
    /// `e_machine`.
    pub machine: u32,
    /// `e_type`.
    #[serde(rename = "type")]
    pub object_type: u32,
    /// Name for `e_type`.
    pub type_name: ElfObjectTypeName,
    /// Declared note tables, programs first.
    pub tables: Vec<ElfNoteTable>,
    /// Examined notes in table order.
    pub entries: Vec<ElfNoteEntry>,
    /// Examined coverage.
    pub coverage: ElfNotesCoverage,
    /// Scope and unavailable-fact limitations.
    pub limitations: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::error::InputIssueReason;
    use serde_json::{Number, json};

    fn parse(raw: Value) -> Result<InspectElfNotesInput, Vec<InputIssue>> {
        InspectElfNotesInput::parse(Some(&raw))
    }

    fn range(key: &str, minimum: Option<u64>, maximum: Option<u64>) -> InputIssue {
        InputIssue::new([key], InputIssueReason::OutOfRange)
            .with_range(minimum.map(Number::from), maximum.map(Number::from))
    }

    #[test]
    fn input_defaults_and_member_order() {
        let input = parse(json!({"path": "/artifacts/app"})).unwrap();
        assert_eq!(input, InspectElfNotesInput::new("/artifacts/app"));
        assert_eq!(
            serde_json::to_string(&input).unwrap(),
            r#"{"path":"/artifacts/app","max_file_bytes":67108864,"max_entries":32}"#
        );
    }

    #[test]
    fn input_parsing_reports_each_issue_in_shape_order_then_unknown_members() {
        assert_eq!(
            parse(json!({"zeta": 1, "max_entries": 257, "max_file_bytes": 63, "path": "/a"})),
            Err(vec![
                range("max_file_bytes", Some(64), None),
                range("max_entries", None, Some(256)),
                InputIssue::new(["zeta"], InputIssueReason::UnknownArgument),
            ])
        );
        assert_eq!(
            parse(
                json!({"path": "/a", "max_file_bytes": MAX_INSPECT_ELF_NOTE_FILE_BYTES + 1, "max_entries": 0})
            ),
            Err(vec![
                range(
                    "max_file_bytes",
                    None,
                    Some(MAX_INSPECT_ELF_NOTE_FILE_BYTES)
                ),
                range("max_entries", Some(1), None),
            ])
        );
        assert_eq!(
            parse(json!({"path": "/a", "max_file_bytes": -5, "max_entries": 1.5})),
            Err(vec![
                range("max_file_bytes", Some(64), None),
                InputIssue::new(["max_entries"], InputIssueReason::InvalidType)
                    .with_expected("int"),
            ])
        );
        let accepted = parse(json!({
            "path": "/a",
            "max_file_bytes": MAX_INSPECT_ELF_NOTE_FILE_BYTES,
            "max_entries": 256.0,
        }))
        .unwrap();
        assert_eq!(accepted.max_entries, MAX_INSPECT_ELF_NOTE_ENTRIES);
    }

    #[test]
    fn input_parsing_admits_only_nonempty_nul_free_path_text() {
        assert_eq!(
            parse(json!({})),
            Err(vec![
                InputIssue::new(["path"], InputIssueReason::MissingArgument)
                    .with_expected("string")
            ])
        );
        assert_eq!(
            parse(json!({"path": 7, "max_entries": "8"})),
            Err(vec![
                InputIssue::new(["path"], InputIssueReason::InvalidType).with_expected("string"),
                InputIssue::new(["max_entries"], InputIssueReason::InvalidType)
                    .with_expected("number"),
            ])
        );
        assert_eq!(
            parse(json!({"path": ""})),
            Err(vec![range("path", Some(1), None)])
        );
        assert_eq!(
            parse(json!({"path": "/a\0b"})),
            Err(vec![
                InputIssue::new(["path"], InputIssueReason::InvalidFormat)
                    .with_expected("regex")
                    .with_message("Local filesystem paths cannot contain NUL")
            ])
        );
        assert_eq!(
            parse(json!(["/a"])),
            Err(vec![
                InputIssue::new(Vec::<String>::new(), InputIssueReason::InvalidType)
                    .with_expected("object")
            ])
        );
        assert_eq!(
            InspectElfNotesInput::parse(None),
            Err(vec![
                InputIssue::new(Vec::<String>::new(), InputIssueReason::MissingArgument)
                    .with_expected("object")
            ])
        );
    }

    #[test]
    fn hex_values_round_trip_and_reject_foreign_text() {
        let bytes: HexBytes = serde_json::from_str(r#""00ff1a""#).unwrap();
        assert_eq!(bytes, HexBytes(vec![0, 0xff, 0x1a]));
        assert_eq!(serde_json::to_string(&bytes).unwrap(), r#""00ff1a""#);
        assert_eq!(
            serde_json::from_str::<HexBytes>(r#""""#).unwrap(),
            HexBytes::default()
        );
        for invalid in [r#""0""#, r#""FF""#, r#""zz""#] {
            assert!(
                serde_json::from_str::<HexBytes>(invalid).is_err(),
                "{invalid}"
            );
        }

        let word: HexWord = serde_json::from_str(r#""0x7fff0000""#).unwrap();
        assert_eq!(word, HexWord(0x7fff_0000));
        assert_eq!(serde_json::to_string(&HexWord(0)).unwrap(), r#""0x0""#);
        for invalid in [
            r#""0x""#,
            r#""7f""#,
            r#""0xFF""#,
            r#""0x10000000000000000""#,
        ] {
            assert!(
                serde_json::from_str::<HexWord>(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn type_names_follow_owner_tables() {
        assert_eq!(ElfNoteTypeName::gnu(3), ElfNoteTypeName::GnuBuildId);
        assert_eq!(ElfNoteTypeName::gnu(6), ElfNoteTypeName::Unknown);
        assert_eq!(
            ElfNoteTypeName::core(0x4649_4c45),
            ElfNoteTypeName::CoreFile
        );
        assert_eq!(ElfNoteTypeName::core(1), ElfNoteTypeName::Unknown);
        assert_eq!(ElfObjectTypeName::from_e_type(4), ElfObjectTypeName::Core);
        assert_eq!(
            ElfObjectTypeName::from_e_type(0xfe00),
            ElfObjectTypeName::Unknown
        );
        assert_eq!(
            serde_json::to_string(&ElfNoteTypeName::GnuGoldVersion).unwrap(),
            r#""gnu_gold_version""#
        );
    }
}
