//! Format-neutral facts shared by ELF result contracts.
//!
//! Upstream reference: the shared members of
//! `upstream:src/domain/native/elfNotes.ts` and
//! `upstream:src/domain/native/kernelModule.ts`.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::digest::Sha256Digest;

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

pub(crate) const fn lower_hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// ELF class of the inspected image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElfFormat {
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
pub struct InspectedArtifact {
    /// Caller-selected path, preserved as given.
    #[serde(deserialize_with = "non_empty_string")]
    pub path: String,
    /// SHA-256 of the inspected bytes.
    pub sha256: Sha256Digest,
    /// Inspected byte length.
    pub bytes: u32,
}

pub(crate) fn non_empty_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    let text = String::deserialize(deserializer)?;
    if text.is_empty() {
        return Err(serde::de::Error::custom("expected a non-empty string"));
    }
    Ok(text)
}
