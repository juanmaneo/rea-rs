//! Canonical digest and identifier shapes.
//!
//! Every digest REA emits is lowercase hex SHA-256. Namespaced identifiers use
//! `<prefix>_<64 lowercase hex>` so that an identifier pasted from another
//! family fails validation instead of resolving to the wrong object.
//!
//! Upstream reference: `upstream:src/domain/digests.ts`.

use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

/// A lowercase hex SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Wrap raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Digest `bytes` in one call.
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Finish an incremental hasher.
    pub fn finish(hasher: Sha256) -> Self {
        Self(hasher.finalize().into())
    }

    /// The raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({self})")
    }
}

/// A string that is not a lowercase hex SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("expected a lowercase hex SHA-256 digest")]
pub struct InvalidDigest;

impl FromStr for Sha256Digest {
    type Err = InvalidDigest;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes: &[u8; 64] = text.as_bytes().try_into().map_err(|_| InvalidDigest)?;
        let mut digest = [0u8; 32];
        for (slot, [high, low]) in digest.iter_mut().zip(bytes.as_chunks::<2>().0) {
            *slot = (lower_hex_value(*high)? << 4) | lower_hex_value(*low)?;
        }
        Ok(Self(digest))
    }
}

const fn lower_hex_value(byte: u8) -> Result<u8, InvalidDigest> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(InvalidDigest),
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// An identifier family with a fixed textual prefix.
pub trait IdentifierFamily {
    /// The prefix without the trailing underscore, for example `ev`.
    const PREFIX: &'static str;
}

/// Evidence semantic identifiers (`ev_`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceFamily {}

impl IdentifierFamily for EvidenceFamily {
    const PREFIX: &'static str = "ev";
}

/// A namespaced identifier `<prefix>_<digest>`; each family is a distinct type.
pub struct PrefixedDigest<F: IdentifierFamily> {
    digest: Sha256Digest,
    family: PhantomData<fn() -> F>,
}

impl<F: IdentifierFamily> Clone for PrefixedDigest<F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: IdentifierFamily> Copy for PrefixedDigest<F> {}

impl<F: IdentifierFamily> PartialEq for PrefixedDigest<F> {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

impl<F: IdentifierFamily> Eq for PrefixedDigest<F> {}

impl<F: IdentifierFamily> std::hash::Hash for PrefixedDigest<F> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}

impl<F: IdentifierFamily> PrefixedDigest<F> {
    /// Bind a digest to this identifier family.
    pub const fn new(digest: Sha256Digest) -> Self {
        Self {
            digest,
            family: PhantomData,
        }
    }

    /// The bare digest.
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

impl<F: IdentifierFamily> fmt::Display for PrefixedDigest<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", F::PREFIX, self.digest)
    }
}

impl<F: IdentifierFamily> fmt::Debug for PrefixedDigest<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// A string that is not a `<prefix>_<digest>` identifier of the expected family.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("expected a {prefix}_ prefixed lowercase sha256 digest")]
pub struct InvalidPrefixedDigest {
    prefix: &'static str,
}

impl<F: IdentifierFamily> FromStr for PrefixedDigest<F> {
    type Err = InvalidPrefixedDigest;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = InvalidPrefixedDigest { prefix: F::PREFIX };
        let rest = text
            .strip_prefix(F::PREFIX)
            .and_then(|rest| rest.strip_prefix('_'))
            .ok_or_else(|| invalid.clone())?;
        rest.parse().map(Self::new).map_err(|_| invalid)
    }
}

impl<F: IdentifierFamily> Serialize for PrefixedDigest<F> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de, F: IdentifierFamily> Deserialize<'de> for PrefixedDigest<F> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_round_trips_lowercase_hex_only() {
        let digest = Sha256Digest::of(b"abc");
        let text = digest.to_string();
        assert_eq!(
            text,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(text.parse::<Sha256Digest>(), Ok(digest));
        assert!(text.to_uppercase().parse::<Sha256Digest>().is_err());
        assert!(text[1..].parse::<Sha256Digest>().is_err());
    }

    #[test]
    fn prefixed_digest_rejects_other_families() {
        type EvidenceId = PrefixedDigest<EvidenceFamily>;
        let digest = Sha256Digest::of(b"abc");
        let id = EvidenceId::new(digest);
        let text = id.to_string();
        assert!(text.starts_with("ev_"));
        assert_eq!(text.parse::<EvidenceId>(), Ok(id));
        assert!(format!("xx_{digest}").parse::<EvidenceId>().is_err());
        assert!(digest.to_string().parse::<EvidenceId>().is_err());
    }
}
