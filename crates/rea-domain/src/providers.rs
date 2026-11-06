//! Identities of REA's built-in, execution-free providers.
//!
//! Upstream reference: `upstream:src/domain/investigationProviders.ts`.
//! Identities are added here as each capability is ported.

use crate::evidence::EvidenceProvider;

/// A provider's stable Evidence identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProviderIdentity {
    /// Stable identifier recorded in Evidence.
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// Provider version.
    pub version: &'static str,
}

impl ProviderIdentity {
    /// The Evidence `provider` member for this identity.
    pub fn to_evidence_provider(self) -> EvidenceProvider {
        EvidenceProvider {
            id: self.id.to_owned(),
            name: self.name.to_owned(),
            version: Some(self.version.to_owned()),
        }
    }
}

/// Portable, execution-free ELF note-table decoding.
pub const ELF_NOTES_PROVIDER: ProviderIdentity = ProviderIdentity {
    id: "rea-elf-notes",
    name: "REA ELF note parser",
    version: "1",
};
