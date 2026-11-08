//! ELF readers.
//!
//! [`parse_elf_notes`] decodes `PT_NOTE` and `SHT_NOTE` tables from one
//! in-memory ELF image into the `inspect_elf_notes` result contract.
//! [`parse_kernel_module`] decodes Linux kernel-module metadata into the
//! `inspect_kernel_module` result contract.

mod artifact_read;
mod budget;
mod descriptors;
mod header;
mod image;
mod kernel_module;
mod kernel_module_provider;
mod notes;
mod provider;
mod section_names;

pub use kernel_module::parse_kernel_module;
pub use kernel_module_provider::KernelModuleProvider;
pub use notes::parse_elf_notes;
pub use provider::ElfNotesProvider;

/// Whether a format failure is malformed input or an unsupported feature.
///
/// Upstream reference: `BinaryFormatFailure.kind` in
/// `upstream:src/native/metadata/BinaryContainer.ts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryFormatFailureKind {
    /// The bytes violate the format (invalid input).
    Malformed,
    /// The bytes are well formed but use a feature this reader refuses
    /// (unsupported target).
    Unsupported,
}

/// The constrained bound of a limit failure.
///
/// Upstream reference: `ArtifactLimitBoundary` in
/// `upstream:src/artifacts/ArtifactReader.ts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfNotesLimitBoundary {
    /// The artifact exceeds the operation's input ceiling.
    FileSize,
    /// The caller-selected `max_entries` budget.
    Capacity,
    /// The note text, hash, and scan budget fixed by the admitted image
    /// length plus decoded section names.
    Memory,
}

/// Why ELF note inspection failed without a partial result.
///
/// Messages are byte-identical to upstream text. Upstream raises malformed
/// input as `ArtifactReaderFailure("format")`; both that and
/// `BinaryFormatFailure("malformed")` project to the same invalid-input
/// issue, so they share [`BinaryFormatFailureKind::Malformed`] here.
///
/// Upstream reference: `upstream:src/native/elf/ElfNoteParser.ts` and the
/// classification in `upstream:src/native/elf/ElfNotesProvider.ts`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ElfNotesFailure {
    /// Malformed or unsupported ELF structure.
    #[error("{message}")]
    Format {
        /// Invalid input versus unsupported target.
        kind: BinaryFormatFailureKind,
        /// Upstream failure text.
        message: String,
    },
    /// The source plus its decoded section-name table exceeds
    /// `max_file_bytes`; raising it to `minimum_max_file_bytes` admits it.
    #[error(
        "ELF source and decoded section names require {minimum_max_file_bytes} bytes, above the selected max_file_bytes ({selected_max_file_bytes})."
    )]
    SectionNameBudget {
        /// Source length plus the declared decoded table size.
        minimum_max_file_bytes: u128,
        /// The caller-selected `max_file_bytes`.
        selected_max_file_bytes: u64,
    },
    /// A read, entry, or text budget was exhausted.
    #[error("{message}")]
    Limit {
        /// The exhausted bound.
        boundary: ElfNotesLimitBoundary,
        /// Upstream failure text.
        message: String,
    },
}

/// Why kernel-module inspection failed without a partial result.
///
/// Messages are byte-identical to upstream text.
///
/// Upstream reference: `upstream:src/native/elf/KernelModuleParser.ts` and
/// the classification in `upstream:src/native/elf/KernelModuleProvider.ts`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KernelModuleFailure {
    /// The ELF structure is malformed (invalid input).
    #[error("{message}")]
    Malformed {
        /// Upstream failure text.
        message: String,
    },
    /// The 16 MiB structural decoding allowance for headers, tables, and
    /// section names is exhausted.
    #[error("{message}")]
    Structure {
        /// Upstream failure text.
        message: String,
    },
    /// The caller-selected `max_entries` budget is exhausted.
    #[error("Kernel module entries exceed the {max_entries}-entry budget.")]
    Capacity {
        /// The caller-selected `max_entries`.
        max_entries: u64,
    },
    /// The image exceeds the operation's input ceiling.
    #[error("{message}")]
    FileSize {
        /// Failure text.
        message: String,
    },
}

impl ElfNotesFailure {
    pub(crate) fn malformed(message: impl Into<String>) -> Self {
        Self::Format {
            kind: BinaryFormatFailureKind::Malformed,
            message: message.into(),
        }
    }

    pub(crate) fn unsupported(message: impl Into<String>) -> Self {
        Self::Format {
            kind: BinaryFormatFailureKind::Unsupported,
            message: message.into(),
        }
    }
}
