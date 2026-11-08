//! The `inspect_elf_notes` provider: one stable read, then the note parser.
//!
//! Upstream reference: `upstream:src/native/elf/ElfNotesProvider.ts`.

use std::path::Path;

use rea_domain::cancellation::CancellationSignal;
use rea_domain::error::{
    AnalysisError, FixedAllowance, FixedAllowanceKind, ResourceConstraintError,
    ResourceConstraintRecovery, ResourceKind,
};
use rea_domain::native::elf::InspectedArtifact;
use rea_domain::native::elf_notes::{
    ElfNotes, InspectElfNotesInput, MAX_INSPECT_ELF_NOTE_ENTRIES, MAX_INSPECT_ELF_NOTE_FILE_BYTES,
};
use rea_domain::providers::{ELF_NOTES_PROVIDER, ProviderIdentity};
use rea_filesystem::read_stable_artifact;
use serde_json::{Map, Value};

use super::artifact_read::{ReadSubject, invalid_format, read_failure};
use super::{BinaryFormatFailureKind, ElfNotesFailure, ElfNotesLimitBoundary, parse_elf_notes};

const OPERATION: &str = "inspect_elf_notes";

const NOTE_TEXT_BUDGET: &str = "The ELF note text, hash, and scan budget fixed by the admitted image length plus decoded section names";

/// Portable parser over one bounded, identity-checked regular file.
///
/// The work is synchronous; asynchronous callers run it as blocking work.
#[derive(Debug, Clone, Copy, Default)]
pub struct ElfNotesProvider;

impl ElfNotesProvider {
    /// This provider's Evidence identity.
    pub const IDENTITY: ProviderIdentity = ELF_NOTES_PROVIDER;

    /// Read `input.path` once and decode its note tables.
    pub fn inspect(
        &self,
        input: &InspectElfNotesInput,
        signal: &CancellationSignal,
    ) -> Result<ElfNotes, AnalysisError> {
        let subject = ReadSubject {
            operation: OPERATION,
            noun: "Selected ELF image",
            path: &input.path,
        };
        let snapshot = read_stable_artifact(Path::new(&input.path), input.max_file_bytes, signal)
            .map_err(|failure| {
            read_failure(failure, &subject, |message| {
                limit_failure(ElfNotesLimitBoundary::FileSize, message, input)
            })
        })?;
        let Ok(bytes) = u32::try_from(snapshot.bytes.len()) else {
            // The stable read admits at most `max_file_bytes`, which input
            // validation bounds well below `u32::MAX`.
            return Err(limit_failure(
                ElfNotesLimitBoundary::FileSize,
                format!(
                    "Selected artifact exceeds {} bytes: {}",
                    input.max_file_bytes, input.path
                ),
                input,
            ));
        };
        let artifact = InspectedArtifact {
            path: input.path.clone(),
            sha256: snapshot.sha256,
            bytes,
        };
        parse_elf_notes(&snapshot.bytes, artifact, input)
            .map_err(|failure| parse_failure(failure, input))
    }
}

fn parse_failure(failure: ElfNotesFailure, input: &InspectElfNotesInput) -> AnalysisError {
    match failure {
        ElfNotesFailure::SectionNameBudget {
            minimum_max_file_bytes,
            selected_max_file_bytes,
        } => {
            let message = failure.to_string();
            let mut limits = Map::new();
            limits.insert("max_file_bytes".into(), selected_max_file_bytes.into());
            limits.insert(
                "minimum_required_bytes".into(),
                minimum_max_file_bytes.to_string().into(),
            );
            let remediation = if minimum_max_file_bytes
                <= u128::from(MAX_INSPECT_ELF_NOTE_FILE_BYTES)
            {
                format!(
                    "Raise max_file_bytes to at least {minimum_max_file_bytes} bytes to admit the source and decoded ELF section names."
                )
            } else {
                format!(
                    "The source and decoded ELF section names require {minimum_max_file_bytes} bytes, above this operation's {MAX_INSPECT_ELF_NOTE_FILE_BYTES}-byte maximum; select an image with a smaller section-name table."
                )
            };
            ResourceConstraintError::new(OPERATION, ResourceKind::Memory, message, Some(limits))
                .with_recovery(ResourceConstraintRecovery::non_retryable(remediation))
                .into()
        }
        ElfNotesFailure::Format {
            kind: BinaryFormatFailureKind::Unsupported,
            message,
        } => AnalysisError::unsupported_target(OPERATION, input.path.clone(), message),
        ElfNotesFailure::Format {
            kind: BinaryFormatFailureKind::Malformed,
            message,
        } => invalid_format(OPERATION, message, None),
        ElfNotesFailure::Limit { boundary, message } => limit_failure(boundary, message, input),
    }
}

/// Caller-selected read and entry budgets name the bound to raise. The note
/// text, hash, and scan ceiling equals the admitted image length plus decoded
/// section names, so host memory cannot raise it.
fn limit_failure(
    boundary: ElfNotesLimitBoundary,
    message: String,
    input: &InspectElfNotesInput,
) -> AnalysisError {
    let mut limits = Map::new();
    limits.insert("max_file_bytes".into(), Value::from(input.max_file_bytes));
    limits.insert("max_entries".into(), Value::from(input.max_entries));
    let (resource, recovery) = match boundary {
        ElfNotesLimitBoundary::Memory => (
            ResourceKind::Memory,
            ResourceConstraintRecovery::fixed(FixedAllowance::new(
                NOTE_TEXT_BUDGET,
                FixedAllowanceKind::Parser,
            )),
        ),
        ElfNotesLimitBoundary::FileSize => (
            ResourceKind::FileSize,
            ResourceConstraintRecovery::non_retryable(
                if input.max_file_bytes >= MAX_INSPECT_ELF_NOTE_FILE_BYTES {
                    format!(
                        "The image exceeds the {MAX_INSPECT_ELF_NOTE_FILE_BYTES}-byte input ceiling this operation accepts; select a smaller artifact."
                    )
                } else {
                    format!(
                        "Raise max_file_bytes above {} bytes or select a smaller artifact; the limit is the caller-selected input read budget.",
                        input.max_file_bytes
                    )
                },
            ),
        ),
        ElfNotesLimitBoundary::Capacity => (
            ResourceKind::Capacity,
            ResourceConstraintRecovery::non_retryable(
                if input.max_entries >= MAX_INSPECT_ELF_NOTE_ENTRIES {
                    format!(
                        "The image exceeds the {MAX_INSPECT_ELF_NOTE_ENTRIES}-entry note-table ceiling this operation accepts; select a smaller artifact."
                    )
                } else {
                    format!(
                        "Raise max_entries above {} or select a smaller artifact; the limit is the caller-selected note entry budget.",
                        input.max_entries
                    )
                },
            ),
        ),
    };
    ResourceConstraintError::new(OPERATION, resource, message, Some(limits))
        .with_recovery(recovery)
        .into()
}
