//! `inspect_elf_notes`: caller validation, output checks, and Evidence
//! provenance shared by the CLI and MCP adapters.
//!
//! Upstream reference:
//! `upstream:src/application/binaryDiagnostics/ElfNotesService.ts` and
//! `ElfNotesPort.ts`.

use std::path::Path;

use rea_domain::cancellation::CancellationSignal;
use rea_domain::error::{AnalysisError, InputIssue, InputIssueReason};
use rea_domain::evidence::{
    BinaryArchitecture, Evidence, EvidenceLocation, EvidenceObservation, EvidenceSubjectTarget,
    SubjectFormat,
};
use rea_domain::native::elf::ElfFileRange;
use rea_domain::native::elf_notes::{ElfNotes, InspectElfNotesInput};
use rea_domain::providers::ProviderIdentity;
use rea_native::elf::ElfNotesProvider;
use serde_json::Value;

use crate::evidence::complete_provider_evidence;

/// Public operation name.
pub const OPERATION: &str = "inspect_elf_notes";

const MALFORMED_OUTPUT: &str =
    "ELF note provider returned malformed output or changed artifact identity.";

/// Stable read and ELF note-table decoding, independent of a disassembler session.
pub trait ElfNotesPort {
    /// The provider's Evidence identity.
    fn identity(&self) -> ProviderIdentity;

    /// Decode the note tables of the admitted input.
    fn inspect(
        &self,
        input: &InspectElfNotesInput,
        signal: &CancellationSignal,
    ) -> Result<ElfNotes, AnalysisError>;
}

impl ElfNotesPort for ElfNotesProvider {
    fn identity(&self) -> ProviderIdentity {
        Self::IDENTITY
    }

    fn inspect(
        &self,
        input: &InspectElfNotesInput,
        signal: &CancellationSignal,
    ) -> Result<ElfNotes, AnalysisError> {
        ElfNotesProvider::inspect(self, input, signal)
    }
}

/// The `inspect_elf_notes` workflow over one provider.
#[derive(Debug, Clone, Default)]
pub struct ElfNotesService<P = ElfNotesProvider> {
    provider: P,
}

impl<P: ElfNotesPort> ElfNotesService<P> {
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
        let input = InspectElfNotesInput::parse(raw)
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
    report: &ElfNotes,
    input: &InspectElfNotesInput,
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
        report
            .tables
            .iter()
            .map(|table| EvidenceLocation::FileOffsetRange {
                start: u64::from(table.location.offset),
                end: u64::from(table.location.offset) + u64::from(table.location.bytes),
            }),
    )
    .collect();
    let target = EvidenceSubjectTarget {
        path: report.artifact.path.clone(),
        sha256: report.artifact.sha256,
        format: SubjectFormat::Elf,
        architecture: u16::try_from(report.machine)
            .ok()
            .and_then(BinaryArchitecture::from_elf_machine),
    };
    Evidence::create(Some(&target), &provider.to_evidence_provider(), observation)
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))
}

/// Counts and ranges stay within the admitted budgets and artifact.
fn valid_report(report: &ElfNotes, input: &InspectElfNotesInput) -> bool {
    let artifact_bytes = u64::from(report.artifact.bytes);
    let inside =
        |range: &ElfFileRange| u64::from(range.offset) + u64::from(range.bytes) <= artifact_bytes;
    let coverage = &report.coverage;
    artifact_bytes <= input.max_file_bytes
        && u64::from(coverage.examined_entries) <= input.max_entries
        && report.entries.len() == coverage.examined_entries as usize
        && report.tables.len() == coverage.examined_tables as usize
        && report.tables.iter().all(|table| inside(&table.location))
        && report
            .entries
            .iter()
            .all(|entry| inside(&entry.location) && inside(&entry.descriptor.location))
}
