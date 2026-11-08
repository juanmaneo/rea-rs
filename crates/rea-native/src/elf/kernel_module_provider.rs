//! The `inspect_kernel_module` provider: one stable read, then the
//! kernel-module parser.
//!
//! Upstream reference: `upstream:src/native/elf/KernelModuleProvider.ts`.

use std::path::Path;

use rea_domain::cancellation::CancellationSignal;
use rea_domain::error::{
    AnalysisError, FixedAllowance, FixedAllowanceKind, ResourceConstraintError,
    ResourceConstraintRecovery, ResourceKind,
};
use rea_domain::native::elf::InspectedArtifact;
use rea_domain::native::kernel_module::{
    InspectKernelModuleInput, KernelModule, MAX_INSPECT_KERNEL_MODULE_ENTRIES,
    MAX_INSPECT_KERNEL_MODULE_FILE_BYTES,
};
use rea_domain::providers::{KERNEL_MODULE_PROVIDER, ProviderIdentity};
use rea_filesystem::read_stable_artifact;
use serde_json::{Map, Value};

use super::artifact_read::{ReadSubject, invalid_format, read_failure};
use super::image::STRUCTURE_BYTES;
use super::{KernelModuleFailure, parse_kernel_module};

const OPERATION: &str = "inspect_kernel_module";

/// Portable parser over one bounded, identity-checked regular file.
///
/// The work is synchronous; asynchronous callers run it as blocking work.
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelModuleProvider;

impl KernelModuleProvider {
    /// This provider's Evidence identity.
    pub const IDENTITY: ProviderIdentity = KERNEL_MODULE_PROVIDER;

    /// Read `input.path` once and decode its kernel-module metadata.
    pub fn inspect(
        &self,
        input: &InspectKernelModuleInput,
        signal: &CancellationSignal,
    ) -> Result<KernelModule, AnalysisError> {
        let subject = ReadSubject {
            operation: OPERATION,
            noun: "Selected kernel module",
            path: &input.path,
        };
        let snapshot = read_stable_artifact(Path::new(&input.path), input.max_file_bytes, signal)
            .map_err(|failure| {
            read_failure(failure, &subject, |message| {
                file_size_failure(message, input)
            })
        })?;
        let Ok(bytes) = u32::try_from(snapshot.bytes.len()) else {
            // The stable read admits at most `max_file_bytes`, which input
            // validation bounds well below `u32::MAX`.
            return Err(file_size_failure(
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
        parse_kernel_module(&snapshot.bytes, artifact, input)
            .map_err(|failure| parse_failure(failure, input))
    }
}

fn parse_failure(failure: KernelModuleFailure, input: &InspectKernelModuleInput) -> AnalysisError {
    let message = failure.to_string();
    match failure {
        KernelModuleFailure::Malformed { .. } => invalid_format(OPERATION, message, None),
        KernelModuleFailure::Structure { .. } => {
            let mut limits = Map::new();
            limits.insert("boundary".into(), "structure".into());
            limits.insert("maximum_bytes".into(), STRUCTURE_BYTES.into());
            ResourceConstraintError::new(OPERATION, ResourceKind::Memory, message, Some(limits))
                .with_recovery(ResourceConstraintRecovery::fixed(FixedAllowance::new(
                    "The ELF structural decoding allowance",
                    FixedAllowanceKind::Parser,
                )))
                .into()
        }
        KernelModuleFailure::Capacity { .. } => budget_failure(
            ResourceKind::Capacity,
            message,
            input,
            if input.max_entries >= MAX_INSPECT_KERNEL_MODULE_ENTRIES {
                format!(
                    "The image exceeds the {MAX_INSPECT_KERNEL_MODULE_ENTRIES}-entry kernel-module ceiling this operation accepts; select a smaller artifact."
                )
            } else {
                format!(
                    "Raise max_entries above {} or select a smaller artifact; the limit is the caller-selected .modinfo and __versions entry budget.",
                    input.max_entries
                )
            },
        ),
        KernelModuleFailure::FileSize { .. } => file_size_failure(message, input),
    }
}

fn file_size_failure(message: String, input: &InspectKernelModuleInput) -> AnalysisError {
    budget_failure(
        ResourceKind::FileSize,
        message,
        input,
        if input.max_file_bytes >= MAX_INSPECT_KERNEL_MODULE_FILE_BYTES {
            format!(
                "The image exceeds the {MAX_INSPECT_KERNEL_MODULE_FILE_BYTES}-byte input ceiling this operation accepts; select a smaller artifact."
            )
        } else {
            format!(
                "Raise max_file_bytes above {} bytes or select a smaller artifact; the limit is the caller-selected input read budget.",
                input.max_file_bytes
            )
        },
    )
}

/// A caller-selected read or entry budget names the bound to raise.
fn budget_failure(
    resource: ResourceKind,
    message: String,
    input: &InspectKernelModuleInput,
    remediation: String,
) -> AnalysisError {
    let mut limits = Map::new();
    limits.insert("max_file_bytes".into(), Value::from(input.max_file_bytes));
    limits.insert("max_entries".into(), Value::from(input.max_entries));
    ResourceConstraintError::new(OPERATION, resource, message, Some(limits))
        .with_recovery(ResourceConstraintRecovery::non_retryable(remediation))
        .into()
}
