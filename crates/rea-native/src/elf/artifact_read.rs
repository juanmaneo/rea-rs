//! Stable-read failure projection shared by the ELF providers.
//!
//! Upstream reference: `upstream:src/artifacts/StableArtifactFailure.ts` and
//! the read classification in `upstream:src/native/elf/ElfNotesProvider.ts`
//! and `upstream:src/native/elf/KernelModuleProvider.ts`.

use std::path::Path;

use rea_domain::error::{
    AccessDeniedCode, AnalysisError, ArtifactOperationError, InputError, InputIssue,
    InputIssueReason,
};
use rea_filesystem::{ErrnoCode, StableReadError};

/// The operation and selection a stable read served.
pub(crate) struct ReadSubject<'a> {
    pub(crate) operation: &'static str,
    /// Caller-facing noun for the selection, such as `Selected ELF image`.
    pub(crate) noun: &'static str,
    pub(crate) path: &'a str,
}

/// Project a stable-read failure. `file_size` projects a read beyond the
/// caller's `max_file_bytes` from its message.
pub(crate) fn read_failure(
    failure: StableReadError,
    subject: &ReadSubject<'_>,
    file_size: impl FnOnce(String) -> AnalysisError,
) -> AnalysisError {
    let ReadSubject {
        operation,
        noun,
        path,
    } = *subject;
    let message = failure.to_string();
    match failure {
        StableReadError::Changed { .. } => {
            AnalysisError::artifact_changed(operation, path.to_owned(), message)
        }
        StableReadError::Cancelled => AnalysisError::cancelled(operation),
        StableReadError::ExceedsLimit { .. } | StableReadError::GrewBeyondLimit { .. } => {
            file_size(message)
        }
        StableReadError::NotRegularFile { resolved_path, .. } => {
            // A non-UTF-8 target cannot be named in caller-facing text, so
            // only the retry hint is omitted.
            let resolved = resolved_path
                .as_deref()
                .and_then(Path::to_str)
                .map(str::to_owned);
            invalid_format(operation, message, resolved)
        }
        StableReadError::Io { ref source, .. } => match ErrnoCode::of(source) {
            Some(ErrnoCode::Eacces) => {
                AnalysisError::access_denied(operation, path.to_owned(), AccessDeniedCode::Eacces)
            }
            Some(ErrnoCode::Eperm) => {
                AnalysisError::access_denied(operation, path.to_owned(), AccessDeniedCode::Eperm)
            }
            Some(code) if code.is_selected_regular_file() => AnalysisError::input(
                operation,
                [
                    InputIssue::new(["path"], InputIssueReason::InvalidValue).with_message(
                        format!("{noun} could not be read ({}): {path}.", code.as_str()),
                    ),
                ],
            ),
            _ => ArtifactOperationError::new(operation, failure.reason(), Some(message)).into(),
        },
    }
}

/// A malformed selection; a rejected symlink offers its verified target.
///
/// Upstream reference: `stableArtifactInputRecovery` in
/// `upstream:src/artifacts/StableArtifactFailure.ts`.
pub(crate) fn invalid_format(
    operation: &'static str,
    message: String,
    resolved_path: Option<String>,
) -> AnalysisError {
    let error = InputError::new(operation).with_issues([InputIssue::new(
        ["path"],
        InputIssueReason::InvalidFormat,
    )
    .with_message(message)]);
    match resolved_path {
        Some(resolved) => error
            .with_remediation_action(format!(
                "Retry with the resolved regular file path {resolved}. The selected symlink is not admitted; the retry will validate the target again."
            ))
            .conforming_to_input_contract()
            .into(),
        None => error.into(),
    }
}
