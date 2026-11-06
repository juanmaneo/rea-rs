//! Caller-facing message, remediation, and category of a typed failure.
//!
//! Upstream reference: `upstream:src/domain/analysisErrorPresentation.ts`
//! (approved copy in `upstream:docs/user-visible-errors.csv`).

use super::kind::{
    AnalysisErrorKind as Kind, ArtifactDigestClaim, ArtifactLimitBoundary, ArtifactOperationError,
    ArtifactOperationReason, ConfigurationError, EvidenceFileError, EvidenceFileOperation,
    EvidenceFileReason, NO_BINARY_OPEN_MESSAGE, ResourceKind, StorageSystemCode, TimeoutError,
};
use super::projection::ErrorCategory;
use super::{AnalysisError, CallerLifetime};

/// File export when one MCP frame cannot carry the retained session bundle.
pub const MCP_TRANSPORT_EVIDENCE_EXPORT: &str = "Export complete retained session evidence through export_evidence_bundle to a caller-selected path, or use complete CLI JSON output. The connection remains usable.";

/// Next step when one MCP frame cannot carry a complete retained session bundle.
pub const MCP_TRANSPORT_EVIDENCE_DISCOVERY: &str = "Discover retained records with get_evidence_bundle and detail: summary, then read selected complete records with detail: records and an exact evidence_id, or inspect compatible records through inspect_analysis_view using an exact Evidence reference. Export complete retained session evidence through export_evidence_bundle to a caller-selected path, or use complete CLI JSON output. The connection remains usable.";

/// Next step when one MCP frame cannot carry a selected page of complete records.
pub const MCP_TRANSPORT_EVIDENCE_RECORDS: &str = "Request fewer records with get_evidence_bundle detail: records, a smaller limit or an exact evidence_id filter; inspect compatible records in pages through inspect_analysis_view. A single record larger than one response needs export. Export complete retained session evidence through export_evidence_bundle to a caller-selected path, or use complete CLI JSON output. The connection remains usable.";

/// Next step when one MCP frame cannot carry a selected page of link rows.
pub const MCP_TRANSPORT_EVIDENCE_LINKS: &str = "Request fewer rows with get_evidence_bundle detail: links, a smaller limit or an exact evidence_id filter, then follow next_offset.";

const UNREADABLE_OUTPUT: &str = "Analysis returned an unreadable result. Run `rea doctor` and review the reported details; repeating the unchanged request is not expected to succeed.";
const UNSUPPORTED_PROVIDER: &str =
    "This analysis is unavailable for the current target. Choose another analysis or target.";
const CANCELLED: &str = "Analysis was cancelled. Start it again when ready.";
const ADAPTER_FAILURE: &str = "Analysis could not complete. Run `rea doctor` and review the reported details; repeating the unchanged request is not expected to succeed.";
const FALLBACK: &str = "Analysis could not complete. Run `rea doctor`, then try again.";

/// Operations that accept `integrity_policy` for declared-integrity mismatches.
const INTEGRITY_POLICY_OPERATIONS: [&str; 4] = [
    "inventory_artifact",
    "inspect_artifact",
    "extract_artifact",
    "analyze_javascript_application",
];

impl AnalysisError {
    /// Describe the request's outcome, adding continuing-caller facts only
    /// for that caller.
    pub fn user_message(&self, lifetime: CallerLifetime) -> String {
        let error = self.resolved();
        let outcome = error.outcome_user_message();
        let continuing = error
            .continuing_caller_guidance
            .as_ref()
            .and_then(|guidance| guidance.user_message.as_deref());
        match (lifetime, continuing) {
            (CallerLifetime::Continuing, Some(continuing)) => format!("{outcome} {continuing}"),
            _ => outcome,
        }
    }

    /// Name the next step that holds for as long as the caller keeps REA's
    /// runtime and session.
    ///
    /// Like upstream, a failure without specific remediation falls back to
    /// the continuing-caller message even for an invocation caller.
    pub fn remediation_action(&self, lifetime: CallerLifetime) -> String {
        let error = self.resolved();
        if lifetime == CallerLifetime::Continuing
            && let Some(action) = error
                .continuing_caller_guidance
                .as_ref()
                .and_then(|guidance| guidance.remediation_action.as_ref())
        {
            return action.clone();
        }
        if let Some(action) = error.specific_remediation_action() {
            return action;
        }
        error.user_message(CallerLifetime::Continuing)
    }

    /// Category of the original operation's failure, unchanged by cleanup.
    pub fn category(&self) -> ErrorCategory {
        let error = self.primary();
        match &error.kind {
            Kind::CapabilityUnavailable(_) if error.capability_retryable() => {
                ErrorCategory::Unavailable
            }
            Kind::CapabilityUnavailable(_) => ErrorCategory::UnsupportedProvider,
            Kind::ArtifactOperation(artifact) => match artifact.reason {
                ArtifactOperationReason::Integrity => ErrorCategory::IntegrityMismatch,
                ArtifactOperationReason::Limit => ErrorCategory::Truncated,
                ArtifactOperationReason::Cancelled => ErrorCategory::Cancelled,
                ArtifactOperationReason::Unavailable => ErrorCategory::Unavailable,
                ArtifactOperationReason::Format
                | ArtifactOperationReason::Path
                | ArtifactOperationReason::Io => ErrorCategory::ExecutionFailure,
            },
            Kind::EvidenceFile(file) => match file.reason {
                EvidenceFileReason::PathLimit | EvidenceFileReason::StorageLimit => {
                    ErrorCategory::ResourceConstraint
                }
                EvidenceFileReason::Missing
                | EvidenceFileReason::SymlinkTraversal
                | EvidenceFileReason::NotFile
                | EvidenceFileReason::WrongKind
                | EvidenceFileReason::Exists => ErrorCategory::InvalidInput,
                EvidenceFileReason::InvalidJson | EvidenceFileReason::Io => {
                    ErrorCategory::ExecutionFailure
                }
            },
            Kind::Configuration(_) | Kind::Input(_) => ErrorCategory::InvalidInput,
            Kind::AccessDenied(_) | Kind::NoBinaryOpen => ErrorCategory::Unavailable,
            Kind::ArtifactChanged(_) | Kind::EvidenceIntegrity(_) => {
                ErrorCategory::IntegrityMismatch
            }
            Kind::UnsupportedTarget(_) => ErrorCategory::UnsupportedTarget,
            Kind::Cancelled(_) => ErrorCategory::Cancelled,
            Kind::Timeout(_) => ErrorCategory::Timeout,
            Kind::ResourceConstraint(_) => ErrorCategory::ResourceConstraint,
            Kind::Protocol(_) | Kind::Output(_) | Kind::ProviderAdapter(_) => {
                ErrorCategory::ExecutionFailure
            }
        }
    }

    /// The outcome every caller receives, without continuing-caller guidance.
    pub(super) fn outcome_user_message(&self) -> String {
        match &self.kind {
            Kind::UnsupportedTarget(error) => return error.message(),
            Kind::ResourceConstraint(error) => return error.reason.clone(),
            Kind::AccessDenied(_) => {
                return "Host filesystem permissions denied read access to the selected path."
                    .to_owned();
            }
            Kind::ArtifactChanged(_) => {
                return "The selected artifact changed during acquisition; no stable snapshot was decoded."
                    .to_owned();
            }
            Kind::Input(error) => {
                return error.user_message.clone().unwrap_or_else(|| {
                    "Analysis input is invalid. Check the arguments and try again.".to_owned()
                });
            }
            Kind::Timeout(error) => {
                return error
                    .user_message
                    .clone()
                    .unwrap_or_else(|| timeout_user_message(error));
            }
            _ => {}
        }
        if let Some(message) = self.producer_user_message() {
            return message.to_owned();
        }
        match &self.kind {
            Kind::CapabilityUnavailable(_) if self.capability_retryable() => {
                "Required runtime controls are unavailable for this attempt.".to_owned()
            }
            Kind::Protocol(_) | Kind::Output(_) => UNREADABLE_OUTPUT.to_owned(),
            Kind::CapabilityUnavailable(_) => UNSUPPORTED_PROVIDER.to_owned(),
            Kind::Cancelled(_) => CANCELLED.to_owned(),
            Kind::ProviderAdapter(_) => ADAPTER_FAILURE.to_owned(),
            Kind::ArtifactOperation(error) => artifact_message(error),
            Kind::EvidenceIntegrity(_) => {
                "Evidence is invalid or has changed. Recreate or re-import it, then try again."
                    .to_owned()
            }
            Kind::EvidenceFile(error) => evidence_file_message(error).to_owned(),
            Kind::Configuration(error) => configuration_message(error),
            Kind::NoBinaryOpen => NO_BINARY_OPEN_MESSAGE.to_owned(),
            Kind::UnsupportedTarget(_)
            | Kind::ResourceConstraint(_)
            | Kind::AccessDenied(_)
            | Kind::ArtifactChanged(_)
            | Kind::Input(_)
            | Kind::Timeout(_) => FALLBACK.to_owned(),
        }
    }

    /// Upstream's generic `userMessage` override for the tags that carry one.
    fn producer_user_message(&self) -> Option<&str> {
        match &self.kind {
            Kind::Output(error) => error.user_message.as_deref(),
            Kind::CapabilityUnavailable(error) => error.user_message.as_deref(),
            Kind::ProviderAdapter(error) => error.user_message.as_deref(),
            Kind::ArtifactOperation(error) => error.effective_user_message(),
            Kind::EvidenceIntegrity(error) => error.user_message.as_deref(),
            Kind::EvidenceFile(error) => error.user_message.as_deref(),
            Kind::Input(error) => error.user_message.as_deref(),
            Kind::Timeout(error) => error.user_message.as_deref(),
            Kind::Protocol(_)
            | Kind::AccessDenied(_)
            | Kind::ArtifactChanged(_)
            | Kind::UnsupportedTarget(_)
            | Kind::Cancelled(_)
            | Kind::ResourceConstraint(_)
            | Kind::Configuration(_)
            | Kind::NoBinaryOpen => None,
        }
    }

    fn specific_remediation_action(&self) -> Option<String> {
        match &self.kind {
            Kind::ProviderAdapter(error) => error.remediation_action.clone(),
            Kind::CapabilityUnavailable(error) => error.remediation_action.clone().or_else(|| {
                self.capability_retryable().then(|| {
                    "Review details.reason, then retry the same analysis after the condition clears."
                        .to_owned()
                })
            }),
            Kind::EvidenceFile(error) => error.published.as_ref().map(|published| {
                match published.path {
                    None => "Resolve the reported staging cleanup failure. Publication completed; its path identity is excluded.",
                    Some(_) => "Use the published file at details.published_path and resolve the reported staging cleanup failure.",
                }
                .to_owned()
            }),
            Kind::UnsupportedTarget(error) => Some(error.remediation_action.clone().unwrap_or_else(|| {
                "Select a target supported by this operation or choose an operation supporting the reported target format."
                    .to_owned()
            })),
            Kind::ResourceConstraint(error) => Some(
                error
                    .recovery
                    .remediation_action()
                    .map(str::to_owned)
                    .or_else(|| error.recovery.fixed_allowance().map(|allowance| allowance.remediation()))
                    .unwrap_or_else(|| resource_remediation(error.resource).to_owned()),
            ),
            Kind::Timeout(error) => Some(
                error
                    .remediation_action
                    .clone()
                    .unwrap_or_else(|| timeout_remediation(error)),
            ),
            Kind::ArtifactOperation(error)
                if error.reason == ArtifactOperationReason::Limit
                    && error.boundary == Some(ArtifactLimitBoundary::Capacity) =>
            {
                Some("Use an artifact within the capacity reported in details.detail. Changing output detail or retrying the unchanged input does not remove this boundary.".to_owned())
            }
            Kind::AccessDenied(_) => Some(
                "Check the current process's read access to the selected path. Retry with a readable local file."
                    .to_owned(),
            ),
            Kind::ArtifactChanged(_) => Some(
                "Wait until the selected file is stable. For an active binary session, reopen the target with open_binary before retrying so REA acquires its current identity; for a CLI command or target-free tool, rerun the operation."
                    .to_owned(),
            ),
            Kind::Configuration(error) => Some(error.remediation_action.clone().unwrap_or_else(|| {
                if error.settings.is_empty() {
                    self.user_message(CallerLifetime::Continuing)
                } else {
                    let mut settings: Vec<&str> = Vec::new();
                    for issue in &error.settings {
                        if !settings.contains(&issue.setting.as_str()) {
                            settings.push(&issue.setting);
                        }
                    }
                    format!(
                        "Correct {} in the environment that starts REA (your shell or the MCP client's registration), then rerun.",
                        settings.join(", ")
                    )
                }
            })),
            Kind::Input(error) => Some(error.remediation_action.clone().unwrap_or_else(|| {
                format!(
                    "Read the declared input schema or CLI usage for {}; if using MCP and the catalog may be stale, call tools/list. Correct the listed fields, then retry. Do not repeat the unchanged call.",
                    error.operation
                )
            })),
            Kind::Output(error) => error.remediation_action.clone(),
            Kind::Protocol(_)
            | Kind::Cancelled(_)
            | Kind::ArtifactOperation(_)
            | Kind::EvidenceIntegrity(_)
            | Kind::NoBinaryOpen => None,
        }
    }
}

fn resource_remediation(resource: ResourceKind) -> &'static str {
    match resource {
        ResourceKind::Capacity => {
            "Wait for an active analysis to complete, then retry within the reported admission limits."
        }
        ResourceKind::Transport => MCP_TRANSPORT_EVIDENCE_DISCOVERY,
        ResourceKind::Cpu => {
            "Review the reported worker CPU limits and observed signal. Retry with sufficient CPU time or a smaller artifact; REA retains tighter inherited limits."
        }
        ResourceKind::FileSize => {
            "Review the reported worker file-size limits and write failure. Retry with a sufficient file-size allowance for the evidence reply; REA retains tighter inherited limits."
        }
        ResourceKind::Memory => {
            "Review the reported worker memory limits and available host memory. Retry with sufficient memory or a smaller artifact; REA retains tighter inherited limits."
        }
    }
}

fn timeout_user_message(error: &TimeoutError) -> String {
    format!(
        "REA's {} operation reached its {}ms server/provider deadline. This is not a client-side timeout; extending only the MCP client's deadline does not change this budget.",
        error.operation, error.timeout_ms
    )
}

fn timeout_remediation(error: &TimeoutError) -> String {
    format!(
        "Inspect any partial Evidence, provider diagnostics and reported session/provider cleanup state for {}. Reduce the request if supported, or resolve the reported provider condition before retrying. Do not repeat the unchanged call or retry while work or cleanup may still be active.",
        error.operation
    )
}

fn artifact_message(error: &ArtifactOperationError) -> String {
    let details = error.integrity.as_ref();
    match error.reason {
        ArtifactOperationReason::Cancelled => {
            "Artifact operation was cancelled. Start it again when ready.".to_owned()
        }
        ArtifactOperationReason::Limit => error.detail.clone().unwrap_or_else(|| {
            "Artifact processing reached a resource limit. Select an artifact within the reported limits and retry."
                .to_owned()
        }),
        ArtifactOperationReason::Path => error.detail.clone().unwrap_or_else(|| {
            "Artifact contains a conflicting internal path. Inspect the reported path before retrying."
                .to_owned()
        }),
        ArtifactOperationReason::Unavailable => match details {
            Some(details) if details.unpacked => format!(
                "ASAR unpacked companion bytes are unavailable for {}. Select the archive in place with its .unpacked directory beside it, then retry.",
                details.logical_path
            ),
            _ => "Artifact processing is unavailable. Review the reported availability reason and resolve that condition before retrying."
                .to_owned(),
        },
        ArtifactOperationReason::Integrity
            if details.is_some()
                && INTEGRITY_POLICY_OPERATIONS.contains(&error.operation.as_str()) =>
        {
            let unpacked_companion = details.is_some_and(|details| {
                details.unpacked
                    && matches!(
                        details.digest,
                        ArtifactDigestClaim::Sha256 {
                            calculated: Some(_),
                            ..
                        }
                    )
            });
            let lead = match details {
                Some(details) if unpacked_companion => format!(
                    "Declared ASAR integrity for unpacked entry {} contradicts its companion file; packaging tools commonly sign or strip unpacked native binaries after writing the archive.",
                    details.logical_path
                ),
                _ => "Artifact bytes contradict declared integrity.".to_owned(),
            };
            let rerun = if error.operation == "inventory_artifact" {
                "inspect_artifact"
            } else {
                error.operation.as_str()
            };
            format!(
                "{lead} If expected, rerun {rerun} with integrity_policy=record-and-continue (CLI: --integrity-policy record-and-continue) to retain observed bytes as untrusted; otherwise get a fresh copy."
            )
        }
        ArtifactOperationReason::Format | ArtifactOperationReason::Integrity => {
            "Artifact is invalid or has changed. Get a fresh copy and try again.".to_owned()
        }
        ArtifactOperationReason::Io => {
            "Artifact could not be read or written. Check file access and try again.".to_owned()
        }
    }
}

fn evidence_file_message(error: &EvidenceFileError) -> &'static str {
    if error.published.is_some() {
        return "The output file was published, but staging cleanup remains incomplete.";
    }
    match error.reason {
        EvidenceFileReason::PathLimit => {
            "Filesystem path-length constraints prevented reading or atomic publication at the selected path. Choose a shorter local path."
        }
        EvidenceFileReason::StorageLimit => match error.system_code {
            Some(StorageSystemCode::Efbig) => {
                "The host file-size limit prevented Evidence publication. Increase the inherited file-size allowance and retry."
            }
            None => {
                "A host filesystem resource limit prevented Evidence publication. Check the file-size allowance, filesystem space and quota before retrying."
            }
            Some(StorageSystemCode::Enospc | StorageSystemCode::Edquot) => {
                "The filesystem lacks space or quota for Evidence publication. Free space or increase quota and retry."
            }
        },
        EvidenceFileReason::SymlinkTraversal => {
            "The selected path cannot be resolved because its symbolic-link chain loops or exceeds the host traversal limit. Repair the chain or select another path."
        }
        EvidenceFileReason::Missing => match error.operation {
            EvidenceFileOperation::Read => {
                "Evidence file does not exist at the selected path. Check the path and try again."
            }
            EvidenceFileOperation::Write => {
                "Evidence output directory does not exist. Choose an existing directory and try again."
            }
        },
        EvidenceFileReason::NotFile => {
            "Evidence path does not point to a regular file. Choose a file and try again."
        }
        EvidenceFileReason::Exists => {
            "Evidence file already exists. Choose another path or allow overwrite."
        }
        EvidenceFileReason::InvalidJson => {
            "Evidence file is not valid JSON. Repair or recreate the file and try again."
        }
        EvidenceFileReason::WrongKind | EvidenceFileReason::Io => {
            "Evidence file could not be accessed. Check file permissions and try again."
        }
    }
}

fn configuration_message(error: &ConfigurationError) -> String {
    if error.settings.is_empty() {
        return "REA configuration is invalid. Run `rea doctor` and fix the reported setting."
            .to_owned();
    }
    let settings = error
        .settings
        .iter()
        .map(|issue| {
            if issue.constraint.contains(issue.setting.as_str()) {
                issue
                    .constraint
                    .strip_suffix('.')
                    .unwrap_or(&issue.constraint)
                    .to_owned()
            } else {
                format!("{}: {}", issue.setting, issue.constraint)
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!("REA configuration is invalid: {settings}.")
}
