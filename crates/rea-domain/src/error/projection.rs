//! Projection of typed failures onto the caller-visible error contract.
//!
//! The contract is `upstream:docs/error-contract.schema.json`. The continuing
//! form describes a caller such as an MCP connection and is also the
//! adapter-independent form retained inside Evidence; an adapter that releases
//! its provider session after the request, such as a one-shot CLI command,
//! projects for [`CallerLifetime::Invocation`].
//!
//! Upstream reference: `upstream:src/domain/analysisErrorProjection.ts` and
//! `upstream:src/contracts/errorSchemas.ts`.

use std::ptr;

use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use super::kind::{
    AnalysisErrorKind as Kind, ArtifactOperationReason, EvidenceFileReason, ResourceKind,
};
use super::{AnalysisError, CallerLifetime};

/// Stable machine-readable failure code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// `invalid_request`.
    InvalidRequest,
    /// `access_denied`.
    AccessDenied,
    /// `artifact_changed`.
    ArtifactChanged,
    /// `unreadable_output`.
    UnreadableOutput,
    /// `capability_unavailable`.
    CapabilityUnavailable,
    /// `unsupported_target`.
    UnsupportedTarget,
    /// `provider_unavailable`.
    ProviderUnavailable,
    /// `provider_timeout`.
    ProviderTimeout,
    /// `resource_constraint`.
    ResourceConstraint,
    /// `cancelled`.
    Cancelled,
    /// `artifact_integrity_mismatch`.
    ArtifactIntegrityMismatch,
    /// `artifact_operation_failed`.
    ArtifactOperationFailed,
    /// `evidence_integrity_mismatch`.
    EvidenceIntegrityMismatch,
    /// `truncated`.
    Truncated,
    /// `process_capture_failed`.
    ProcessCaptureFailed,
    /// `cleanup_incomplete`.
    CleanupIncomplete,
    /// `revision_conflict`.
    RevisionConflict,
    /// `configuration_invalid`.
    ConfigurationInvalid,
    /// `target_unavailable`.
    TargetUnavailable,
    /// `execution_failure`.
    ExecutionFailure,
}

impl ErrorCode {
    /// Contract text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::AccessDenied => "access_denied",
            Self::ArtifactChanged => "artifact_changed",
            Self::UnreadableOutput => "unreadable_output",
            Self::CapabilityUnavailable => "capability_unavailable",
            Self::UnsupportedTarget => "unsupported_target",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::ProviderTimeout => "provider_timeout",
            Self::ResourceConstraint => "resource_constraint",
            Self::Cancelled => "cancelled",
            Self::ArtifactIntegrityMismatch => "artifact_integrity_mismatch",
            Self::ArtifactOperationFailed => "artifact_operation_failed",
            Self::EvidenceIntegrityMismatch => "evidence_integrity_mismatch",
            Self::Truncated => "truncated",
            Self::ProcessCaptureFailed => "process_capture_failed",
            Self::CleanupIncomplete => "cleanup_incomplete",
            Self::RevisionConflict => "revision_conflict",
            Self::ConfigurationInvalid => "configuration_invalid",
            Self::TargetUnavailable => "target_unavailable",
            Self::ExecutionFailure => "execution_failure",
        }
    }

    /// Codes whose unchanged request may succeed later.
    const fn retryable(self) -> bool {
        matches!(
            self,
            Self::ArtifactChanged
                | Self::ProviderTimeout
                | Self::Cancelled
                | Self::RevisionConflict
                | Self::ProviderUnavailable
        )
    }
}

/// Broad failure category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    /// `invalid_input`.
    InvalidInput,
    /// `unsupported_provider`.
    UnsupportedProvider,
    /// `unsupported_target`.
    UnsupportedTarget,
    /// `integrity_mismatch`.
    IntegrityMismatch,
    /// `truncated`.
    Truncated,
    /// `cancelled`.
    Cancelled,
    /// `timeout`.
    Timeout,
    /// `resource_constraint`.
    ResourceConstraint,
    /// `unavailable`.
    Unavailable,
    /// `execution_failure`.
    ExecutionFailure,
}

impl ErrorCategory {
    /// Contract text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::UnsupportedProvider => "unsupported_provider",
            Self::UnsupportedTarget => "unsupported_target",
            Self::IntegrityMismatch => "integrity_mismatch",
            Self::Truncated => "truncated",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
            Self::ResourceConstraint => "resource_constraint",
            Self::Unavailable => "unavailable",
            Self::ExecutionFailure => "execution_failure",
        }
    }
}

/// Small, bounded next-step metadata; prose stays in `remediation.action`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorRecovery {
    /// Read the operation's declared input contract.
    InspectInputContract {
        /// Refused operation.
        operation: String,
    },
    /// Inspect partial and cleanup state left by a deadline.
    InspectTimeoutState {
        /// Timed-out operation.
        operation: String,
        /// Elapsed deadline.
        timeout_ms: u64,
    },
    /// Retry only retained cleanup on the same connection.
    RetryCleanup {
        /// Retry operation.
        operation: String,
    },
}

impl ErrorRecovery {
    /// Contract JSON.
    pub fn to_value(&self) -> Value {
        let mut recovery = Map::new();
        let (kind, operation) = match self {
            Self::InspectInputContract { operation } => ("inspect_input_contract", operation),
            Self::InspectTimeoutState { operation, .. } => ("inspect_timeout_state", operation),
            Self::RetryCleanup { operation } => ("retry_cleanup", operation),
        };
        recovery.insert("kind".into(), kind.into());
        recovery.insert("operation".into(), operation.clone().into());
        if let Self::InspectTimeoutState { timeout_ms, .. } = self {
            recovery.insert("timeout_ms".into(), (*timeout_ms).into());
        }
        Value::Object(recovery)
    }
}

/// Exhaustive, secret-safe caller fields of one failure.
#[derive(Debug, Clone, PartialEq)]
pub struct AnalysisErrorProjection {
    /// Machine-readable code.
    pub code: ErrorCode,
    /// Broad category of the original operation's failure.
    pub category: ErrorCategory,
    /// Caller-facing message.
    pub message: String,
    /// Whether the unchanged request may succeed later.
    pub retryable: bool,
    /// Next step (`remediation.action`).
    pub remediation_action: String,
    /// Structured next step.
    pub recovery: Option<ErrorRecovery>,
    /// Facts; `None` when empty.
    pub details: Option<Map<String, Value>>,
}

impl AnalysisErrorProjection {
    /// Contract JSON in upstream member order.
    pub fn to_value(&self) -> Value {
        let mut projection = Map::new();
        projection.insert("code".into(), self.code.as_str().into());
        projection.insert("category".into(), self.category.as_str().into());
        projection.insert("message".into(), self.message.clone().into());
        projection.insert("retryable".into(), self.retryable.into());
        let mut remediation = Map::new();
        remediation.insert("action".into(), self.remediation_action.clone().into());
        projection.insert("remediation".into(), Value::Object(remediation));
        if let Some(recovery) = &self.recovery {
            projection.insert("recovery".into(), recovery.to_value());
        }
        if let Some(details) = &self.details {
            projection.insert("details".into(), Value::Object(details.clone()));
        }
        Value::Object(projection)
    }
}

impl Serialize for AnalysisErrorProjection {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_value().serialize(serializer)
    }
}

impl From<&AnalysisErrorProjection> for Value {
    fn from(projection: &AnalysisErrorProjection) -> Self {
        projection.to_value()
    }
}

/// A child failure embedded in a composed error's diagnostics.
#[derive(Debug, Clone, Copy)]
pub struct ChildFailure<'a> {
    /// The child.
    pub error: &'a AnalysisError,
    /// `false` omits output that the composing error already retains.
    pub include_captured_output: bool,
}

/// Diagnostics for each caller lifetime, from [`child_failure_diagnostics`].
#[derive(Debug, Clone, PartialEq)]
pub struct ChildFailureDiagnostics {
    /// Continuing-caller diagnostics.
    pub diagnostics: Map<String, Value>,
    /// Present only when some child projects differently for an invocation caller.
    pub invocation_diagnostics: Option<Map<String, Value>>,
}

/// Record child failures as composition-time snapshots, so cleanup history
/// keeps the state it had. Children follow `base` in key order.
pub fn child_failure_diagnostics(
    children: &[(&str, ChildFailure<'_>)],
    base: Map<String, Value>,
) -> ChildFailureDiagnostics {
    let project = |child: &ChildFailure<'_>, lifetime| {
        child
            .error
            .project_with(child.include_captured_output, lifetime)
            .to_value()
    };
    let mut continuing = base;
    for (key, child) in children {
        continuing.insert(
            (*key).to_owned(),
            project(child, CallerLifetime::Continuing),
        );
    }
    let mut varying = children
        .iter()
        .filter(|(_, child)| child.error.projection_depends_on_lifetime())
        .peekable();
    let invocation_diagnostics = varying.peek().is_some().then(|| {
        let mut invocation = continuing.clone();
        for (key, child) in varying {
            invocation.insert(
                (*key).to_owned(),
                project(child, CallerLifetime::Invocation),
            );
        }
        invocation
    });
    ChildFailureDiagnostics {
        diagnostics: continuing,
        invocation_diagnostics,
    }
}

impl AnalysisError {
    /// Project onto the caller-visible error contract for a caller with `lifetime`.
    pub fn project(&self, lifetime: CallerLifetime) -> AnalysisErrorProjection {
        self.project_with(true, lifetime)
    }

    /// [`AnalysisError::project`] without captured output, for cleanup history
    /// whose enclosing owner already retains that output.
    pub fn project_without_captured_output(
        &self,
        lifetime: CallerLifetime,
    ) -> AnalysisErrorProjection {
        self.project_with(false, lifetime)
    }

    /// Every lifetime-dependent input the projection reads lies on this chain.
    fn projection_depends_on_lifetime(&self) -> bool {
        self.cleanup_chain().any(|node| {
            node.limit.is_some()
                || node.continuing_caller_guidance.is_some()
                || node.invocation_diagnostics.is_some()
                || node.workflow_unknown_publication.is_some()
        })
    }

    fn cleanup_chain(&self) -> impl Iterator<Item = &AnalysisError> {
        std::iter::successors(Some(self), |node| node.cleanup_primary.as_deref())
    }

    fn project_with(
        &self,
        include_captured_output: bool,
        lifetime: CallerLifetime,
    ) -> AnalysisErrorProjection {
        let composed = self;
        let error = composed.resolved();
        let diagnostics = error
            .cleanup_chain()
            .find(|node| node.diagnostics.is_some() || node.cleanup_primary.is_none())
            .and_then(|source| source.diagnostics_for(lifetime));
        let cleanup_history = if ptr::eq(composed, error) {
            None
        } else {
            composed.diagnostics_for(lifetime)
        };
        let captured_output = composed
            .captured_output
            .as_ref()
            .or(error.captured_output.as_ref());
        let partial_observation = composed
            .partial_observation
            .as_ref()
            .or(error.partial_observation.as_ref());
        let primary = error.primary();
        let underlying = primary.underlying_code();
        let incomplete = error.cleanup_incomplete();
        let code = if incomplete {
            ErrorCode::CleanupIncomplete
        } else {
            underlying
        };
        let primary_details = primary.primary_details();
        let publication = composed
            .workflow_unknown_publication
            .as_ref()
            .or(primary.workflow_unknown_publication.as_ref());

        let mut details = primary_details.clone().unwrap_or_default();
        if let Some(publication) = publication {
            details.insert(
                "workflow_unknown_publication".into(),
                publication.to_value(lifetime),
            );
        }
        if let Some(limit) = &primary.limit {
            details.insert("limit".into(), limit.to_value(lifetime));
        }
        if let Some(diagnostics) = diagnostics {
            details.insert("diagnostics".into(), Value::Object(diagnostics.clone()));
            if let Some(provider) = primary_details.as_ref().and_then(|d| d.get("diagnostics")) {
                details.insert("provider_diagnostics".into(), provider.clone());
            }
        }
        if let Some(history) = cleanup_history {
            details.insert("cleanup_history".into(), Value::Object(history.clone()));
        }
        if incomplete {
            details.insert("cleanup".into(), "incomplete".into());
            details.insert("resources".into(), error.cleanup_resources().into());
            if let Some(observation) = &error.cleanup.observation {
                details.insert("cleanup_reason".into(), observation.reason.clone().into());
            }
            let execution_failure = primary_details
                .as_ref()
                .and_then(|d| d.get("execution_failure"))
                .cloned()
                .unwrap_or_else(|| underlying.as_str().into());
            details.insert("execution_failure".into(), execution_failure);
        }
        if include_captured_output && let Some(output) = captured_output {
            details.insert("captured_output".into(), output.to_value());
        }
        if let Some(observation) = partial_observation {
            details.insert("partial_observation".into(), observation.clone());
        }

        let cleanup_retry = error.cleanup_retry();
        let recovery = match cleanup_retry {
            Some(retry) => Some(ErrorRecovery::RetryCleanup {
                operation: retry.operation().to_owned(),
            }),
            None => error.error_recovery(),
        };
        let mut remediation_action = error.remediation_action(lifetime);
        if let Some(retry) = cleanup_retry {
            remediation_action.push(' ');
            remediation_action.push_str(&retry.remediation());
        }
        if lifetime == CallerLifetime::Continuing
            && publication.is_some_and(|publication| publication.evidence_retention.is_retained())
        {
            remediation_action.push_str(" Use get_evidence_bundle with the Evidence ID in details.workflow_unknown_publication to retrieve the completed result; use list_unknowns to inspect recorded questions. Publication stopped at the reported index; later questions were not checked in this attempt.");
        }
        let retryable = code.retryable()
            || error.capability_retryable()
            || (code == ErrorCode::ResourceConstraint
                && matches!(&error.kind, Kind::ResourceConstraint(resource)
                    if resource.recovery.retryable().unwrap_or(resource.resource == ResourceKind::Capacity)));

        AnalysisErrorProjection {
            code,
            category: error.category(),
            message: error.user_message(lifetime),
            retryable,
            remediation_action,
            recovery,
            details: (!details.is_empty()).then_some(details),
        }
    }

    fn error_recovery(&self) -> Option<ErrorRecovery> {
        match &self.kind {
            Kind::Input(error) if !error.conforms_to_input_contract => {
                Some(ErrorRecovery::InspectInputContract {
                    operation: error.operation.clone(),
                })
            }
            Kind::Timeout(error) => Some(ErrorRecovery::InspectTimeoutState {
                operation: error.operation.clone(),
                timeout_ms: error.timeout_ms,
            }),
            _ => None,
        }
    }

    fn underlying_code(&self) -> ErrorCode {
        match &self.kind {
            Kind::ArtifactOperation(error) => match error.reason {
                ArtifactOperationReason::Integrity if error.integrity.is_some() => {
                    ErrorCode::ArtifactIntegrityMismatch
                }
                ArtifactOperationReason::Limit => ErrorCode::Truncated,
                ArtifactOperationReason::Cancelled => ErrorCode::Cancelled,
                _ => ErrorCode::ArtifactOperationFailed,
            },
            Kind::EvidenceFile(error) => match error.reason {
                EvidenceFileReason::InvalidJson => ErrorCode::EvidenceIntegrityMismatch,
                EvidenceFileReason::PathLimit | EvidenceFileReason::StorageLimit => {
                    ErrorCode::ResourceConstraint
                }
                EvidenceFileReason::Io => ErrorCode::ExecutionFailure,
                EvidenceFileReason::NotFile
                | EvidenceFileReason::Exists
                | EvidenceFileReason::WrongKind
                | EvidenceFileReason::Missing
                | EvidenceFileReason::SymlinkTraversal => ErrorCode::InvalidRequest,
            },
            Kind::Protocol(_) | Kind::Output(_) => ErrorCode::UnreadableOutput,
            Kind::Input(_) => ErrorCode::InvalidRequest,
            Kind::AccessDenied(_) => ErrorCode::AccessDenied,
            Kind::ArtifactChanged(_) => ErrorCode::ArtifactChanged,
            Kind::CapabilityUnavailable(_) => ErrorCode::CapabilityUnavailable,
            Kind::UnsupportedTarget(_) => ErrorCode::UnsupportedTarget,
            Kind::Cancelled(_) => ErrorCode::Cancelled,
            Kind::Timeout(_) => ErrorCode::ProviderTimeout,
            Kind::ResourceConstraint(_) => ErrorCode::ResourceConstraint,
            Kind::Configuration(_) => ErrorCode::ConfigurationInvalid,
            Kind::NoBinaryOpen => ErrorCode::TargetUnavailable,
            Kind::EvidenceIntegrity(_) => ErrorCode::EvidenceIntegrityMismatch,
            Kind::ProviderAdapter(_) => ErrorCode::ExecutionFailure,
        }
    }

    /// Facts owned by the primary failure's tag.
    fn primary_details(&self) -> Option<Map<String, Value>> {
        let mut details = Map::new();
        let mut put = |key: &str, value: Value| {
            details.insert(key.to_owned(), value);
        };
        match &self.kind {
            Kind::UnsupportedTarget(error) => {
                put("operation", error.operation.clone().into());
                put("path", error.path.clone().into());
                put("reason", error.reason.clone().into());
            }
            Kind::ResourceConstraint(error) => {
                put("operation", error.operation.clone().into());
                put("resource", error.resource.as_str().into());
                put("reason", error.reason.clone().into());
                put(
                    "reported_limits",
                    error
                        .reported_limits
                        .clone()
                        .map_or(Value::Null, Value::Object),
                );
            }
            Kind::ArtifactChanged(error) => {
                put("operation", error.operation.clone().into());
                put("path", error.path.clone().into());
                put("reason", error.reason.clone().into());
                put("boundary", "stable-artifact-read".into());
            }
            Kind::AccessDenied(error) => {
                put("operation", error.operation.clone().into());
                put("path", error.path.clone().into());
                put("system_code", error.system_code.as_str().into());
                put("boundary", "filesystem-read".into());
            }
            Kind::Output(error) => {
                put("operation", error.operation.clone().into());
                put("reason", error.reason.clone().into());
                if let Some(diagnostics) = &self.diagnostics {
                    put("diagnostics", Value::Object(diagnostics.clone()));
                }
            }
            Kind::Input(error) => {
                if error.issues.is_empty() {
                    return None;
                }
                put("operation", error.operation.clone().into());
                put(
                    "issues",
                    error.issues.iter().map(|issue| issue.to_value()).collect(),
                );
            }
            Kind::EvidenceIntegrity(error) => put("reason", error.message.clone().into()),
            Kind::ArtifactOperation(error) => {
                if let Some(integrity) = &error.integrity {
                    return Some(integrity.to_map());
                }
                put("operation", error.operation.clone().into());
                put("reason", error.reason.as_str().into());
                if error.reason == ArtifactOperationReason::Limit {
                    put("truncated", true.into());
                }
                if let Some(detail) = &error.detail {
                    put("detail", detail.clone().into());
                }
                if let Some(boundary) = error.boundary {
                    put("boundary", boundary.as_str().into());
                }
                if let Some(admission) = &error.admission {
                    put("admission", "asar-header".into());
                    put("maximum_header_bytes", admission.maximum_bytes.into());
                    put(
                        "maximum_header_bytes_source",
                        admission.source.as_str().into(),
                    );
                    put("setting", "REA_ASAR_MAX_HEADER_BYTES".into());
                }
            }
            Kind::EvidenceFile(error) => {
                put("operation", error.operation.as_str().into());
                put("reason", error.reason.as_str().into());
                if error.reason == EvidenceFileReason::PathLimit {
                    put("boundary", "filesystem-path".into());
                }
                if let Some(code) = error.system_code {
                    put("system_code", code.as_str().into());
                }
                if let Some(path) = &error.path {
                    put("path", path.clone().into());
                }
                if let Some(issues) = &error.content_issues {
                    put(
                        "content_issues",
                        issues.iter().map(|issue| issue.to_value()).collect(),
                    );
                }
                if let Some(published) = &error.published {
                    put("published", true.into());
                    put("bytes", published.bytes.into());
                    if let Some(path) = &published.path {
                        put("published_path", path.clone().into());
                    }
                }
            }
            Kind::CapabilityUnavailable(error) => {
                put("provider_id", error.provider_id.clone().into());
                put("operation", error.operation.clone().into());
                put("reason", error.reason.clone().into());
            }
            Kind::ProviderAdapter(error) => {
                put("provider_id", error.provider_id.clone().into());
                put("operation", error.operation.clone().into());
                if self.cleanup_incomplete() {
                    put("cleanup", "incomplete".into());
                    put("resources", self.cleanup_resources().into());
                }
            }
            Kind::Cancelled(error) => {
                let incomplete = self.cleanup_incomplete();
                put("operation", error.operation.clone().into());
                put(
                    "cleanup",
                    if incomplete { "incomplete" } else { "complete" }.into(),
                );
                if let Some(observation) = self.cleanup.observation.as_ref().filter(|_| incomplete)
                {
                    put("cleanup_reason", observation.reason.clone().into());
                    put("resources", observation.resources.clone().into());
                    put("execution_failure", "cancelled".into());
                }
            }
            Kind::Timeout(error) => {
                put("operation", error.operation.clone().into());
                put("timeout_ms", error.timeout_ms.into());
                if let Some(observation) = self
                    .cleanup
                    .observation
                    .as_ref()
                    .filter(|_| self.cleanup_incomplete())
                {
                    put("cleanup", "incomplete".into());
                    put("cleanup_reason", observation.reason.clone().into());
                    put("resources", observation.resources.clone().into());
                }
            }
            Kind::Configuration(error) => {
                if error.settings.is_empty() {
                    return None;
                }
                put(
                    "settings",
                    error
                        .settings
                        .iter()
                        .map(|issue| {
                            let mut setting = Map::new();
                            setting.insert("setting".into(), issue.setting.clone().into());
                            setting.insert("constraint".into(), issue.constraint.clone().into());
                            Value::Object(setting)
                        })
                        .collect(),
                );
            }
            Kind::Protocol(_) | Kind::NoBinaryOpen => return None,
        }
        Some(details)
    }
}
