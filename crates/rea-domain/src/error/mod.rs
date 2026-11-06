//! Provider-neutral analysis failures and their caller-visible projection.
//!
//! An [`AnalysisError`] is one expected failure: an [`AnalysisErrorKind`]
//! (the tag and the facts it owns) plus lifecycle context every failure can
//! carry: diagnostics, captured output, a partial observation, a bound
//! setting limit, continuing-caller guidance, secondary failures, and cleanup
//! state. [`AnalysisError::project`] maps it onto the caller-visible error
//! contract (`upstream:docs/error-contract.schema.json`) with upstream's
//! member order and approved copy.
//!
//! # Building failures
//!
//! - Constructors taking the operation name: [`AnalysisError::input`],
//!   [`access_denied`](AnalysisError::access_denied),
//!   [`artifact_changed`](AnalysisError::artifact_changed),
//!   [`unsupported_target`](AnalysisError::unsupported_target),
//!   [`cancelled`](AnalysisError::cancelled),
//!   [`timeout`](AnalysisError::timeout),
//!   [`resource_constraint`](AnalysisError::resource_constraint),
//!   [`artifact_operation`](AnalysisError::artifact_operation),
//!   [`output`](AnalysisError::output),
//!   [`capability_unavailable`](AnalysisError::capability_unavailable),
//!   [`provider_adapter`](AnalysisError::provider_adapter), and others.
//! - Kind-specific options live on the payload structs in [`kind`]
//!   ([`InputError`], [`ResourceConstraintError`], ...); build one and
//!   convert it with `AnalysisError::from`.
//! - Shared context uses consuming builders (`with_diagnostics`,
//!   `with_captured_output`, `with_partial_observation`, `with_limit`,
//!   `with_cleanup`, ...).
//! - Cleanup composition: [`AnalysisError::provider_cleanup`],
//!   [`AnalysisError::cleanup_failure`],
//!   [`AnalysisError::dependent_cleanup_failure`],
//!   [`AnalysisError::bind_cleanup_dependencies`],
//!   [`AnalysisError::bind_cleanup_retry`], and [`CleanupHandle::resolve`].
//!
//! ```
//! use rea_domain::error::{
//!     AnalysisError, CallerLifetime, FixedAllowance, FixedAllowanceKind, InputIssue,
//!     InputIssueReason, ResourceConstraintError, ResourceConstraintRecovery, ResourceKind,
//! };
//!
//! let input = AnalysisError::input(
//!     "inspect_elf_notes",
//!     [InputIssue::new(["path"], InputIssueReason::MissingArgument)],
//! );
//! assert_eq!(input.project(CallerLifetime::Continuing).code.as_str(), "invalid_request");
//!
//! let mut limits = serde_json::Map::new();
//! limits.insert("maximum_note_bytes".into(), 4096.into());
//! let refusal: AnalysisError = ResourceConstraintError::new(
//!     "inspect_elf_notes",
//!     ResourceKind::Memory,
//!     "The note section exceeds the parser allowance.",
//!     Some(limits),
//! )
//! .with_recovery(ResourceConstraintRecovery::fixed(FixedAllowance::new(
//!     "The ELF note parser allowance",
//!     FixedAllowanceKind::Parser,
//! )))
//! .into();
//! let projected = refusal.project(CallerLifetime::Invocation);
//! assert!(!projected.retryable);
//! ```
//!
//! # Simplifications relative to upstream
//!
//! Upstream links cleanup owners through a live `WeakRef` graph; here a
//! pending error shares a [`CleanupHandle`] with its clones, and a composition
//! owns clones of its dependencies and evaluates their state on demand (see
//! [`cleanup`]). The projected facts are the same.
//!
//! Upstream reference: `upstream:src/domain/analysisErrorBase.ts` and its
//! sibling `analysisError*.ts` modules.

pub mod allowance;
pub mod cleanup;
pub mod kind;
pub mod presentation;
pub mod projection;
pub mod settings;

use std::fmt;

use serde_json::{Map, Value};

use crate::evidence::EvidenceId;

pub use allowance::{
    FixedAllowance, FixedAllowanceKind, ResourceConstraintRecovery, fixed_allowance_remediation,
};
pub use cleanup::{CleanupHandle, CleanupObservation, CleanupRetry, DEFAULT_CLEANUP_OPERATION};
pub use kind::{
    AccessDeniedCode, AccessDeniedError, AdmissionSource, AnalysisErrorKind, AnalysisErrorTag,
    ArtifactAdmissionLimit, ArtifactChangedError, ArtifactDigestClaim, ArtifactIntegrityDetails,
    ArtifactLimitBoundary, ArtifactOperationError, ArtifactOperationReason, CancelledError,
    CapabilityUnavailableError, ConfigurationError, ConfigurationSettingIssue, EvidenceFileError,
    EvidenceFileOperation, EvidenceFileReason, EvidenceIntegrityError, InputError, InputIssue,
    InputIssueReason, IssuePathSegment, OutputError, ProtocolError, ProviderAdapterError,
    PublishedEvidenceFile, ResourceConstraintError, ResourceKind, StorageSystemCode, TimeoutError,
    UnsupportedTargetError,
};
pub use presentation::{
    MCP_TRANSPORT_EVIDENCE_DISCOVERY, MCP_TRANSPORT_EVIDENCE_EXPORT, MCP_TRANSPORT_EVIDENCE_LINKS,
    MCP_TRANSPORT_EVIDENCE_RECORDS,
};
pub use projection::{
    AnalysisErrorProjection, ChildFailure, ChildFailureDiagnostics, ErrorCategory, ErrorCode,
    ErrorRecovery, child_failure_diagnostics,
};
pub use settings::{
    AnalysisSettingId, AnalysisSettingLimit, SettingAppliesAt, SettingSource, SettingUnit,
};

/// How long the adapter delivering a failure keeps REA's runtime and
/// provider session for its caller.
///
/// An MCP connection continues: later calls reuse the session and can update
/// runtime settings. A one-shot invocation, such as a CLI command, releases
/// its provider session and exits before its caller can act; only a new
/// invocation's launch settings or arguments apply.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum CallerLifetime {
    /// `continuing`, such as an MCP connection; also the form retained in Evidence.
    #[default]
    Continuing,
    /// `invocation`, such as a one-shot CLI command.
    Invocation,
}

/// Producer guidance that holds only for a continuing caller, kept apart
/// from the outcome so the error's own message stays true after an
/// invocation releases its session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContinuingCallerGuidance {
    /// Appended to the outcome, such as that the provider session remains usable.
    pub user_message: Option<String>,
    /// Replaces the remediation, such as a same-session runtime setting update.
    pub remediation_action: Option<String>,
}

/// Retained command output; truncation stays explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedOutput {
    /// Retained standard output text.
    pub stdout: String,
    /// Retained standard error text.
    pub stderr: String,
    /// Whether retention truncated either stream.
    pub truncated: bool,
    /// Observed standard output bytes.
    pub stdout_bytes: Option<u64>,
    /// Observed standard error bytes.
    pub stderr_bytes: Option<u64>,
    /// `Some(None)` records that no exit code was observed.
    pub exit_code: Option<Option<i64>>,
    /// `Some(None)` records that no signal was observed.
    pub signal: Option<Option<String>>,
}

impl CapturedOutput {
    /// Retained streams without byte counts or exit status.
    pub fn new(stdout: impl Into<String>, stderr: impl Into<String>, truncated: bool) -> Self {
        Self {
            stdout: stdout.into(),
            stderr: stderr.into(),
            truncated,
            stdout_bytes: None,
            stderr_bytes: None,
            exit_code: None,
            signal: None,
        }
    }

    /// Contract JSON.
    pub fn to_value(&self) -> Value {
        let mut output = Map::new();
        output.insert("stdout".into(), self.stdout.clone().into());
        output.insert("stderr".into(), self.stderr.clone().into());
        output.insert("truncated".into(), self.truncated.into());
        if let Some(bytes) = self.stdout_bytes {
            output.insert("stdout_bytes".into(), bytes.into());
        }
        if let Some(bytes) = self.stderr_bytes {
            output.insert("stderr_bytes".into(), bytes.into());
        }
        if let Some(code) = self.exit_code {
            output.insert("exit_code".into(), code.map_or(Value::Null, Value::from));
        }
        if let Some(signal) = &self.signal {
            output.insert(
                "signal".into(),
                signal.clone().map_or(Value::Null, Value::String),
            );
        }
        Value::Object(output)
    }
}

/// Whether a workflow's Evidence was retained before publication stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceRetention {
    /// `retained`; an invocation caller receives `invocation-only`.
    Retained,
    /// `unverified`.
    Unverified,
}

impl EvidenceRetention {
    /// Whether the Evidence was retained.
    pub const fn is_retained(self) -> bool {
        matches!(self, Self::Retained)
    }
}

/// Automatic question publication stopped after a workflow produced its
/// Evidence. Counts describe question occurrences, not distinct Unknowns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowUnknownPublication {
    /// Evidence produced by the workflow.
    pub evidence_id: EvidenceId,
    /// Whether that Evidence was retained.
    pub evidence_retention: EvidenceRetention,
    /// Questions the workflow produced.
    pub total_questions: u64,
    /// Questions newly recorded.
    pub created_questions: u64,
    /// Questions that already existed.
    pub existing_questions: u64,
    /// Index at which publication stopped.
    pub next_question_index: u64,
}

impl WorkflowUnknownPublication {
    fn to_value(&self, lifetime: CallerLifetime) -> Value {
        let retention = match (lifetime, self.evidence_retention) {
            (CallerLifetime::Invocation, EvidenceRetention::Retained) => "invocation-only",
            (_, EvidenceRetention::Retained) => "retained",
            (_, EvidenceRetention::Unverified) => "unverified",
        };
        let mut publication = Map::new();
        publication.insert("evidence_id".into(), self.evidence_id.to_string().into());
        publication.insert("evidence_retention".into(), retention.into());
        publication.insert("total_questions".into(), self.total_questions.into());
        publication.insert("created_questions".into(), self.created_questions.into());
        publication.insert("existing_questions".into(), self.existing_questions.into());
        publication.insert(
            "next_question_index".into(),
            self.next_question_index.into(),
        );
        Value::Object(publication)
    }
}

/// One expected analysis failure with the context that must survive projection.
///
/// The state is boxed so `Result<_, AnalysisError>` stays pointer-sized on
/// the success path.
#[derive(Debug, Clone)]
pub struct AnalysisError(Box<AnalysisErrorState>);

#[derive(Debug, Clone)]
struct AnalysisErrorState {
    kind: AnalysisErrorKind,
    diagnostics: Option<Map<String, Value>>,
    invocation_diagnostics: Option<Map<String, Value>>,
    continuing_caller_guidance: Option<ContinuingCallerGuidance>,
    captured_output: Option<CapturedOutput>,
    partial_observation: Option<Value>,
    workflow_unknown_publication: Option<WorkflowUnknownPublication>,
    limit: Option<AnalysisSettingLimit>,
    cleanup_primary: Option<AnalysisError>,
    secondary_failures: Vec<AnalysisError>,
    cleanup: cleanup::CleanupState,
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.kind.fmt(f)
    }
}

impl std::error::Error for AnalysisError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0
            .cleanup_primary
            .as_ref()
            .map(|primary| primary as &(dyn std::error::Error + 'static))
    }
}

impl From<AnalysisErrorKind> for AnalysisError {
    fn from(kind: AnalysisErrorKind) -> Self {
        Self::new(kind)
    }
}

macro_rules! from_payload {
    ($($payload:ident => $variant:ident),* $(,)?) => {
        $(impl From<$payload> for AnalysisError {
            fn from(payload: $payload) -> Self {
                Self::new(AnalysisErrorKind::$variant(payload))
            }
        })*
    };
}

from_payload! {
    ProtocolError => Protocol,
    InputError => Input,
    AccessDeniedError => AccessDenied,
    ArtifactChangedError => ArtifactChanged,
    OutputError => Output,
    CapabilityUnavailableError => CapabilityUnavailable,
    UnsupportedTargetError => UnsupportedTarget,
    CancelledError => Cancelled,
    TimeoutError => Timeout,
    ResourceConstraintError => ResourceConstraint,
    ProviderAdapterError => ProviderAdapter,
    ArtifactOperationError => ArtifactOperation,
    ConfigurationError => Configuration,
    EvidenceIntegrityError => EvidenceIntegrity,
    EvidenceFileError => EvidenceFile,
}

impl AnalysisError {
    /// A failure with no lifecycle context.
    pub fn new(kind: AnalysisErrorKind) -> Self {
        Self(Box::new(AnalysisErrorState {
            kind,
            diagnostics: None,
            invocation_diagnostics: None,
            continuing_caller_guidance: None,
            captured_output: None,
            partial_observation: None,
            workflow_unknown_publication: None,
            limit: None,
            cleanup_primary: None,
            secondary_failures: Vec::new(),
            cleanup: cleanup::CleanupState::default(),
        }))
    }

    /// Caller input failed parsing; `issues` name each rejected argument.
    pub fn input(
        operation: impl Into<String>,
        issues: impl IntoIterator<Item = InputIssue>,
    ) -> Self {
        InputError::new(operation).with_issues(issues).into()
    }

    /// Host filesystem permissions denied reading `path`.
    pub fn access_denied(
        operation: impl Into<String>,
        path: impl Into<String>,
        system_code: AccessDeniedCode,
    ) -> Self {
        AccessDeniedError {
            operation: operation.into(),
            path: path.into(),
            system_code,
        }
        .into()
    }

    /// The selected artifact at `path` changed during acquisition.
    pub fn artifact_changed(
        operation: impl Into<String>,
        path: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        ArtifactChangedError {
            operation: operation.into(),
            path: path.into(),
            reason: reason.into(),
        }
        .into()
    }

    /// Output failed parsing; `reason` is caller-safe.
    pub fn output(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        OutputError::new(operation, reason).into()
    }

    /// The selected provider cannot execute `operation`.
    pub fn capability_unavailable(
        provider_id: impl Into<String>,
        operation: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        CapabilityUnavailableError::new(provider_id, operation, reason).into()
    }

    /// The readable artifact at `path` lies outside the operation's formats.
    pub fn unsupported_target(
        operation: impl Into<String>,
        path: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        UnsupportedTargetError {
            operation: operation.into(),
            path: path.into(),
            reason: reason.into(),
            remediation_action: None,
        }
        .into()
    }

    /// Caller cancellation won before the work completed.
    pub fn cancelled(operation: impl Into<String>) -> Self {
        CancelledError {
            operation: operation.into(),
        }
        .into()
    }

    /// The operation exceeded its `timeout_ms` server/provider deadline.
    pub fn timeout(operation: impl Into<String>, timeout_ms: u64) -> Self {
        TimeoutError::new(operation, timeout_ms).into()
    }

    /// A resource refusal with the resource kind's default recovery; use
    /// [`ResourceConstraintError::with_recovery`] for overrides or fixed allowances.
    /// `reason` is the caller-facing message; `reported_limits` of `None`
    /// projects as `null`.
    pub fn resource_constraint(
        operation: impl Into<String>,
        resource: ResourceKind,
        reason: impl Into<String>,
        reported_limits: Option<Map<String, Value>>,
    ) -> Self {
        ResourceConstraintError::new(operation, resource, reason, reported_limits).into()
    }

    /// A provider adapter failed outside its more precise variants.
    pub fn provider_adapter(provider_id: impl Into<String>, operation: impl Into<String>) -> Self {
        ProviderAdapterError::new(provider_id, operation).into()
    }

    /// An artifact operation failed a typed safety boundary; `detail` names
    /// the specific constraint.
    pub fn artifact_operation(
        operation: impl Into<String>,
        reason: ArtifactOperationReason,
        detail: Option<String>,
    ) -> Self {
        ArtifactOperationError::new(operation, reason, detail).into()
    }

    /// Runtime configuration could not be parsed safely.
    pub fn configuration(
        message: impl Into<String>,
        settings: impl IntoIterator<Item = ConfigurationSettingIssue>,
    ) -> Self {
        ConfigurationError {
            message: message.into(),
            settings: settings.into_iter().collect(),
            remediation_action: None,
        }
        .into()
    }

    /// Evidence identity, schema, or manifests failed integrity checks.
    pub fn evidence_integrity(message: impl Into<String>) -> Self {
        EvidenceIntegrityError {
            message: message.into(),
            user_message: None,
        }
        .into()
    }

    /// Evidence bundle filesystem access failed.
    pub fn evidence_file(operation: EvidenceFileOperation, reason: EvidenceFileReason) -> Self {
        EvidenceFileError::new(operation, reason).into()
    }

    /// Provider-neutral invalid input or output at an application boundary.
    pub fn protocol(message: impl Into<String>) -> Self {
        ProtocolError {
            message: message.into(),
        }
        .into()
    }

    /// No app or binary session exists.
    pub fn no_binary_open() -> Self {
        Self::new(AnalysisErrorKind::NoBinaryOpen)
    }

    /// Producer-owned, caller-safe diagnostics retained through projection.
    #[must_use]
    pub fn with_diagnostics(mut self, diagnostics: Map<String, Value>) -> Self {
        self.0.diagnostics = Some(diagnostics);
        self
    }

    /// The same diagnostics recorded for an invocation caller, when an
    /// embedded child projects differently for that lifetime.
    #[must_use]
    pub fn with_invocation_diagnostics(mut self, diagnostics: Map<String, Value>) -> Self {
        self.0.invocation_diagnostics = Some(diagnostics);
        self
    }

    /// Diagnostics embedding child failures, from [`child_failure_diagnostics`].
    #[must_use]
    pub fn with_child_failure_diagnostics(mut self, children: ChildFailureDiagnostics) -> Self {
        self.0.diagnostics = Some(children.diagnostics);
        self.0.invocation_diagnostics = children.invocation_diagnostics;
        self
    }

    /// Guidance that holds only for a continuing caller.
    #[must_use]
    pub fn with_continuing_caller_guidance(mut self, guidance: ContinuingCallerGuidance) -> Self {
        self.0.continuing_caller_guidance = Some(guidance);
        self
    }

    /// Command output retained with the failure.
    #[must_use]
    pub fn with_captured_output(mut self, output: CapturedOutput) -> Self {
        self.0.captured_output = Some(output);
        self
    }

    /// Evidence collected before the failure, as JSON.
    #[must_use]
    pub fn with_partial_observation(mut self, observation: Value) -> Self {
        self.0.partial_observation = Some(observation);
        self
    }

    /// Bind the accepted setting at its producing boundary.
    #[must_use]
    pub fn with_limit(mut self, limit: AnalysisSettingLimit) -> Self {
        self.0.limit = Some(limit);
        self
    }

    /// Typed primary retained when a later lifecycle failure composes this error.
    #[must_use]
    pub fn with_cleanup_primary(mut self, primary: AnalysisError) -> Self {
        self.0.cleanup_primary = Some(primary);
        self
    }

    /// Merge diagnostic facts without replacing the typed error; invocation
    /// diagnostics receive them only when already present.
    pub fn retain_diagnostics(&mut self, diagnostics: Map<String, Value>) {
        if let Some(invocation) = &mut self.0.invocation_diagnostics {
            invocation.extend(diagnostics.clone());
        }
        self.0
            .diagnostics
            .get_or_insert_with(Map::new)
            .extend(diagnostics);
    }

    /// Retain a later typed failure without changing the primary semantics
    /// or cleanup status.
    pub fn retain_secondary_failure(
        &mut self,
        failure: AnalysisError,
        diagnostics: Option<Map<String, Value>>,
    ) {
        if let Some(diagnostics) = diagnostics {
            self.retain_diagnostics(diagnostics);
        }
        self.0.secondary_failures.push(failure);
    }

    /// Retain a completed observation when a later step fails; the first wins.
    pub fn retain_partial_observation(&mut self, observation: Value) {
        self.0.partial_observation.get_or_insert(observation);
    }

    /// Preserve the committed prefix when automatic question publication
    /// stops; the first wins.
    pub fn retain_workflow_unknown_publication(&mut self, publication: WorkflowUnknownPublication) {
        self.0
            .workflow_unknown_publication
            .get_or_insert(publication);
    }

    /// The typed failure.
    pub fn kind(&self) -> &AnalysisErrorKind {
        &self.0.kind
    }

    /// Stable tag.
    pub fn tag(&self) -> AnalysisErrorTag {
        self.0.kind.tag()
    }

    /// Producer diagnostics.
    pub fn diagnostics(&self) -> Option<&Map<String, Value>> {
        self.0.diagnostics.as_ref()
    }

    /// Diagnostics recorded for a caller with `lifetime`.
    pub fn diagnostics_for(&self, lifetime: CallerLifetime) -> Option<&Map<String, Value>> {
        match lifetime {
            CallerLifetime::Invocation => self
                .0
                .invocation_diagnostics
                .as_ref()
                .or(self.0.diagnostics.as_ref()),
            CallerLifetime::Continuing => self.0.diagnostics.as_ref(),
        }
    }

    /// Retained command output.
    pub fn captured_output(&self) -> Option<&CapturedOutput> {
        self.0.captured_output.as_ref()
    }

    /// Retained partial observation.
    pub fn partial_observation(&self) -> Option<&Value> {
        self.0.partial_observation.as_ref()
    }

    /// Bound setting limit.
    pub fn limit(&self) -> Option<&AnalysisSettingLimit> {
        self.0.limit.as_ref()
    }

    /// Continuing-caller guidance.
    pub fn continuing_caller_guidance(&self) -> Option<&ContinuingCallerGuidance> {
        self.0.continuing_caller_guidance.as_ref()
    }

    /// Retained workflow publication prefix.
    pub fn workflow_unknown_publication(&self) -> Option<&WorkflowUnknownPublication> {
        self.0.workflow_unknown_publication.as_ref()
    }

    /// Typed primary of a cleanup composition.
    pub fn cleanup_primary(&self) -> Option<&AnalysisError> {
        self.0.cleanup_primary.as_ref()
    }

    /// Later typed failures retained beside the primary.
    pub fn secondary_failures(&self) -> &[AnalysisError] {
        &self.0.secondary_failures
    }

    /// Confirmed cleanup reveals the typed primary; unresolved ownership stays visible.
    pub fn resolved(&self) -> &AnalysisError {
        let mut error = self;
        while !error.cleanup_incomplete()
            && let Some(primary) = error.0.cleanup_primary.as_ref()
        {
            error = primary;
        }
        error
    }

    /// Original operation semantics, distinct from any cleanup envelope.
    pub fn primary(&self) -> &AnalysisError {
        let mut error = self;
        while let Some(primary) = error.0.cleanup_primary.as_ref() {
            error = primary;
        }
        error
    }

    /// Upstream computes capability retryability at construction: a refusal
    /// raised with incomplete cleanup is never retryable.
    pub(crate) fn capability_retryable(&self) -> bool {
        matches!(&self.0.kind, AnalysisErrorKind::CapabilityUnavailable(error) if error.retryable)
            && self.0.cleanup.observation.is_none()
    }
}
