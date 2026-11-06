//! Typed payloads of expected analysis failures.
//!
//! Each payload holds only the facts its tag owns. Lifecycle context shared by
//! every failure (diagnostics, captured output, cleanup, partial observations)
//! lives on [`AnalysisError`](super::AnalysisError).
//!
//! Upstream reference: `upstream:src/domain/analysisErrorCore.ts`,
//! `artifactOperationError.ts`, `providerAdapterError.ts`,
//! `configurationErrors.ts`, and `evidenceErrors.ts`.

use std::fmt;

use serde_json::{Map, Number, Value};

use super::allowance::ResourceConstraintRecovery;

/// Stable tag of an expected analysis failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnalysisErrorTag {
    /// `AnalysisProtocolError`.
    AnalysisProtocolError,
    /// `AnalysisInputError`.
    AnalysisInputError,
    /// `AnalysisAccessDeniedError`.
    AnalysisAccessDeniedError,
    /// `AnalysisArtifactChangedError`.
    AnalysisArtifactChangedError,
    /// `AnalysisOutputError`.
    AnalysisOutputError,
    /// `AnalysisCapabilityUnavailableError`.
    AnalysisCapabilityUnavailableError,
    /// `AnalysisUnsupportedTargetError`.
    AnalysisUnsupportedTargetError,
    /// `AnalysisCancelledError`.
    AnalysisCancelledError,
    /// `AnalysisTimeoutError`.
    AnalysisTimeoutError,
    /// `AnalysisResourceConstraintError`.
    AnalysisResourceConstraintError,
    /// `ProviderAdapterError`.
    ProviderAdapterError,
    /// `ArtifactOperationError`.
    ArtifactOperationError,
    /// `EvidenceIntegrityError`.
    EvidenceIntegrityError,
    /// `EvidenceFileError`.
    EvidenceFileError,
    /// `ConfigurationError`.
    ConfigurationError,
    /// `NoBinaryOpenError`.
    NoBinaryOpenError,
}

impl AnalysisErrorTag {
    /// Upstream tag text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnalysisProtocolError => "AnalysisProtocolError",
            Self::AnalysisInputError => "AnalysisInputError",
            Self::AnalysisAccessDeniedError => "AnalysisAccessDeniedError",
            Self::AnalysisArtifactChangedError => "AnalysisArtifactChangedError",
            Self::AnalysisOutputError => "AnalysisOutputError",
            Self::AnalysisCapabilityUnavailableError => "AnalysisCapabilityUnavailableError",
            Self::AnalysisUnsupportedTargetError => "AnalysisUnsupportedTargetError",
            Self::AnalysisCancelledError => "AnalysisCancelledError",
            Self::AnalysisTimeoutError => "AnalysisTimeoutError",
            Self::AnalysisResourceConstraintError => "AnalysisResourceConstraintError",
            Self::ProviderAdapterError => "ProviderAdapterError",
            Self::ArtifactOperationError => "ArtifactOperationError",
            Self::EvidenceIntegrityError => "EvidenceIntegrityError",
            Self::EvidenceFileError => "EvidenceFileError",
            Self::ConfigurationError => "ConfigurationError",
            Self::NoBinaryOpenError => "NoBinaryOpenError",
        }
    }
}

impl fmt::Display for AnalysisErrorTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The typed failure and the facts its tag owns.
#[derive(Debug, Clone, PartialEq)]
pub enum AnalysisErrorKind {
    /// Provider-neutral invalid analysis input or output at an application boundary.
    Protocol(ProtocolError),
    /// Caller input failed provider-neutral parsing.
    Input(InputError),
    /// Host filesystem permissions denied the selected read.
    AccessDenied(AccessDeniedError),
    /// The selected artifact changed during acquisition.
    ArtifactChanged(ArtifactChangedError),
    /// Provider output failed provider-neutral parsing.
    Output(OutputError),
    /// The selected provider cannot execute a declared operation.
    CapabilityUnavailable(CapabilityUnavailableError),
    /// A readable artifact lies outside the operation's supported formats.
    UnsupportedTarget(UnsupportedTargetError),
    /// Caller cancellation won before the work completed.
    Cancelled(CancelledError),
    /// The operation exceeded its declared execution deadline.
    Timeout(TimeoutError),
    /// A measured resource constraint or bounded admission refusal.
    ResourceConstraint(ResourceConstraintError),
    /// A provider adapter failed outside its more precise typed variants.
    ProviderAdapter(ProviderAdapterError),
    /// Artifact inventory, inspection, or extraction failed a typed safety boundary.
    ArtifactOperation(ArtifactOperationError),
    /// Runtime configuration could not be parsed safely.
    Configuration(ConfigurationError),
    /// Evidence identity, schema, or bundle manifests failed integrity checks.
    EvidenceIntegrity(EvidenceIntegrityError),
    /// Evidence bundle filesystem access failed.
    EvidenceFile(EvidenceFileError),
    /// No app or binary session exists for an analysis request.
    NoBinaryOpen,
}

impl AnalysisErrorKind {
    /// Stable tag.
    pub const fn tag(&self) -> AnalysisErrorTag {
        match self {
            Self::Protocol(_) => AnalysisErrorTag::AnalysisProtocolError,
            Self::Input(_) => AnalysisErrorTag::AnalysisInputError,
            Self::AccessDenied(_) => AnalysisErrorTag::AnalysisAccessDeniedError,
            Self::ArtifactChanged(_) => AnalysisErrorTag::AnalysisArtifactChangedError,
            Self::Output(_) => AnalysisErrorTag::AnalysisOutputError,
            Self::CapabilityUnavailable(_) => AnalysisErrorTag::AnalysisCapabilityUnavailableError,
            Self::UnsupportedTarget(_) => AnalysisErrorTag::AnalysisUnsupportedTargetError,
            Self::Cancelled(_) => AnalysisErrorTag::AnalysisCancelledError,
            Self::Timeout(_) => AnalysisErrorTag::AnalysisTimeoutError,
            Self::ResourceConstraint(_) => AnalysisErrorTag::AnalysisResourceConstraintError,
            Self::ProviderAdapter(_) => AnalysisErrorTag::ProviderAdapterError,
            Self::ArtifactOperation(_) => AnalysisErrorTag::ArtifactOperationError,
            Self::Configuration(_) => AnalysisErrorTag::ConfigurationError,
            Self::EvidenceIntegrity(_) => AnalysisErrorTag::EvidenceIntegrityError,
            Self::EvidenceFile(_) => AnalysisErrorTag::EvidenceFileError,
            Self::NoBinaryOpen => AnalysisErrorTag::NoBinaryOpenError,
        }
    }
}

/// Internal (log) message, matching upstream's `Error.message`. Callers
/// receive the projection's `message` instead.
impl fmt::Display for AnalysisErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => f.write_str(&error.message),
            Self::Input(error) => write!(f, "Invalid analysis input for {}", error.operation),
            Self::AccessDenied(error) => write!(
                f,
                "Host filesystem read access denied ({}) for {} during {}",
                error.system_code.as_str(),
                error.path,
                error.operation
            ),
            Self::ArtifactChanged(error) => write!(
                f,
                "Selected artifact changed during acquisition: {}",
                error.reason
            ),
            Self::Output(error) => write!(
                f,
                "Invalid analysis output for {}: {}",
                error.operation, error.reason
            ),
            Self::CapabilityUnavailable(error) => write!(
                f,
                "Provider {} cannot execute {}: {}",
                error.provider_id, error.operation, error.reason
            ),
            Self::UnsupportedTarget(error) => f.write_str(&error.message()),
            Self::Cancelled(error) => {
                write!(f, "Analysis operation was cancelled: {}", error.operation)
            }
            Self::Timeout(error) => write!(
                f,
                "Analysis operation timed out after {}ms: {}",
                error.timeout_ms, error.operation
            ),
            Self::ResourceConstraint(error) => write!(
                f,
                "Resource constraint during {}: {}",
                error.operation, error.reason
            ),
            Self::ProviderAdapter(error) => write!(
                f,
                "Provider {} adapter failed during {}",
                error.provider_id, error.operation
            ),
            Self::ArtifactOperation(error) => f.write_str(&error.message()),
            Self::Configuration(error) => f.write_str(&error.message),
            Self::EvidenceIntegrity(error) => f.write_str(&error.message),
            Self::EvidenceFile(error) => write!(
                f,
                "Evidence bundle {} failed: {}",
                error.operation.as_str(),
                error.reason.as_str()
            ),
            Self::NoBinaryOpen => f.write_str(NO_BINARY_OPEN_MESSAGE),
        }
    }
}

pub(super) const NO_BINARY_OPEN_MESSAGE: &str = "No app is open. Ask the user which app to investigate, then call open_binary with its local path.";

/// Provider-neutral invalid analysis input or output at an application boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    /// Internal message; callers receive a generic unreadable-output message.
    pub message: String,
}

/// Caller input failed provider-neutral application parsing.
#[derive(Debug, Clone, PartialEq)]
pub struct InputError {
    /// Operation whose input contract was violated.
    pub operation: String,
    /// Secret-safe correction metadata, one per rejected argument.
    pub issues: Vec<InputIssue>,
    /// Replaces the generic invalid-input message.
    pub user_message: Option<String>,
    /// Refusal-specific correction when generic input-contract advice cannot fix it.
    pub remediation_action: Option<String>,
    /// The refused values satisfy the advertised contract, but the selected
    /// target lacks the requested fact; no input-contract recovery applies.
    pub conforms_to_input_contract: bool,
}

impl InputError {
    /// An input refusal for `operation` with no issues yet.
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            issues: Vec::new(),
            user_message: None,
            remediation_action: None,
            conforms_to_input_contract: false,
        }
    }

    /// Attach the rejected arguments.
    #[must_use]
    pub fn with_issues(mut self, issues: impl IntoIterator<Item = InputIssue>) -> Self {
        self.issues.extend(issues);
        self
    }

    /// Replace the generic invalid-input message.
    #[must_use]
    pub fn with_user_message(mut self, message: impl Into<String>) -> Self {
        self.user_message = Some(message.into());
        self
    }

    /// Replace the generic input-contract remediation.
    #[must_use]
    pub fn with_remediation_action(mut self, action: impl Into<String>) -> Self {
        self.remediation_action = Some(action.into());
        self
    }

    /// Mark the refused values as conforming to the advertised input contract.
    #[must_use]
    pub fn conforming_to_input_contract(mut self) -> Self {
        self.conforms_to_input_contract = true;
        self
    }
}

/// One segment of a JSON path into the caller's arguments.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IssuePathSegment {
    /// Object member name.
    Key(String),
    /// Array index.
    Index(u64),
}

impl From<&str> for IssuePathSegment {
    fn from(key: &str) -> Self {
        Self::Key(key.to_owned())
    }
}

impl From<String> for IssuePathSegment {
    fn from(key: String) -> Self {
        Self::Key(key)
    }
}

impl From<u64> for IssuePathSegment {
    fn from(index: u64) -> Self {
        Self::Index(index)
    }
}

impl From<usize> for IssuePathSegment {
    fn from(index: usize) -> Self {
        Self::Index(index as u64)
    }
}

impl From<&IssuePathSegment> for Value {
    fn from(segment: &IssuePathSegment) -> Self {
        match segment {
            IssuePathSegment::Key(key) => Value::String(key.clone()),
            IssuePathSegment::Index(index) => Value::from(*index),
        }
    }
}

/// Why one caller argument was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputIssueReason {
    /// `unknown_argument`.
    UnknownArgument,
    /// `missing_argument`.
    MissingArgument,
    /// `invalid_type`.
    InvalidType,
    /// `out_of_range`.
    OutOfRange,
    /// `invalid_value`.
    InvalidValue,
    /// `invalid_format`.
    InvalidFormat,
}

impl InputIssueReason {
    /// Contract text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownArgument => "unknown_argument",
            Self::MissingArgument => "missing_argument",
            Self::InvalidType => "invalid_type",
            Self::OutOfRange => "out_of_range",
            Self::InvalidValue => "invalid_value",
            Self::InvalidFormat => "invalid_format",
        }
    }
}

/// Secret-safe correction metadata for one rejected caller argument.
#[derive(Debug, Clone, PartialEq)]
pub struct InputIssue {
    /// Location of the argument in the request.
    pub path: Vec<IssuePathSegment>,
    /// Why it was rejected.
    pub reason: InputIssueReason,
    /// Schema-authored correction guidance for cross-field or custom checks.
    pub message: Option<String>,
    /// The accepted shape or values.
    pub expected: Option<Value>,
    /// Producer-examined facts about the refused value, such as its location and shape.
    pub observed: Option<Value>,
    /// Smallest accepted value.
    pub minimum: Option<Number>,
    /// Largest accepted value.
    pub maximum: Option<Number>,
}

impl InputIssue {
    /// An issue at `path`.
    pub fn new<P, S>(path: P, reason: InputIssueReason) -> Self
    where
        P: IntoIterator<Item = S>,
        S: Into<IssuePathSegment>,
    {
        Self {
            path: path.into_iter().map(Into::into).collect(),
            reason,
            message: None,
            expected: None,
            observed: None,
            minimum: None,
            maximum: None,
        }
    }

    /// Attach correction guidance.
    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Attach the accepted shape or values.
    #[must_use]
    pub fn with_expected(mut self, expected: impl Into<Value>) -> Self {
        self.expected = Some(expected.into());
        self
    }

    /// Attach examined facts about the refused value.
    #[must_use]
    pub fn with_observed(mut self, observed: impl Into<Value>) -> Self {
        self.observed = Some(observed.into());
        self
    }

    /// Attach the accepted inclusive range bounds.
    #[must_use]
    pub fn with_range(mut self, minimum: Option<Number>, maximum: Option<Number>) -> Self {
        self.minimum = minimum;
        self.maximum = maximum;
        self
    }

    pub(super) fn to_value(&self) -> Value {
        let mut issue = Map::new();
        issue.insert(
            "path".into(),
            Value::Array(self.path.iter().map(Value::from).collect()),
        );
        issue.insert("reason".into(), self.reason.as_str().into());
        if let Some(message) = &self.message {
            issue.insert("message".into(), message.clone().into());
        }
        if let Some(expected) = &self.expected {
            issue.insert("expected".into(), expected.clone());
        }
        if let Some(observed) = &self.observed {
            issue.insert("observed".into(), observed.clone());
        }
        if let Some(minimum) = &self.minimum {
            issue.insert("minimum".into(), Value::Number(minimum.clone()));
        }
        if let Some(maximum) = &self.maximum {
            issue.insert("maximum".into(), Value::Number(maximum.clone()));
        }
        Value::Object(issue)
    }
}

/// Host error code that denied a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessDeniedCode {
    /// `EACCES`.
    Eacces,
    /// `EPERM`.
    Eperm,
}

impl AccessDeniedCode {
    /// Contract text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eacces => "EACCES",
            Self::Eperm => "EPERM",
        }
    }

    /// Classify a raw OS error number; other errors are not access denial.
    pub fn from_raw_os_error(code: i32) -> Option<Self> {
        match code {
            1 => Some(Self::Eperm),
            13 => Some(Self::Eacces),
            _ => None,
        }
    }
}

/// Host filesystem permissions denied the selected read; this is not malformed input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDeniedError {
    /// Operation that attempted the read.
    pub operation: String,
    /// Caller-visible path text of the selected file.
    pub path: String,
    /// Host error code.
    pub system_code: AccessDeniedCode,
}

/// Selected artifact acquisition observed a change, so no stable identity can be reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactChangedError {
    /// Operation that acquired the artifact.
    pub operation: String,
    /// Caller-visible path text of the selected file.
    pub path: String,
    /// The observed change.
    pub reason: String,
}

/// Provider output failed provider-neutral application parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputError {
    /// Operation whose output was unreadable.
    pub operation: String,
    /// Caller-safe description of the defect.
    pub reason: String,
    /// Caller-facing explanation for a deterministic, diagnosable refusal.
    pub user_message: Option<String>,
    /// Refusal-specific remediation.
    pub remediation_action: Option<String>,
    /// The failure concerns cleanup only.
    pub cleanup_only: bool,
}

impl OutputError {
    /// An unreadable output from `operation`.
    pub fn new(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            reason: reason.into(),
            user_message: None,
            remediation_action: None,
            cleanup_only: false,
        }
    }
}

/// Selected provider cannot execute a declared analysis operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityUnavailableError {
    /// Provider that refused.
    pub provider_id: String,
    /// Refused operation.
    pub operation: String,
    /// Caller-safe reason.
    pub reason: String,
    /// Replaces the generic unavailable-capability message.
    pub user_message: Option<String>,
    /// Producer recovery.
    pub remediation_action: Option<String>,
    /// The producer expects the same request to succeed later. Ignored while
    /// the failure was raised with incomplete cleanup.
    pub retryable: bool,
}

impl CapabilityUnavailableError {
    /// An unavailable capability.
    pub fn new(
        provider_id: impl Into<String>,
        operation: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            operation: operation.into(),
            reason: reason.into(),
            user_message: None,
            remediation_action: None,
            retryable: false,
        }
    }
}

/// A readable supplied artifact lies outside this operation's supported target formats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedTargetError {
    /// Refusing operation.
    pub operation: String,
    /// Caller-visible path text of the selected target.
    pub path: String,
    /// Caller-safe description of the unsupported format.
    pub reason: String,
    /// Recovery when the producer knows an available workflow.
    pub remediation_action: Option<String>,
}

impl UnsupportedTargetError {
    pub(super) fn message(&self) -> String {
        format!(
            "Unsupported target for {} at {}: {}",
            self.operation, self.path, self.reason
        )
    }
}

/// Caller cancellation won before provider-neutral work completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelledError {
    /// Cancelled operation.
    pub operation: String,
}

/// Provider-neutral operation exceeded its declared execution deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutError {
    /// Operation that timed out.
    pub operation: String,
    /// The elapsed server/provider deadline.
    pub timeout_ms: u64,
    /// Provider-specific explanation of which deadline elapsed.
    pub user_message: Option<String>,
    /// Provider-specific setting or action that changes that deadline.
    pub remediation_action: Option<String>,
}

impl TimeoutError {
    /// A timeout of `operation` after `timeout_ms`.
    pub fn new(operation: impl Into<String>, timeout_ms: u64) -> Self {
        Self {
            operation: operation.into(),
            timeout_ms,
            user_message: None,
            remediation_action: None,
        }
    }
}

/// Resource class of a [`ResourceConstraintError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    /// `memory`.
    Memory,
    /// `cpu`.
    Cpu,
    /// `file-size`.
    FileSize,
    /// `transport`.
    Transport,
    /// `capacity`: occupied admission capacity, retryable by default.
    Capacity,
}

impl ResourceKind {
    /// Contract text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Cpu => "cpu",
            Self::FileSize => "file-size",
            Self::Transport => "transport",
            Self::Capacity => "capacity",
        }
    }
}

/// A measured resource constraint or bounded admission refusal.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceConstraintError {
    /// Refusing operation.
    pub operation: String,
    /// Constrained resource.
    pub resource: ResourceKind,
    /// Caller-facing description; it is the projected message.
    pub reason: String,
    /// Observed limits; `None` projects as `null` (limits unknown).
    pub reported_limits: Option<Map<String, Value>>,
    /// The one recovery this refusal carries.
    pub recovery: ResourceConstraintRecovery,
}

impl ResourceConstraintError {
    /// A resource refusal with the resource kind's default recovery.
    pub fn new(
        operation: impl Into<String>,
        resource: ResourceKind,
        reason: impl Into<String>,
        reported_limits: Option<Map<String, Value>>,
    ) -> Self {
        Self {
            operation: operation.into(),
            resource,
            reason: reason.into(),
            reported_limits,
            recovery: ResourceConstraintRecovery::default(),
        }
    }

    /// Replace the recovery.
    #[must_use]
    pub fn with_recovery(mut self, recovery: ResourceConstraintRecovery) -> Self {
        self.recovery = recovery;
        self
    }
}

/// A provider adapter failed outside its more precise typed variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAdapterError {
    /// Failing provider.
    pub provider_id: String,
    /// Failing operation.
    pub operation: String,
    /// Replaces the generic adapter-failure message.
    pub user_message: Option<String>,
    /// Producer recovery.
    pub remediation_action: Option<String>,
}

impl ProviderAdapterError {
    /// An adapter failure.
    pub fn new(provider_id: impl Into<String>, operation: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            operation: operation.into(),
            user_message: None,
            remediation_action: None,
        }
    }

    /// Attach producer recovery.
    #[must_use]
    pub fn with_remediation_action(mut self, action: impl Into<String>) -> Self {
        self.remediation_action = Some(action.into());
        self
    }
}

/// Why an artifact operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactOperationReason {
    /// `cancelled`.
    Cancelled,
    /// `format`: malformed or invalid content.
    Format,
    /// `integrity`.
    Integrity,
    /// `limit`: a resource limit truncated the operation.
    Limit,
    /// `path`: a conflicting internal path.
    Path,
    /// `unavailable`.
    Unavailable,
    /// `io`.
    Io,
}

impl ArtifactOperationReason {
    /// Contract text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Format => "format",
            Self::Integrity => "integrity",
            Self::Limit => "limit",
            Self::Path => "path",
            Self::Unavailable => "unavailable",
            Self::Io => "io",
        }
    }
}

/// The resource class that refused an artifact operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactLimitBoundary {
    /// `file-size`.
    FileSize,
    /// `capacity`.
    Capacity,
    /// `memory`.
    Memory,
}

impl ArtifactLimitBoundary {
    /// Contract text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileSize => "file-size",
            Self::Capacity => "capacity",
            Self::Memory => "memory",
        }
    }
}

/// Source of an admission's effective byte ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdmissionSource {
    /// `default`.
    Default,
    /// `setting`.
    Setting,
    /// `runtime`.
    Runtime,
}

impl AdmissionSource {
    /// Contract text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Setting => "setting",
            Self::Runtime => "runtime",
        }
    }
}

/// ASAR header admission named by the producing reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactAdmissionLimit {
    /// Bytes the header needed, when measured.
    pub required_bytes: Option<u64>,
    /// Effective header byte ceiling.
    pub maximum_bytes: u64,
    /// Where the ceiling came from.
    pub source: AdmissionSource,
}

/// Declared and observed digest of one artifact entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactDigestClaim {
    /// SHA-256 integrity, possibly undeclared.
    Sha256 {
        /// Declared lowercase hex digest.
        declared: Option<String>,
        /// Calculated lowercase hex digest, when the bytes were readable.
        calculated: Option<String>,
    },
    /// MD5 integrity.
    Md5 {
        /// Declared lowercase hex digest.
        declared: String,
        /// Calculated lowercase hex digest, when the bytes were readable.
        calculated: Option<String>,
    },
    /// DFU CRC-32 container checksum.
    DfuCrc32 {
        /// Declared lowercase hex checksum.
        declared: String,
        /// Calculated lowercase hex checksum, when the bytes were readable.
        calculated: Option<String>,
    },
}

/// Exact coordinates of an artifact-integrity contradiction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactIntegrityDetails {
    /// Logical path of the entry inside the artifact.
    pub logical_path: String,
    /// The entry's bytes live in an unpacked companion file.
    pub unpacked: bool,
    /// Declared versus calculated digest.
    pub digest: ArtifactDigestClaim,
}

impl ArtifactIntegrityDetails {
    pub(super) fn to_map(&self) -> Map<String, Value> {
        let text = |value: &Option<String>| value.clone().map_or(Value::Null, Value::String);
        let mut details = Map::new();
        details.insert("logical_path".into(), self.logical_path.clone().into());
        match &self.digest {
            ArtifactDigestClaim::Sha256 {
                declared,
                calculated,
            } => {
                details.insert("declared_sha256".into(), text(declared));
                details.insert("calculated_sha256".into(), text(calculated));
            }
            ArtifactDigestClaim::Md5 {
                declared,
                calculated,
            } => {
                details.insert("algorithm".into(), "md5".into());
                details.insert("declared_md5".into(), declared.clone().into());
                details.insert("calculated_md5".into(), text(calculated));
            }
            ArtifactDigestClaim::DfuCrc32 {
                declared,
                calculated,
            } => {
                details.insert("algorithm".into(), "dfu-crc32".into());
                details.insert("declared_crc32".into(), declared.clone().into());
                details.insert("calculated_crc32".into(), text(calculated));
            }
        }
        details.insert("unpacked".into(), self.unpacked.into());
        details
    }
}

/// Artifact inventory or extraction failed a typed safety boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactOperationError {
    /// Failing operation, such as `inspect_elf_notes`.
    pub operation: String,
    /// Failure class.
    pub reason: ArtifactOperationReason,
    /// Declared-versus-observed integrity coordinates.
    pub integrity: Option<ArtifactIntegrityDetails>,
    /// The specific constraint that failed, such as the colliding path.
    pub detail: Option<String>,
    /// Replaces the reason's default message.
    pub user_message: Option<String>,
    /// Admission that refused the artifact.
    pub admission: Option<ArtifactAdmissionLimit>,
    /// Resource class that refused the artifact.
    pub boundary: Option<ArtifactLimitBoundary>,
}

impl ArtifactOperationError {
    /// An artifact operation failure with an optional constraint detail.
    pub fn new(
        operation: impl Into<String>,
        reason: ArtifactOperationReason,
        detail: Option<String>,
    ) -> Self {
        Self {
            operation: operation.into(),
            reason,
            integrity: None,
            detail,
            user_message: None,
            admission: None,
            boundary: None,
        }
    }

    /// Name the resource class that refused the artifact.
    #[must_use]
    pub fn with_boundary(mut self, boundary: ArtifactLimitBoundary) -> Self {
        self.boundary = Some(boundary);
        self
    }

    /// An admission refusal reports its detail as the caller message.
    pub(super) fn effective_user_message(&self) -> Option<&str> {
        self.user_message.as_deref().or(match self.admission {
            Some(_) => self.detail.as_deref(),
            None => None,
        })
    }

    pub(super) fn message(&self) -> String {
        let reason = self.reason.as_str();
        let Some(integrity) = &self.integrity else {
            return format!("Artifact {} failed: {reason}", self.operation);
        };
        let mut facts = integrity.to_map();
        facts.shift_remove("logical_path");
        let description = facts
            .iter()
            .map(|(key, value)| match value {
                Value::Null => format!("{key}=unavailable"),
                Value::String(text) => format!("{key}={text}"),
                other => format!("{key}={other}"),
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "Artifact {} failed: {reason} at {} ({description})",
            self.operation, integrity.logical_path
        )
    }
}

/// One rejected configuration setting and the constraint it failed; its value is not retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationSettingIssue {
    /// Setting name, such as an environment variable.
    pub setting: String,
    /// The constraint it failed.
    pub constraint: String,
}

/// Runtime configuration could not be parsed safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationError {
    /// Internal message.
    pub message: String,
    /// Rejected settings.
    pub settings: Vec<ConfigurationSettingIssue>,
    /// Producer-owned recovery when the setting can be repaired in a running session.
    pub remediation_action: Option<String>,
}

/// Evidence identity, schema, or bundle manifests failed integrity checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceIntegrityError {
    /// Integrity defect; projected as `details.reason`.
    pub message: String,
    /// Replaces the generic integrity message.
    pub user_message: Option<String>,
}

/// Direction of an Evidence bundle file access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceFileOperation {
    /// `read`.
    Read,
    /// `write`.
    Write,
}

impl EvidenceFileOperation {
    /// Contract text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// Why an Evidence bundle file access failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceFileReason {
    /// `not-file`.
    NotFile,
    /// `exists`.
    Exists,
    /// `wrong-kind`.
    WrongKind,
    /// `invalid-json`.
    InvalidJson,
    /// `missing`.
    Missing,
    /// `path-limit`.
    PathLimit,
    /// `storage-limit`.
    StorageLimit,
    /// `symlink-traversal`.
    SymlinkTraversal,
    /// `io`.
    Io,
}

impl EvidenceFileReason {
    /// Contract text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFile => "not-file",
            Self::Exists => "exists",
            Self::WrongKind => "wrong-kind",
            Self::InvalidJson => "invalid-json",
            Self::Missing => "missing",
            Self::PathLimit => "path-limit",
            Self::StorageLimit => "storage-limit",
            Self::SymlinkTraversal => "symlink-traversal",
            Self::Io => "io",
        }
    }
}

/// Host storage error code that refused Evidence publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageSystemCode {
    /// `EFBIG`.
    Efbig,
    /// `ENOSPC`.
    Enospc,
    /// `EDQUOT`.
    Edquot,
}

impl StorageSystemCode {
    /// Contract text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Efbig => "EFBIG",
            Self::Enospc => "ENOSPC",
            Self::Edquot => "EDQUOT",
        }
    }
}

/// Publication that completed before staging cleanup failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedEvidenceFile {
    /// Published path, unless its identity is explicitly excluded.
    pub path: Option<String>,
    /// Published byte count.
    pub bytes: u64,
}

/// Evidence bundle filesystem access failed within the configured policy.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceFileError {
    /// Read or write.
    pub operation: EvidenceFileOperation,
    /// Failure class.
    pub reason: EvidenceFileReason,
    /// Caller-selected path that failed, resolved against the working directory.
    pub path: Option<String>,
    /// Present only when a write committed before cleanup failed.
    pub published: Option<PublishedEvidenceFile>,
    /// Replaces the reason's default message.
    pub user_message: Option<String>,
    /// Schema issues relative to the selected file's JSON root.
    pub content_issues: Option<Vec<InputIssue>>,
    /// Host storage error code.
    pub system_code: Option<StorageSystemCode>,
}

impl EvidenceFileError {
    /// An Evidence file failure.
    pub fn new(operation: EvidenceFileOperation, reason: EvidenceFileReason) -> Self {
        Self {
            operation,
            reason,
            path: None,
            published: None,
            user_message: None,
            content_issues: None,
            system_code: None,
        }
    }
}
