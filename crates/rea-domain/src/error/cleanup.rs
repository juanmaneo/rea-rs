//! Cleanup uncertainty attached to typed failures and its composition.
//!
//! Upstream links errors through a live graph of `WeakRef` dependents
//! (`upstream:src/domain/analysisErrorBase.ts`). This port evaluates cleanup
//! state on demand instead: a pending error shares a [`CleanupHandle`] with
//! every clone of itself, and a composed error owns clones of the errors it
//! depends on. Because cleanup only ever moves from incomplete to complete,
//! pulling the state from the owned dependencies reports the same facts as
//! upstream's push propagation.
//!
//! Upstream reference: `upstream:src/domain/analysisErrorBase.ts`,
//! `analysisErrorCleanup.ts`, `analysisErrorCancellation.ts`,
//! `analysisErrorRecovery.ts`, and `providerCleanupError.ts`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Map, Value};

use super::kind::{AnalysisErrorKind, ProviderAdapterError};
use super::projection::{ChildFailure, child_failure_diagnostics};
use super::{AnalysisError, CallerLifetime, ContinuingCallerGuidance};

/// Default operation of a composed cleanup failure and of provider cleanup.
pub const DEFAULT_CLEANUP_OPERATION: &str = "close_binary";

const PROVIDER_CLEANUP_MESSAGE: &str = "Provider cleanup could not be fully confirmed. Review the reported local resources before opening another target.";

/// Shared completion flag of one pending cleanup.
///
/// Every clone of the error that created it observes [`CleanupHandle::resolve`].
#[derive(Debug, Clone)]
pub struct CleanupHandle(Arc<AtomicBool>);

impl CleanupHandle {
    fn pending() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }

    /// Record that the owning resource confirmed cleanup.
    pub fn resolve(&self) {
        self.0.store(false, Ordering::Release);
    }

    /// Whether cleanup is still unconfirmed.
    pub fn is_pending(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Cleanup uncertainty observed when a failure was raised. It is history:
/// it stays attached after cleanup completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupObservation {
    /// Caller-safe reason cleanup could not be confirmed.
    pub reason: String,
    /// Resources that remained unconfirmed.
    pub resources: Vec<String>,
}

impl CleanupObservation {
    /// An observation of unconfirmed `resources`.
    pub fn new(
        reason: impl Into<String>,
        resources: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            reason: reason.into(),
            resources: resources.into_iter().map(Into::into).collect(),
        }
    }
}

/// Same-connection operation that retries every live cleanup resource an
/// error reports. Only the owner retaining those resources binds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CleanupRetry {
    /// `close_binary` without `snapshot_path`.
    CloseBinary,
}

impl CleanupRetry {
    /// Operation name.
    pub const fn operation(self) -> &'static str {
        match self {
            Self::CloseBinary => "close_binary",
        }
    }

    /// Retry advice; it never promises release or process exit.
    pub fn remediation(self) -> String {
        format!(
            "This connection retains that cleanup. Keep it open; after the reported condition settles or is resolved, call {} without snapshot_path and check its result. That call retries the retained cleanup without rerunning the failed analysis, preserves investigation Evidence and Unknown history, and can report cleanup_incomplete again.",
            self.operation()
        )
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct CleanupState {
    pub(super) observation: Option<CleanupObservation>,
    /// Resources set by a more specific producer; they replace the observation's.
    pub(super) resources: Option<Vec<String>>,
    pub(super) status: CleanupStatus,
    pub(super) retry: Option<CleanupRetry>,
}

#[derive(Debug, Clone, Default)]
pub(super) enum CleanupStatus {
    #[default]
    Complete,
    Pending(CleanupHandle),
    /// Incomplete until every dependency completes.
    Dependent(Vec<AnalysisError>),
}

fn unique(resources: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = Vec::new();
    for resource in resources {
        if !seen.contains(&resource) {
            seen.push(resource);
        }
    }
    seen
}

impl AnalysisError {
    /// Provider resources could not be proven closed after bounded cleanup
    /// (upstream `ProviderCleanupError`).
    ///
    /// The adapter's message is replaced by the fixed provider-cleanup
    /// message. Pass `ProviderAdapterError::new(provider, DEFAULT_CLEANUP_OPERATION)`
    /// for binary-session cleanup. The cleanup is pending until resolved;
    /// `resources` stay authoritative even if an observation is attached later.
    pub fn provider_cleanup(
        mut adapter: ProviderAdapterError,
        resources: impl IntoIterator<Item = impl Into<String>>,
        diagnostics: Map<String, Value>,
    ) -> Self {
        adapter.user_message = Some(PROVIDER_CLEANUP_MESSAGE.to_owned());
        let mut error = Self::new(AnalysisErrorKind::ProviderAdapter(adapter));
        error.0.diagnostics = Some(diagnostics);
        error.0.cleanup.resources = Some(resources.into_iter().map(Into::into).collect());
        error.0.cleanup.status = CleanupStatus::Pending(CleanupHandle::pending());
        error
    }

    /// Attach cleanup uncertainty observed when this failure was raised. The
    /// cleanup is pending until [`AnalysisError::resolve_cleanup`].
    #[must_use]
    pub fn with_cleanup(mut self, observation: CleanupObservation) -> Self {
        self.0.cleanup.observation = Some(observation);
        if !matches!(self.0.cleanup.status, CleanupStatus::Pending(_)) {
            self.0.cleanup.status = CleanupStatus::Pending(CleanupHandle::pending());
        }
        self
    }

    /// Whether cleanup remains unconfirmed.
    pub fn cleanup_incomplete(&self) -> bool {
        match &self.0.cleanup.status {
            CleanupStatus::Complete => false,
            CleanupStatus::Pending(handle) => handle.is_pending(),
            CleanupStatus::Dependent(dependencies) => {
                dependencies.iter().any(Self::cleanup_incomplete)
            }
        }
    }

    /// The cleanup observation, retained as history after completion.
    pub fn cleanup_observation(&self) -> Option<&CleanupObservation> {
        self.0.cleanup.observation.as_ref()
    }

    /// Currently attributed resources. Live dependencies own attribution;
    /// otherwise the producer's resources apply.
    pub fn cleanup_resources(&self) -> Vec<String> {
        match &self.0.cleanup.status {
            CleanupStatus::Dependent(dependencies) => unique(
                dependencies
                    .iter()
                    .filter(|dependency| dependency.cleanup_incomplete())
                    .flat_map(Self::cleanup_resources),
            ),
            CleanupStatus::Complete | CleanupStatus::Pending(_) => self
                .0
                .cleanup
                .resources
                .clone()
                .or_else(|| {
                    self.0
                        .cleanup
                        .observation
                        .as_ref()
                        .map(|observation| observation.resources.clone())
                })
                .unwrap_or_default(),
        }
    }

    /// Handle that resolves this error's own pending cleanup, shared by its clones.
    /// Absent when cleanup is complete or follows dependencies.
    pub fn cleanup_handle(&self) -> Option<CleanupHandle> {
        match &self.0.cleanup.status {
            CleanupStatus::Pending(handle) => Some(handle.clone()),
            CleanupStatus::Complete | CleanupStatus::Dependent(_) => None,
        }
    }

    /// Clear this error's own pending cleanup after its owning resource
    /// confirms success. A composition waiting on dependencies is unaffected.
    pub fn resolve_cleanup(&self) {
        if let CleanupStatus::Pending(handle) = &self.0.cleanup.status {
            handle.resolve();
        }
    }

    /// Caller retry for the live cleanup; absent once cleanup completes.
    pub fn cleanup_retry(&self) -> Option<CleanupRetry> {
        if self.cleanup_incomplete() {
            self.0.cleanup.retry
        } else {
            None
        }
    }

    /// Bind only from the owner retaining every reported resource for this retry.
    #[must_use]
    pub fn bind_cleanup_retry(mut self, retry: CleanupRetry) -> Self {
        self.0.cleanup.retry = Some(retry);
        self
    }

    /// Keep a composed error incomplete until all explicitly owned source
    /// errors resolve. Pass clones; they share pending state with the originals.
    ///
    /// Dependencies already complete are ignored; if none is pending, cleanup
    /// completes. Binding to an error whose cleanup is already complete has
    /// no effect.
    #[must_use]
    pub fn bind_cleanup_dependencies(
        mut self,
        dependencies: impl IntoIterator<Item = AnalysisError>,
    ) -> Self {
        if !self.cleanup_incomplete() {
            return self;
        }
        let pending = dependencies.into_iter().filter(Self::cleanup_incomplete);
        match &mut self.0.cleanup.status {
            CleanupStatus::Dependent(existing) => existing.extend(pending),
            status => {
                let pending: Vec<_> = pending.collect();
                *status = if pending.is_empty() {
                    CleanupStatus::Complete
                } else {
                    CleanupStatus::Dependent(pending)
                };
            }
        }
        self
    }

    /// Preserve a lifecycle failure alongside cleanup that remains incomplete
    /// (upstream `analysisErrorWithCleanupFailure`).
    ///
    /// The result keeps `primary` as its cleanup primary, takes its message
    /// from `primary` and its remediation from `cleanup`, and records both
    /// failures in diagnostics. Its own cleanup is pending until resolved;
    /// use [`AnalysisError::dependent_cleanup_failure`] to follow both owners.
    pub fn cleanup_failure(
        primary: AnalysisError,
        cleanup: &AnalysisError,
        operation: impl Into<String>,
    ) -> Self {
        let provider_id = match &cleanup.0.kind {
            AnalysisErrorKind::ProviderAdapter(adapter) => adapter.provider_id.clone(),
            _ => "rea".to_owned(),
        };
        let remediation = cleanup.remediation_action(CallerLifetime::Invocation);
        let continuing_remediation = cleanup.remediation_action(CallerLifetime::Continuing);
        let resolved_primary = primary.resolved();
        let guidance = ContinuingCallerGuidance {
            user_message: resolved_primary
                .0
                .continuing_caller_guidance
                .as_ref()
                .and_then(|guidance| guidance.user_message.clone()),
            remediation_action: (continuing_remediation != remediation)
                .then_some(continuing_remediation),
        };
        let mut adapter = ProviderAdapterError::new(provider_id, operation);
        adapter.user_message = Some(resolved_primary.outcome_user_message());
        adapter.remediation_action = Some(remediation);

        let reason = cleanup.0.cleanup.observation.as_ref().map_or_else(
            || cleanup.user_message(CallerLifetime::Invocation),
            |observation| observation.reason.clone(),
        );
        let primary_resources = if primary.cleanup_incomplete() {
            primary.cleanup_resources()
        } else {
            Vec::new()
        };
        let resources = unique(
            primary_resources
                .into_iter()
                .chain(cleanup.cleanup_resources()),
        );
        let children = child_failure_diagnostics(
            &[
                (
                    "primary_error",
                    ChildFailure {
                        error: &primary,
                        include_captured_output: primary.0.captured_output.is_none(),
                    },
                ),
                (
                    "cleanup_error",
                    ChildFailure {
                        error: cleanup,
                        include_captured_output: true,
                    },
                ),
            ],
            Map::new(),
        );

        let mut composed = Self::new(AnalysisErrorKind::ProviderAdapter(adapter))
            .with_cleanup(CleanupObservation { reason, resources })
            .with_child_failure_diagnostics(children);
        if guidance.user_message.is_some() || guidance.remediation_action.is_some() {
            composed.0.continuing_caller_guidance = Some(guidance);
        }
        composed
            .0
            .captured_output
            .clone_from(&primary.0.captured_output);
        composed
            .0
            .partial_observation
            .clone_from(&primary.0.partial_observation);
        composed.0.cleanup_primary = Some(primary);
        composed
    }

    /// [`AnalysisError::cleanup_failure`] bound to both `primary` and
    /// `cleanup`: it completes when both owners resolve.
    pub fn dependent_cleanup_failure(
        primary: AnalysisError,
        cleanup: AnalysisError,
        operation: impl Into<String>,
    ) -> Self {
        Self::cleanup_failure(primary.clone(), &cleanup, operation)
            .bind_cleanup_dependencies([primary, cleanup])
    }

    /// Keep the established failure while retaining a later caller
    /// cancellation once (upstream `analysisErrorWithCancellation`).
    ///
    /// The cancellation is retained as a secondary failure of the primary
    /// unless the primary is itself a cancellation or already retains one.
    pub fn with_cancellation(failure: Option<AnalysisError>, cancellation: AnalysisError) -> Self {
        let Some(mut failure) = failure else {
            return cancellation;
        };
        let primary = failure.primary_mut();
        let cancelled =
            |error: &AnalysisError| matches!(error.0.kind, AnalysisErrorKind::Cancelled(_));
        if !cancelled(primary) && !primary.0.secondary_failures.iter().any(cancelled) {
            primary.retain_secondary_failure(cancellation, None);
        }
        failure
    }

    fn primary_mut(&mut self) -> &mut Self {
        match self.0.cleanup_primary {
            Some(ref mut primary) => primary.primary_mut(),
            None => self,
        }
    }
}
