//! Completion of provider Evidence.
//!
//! Upstream reference: `completeProviderEvidence` in
//! `upstream:src/application/ProviderOperationExecution.ts`.

use rea_domain::cancellation::CancellationSignal;
use rea_domain::error::AnalysisError;
use rea_domain::evidence::Evidence;

/// Classify completion after Evidence assembly, preserving the assembled
/// facts as a partial observation when cancellation arrived late.
pub fn complete_provider_evidence(
    evidence: Evidence,
    signal: &CancellationSignal,
) -> Result<Evidence, AnalysisError> {
    if !signal.is_cancelled() {
        return Ok(evidence);
    }
    let error = AnalysisError::cancelled(evidence.operation.clone());
    Err(match serde_json::to_value(&evidence) {
        Ok(observation) => error.with_partial_observation(observation),
        Err(_) => error,
    })
}
