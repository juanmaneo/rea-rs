//! Cleanup composition parity with
//! `upstream:src/domain/analysisErrorCleanup.test.ts` and
//! `upstream:src/domain/providerCleanupError.test.ts`.
//!
//! Upstream resolves an error object directly; here the [`CleanupHandle`]
//! taken before an error moves into a composition plays that role.

#[path = "fixtures/error_contract_checker.rs"]
mod checker;

use checker::{assert_matches, continuing, object, without};
use rea_domain::error::{
    AnalysisError, AnalysisErrorKind, ArtifactOperationReason, CallerLifetime, CapturedOutput,
    CleanupObservation, CleanupRetry, DEFAULT_CLEANUP_OPERATION, InputError, InputIssue,
    InputIssueReason, ProviderAdapterError, ResourceConstraintError, ResourceConstraintRecovery,
    ResourceKind, TimeoutError,
};
use serde_json::{Value, json};

fn provider_cleanup(provider: &str, resources: &[&str], diagnostics: Value) -> AnalysisError {
    AnalysisError::provider_cleanup(
        ProviderAdapterError::new(provider, DEFAULT_CLEANUP_OPERATION),
        resources.iter().copied(),
        object(diagnostics),
    )
}

#[test]
fn keeps_each_owners_capture_without_text_based_deduplication() {
    for matching in [false, true] {
        let primary_output = CapturedOutput::new("primary-capture-sentinel", "", false);
        let cleanup_output = CapturedOutput::new(
            if matching {
                "primary-capture-sentinel"
            } else {
                "cleanup-capture-sentinel"
            },
            "",
            true,
        );
        let primary =
            AnalysisError::timeout("inspect", 1234).with_captured_output(primary_output.clone());
        let cleanup = provider_cleanup("fixture", &["owned-worker"], json!({}))
            .with_captured_output(cleanup_output.clone());
        let composed = AnalysisError::cleanup_failure(primary.clone(), &cleanup, "inspect");
        let projected = continuing(&composed);
        assert_eq!(
            projected["details"]["captured_output"],
            primary_output.to_value()
        );
        assert_matches(
            &projected["details"]["diagnostics"],
            &json!({
                "primary_error": {"code": "provider_timeout", "details": {"timeout_ms": 1234}},
                "cleanup_error": {"details": {"captured_output": cleanup_output.to_value()}}
            }),
        );
        let text = projected.to_string();
        assert_eq!(
            text.matches("primary-capture-sentinel").count(),
            if matching { 2 } else { 1 }
        );
        if !matching {
            assert_eq!(text.matches("cleanup-capture-sentinel").count(), 1);
        }
        let without = primary
            .project_without_captured_output(CallerLifetime::Continuing)
            .to_value();
        assert_eq!(checker::validate(&without), Ok(()));
        assert!(without["details"].get("captured_output").is_none());
        assert_eq!(
            continuing(&primary)["details"]["captured_output"],
            primary_output.to_value()
        );
    }
}

#[test]
fn keeps_dependency_owned_resources_empty_after_the_final_owner_releases() {
    let file = provider_cleanup("fixture", &["file-owner"], json!({}));
    let trace = provider_cleanup("fixture", &["trace-owner"], json!({}));
    let (file_handle, trace_handle) = (
        file.cleanup_handle().unwrap(),
        trace.cleanup_handle().unwrap(),
    );
    let composed = AnalysisError::dependent_cleanup_failure(file, trace, DEFAULT_CLEANUP_OPERATION);
    assert_eq!(composed.cleanup_resources(), ["file-owner", "trace-owner"]);
    file_handle.resolve();
    assert_eq!(composed.cleanup_resources(), ["trace-owner"]);
    trace_handle.resolve();
    assert!(!composed.cleanup_incomplete());
    assert!(composed.cleanup_resources().is_empty());
    assert_eq!(
        composed.cleanup_observation().unwrap().resources,
        ["file-owner", "trace-owner"]
    );
}

#[test]
fn keeps_primary_diagnostics_separate_from_historical_cleanup_diagnostics_with_the_same_keys() {
    let primary = AnalysisError::from(InputError::new("inspect")).with_diagnostics(object(json!({
        "primary_error": "source observation",
        "cleanup_error": "another source observation"
    })));
    let cleanup = provider_cleanup("fixture", &["owned-input"], json!({}));
    let handle = cleanup.cleanup_handle().unwrap();
    let composed = AnalysisError::dependent_cleanup_failure(
        primary.clone(),
        cleanup,
        DEFAULT_CLEANUP_OPERATION,
    );
    handle.resolve();
    let projected = continuing(&composed);
    assert_eq!(
        projected["details"]["diagnostics"],
        Value::Object(primary.diagnostics().unwrap().clone())
    );
    assert_eq!(
        projected["details"]["cleanup_history"]["primary_error"],
        continuing(&primary)
    );
    assert_eq!(
        projected["details"]["cleanup_history"]["cleanup_error"]["code"],
        "cleanup_incomplete"
    );
    assert_eq!(composed.cleanup_primary().unwrap().tag(), primary.tag());
}

fn typed_primaries() -> Vec<AnalysisError> {
    vec![
        AnalysisError::artifact_operation(
            "inspect_asset_catalog",
            ArtifactOperationReason::Integrity,
            Some("Asset catalog changed during inspection: Contents/Resources/Assets.car".into()),
        ),
        AnalysisError::input(
            "inspect",
            [InputIssue::new(["path"], InputIssueReason::OutOfRange)
                .with_message("fixed input allowance")],
        )
        .with_diagnostics(object(json!({"input": "original"}))),
        AnalysisError::cancelled("inspect"),
        AnalysisError::timeout("inspect", 1234),
        ResourceConstraintError::new(
            "inspect",
            ResourceKind::FileSize,
            "fixed input allowance",
            Some(object(json!({"maximum_input_bytes": 123}))),
        )
        .with_recovery(ResourceConstraintRecovery::non_retryable(
            "Select a smaller suitable input.",
        ))
        .into(),
        AnalysisError::output("inspect", "invalid output")
            .with_captured_output(CapturedOutput::new(
                "original output",
                "original warning",
                true,
            ))
            .with_partial_observation(json!({
                "operation": "inspect",
                "result": {"original_fact": true}
            })),
    ]
}

#[test]
fn restores_the_typed_primary_after_confirmed_cleanup() {
    for primary in typed_primaries() {
        let tag = primary.tag();
        let original = continuing(&primary);
        let cleanup = AnalysisError::provider_cleanup(
            ProviderAdapterError::new("fixture", "inspect"),
            ["owned-input"],
            object(json!({"reason": "close denied"})),
        )
        .with_cleanup(CleanupObservation::new("close denied", ["owned-input"]));
        let handle = cleanup.cleanup_handle().unwrap();
        let cleanup_message = continuing(&cleanup)["message"].clone();
        let composed =
            AnalysisError::dependent_cleanup_failure(primary.clone(), cleanup, "inspect");
        assert_eq!(
            composed.cleanup_observation().unwrap().reason,
            "close denied"
        );
        assert_ne!(cleanup_message, "close denied");

        let pending = continuing(&composed);
        assert_eq!(pending["code"], "cleanup_incomplete", "{tag}");
        assert_eq!(pending["category"], original["category"], "{tag}");
        assert_eq!(composed.category().as_str(), original["category"]);
        let mut semantic = match original.get("details") {
            Some(details) => without(details.clone(), "diagnostics"),
            None => json!({}),
        };
        semantic["cleanup"] = json!("incomplete");
        semantic["execution_failure"] = original["code"].clone();
        semantic["resources"] = json!(["owned-input"]);
        assert_matches(&pending["details"], &semantic);

        handle.resolve();
        let projected = continuing(&composed);
        assert_matches(&projected, &original);
        let expected_history = if primary.captured_output().is_some() {
            primary
                .project_without_captured_output(CallerLifetime::Continuing)
                .to_value()
        } else {
            original.clone()
        };
        assert_eq!(
            projected["details"]["cleanup_history"]["primary_error"], expected_history,
            "{tag}"
        );
        assert_eq!(
            projected["details"]["cleanup_history"]["cleanup_error"]["code"],
            "cleanup_incomplete"
        );
        assert_ne!(
            projected["details"].get("cleanup"),
            Some(&json!("incomplete"))
        );
        assert!(projected["details"].get("resources").is_none());
        assert_eq!(composed.category().as_str(), original["category"]);
        assert_eq!(
            composed.user_message(CallerLifetime::Continuing),
            original["message"]
        );
        assert_eq!(
            composed.remediation_action(CallerLifetime::Continuing),
            original["remediation"]["action"]
        );
    }
}

#[test]
fn waits_for_both_nested_cleanup_owners() {
    for inner_first in [true, false] {
        let primary = AnalysisError::input(
            "inspect",
            [InputIssue::new(["path"], InputIssueReason::MissingArgument)],
        );
        let inner_cleanup = provider_cleanup("fixture", &["input"], json!({}));
        let outer_cleanup = provider_cleanup("fixture", &["workspace"], json!({}));
        let inner_handle = inner_cleanup.cleanup_handle().unwrap();
        let outer_handle = outer_cleanup.cleanup_handle().unwrap();
        let inner = AnalysisError::dependent_cleanup_failure(
            primary.clone(),
            inner_cleanup,
            DEFAULT_CLEANUP_OPERATION,
        );
        let outer = AnalysisError::dependent_cleanup_failure(
            inner,
            outer_cleanup,
            DEFAULT_CLEANUP_OPERATION,
        );
        let (released, pending) = if inner_first {
            (inner_handle, outer_handle)
        } else {
            (outer_handle, inner_handle)
        };
        assert_matches(
            &continuing(&outer),
            &json!({
                "code": "cleanup_incomplete",
                "category": "invalid_input",
                "details": {
                    "operation": "inspect",
                    "issues": [{"path": ["path"], "reason": "missing_argument"}],
                    "execution_failure": "invalid_request"
                }
            }),
        );
        released.resolve();
        assert!(outer.cleanup_incomplete());
        let projected = continuing(&outer);
        assert_eq!(projected["code"], "cleanup_incomplete");
        assert_eq!(projected["category"], "invalid_input");
        pending.resolve();
        assert!(!outer.cleanup_incomplete());
        assert_matches(&continuing(&outer), &continuing(&primary));
    }
}

#[test]
fn does_not_infer_cleanup_success_when_a_composition_has_no_live_owner_binding() {
    let primary = AnalysisError::from(InputError::new("inspect"));
    let cleanup = provider_cleanup("fixture", &["input"], json!({}));
    let composed = AnalysisError::cleanup_failure(primary, &cleanup, DEFAULT_CLEANUP_OPERATION);
    cleanup.resolve_cleanup();
    let projected = continuing(&composed);
    assert_eq!(projected["code"], "cleanup_incomplete");
    assert_eq!(projected["category"], "invalid_input");
    assert!(composed.cleanup_incomplete());
}

#[test]
fn keeps_the_physical_failure_primary_when_later_cleanup_fails() {
    let primary = AnalysisError::artifact_operation(
        "inspect_asset_catalog",
        ArtifactOperationReason::Io,
        Some("selected file read EIO".into()),
    );
    let cleanup = provider_cleanup("fixture", &["owned-input"], json!({}));
    let handle = cleanup.cleanup_handle().unwrap();
    let composed = AnalysisError::dependent_cleanup_failure(primary.clone(), cleanup, "inspect");
    assert_matches(
        &continuing(&composed),
        &json!({
            "code": "cleanup_incomplete",
            "category": "execution_failure",
            "details": {
                "operation": "inspect_asset_catalog",
                "reason": "io",
                "detail": "selected file read EIO",
                "execution_failure": "artifact_operation_failed"
            }
        }),
    );
    handle.resolve();
    assert_matches(&continuing(&composed), &continuing(&primary));
}

#[test]
fn retains_an_observation_attached_to_the_composite_after_the_primary_failed() {
    let primary = AnalysisError::from(InputError::new("inspect"));
    let cleanup = provider_cleanup("fixture", &["input"], json!({}));
    let handle = cleanup.cleanup_handle().unwrap();
    let mut composed =
        AnalysisError::dependent_cleanup_failure(primary, cleanup, DEFAULT_CLEANUP_OPERATION);
    let observation = json!({"operation": "inspect", "result": {"late_fact": true}});
    composed.retain_partial_observation(observation.clone());
    composed.resolve_cleanup();
    assert_eq!(continuing(&composed)["code"], "cleanup_incomplete");
    handle.resolve();
    assert_matches(
        &continuing(&composed),
        &json!({"code": "invalid_request", "details": {"partial_observation": observation}}),
    );
}

#[test]
fn follows_a_finalizer_above_the_semantic_primary_until_every_owner_resolves() {
    // Upstream also asserts a ProcessCapture `cleanup_report`; that report is
    // deferred with ProcessCaptureError, so only the lifecycle is ported.
    let primary = AnalysisError::input(
        "inspect",
        [InputIssue::new(["path"], InputIssueReason::MissingArgument)],
    );
    let finalized =
        provider_cleanup("fixture", &["input"], json!({})).with_cleanup_primary(primary);
    let later = provider_cleanup("fixture", &["workspace"], json!({}));
    let (finalized_handle, later_handle) = (
        finalized.cleanup_handle().unwrap(),
        later.cleanup_handle().unwrap(),
    );
    let outer = AnalysisError::dependent_cleanup_failure(
        finalized.clone(),
        later,
        DEFAULT_CLEANUP_OPERATION,
    );
    let expected = json!({
        "category": "invalid_input",
        "details": {"operation": "inspect", "issues": [{"path": ["path"], "reason": "missing_argument"}]}
    });
    assert_matches(&continuing(&finalized), &expected);
    assert_matches(&continuing(&outer), &expected);
    assert!(outer.cleanup_incomplete());
    later_handle.resolve();
    assert_matches(&continuing(&outer), &expected);
    assert!(outer.cleanup_incomplete());
    finalized_handle.resolve();
    assert_matches(&continuing(&outer), &expected);
    assert!(!outer.cleanup_incomplete());
}

#[test]
fn preserves_the_binary_cleanup_default_and_an_explicitly_owned_nonbinary_operation() {
    let binary = provider_cleanup("ghidra", &["database"], json!({}));
    assert_eq!(continuing(&binary)["details"]["operation"], "close_binary");
    let error = AnalysisError::provider_cleanup(
        ProviderAdapterError::new("source-map-decoder", "trace_web_source_location"),
        ["runtime"],
        object(json!({"reason": "cleanup failed"})),
    );
    assert_matches(
        &continuing(&error),
        &json!({
            "code": "cleanup_incomplete",
            "message": "Provider cleanup could not be fully confirmed. Review the reported local resources before opening another target.",
            "details": {"operation": "trace_web_source_location"}
        }),
    );
}

#[test]
fn combines_only_live_cleanup_resources() {
    for resolved in [false, true] {
        let primary = AnalysisError::provider_cleanup(
            ProviderAdapterError::new("adb", "capture_adb_screen"),
            ["publication-handle"],
            object(json!({"reason": "first descriptor close failed"})),
        );
        if resolved {
            primary.resolve_cleanup();
        }
        let cleanup = provider_cleanup(
            "adb",
            &["runtime-root"],
            json!({"reason": "workspace removal failed"}),
        );
        let combined = AnalysisError::cleanup_failure(primary, &cleanup, DEFAULT_CLEANUP_OPERATION);
        let resources = if resolved {
            json!(["runtime-root"])
        } else {
            json!(["publication-handle", "runtime-root"])
        };
        assert_matches(
            &continuing(&combined),
            &json!({
                "code": "cleanup_incomplete",
                "details": {
                    "resources": resources,
                    "diagnostics": {
                        "primary_error": {"details": {"diagnostics": {"reason": "first descriptor close failed"}}},
                        "cleanup_error": {"details": {"diagnostics": {"reason": "workspace removal failed"}}}
                    }
                }
            }),
        );
        assert_eq!(continuing(&combined)["details"]["provider_id"], "adb");
    }
}

#[test]
fn projects_only_unresolved_resources_through_nested_cleanup_groups() {
    for alpha_first in [true, false] {
        let alpha = provider_cleanup("alpha", &["alpha-file"], json!({}));
        let beta = provider_cleanup("beta", &["beta-file"], json!({}));
        let third = provider_cleanup("third", &["third-file"], json!({}));
        let handles = [&alpha, &beta, &third].map(|e| e.cleanup_handle().unwrap());
        let children = provider_cleanup("rea", &["alpha-file", "beta-file"], json!({}))
            .bind_cleanup_dependencies([alpha.clone(), beta.clone()]);
        let outer = provider_cleanup("rea", &["alpha-file", "beta-file", "third-file"], json!({}))
            .bind_cleanup_dependencies([children, third]);
        let (released, remaining, remaining_resource) = if alpha_first {
            (&handles[0], &handles[1], "beta-file")
        } else {
            (&handles[1], &handles[0], "alpha-file")
        };
        released.resolve();
        assert!(outer.cleanup_incomplete());
        assert_eq!(
            outer.cleanup_resources(),
            [remaining_resource, "third-file"]
        );
        assert_matches(
            &continuing(&outer),
            &json!({
                "code": "cleanup_incomplete",
                "details": {"resources": [remaining_resource, "third-file"]}
            }),
        );
        remaining.resolve();
        assert!(outer.cleanup_incomplete());
        assert_eq!(outer.cleanup_resources(), ["third-file"]);
        handles[2].resolve();
        assert!(!outer.cleanup_incomplete());
        assert_ne!(continuing(&outer)["code"], "cleanup_incomplete");
    }
}

#[test]
fn offers_a_bound_cleanup_retry_only_while_that_cleanup_remains_incomplete() {
    let retry_action = CleanupRetry::CloseBinary.remediation();
    let plain = provider_cleanup("kuna", &["staging"], json!({"reason": "stop unproven"}));
    let unbound = continuing(&plain);
    assert!(unbound.get("recovery").is_none());
    assert_eq!(
        unbound["remediation"]["action"],
        plain.remediation_action(CallerLifetime::Continuing)
    );
    assert!(
        !unbound["remediation"]["action"]
            .as_str()
            .unwrap()
            .contains(&retry_action)
    );

    let retained = provider_cleanup("kuna", &["staging"], json!({"reason": "stop unproven"}))
        .bind_cleanup_retry(CleanupRetry::CloseBinary);
    let offered = continuing(&retained);
    assert_matches(
        &offered,
        &json!({
            "code": "cleanup_incomplete",
            "retryable": false,
            "recovery": {"kind": "retry_cleanup", "operation": "close_binary"},
            "details": {"resources": ["staging"]}
        }),
    );
    assert_eq!(
        offered["remediation"]["action"],
        format!(
            "{} {retry_action}",
            retained.remediation_action(CallerLifetime::Continuing)
        )
    );

    retained.resolve_cleanup();
    assert_eq!(retained.cleanup_retry(), None);
    let released = continuing(&retained);
    assert_eq!(released["code"], "execution_failure");
    assert!(released.get("recovery").is_none());
    assert!(
        !released["remediation"]["action"]
            .as_str()
            .unwrap()
            .contains(&retry_action)
    );
}

#[test]
fn keeps_a_retry_offer_with_the_owner_of_the_composed_resources() {
    let retry_action = CleanupRetry::CloseBinary.remediation();
    let primary = AnalysisError::cancelled("procedure_assembly");
    let retained = provider_cleanup("kuna", &["staging"], json!({"reason": "stop unproven"}))
        .bind_cleanup_retry(CleanupRetry::CloseBinary);
    let owner_remediation = retained.remediation_action(CallerLifetime::Continuing);
    let handle = retained.cleanup_handle().unwrap();
    let composed =
        AnalysisError::dependent_cleanup_failure(primary, retained, DEFAULT_CLEANUP_OPERATION);
    let unbound = continuing(&composed);
    assert!(unbound.get("recovery").is_none());
    assert_eq!(unbound["remediation"]["action"], owner_remediation.as_str());

    let composed = composed.bind_cleanup_retry(CleanupRetry::CloseBinary);
    let offered = continuing(&composed);
    assert_matches(
        &offered,
        &json!({
            "code": "cleanup_incomplete",
            "recovery": {"kind": "retry_cleanup", "operation": "close_binary"},
            "details": {"execution_failure": "cancelled"}
        }),
    );
    let action = offered["remediation"]["action"].as_str().unwrap();
    assert_eq!(action, format!("{owner_remediation} {retry_action}"));
    assert_eq!(action.matches(retry_action.as_str()).count(), 1);

    handle.resolve();
    assert!(!composed.cleanup_incomplete());
    let released = continuing(&composed);
    assert_eq!(released["code"], "cancelled");
    assert!(released.get("recovery").is_none());
}

#[test]
fn composes_guidance_from_the_primary_message_and_the_cleanup_remediation() {
    let primary = AnalysisError::from(TimeoutError {
        user_message: Some("Only this request stopped.".into()),
        ..TimeoutError::new("inspect", 10)
    });
    let cleanup = provider_cleanup("fixture", &["worker"], json!({}));
    let composed = AnalysisError::cleanup_failure(primary, &cleanup, DEFAULT_CLEANUP_OPERATION);
    assert_eq!(
        composed.user_message(CallerLifetime::Invocation),
        "Only this request stopped."
    );
    assert_eq!(
        composed.remediation_action(CallerLifetime::Invocation),
        "Provider cleanup could not be fully confirmed. Review the reported local resources before opening another target."
    );
    assert_eq!(
        composed.cleanup_observation().unwrap().reason,
        "Provider cleanup could not be fully confirmed. Review the reported local resources before opening another target."
    );
    assert!(composed.continuing_caller_guidance().is_none());
    assert_eq!(
        composed.to_string(),
        "Provider fixture adapter failed during close_binary"
    );
    let rea_owned = AnalysisError::cleanup_failure(
        AnalysisError::cancelled("inspect"),
        &AnalysisError::output("inspect", "cleanup reply unreadable")
            .with_cleanup(CleanupObservation::new("reply lost", ["worker"])),
        "inspect",
    );
    assert!(matches!(
        rea_owned.kind(),
        AnalysisErrorKind::ProviderAdapter(adapter) if adapter.provider_id == "rea"
    ));
    assert_matches(
        &continuing(&rea_owned),
        &json!({"category": "cancelled", "details": {"operation": "inspect", "cleanup": "incomplete"}}),
    );
}
