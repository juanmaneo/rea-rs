//! Projection parity with `upstream:src/domain/analysisErrorProjection.test.ts`
//! and `upstream:src/domain/fixedAllowanceRemediation.test.ts`.
//!
//! Every projection is validated against the copied error contract schema.

#[path = "fixtures/error_contract_checker.rs"]
mod checker;

use checker::{assert_matches, continuing, invocation, object};
use rea_domain::error::ChildFailure;
use rea_domain::error::{
    AccessDeniedCode, AnalysisError, AnalysisSettingId, AnalysisSettingLimit, ArtifactDigestClaim,
    ArtifactIntegrityDetails, ArtifactOperationError, ArtifactOperationReason, CallerLifetime,
    CapabilityUnavailableError, CapturedOutput, CleanupObservation, ConfigurationError,
    ConfigurationSettingIssue, ContinuingCallerGuidance, EvidenceFileError, EvidenceFileOperation,
    EvidenceFileReason, EvidenceRetention, FixedAllowance, FixedAllowanceKind, InputError,
    InputIssue, InputIssueReason, MCP_TRANSPORT_EVIDENCE_DISCOVERY, MCP_TRANSPORT_EVIDENCE_EXPORT,
    MCP_TRANSPORT_EVIDENCE_RECORDS, ProviderAdapterError, PublishedEvidenceFile,
    ResourceConstraintError, ResourceConstraintRecovery, ResourceKind, SettingSource, TimeoutError,
    WorkflowUnknownPublication, child_failure_diagnostics, fixed_allowance_remediation,
};
use rea_domain::json::{JsonLayout, to_json_string};
use serde_json::{Map, Value, json};

fn compact(value: &Value) -> String {
    to_json_string(value, JsonLayout::Compact)
}

fn retained_output() -> CapturedOutput {
    CapturedOutput::new("selected output\u{0}", "upstream warning", true)
}

fn retained_output_json() -> Value {
    json!({"stdout": "selected output\u{0}", "stderr": "upstream warning", "truncated": true})
}

fn cleanup(reason: &str, resources: &[&str]) -> CleanupObservation {
    CleanupObservation::new(reason, resources.iter().copied())
}

fn has_word(text: &str, word: &str) -> bool {
    text.to_lowercase()
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|token| token == word)
}

fn continuing_only() -> ContinuingCallerGuidance {
    ContinuingCallerGuidance {
        user_message: Some("The fixture session remains usable.".into()),
        remediation_action: Some("Update the fixture runtime setting on this session.".into()),
    }
}

#[test]
fn projects_nested_workflow_publication_recovery_for_the_actual_caller_lifetime() {
    // Upstream uses an UnknownRegistryError child; that tag is deferred, so a
    // provider-neutral output failure carries the publication instead.
    let mut child = AnalysisError::output("trace_feature", "publication stopped");
    child.retain_workflow_unknown_publication(WorkflowUnknownPublication {
        evidence_id: format!("ev_{}", "a".repeat(64)).parse().unwrap(),
        evidence_retention: EvidenceRetention::Retained,
        total_questions: 3,
        created_questions: 1,
        existing_questions: 0,
        next_question_index: 1,
    });
    let error = AnalysisError::cancelled("trace_feature").with_child_failure_diagnostics(
        child_failure_diagnostics(
            &[(
                "child",
                ChildFailure {
                    error: &child,
                    include_captured_output: true,
                },
            )],
            Map::new(),
        ),
    );
    let child_of = |projected: &Value| {
        let child = projected["details"]["diagnostics"]["child"].clone();
        assert_eq!(checker::validate(&child), Ok(()));
        child
    };
    let continuing_child = child_of(&continuing(&error));
    assert_matches(
        &continuing_child["details"]["workflow_unknown_publication"],
        &json!({"evidence_retention": "retained", "created_questions": 1, "next_question_index": 1}),
    );
    assert!(
        continuing_child["remediation"]["action"]
            .as_str()
            .unwrap()
            .contains("get_evidence_bundle")
    );
    let invocation_child = child_of(&invocation(&error));
    assert_matches(
        &invocation_child["details"]["workflow_unknown_publication"],
        &json!({"evidence_retention": "invocation-only", "created_questions": 1, "next_question_index": 1}),
    );
    assert!(
        !invocation_child["remediation"]["action"]
            .as_str()
            .unwrap()
            .contains("get_evidence_bundle")
    );
}

#[test]
fn does_not_mark_deterministic_input_validation_as_retryable() {
    let projected = continuing(&AnalysisError::input(
        "extract_firmware",
        [InputIssue::new(
            ["range", "length"],
            InputIssueReason::MissingArgument,
        )],
    ));
    assert_eq!(
        compact(&projected),
        r#"{"code":"invalid_request","category":"invalid_input","message":"Analysis input is invalid. Check the arguments and try again.","retryable":false,"remediation":{"action":"Read the declared input schema or CLI usage for extract_firmware; if using MCP and the catalog may be stale, call tools/list. Correct the listed fields, then retry. Do not repeat the unchanged call."},"recovery":{"kind":"inspect_input_contract","operation":"extract_firmware"},"details":{"operation":"extract_firmware","issues":[{"path":["range","length"],"reason":"missing_argument"}]}}"#
    );
}

#[test]
fn keeps_retryability_for_provider_timeouts() {
    assert_matches(
        &continuing(&AnalysisError::timeout("inspect_binary_layout", 2500)),
        &json!({"code": "provider_timeout", "retryable": true}),
    );
}

#[test]
fn names_the_input_contract_for_malformed_analysis_arguments() {
    let projected = continuing(&AnalysisError::input(
        "inspect_analysis_view",
        [
            InputIssue::new(["view", "kind"], InputIssueReason::InvalidValue)
                .with_expected(json!(["summary", "module"])),
        ],
    ));
    assert_matches(
        &projected,
        &json!({
            "recovery": {"kind": "inspect_input_contract", "operation": "inspect_analysis_view"},
            "remediation": {"action": "Read the declared input schema or CLI usage for inspect_analysis_view; if using MCP and the catalog may be stale, call tools/list. Correct the listed fields, then retry. Do not repeat the unchanged call."},
            "details": {"issues": [{"path": ["view", "kind"], "reason": "invalid_value", "expected": ["summary", "module"]}]}
        }),
    );
}

#[test]
fn omits_schema_recovery_when_a_conforming_request_lacks_a_target_fact() {
    let issue = InputIssue::new(["address"], InputIssueReason::InvalidValue)
        .with_message("Address 0x2000 is in uninitialized memory block .bss")
        .with_observed(json!({"address": "0x2000", "file_mapping": "uninitialized"}));
    let error: AnalysisError = InputError::new("address_to_file_offset")
        .with_issues([issue])
        .with_user_message("No exact original-file offset exists.")
        .with_remediation_action("Select an address inside a file-backed mapping.")
        .conforming_to_input_contract()
        .into();
    let expected = json!({
        "code": "invalid_request",
        "category": "invalid_input",
        "message": "No exact original-file offset exists.",
        "retryable": false,
        "remediation": {"action": "Select an address inside a file-backed mapping."},
        "details": {
            "operation": "address_to_file_offset",
            "issues": [{
                "path": ["address"],
                "reason": "invalid_value",
                "message": "Address 0x2000 is in uninitialized memory block .bss",
                "observed": {"address": "0x2000", "file_mapping": "uninitialized"}
            }]
        }
    });
    assert_eq!(compact(&continuing(&error)), compact(&expected));
}

#[test]
fn separates_timeout_state_inspection_from_client_deadline_recovery() {
    let projected = continuing(&AnalysisError::timeout("inspect_binary_layout", 2_500));
    assert_matches(
        &projected,
        &json!({
            "code": "provider_timeout",
            "recovery": {"kind": "inspect_timeout_state", "operation": "inspect_binary_layout", "timeout_ms": 2500}
        }),
    );
    let message = projected["message"].as_str().unwrap();
    let action = projected["remediation"]["action"].as_str().unwrap();
    assert!(message.contains("server/provider deadline"));
    assert!(message.contains("not a client-side timeout"));
    assert!(action.contains("provider diagnostics"));
    for forbidden in [
        "raise its tool deadline",
        "declared timeout controls",
        "larger server/provider budget",
        "without assuming adjustable limits",
        "do not assume adjustable",
    ] {
        assert!(!action.contains(forbidden));
    }
}

#[test]
fn preserves_the_producers_capability_retry_disposition() {
    let reason = "Native self-test failed with a sharing violation";
    for (retryable, category) in [(false, "unsupported_provider"), (true, "unavailable")] {
        let error: AnalysisError = CapabilityUnavailableError {
            retryable,
            ..CapabilityUnavailableError::new("fixture-provider", "inspect", reason)
        }
        .into();
        let projected = continuing(&error);
        assert_matches(
            &projected,
            &json!({
                "code": "capability_unavailable",
                "category": category,
                "retryable": retryable,
                "details": {"reason": reason}
            }),
        );
        if retryable {
            assert_eq!(
                projected["message"],
                "Required runtime controls are unavailable for this attempt."
            );
            assert!(
                projected["remediation"]["action"]
                    .as_str()
                    .unwrap()
                    .contains("retry the same analysis")
            );
        }
    }
}

#[test]
fn preserves_a_caller_selected_message_for_a_retryable_capability_failure() {
    let error: AnalysisError = CapabilityUnavailableError {
        retryable: true,
        user_message: Some("Selected runtime diagnostic".into()),
        ..CapabilityUnavailableError::new("fixture-provider", "inspect", "temporary failure")
    }
    .into();
    assert_eq!(continuing(&error)["message"], "Selected runtime diagnostic");
}

#[test]
fn retains_cleanup_ownership_before_allowing_a_transient_operation_to_retry() {
    let error = AnalysisError::from(CapabilityUnavailableError {
        retryable: true,
        ..CapabilityUnavailableError::new("fixture-provider", "inspect", "temporary failure")
    })
    .with_cleanup(cleanup("owned handle is still live", &["native-owner"]));
    assert_matches(
        &continuing(&error),
        &json!({
            "code": "cleanup_incomplete",
            "retryable": false,
            "details": {
                "cleanup": "incomplete",
                "resources": ["native-owner"],
                "execution_failure": "capability_unavailable"
            }
        }),
    );
}

#[test]
fn projects_a_published_file_receipt_alongside_retained_cleanup_failure() {
    let error = AnalysisError::from(EvidenceFileError {
        path: Some("/tmp/evidence.json".into()),
        published: Some(PublishedEvidenceFile {
            path: Some("/tmp/evidence.json".into()),
            bytes: 42,
        }),
        ..EvidenceFileError::new(EvidenceFileOperation::Write, EvidenceFileReason::Io)
    })
    .with_cleanup(cleanup(
        "staging directory is still owned",
        &["/tmp/.rea-write-abc"],
    ));
    assert_matches(
        &continuing(&error),
        &json!({
            "code": "cleanup_incomplete",
            "message": "The output file was published, but staging cleanup remains incomplete.",
            "remediation": {"action": "Use the published file at details.published_path and resolve the reported staging cleanup failure."},
            "details": {
                "operation": "write",
                "path": "/tmp/evidence.json",
                "published": true,
                "published_path": "/tmp/evidence.json",
                "bytes": 42,
                "resources": ["/tmp/.rea-write-abc"]
            }
        }),
    );
}

#[test]
fn distinguishes_unsupported_target_formats_from_unavailable_provider_capabilities() {
    let error = AnalysisError::unsupported_target(
        "inspect_evm_interface",
        "/selected/runtime.hex",
        "EOF-style EF00 container is unsupported.",
    )
    .with_captured_output(retained_output());
    let projected = continuing(&error);
    assert_matches(
        &projected,
        &json!({
            "code": "unsupported_target",
            "category": "unsupported_target",
            "retryable": false,
            "details": {
                "operation": "inspect_evm_interface",
                "path": "/selected/runtime.hex",
                "reason": "EOF-style EF00 container is unsupported.",
                "captured_output": retained_output_json()
            }
        }),
    );
    assert!(projected["message"].as_str().unwrap().contains("EF00"));
    let action = projected["remediation"]["action"].as_str().unwrap();
    assert!(action.contains("target format"));
    assert!(!action.contains("doctor"));
}

#[test]
fn marks_occupied_capacity_retryable_only_while_cleanup_is_confirmed() {
    for cleanup_incomplete in [false, true] {
        let mut error = AnalysisError::resource_constraint(
            "inspect_sqlite_database",
            ResourceKind::Capacity,
            "Inspection slots are occupied",
            Some(object(json!({"max_concurrent_inspections": 2}))),
        );
        if cleanup_incomplete {
            error = error.with_cleanup(cleanup("Snapshot removal denied", &["/private/snapshot"]));
        }
        let projected = continuing(&error);
        assert_eq!(projected["retryable"], !cleanup_incomplete);
        assert_eq!(
            projected["code"],
            if cleanup_incomplete {
                "cleanup_incomplete"
            } else {
                "resource_constraint"
            }
        );
        assert_matches(
            &projected["details"],
            &json!({"resource": "capacity", "reported_limits": {"max_concurrent_inspections": 2}}),
        );
        assert!(
            projected["remediation"]["action"]
                .as_str()
                .unwrap()
                .contains("Wait")
        );
    }
}

#[test]
fn projects_reported_constraints_with_observed_or_unknown_limits() {
    let cases = [
        (ResourceKind::Memory, Value::Null),
        (
            ResourceKind::Memory,
            json!({"address_space_bytes": 67_108_864}),
        ),
        (ResourceKind::Cpu, Value::Null),
        (ResourceKind::Cpu, json!({"cpu_seconds": 1})),
        (ResourceKind::FileSize, Value::Null),
        (ResourceKind::FileSize, json!({"file_size_bytes": 1024})),
        (
            ResourceKind::Transport,
            json!({"result_budget_bytes": 10_485_760}),
        ),
    ];
    for (resource, limits) in cases {
        let reason = if resource == ResourceKind::Memory {
            "Memory allocation failed; exact cause unknown."
        } else {
            "Observed SIGXCPU; exact signal cause unknown."
        };
        let error = AnalysisError::resource_constraint(
            "inspect_binary_layout",
            resource,
            reason,
            limits.as_object().cloned(),
        )
        .with_captured_output(retained_output());
        assert_matches(
            &continuing(&error),
            &json!({
                "code": "resource_constraint",
                "category": "resource_constraint",
                "retryable": false,
                "message": reason,
                "details": {
                    "resource": resource.as_str(),
                    "reported_limits": limits,
                    "captured_output": retained_output_json()
                }
            }),
        );
    }
    let transport = continuing(&AnalysisError::resource_constraint(
        "get_evidence_bundle",
        ResourceKind::Transport,
        "The bundle exceeds one MCP frame.",
        None,
    ));
    assert_eq!(
        transport["remediation"]["action"],
        MCP_TRANSPORT_EVIDENCE_DISCOVERY
    );
    assert!(MCP_TRANSPORT_EVIDENCE_DISCOVERY.ends_with(MCP_TRANSPORT_EVIDENCE_EXPORT));
    assert!(MCP_TRANSPORT_EVIDENCE_RECORDS.ends_with(MCP_TRANSPORT_EVIDENCE_EXPORT));
}

#[test]
fn retains_captured_output_without_changing_the_typed_primary_failure() {
    let failures = [
        AnalysisError::from(InputError::new("inspect")),
        AnalysisError::output("inspect", "invalid reply"),
        AnalysisError::capability_unavailable("provider", "inspect", "unsupported profile"),
        AnalysisError::cancelled("inspect"),
        AnalysisError::timeout("inspect", 30),
    ];
    for failure in failures {
        let tag = failure.tag();
        let projected = continuing(&failure.with_captured_output(retained_output()));
        assert_eq!(
            projected["details"]["captured_output"],
            retained_output_json(),
            "{tag}"
        );
    }
}

#[test]
fn retains_incomplete_cleanup_for_lifecycle_failures() {
    let failures = [
        AnalysisError::cancelled("observe_native_calls").with_cleanup(cleanup(
            "target process termination could not be verified",
            &["native-target:4242"],
        )),
        AnalysisError::timeout("observe_native_calls", 65_000).with_cleanup(cleanup(
            "target process identity was unavailable",
            &["native-target:4242"],
        )),
    ];
    for failure in &failures {
        let projected = continuing(failure);
        assert_matches(
            &projected,
            &json!({
                "code": "cleanup_incomplete",
                "details": {"cleanup": "incomplete", "resources": ["native-target:4242"]}
            }),
        );
        assert!(projected["details"]["cleanup_reason"].is_string());
    }
    assert_eq!(
        compact(&continuing(&failures[1])),
        r#"{"code":"cleanup_incomplete","category":"timeout","message":"REA's observe_native_calls operation reached its 65000ms server/provider deadline. This is not a client-side timeout; extending only the MCP client's deadline does not change this budget.","retryable":false,"remediation":{"action":"Inspect any partial Evidence, provider diagnostics and reported session/provider cleanup state for observe_native_calls. Reduce the request if supported, or resolve the reported provider condition before retrying. Do not repeat the unchanged call or retry while work or cleanup may still be active."},"recovery":{"kind":"inspect_timeout_state","operation":"observe_native_calls","timeout_ms":65000},"details":{"operation":"observe_native_calls","timeout_ms":65000,"cleanup":"incomplete","cleanup_reason":"target process identity was unavailable","resources":["native-target:4242"],"execution_failure":"provider_timeout"}}"#
    );
}

#[test]
fn retains_the_original_failure_tag_and_code_when_cleanup_is_incomplete() {
    let error = AnalysisError::evidence_integrity(
        "The launched native target did not match its selected digest",
    )
    .with_cleanup(cleanup(
        "target survivor identity could not be verified",
        &["native-target:4242"],
    ));
    assert_eq!(error.tag().as_str(), "EvidenceIntegrityError");
    assert_matches(
        &continuing(&error),
        &json!({
            "code": "cleanup_incomplete",
            "category": "integrity_mismatch",
            "details": {
                "cleanup": "incomplete",
                "cleanup_reason": "target survivor identity could not be verified",
                "resources": ["native-target:4242"],
                "execution_failure": "evidence_integrity_mismatch"
            }
        }),
    );
}

fn partial_observation() -> Value {
    json!({
        "kind": "native-call-observation",
        "target": {"path": "/tmp/selected-app", "sha256": "a".repeat(64)},
        "coverage": {"status": "partial", "reason": "cancelled"},
        "limitations": ["Observation ended before the requested window completed."]
    })
}

#[test]
fn projects_partial_observations_through_healthy_cancellation_failures() {
    let error = AnalysisError::cancelled("observe_native_calls")
        .with_partial_observation(partial_observation());
    assert_matches(
        &continuing(&error),
        &json!({
            "code": "cancelled",
            "details": {
                "operation": "observe_native_calls",
                "cleanup": "complete",
                "partial_observation": partial_observation()
            }
        }),
    );
}

#[test]
fn retains_partial_observations_and_cleanup_uncertainty_on_provider_failures() {
    let error = AnalysisError::provider_adapter("native-lldb", "observe_native_calls")
        .with_partial_observation(partial_observation())
        .with_cleanup(cleanup(
            "target process termination could not be verified",
            &["native-target:4242"],
        ));
    assert_matches(
        &continuing(&error),
        &json!({
            "code": "cleanup_incomplete",
            "details": {
                "provider_id": "native-lldb",
                "operation": "observe_native_calls",
                "cleanup": "incomplete",
                "cleanup_reason": "target process termination could not be verified",
                "resources": ["native-target:4242"],
                "execution_failure": "execution_failure",
                "partial_observation": partial_observation()
            }
        }),
    );
}

#[test]
fn preserves_detached_actionable_diagnostics() {
    let diagnostics = json!({
        "runtime_root": "/tmp/rea-ghidra-fixture",
        "profile_digest": "a".repeat(64),
        "exit_code": 1
    });
    let errors = [
        (
            AnalysisError::provider_adapter("ghidra", "health"),
            json!({"provider_id": "ghidra", "operation": "health"}),
        ),
        (
            AnalysisError::cancelled("health"),
            json!({"operation": "health"}),
        ),
        (
            AnalysisError::timeout("health", 250),
            json!({"operation": "health"}),
        ),
    ];
    for (error, mut expected) in errors {
        let error = error.with_diagnostics(object(diagnostics.clone()));
        expected["diagnostics"] = diagnostics.clone();
        assert_matches(&continuing(&error)["details"], &expected);
    }
}

#[test]
fn does_not_recommend_an_unchanged_retry_for_non_retryable_failures() {
    for (error, code) in [
        (
            AnalysisError::output("inspect_firmware_regions", "report missing"),
            "unreadable_output",
        ),
        (
            AnalysisError::provider_adapter("firmware", "inspect_firmware_regions"),
            "execution_failure",
        ),
    ] {
        let projected = continuing(&error);
        assert_matches(&projected, &json!({"code": code, "retryable": false}));
        for text in [&projected["message"], &projected["remediation"]["action"]] {
            assert!(!has_word(text.as_str().unwrap(), "retry"), "{text}");
        }
    }
}

#[test]
fn preserves_the_reported_output_constraint() {
    let error = AnalysisError::output(
        "extract_firmware",
        "Report exceeded the declared byte budget",
    );
    assert_matches(
        &continuing(&error),
        &json!({
            "code": "unreadable_output",
            "details": {"operation": "extract_firmware", "reason": "Report exceeded the declared byte budget"}
        }),
    );
    assert_eq!(
        error.to_string(),
        "Invalid analysis output for extract_firmware: Report exceeded the declared byte budget"
    );
}

#[test]
fn maps_representative_failures() {
    let input = continuing(&AnalysisError::from(InputError::new("overview")));
    assert_eq!(input["code"], "invalid_request");
    assert!(input.get("details").is_none());
    let capability = continuing(&AnalysisError::capability_unavailable(
        "fixture", "overview", "absent",
    ));
    assert_matches(
        &capability,
        &json!({
            "code": "capability_unavailable",
            "category": "unsupported_provider",
            "message": "This analysis is unavailable for the current target. Choose another analysis or target.",
            "details": {"provider_id": "fixture", "operation": "overview", "reason": "absent"}
        }),
    );
}

#[test]
fn reports_a_target_the_host_refused_to_read_as_access_denied() {
    // Upstream exercises BinaryTargetError (deferred); AnalysisAccessDeniedError
    // shares the code, category, remediation, and boundary.
    for code in [AccessDeniedCode::Eacces, AccessDeniedCode::Eperm] {
        let error = AnalysisError::access_denied("inspect_elf_notes", "/local/targets/app", code);
        assert_matches(
            &continuing(&error),
            &json!({
                "code": "access_denied",
                "category": "unavailable",
                "retryable": false,
                "message": "Host filesystem permissions denied read access to the selected path.",
                "remediation": {"action": "Check the current process's read access to the selected path. Retry with a readable local file."},
                "details": {
                    "operation": "inspect_elf_notes",
                    "path": "/local/targets/app",
                    "system_code": code.as_str(),
                    "boundary": "filesystem-read"
                }
            }),
        );
    }
    assert_eq!(
        AccessDeniedCode::from_raw_os_error(13),
        Some(AccessDeniedCode::Eacces)
    );
    assert_eq!(
        AccessDeniedCode::from_raw_os_error(1),
        Some(AccessDeniedCode::Eperm)
    );
    assert_eq!(AccessDeniedCode::from_raw_os_error(2), None);
}

#[test]
fn reports_an_artifact_change_as_retryable() {
    assert_matches(
        &continuing(&AnalysisError::artifact_changed(
            "inspect_elf_notes",
            "/selected/app",
            "size changed from 10 to 12 bytes",
        )),
        &json!({
            "code": "artifact_changed",
            "category": "integrity_mismatch",
            "retryable": true,
            "message": "The selected artifact changed during acquisition; no stable snapshot was decoded.",
            "details": {
                "operation": "inspect_elf_notes",
                "path": "/selected/app",
                "reason": "size changed from 10 to 12 bytes",
                "boundary": "stable-artifact-read"
            }
        }),
    );
}

#[test]
fn uses_explicit_capability_message_while_retaining_the_constraint() {
    let error: AnalysisError = CapabilityUnavailableError {
        user_message: Some("Use the supported host workflow.".into()),
        ..CapabilityUnavailableError::new("fixture", "capture", "host constraint")
    }
    .into();
    assert_matches(
        &continuing(&error),
        &json!({
            "code": "capability_unavailable",
            "category": "unsupported_provider",
            "message": "Use the supported host workflow.",
            "details": {"provider_id": "fixture", "operation": "capture", "reason": "host constraint"}
        }),
    );
}

#[test]
fn preserves_exact_artifact_integrity_coordinates() {
    let error: AnalysisError = ArtifactOperationError {
        integrity: Some(ArtifactIntegrityDetails {
            logical_path: "main.js".into(),
            unpacked: true,
            digest: ArtifactDigestClaim::Sha256 {
                declared: Some("a".repeat(64)),
                calculated: Some("b".repeat(64)),
            },
        }),
        ..ArtifactOperationError::new(
            "inventory_artifact",
            ArtifactOperationReason::Integrity,
            None,
        )
    }
    .into();
    let projected = continuing(&error);
    assert_eq!(projected["code"], "artifact_integrity_mismatch");
    assert_eq!(projected["category"], "integrity_mismatch");
    assert_eq!(
        compact(&projected["details"]),
        compact(&json!({
            "logical_path": "main.js",
            "declared_sha256": "a".repeat(64),
            "calculated_sha256": "b".repeat(64),
            "unpacked": true
        }))
    );
    assert_eq!(
        projected["message"],
        "Declared ASAR integrity for unpacked entry main.js contradicts its companion file; packaging tools commonly sign or strip unpacked native binaries after writing the archive. If expected, rerun inspect_artifact with integrity_policy=record-and-continue (CLI: --integrity-policy record-and-continue) to retain observed bytes as untrusted; otherwise get a fresh copy."
    );
    assert_eq!(
        error.to_string(),
        format!(
            "Artifact inventory_artifact failed: integrity at main.js (declared_sha256={}, calculated_sha256={}, unpacked=true)",
            "a".repeat(64),
            "b".repeat(64)
        )
    );
}

#[test]
fn classifies_evidence_files_by_who_can_correct_them() {
    let cases = [
        (
            EvidenceFileOperation::Read,
            EvidenceFileReason::Missing,
            "invalid_request",
            "invalid_input",
        ),
        (
            EvidenceFileOperation::Read,
            EvidenceFileReason::NotFile,
            "invalid_request",
            "invalid_input",
        ),
        (
            EvidenceFileOperation::Write,
            EvidenceFileReason::Missing,
            "invalid_request",
            "invalid_input",
        ),
        (
            EvidenceFileOperation::Write,
            EvidenceFileReason::Exists,
            "invalid_request",
            "invalid_input",
        ),
        (
            EvidenceFileOperation::Write,
            EvidenceFileReason::PathLimit,
            "resource_constraint",
            "resource_constraint",
        ),
        (
            EvidenceFileOperation::Read,
            EvidenceFileReason::InvalidJson,
            "evidence_integrity_mismatch",
            "execution_failure",
        ),
        (
            EvidenceFileOperation::Read,
            EvidenceFileReason::Io,
            "execution_failure",
            "execution_failure",
        ),
    ];
    for (operation, reason, code, category) in cases {
        let error: AnalysisError = EvidenceFileError {
            path: Some("/selected.json".into()),
            ..EvidenceFileError::new(operation, reason)
        }
        .into();
        assert_matches(
            &continuing(&error),
            &json!({
                "code": code,
                "category": category,
                "details": {"operation": operation.as_str(), "reason": reason.as_str(), "path": "/selected.json"}
            }),
        );
    }
}

#[test]
fn retains_the_primary_failure_and_both_cleanup_reports_after_a_secondary_failure() {
    let mut primary = AnalysisError::cancelled("execute_rizin_command")
        .with_captured_output(CapturedOutput::new("partial", "diagnostic", false))
        .with_cleanup(cleanup("writer remains", &["writer"]));
    let secondary = AnalysisError::output("open_binary", "cannot rebind")
        .with_cleanup(cleanup("provider remains", &["provider", "writer"]));
    let mut diagnostics = Map::new();
    diagnostics.insert("rebind_error".into(), continuing(&secondary));
    primary.retain_secondary_failure(secondary, Some(diagnostics));
    assert_eq!(primary.tag().as_str(), "AnalysisCancelledError");
    assert_eq!(primary.secondary_failures().len(), 1);
    assert_matches(
        &continuing(&primary),
        &json!({
            "code": "cleanup_incomplete",
            "details": {
                "execution_failure": "cancelled",
                "resources": ["writer"],
                "cleanup_reason": "writer remains",
                "captured_output": {"stdout": "partial", "stderr": "diagnostic"},
                "diagnostics": {"rebind_error": {"code": "cleanup_incomplete"}}
            }
        }),
    );
}

#[test]
fn retains_a_later_cancellation_once_beside_the_established_failure() {
    let failure = AnalysisError::output("inspect", "invalid reply");
    let once = AnalysisError::with_cancellation(Some(failure), AnalysisError::cancelled("inspect"));
    let twice = AnalysisError::with_cancellation(Some(once), AnalysisError::cancelled("inspect"));
    assert_eq!(twice.tag().as_str(), "AnalysisOutputError");
    assert_eq!(twice.secondary_failures().len(), 1);
    let cancelled = AnalysisError::with_cancellation(
        Some(AnalysisError::cancelled("inspect")),
        AnalysisError::cancelled("inspect"),
    );
    assert!(cancelled.secondary_failures().is_empty());
    assert_eq!(
        AnalysisError::with_cancellation(None, AnalysisError::cancelled("inspect"))
            .tag()
            .as_str(),
        "AnalysisCancelledError"
    );
}

#[test]
fn preserves_producer_capability_recovery() {
    let recovery = "Choose an explicit disposition, then retry the same session.";
    for retryable in [false, true] {
        let error: AnalysisError = CapabilityUnavailableError {
            retryable,
            remediation_action: Some(recovery.into()),
            ..CapabilityUnavailableError::new("fixture", "close", "live state")
        }
        .into();
        assert_matches(
            &continuing(&error),
            &json!({
                "code": "capability_unavailable",
                "retryable": retryable,
                "remediation": {"action": recovery},
                "details": {"provider_id": "fixture", "operation": "close", "reason": "live state"}
            }),
        );
    }
}

#[test]
fn does_not_offer_entry_policy_retries_without_an_entry_contradiction() {
    let native = continuing(&AnalysisError::artifact_operation(
        "inspect_artifact",
        ArtifactOperationReason::Integrity,
        Some("hdiutil verify failed: invalid checksum".into()),
    ));
    assert_eq!(native["code"], "artifact_operation_failed");
    assert_eq!(native["category"], "integrity_mismatch");
    assert_matches(
        &native["details"],
        &json!({"reason": "integrity", "detail": "hdiutil verify failed: invalid checksum"}),
    );
    for text in [&native["message"], &native["remediation"]["action"]] {
        assert!(!text.as_str().unwrap().contains("record-and-continue"));
    }
}

#[test]
fn projects_artifact_limits_with_their_boundary() {
    let error: AnalysisError = ArtifactOperationError::new(
        "inspect_elf_notes",
        ArtifactOperationReason::Limit,
        Some("The note table exceeds 4096 entries.".into()),
    )
    .with_boundary(rea_domain::error::ArtifactLimitBoundary::Capacity)
    .into();
    assert_eq!(
        compact(&continuing(&error)),
        compact(&json!({
            "code": "truncated",
            "category": "truncated",
            "message": "The note table exceeds 4096 entries.",
            "retryable": false,
            "remediation": {"action": "Use an artifact within the capacity reported in details.detail. Changing output detail or retrying the unchanged input does not remove this boundary."},
            "details": {
                "operation": "inspect_elf_notes",
                "reason": "limit",
                "truncated": true,
                "detail": "The note table exceeds 4096 entries.",
                "boundary": "capacity"
            }
        }))
    );
    let format = continuing(&AnalysisError::artifact_operation(
        "inspect_elf_notes",
        ArtifactOperationReason::Format,
        Some("note 3 descriptor overruns the section".into()),
    ));
    assert_eq!(
        format["message"],
        "Artifact is invalid or has changed. Get a fresh copy and try again."
    );
    assert_eq!(format["remediation"]["action"], format["message"]);
}

#[test]
fn preserves_ordinary_configuration_recovery_and_a_producer_owned_session_repair() {
    let settings = || {
        vec![ConfigurationSettingIssue {
            setting: "REA_EXAMPLE".into(),
            constraint: "must be positive".into(),
        }]
    };
    let original = continuing(&AnalysisError::configuration("Invalid setting", settings()));
    let repairing = continuing(&AnalysisError::from(ConfigurationError {
        message: "Invalid setting".into(),
        settings: settings(),
        remediation_action: Some("Repair the running session, then retry.".into()),
    }));
    assert_eq!(
        original["remediation"]["action"],
        "Correct REA_EXAMPLE in the environment that starts REA (your shell or the MCP client's registration), then rerun."
    );
    assert_eq!(
        original["message"],
        "REA configuration is invalid: REA_EXAMPLE: must be positive."
    );
    let mut expected = original.clone();
    expected["remediation"] = json!({"action": "Repair the running session, then retry."});
    assert_eq!(repairing, expected);
    assert_eq!(repairing["code"], "configuration_invalid");
}

#[test]
fn states_continuing_session_guidance_only_to_a_continuing_caller() {
    let errors = [
        AnalysisError::from(TimeoutError {
            user_message: Some("Only this request stopped.".into()),
            remediation_action: Some("Rerun with a longer launch deadline.".into()),
            ..TimeoutError::new("procedure_pseudo_code", 5000)
        }),
        AnalysisError::from(ProviderAdapterError {
            user_message: Some("Only this request stopped.".into()),
            ..ProviderAdapterError::new("fixture", "procedure_pseudo_code")
                .with_remediation_action("Rerun with a longer launch deadline.")
        }),
        AnalysisError::from(
            ResourceConstraintError::new(
                "search_strings",
                ResourceKind::Cpu,
                "Only this request stopped.",
                None,
            )
            .with_recovery(ResourceConstraintRecovery::remediation(
                "Rerun with a longer launch deadline.",
            )),
        ),
    ];
    for error in errors {
        let error = error.with_continuing_caller_guidance(continuing_only());
        let continuing_projection = continuing(&error);
        assert_matches(
            &continuing_projection,
            &json!({
                "message": "Only this request stopped. The fixture session remains usable.",
                "remediation": {"action": "Update the fixture runtime setting on this session."}
            }),
        );
        assert_matches(
            &invocation(&error),
            &json!({
                "code": continuing_projection["code"],
                "message": "Only this request stopped.",
                "remediation": {"action": "Rerun with a longer launch deadline."}
            }),
        );
        assert_eq!(
            error.user_message(CallerLifetime::Invocation),
            "Only this request stopped."
        );
        assert_eq!(
            error.remediation_action(CallerLifetime::Invocation),
            "Rerun with a longer launch deadline."
        );
    }
}

#[test]
fn re_scopes_a_limit_for_a_finished_invocation_and_keeps_its_enforced_facts() {
    let limit = AnalysisSettingLimit::new(
        AnalysisSettingId::RegexMatchingDeadlineMs,
        Some(250),
        Some(SettingSource::Setting),
    );
    let error = AnalysisError::resource_constraint(
        "search_strings",
        ResourceKind::Cpu,
        "Regex matching exceeded its deadline.",
        None,
    )
    .with_limit(limit.clone());
    assert_eq!(
        compact(&continuing(&error)["details"]["limit"]),
        r#"{"setting":"regex.matching_deadline_ms","effective_value":250,"source":"setting","unit":"ms","minimum":1,"maximum":2147483647,"applies_at":"next_operation","agent_editable":true,"scope":"rea-runtime","rea_restart_required":false}"#
    );
    assert_eq!(
        compact(&invocation(&error)["details"]["limit"]),
        r#"{"setting":"regex.matching_deadline_ms","effective_value":250,"source":"setting","unit":"ms","minimum":1,"maximum":2147483647,"agent_editable":true,"rea_restart_required":false,"applies_at":"next_invocation","scope":"rea-invocation","environment":"REA_REGEX_MATCHING_DEADLINE_MS"}"#
    );
    assert_eq!(error.limit(), Some(&limit));
}

#[test]
fn names_a_per_call_parameter_not_an_environment_when_a_setting_has_no_launch_seed() {
    let error =
        AnalysisError::timeout("inspect_wasm_artifact", 100).with_limit(AnalysisSettingLimit::new(
            AnalysisSettingId::WasmCommandTimeoutMs,
            Some(100),
            Some(SettingSource::Request),
        ));
    let limit = &invocation(&error)["details"]["limit"];
    assert_matches(
        limit,
        &json!({
            "setting": "wasm.command_timeout_ms",
            "source": "request",
            "parameter": "command_timeout_ms",
            "applies_at": "next_invocation",
            "scope": "rea-invocation"
        }),
    );
    assert!(limit.get("environment").is_none());
}

#[test]
fn projects_a_composed_cleanup_failures_children_for_the_caller_and_keeps_their_history() {
    let primary = AnalysisError::from(TimeoutError {
        user_message: Some("Only this request stopped.".into()),
        remediation_action: Some("Rerun with a longer launch deadline.".into()),
        ..TimeoutError::new("search_strings", 250)
    })
    .with_limit(AnalysisSettingLimit::new(
        AnalysisSettingId::RegexMatchingDeadlineMs,
        Some(250),
        Some(SettingSource::Setting),
    ))
    .with_continuing_caller_guidance(continuing_only());
    let cleanup = AnalysisError::provider_cleanup(
        ProviderAdapterError::new("fixture", "close_binary")
            .with_remediation_action("Close the retained fixture process."),
        ["fixture-process"],
        object(json!({"reason": "exit unconfirmed"})),
    );
    let handle = cleanup.cleanup_handle().unwrap();
    let composed =
        AnalysisError::dependent_cleanup_failure(primary.clone(), cleanup, "close_binary");
    let details = |lifetime| checker::project(&composed, lifetime)["details"].clone();

    let invocation_details = details(CallerLifetime::Invocation);
    assert_matches(
        &invocation_details,
        &json!({
            "limit": {"scope": "rea-invocation"},
            "diagnostics": {"cleanup_error": {"code": "cleanup_incomplete"}}
        }),
    );
    assert_eq!(
        invocation_details["diagnostics"]["primary_error"],
        invocation(&primary)
    );
    let continuing_details = details(CallerLifetime::Continuing);
    assert_matches(
        &continuing_details,
        &json!({"limit": {"scope": "rea-runtime"}}),
    );
    assert_eq!(
        continuing_details["diagnostics"]["primary_error"],
        continuing(&primary)
    );
    assert_eq!(
        invocation(&composed)["message"],
        "Only this request stopped."
    );
    assert_eq!(
        continuing(&composed)["message"],
        "Only this request stopped. The fixture session remains usable."
    );

    handle.resolve();
    for lifetime in [CallerLifetime::Continuing, CallerLifetime::Invocation] {
        let history = details(lifetime)["cleanup_history"].clone();
        assert_eq!(
            history["primary_error"],
            checker::project(&primary, lifetime)
        );
        assert_eq!(history["cleanup_error"]["code"], "cleanup_incomplete");
    }
}

#[test]
fn records_one_lifetime_form_when_no_child_depends_on_the_caller() {
    let cleanup = AnalysisError::provider_cleanup(
        ProviderAdapterError::new("fixture", "close_binary"),
        ["fixture-process"],
        Map::new(),
    );
    let composed = AnalysisError::cleanup_failure(
        AnalysisError::input(
            "read_bytes",
            [InputIssue::new(
                ["address"],
                InputIssueReason::InvalidFormat,
            )],
        ),
        &cleanup,
        "close_binary",
    );
    assert!(
        std::ptr::eq(
            composed
                .diagnostics_for(CallerLifetime::Invocation)
                .unwrap(),
            composed
                .diagnostics_for(CallerLifetime::Continuing)
                .unwrap()
        ),
        "no separate invocation diagnostics are recorded"
    );
    assert_eq!(
        invocation(&composed)["details"],
        continuing(&composed)["details"]
    );
}

#[test]
fn keeps_a_fixed_allowance_and_a_remediation_action_from_co_occurring() {
    let allowance = ResourceConstraintRecovery::fixed(FixedAllowance::new(
        "parser_allowance",
        FixedAllowanceKind::Parser,
    ));
    assert_eq!(allowance.retryable(), Some(false));
    assert_eq!(allowance.remediation_action(), None);
    assert_eq!(
        allowance.fixed_allowance(),
        Some(&FixedAllowance::new(
            "parser_allowance",
            FixedAllowanceKind::Parser
        ))
    );
    let guided = ResourceConstraintRecovery::Remediation {
        action: Some("wait_for_slot".into()),
        retryable: Some(true),
    };
    assert_eq!(guided.fixed_allowance(), None);
    assert_eq!(guided.remediation_action(), Some("wait_for_slot"));
    assert_eq!(guided.retryable(), Some(true));
}

#[test]
fn projects_fixed_allowances_without_the_generic_resource_fallback() {
    let cases: [(FixedAllowanceKind, ResourceKind, &[&str]); 8] = [
        (
            FixedAllowanceKind::Parser,
            ResourceKind::Memory,
            &[
                "available host memory. Retry",
                "worker memory limits and available",
            ],
        ),
        (
            FixedAllowanceKind::Count,
            ResourceKind::Capacity,
            &["Wait for an active analysis", "fixed byte allowance"],
        ),
        (
            FixedAllowanceKind::Bytes,
            ResourceKind::Capacity,
            &["Wait for an active analysis", "fixed count"],
        ),
        (
            FixedAllowanceKind::Report,
            ResourceKind::Transport,
            &["get_evidence_bundle", "complete CLI JSON output"],
        ),
        (
            FixedAllowanceKind::Input,
            ResourceKind::FileSize,
            &["evidence reply", "file-size allowance for the evidence"],
        ),
        (
            FixedAllowanceKind::Capture,
            ResourceKind::Memory,
            &["available host memory. Retry", "live output may change"],
        ),
        (
            FixedAllowanceKind::Live,
            ResourceKind::Memory,
            &["available host memory. Retry", "unchanged request"],
        ),
        (
            FixedAllowanceKind::Work,
            ResourceKind::Cpu,
            &["worker CPU limits and observed signal"],
        ),
    ];
    for (kind, resource, forbidden) in cases {
        let allowance = format!("The {} allowance", kind.as_str());
        let error: AnalysisError = ResourceConstraintError::new(
            "inspect_fixture",
            resource,
            "allowance exceeded",
            Some(object(json!({"maximum": 1}))),
        )
        .with_recovery(ResourceConstraintRecovery::fixed(FixedAllowance::new(
            allowance.clone(),
            kind,
        )))
        .into();
        let projected = continuing(&error);
        assert_eq!(projected["retryable"], false, "{kind:?}");
        let action = projected["remediation"]["action"].as_str().unwrap();
        assert_eq!(action, fixed_allowance_remediation(&allowance, kind));
        assert!(action.contains(&allowance));
        for pattern in forbidden {
            assert!(!action.contains(pattern), "{kind:?}: {pattern}");
        }
        if matches!(kind, FixedAllowanceKind::Count | FixedAllowanceKind::Bytes) {
            assert!(!has_word(action, "retry"), "{kind:?}");
        }
        if kind == FixedAllowanceKind::Live {
            assert!(action.contains("live output may change between requests"));
        }
        if kind == FixedAllowanceKind::Capture {
            assert!(action.contains("Repeating the unchanged request fails the same way."));
        }
    }
}

#[test]
fn projects_a_non_retryable_resource_refusal_with_a_fixed_allowance_byte_for_byte() {
    let refusal: AnalysisError = ResourceConstraintError::new(
        "inspect_elf_notes",
        ResourceKind::Memory,
        "The note section exceeds the parser allowance.",
        Some(object(json!({"maximum_note_bytes": 4096}))),
    )
    .with_recovery(ResourceConstraintRecovery::fixed(FixedAllowance::new(
        "The ELF note parser allowance",
        FixedAllowanceKind::Parser,
    )))
    .into();
    assert_eq!(
        compact(&invocation(&refusal)),
        r#"{"code":"resource_constraint","category":"resource_constraint","message":"The note section exceeds the parser allowance.","retryable":false,"remediation":{"action":"The ELF note parser allowance is a fixed allowance. Worker memory limits, inherited limits, and additional host memory do not raise it. Select another complete input within the allowance when that preserves the needed observation. Repeating the unchanged request fails the same way."},"details":{"operation":"inspect_elf_notes","resource":"memory","reason":"The note section exceeds the parser allowance.","reported_limits":{"maximum_note_bytes":4096}}}"#
    );
    let producer_input = FixedAllowance::producer_input(1024, "The ELF input allowance");
    assert_eq!(
        producer_input.remediation(),
        "Select a suitable complete artifact within The ELF input allowance of 1024 bytes (this release has no runtime override). Increasing an evidence-reply file-size allowance does not admit this input. Do not truncate required bytes. Repeating the unchanged request fails the same way."
    );
    let overridden = continuing(&AnalysisError::from(
        ResourceConstraintError::new("inspect_fixture", ResourceKind::Capacity, "full", None)
            .with_recovery(ResourceConstraintRecovery::non_retryable(
                "Select fewer notes.",
            )),
    ));
    assert_matches(
        &overridden,
        &json!({"retryable": false, "remediation": {"action": "Select fewer notes."}, "details": {"reported_limits": null}}),
    );
}
