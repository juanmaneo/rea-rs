//! The hand-written schema checker rejects contract violations, and the
//! Rust code and category enums match the contract schema exactly.

#[path = "fixtures/error_contract_checker.rs"]
mod checker;

use rea_domain::error::{AnalysisError, ErrorCategory, ErrorCode};
use serde_json::{Value, json};

fn valid() -> Value {
    checker::continuing(&AnalysisError::timeout("inspect_binary_layout", 2500))
}

use checker::{replaced as with, without};

#[test]
fn accepts_a_projected_failure() {
    assert_eq!(checker::validate(&valid()), Ok(()));
}

#[test]
fn rejects_contract_violations() {
    let violations = [
        without(valid(), "remediation"),
        without(valid(), "message"),
        with(valid(), "/code", json!("unknown_code")),
        with(valid(), "/category", json!("unknown_category")),
        with(valid(), "/message", json!("")),
        with(valid(), "/retryable", json!("false")),
        with(
            valid(),
            "/remediation",
            json!({"action": "x", "extra": true}),
        ),
        with(valid(), "/remediation/action", json!("")),
        with(valid(), "/recovery/timeout_ms", json!(0)),
        with(valid(), "/recovery/timeout_ms", json!(1.5)),
        with(
            valid(),
            "/recovery/timeout_ms",
            json!(9_007_199_254_740_992_u64),
        ),
        with(valid(), "/recovery/kind", json!("retry_everything")),
        with(
            valid(),
            "/recovery",
            json!({"kind": "inspect_input_contract", "operation": "x", "timeout_ms": 1}),
        ),
        with(valid(), "/recovery", json!({"kind": "retry_cleanup"})),
        with(valid(), "/details", json!([])),
        {
            let mut value = valid();
            value["unexpected"] = json!(true);
            value
        },
    ];
    for violation in violations {
        assert!(
            checker::validate(&violation).is_err(),
            "accepted invalid projection {violation:#}"
        );
    }
}

#[test]
fn rejects_artifact_integrity_details_outside_the_declared_shapes() {
    let base = json!({
        "code": "artifact_integrity_mismatch",
        "category": "integrity_mismatch",
        "message": "Artifact bytes contradict declared integrity.",
        "retryable": false,
        "remediation": {"action": "Get a fresh copy."},
        "details": {
            "logical_path": "a.bin",
            "algorithm": "md5",
            "declared_md5": "0".repeat(32),
            "calculated_md5": null,
            "unpacked": false
        }
    });
    assert_eq!(checker::validate(&base), Ok(()));
    for violation in [
        with(base.clone(), "/details/declared_md5", json!("0".repeat(31))),
        with(base.clone(), "/details/declared_md5", json!("G".repeat(32))),
        with(base.clone(), "/details/calculated_md5", json!(7)),
        without(base.clone(), "details"),
    ] {
        assert!(checker::validate(&violation).is_err(), "{violation:#}");
    }
}

#[test]
fn rust_codes_and_categories_match_the_contract_exactly() {
    const CODES: [ErrorCode; 20] = [
        ErrorCode::InvalidRequest,
        ErrorCode::AccessDenied,
        ErrorCode::ArtifactChanged,
        ErrorCode::UnreadableOutput,
        ErrorCode::CapabilityUnavailable,
        ErrorCode::UnsupportedTarget,
        ErrorCode::ProviderUnavailable,
        ErrorCode::ProviderTimeout,
        ErrorCode::ResourceConstraint,
        ErrorCode::Cancelled,
        ErrorCode::ArtifactIntegrityMismatch,
        ErrorCode::ArtifactOperationFailed,
        ErrorCode::EvidenceIntegrityMismatch,
        ErrorCode::Truncated,
        ErrorCode::ProcessCaptureFailed,
        ErrorCode::CleanupIncomplete,
        ErrorCode::RevisionConflict,
        ErrorCode::ConfigurationInvalid,
        ErrorCode::TargetUnavailable,
        ErrorCode::ExecutionFailure,
    ];
    const CATEGORIES: [ErrorCategory; 10] = [
        ErrorCategory::InvalidInput,
        ErrorCategory::UnsupportedProvider,
        ErrorCategory::UnsupportedTarget,
        ErrorCategory::IntegrityMismatch,
        ErrorCategory::Truncated,
        ErrorCategory::Cancelled,
        ErrorCategory::Timeout,
        ErrorCategory::ResourceConstraint,
        ErrorCategory::Unavailable,
        ErrorCategory::ExecutionFailure,
    ];
    let branches = checker::schema()["oneOf"].as_array().expect("oneOf");
    let schema_codes: Vec<&str> = branches
        .iter()
        .map(|branch| {
            branch["properties"]["code"]["const"]
                .as_str()
                .expect("code const")
        })
        .collect();
    let rust_codes: Vec<&str> = CODES.iter().map(|code| code.as_str()).collect();
    assert_eq!(schema_codes, rust_codes);
    for branch in branches {
        let categories: Vec<&str> = branch["properties"]["category"]["enum"]
            .as_array()
            .expect("category enum")
            .iter()
            .map(|category| category.as_str().expect("category"))
            .collect();
        let rust: Vec<&str> = CATEGORIES.iter().map(|c| c.as_str()).collect();
        assert_eq!(categories, rust);
    }
}
