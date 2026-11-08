//! `inspect_kernel_module` through the shared service.
//!
//! Fake-provider cases are ported from
//! `upstream:src/application/binaryDiagnostics/KernelModuleService.test.ts`;
//! real-provider cases from `upstream:tests/boundary/filesystem/kernelModule.test.ts`.
//! Fixtures are shared with the parser tests in `rea-native`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

#[path = "../../rea-native/tests/kernel_module/fixture.rs"]
mod fixture;

use std::cell::Cell;
use std::fs;
use std::path::Path;

use fixture::{KernelModuleOptions, compressed_kernel_module_container, kernel_module_fixture};
use rea_application::binary_diagnostics::kernel_module::{KernelModulePort, KernelModuleService};
use rea_domain::cancellation::CancellationSignal;
use rea_domain::error::{AnalysisError, AnalysisErrorKind, CallerLifetime};
use rea_domain::evidence::Evidence;
use rea_domain::native::kernel_module::{
    InspectKernelModuleInput, KernelModule, KernelModuleCodec,
};
use rea_domain::providers::{KERNEL_MODULE_PROVIDER, ProviderIdentity};
use rea_native::elf::KernelModuleProvider;
use serde_json::{Value, json};

const PATH: &str = "/artifacts/demo.ko";

fn report_value() -> Value {
    let digest = "a".repeat(64);
    json!({
        "artifact": { "path": PATH, "sha256": digest, "bytes": 512 },
        "format": "elf64",
        "byte_order": "little",
        "machine": 62,
        "type": 1,
        "type_name": "relocatable",
        "applicability": "applicable",
        "compression": null,
        "next_probe": null,
        "modinfo": {
            "status": "present",
            "location": { "offset": 64, "bytes": 0 },
            "sha256": digest,
            "entries": [],
            "reason": null
        },
        "versions": {
            "status": "absent",
            "layout": "elf64_unsigned_long_name56",
            "entry_bytes": 64,
            "location": null,
            "sha256": null,
            "entries": [],
            "reason": null
        },
        "this_module": { "status": "absent", "location": null, "layout": "unknown" },
        "ksymtab": { "status": "observed", "sections": [] },
        "init_text": { "status": "absent", "location": null, "bytes": null, "compressed": null },
        "exit_text": { "status": "absent", "location": null, "bytes": null, "compressed": null },
        "signature": {
            "status": "absent",
            "magic": null,
            "info": null,
            "pkcs7": null,
            "reason": null
        },
        "coverage": { "status": "complete", "examined_entries": 0 },
        "limitations": ["Kernel module metadata was not executed."]
    })
}

fn report_with(changes: impl FnOnce(&mut Value)) -> KernelModule {
    let mut value = report_value();
    changes(&mut value);
    serde_json::from_value(value).unwrap()
}

/// Returns `report` and optionally cancels the caller's signal while
/// completing.
struct FakeProvider {
    report: KernelModule,
    calls: Cell<usize>,
    cancel_while_completing: bool,
}

impl FakeProvider {
    fn new(report: KernelModule) -> Self {
        Self {
            report,
            calls: Cell::new(0),
            cancel_while_completing: false,
        }
    }
}

impl KernelModulePort for &FakeProvider {
    fn identity(&self) -> ProviderIdentity {
        KERNEL_MODULE_PROVIDER
    }

    fn inspect(
        &self,
        _input: &InspectKernelModuleInput,
        signal: &CancellationSignal,
    ) -> Result<KernelModule, AnalysisError> {
        self.calls.set(self.calls.get() + 1);
        if self.cancel_while_completing {
            signal.cancel();
        }
        Ok(self.report.clone())
    }
}

fn fake_run(provider: &FakeProvider, arguments: &Value) -> Result<Evidence, AnalysisError> {
    KernelModuleService::new(provider).inspect(Some(arguments), &CancellationSignal::new())
}

fn run(arguments: &Value) -> Result<Evidence, AnalysisError> {
    run_with(arguments, &CancellationSignal::new())
}

fn run_with(arguments: &Value, signal: &CancellationSignal) -> Result<Evidence, AnalysisError> {
    KernelModuleService::new(KernelModuleProvider).inspect(Some(arguments), signal)
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> String {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    path.to_str().unwrap().to_owned()
}

fn projected(error: &AnalysisError) -> Value {
    error.project(CallerLifetime::Invocation).to_value()
}

#[test]
fn rejects_a_relative_path_and_extra_arguments_before_reading() {
    let provider = FakeProvider::new(report_with(|_| {}));
    let relative = fake_run(&provider, &json!({ "path": "demo.ko" })).unwrap_err();
    let extra = fake_run(&provider, &json!({ "path": PATH, "extra": true })).unwrap_err();
    assert!(matches!(relative.kind(), AnalysisErrorKind::Input(_)));
    assert!(matches!(extra.kind(), AnalysisErrorKind::Input(_)));
    assert_eq!(provider.calls.get(), 0);
}

#[test]
fn records_an_applicable_module_and_its_x86_64_architecture() {
    let report = report_with(|_| {});
    let provider = FakeProvider::new(report.clone());
    let evidence = fake_run(&provider, &json!({ "path": PATH })).unwrap();
    let value = serde_json::to_value(&evidence).unwrap();
    assert_eq!(value["confidence"], "observed");
    assert_eq!(value["subject"]["format"], "elf");
    assert_eq!(value["subject"]["architecture"], "x86_64");
    assert_eq!(
        value["normalized_result"],
        serde_json::to_value(&report).unwrap()
    );
}

#[test]
fn rejects_a_report_whose_entry_count_does_not_match_the_examined_sections() {
    let provider = FakeProvider::new(report_with(|report| {
        report["coverage"]["examined_entries"] = 1.into();
    }));
    let error = fake_run(&provider, &json!({ "path": PATH })).unwrap_err();
    assert!(matches!(error.kind(), AnalysisErrorKind::Output(_)));
}

#[test]
fn rejects_a_ksymtab_listing_whose_name_disagrees_with_its_reason() {
    for (name, reason) in [
        (json!("__ksymtab"), json!("ksymtab_name_exceeds_limit")),
        (Value::Null, Value::Null),
    ] {
        let provider = FakeProvider::new(report_with(|report| {
            report["ksymtab"] = json!({
                "status": "observed",
                "sections": [{
                    "name": name,
                    "location": { "offset": 64, "bytes": 0 },
                    "compressed": false,
                    "reason": reason
                }]
            });
            report["coverage"]["examined_entries"] = 1.into();
        }));
        let error = fake_run(&provider, &json!({ "path": PATH })).unwrap_err();
        assert!(
            matches!(error.kind(), AnalysisErrorKind::Output(_)),
            "{error:?}"
        );
    }
}

#[test]
fn retains_a_completed_observation_if_the_caller_cancels_while_the_provider_completes() {
    let report = report_with(|_| {});
    let mut provider = FakeProvider::new(report.clone());
    provider.cancel_while_completing = true;
    let error = fake_run(&provider, &json!({ "path": PATH })).unwrap_err();
    assert!(matches!(error.kind(), AnalysisErrorKind::Cancelled(_)));
    let observation = error.partial_observation().unwrap().clone();
    let evidence: Evidence = serde_json::from_value(observation.clone()).unwrap();
    evidence.verify().unwrap();
    assert_eq!(observation["operation"], "inspect_kernel_module");
    assert_eq!(observation["confidence"], "observed");
    assert_eq!(observation["subject"]["format"], "elf");
    assert_eq!(observation["subject"]["architecture"], "x86_64");
    assert_eq!(
        observation["normalized_result"],
        serde_json::to_value(&report).unwrap()
    );
}

#[test]
fn reports_non_file_and_malformed_elf_selections_as_caller_input_errors() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let path = write(
        root,
        "demo.ko",
        &kernel_module_fixture(&KernelModuleOptions::default()),
    );
    let malformed = write(root, "malformed", b"not an elf");
    let mut candidates = vec![
        (root.to_str().unwrap().to_owned(), "invalid_format"),
        (malformed, "invalid_format"),
        (
            root.join("missing").to_str().unwrap().to_owned(),
            "invalid_value",
        ),
        (format!("{path}/child"), "invalid_value"),
    ];
    #[cfg(unix)]
    {
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        candidates.push((alias.to_str().unwrap().to_owned(), "invalid_format"));
    }
    for (candidate, reason) in candidates {
        let error = run(&json!({ "path": candidate })).unwrap_err();
        assert!(
            matches!(error.kind(), AnalysisErrorKind::Input(_)),
            "{candidate}: {error:?}"
        );
        let projected = projected(&error);
        assert_eq!(projected["details"]["operation"], "inspect_kernel_module");
        let issues = projected["details"]["issues"].as_array().unwrap();
        assert_eq!(issues.len(), 1, "{candidate}: {projected}");
        assert_eq!(issues[0]["path"], json!(["path"]));
        assert_eq!(issues[0]["reason"], reason, "{candidate}: {projected}");
        assert!(issues[0]["message"].is_string(), "{candidate}: {projected}");
    }
}

#[test]
fn returns_typed_resource_and_cancellation_failures() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        dir.path(),
        "demo.ko",
        &kernel_module_fixture(&KernelModuleOptions::default()),
    );
    let too_small = run(&json!({ "path": path, "max_file_bytes": 64 })).unwrap_err();
    assert!(matches!(
        too_small.kind(),
        AnalysisErrorKind::ResourceConstraint(_)
    ));
    let too_many = run(&json!({ "path": path, "max_entries": 1 })).unwrap_err();
    assert!(matches!(
        too_many.kind(),
        AnalysisErrorKind::ResourceConstraint(_)
    ));
    let signal = CancellationSignal::new();
    signal.cancel();
    let cancelled = run_with(&json!({ "path": path }), &signal).unwrap_err();
    assert!(matches!(cancelled.kind(), AnalysisErrorKind::Cancelled(_)));
}

#[test]
fn reports_a_gzip_container_as_unsupported_without_treating_it_as_a_module() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        dir.path(),
        "demo.ko.gz",
        &compressed_kernel_module_container(KernelModuleCodec::Gzip),
    );
    let evidence = run(&json!({ "path": path })).unwrap();
    let value = serde_json::to_value(&evidence).unwrap();
    assert_eq!(value["subject"]["format"], "file");
    let result = &value["normalized_result"];
    assert_eq!(result["applicability"], "unsupported");
    assert_eq!(
        result["compression"],
        json!({ "codec": "gzip", "status": "unsupported" })
    );
    assert_eq!(result["next_probe"]["operation"], "external_decompression");
    assert_eq!(result["modinfo"], Value::Null);
}
