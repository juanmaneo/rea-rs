//! `inspect_elf_notes` through the shared service and the real provider.
//!
//! Failure cases are ported from `upstream:src/native/elf/ElfNotesProvider.test.ts`;
//! input and Evidence cases from `upstream:tests/acceptance/elfNotes*.test.ts`.
//! Fixtures are shared with the parser tests in `rea-native`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

#[path = "../../rea-native/tests/elf_notes/fixture.rs"]
mod fixture;

use std::fs;
use std::path::Path;

use fixture::{
    Bits, ImageOptions, Ownership, compressed_elf_note_fixture, elf_extended_section_count_fixture,
    elf_note, elf_note_fixture, elf_note_table_past_end, get16, get64le,
};
use rea_application::binary_diagnostics::elf_notes::ElfNotesService;
use rea_domain::cancellation::CancellationSignal;
use rea_domain::error::CallerLifetime;
use rea_domain::evidence::Evidence;
use rea_native::elf::ElfNotesProvider;
use serde_json::{Value, json};

fn run(arguments: Value) -> Result<Evidence, Value> {
    run_with(arguments, &CancellationSignal::new())
}

fn run_with(arguments: Value, signal: &CancellationSignal) -> Result<Evidence, Value> {
    ElfNotesService::new(ElfNotesProvider)
        .inspect(Some(&arguments), signal)
        .map_err(|error| error.project(CallerLifetime::Invocation).to_value())
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> String {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    path.to_str().unwrap().to_owned()
}

fn failure(arguments: Value) -> Value {
    run(arguments).expect_err("expected the operation to fail")
}

#[test]
fn records_verifiable_evidence_without_modifying_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = elf_note_fixture(&ImageOptions::default());
    let path = write(dir.path(), "program", &bytes);

    let evidence = run(json!({ "path": path })).unwrap();

    evidence.verify().unwrap();
    assert_eq!(evidence.operation, "inspect_elf_notes");
    assert_eq!(evidence.provider.id, "rea-elf-notes");
    let subject = evidence.subject.as_ref().unwrap();
    assert_eq!(subject.local_path, path);
    assert_eq!(
        subject.digest.sha256,
        rea_domain::digest::Sha256Digest::of(&bytes)
    );
    let value = serde_json::to_value(&evidence).unwrap();
    assert_eq!(value["subject"]["format"], "elf");
    assert_eq!(value["subject"]["architecture"], "x86_64");
    assert_eq!(value["parameters"]["max_entries"], 32);
    assert_eq!(
        value["locations"][0],
        json!({"kind": "artifact-path", "path": path})
    );
    assert_eq!(value["locations"][1]["kind"], "file-offset-range");
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn rejects_unreadable_arguments_with_projected_issues() {
    let projected = failure(json!({ "path": "/a", "max_entries": 0, "extra": true }));
    assert_eq!(projected["code"], "invalid_request");
    assert_eq!(projected["details"]["operation"], "inspect_elf_notes");
    let issues = &projected["details"]["issues"];
    assert_eq!(issues[0]["path"], json!(["max_entries"]));
    assert_eq!(issues[0]["reason"], "out_of_range");
    assert_eq!(issues[0]["minimum"], 1);
    assert_eq!(
        issues[1],
        json!({"path": ["extra"], "reason": "unknown_argument"})
    );
}

#[test]
fn rejects_a_relative_path() {
    let projected = failure(json!({ "path": "relative/program" }));
    assert_eq!(projected["code"], "invalid_request");
    assert_eq!(
        projected["details"]["issues"][0],
        json!({
            "path": ["path"],
            "reason": "invalid_format",
            "message": "Expected an absolute filesystem path on this host."
        })
    );
}

#[test]
fn missing_arguments_are_a_missing_object() {
    let error = ElfNotesService::new(ElfNotesProvider)
        .inspect(None, &CancellationSignal::new())
        .unwrap_err();
    let projected = error.project(CallerLifetime::Invocation).to_value();
    assert_eq!(projected["code"], "invalid_request");
    assert_eq!(
        projected["details"]["issues"][0]["reason"],
        "missing_argument"
    );
}

#[test]
fn a_cancelled_signal_wins_before_any_read() {
    let signal = CancellationSignal::new();
    signal.cancel();
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        dir.path(),
        "program",
        &elf_note_fixture(&ImageOptions::default()),
    );
    let projected = run_with(json!({ "path": path }), &signal).unwrap_err();
    assert_eq!(projected["code"], "cancelled");
}

#[test]
fn projects_compressed_note_sections_as_unsupported_rather_than_malformed() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = elf_note_fixture(&ImageOptions {
        ownership: Ownership::Section,
        ..ImageOptions::default()
    });
    let section = usize::try_from(get64le(&bytes, 40)).unwrap() + 64;
    bytes[section + 8..section + 16].copy_from_slice(&0x800_u64.to_le_bytes());
    let path = write(dir.path(), "compressed.o", &bytes);

    let projected = failure(json!({ "path": path }));

    assert_eq!(projected["code"], "unsupported_target");
    assert!(
        projected["message"]
            .as_str()
            .unwrap()
            .contains("Compressed ELF note sections")
    );
}

#[test]
fn reports_a_note_table_past_the_end_of_the_file_as_invalid_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "program", &elf_note_table_past_end());

    let projected = failure(json!({ "path": path }));

    assert_eq!(projected["code"], "invalid_request");
    let issue = &projected["details"]["issues"][0];
    assert_eq!(issue["path"], json!(["path"]));
    assert_eq!(issue["reason"], "invalid_format");
    assert!(
        issue["message"]
            .as_str()
            .unwrap()
            .contains("leaves the artifact")
    );
}

#[test]
fn reports_valid_extended_section_numbering_as_an_unsupported_target() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        dir.path(),
        "extended-count.elf",
        &elf_extended_section_count_fixture(),
    );

    let projected = failure(json!({ "path": path }));

    assert_eq!(projected["code"], "unsupported_target");
    assert!(
        projected["message"]
            .as_str()
            .unwrap()
            .contains("ELF extended numbering is unsupported")
    );
}

#[test]
fn reports_a_truncated_image_as_invalid_input_naming_the_missing_section_table() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "truncated", b"\x7fELF");
    let projected = failure(json!({ "path": path }));
    assert_eq!(projected["code"], "invalid_request");
    assert_eq!(projected["details"]["operation"], "inspect_elf_notes");
}

#[test]
fn names_the_note_text_budget_instead_of_host_memory() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = elf_note_fixture(&ImageOptions {
        ownership: Ownership::Program,
        notes: Some(elf_note("GNU", 3, &[1_u8; 4096])),
        ..ImageOptions::default()
    });
    let path = write(dir.path(), "program", &bytes);

    let projected = failure(json!({ "path": path }));

    assert_eq!(projected["code"], "resource_constraint");
    assert_eq!(projected["retryable"], false);
    assert!(
        projected["message"]
            .as_str()
            .unwrap()
            .contains("byte budget")
    );
    let action = projected["remediation"]["action"].as_str().unwrap();
    assert!(action.contains("ELF note text, hash, and scan budget"));
    assert!(action.contains("admitted image length"));
    assert!(action.contains("do not raise it"));
    assert!(!action.contains("available host memory"));
}

#[test]
fn keeps_a_caller_file_size_budget_distinct_from_host_memory() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        dir.path(),
        "program",
        &elf_note_fixture(&ImageOptions {
            ownership: Ownership::Program,
            ..ImageOptions::default()
        }),
    );

    let projected = failure(json!({ "path": path, "max_file_bytes": 64 }));

    assert_eq!(projected["code"], "resource_constraint");
    assert_eq!(projected["retryable"], false);
    let action = projected["remediation"]["action"].as_str().unwrap();
    assert!(action.contains("max_file_bytes"));
    assert!(!action.contains("available host memory"));
}

#[test]
fn reports_and_admits_compressed_names_through_max_file_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = compressed_elf_note_fixture(Bits::Elf64, true, 1, ".note.gnu.build-id");
    let section_offset = usize::try_from(get64le(&bytes, 40)).unwrap();
    let name_header = section_offset + usize::from(get16(&bytes, 62, true)) * 64;
    let names_offset = usize::try_from(get64le(&bytes, name_header + 24)).unwrap();
    let decoded_names_bytes = get64le(&bytes, names_offset + 8);
    let minimum = bytes.len() as u64 + decoded_names_bytes;
    let path = write(dir.path(), "compressed-names.elf", &bytes);

    let refused = failure(json!({ "path": path, "max_file_bytes": bytes.len() + 1 }));

    assert_eq!(refused["code"], "resource_constraint");
    assert_eq!(refused["retryable"], false);
    assert_eq!(refused["details"]["resource"], "memory");
    assert_eq!(
        refused["details"]["reported_limits"]["max_file_bytes"],
        bytes.len() + 1
    );
    assert_eq!(
        refused["details"]["reported_limits"]["minimum_required_bytes"],
        minimum.to_string()
    );
    assert!(
        refused["remediation"]["action"]
            .as_str()
            .unwrap()
            .contains("max_file_bytes")
    );

    let admitted = run(json!({ "path": path, "max_file_bytes": minimum })).unwrap();
    assert_eq!(
        admitted.normalized_result["tables"][0]["name"],
        ".note.gnu.build-id"
    );
}

#[test]
fn rejects_a_missing_file_as_an_invalid_value_naming_the_errno() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing");
    let projected = failure(json!({ "path": path.to_str().unwrap() }));
    assert_eq!(projected["code"], "invalid_request");
    assert_eq!(
        projected["details"]["issues"][0]["message"],
        format!(
            "Selected ELF image could not be read (ENOENT): {}.",
            path.display()
        )
    );
}

#[cfg(unix)]
#[test]
fn rejects_a_symlink_and_offers_its_regular_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = write(
        dir.path(),
        "target",
        &elf_note_fixture(&ImageOptions::default()),
    );
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let projected = failure(json!({ "path": link.to_str().unwrap() }));

    assert_eq!(projected["code"], "invalid_request");
    let resolved = fs::canonicalize(&target).unwrap();
    assert!(
        projected["remediation"]["action"]
            .as_str()
            .unwrap()
            .contains(&format!(
                "Retry with the resolved regular file path {}",
                resolved.display()
            ))
    );
}
