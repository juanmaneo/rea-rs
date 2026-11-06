//! `rea inspect-elf-notes` through the compiled binary.
//!
//! Ported from `upstream:tests/acceptance/elfNotesCli.test.ts`. Fixtures are
//! shared with the parser tests in `rea-native`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

#[path = "../../rea-native/tests/elf_notes/fixture.rs"]
mod fixture;

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use fixture::{
    Bits, ImageOptions, NameDamage, Ownership, compressed_elf_note_fixture,
    compressed_elf_note_section_fixture, elf_extended_section_count_fixture, elf_note_fixture,
    elf_note_with_unreadable_section_name_fixture, put16,
};
use serde_json::{Value, json};

const BUILD_ID: &str = "0123456789abcdef0123456789abcdef01234567";

struct Run {
    output: Output,
}

impl Run {
    fn code(&self) -> Option<i32> {
        self.output.status.code()
    }

    fn stdout(&self) -> &str {
        std::str::from_utf8(&self.output.stdout).unwrap()
    }

    fn stderr(&self) -> &str {
        std::str::from_utf8(&self.output.stderr).unwrap()
    }

    fn json(&self) -> Value {
        serde_json::from_str(self.stdout()).unwrap_or_else(|error| {
            panic!(
                "stdout is not JSON ({error}): {}\nstderr: {}",
                self.stdout(),
                self.stderr()
            )
        })
    }

    fn succeeds(&self) -> Value {
        assert_eq!(self.code(), Some(0), "stderr: {}", self.stderr());
        self.json()
    }

    fn fails(&self) -> Value {
        assert_eq!(self.code(), Some(1), "stderr: {}", self.stderr());
        self.json()
    }
}

fn rea(arguments: &[&str], cwd: Option<&Path>) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rea"));
    command.args(arguments);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    Run {
        output: command.output().unwrap(),
    }
}

fn inspect(path: &Path) -> Run {
    rea(
        &["inspect-elf-notes", path.to_str().unwrap(), "--json"],
        None,
    )
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

fn build_id_of(entries: &Value) -> Option<&Value> {
    entries
        .as_array()?
        .iter()
        .find(|entry| entry["type_name"] == "gnu_build_id")
        .map(|entry| &entry["gnu"]["build_id_hex"])
}

#[test]
fn reports_a_gnu_build_id_through_the_public_cli() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        dir.path(),
        "program",
        &elf_note_fixture(&ImageOptions {
            ownership: Ownership::Program,
            ..ImageOptions::default()
        }),
    );

    let evidence = inspect(&path).succeeds();

    assert_eq!(evidence["operation"], "inspect_elf_notes");
    assert_eq!(
        build_id_of(&evidence["normalized_result"]["entries"]),
        Some(&json!(BUILD_ID))
    );
    let parsed: rea_domain::evidence::Evidence = serde_json::from_value(evidence).unwrap();
    parsed.verify().unwrap();
}

#[test]
fn resolves_section_note_names_from_zlib_and_zstandard_string_tables() {
    let dir = tempfile::tempdir().unwrap();
    for compression_type in [1_u32, 2] {
        let bytes =
            compressed_elf_note_fixture(Bits::Elf64, true, compression_type, ".note.gnu.build-id");
        let path = write(dir.path(), &format!("program-{compression_type}"), &bytes);

        let evidence = inspect(&path).succeeds();

        let result = &evidence["normalized_result"];
        assert_eq!(result["tables"][0]["name"], ".note.gnu.build-id");
        assert_eq!(result["entries"][0]["gnu"]["build_id_hex"], BUILD_ID);
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn keeps_gnu_notes_when_a_section_name_offset_is_outside_its_string_table() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = elf_note_with_unreadable_section_name_fixture(NameDamage::Outside);
    let path = write(dir.path(), "program", &bytes);

    let evidence = inspect(&path).succeeds();

    let result = &evidence["normalized_result"];
    assert_eq!(result["tables"][0]["name"], Value::Null);
    assert!(result["limitations"].as_array().unwrap().contains(&json!(
        "ELF section names are incomplete because a name offset is outside its string table."
    )));
    assert_eq!(result["entries"][0]["gnu"]["build_id_hex"], BUILD_ID);
    assert_eq!(result["coverage"]["status"], "complete");
    assert_eq!(result["coverage"]["examined_tables"], 1);
    assert_eq!(result["coverage"]["examined_entries"], 1);
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn resolves_a_relative_path_against_the_working_directory_and_keeps_the_selection() {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    write(
        &root,
        "unsigned",
        &elf_note_fixture(&ImageOptions {
            ownership: Ownership::None,
            ..ImageOptions::default()
        }),
    );

    let evidence = rea(&["inspect-elf-notes", "unsigned", "--json"], Some(&root)).succeeds();

    assert_eq!(evidence["normalized_result"]["tables"], json!([]));
    assert_eq!(
        evidence["subject"]["local_path"],
        root.join("unsigned").to_str().unwrap()
    );
    assert_eq!(evidence["caller_input_path"], "unsigned");
}

#[test]
fn reports_a_truncated_elf_as_invalid_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "broken", b"\x7fELF");

    let projected = inspect(&path).fails();

    assert_eq!(projected["code"], "invalid_request");
    assert_eq!(projected["details"]["operation"], "inspect_elf_notes");
}

#[test]
fn reports_compressed_note_storage_as_unsupported_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = compressed_elf_note_section_fixture(Bits::Elf64, true);
    let path = write(dir.path(), "debug-notes.o", &bytes);

    let projected = inspect(&path).fails();

    assert_eq!(projected["code"], "unsupported_target");
    assert!(
        projected["message"]
            .as_str()
            .unwrap()
            .contains("Compressed ELF note sections are unsupported")
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn reports_valid_extended_numbering_as_unsupported_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = elf_extended_section_count_fixture();
    let path = write(dir.path(), "extended-count.elf", &bytes);

    let projected = inspect(&path).fails();

    assert_eq!(projected["code"], "unsupported_target");
    assert!(
        projected["message"]
            .as_str()
            .unwrap()
            .contains("ELF extended numbering is unsupported")
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn rejects_dangling_section_name_references_and_preserves_sectionless_notes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("program");
    for ownership in [Ownership::Program, Ownership::None] {
        let none = matches!(ownership, Ownership::None);
        let mut bytes = elf_note_fixture(&ImageOptions {
            ownership,
            ..ImageOptions::default()
        });
        put16(&mut bytes, 62, 5, true);
        fs::write(&path, &bytes).unwrap();

        let projected = inspect(&path).fails();

        assert_eq!(projected["code"], "invalid_request");
        assert_eq!(projected["category"], "invalid_input");
        assert_eq!(projected["details"]["operation"], "inspect_elf_notes");
        let issue = &projected["details"]["issues"][0];
        assert_eq!(issue["path"], json!(["path"]));
        assert_eq!(issue["reason"], "invalid_format");
        assert_eq!(issue["message"], "ELF section table is missing");
        assert_eq!(fs::read(&path).unwrap(), bytes);

        put16(&mut bytes, 62, 0, true);
        fs::write(&path, &bytes).unwrap();
        let evidence = inspect(&path).succeeds();
        assert_eq!(
            evidence["normalized_result"]["coverage"]["status"],
            "complete"
        );
        assert_eq!(
            evidence["normalized_result"]["tables"]
                .as_array()
                .unwrap()
                .len(),
            usize::from(!none)
        );
    }
}

#[test]
fn projects_budget_and_argument_refusals_with_exit_code_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        dir.path(),
        "program",
        &elf_note_fixture(&ImageOptions::default()),
    );
    let selected = path.to_str().unwrap();

    let small = rea(
        &["inspect-elf-notes", selected, "--max-file-bytes", "64"],
        None,
    )
    .fails();
    assert_eq!(small["code"], "resource_constraint");
    assert_eq!(small["details"]["resource"], "file-size");

    let out_of_range = rea(&["inspect-elf-notes", selected, "--max-entries", "0"], None).fails();
    assert_eq!(out_of_range["code"], "invalid_request");
    assert_eq!(
        out_of_range["details"]["issues"][0]["path"],
        json!(["max_entries"])
    );
    assert_eq!(
        out_of_range["details"]["issues"][0]["reason"],
        "out_of_range"
    );

    let not_a_number = rea(
        &["inspect-elf-notes", selected, "--max-entries", "many"],
        None,
    )
    .fails();
    assert_eq!(
        not_a_number["details"]["issues"][0]["reason"],
        "invalid_type"
    );

    let empty = rea(&["inspect-elf-notes", ""], None).fails();
    assert_eq!(empty["code"], "invalid_request");
    assert_eq!(empty["details"]["issues"][0]["path"], json!(["path"]));
}

#[test]
fn writes_compact_json_with_one_trailing_newline_when_piped() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        dir.path(),
        "program",
        &elf_note_fixture(&ImageOptions::default()),
    );

    let run = rea(
        &[
            "inspect-elf-notes",
            path.to_str().unwrap(),
            "--format",
            "json",
        ],
        None,
    );

    assert_eq!(run.code(), Some(0));
    let text = run.stdout();
    assert!(text.ends_with("}\n"));
    assert_eq!(text.matches('\n').count(), 1, "compact output is one line");
    assert!(text.starts_with("{\"evidence_id\":\"ev_"));
}

#[test]
fn rejects_unported_output_formats_at_the_command_line() {
    let run = rea(&["inspect-elf-notes", "/x", "--format", "yaml"], None);
    assert_eq!(run.code(), Some(2));
    assert!(run.stdout().is_empty());
    assert!(run.stderr().contains("invalid value 'yaml'"));
}
