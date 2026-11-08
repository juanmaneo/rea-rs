//! `rea inspect-kernel-module` through the compiled binary.
//!
//! Ported from `upstream:tests/acceptance/kernelModuleCli.test.ts`. Fixtures
//! are shared with the parser tests in `rea-native`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

#[path = "../../rea-native/tests/kernel_module/fixture.rs"]
mod fixture;

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use fixture::{KernelModuleOptions, compressed_kernel_module_container, kernel_module_fixture};
use rea_domain::evidence::Evidence;
use rea_domain::native::kernel_module::KernelModuleCodec;
use serde_json::{Value, json};

fn rea(arguments: &[&str], cwd: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rea"));
    command.args(arguments);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.output().unwrap()
}

fn document(output: &Output, code: i32) -> Value {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(code), "stderr: {stderr}");
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("stdout is not JSON ({error}); stderr: {stderr}"))
}

/// Parse and verify the Evidence document, as upstream's output schema does.
fn evidence(output: &Output) -> Value {
    let document = document(output, 0);
    let parsed: Evidence = serde_json::from_value(document.clone()).unwrap();
    parsed.verify().unwrap();
    document
}

fn inspect(path: &Path) -> Output {
    rea(
        &["inspect-kernel-module", path.to_str().unwrap(), "--json"],
        None,
    )
}

#[test]
fn reports_license_duplicate_aliases_and_version_crcs_through_the_public_cli() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("demo.ko");
    fs::write(
        &path,
        kernel_module_fixture(&KernelModuleOptions::default()),
    )
    .unwrap();
    let evidence = evidence(&inspect(&path));
    let result = &evidence["normalized_result"];
    let pairs: Vec<_> = result["modinfo"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| json!([entry["key"], entry["value"]]))
        .collect();
    assert_eq!(
        pairs,
        [
            json!(["license", "GPL"]),
            json!(["vermagic", "5.15.0 SMP mod_unload"]),
            json!(["alias", "pci:v1"]),
            json!(["alias", "pci:v2"]),
            json!(["name", "demo"]),
            json!(["depends", ""]),
        ]
    );
    assert_eq!(
        result["versions"]["entries"][0]["crc_hex"],
        "0000000012345678"
    );
    assert_eq!(result["signature"]["status"], "present");
}

#[test]
fn resolves_a_relative_kernel_module_path_against_the_working_directory() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("demo.ko"),
        kernel_module_fixture(&KernelModuleOptions {
            object_type: 3,
            ..Default::default()
        }),
    )
    .unwrap();
    let evidence = evidence(&rea(
        &["inspect-kernel-module", "demo.ko", "--json"],
        Some(root.path()),
    ));
    assert_eq!(
        evidence["normalized_result"]["applicability"],
        "not_applicable"
    );
    assert_eq!(evidence["normalized_result"]["type_name"], "shared");
    assert_eq!(
        evidence["subject"]["local_path"],
        root.path().join("demo.ko").to_str().unwrap()
    );
}

#[test]
fn reports_a_non_elf_file_as_invalid_input() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("broken.ko");
    fs::write(&path, b"not an elf").unwrap();
    let failure = document(&inspect(&path), 1);
    assert_eq!(failure["code"], "invalid_request");
    assert_eq!(failure["details"]["operation"], "inspect_kernel_module");
}

#[test]
fn reports_a_compressed_container_without_claiming_the_payload_is_a_module() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("demo.ko.xz");
    fs::write(
        &path,
        compressed_kernel_module_container(KernelModuleCodec::Xz),
    )
    .unwrap();
    let evidence = evidence(&inspect(&path));
    let result = &evidence["normalized_result"];
    assert_eq!(result["applicability"], "unsupported");
    assert_eq!(result["format"], Value::Null);
    assert_eq!(
        result["compression"],
        json!({ "codec": "xz", "status": "unsupported" })
    );
    assert_eq!(result["next_probe"]["operation"], "external_decompression");
    assert_eq!(result["modinfo"], Value::Null);
    assert_eq!(evidence["subject"]["format"], "file");
}
