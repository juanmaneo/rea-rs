//! `rea inspect-elf-notes`.
//!
//! Upstream reference: the `inspectElfNotes` command in
//! `upstream:src/cli/binaryDiagnosticsCommands.ts` and
//! `upstream:src/cli/cliEvidenceCallerPath.ts`.

use std::process::ExitCode;

use rea_application::binary_diagnostics::elf_notes::{ElfNotesService, OPERATION};
use rea_domain::error::{AnalysisError, CallerLifetime, InputIssue, InputIssueReason};
use rea_domain::evidence::Evidence;
use rea_filesystem::absolute_caller_path;
use rea_native::elf::ElfNotesProvider;
use serde_json::{Map, Number, Value};

use crate::arguments::{InspectElfNotesArguments, OutputFormat};
use crate::interrupt::Interrupts;
use crate::output::write_document;

/// Run the command and write its one result document.
pub fn run(arguments: &InspectElfNotesArguments, format: OutputFormat) -> ExitCode {
    let interrupts = Interrupts::install();
    let outcome = inspect(arguments, &interrupts);
    let (document, succeeded) = match outcome {
        Ok(evidence) => match serde_json::to_value(&evidence) {
            Ok(document) => (document, true),
            Err(error) => {
                eprintln!("rea: could not serialize Evidence: {error}");
                return ExitCode::FAILURE;
            }
        },
        Err(error) => (error.project(CallerLifetime::Invocation).to_value(), false),
    };
    if let Err(error) = write_document(&document, format) {
        eprintln!("rea: could not write the result: {error}");
        return ExitCode::FAILURE;
    }
    match (interrupts.exit_code(), succeeded) {
        (Some(code), _) => ExitCode::from(code),
        (None, true) => ExitCode::SUCCESS,
        (None, false) => ExitCode::FAILURE,
    }
}

fn inspect(
    arguments: &InspectElfNotesArguments,
    interrupts: &Interrupts,
) -> Result<Evidence, AnalysisError> {
    let raw = raw_input(arguments)?;
    let service = ElfNotesService::new(ElfNotesProvider);
    match service.inspect(Some(&raw), interrupts.signal()) {
        Ok(evidence) => bind_caller_path(evidence, &arguments.path),
        Err(error) => Err(bind_partial_observation(error, &arguments.path)),
    }
}

/// The caller's arguments as the shared workflow's raw input. Path admission
/// and every budget range belong to the workflow, so values that are not
/// numbers are forwarded as text for it to refuse.
fn raw_input(arguments: &InspectElfNotesArguments) -> Result<Value, AnalysisError> {
    let mut raw = Map::new();
    raw.insert("path".into(), absolute_path(&arguments.path)?.into());
    for (key, value) in [
        ("max_file_bytes", &arguments.max_file_bytes),
        ("max_entries", &arguments.max_entries),
    ] {
        if let Some(text) = value {
            raw.insert(key.into(), number_or_text(text));
        }
    }
    Ok(Value::Object(raw))
}

fn number_or_text(text: &str) -> Value {
    if let Ok(integer) = text.parse::<i64>() {
        Value::from(integer)
    } else if let Ok(integer) = text.parse::<u64>() {
        Value::from(integer)
    } else {
        text.parse::<f64>()
            .ok()
            .and_then(Number::from_f64)
            .map_or_else(|| Value::from(text), Value::Number)
    }
}

/// Make the selection absolute, leaving empty and NUL-bearing text for the
/// workflow's path admission to refuse.
fn absolute_path(path: &str) -> Result<String, AnalysisError> {
    if path.is_empty() || path.contains('\0') {
        return Ok(path.to_owned());
    }
    absolute_caller_path(path, || {
        std::env::current_dir()
            .ok()
            .and_then(|directory| directory.to_str().map(str::to_owned))
    })
    .map_err(|_| {
        AnalysisError::input(
            OPERATION,
            [InputIssue::new(["path"], InputIssueReason::InvalidValue)
                .with_message("The working directory is unavailable to resolve a relative path.")],
        )
    })
}

/// Bind the operator's selection before anything can retain the Evidence.
fn bind_caller_path(evidence: Evidence, selected: &str) -> Result<Evidence, AnalysisError> {
    evidence
        .with_caller_input_path(selected)
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))
}

/// A partial observation that is not Evidence keeps its original form.
fn bind_partial_observation(error: AnalysisError, selected: &str) -> AnalysisError {
    let rebound = error
        .partial_observation()
        .and_then(|observation| serde_json::from_value::<Evidence>(observation.clone()).ok())
        .and_then(|evidence| evidence.with_caller_input_path(selected).ok())
        .and_then(|evidence| serde_json::to_value(evidence).ok());
    match rebound {
        Some(observation) => error.with_partial_observation(observation),
        None => error,
    }
}
