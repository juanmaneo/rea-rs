//! `rea inspect-elf-notes`.
//!
//! Upstream reference: the `inspectElfNotes` command in
//! `upstream:src/cli/binaryDiagnosticsCommands.ts`.

use std::process::ExitCode;

use rea_application::binary_diagnostics::elf_notes::{ElfNotesService, OPERATION};
use rea_native::elf::ElfNotesProvider;

use crate::arguments::{InspectElfNotesArguments, OutputFormat};
use crate::evidence_command::{self, Selection};

/// Run the command and write its one result document.
pub fn run(arguments: &InspectElfNotesArguments, format: OutputFormat) -> ExitCode {
    let selection = Selection {
        operation: OPERATION,
        path: &arguments.path,
        options: &[
            ("max_file_bytes", &arguments.max_file_bytes),
            ("max_entries", &arguments.max_entries),
        ],
    };
    evidence_command::run(&selection, format, |raw, signal| {
        ElfNotesService::new(ElfNotesProvider).inspect(Some(raw), signal)
    })
}
