//! `rea inspect-kernel-module`.
//!
//! Upstream reference: the `inspectKernelModule` command in
//! `upstream:src/cli/binaryDiagnosticsCommands.ts`.

use std::process::ExitCode;

use rea_application::binary_diagnostics::kernel_module::{KernelModuleService, OPERATION};
use rea_native::elf::KernelModuleProvider;

use crate::arguments::{InspectKernelModuleArguments, OutputFormat};
use crate::evidence_command::{self, Selection};

/// Run the command and write its one result document.
pub fn run(arguments: &InspectKernelModuleArguments, format: OutputFormat) -> ExitCode {
    let selection = Selection {
        operation: OPERATION,
        path: &arguments.path,
        options: &[
            ("max_file_bytes", &arguments.max_file_bytes),
            ("max_entries", &arguments.max_entries),
        ],
    };
    evidence_command::run(&selection, format, |raw, signal| {
        KernelModuleService::new(KernelModuleProvider).inspect(Some(raw), signal)
    })
}
