//! The `rea` command-line adapter.
//!
//! Each command runs one shared application workflow, binds the operator's
//! selection to the result, and writes one JSON document to stdout. A failure
//! is the projected analysis error on stdout with exit code 1.
//!
//! Upstream reference: `upstream:src/cli/` and `upstream:src/cliOutput.ts`.

mod arguments;
mod evidence_command;
mod inspect_elf_notes;
mod inspect_kernel_module;
mod interrupt;
mod output;

use std::process::ExitCode;

use arguments::{Cli, Command};
use clap::Parser;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let format = cli.output.format();
    match cli.command {
        Command::InspectElfNotes(arguments) => inspect_elf_notes::run(&arguments, format),
        Command::InspectKernelModule(arguments) => inspect_kernel_module::run(&arguments, format),
    }
}
