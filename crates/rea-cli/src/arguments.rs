//! Command-line grammar.
//!
//! Upstream reference: `upstream:src/cli/binaryDiagnosticsCommands.ts` and the
//! built-in output flags in `upstream:src/cliBuiltinArguments.ts`.

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Local-only reverse-engineering workflows with shared CLI and MCP contracts.
#[derive(Debug, Parser)]
#[command(name = "rea", version)]
pub struct Cli {
    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
    /// Output controls shared by every command.
    #[command(flatten)]
    pub output: OutputOptions,
}

/// Commands ported so far.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect ELF PT_NOTE and SHT_NOTE identities without executing the image
    InspectElfNotes(InspectElfNotesArguments),
}

/// Arguments of `inspect-elf-notes`.
#[derive(Debug, Args)]
pub struct InspectElfNotesArguments {
    /// Local ELF32/ELF64 image
    pub path: String,
    /// Maximum stable artifact bytes to read (default 64 MiB)
    #[arg(long)]
    pub max_file_bytes: Option<String>,
    /// Maximum note entries to examine across every table; exceeding the
    /// budget fails without partial success
    #[arg(long)]
    pub max_entries: Option<String>,
}

/// Output formats ported so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// One JSON document: indented on a terminal, compact when piped.
    Json,
}

/// Output flags, accepted before or after the command.
#[derive(Debug, Args)]
pub struct OutputOptions {
    /// Print the result as JSON
    #[arg(long, global = true)]
    json: bool,
    /// Output format (default: json)
    #[arg(long, global = true, value_enum)]
    format: Option<OutputFormat>,
}

impl OutputOptions {
    /// The selected format. Upstream defaults to `toon`, which is not ported;
    /// JSON is the default until it is.
    pub fn format(&self) -> OutputFormat {
        if self.json {
            OutputFormat::Json
        } else {
            self.format.unwrap_or(OutputFormat::Json)
        }
    }
}
