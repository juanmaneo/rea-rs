//! Writing one structured result to stdout.
//!
//! Upstream reference: `jsonOutputParts` in `upstream:src/cli/jsonOutput.ts`.

use std::io::{self, IsTerminal, Write};

use rea_domain::json::{JsonLayout, write_json};
use serde_json::Value;

use crate::arguments::OutputFormat;

/// Write `value` and a final newline. JSON is indented for a terminal
/// reader and compact when piped or redirected, where indentation adds
/// tokens but no information.
pub fn write_document(value: &Value, format: OutputFormat) -> io::Result<()> {
    let stdout = io::stdout();
    let layout = if stdout.is_terminal() {
        JsonLayout::Pretty
    } else {
        JsonLayout::Compact
    };
    let mut out = io::BufWriter::new(stdout.lock());
    match format {
        OutputFormat::Json => write_json(value, layout, &mut out)?,
    }
    out.write_all(b"\n")?;
    out.flush()
}
