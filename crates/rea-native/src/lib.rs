//! In-process native binary format readers.
//!
//! Each reader parses bytes already admitted by `rea-filesystem` into the
//! result contracts declared in `rea_domain::native`. Readers never execute
//! the target and never modify it.
//!
//! Upstream reference: `upstream:src/native/`.

pub mod elf;
