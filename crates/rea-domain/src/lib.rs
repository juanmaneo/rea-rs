//! Pure, side-effect-free REA domain semantics.
//!
//! This crate is the innermost layer of the workspace. It owns the Evidence
//! envelope and its semantic identity, canonical JSON digests, the
//! caller-visible analysis error contract, and format-specific result
//! declarations. It performs no I/O and depends on no other workspace crate.
//!
//! Upstream reference: `upstream:src/domain/`.

pub mod digest;
pub mod error;
pub mod evidence;
pub mod json;
pub mod native;
