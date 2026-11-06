//! Shared note text, hash, and scan budget.
//!
//! Retained text (owner names, section names, GNU descriptor text, CORE
//! string representations), descriptor hashing, and descriptor scans each
//! draw from separate counters with one shared byte ceiling. Repeated ranges
//! reuse cached hashes and scans; retained text counts again.
//!
//! Upstream reference: `TextBudget` in `upstream:src/native/elf/ElfNoteParser.ts`.

use std::collections::HashMap;

use rea_domain::digest::Sha256Digest;

use super::{ElfNotesFailure, ElfNotesLimitBoundary};

/// A descriptor's file range, which keys cached hashes and scans.
pub(crate) type DescriptorRange = (usize, usize);

#[derive(Debug, Clone, Copy)]
pub(crate) enum Counter {
    Used,
    Hashed,
    Scanned,
}

#[derive(Debug)]
pub(crate) struct TextBudget {
    pub(crate) limit: u64,
    used: u64,
    hashed: u64,
    scanned: u64,
    pub(crate) hashes: HashMap<DescriptorRange, Sha256Digest>,
    /// GNU gold-version content length without trailing NULs.
    pub(crate) gold_scans: HashMap<DescriptorRange, usize>,
    /// Total `NT_FILE` path bytes, or `None` when the string area is malformed.
    pub(crate) file_scans: HashMap<DescriptorRange, Option<u64>>,
    /// Index of the `AT_NULL` pair, or `None` when the vector is malformed.
    pub(crate) auxv_scans: HashMap<DescriptorRange, Option<usize>>,
}

impl TextBudget {
    pub(crate) fn new(limit: u64) -> Self {
        Self {
            limit,
            used: 0,
            hashed: 0,
            scanned: 0,
            hashes: HashMap::new(),
            gold_scans: HashMap::new(),
            file_scans: HashMap::new(),
            auxv_scans: HashMap::new(),
        }
    }

    pub(crate) fn exceeded(&self) -> ElfNotesFailure {
        ElfNotesFailure::Limit {
            boundary: ElfNotesLimitBoundary::Memory,
            message: format!("ELF note text exceeds the {}-byte budget.", self.limit),
        }
    }

    /// Retained-text bytes still available.
    pub(crate) fn remaining_text(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    pub(crate) fn charge(&mut self, bytes: u64, counter: Counter) -> Result<(), ElfNotesFailure> {
        let current = match counter {
            Counter::Used => &mut self.used,
            Counter::Hashed => &mut self.hashed,
            Counter::Scanned => &mut self.scanned,
        };
        match self.limit.checked_sub(*current) {
            Some(room) if bytes <= room => {
                *current += bytes;
                Ok(())
            }
            _ => Err(self.exceeded()),
        }
    }

    pub(crate) fn charge_text(&mut self, bytes: u64) -> Result<(), ElfNotesFailure> {
        self.charge(bytes, Counter::Used)
    }
}
