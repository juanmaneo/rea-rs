//! Owned, bounded, identity-checked reads of caller-selected local files.
//!
//! Upstream reference: `upstream:src/filesystem/` and
//! `upstream:src/artifacts/readStableArtifact.ts`.
//!
//! Descriptors close on drop. A read-only descriptor holds no buffered
//! writes, so its close failure has no caller-visible consequence; upstream's
//! descriptor-cleanup failure projection is not reproduced here.

pub mod errno;
pub mod stable_read;

pub use errno::ErrnoCode;
pub use stable_read::{ChangeStage, StableArtifact, StableReadError, read_stable_artifact};
