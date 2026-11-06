//! One bounded, identity-checked read of a caller-selected regular file.
//!
//! Upstream reference: `upstream:src/artifacts/readStableArtifact.ts`.

use std::fmt;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use rea_domain::cancellation::CancellationSignal;
use rea_domain::digest::Sha256Digest;
use rea_domain::error::{ArtifactLimitBoundary, ArtifactOperationReason};
use sha2::{Digest, Sha256};

use crate::errno::ErrnoCode;

/// Bytes read past the admitted length are hashed through scratch space of
/// this size so growth is detected without allocating beyond the budget.
const READ_CHUNK_BYTES: usize = 65_536;

/// The exact bytes and digest of one stable read.
#[derive(Clone, PartialEq, Eq)]
pub struct StableArtifact {
    /// The complete file contents.
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`.
    pub sha256: Sha256Digest,
}

impl fmt::Debug for StableArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StableArtifact")
            .field("bytes", &self.bytes.len())
            .field("sha256", &self.sha256)
            .finish()
    }
}

/// When a replacement or in-place change was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeStage {
    /// Between path validation and descriptor admission.
    BeforeOpen,
    /// While the admitted descriptor was read.
    DuringRead,
}

impl fmt::Display for ChangeStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BeforeOpen => "before open",
            Self::DuringRead => "during read",
        })
    }
}

/// Why a stable read produced no snapshot.
///
/// Messages are byte-identical to upstream `ArtifactReaderFailure` text.
#[derive(Debug, thiserror::Error)]
pub enum StableReadError {
    /// The selected path is not a regular file, or is a symlink.
    #[error("Expected a regular file without a symlink: {}", path.display())]
    NotRegularFile {
        /// The selected path.
        path: PathBuf,
        /// The regular file a rejected symlink currently resolves to, offered
        /// only as a retry hint; the retry validates it again.
        resolved_path: Option<PathBuf>,
    },
    /// The file was already larger than the byte budget.
    #[error("Selected artifact exceeds {maximum_bytes} bytes: {}", path.display())]
    ExceedsLimit {
        /// The selected path.
        path: PathBuf,
        /// The caller-selected byte budget.
        maximum_bytes: u64,
    },
    /// The file grew beyond the byte budget while it was read.
    #[error("Selected artifact grew beyond its byte limit: {}", path.display())]
    GrewBeyondLimit {
        /// The selected path.
        path: PathBuf,
    },
    /// The file was replaced or modified after validation.
    #[error("Artifact changed {stage}: {}", path.display())]
    Changed {
        /// The selected path.
        path: PathBuf,
        /// When the change was observed.
        stage: ChangeStage,
        /// The path lookup failure that revealed the change, if any.
        #[source]
        source: Option<io::Error>,
    },
    /// Caller cancellation won before the read completed.
    #[error("Artifact read cancelled")]
    Cancelled,
    /// The host refused or failed an operation before or outside the
    /// identity checks.
    #[error("{source}")]
    Io {
        /// The selected path.
        path: PathBuf,
        /// The host failure.
        #[source]
        source: io::Error,
    },
}

impl StableReadError {
    /// The artifact-operation reason this failure reports.
    pub fn reason(&self) -> ArtifactOperationReason {
        match self {
            Self::NotRegularFile { .. } => ArtifactOperationReason::Path,
            Self::ExceedsLimit { .. } | Self::GrewBeyondLimit { .. } => {
                ArtifactOperationReason::Limit
            }
            Self::Changed { .. } => ArtifactOperationReason::Integrity,
            Self::Cancelled => ArtifactOperationReason::Cancelled,
            Self::Io { .. } => ArtifactOperationReason::Io,
        }
    }

    /// The constrained bound of a limit failure.
    pub fn limit_boundary(&self) -> Option<ArtifactLimitBoundary> {
        match self {
            Self::ExceedsLimit { .. } | Self::GrewBeyondLimit { .. } => {
                Some(ArtifactLimitBoundary::FileSize)
            }
            _ => None,
        }
    }

    /// The classified host error code of an opaque I/O failure.
    pub fn errno(&self) -> Option<ErrnoCode> {
        match self {
            Self::Io { source, .. } => ErrnoCode::of(source),
            _ => None,
        }
    }
}

/// Read one bounded regular file and reject replacement or in-place changes.
///
/// The path is examined without following a final symlink, opened with
/// `O_NOFOLLOW | O_NONBLOCK`, and its descriptor and name identities are
/// compared before and after the read. Bytes are published only after the
/// exact count and both identities validate.
pub fn read_stable_artifact(
    path: &Path,
    maximum_bytes: u64,
    signal: &CancellationSignal,
) -> Result<StableArtifact, StableReadError> {
    active(signal)?;
    let io = |source| StableReadError::Io {
        path: path.to_path_buf(),
        source,
    };
    platform::supported().map_err(io)?;
    let before = fs::symlink_metadata(path).map_err(io)?;
    if !before.file_type().is_file() {
        let resolved_path = if before.file_type().is_symlink() {
            resolved_regular_file(path)
        } else {
            None
        };
        return Err(StableReadError::NotRegularFile {
            path: path.to_path_buf(),
            resolved_path,
        });
    }
    if before.len() > maximum_bytes {
        return Err(StableReadError::ExceedsLimit {
            path: path.to_path_buf(),
            maximum_bytes,
        });
    }
    let file = after_validation(path, ChangeStage::BeforeOpen, open_no_follow(path))?;
    let initial = file.metadata().map_err(io)?;
    if !initial.file_type().is_file() || !platform::same_identity(&initial, &before) {
        return Err(changed(path, ChangeStage::BeforeOpen, None));
    }
    active(signal)?;

    // A raced descriptor size must not allocate beyond the selected budget.
    let admitted = usize::try_from(initial.len().min(maximum_bytes)).map_err(|_| {
        io(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "artifact length exceeds host address space",
        ))
    })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(admitted)
        .map_err(|error| io(io::Error::new(io::ErrorKind::OutOfMemory, error)))?;
    bytes.resize(admitted, 0);
    let mut overflow = [0_u8; READ_CHUNK_BYTES];
    let mut hasher = Sha256::new();
    let mut count: u64 = 0;
    loop {
        active(signal)?;
        let inside = count < admitted as u64;
        let target: &mut [u8] = if inside {
            // `count < admitted`, which fits in `usize`.
            let offset = count as usize;
            let end = admitted.min(offset + READ_CHUNK_BYTES);
            &mut bytes[offset..end]
        } else {
            &mut overflow
        };
        let read = match platform::read_at(&file, target, count) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io(error)),
        };
        if read == 0 {
            break;
        }
        active(signal)?;
        count += read as u64;
        if count > maximum_bytes {
            return Err(StableReadError::GrewBeyondLimit {
                path: path.to_path_buf(),
            });
        }
        hasher.update(&target[..read]);
    }
    let after = file.metadata().map_err(io)?;
    let current = after_validation(path, ChangeStage::DuringRead, fs::symlink_metadata(path))?;
    if !platform::same_regular_file_state(&initial, &after)
        || !platform::same_regular_file_state(&initial, &current)
        || count != initial.len()
    {
        return Err(changed(path, ChangeStage::DuringRead, None));
    }
    active(signal)?;
    Ok(StableArtifact {
        bytes,
        sha256: Sha256Digest::finish(hasher),
    })
}

fn active(signal: &CancellationSignal) -> Result<(), StableReadError> {
    if signal.is_cancelled() {
        Err(StableReadError::Cancelled)
    } else {
        Ok(())
    }
}

fn changed(path: &Path, stage: ChangeStage, source: Option<io::Error>) -> StableReadError {
    StableReadError::Changed {
        path: path.to_path_buf(),
        stage,
        source,
    }
}

/// After validation, a path that no longer resolves means the selection changed.
fn after_validation<T>(
    path: &Path,
    stage: ChangeStage,
    result: io::Result<T>,
) -> Result<T, StableReadError> {
    result.map_err(|source| match ErrnoCode::of(&source) {
        Some(code) if code.is_unresolved_path() => changed(path, stage, Some(source)),
        _ => StableReadError::Io {
            path: path.to_path_buf(),
            source,
        },
    })
}

/// Suggest a retry only when the rejected link currently resolves to a regular file.
fn resolved_regular_file(path: &Path) -> Option<PathBuf> {
    // A missing or unreadable target changes only the recovery hint.
    let resolved = fs::canonicalize(path).ok()?;
    let target = fs::symlink_metadata(&resolved).ok()?;
    target.file_type().is_file().then_some(resolved)
}

fn open_no_follow(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    platform::no_follow(&mut options);
    options.open(path)
}

#[cfg(unix)]
mod platform {
    use std::fs::{File, Metadata, OpenOptions};
    use std::io;
    use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};

    pub(super) fn supported() -> io::Result<()> {
        Ok(())
    }

    pub(super) fn no_follow(options: &mut OpenOptions) {
        // `O_NONBLOCK` keeps a FIFO swapped in after validation from
        // blocking the open; the descriptor check then rejects it.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }

    pub(super) fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        file.read_at(buffer, offset)
    }

    pub(super) fn same_identity(left: &Metadata, right: &Metadata) -> bool {
        left.dev() == right.dev() && left.ino() == right.ino()
    }

    /// Upstream reference: `sameRegularFileState` in
    /// `upstream:src/filesystem/RegularFile.ts` (nanosecond precision).
    pub(super) fn same_regular_file_state(expected: &Metadata, observed: &Metadata) -> bool {
        observed.file_type().is_file()
            && same_identity(expected, observed)
            && expected.size() == observed.size()
            && expected.mode() == observed.mode()
            && expected.mtime() == observed.mtime()
            && expected.mtime_nsec() == observed.mtime_nsec()
            && expected.ctime() == observed.ctime()
            && expected.ctime_nsec() == observed.ctime_nsec()
    }
}

#[cfg(not(unix))]
mod platform {
    //! Non-Unix hosts lack stable `dev`/`ino` identity in `std`; reads are
    //! refused until a native identity check is ported.

    use std::fs::{File, Metadata, OpenOptions};
    use std::io;

    pub(super) fn supported() -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "stable artifact reads are not yet ported to this host",
        ))
    }

    pub(super) fn no_follow(_options: &mut OpenOptions) {}

    pub(super) fn read_at(_file: &File, _buffer: &mut [u8], _offset: u64) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub(super) fn same_identity(_left: &Metadata, _right: &Metadata) -> bool {
        false
    }

    pub(super) fn same_regular_file_state(_expected: &Metadata, _observed: &Metadata) -> bool {
        false
    }
}
