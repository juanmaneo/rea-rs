//! Typed host error codes that change how a selected-path failure is reported.
//!
//! Upstream reference: `UNRESOLVED_PATH_ERROR_CODES` and
//! `SELECTED_REGULAR_FILE_ERROR_CODES` in `upstream:src/filesystem/RegularFile.ts`,
//! and `artifactSelectedPathErrno` in
//! `upstream:src/artifacts/ArtifactFileOperation.ts`.

use std::io;

/// Whether an `open` with `O_NOFOLLOW` failed because the final path
/// component is a symlink.
///
/// Linux reports `ELOOP`; FreeBSD reports `EMLINK`. `EMLINK` keeps its usual
/// "too many links" meaning everywhere else, so this applies only to the
/// result of an `O_NOFOLLOW` open and is not folded into [`ErrnoCode`].
/// Upstream checks `ELOOP` only.
#[cfg(unix)]
pub fn is_no_follow_symlink(error: &io::Error) -> bool {
    match error.raw_os_error() {
        Some(libc::ELOOP) => true,
        #[cfg(target_os = "freebsd")]
        Some(libc::EMLINK) => true,
        _ => false,
    }
}

/// Whether an `open` with `O_NOFOLLOW` failed because the final path
/// component is a symlink.
#[cfg(not(unix))]
pub fn is_no_follow_symlink(_error: &io::Error) -> bool {
    false
}

/// A host error code REA classifies; other codes stay opaque I/O failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrnoCode {
    /// `ENOENT`.
    Enoent,
    /// `ENOTDIR`.
    Enotdir,
    /// `ELOOP`.
    Eloop,
    /// `ENAMETOOLONG`.
    Enametoolong,
    /// `EISDIR`.
    Eisdir,
    /// `ESTALE`.
    Estale,
    /// `EACCES`.
    Eacces,
    /// `EPERM`.
    Eperm,
}

impl ErrnoCode {
    /// Classify an I/O error by its raw OS error number.
    pub fn of(error: &io::Error) -> Option<Self> {
        Self::from_raw_os_error(error.raw_os_error()?)
    }

    /// Classify a raw OS error number.
    #[cfg(unix)]
    pub fn from_raw_os_error(code: i32) -> Option<Self> {
        Some(match code {
            libc::ENOENT => Self::Enoent,
            libc::ENOTDIR => Self::Enotdir,
            libc::ELOOP => Self::Eloop,
            libc::ENAMETOOLONG => Self::Enametoolong,
            libc::EISDIR => Self::Eisdir,
            libc::ESTALE => Self::Estale,
            libc::EACCES => Self::Eacces,
            libc::EPERM => Self::Eperm,
            _ => return None,
        })
    }

    /// Classify a raw OS error number.
    #[cfg(not(unix))]
    pub fn from_raw_os_error(_code: i32) -> Option<Self> {
        None
    }

    /// The POSIX name, as Node.js reports it in `error.code`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enoent => "ENOENT",
            Self::Enotdir => "ENOTDIR",
            Self::Eloop => "ELOOP",
            Self::Enametoolong => "ENAMETOOLONG",
            Self::Eisdir => "EISDIR",
            Self::Estale => "ESTALE",
            Self::Eacces => "EACCES",
            Self::Eperm => "EPERM",
        }
    }

    /// Whether the code establishes that nothing resolves at the path as written.
    pub const fn is_unresolved_path(self) -> bool {
        matches!(
            self,
            Self::Enoent | Self::Enotdir | Self::Eloop | Self::Enametoolong
        )
    }

    /// Whether the code identifies the selected path or file itself rather
    /// than the host.
    pub const fn is_selected_regular_file(self) -> bool {
        self.is_unresolved_path() || matches!(self, Self::Eisdir | Self::Estale)
    }
}
