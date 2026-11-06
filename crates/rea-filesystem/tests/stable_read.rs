//! Stable artifact reads through the public filesystem boundary.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

use rea_domain::cancellation::CancellationSignal;
use rea_domain::digest::Sha256Digest;
use rea_domain::error::{ArtifactLimitBoundary, ArtifactOperationReason};
use rea_filesystem::{ErrnoCode, StableReadError, is_no_follow_symlink, read_stable_artifact};

fn read(
    path: &Path,
    maximum_bytes: u64,
) -> Result<rea_filesystem::StableArtifact, StableReadError> {
    read_stable_artifact(path, maximum_bytes, &CancellationSignal::new())
}

#[test]
fn reads_exact_bytes_and_digest_without_modifying_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image");
    let contents: Vec<u8> = (0..200_000_u32).map(|i| (i % 251) as u8).collect();
    fs::write(&path, &contents).unwrap();
    let before = fs::metadata(&path).unwrap();

    let snapshot = read(&path, contents.len() as u64).unwrap();

    assert_eq!(snapshot.bytes, contents);
    assert_eq!(snapshot.sha256, Sha256Digest::of(&contents));
    let after = fs::metadata(&path).unwrap();
    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
    assert_eq!(fs::read(&path).unwrap(), contents);
}

#[test]
fn recognises_the_host_errno_for_a_no_follow_open_of_a_symlink() {
    use std::os::unix::fs::OpenOptionsExt;

    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    fs::write(&target, b"x").unwrap();
    let link = dir.path().join("link");
    symlink(&target, &link).unwrap();

    let error = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&link)
        .unwrap_err();

    assert!(
        is_no_follow_symlink(&error),
        "unrecognised errno: {error:?}"
    );
    assert!(!is_no_follow_symlink(&std::io::Error::from_raw_os_error(
        libc::ENOENT
    )));
}

#[test]
fn reads_an_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty");
    fs::write(&path, b"").unwrap();
    let snapshot = read(&path, 64).unwrap();
    assert!(snapshot.bytes.is_empty());
    assert_eq!(snapshot.sha256, Sha256Digest::of(b""));
}

#[test]
fn refuses_a_file_above_the_byte_budget_before_reading() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large");
    fs::write(&path, [0_u8; 65]).unwrap();
    let error = read(&path, 64).unwrap_err();
    assert!(matches!(
        error,
        StableReadError::ExceedsLimit {
            maximum_bytes: 64,
            ..
        }
    ));
    assert_eq!(error.reason(), ArtifactOperationReason::Limit);
    assert_eq!(
        error.limit_boundary(),
        Some(ArtifactLimitBoundary::FileSize)
    );
    assert_eq!(
        error.to_string(),
        format!("Selected artifact exceeds 64 bytes: {}", path.display())
    );
}

#[test]
fn rejects_a_symlink_and_offers_its_regular_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    let link = dir.path().join("link");
    fs::write(&target, b"\x7fELF").unwrap();
    symlink(&target, &link).unwrap();

    let error = read(&link, 64).unwrap_err();
    assert_eq!(error.reason(), ArtifactOperationReason::Path);
    assert_eq!(
        error.to_string(),
        format!(
            "Expected a regular file without a symlink: {}",
            link.display()
        )
    );
    let StableReadError::NotRegularFile { resolved_path, .. } = error else {
        panic!("expected a path failure");
    };
    assert_eq!(resolved_path, Some(fs::canonicalize(&target).unwrap()));
}

#[test]
fn rejects_a_dangling_symlink_without_a_retry_hint() {
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("link");
    symlink(dir.path().join("missing"), &link).unwrap();
    let error = read(&link, 64).unwrap_err();
    assert!(matches!(
        error,
        StableReadError::NotRegularFile {
            resolved_path: None,
            ..
        }
    ));
}

#[test]
fn rejects_a_directory_and_a_fifo() {
    let dir = tempfile::tempdir().unwrap();
    let error = read(dir.path(), 64).unwrap_err();
    assert!(matches!(
        error,
        StableReadError::NotRegularFile {
            resolved_path: None,
            ..
        }
    ));

    let fifo = dir.path().join("fifo");
    let status = Command::new("mkfifo").arg(&fifo).status();
    if status.is_ok_and(|status| status.success()) {
        let error = read(&fifo, 64).unwrap_err();
        assert!(matches!(error, StableReadError::NotRegularFile { .. }));
    }
}

#[test]
fn reports_a_missing_path_as_a_classified_host_error() {
    let dir = tempfile::tempdir().unwrap();
    let error = read(&dir.path().join("missing"), 64).unwrap_err();
    assert_eq!(error.reason(), ArtifactOperationReason::Io);
    assert_eq!(error.errno(), Some(ErrnoCode::Enoent));
}

#[test]
fn reports_permission_denial_as_a_classified_host_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("locked");
    fs::write(&path, b"secret").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&path).is_ok() {
        // Privileged hosts bypass file modes.
        return;
    }
    let error = read(&path, 64).unwrap_err();
    assert_eq!(error.errno(), Some(ErrnoCode::Eacces));
}

#[test]
fn honours_cancellation_before_any_filesystem_access() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image");
    fs::write(&path, b"bytes").unwrap();
    let signal = CancellationSignal::new();
    signal.cancel();
    let error = read_stable_artifact(&path, 64, &signal).unwrap_err();
    assert!(matches!(error, StableReadError::Cancelled));
    assert_eq!(error.reason(), ArtifactOperationReason::Cancelled);
}
