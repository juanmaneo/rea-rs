//! Making a caller-selected local path absolute without changing which file
//! it names.
//!
//! POSIX resolves `..` after following the preceding symlink, so lexical
//! normalization of `link/../file` can select a different file. Only interior
//! `.` segments and repeated separators are removed, which never change the
//! named file; every `..` is kept for the filesystem to resolve, and a
//! trailing `/` or `/.` keeps its directory requirement as one trailing `/`.
//! Absolute paths never need the ambient working directory, which may
//! already have been removed during cleanup.
//!
//! Upstream reference: `absoluteCallerPath` in `upstream:src/filesystem/callerPath.ts`
//! (POSIX branch; the Win32 branch is not ported).

/// Why a relative path could not be made absolute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("A relative path needs an absolute working directory to resolve against.")]
pub struct RelativeWorkingDirectory;

/// Resolve `path` against `working_directory`, which is consulted only when
/// `path` is relative. A relative `working_directory` is not accepted.
pub fn absolute_caller_path(
    path: &str,
    working_directory: impl FnOnce() -> Option<String>,
) -> Result<String, RelativeWorkingDirectory> {
    if path.starts_with('/') {
        return Ok(normalize_absolute(path));
    }
    let base = working_directory().ok_or(RelativeWorkingDirectory)?;
    if !base.starts_with('/') {
        return Err(RelativeWorkingDirectory);
    }
    Ok(normalize_absolute(&format!("{base}/{path}")))
}

fn normalize_absolute(path: &str) -> String {
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect();
    let directory = !segments.is_empty() && (path.ends_with('/') || path.ends_with("/."));
    let mut normalized = format!("/{}", segments.join("/"));
    if directory {
        normalized.push('/');
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(path: &str) -> String {
        absolute_caller_path(path, || Some("/work/dir".to_owned())).unwrap()
    }

    #[test]
    fn removes_only_interior_dot_segments_and_repeated_separators() {
        assert_eq!(resolve("/a//b/./c"), "/a/b/c");
        assert_eq!(resolve("/"), "/");
        assert_eq!(resolve("/./"), "/");
    }

    #[test]
    fn keeps_parent_segments_for_the_filesystem_to_resolve() {
        assert_eq!(resolve("/link/../file"), "/link/../file");
        assert_eq!(resolve("../up"), "/work/dir/../up");
    }

    #[test]
    fn preserves_a_directory_requirement_as_one_trailing_separator() {
        assert_eq!(resolve("/a/b/"), "/a/b/");
        assert_eq!(resolve("/a/b/."), "/a/b/");
        assert_eq!(resolve("/a/b//"), "/a/b/");
        assert_eq!(resolve("/a/b/./"), "/a/b/");
    }

    #[test]
    fn resolves_relative_paths_against_the_working_directory() {
        assert_eq!(resolve("unsigned"), "/work/dir/unsigned");
        assert_eq!(resolve("./x/./y"), "/work/dir/x/y");
        assert_eq!(resolve("x/"), "/work/dir/x/");
        assert_eq!(
            absolute_caller_path("x", || Some("/work/dir/".to_owned())).unwrap(),
            "/work/dir/x"
        );
    }

    #[test]
    fn never_consults_the_working_directory_for_an_absolute_path() {
        assert_eq!(
            absolute_caller_path("/a", || panic!("working directory consulted")),
            Ok("/a".to_owned())
        );
    }

    #[test]
    fn refuses_a_relative_path_without_an_absolute_working_directory() {
        assert_eq!(
            absolute_caller_path("x", || None),
            Err(RelativeWorkingDirectory)
        );
        assert_eq!(
            absolute_caller_path("x", || Some("relative".to_owned())),
            Err(RelativeWorkingDirectory)
        );
    }
}
