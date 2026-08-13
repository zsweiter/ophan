use std::path::{Component, Path, PathBuf};

/// Normalize a path lexically by removing:
///
/// - Root prefixes (`/`, `C:\`)
/// - Current directory components (`.`)
/// - Parent directory components (`..`)
///
/// This function **does not** resolve symbolic links or access the filesystem.
/// The returned path is always relative.
#[must_use]
#[inline]
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::with_capacity(path.as_os_str().len());

    for component in path.components() {
        match component {
            Component::Normal(name) => normalized.push(name),
            Component::ParentDir => {
                normalized.pop();
            },
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {},
        }
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::normalize_path;
    use std::path::{Path, PathBuf};

    #[test]
    fn empty_path() {
        assert_eq!(normalize_path(Path::new("")), PathBuf::new());
    }

    #[test]
    fn current_directory() {
        assert_eq!(normalize_path(Path::new(".")), PathBuf::new());
    }

    #[test]
    fn normal_path() {
        assert_eq!(normalize_path(Path::new("images/logo.png")), PathBuf::from("images/logo.png"),);
    }

    #[test]
    fn removes_current_directory_components() {
        assert_eq!(
            normalize_path(Path::new("./images/./logo.png")),
            PathBuf::from("images/logo.png"),
        );
    }

    #[test]
    fn resolves_parent_directory() {
        assert_eq!(
            normalize_path(Path::new("images/icons/../logo.png")),
            PathBuf::from("images/logo.png"),
        );
    }

    #[test]
    fn cannot_escape_root() {
        assert_eq!(
            normalize_path(Path::new("../../../../etc/passwd")),
            PathBuf::from("etc/passwd"),
        );
    }

    #[test]
    fn absolute_path_becomes_relative() {
        assert_eq!(normalize_path(Path::new("/etc/passwd")), PathBuf::from("etc/passwd"),);
    }

    #[test]
    fn mixed_components() {
        assert_eq!(
            normalize_path(Path::new("/var/www/../static/./css/site.css")),
            PathBuf::from("var/static/css/site.css"),
        );
    }

    #[test]
    fn parent_directory_on_empty_path_is_ignored() {
        assert_eq!(normalize_path(Path::new("..")), PathBuf::new());
    }

    #[test]
    fn multiple_parent_directories_are_ignored() {
        assert_eq!(normalize_path(Path::new("../../../")), PathBuf::new(),);
    }

    #[cfg(windows)]
    #[test]
    fn strips_windows_prefix() {
        assert_eq!(
            normalize_path(Path::new(r"C:\www\..\index.html")),
            PathBuf::from(r"index.html"),
        );
    }
}
