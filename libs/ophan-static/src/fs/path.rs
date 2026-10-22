use std::path::{Path, PathBuf};

/// Reasons a request path cannot be mapped onto the document root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// Malformed percent-encoding, non UTF-8 bytes, NUL, encoded separators or dot segments.
    Malformed,
    /// A segment names a hidden file or directory while dotfiles are disabled.
    Hidden,
}

/// Map a raw (percent-encoded) URI path onto `root`.
///
/// Every segment is decoded on its own so an encoded `/` can never introduce a new
/// path component. Empty segments are skipped; `.` and `..` segments, raw or decoded,
/// are rejected instead of resolved so the result is always lexically inside `root`.
pub fn resolve(root: &Path, uri_path: &str, allow_dotfiles: bool) -> Result<PathBuf, PathError> {
    let mut resolved = PathBuf::with_capacity(root.as_os_str().len() + uri_path.len() + 1);
    resolved.push(root);

    let mut scratch: Vec<u8> = Vec::new();

    for raw in uri_path.split('/') {
        if raw.is_empty() {
            continue;
        }

        let segment: &str = if raw.as_bytes().contains(&b'%') {
            scratch.clear();
            percent_decode(raw.as_bytes(), &mut scratch)?;
            std::str::from_utf8(&scratch).map_err(|_| PathError::Malformed)?
        } else {
            raw
        };

        check_segment(segment, allow_dotfiles)?;
        resolved.push(segment);
    }

    Ok(resolved)
}

#[inline]
fn check_segment(segment: &str, allow_dotfiles: bool) -> Result<(), PathError> {
    if segment == "." || segment == ".." {
        return Err(PathError::Malformed);
    }

    if segment.bytes().any(|b| matches!(b, b'\0' | b'/' | b'\\')) {
        return Err(PathError::Malformed);
    }

    if !allow_dotfiles && segment.starts_with('.') {
        return Err(PathError::Hidden);
    }

    Ok(())
}

#[inline]
fn percent_decode(input: &[u8], out: &mut Vec<u8>) -> Result<(), PathError> {
    out.reserve(input.len());

    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b == b'%' {
            let hi = input.get(i + 1).copied().and_then(hex_val).ok_or(PathError::Malformed)?;
            let lo = input.get(i + 2).copied().and_then(hex_val).ok_or(PathError::Malformed)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }

    Ok(())
}

#[inline]
const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(uri: &str) -> PathBuf {
        resolve(Path::new("/srv"), uri, false).unwrap()
    }

    fn err(uri: &str) -> PathError {
        resolve(Path::new("/srv"), uri, false).unwrap_err()
    }

    #[test]
    fn plain_paths() {
        assert_eq!(ok("/"), PathBuf::from("/srv"));
        assert_eq!(ok(""), PathBuf::from("/srv"));
        assert_eq!(ok("/a/b.txt"), PathBuf::from("/srv/a/b.txt"));
        assert_eq!(ok("//a///b/"), PathBuf::from("/srv/a/b"));
    }

    #[test]
    fn decodes_percent_escapes() {
        assert_eq!(ok("/my%20file.txt"), PathBuf::from("/srv/my file.txt"));
        assert_eq!(ok("/%C3%A9t%c3%a9"), PathBuf::from("/srv/été"));
        assert_eq!(ok("/a+b"), PathBuf::from("/srv/a+b"));
        assert_eq!(ok("/100%25"), PathBuf::from("/srv/100%"));
    }

    #[test]
    fn rejects_bad_escapes() {
        assert_eq!(err("/%"), PathError::Malformed);
        assert_eq!(err("/%2"), PathError::Malformed);
        assert_eq!(err("/%zz"), PathError::Malformed);
        assert_eq!(err("/%ff%fe"), PathError::Malformed);
    }

    #[test]
    fn rejects_encoded_separators_and_nul() {
        assert_eq!(err("/a%2Fb"), PathError::Malformed);
        assert_eq!(err("/a%2fb"), PathError::Malformed);
        assert_eq!(err("/a%5Cb"), PathError::Malformed);
        assert_eq!(err("/a\\b"), PathError::Malformed);
        assert_eq!(err("/a%00b"), PathError::Malformed);
    }

    #[test]
    fn rejects_traversal() {
        assert_eq!(err("/../etc/passwd"), PathError::Malformed);
        assert_eq!(err("/a/./b"), PathError::Malformed);
        assert_eq!(err("/%2e%2e/etc/passwd"), PathError::Malformed);
        assert_eq!(err("/a/%2E%2E/%2e%2e/x"), PathError::Malformed);
        assert_eq!(err("/a/%2e/b"), PathError::Malformed);
        assert_eq!(err("/..%2fetc"), PathError::Malformed);
    }

    #[test]
    fn hidden_segments() {
        assert_eq!(err("/.git/config"), PathError::Hidden);
        assert_eq!(err("/a/.env"), PathError::Hidden);
        assert_eq!(err("/%2egit/config"), PathError::Hidden);
        assert_eq!(
            resolve(Path::new("/srv"), "/.git/config", true).unwrap(),
            PathBuf::from("/srv/.git/config")
        );
        assert_eq!(resolve(Path::new("/srv"), "/..", true).unwrap_err(), PathError::Malformed);
    }
}
