use http::{HeaderValue, header};
use std::fs::Metadata;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// Build a strong ETag from size + mtime + inode.
///
/// Format: `"<hex-size>-<hex-mtime>-<hex-inode>"`
///
/// Example: `"3fa-66b69d7e-15d2"`
///
#[inline]
pub fn create_etag(meta: &Metadata) -> HeaderValue {
    #[cfg(unix)]
    {
        let mut etag = String::with_capacity(64);

        etag.push('"');
        push_hex(meta.size(), &mut etag);
        etag.push('-');
        push_hex(meta.mtime() as u64, &mut etag);
        etag.push('-');
        push_hex(meta.ino(), &mut etag);
        etag.push('"');

        HeaderValue::from_maybe_shared(etag).unwrap_or_else(|_| HeaderValue::from_static("\"0\""))
    }

    #[cfg(not(unix))]
    {
        use std::time::UNIX_EPOCH;

        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut etag = String::with_capacity(64);

        etag.push('"');
        push_hex(meta.size(), &mut etag);
        etag.push('-');
        push_hex(mtime as u64, &mut etag);
        etag.push('-');
        push_hex(0, &mut etag);
        etag.push('"');

        HeaderValue::from_maybe_shared(etag).unwrap_or_else(|_| HeaderValue::from_static("\"0\""))
    }
}

/// RFC 7232 Last-Modified value (IMF-fixdate).
#[inline]
pub fn last_modified_header(meta: &Metadata) -> Option<HeaderValue> {
    let modified = meta.modified().ok()?;
    let datetime = httpdate::HttpDate::from(modified);
    HeaderValue::from_maybe_shared(datetime.to_string()).ok()
}

/// Check If-None-Match / If-Modified-Since.
/// Returns true when the client already has a fresh representation → 304.
#[inline]
pub fn is_not_modified(headers: &http::HeaderMap, etag: &HeaderValue, last_mod: Option<&HeaderValue>) -> bool {
    // If-None-Match takes precedence (RFC 7232 §3.2)
    if let Some(inm) = headers.get(header::IF_NONE_MATCH) {
        // Simple exact match; for multi-etag we could split, but most clients send one
        if inm == etag || inm.as_bytes() == b"*" {
            return true;
        }
        return false; // present but not matching → must revalidate
    }

    // Fallback to If-Modified-Since
    if let (Some(ims), Some(lm)) = (headers.get(header::IF_MODIFIED_SINCE), last_mod) {
        // If the resource's Last-Modified is ≤ If-Modified-Since → not modified
        if let (Ok(ims_date), Ok(lm_date)) = (
            httpdate::parse_http_date(ims.to_str().unwrap_or("")),
            httpdate::parse_http_date(lm.to_str().unwrap_or("")),
        ) {
            return lm_date <= ims_date;
        }
    }

    false
}

const HEX: &[u8; 16] = b"0123456789abcdef";

#[inline]
fn push_hex(mut value: u64, out: &mut String) {
    if value == 0 {
        out.push('0');
        return;
    }

    let mut buf = [0u8; 16];
    let mut i = 16;

    while value != 0 {
        i -= 1;
        buf[i] = HEX[(value & 0xf) as usize];
        value >>= 4;
    }

    // SAFETY: HEX only contains valid ASCII characters.
    unsafe {
        out.push_str(std::str::from_utf8_unchecked(&buf[i..]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Duration, SystemTime};

    fn temp_file(name: &str, content: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("ophan_conditional_test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn create_etag_format() {
        let path = temp_file("etag_test.txt", b"hello world");
        let meta = fs::metadata(&path).unwrap();
        let etag = create_etag(&meta);

        let etag_str = etag.to_str().unwrap();
        assert!(etag_str.starts_with('"'));
        assert!(etag_str.ends_with('"'));

        let inner = &etag_str[1..etag_str.len() - 1];
        let parts: Vec<&str> = inner.split('-').collect();
        assert_eq!(parts.len(), 3, "etag should have 3 parts: size-mtime-inode");

        let _ = fs::remove_dir_all(dir_name(&path));
    }

    #[test]
    fn create_etag_consistent_for_same_file() {
        let path = temp_file("etag_consistent.txt", b"test data");
        let meta = fs::metadata(&path).unwrap();

        let etag1 = create_etag(&meta);
        let etag2 = create_etag(&meta);

        assert_eq!(etag1, etag2);
        let _ = fs::remove_dir_all(dir_name(&path));
    }

    #[test]
    fn last_modified_header_returns_value() {
        let path = temp_file("lm_test.txt", b"data");
        let meta = fs::metadata(&path).unwrap();

        let lm = last_modified_header(&meta);
        assert!(lm.is_some());

        let lm_str = lm.unwrap().to_str().unwrap().to_string();
        assert!(!lm_str.is_empty());
        let _ = fs::remove_dir_all(dir_name(&path));
    }

    #[test]
    fn is_not_modified_etag_match() {
        let etag = HeaderValue::from_static("\"abc-123-456\"");
        let mut headers = http::HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, etag.clone());

        assert!(is_not_modified(&headers, &etag, None));
    }

    #[test]
    fn is_not_modified_etag_star() {
        let etag = HeaderValue::from_static("\"abc-123-456\"");
        let mut headers = http::HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));

        assert!(is_not_modified(&headers, &etag, None));
    }

    #[test]
    fn is_not_modified_etag_mismatch() {
        let etag = HeaderValue::from_static("\"abc-123-456\"");
        let mut headers = http::HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("\"different-etag\""));

        assert!(!is_not_modified(&headers, &etag, None));
    }

    #[test]
    fn is_not_modified_if_modified_since_future() {
        let etag = HeaderValue::from_static("\"abc-123-456\"");

        let lm_date = httpdate::HttpDate::from(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let ims_date = httpdate::HttpDate::from(SystemTime::UNIX_EPOCH + Duration::from_secs(1_710_000_000));

        let lm = HeaderValue::from_maybe_shared(lm_date.to_string()).unwrap();
        let ims = HeaderValue::from_maybe_shared(ims_date.to_string()).unwrap();

        let mut headers = http::HeaderMap::new();
        headers.insert(header::IF_MODIFIED_SINCE, ims);

        assert!(is_not_modified(&headers, &etag, Some(&lm)));
    }

    #[test]
    fn is_not_modified_if_modified_since_past() {
        let lm_date = httpdate::HttpDate::from(SystemTime::UNIX_EPOCH + Duration::from_secs(1_710_000_000));
        let ims_date = httpdate::HttpDate::from(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000));

        let lm = HeaderValue::from_maybe_shared(lm_date.to_string()).unwrap();
        let ims = HeaderValue::from_maybe_shared(ims_date.to_string()).unwrap();

        let mut headers = http::HeaderMap::new();
        headers.insert(header::IF_MODIFIED_SINCE, ims);

        assert!(!is_not_modified(&headers, &lm, Some(&lm)));
    }

    #[test]
    fn is_not_modified_no_headers() {
        let etag = HeaderValue::from_static("\"abc-123-456\"");
        let headers = http::HeaderMap::new();

        assert!(!is_not_modified(&headers, &etag, None));
    }

    fn dir_name(path: &std::path::Path) -> std::path::PathBuf {
        path.parent().unwrap().to_path_buf()
    }
}
