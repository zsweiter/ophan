use http::{HeaderMap, HeaderValue, header};
use std::fs::Metadata;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut etag = String::with_capacity(64);

        etag.push('"');
        push_hex(meta.len(), &mut etag);
        etag.push('-');
        push_hex(mtime, &mut etag);
        etag.push('-');
        push_hex(0, &mut etag);
        etag.push('"');

        HeaderValue::from_maybe_shared(etag).unwrap_or_else(|_| HeaderValue::from_static("\"0\""))
    }
}

/// Precomputed `Last-Modified` validator.
#[derive(Debug, Clone)]
pub struct LastModified {
    /// RFC 9110 IMF-fixdate header value.
    pub value: HeaderValue,
    /// Modification time truncated to whole seconds, as carried by the header.
    pub time: SystemTime,
}

impl LastModified {
    #[inline]
    pub fn from_metadata(meta: &Metadata) -> Option<Self> {
        let modified = meta.modified().ok()?;
        let secs = modified.duration_since(UNIX_EPOCH).ok()?.as_secs();
        let time = UNIX_EPOCH + Duration::from_secs(secs);
        let value = HeaderValue::from_maybe_shared(httpdate::fmt_http_date(time)).ok()?;

        Some(Self { value, time })
    }

    #[inline]
    fn parse_date(&self, raw: &HeaderValue) -> Option<SystemTime> {
        if raw.as_bytes() == self.value.as_bytes() {
            return Some(self.time);
        }
        httpdate::parse_http_date(raw.to_str().ok()?).ok()
    }
}

/// Evaluate If-None-Match / If-Modified-Since (RFC 9110 §13.2.2).
/// Returns true when the client already has a fresh representation → 304.
#[inline]
pub fn is_not_modified(headers: &HeaderMap, etag: &HeaderValue, last_mod: Option<&LastModified>) -> bool {
    let mut if_none_match = headers.get_all(header::IF_NONE_MATCH).iter().peekable();

    // If-None-Match takes precedence; when present If-Modified-Since is ignored.
    if if_none_match.peek().is_some() {
        return if_none_match.any(|value| etag_list_matches_weak(value.as_bytes(), etag.as_bytes()));
    }

    if let (Some(ims), Some(lm)) = (headers.get(header::IF_MODIFIED_SINCE), last_mod)
        && let Some(ims_date) = lm.parse_date(ims)
    {
        return lm.time <= ims_date;
    }

    false
}

/// Evaluate If-Range (RFC 9110 §13.1.5).
/// Returns true when the Range header may be honoured.
#[inline]
pub fn if_range_allows(headers: &HeaderMap, etag: &HeaderValue, last_mod: Option<&LastModified>) -> bool {
    let Some(value) = headers.get(header::IF_RANGE) else {
        return true;
    };

    let raw = trim_ows(value.as_bytes());

    if raw.starts_with(b"\"") || raw.starts_with(b"W/") {
        return strong_eq(raw, etag.as_bytes());
    }

    match (last_mod, httpdate::parse_http_date(value.to_str().unwrap_or(""))) {
        (Some(lm), Ok(date)) => lm.time == date,
        _ => false,
    }
}

/// Strong comparison: both validators must be strong and byte-identical.
#[inline]
fn strong_eq(a: &[u8], b: &[u8]) -> bool {
    !a.starts_with(b"W/") && !b.starts_with(b"W/") && a == b
}

/// Weak comparison against every member of an `If-None-Match` field value.
fn etag_list_matches_weak(list: &[u8], etag: &[u8]) -> bool {
    let target = opaque_tag(etag);
    let mut rest = list;

    loop {
        rest = trim_start(rest, |b| b == b' ' || b == b'\t' || b == b',');
        if rest.is_empty() {
            return false;
        }

        if rest[0] == b'*' {
            return true;
        }

        let tag_start = if rest.starts_with(b"W/") { 2 } else { 0 };
        if rest.get(tag_start) != Some(&b'"') {
            return false;
        }

        let Some(close) = rest[tag_start + 1..].iter().position(|&b| b == b'"') else {
            return false;
        };

        let end = tag_start + 1 + close + 1;
        if &rest[tag_start..end] == target {
            return true;
        }

        rest = &rest[end..];
    }
}

#[inline]
fn opaque_tag(etag: &[u8]) -> &[u8] {
    etag.strip_prefix(b"W/").unwrap_or(etag)
}

#[inline]
fn trim_start(bytes: &[u8], pred: impl Fn(u8) -> bool) -> &[u8] {
    let start = bytes.iter().position(|&b| !pred(b)).unwrap_or(bytes.len());
    &bytes[start..]
}

#[inline]
fn trim_ows(bytes: &[u8]) -> &[u8] {
    let is_ows = |b: &u8| *b == b' ' || *b == b'\t';
    let start = bytes.iter().position(|b| !is_ows(b)).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|b| !is_ows(b)).map_or(start, |e| e + 1);
    &bytes[start..end]
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
    use std::io::Write;
    use tempfile::NamedTempFile;

    use super::*;

    fn temp_file(content: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content).unwrap();
        file.flush().unwrap();
        file
    }

    fn last_mod_at(secs: u64) -> LastModified {
        let time = UNIX_EPOCH + Duration::from_secs(secs);
        LastModified {
            value: HeaderValue::from_str(&httpdate::fmt_http_date(time)).unwrap(),
            time,
        }
    }

    fn headers(pairs: &[(header::HeaderName, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(name.clone(), HeaderValue::from_static(value));
        }
        map
    }

    fn etag() -> HeaderValue {
        HeaderValue::from_static("\"abc-123-456\"")
    }

    #[test]
    fn create_etag_format() {
        let path = temp_file(b"hello world");
        let meta = path.as_file().metadata().unwrap();
        let etag = create_etag(&meta);

        let etag_str = etag.to_str().unwrap();
        assert!(etag_str.starts_with('"'));
        assert!(etag_str.ends_with('"'));

        let inner = &etag_str[1..etag_str.len() - 1];
        let parts: Vec<&str> = inner.split('-').collect();
        assert_eq!(parts.len(), 3, "etag should have 3 parts: size-mtime-inode");
    }

    #[test]
    fn create_etag_consistent_for_same_file() {
        let path = temp_file(b"test data");
        let meta = path.as_file().metadata().unwrap();

        let etag1 = create_etag(&meta);
        let etag2 = create_etag(&meta);

        assert_eq!(etag1, etag2);
    }

    #[test]
    fn last_modified_from_metadata() {
        let path = temp_file(b"data");
        let meta = path.as_file().metadata().unwrap();

        let lm = LastModified::from_metadata(&meta).unwrap();
        let parsed = httpdate::parse_http_date(lm.value.to_str().unwrap()).unwrap();
        assert_eq!(parsed, lm.time);
    }

    #[test]
    fn is_not_modified_etag_match() {
        let h = headers(&[(header::IF_NONE_MATCH, "\"abc-123-456\"")]);
        assert!(is_not_modified(&h, &etag(), None));
    }

    #[test]
    fn is_not_modified_etag_star() {
        let h = headers(&[(header::IF_NONE_MATCH, "*")]);
        assert!(is_not_modified(&h, &etag(), None));
    }

    #[test]
    fn is_not_modified_etag_mismatch() {
        let h = headers(&[(header::IF_NONE_MATCH, "\"different-etag\"")]);
        assert!(!is_not_modified(&h, &etag(), None));
    }

    #[test]
    fn is_not_modified_etag_list() {
        let h = headers(&[(header::IF_NONE_MATCH, "\"x\", \"abc-123-456\" ,\"y\"")]);
        assert!(is_not_modified(&h, &etag(), None));

        let h = headers(&[(header::IF_NONE_MATCH, "\"x\",\"y\"")]);
        assert!(!is_not_modified(&h, &etag(), None));

        let h = headers(&[(header::IF_NONE_MATCH, "\"a,b\", \"abc-123-456\"")]);
        assert!(is_not_modified(&h, &etag(), None));
    }

    #[test]
    fn is_not_modified_etag_multiple_fields() {
        let h = headers(&[(header::IF_NONE_MATCH, "\"x\""), (header::IF_NONE_MATCH, "\"abc-123-456\"")]);
        assert!(is_not_modified(&h, &etag(), None));
    }

    #[test]
    fn is_not_modified_weak_comparison() {
        let h = headers(&[(header::IF_NONE_MATCH, "W/\"abc-123-456\"")]);
        assert!(is_not_modified(&h, &etag(), None));

        let h = headers(&[(header::IF_NONE_MATCH, "\"x\", W/\"abc-123-456\"")]);
        assert!(is_not_modified(&h, &etag(), None));
    }

    #[test]
    fn is_not_modified_malformed_list() {
        let h = headers(&[(header::IF_NONE_MATCH, "abc-123-456")]);
        assert!(!is_not_modified(&h, &etag(), None));

        let h = headers(&[(header::IF_NONE_MATCH, "\"abc-123-456")]);
        assert!(!is_not_modified(&h, &etag(), None));
    }

    #[test]
    fn if_none_match_overrides_if_modified_since() {
        let lm = last_mod_at(1_700_000_000);
        let mut h = headers(&[(header::IF_NONE_MATCH, "\"other\"")]);
        h.insert(header::IF_MODIFIED_SINCE, lm.value.clone());
        assert!(!is_not_modified(&h, &etag(), Some(&lm)));
    }

    #[test]
    fn is_not_modified_if_modified_since_future() {
        let lm = last_mod_at(1_700_000_000);
        let ims = last_mod_at(1_710_000_000);

        let mut h = HeaderMap::new();
        h.insert(header::IF_MODIFIED_SINCE, ims.value);

        assert!(is_not_modified(&h, &etag(), Some(&lm)));
    }

    #[test]
    fn is_not_modified_if_modified_since_exact() {
        let lm = last_mod_at(1_700_000_000);

        let mut h = HeaderMap::new();
        h.insert(header::IF_MODIFIED_SINCE, lm.value.clone());

        assert!(is_not_modified(&h, &etag(), Some(&lm)));
    }

    #[test]
    fn is_not_modified_if_modified_since_past() {
        let lm = last_mod_at(1_710_000_000);
        let ims = last_mod_at(1_700_000_000);

        let mut h = HeaderMap::new();
        h.insert(header::IF_MODIFIED_SINCE, ims.value);

        assert!(!is_not_modified(&h, &etag(), Some(&lm)));
    }

    #[test]
    fn is_not_modified_if_modified_since_invalid() {
        let lm = last_mod_at(1_700_000_000);
        let h = headers(&[(header::IF_MODIFIED_SINCE, "yesterday")]);

        assert!(!is_not_modified(&h, &etag(), Some(&lm)));
    }

    #[test]
    fn is_not_modified_no_headers() {
        let h = HeaderMap::new();
        assert!(!is_not_modified(&h, &etag(), None));
    }

    #[test]
    fn if_range_absent_allows() {
        assert!(if_range_allows(&HeaderMap::new(), &etag(), None));
    }

    #[test]
    fn if_range_etag() {
        let h = headers(&[(header::IF_RANGE, "\"abc-123-456\"")]);
        assert!(if_range_allows(&h, &etag(), None));

        let h = headers(&[(header::IF_RANGE, "\"other\"")]);
        assert!(!if_range_allows(&h, &etag(), None));

        let h = headers(&[(header::IF_RANGE, "W/\"abc-123-456\"")]);
        assert!(!if_range_allows(&h, &etag(), None));
    }

    #[test]
    fn if_range_date() {
        let lm = last_mod_at(1_700_000_000);

        let mut h = HeaderMap::new();
        h.insert(header::IF_RANGE, lm.value.clone());
        assert!(if_range_allows(&h, &etag(), Some(&lm)));

        h.insert(header::IF_RANGE, last_mod_at(1_700_000_001).value);
        assert!(!if_range_allows(&h, &etag(), Some(&lm)));

        let h = headers(&[(header::IF_RANGE, "garbage")]);
        assert!(!if_range_allows(&h, &etag(), Some(&lm)));
    }
}
