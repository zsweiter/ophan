use bytes::{BufMut, Bytes, BytesMut};
use http::{Version, request::Parts};

const SPACE: u8 = b' ';
pub const CRLF: &[u8; 2] = b"\r\n";
pub const HEADER_KV_DELIMITER: &[u8; 2] = b": ";

const HOST_HEADER: &[u8] = b"Host: ";

/// Encodes an HTTP/1.x request line and header block into wire format.
///
/// Returns an immutable `Bytes` handle. Does not handle body transmission,
/// allowing the transport layer to stream or send body chunks separately.
pub fn http_req_header_to_wire(req: &Parts) -> Result<Bytes, &'static str> {
    let version_str = match req.version {
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 | Version::HTTP_09 => "HTTP/1.1", // Default fallback to 1.1
        _ => return Err("Http1 wire encoder only supports HTTP/1.0 and HTTP/1.1"),
    };

    let path_and_query = req.uri.path_and_query().map_or("/", |pq| pq.as_str());
    let authority = req.uri.authority().map(|a| a.as_str());

    let mut buf = BytesMut::with_capacity(512);

    // Request Line: <METHOD> SP <path> SP <VERSION> CRLF
    buf.put_slice(req.method.as_str().as_bytes());
    buf.put_u8(SPACE);
    buf.put_slice(path_and_query.as_bytes());
    buf.put_u8(SPACE);
    buf.put_slice(version_str.as_bytes());
    buf.put_slice(CRLF);

    // Host Header (from URI authority)
    if let Some(auth) = authority {
        buf.put_slice(HOST_HEADER);
        buf.put_slice(auth.as_bytes());
        buf.put_slice(CRLF);
    }

    // Headers
    for (name, value) in req.headers.iter() {
        buf.put_slice(name.as_str().as_bytes());
        buf.put_slice(HEADER_KV_DELIMITER);
        buf.put_slice(value.as_bytes());
        buf.put_slice(CRLF);
    }

    // Header Frame End
    buf.put_slice(CRLF);

    // Convert BytesMut to Bytes (Zero-copy, O(1))
    Ok(buf.freeze())
}
