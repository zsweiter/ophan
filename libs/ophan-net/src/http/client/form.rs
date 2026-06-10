use std::sync::atomic::AtomicU64;

use bytes::Bytes;

static BOUNDARY_COUNTER: AtomicU64 = AtomicU64::new(0);

fn generate_boundary() -> String {
    let count = BOUNDARY_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = std::process::id();
    let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    format!("ophan_boundary_{pid}_{time}_{count}")
}

enum MultipartField {
    Text {
        name: String,
        value: String,
    },
    File {
        name: String,
        filename: String,
        content_type: String,
        data: Bytes,
    },
}

/// Builds a `multipart/form-data` body.
///
/// Supports text fields and file uploads.  Finish with `.finish()`
/// which returns `(body_bytes, content_type_header_value)`.
pub struct MultipartBuilder {
    fields: Vec<MultipartField>,
}

impl MultipartBuilder {
    pub fn new() -> Self {
        Self { fields: Vec::new() }
    }

    pub fn field(mut self, name: &str, value: &str) -> Self {
        self.fields.push(MultipartField::Text { name: name.to_owned(), value: value.to_owned() });
        self
    }

    pub fn file(mut self, name: &str, filename: &str, content_type: &str, data: Bytes) -> Self {
        self.fields.push(MultipartField::File {
            name: name.to_owned(),
            filename: filename.to_owned(),
            content_type: content_type.to_owned(),
            data,
        });
        self
    }

    pub fn finish(self) -> (Bytes, String) {
        let boundary = generate_boundary();
        let mut body = Vec::new();

        for field in &self.fields {
            body.extend_from_slice(b"--");
            body.extend_from_slice(boundary.as_bytes());
            body.extend_from_slice(b"\r\n");

            match field {
                MultipartField::Text { name, value } => {
                    body.extend_from_slice(b"Content-Disposition: form-data; name=\"");
                    body.extend_from_slice(name.as_bytes());
                    body.extend_from_slice(b"\"\r\n\r\n");
                    body.extend_from_slice(value.as_bytes());
                    body.extend_from_slice(b"\r\n");
                },
                MultipartField::File { name, filename, content_type, data } => {
                    body.extend_from_slice(b"Content-Disposition: form-data; name=\"");
                    body.extend_from_slice(name.as_bytes());
                    body.extend_from_slice(b"\"; filename=\"");
                    body.extend_from_slice(filename.as_bytes());
                    body.extend_from_slice(b"\"\r\nContent-Type: ");
                    body.extend_from_slice(content_type.as_bytes());
                    body.extend_from_slice(b"\r\n\r\n");
                    body.extend_from_slice(data);
                    body.extend_from_slice(b"\r\n");
                },
            }
        }

        body.extend_from_slice(b"--");
        body.extend_from_slice(boundary.as_bytes());
        body.extend_from_slice(b"--\r\n");

        (Bytes::from(body), format!("multipart/form-data; boundary={}", boundary))
    }
}

impl Default for MultipartBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_text_only() {
        let form = MultipartBuilder::new().field("name", "foo").field("age", "30");
        let (body, ct) = form.finish();
        assert!(ct.starts_with("multipart/form-data; boundary="));
        let boundary = ct.trim_start_matches("multipart/form-data; boundary=");
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains(&format!("--{boundary}")));
        assert!(text.contains("name=\"name\""));
        assert!(text.contains("foo"));
        assert!(text.contains(&format!("--{boundary}--")));
    }

    #[test]
    fn multipart_with_file() {
        let data = Bytes::from_static(b"file content here");
        let form = MultipartBuilder::new().field("title", "photo").file("upload", "pic.png", "image/png", data);
        let (body, ct) = form.finish();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("Content-Disposition: form-data; name=\"title\""));
        assert!(text.contains("Content-Disposition: form-data; name=\"upload\"; filename=\"pic.png\""));
        assert!(text.contains("Content-Type: image/png"));
        assert!(text.contains("file content here"));
        assert!(ct.starts_with("multipart/form-data; boundary="));
    }

    #[test]
    fn boundaries_are_unique() {
        let (_, ct1) = MultipartBuilder::new().field("a", "1").finish();
        let (_, ct2) = MultipartBuilder::new().field("b", "2").finish();
        assert_ne!(ct1, ct2);
    }
}
