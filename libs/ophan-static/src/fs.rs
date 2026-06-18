use bytes::Bytes;
use http::{Response, StatusCode, request::Parts};
use memmap2::Mmap;
use std::collections::HashSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::flags::Flags;

pub enum GlobPattern {
    Exact(String),
    Prefix(String),
    Suffix(String),
}

impl GlobPattern {
    pub fn parse(pattern: &str) -> Self {
        if pattern.starts_with('*') && pattern.ends_with('*') {
            Self::Prefix(pattern.trim_matches('*').to_string())
        } else if let Some(suffix) = pattern.strip_prefix('*') {
            Self::Suffix(suffix.to_string())
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            Self::Prefix(prefix.to_string())
        } else {
            Self::Exact(pattern.to_string())
        }
    }

    #[inline(always)]
    pub fn matches(&self, file_name: &str) -> bool {
        match self {
            Self::Exact(p) => file_name == p,
            Self::Prefix(p) => file_name.starts_with(p),
            Self::Suffix(p) => file_name.ends_with(p),
        }
    }
}

#[derive(Default)]
pub struct FileServer {}

pub struct ServeConfig {
    pub root: PathBuf,
    pub blacklist: HashSet<GlobPattern>,
    pub flags: Flags,
}

impl ServeConfig {
    pub fn new(root: PathBuf) -> Self {
        Self { root, blacklist: HashSet::new(), flags: Flags::secure() }
    }
}

impl FileServer {
    pub fn handle_request(
        &self,
        req_parts: &Parts,
        request_path: &str,
        config: ServeConfig,
    ) -> Result<Response<Bytes>, StatusCode> {
        let target_path = self.sanitize_path(request_path, &config.root).ok_or(StatusCode::FORBIDDEN)?;

        if let Some(file_name) = target_path.file_name().and_then(|n| n.to_str()) {
            if !config.flags.contains(Flags::DOTFILES) && file_name.starts_with('.') {
                return Err(StatusCode::FORBIDDEN);
            }
            for pattern in &config.blacklist {
                if pattern.matches(file_name) {
                    return Err(StatusCode::FORBIDDEN);
                }
            }
        }

        if target_path.is_file() {
            self.serve_file(req_parts, &target_path)
        } else if target_path.is_dir() {
            if config.flags.contains(Flags::LISTING) {
                self.serve_directory_listing(request_path, &target_path, &config)
            } else {
                Err(StatusCode::FORBIDDEN)
            }
        } else {
            Err(StatusCode::NOT_FOUND)
        }
    }

    fn sanitize_path(&self, requested: &str, root_path: &Path) -> Option<PathBuf> {
        let requested = requested.trim_start_matches('/');
        let clean_requested = requested.strip_prefix("media/").unwrap_or(requested);

        let path = root_path.join(clean_requested);
        let canonical = path.canonicalize().ok()?;
        let canonical_root = root_path.canonicalize().ok()?;

        if !canonical.starts_with(canonical_root) {
            return None;
        }
        Some(canonical)
    }

    fn serve_file(&self, req_parts: &Parts, path: &Path) -> Result<Response<Bytes>, StatusCode> {
        let file = File::open(path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let meta = file.metadata().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let size = meta.len();

        let mtime = meta
            .modified()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .as_secs()
            .cast_signed();

        let etag = format!("\"{mtime:x}-{size:x}\"");

        #[allow(clippy::collapsible_if)]
        if let Some(if_none_match) = req_parts.headers.get(http::header::IF_NONE_MATCH) {
            if if_none_match.as_bytes() == etag.as_bytes() {
                return Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header(http::header::ETAG, &etag)
                    .body(Bytes::new())
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
            }
        }

        let mmap = unsafe { Mmap::map(&file).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)? };
        let mime = mime_guess::from_path(path).first_or_octet_stream().to_string();

        let mmap_arc = Arc::new(mmap);
        let response_body = Bytes::from_owner(mmap_arc.to_vec());

        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, mime)
            .header(http::header::CONTENT_LENGTH, size)
            .header(http::header::ETAG, etag)
            .header(http::header::CACHE_CONTROL, "public, max-age=3600")
            .body(response_body)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn serve_directory_listing(
        &self,
        req_path: &str,
        system_path: &Path,
        config: &ServeConfig,
    ) -> Result<Response<Bytes>, StatusCode> {
        let mut rows_html = String::with_capacity(4096);

        if req_path != "/" && !req_path.is_empty() {
            rows_html.push_str(
                "<tr class='dir'>
                    <td><a href='../'>📁 ..</a></td>
                    <td class='muted'>-</td>
                    <td class='muted'>Parent Directory</td>
                </tr>",
            );
        }

        if let Ok(entries) = fs::read_dir(system_path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();

                if !config.flags.contains(Flags::DOTFILES) && name.starts_with('.') {
                    continue;
                }
                if config.blacklist.iter().any(|p| p.matches(&name)) {
                    continue;
                }

                let file_type = entry.file_type().ok();
                let meta = entry.metadata().ok();

                let is_dir = file_type.map(|t| t.is_dir()).unwrap_or(false);
                let icon = if is_dir { "📁" } else { "📄" };
                let row_class = if is_dir { "dir" } else { "file" };

                let size_str = meta
                    .map(|m| if is_dir { "-".to_string() } else { format_size(m.len()) })
                    .unwrap_or_else(|| "-".to_string());

                let link_path = format!("{}/{}", req_path.trim_end_matches('/'), name);

                rows_html.push_str(&format!(
                    "<tr class='{}'>
                        <td><a href='{}'>{} {}</a></td>
                        <td class='mono'>{}</td>
                        <td class='muted'>{}</td>
                    </tr>",
                    row_class,
                    link_path,
                    icon,
                    name,
                    size_str,
                    if is_dir { "Directory" } else { "File" }
                ));
            }
        }

        let html = format!(
            "<!DOCTYPE html>
            <html lang='en'>
            <head>
                <meta charset='UTF-8'>
                <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                <title>Index of {0}</title>
                <style>
                    :root {{ --bg: #09090b; --surface: #141416; --border: #27272a; --text: #f4f4f5; --muted: #71717a; --accent: #10b981; }}
                    body {{ background: var(--bg); color: var(--text); font-family: system-ui, -apple-system, sans-serif; max-width: 1000px; margin: 0 auto; padding: 3rem 1.5rem; }}
                    header {{ border-bottom: 1px solid var(--border); padding-bottom: 1rem; margin-bottom: 2rem; }}
                    h1 {{ margin: 0; font-size: 1.5rem; font-weight: 700; tracking-tight: -0.025em; }}
                    .path {{ color: var(--accent); font-family: monospace; }}
                    .table-wrapper {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }}
                    table {{ width: 100%; border-collapse: collapse; text-align: left; }}
                    th {{ background: #18181b; color: var(--muted); font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; padding: 1rem; border-bottom: 1px solid var(--border); }}
                    td {{ padding: 1rem; border-bottom: 1px solid #1f1f23; font-size: 0.925rem; }}
                    tr:last-child td {{ border-bottom: none; }}
                    tr:hover td {{ background: #1c1c1f; }}
                    a {{ color: inherit; text-decoration: none; }}
                    a:hover {{ text-decoration: underline; }}
                    .dir a {{ color: var(--accent); font-weight: 500; }}
                    .muted {{ color: var(--muted); }}
                    .mono {{ font-family: monospace; font-size: 0.85rem; color: #d4d4d8; }}
                </style>
            </head>
            <body>
                <header>
                    <h1>Index of <span class='path'>{0}</span></h1>
                </header>
                <main class='table-wrapper'>
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Size</th>
                                <th>Type</th>
                            </tr>
                        </thead>
                        <tbody>
                            {1}
                        </tbody>
                    </table>
                </main>
            </body>
            </html>",
            req_path, rows_html
        );

        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Bytes::from(html))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
}

pub fn format_size(bytes: u64) -> String {
    let mut buf = [0u8; 16];
    let mut pos = 0;

    let (integral, fractional, unit) = if bytes < 1024 {
        (bytes, 0, " B")
    } else if bytes < 1024 * 1024 {
        // KB
        let val_x10 = (bytes * 10) / 1024;
        (val_x10 / 10, val_x10 % 10, " KB")
    } else if bytes < 1024 * 1024 * 1024 {
        // MB
        let val_x10 = (bytes * 10) / (1024 * 1024);
        (val_x10 / 10, val_x10 % 10, " MB")
    } else if bytes < 1024 * 1024 * 1024 * 1024 {
        // GB
        let val_x10 = (bytes * 10) / (1024 * 1024 * 1024);
        (val_x10 / 10, val_x10 % 10, " GB")
    } else {
        // TB
        let val_x10 = (bytes * 10) / (1024 * 1024 * 1024 * 1024);
        (val_x10 / 10, val_x10 % 10, " TB")
    };

    let mut num = integral;
    let start_pos = pos;

    if num == 0 {
        buf[pos] = b'0';
        pos += 1;
    } else {
        while num > 0 {
            buf[pos] = b'0' + (num % 10) as u8;
            num /= 10;
            pos += 1;
        }
        let mut left = start_pos;
        let mut right = pos - 1;
        while left < right {
            buf.swap(left, right);
            left += 1;
            right -= 1;
        }
    }

    if unit != " B" {
        buf[pos] = b'.';
        buf[pos + 1] = b'0' + fractional as u8;
        pos += 2;
    }

    let unit_bytes = unit.as_bytes();
    buf[pos..pos + unit_bytes.len()].copy_from_slice(unit_bytes);
    pos += unit_bytes.len();

    unsafe { String::from_utf8_unchecked(buf[..pos].to_vec()) }
}
