use std::borrow::Cow;
use std::fmt::Write as _;
use std::io;
use std::path::Path;

use tokio::fs;

use crate::conf::ServeConfig;

const HTML_CAPACITY_HINT: usize = 4 * 1024;

const HTML_HEAD_BEFORE_PATH: &str = "\
<!DOCTYPE html>\
<html lang='en'>\
<head>\
<meta charset='UTF-8'>\
<meta name='viewport' content='width=device-width, initial-scale=1.0'>\
<title>Index of ";

const HTML_MID_BEFORE_ROWS: &str = "</title>\
<style>\
:root{--bg:#09090b;--surface:#141416;--border:#27272a;--text:#f4f4f5;--muted:#71717a;--accent:#10b981}\
body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif;max-width:1000px;margin:0 auto;padding:3rem 1.5rem}\
header{border-bottom:1px solid var(--border);padding-bottom:1rem;margin-bottom:2rem}\
h1{margin:0;font-size:1.5rem;font-weight:700}\
.path{color:var(--accent);font-family:monospace}\
.table-wrapper{background:var(--surface);border:1px solid var(--border);overflow:hidden}\
table{width:100%;border-collapse:collapse;text-align:left}\
th{background:#18181b;color:var(--muted);font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;padding:1rem;border-bottom:1px solid var(--border)}\
td{padding:1rem;border-bottom:1px solid #1f1f23;font-size:.925rem}\
tr:last-child td{border-bottom:none}\
tr:hover td{background:#1c1c1f}\
a{color:inherit;text-decoration:none}\
a:hover{text-decoration:underline}\
.dir a{color:var(--accent);font-weight:500}\
.muted{color:var(--muted)}\
.mono{font-family:monospace;font-size:.85rem;color:#d4d4d8}\
</style>\
</head>\
<body>\
<header><h1>Index of <span class='path'>";

const HTML_MAIN_BEFORE_ROWS: &str = "</span></h1></header>\
<main class='table-wrapper'>\
<table>\
<thead><tr><th>Name</th><th>Size</th><th>Type</th></tr></thead>\
<tbody>";

const HTML_FOOT: &str = "</tbody>\
</table>\
</main>\
</body>\
</html>";

pub struct DirectoryListing;

impl DirectoryListing {
    pub async fn build(req_path: &str, system_path: &Path, conf: &ServeConfig) -> io::Result<String> {
        let mut entries = fs::read_dir(system_path).await?;
        let safe_req_path = html_escape(req_path);

        let mut html = String::with_capacity(HTML_CAPACITY_HINT);

        html.push_str(HTML_HEAD_BEFORE_PATH);
        html.push_str(&safe_req_path);
        html.push_str(HTML_MID_BEFORE_ROWS);
        html.push_str(&safe_req_path);
        html.push_str(HTML_MAIN_BEFORE_ROWS);

        if req_path != "/" && !req_path.is_empty() {
            html.push_str(
                "<tr class='dir'>\
                 <td><a href='../'>\u{1F4C1} ..</a></td>\
                 <td class='muted'>-</td>\
                 <td class='muted'>Parent Directory</td>\
                 </tr>",
            );
        }

        let base_path = req_path.trim_end_matches('/');

        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();
            let name = file_name.to_str().unwrap_or("");
            let meta = entry.metadata().await?;
            let path = entry.path();

            if conf.flags.is_blocked(meta.file_type(), name) {
                continue;
            }

            if conf.is_blacklisted(&path) {
                continue;
            }

            let is_dir = meta.is_dir();
            let icon = if is_dir { "\u{1F4C1}" } else { "\u{1F4C4}" };
            let class = if is_dir { "dir" } else { "file" };

            let href = String::from(base_path) + "/" + name;
            let safe_name = html_escape(name);
            let safe_href = html_escape(&href);

            if is_dir {
                let _ = write!(
                    html,
                    "<tr class='{class}'>\
                     <td><a href='{safe_href}'>{icon} {safe_name}</a></td>\
                     <td class='mono'>-</td>\
                     <td class='muted'>Directory</td>\
                     </tr>"
                );
            } else {
                let formatted_size = flatkit::format_size(meta.len());
                let _ = write!(
                    html,
                    "<tr class='{class}'>\
                     <td><a href='{safe_href}'>{icon} {safe_name}</a></td>\
                     <td class='mono'>{formatted_size}</td>\
                     <td class='muted'>File</td>\
                     </tr>"
                );
            }
        }

        html.push_str(HTML_FOOT);

        Ok(html)
    }
}

/// Minimal HTML escape — only the characters that can break out of an attribute or text node.
#[inline]
pub fn html_escape(s: &str) -> Cow<'_, str> {
    if !s.as_bytes().iter().any(|&b| matches!(b, b'<' | b'>' | b'&' | b'"' | b'\'')) {
        return Cow::Borrowed(s);
    }
    
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }

    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_noop() {
        assert_eq!(html_escape("hello world"), "hello world");
        assert_eq!(html_escape("file.txt"), "file.txt");
        assert_eq!(html_escape("abc123_-"), "abc123_-");
    }

    #[test]
    fn html_escape_special_chars() {
        assert_eq!(html_escape("<b>bold</b>"), "&lt;b&gt;bold&lt;/b&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape(r#"a "quoted" value"#), "a &quot;quoted&quot; value");
        assert_eq!(html_escape("it's"), "it&#39;s");
    }

    #[test]
    fn html_escape_mixed() {
        assert_eq!(html_escape("<img src='x'>"), "&lt;img src=&#39;x&#39;&gt;");
    }

    #[test]
    fn html_escape_empty() {
        assert_eq!(html_escape(""), "");
    }

    #[tokio::test]
    async fn directory_listing_builds_for_root() {
        let dir = std::env::temp_dir().join("ophan_static_test_root_listing");
        let _ = fs::remove_dir_all(&dir).await;
        fs::create_dir_all(&dir).await.unwrap();
        fs::write(dir.join("hello.txt"), b"hi").await.unwrap();
        fs::create_dir(dir.join("subdir")).await.unwrap();

        let conf = ServeConfig::new(&dir);
        let html = DirectoryListing::build("/", &dir, &conf).await.unwrap();

        assert!(html.contains("hello.txt"));
        assert!(html.contains("subdir"));
        assert!(!html.contains("Parent Directory"));

        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn directory_listing_builds_for_subdir() {
        let dir = std::env::temp_dir().join("ophan_static_test_root_listing_sub");
        let sub = dir.join("inner");
        let _ = fs::remove_dir_all(&dir).await;
        fs::create_dir_all(&sub).await.unwrap();
        fs::write(sub.join("file.txt"), b"data").await.unwrap();

        let conf = ServeConfig::new(&dir);
        let html = DirectoryListing::build("/inner/", &sub, &conf).await.unwrap();

        assert!(html.contains("file.txt"));
        assert!(html.contains("Parent Directory"));

        let _ = fs::remove_dir_all(&dir).await;
    }
}
