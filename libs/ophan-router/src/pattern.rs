/// Normalizes a route pattern to matchit-compatible syntax.
///
/// | Input             | Output            | Type                    |
/// |-------------------|-------------------|-------------------------|
/// | `/users/:id`      | `/users/{id}`     | nginx param             |
/// | `/users/{id}`     | `/users/{id}`     | matchit (passthrough)   |
/// | `/static/*`       | `/static/{*_}`    | multi-segment catch-all |
/// | `/api/*/action`   | `/api/{_}/action` | single-segment wildcard |
/// | `/exact/path`     | `/exact/path`     | static                  |
/// | `/*`              | `/{*_}`           | root catch-all          |
pub fn normalize_pattern(pattern: &str) -> String {
    if has_matchit_wildcard(pattern) {
        return pattern.to_string();
    }

    let bytes = pattern.as_bytes();
    let mut result = String::with_capacity(pattern.len());
    let mut i = 0;
    let mut in_brace = false;

    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                in_brace = true;
                result.push('{');
                i += 1;
            },
            b'}' => {
                in_brace = false;
                result.push('}');
                i += 1;
            },
            b':' if !in_brace => {
                let start = i + 1;
                let end = bytes[start..].iter().position(|&b| b == b'/').map(|p| start + p).unwrap_or(bytes.len());
                if end > start {
                    result.push('{');
                    result.push_str(&pattern[start..end]);
                    result.push('}');
                    i = end;
                } else {
                    result.push(':');
                    i += 1;
                }
            },
            b'*' if !in_brace => {
                let is_end = bytes[i + 1..].iter().all(|&b| b.is_ascii_whitespace());
                if is_end {
                    result.push_str("{*_}");
                } else {
                    result.push_str("{_}");
                }
                i += 1;
            },
            _ => {
                let start = i;
                while i < bytes.len() && !matches!(bytes[i], b'{' | b'}' | b':' | b'*') {
                    i += 1;
                }
                result.push_str(&pattern[start..i]);
            },
        }
    }

    result
}

/// Returns true if the pattern contains matchit-style wildcards ({param} or {*param}).
fn has_matchit_wildcard(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        #[allow(clippy::collapsible_if)]
        if bytes[i] == b'{' {
            if i + 1 < bytes.len() && bytes[i + 1] != b'{' {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Returns true if the pattern is a raw regex (starts with `^`).
pub fn is_raw_regex(pattern: &str) -> bool {
    pattern.starts_with('^')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_pattern() {
        assert_eq!(normalize_pattern("/users/settings"), "/users/settings");
    }

    #[test]
    fn nginx_param() {
        assert_eq!(normalize_pattern("/users/:id"), "/users/{id}");
    }

    #[test]
    fn nginx_multi_params() {
        assert_eq!(normalize_pattern("/users/:id/posts/:pid"), "/users/{id}/posts/{pid}");
    }

    #[test]
    fn matchit_param_passthrough() {
        assert_eq!(normalize_pattern("/users/{id}"), "/users/{id}");
    }

    #[test]
    fn matchit_catchall_passthrough() {
        assert_eq!(normalize_pattern("/static/{*path}"), "/static/{*path}");
    }

    #[test]
    fn wildcard_multi_segment_end() {
        assert_eq!(normalize_pattern("/api/files/*"), "/api/files/{*_}");
    }

    #[test]
    fn wildcard_mid_path() {
        assert_eq!(normalize_pattern("/api/*/action"), "/api/{_}/action");
    }

    #[test]
    fn root_catch_all() {
        assert_eq!(normalize_pattern("/*"), "/{*_}");
    }

    #[test]
    fn param_and_wildcard_mix() {
        assert_eq!(normalize_pattern("/users/:id/posts/*"), "/users/{id}/posts/{*_}");
    }

    #[test]
    fn mixed_nginx_and_matchit_brace() {
        assert_eq!(normalize_pattern("/{version}/:id"), "/{version}/:id");
    }

    #[test]
    fn empty_param_is_literal_colon() {
        assert_eq!(normalize_pattern("/alone:"), "/alone:");
    }

    #[test]
    fn root_path() {
        assert_eq!(normalize_pattern("/"), "/");
    }

    #[test]
    fn is_raw_regex_detection() {
        assert!(is_raw_regex("^/assets/.*\\.(png|jpg)$"));
        assert!(is_raw_regex("^/api/v[0-9]+/.*$"));
        assert!(!is_raw_regex("/api/users"));
        assert!(!is_raw_regex("/api/files/*"));
        assert!(!is_raw_regex("/users/:id"));
    }
}
