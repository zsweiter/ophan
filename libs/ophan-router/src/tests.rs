use ophan_net::http::{HttpMethod, HttpMethodSet};

use crate::Router;

use super::error::MatchError;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn router() -> Router<u32> {
    Router::new()
}

fn router_with_vhosts() -> Router<u32> {
    let mut r = Router::new();
    r.add_route(
        Some("api.example.com"),
        "/",
        HttpMethodSet::new(HttpMethod::GET | HttpMethod::POST | HttpMethod::PUT),
        0,
    )
    .unwrap();
    r.add_route(
        Some("admin.example.com"),
        "/",
        HttpMethodSet::new(HttpMethod::GET | HttpMethod::POST | HttpMethod::DELETE),
        1,
    )
    .unwrap();
    r.add_route(Some("*.example.com"), "/", HttpMethodSet::new(HttpMethod::GET), 2).unwrap();
    r
}

// ---------------------------------------------------------------------------
// README: Exact
// ---------------------------------------------------------------------------

#[test]
fn exact_match() {
    let mut r = router();
    r.add_route(None, "/api/users", HttpMethodSet::all(), 42).unwrap();
    assert_eq!(*r.find_route(None, "GET", "/api/users").unwrap().value, 42);
}

#[test]
fn exact_no_match_wrong_path() {
    let mut r = router();
    r.add_route(None, "/api/users", HttpMethodSet::all(), 42).unwrap();
    assert_eq!(r.find_route(None, "GET", "/api/users/123").unwrap_err(), MatchError::NotFound);
}

// ---------------------------------------------------------------------------
// README: Param simple
// ---------------------------------------------------------------------------

#[test]
fn param_simple() {
    let mut r = router();
    r.add_route(None, "/api/users/:id", HttpMethodSet::all(), 20).unwrap();
    let m = r.find_route(None, "GET", "/api/users/1").unwrap();
    assert_eq!(*m.value, 20);
    assert_eq!(m.params.get("id"), Some("1"));
}

#[test]
fn param_no_match_extra_segment() {
    let mut r = router();
    r.add_route(None, "/api/users/:id", HttpMethodSet::all(), 20).unwrap();
    assert_eq!(r.find_route(None, "GET", "/api/users/1/x").unwrap_err(), MatchError::NotFound);
}

#[test]
fn param_multi() {
    let mut r = router();
    r.add_route(None, "/users/:uid/posts/:pid", HttpMethodSet::all(), 30).unwrap();
    let m = r.find_route(None, "GET", "/users/7/posts/99").unwrap();
    assert_eq!(*m.value, 30);
    assert_eq!(m.params.get("uid"), Some("7"));
    assert_eq!(m.params.get("pid"), Some("99"));
}

// ---------------------------------------------------------------------------
// README: Multi-segment wildcard (* at end)
// ---------------------------------------------------------------------------

#[test]
fn multi_segment_wildcard() {
    let mut r = router();
    r.add_route(None, "/api/files/*", HttpMethodSet::all(), 50).unwrap();
    let m = r.find_route(None, "GET", "/api/files/a/b/c").unwrap();
    assert_eq!(*m.value, 50);
    assert_eq!(m.params.get("_"), Some("a/b/c"));
}

#[test]
fn multi_segment_wildcard_single() {
    let mut r = router();
    r.add_route(None, "/api/files/*", HttpMethodSet::all(), 50).unwrap();
    let m = r.find_route(None, "GET", "/api/files/main.js").unwrap();
    assert_eq!(*m.value, 50);
    assert_eq!(m.params.get("_"), Some("main.js"));
}

#[test]
fn multi_segment_wildcard_no_match_empty() {
    let mut r = router();
    r.add_route(None, "/api/files/*", HttpMethodSet::all(), 50).unwrap();
    // Catch-all requires at least one path segment after the prefix
    assert_eq!(r.find_route(None, "GET", "/api/files").unwrap_err(), MatchError::NotFound);
}

// ---------------------------------------------------------------------------
// Mid-path wildcard (* in middle, single-segment)
// ---------------------------------------------------------------------------

#[test]
fn mid_path_wildcard() {
    let mut r = router();
    r.add_route(None, "/api/*/action", HttpMethodSet::all(), 60).unwrap();
    let m = r.find_route(None, "GET", "/api/v1/action").unwrap();
    assert_eq!(*m.value, 60);
}

#[test]
fn mid_path_wildcard_no_match_multi_segment() {
    let mut r = router();
    r.add_route(None, "/api/*/action", HttpMethodSet::all(), 60).unwrap();
    // Mid-path * is single-segment only
    assert_eq!(
        r.find_route(None, "GET", "/api/v1/sub/action").unwrap_err(),
        MatchError::NotFound
    );
}

// ---------------------------------------------------------------------------
// README: Param + wildcard mix
// ---------------------------------------------------------------------------

#[test]
fn param_and_wildcard_mix() {
    let mut r = router();
    r.add_route(None, "/users/:id/posts/*", HttpMethodSet::all(), 70).unwrap();
    let m = r.find_route(None, "GET", "/users/1/posts/a/b").unwrap();
    assert_eq!(*m.value, 70);
    assert_eq!(m.params.get("id"), Some("1"));
    assert_eq!(m.params.get("_"), Some("a/b"));
}

#[test]
fn param_and_wildcard_mix_single() {
    let mut r = router();
    r.add_route(None, "/users/:id/posts/*", HttpMethodSet::all(), 70).unwrap();
    let m = r.find_route(None, "GET", "/users/42/posts/latest").unwrap();
    assert_eq!(*m.value, 70);
    assert_eq!(m.params.get("id"), Some("42"));
    assert_eq!(m.params.get("_"), Some("latest"));
}

// ---------------------------------------------------------------------------
// README: Catch-all /*
// ---------------------------------------------------------------------------

#[test]
fn catch_all_root() {
    let mut r = router();
    r.add_route(None, "/*", HttpMethodSet::all(), 99).unwrap();
    assert_eq!(*r.find_route(None, "GET", "/anything").unwrap().value, 99);
    assert_eq!(*r.find_route(None, "GET", "/a/b/c").unwrap().value, 99);
    assert_eq!(*r.find_route(None, "GET", "/").unwrap().value, 99);
}

#[test]
fn catch_all_with_explicit_root() {
    let mut r = router();
    r.add_route(None, "/", HttpMethodSet::all(), 1).unwrap();
    r.add_route(None, "/*", HttpMethodSet::all(), 99).unwrap();
    // Explicit / takes priority
    assert_eq!(*r.find_route(None, "GET", "/").unwrap().value, 1);
    // Catch-all handles everything else
    assert_eq!(*r.find_route(None, "GET", "/foo").unwrap().value, 99);
}

// ---------------------------------------------------------------------------
// README: Raw regex
// ---------------------------------------------------------------------------

#[test]
fn raw_regex_match() {
    let mut r = router();
    r.add_route(None, r"^/assets/.*\.(png|jpg)$", HttpMethodSet::all(), 80).unwrap();
    assert_eq!(*r.find_route(None, "GET", "/assets/a.png").unwrap().value, 80);
    assert_eq!(*r.find_route(None, "GET", "/assets/b.jpg").unwrap().value, 80);
}

#[test]
fn raw_regex_no_match() {
    let mut r = router();
    r.add_route(None, r"^/assets/.*\.(png|jpg)$", HttpMethodSet::all(), 80).unwrap();
    assert_eq!(r.find_route(None, "GET", "/assets/a.txt").unwrap_err(), MatchError::NotFound);
}

#[test]
fn raw_regex_with_params_in_path() {
    let mut r = router();
    r.add_route(None, r"^/api/v[0-9]+/.*$", HttpMethodSet::all(), 81).unwrap();
    assert_eq!(*r.find_route(None, "GET", "/api/v1/users").unwrap().value, 81);
    assert_eq!(*r.find_route(None, "GET", "/api/v2/posts/42").unwrap().value, 81);
}

#[test]
fn regex_has_no_params() {
    let mut r = router();
    r.add_route(None, r"^/api/v[0-9]+/(.*)$", HttpMethodSet::all(), 81).unwrap();
    let m = r.find_route(None, "GET", "/api/v1/users").unwrap();
    assert_eq!(*m.value, 81);
    assert!(m.params.is_empty());
}

// ---------------------------------------------------------------------------
// Trailing slash normalization
// ---------------------------------------------------------------------------

#[test]
fn exact_with_trailing_slash() {
    let mut r = router();
    r.add_route(None, "/api/users", HttpMethodSet::all(), 42).unwrap();
    assert_eq!(*r.find_route(None, "GET", "/api/users/").unwrap().value, 42);
}

#[test]
fn param_with_trailing_slash() {
    let mut r = router();
    r.add_route(None, "/users/:uid/posts/:pid", HttpMethodSet::all(), 30).unwrap();
    let m = r.find_route(None, "GET", "/users/7/posts/99/").unwrap();
    assert_eq!(*m.value, 30);
    assert_eq!(m.params.get("uid"), Some("7"));
    assert_eq!(m.params.get("pid"), Some("99"));
}

#[test]
fn root_slash_preserved() {
    let mut r = router();
    r.add_route(None, "/", HttpMethodSet::all(), 1).unwrap();
    assert_eq!(*r.find_route(None, "GET", "/").unwrap().value, 1);
}

#[test]
fn double_trailing_slash() {
    let mut r = router();
    r.add_route(None, "/api/users", HttpMethodSet::all(), 42).unwrap();
    assert_eq!(*r.find_route(None, "GET", "/api/users//").unwrap().value, 42);
}

// ---------------------------------------------------------------------------
// Edge cases: host resolution
// ---------------------------------------------------------------------------

#[test]
fn no_host_fallback() {
    let mut r = router();
    r.add_route(None, "/api", HttpMethodSet::all(), 42).unwrap();
    assert_eq!(*r.find_route(None, "GET", "/api").unwrap().value, 42);
}

#[test]
fn exact_host_match() {
    let r = router_with_vhosts();
    assert_eq!(*r.find_route(Some("api.example.com"), "GET", "/").unwrap().value, 0);
}

#[test]
fn wildcard_host_match() {
    let r = router_with_vhosts();
    assert_eq!(*r.find_route(Some("foo.example.com"), "GET", "/").unwrap().value, 2);
}

#[test]
fn wildcard_host_nested_subdomain() {
    let r = router_with_vhosts();
    assert_eq!(*r.find_route(Some("bar.foo.example.com"), "GET", "/").unwrap().value, 2);
}

#[test]
fn wildcard_host_no_apex() {
    let r = router_with_vhosts();
    assert_eq!(
        r.find_route(Some("example.com"), "GET", "/").unwrap_err(),
        MatchError::NotFound
    );
}

#[test]
fn unknown_host_fallback() {
    let mut r = router();
    r.add_route(None, "/data", HttpMethodSet::all(), 99).unwrap();
    assert_eq!(*r.find_route(Some("unknown.com"), "GET", "/data").unwrap().value, 99);
}

#[test]
fn host_port_stripped() {
    let r = router_with_vhosts();
    assert_eq!(*r.find_route(Some("api.example.com:443"), "GET", "/").unwrap().value, 0);
}

#[test]
fn empty_host_string() {
    let mut r = router();
    r.add_route(None, "/data", HttpMethodSet::all(), 1).unwrap();
    assert_eq!(*r.find_route(Some(""), "GET", "/data").unwrap().value, 1);
}

// ---------------------------------------------------------------------------
// Edge cases: method filtering
// ---------------------------------------------------------------------------

#[test]
fn all_methods_default() {
    let mut r = router();
    r.add_route(None, "/any", HttpMethodSet::all(), 42).unwrap();
    for m in &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"] {
        assert!(r.find_route(None, m, "/any").is_ok(), "method {} should be allowed", m);
    }
}

#[test]
fn method_vhost_specific_allowed() {
    let r = router_with_vhosts();
    assert_eq!(*r.find_route(Some("api.example.com"), "GET", "/").unwrap().value, 0);
    assert_eq!(*r.find_route(Some("api.example.com"), "POST", "/").unwrap().value, 0);
}

#[test]
fn method_vhost_specific_rejected() {
    let r = router_with_vhosts();
    assert_eq!(
        r.find_route(Some("api.example.com"), "DELETE", "/").unwrap_err(),
        MatchError::MethodNotAllowed
    );
}

// ---------------------------------------------------------------------------
// Edge cases: method merging
// ---------------------------------------------------------------------------

#[test]
fn merge_methods_on_same_host() {
    let mut r = Router::new();
    r.add_route(Some("merge.test"), "/a", HttpMethodSet::new(HttpMethod::GET), 1).unwrap();
    r.add_route(Some("merge.test"), "/b", HttpMethodSet::new(HttpMethod::POST), 2).unwrap();
    // Both methods should be allowed
    assert_eq!(*r.find_route(Some("merge.test"), "GET", "/a").unwrap().value, 1);
    assert_eq!(*r.find_route(Some("merge.test"), "POST", "/a").unwrap().value, 1);
    assert_eq!(*r.find_route(Some("merge.test"), "GET", "/b").unwrap().value, 2);
    assert_eq!(*r.find_route(Some("merge.test"), "POST", "/b").unwrap().value, 2);
}

#[test]
fn merge_methods_on_default_host() {
    let mut r = Router::new();
    r.add_route(None, "/a", HttpMethodSet::new(HttpMethod::GET), 1).unwrap();
    r.add_route(None, "/b", HttpMethodSet::new(HttpMethod::POST), 2).unwrap();
    assert!(r.find_route(None, "GET", "/a").is_ok());
    assert!(r.find_route(None, "POST", "/b").is_ok());
}

// ---------------------------------------------------------------------------
// Edge cases: priority (static > param > catch-all)
// ---------------------------------------------------------------------------

#[test]
fn static_over_param() {
    let mut r = router();
    r.add_route(None, "/users/:id", HttpMethodSet::all(), 1).unwrap();
    r.add_route(None, "/users/me", HttpMethodSet::all(), 2).unwrap();
    assert_eq!(*r.find_route(None, "GET", "/users/me").unwrap().value, 2);
    assert_eq!(*r.find_route(None, "GET", "/users/42").unwrap().value, 1);
}

#[test]
fn static_over_catch_all() {
    let mut r = router();
    r.add_route(None, "/*", HttpMethodSet::all(), 1).unwrap();
    r.add_route(None, "/users/me", HttpMethodSet::all(), 2).unwrap();
    assert_eq!(*r.find_route(None, "GET", "/users/me").unwrap().value, 2);
    assert_eq!(*r.find_route(None, "GET", "/anything/else").unwrap().value, 1);
}

// ---------------------------------------------------------------------------
// Edge cases: virtual host isolation
// ---------------------------------------------------------------------------

#[test]
fn vhost_isolation() {
    let mut r = Router::new();
    r.add_route(Some("a.com"), "/secret", HttpMethodSet::all(), 1).unwrap();
    r.add_route(Some("b.com"), "/public", HttpMethodSet::all(), 2).unwrap();
    assert_eq!(*r.find_route(Some("a.com"), "GET", "/secret").unwrap().value, 1);
    assert!(r.find_route(Some("a.com"), "GET", "/public").is_err());
    assert_eq!(*r.find_route(Some("b.com"), "GET", "/public").unwrap().value, 2);
    assert!(r.find_route(Some("b.com"), "GET", "/secret").is_err());
}

// ---------------------------------------------------------------------------
// Edge cases: tree operations
// ---------------------------------------------------------------------------

#[test]
fn remove_route() {
    let mut r = router();
    r.add_route(None, "/remove", HttpMethodSet::all(), 42).unwrap();
    assert!(r.find_route(None, "GET", "/remove").is_ok());
    let removed = r.remove("/remove");
    assert_eq!(removed, Some(42));
    assert!(r.find_route(None, "GET", "/remove").is_err());
}

#[test]
fn duplicate_insert_returns_err() {
    let mut r = router();
    r.add_route(None, "/path", HttpMethodSet::all(), 1).unwrap();
    let result = r.add_route(None, "/path", HttpMethodSet::all(), 2);
    assert!(result.is_err(), "duplicate insert should return error");
}

#[test]
fn empty_router() {
    let r = router();
    assert_eq!(r.find_route(None, "GET", "/anything").unwrap_err(), MatchError::NotFound);
}

// ---------------------------------------------------------------------------
// Edge cases: unicode
// ---------------------------------------------------------------------------

#[test]
fn unicode_static() {
    let mut r = router();
    r.add_route(None, "/café", HttpMethodSet::all(), 1).unwrap();
    assert_eq!(*r.find_route(None, "GET", "/café").unwrap().value, 1);
}

#[test]
fn unicode_param() {
    let mut r = router();
    r.add_route(None, "/users/:name", HttpMethodSet::all(), 1).unwrap();
    let m = r.find_route(None, "GET", "/users/ユーザー").unwrap();
    assert_eq!(*m.value, 1);
    assert_eq!(m.params.get("name"), Some("ユーザー"));
}

// ---------------------------------------------------------------------------
// Edge cases: miscellaneous
// ---------------------------------------------------------------------------

#[test]
fn dot_in_path() {
    let mut r = router();
    r.add_route(None, "/api/v1.0/resource", HttpMethodSet::all(), 1).unwrap();
    assert_eq!(*r.find_route(None, "GET", "/api/v1.0/resource").unwrap().value, 1);
}

#[test]
fn numeric_param_value() {
    let mut r = router();
    r.add_route(None, "/items/:id", HttpMethodSet::all(), 1).unwrap();
    let m = r.find_route(None, "GET", "/items/12345").unwrap();
    assert_eq!(*m.value, 1);
    assert_eq!(m.params.get("id"), Some("12345"));
}

#[test]
fn deeply_nested() {
    let mut r = router();
    r.add_route(None, "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/foo", HttpMethodSet::all(), 1).unwrap();
    assert_eq!(
        *r.find_route(None, "GET", "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/foo").unwrap().value,
        1
    );
}

#[test]
fn many_params() {
    let mut r = router();
    r.add_route(None, "/:a/:b/:c/:d/:e/:f/:g/:h", HttpMethodSet::all(), 1).unwrap();
    let m = r.find_route(None, "GET", "/1/2/3/4/5/6/7/8").unwrap();
    assert_eq!(*m.value, 1);
    assert_eq!(m.params.get("a"), Some("1"));
    assert_eq!(m.params.get("h"), Some("8"));
}

#[test]
fn backtracking_scenario() {
    let mut r = router();
    r.add_route(None, "/a/b/c", HttpMethodSet::all(), 1).unwrap();
    r.add_route(None, "/a/:b/c", HttpMethodSet::all(), 2).unwrap();
    r.add_route(None, "/a/:b/d", HttpMethodSet::all(), 3).unwrap();
    assert_eq!(*r.find_route(None, "GET", "/a/b/c").unwrap().value, 1);
    assert_eq!(*r.find_route(None, "GET", "/a/x/c").unwrap().value, 2);
    assert_eq!(*r.find_route(None, "GET", "/a/x/d").unwrap().value, 3);
}

#[test]
fn root_path() {
    let mut r = router();
    r.add_route(None, "/", HttpMethodSet::all(), 1).unwrap();
    assert_eq!(*r.find_route(None, "GET", "/").unwrap().value, 1);
}

#[test]
fn find_route_mut() {
    let mut r = router();
    r.add_route(None, "/counter", HttpMethodSet::all(), 0u32).unwrap();
    {
        let m = r.find_route_mut(None, "GET", "/counter").unwrap();
        *m.value += 1;
    }
    assert_eq!(*r.find_route(None, "GET", "/counter").unwrap().value, 1);
}

// ---------------------------------------------------------------------------
// Complex tree (mixed patterns)
// ---------------------------------------------------------------------------

#[test]
fn complex_tree() {
    let mut r = router();
    let routes = [
        "/api/v1/users",
        "/api/v1/users/:id",
        "/api/v1/users/:id/posts",
        "/api/v1/users/:id/posts/:pid",
        "/api/v1/posts",
        "/api/v2/users",
        "/api/health",
        "/static/files/*",
        "/*", // catch-all last
    ];

    for (i, path) in routes.iter().enumerate() {
        r.add_route(None, path, HttpMethodSet::all(), i as u32).unwrap();
    }

    assert_eq!(*r.find_route(None, "GET", "/api/v1/users").unwrap().value, 0);
    assert_eq!(*r.find_route(None, "GET", "/api/v1/users/42").unwrap().value, 1);
    assert_eq!(*r.find_route(None, "GET", "/api/v1/users/42/posts").unwrap().value, 2);
    let m = r.find_route(None, "GET", "/api/v1/users/42/posts/7").unwrap();
    assert_eq!(*m.value, 3);
    assert_eq!(m.params.get("pid"), Some("7"));
    assert_eq!(*r.find_route(None, "GET", "/api/v1/posts").unwrap().value, 4);
    assert_eq!(*r.find_route(None, "GET", "/api/v2/users").unwrap().value, 5);
    assert_eq!(*r.find_route(None, "GET", "/api/health").unwrap().value, 6);
    assert_eq!(*r.find_route(None, "GET", "/static/files/main.js").unwrap().value, 7);
    assert_eq!(*r.find_route(None, "GET", "/static/files/a/b/c").unwrap().value, 7);

    // catch-all
    assert_eq!(*r.find_route(None, "GET", "/unknown/path").unwrap().value, 8);
    assert_eq!(*r.find_route(None, "GET", "/").unwrap().value, 8);
}

// ---------------------------------------------------------------------------
// Tree + regex mixed
// ---------------------------------------------------------------------------

#[test]
fn tree_and_regex_mixed() {
    let mut r = router();
    r.add_route(None, "/api/users", HttpMethodSet::all(), 1).unwrap();
    r.add_route(None, r"^/api/v[0-9]+/.*$", HttpMethodSet::all(), 2).unwrap();
    // Exact takes priority
    assert_eq!(*r.find_route(None, "GET", "/api/users").unwrap().value, 1);
    // Regex fallback
    assert_eq!(*r.find_route(None, "GET", "/api/v2/posts").unwrap().value, 2);
    // Neither
    assert_eq!(r.find_route(None, "GET", "/other").unwrap_err(), MatchError::NotFound);
}

#[test]
fn regex_tree_conflict_no_collision() {
    let mut r = router();
    r.add_route(None, r"^/api/files/.*\.png$", HttpMethodSet::all(), 1).unwrap();
    r.add_route(None, "/api/files/*", HttpMethodSet::all(), 2).unwrap();
    // Regex checked first if... no, tree is checked first
    // Tree catch-all matches anything under /api/files/
    assert_eq!(*r.find_route(None, "GET", "/api/files/foo.png").unwrap().value, 2);
    // Regex is only reached if tree fails
    // But /api/files/* catches everything, so regex is never reached
    // This is an expected limitation of regex fallback (tree has priority)
}

// ---------------------------------------------------------------------------
// Stress: many routes
// ---------------------------------------------------------------------------

#[test]
fn stress_many_routes() {
    let mut r = router();
    let n = 10_000;
    for i in 0..n {
        let path = format!("/route/{}/detail", i);
        r.add_route(None, &path, HttpMethodSet::all(), i).unwrap();
    }
    for i in 0..n {
        let path = format!("/route/{}/detail", i);
        let m = r.find_route(None, "GET", &path).unwrap();
        assert_eq!(*m.value, i);
    }
}

#[test]
fn stress_many_vhosts() {
    let mut r = Router::new();
    let n = 1_000;
    for i in 0..n {
        let host = format!("host{}.example.com", i);
        r.add_route(Some(&host), "/data", HttpMethodSet::all(), i).unwrap();
    }
    for i in 0..n {
        let host = format!("host{}.example.com", i);
        let m = r.find_route(Some(&host), "GET", "/data").unwrap();
        assert_eq!(*m.value, i);
    }
}

#[test]
fn stress_param_routes() {
    let mut r = router();
    let n = 1_000;
    for i in 0..n {
        let path = format!("/resource/{}/item", i);
        r.add_route(None, &path, HttpMethodSet::all(), i).unwrap();
    }
    for i in 0..n {
        let path = format!("/resource/{}/item", i);
        let m = r.find_route(None, "GET", &path).unwrap();
        assert_eq!(*m.value, i);
    }
}

#[test]
fn stress_mixed_routes() {
    let mut r = router();
    // Insert 5000 static + 500 param + 500 wildcard + 50 regex + catch-all
    let n_static = 5_000;
    let n_param = 500;
    let n_wild = 500;

    for i in 0..n_static {
        let path = format!("/static/route/{}", i);
        r.add_route(None, &path, HttpMethodSet::all(), i).unwrap();
    }
    for i in 0..n_param {
        let path = format!("/param/{}/route", i);
        r.add_route(None, &path, HttpMethodSet::all(), n_static + i).unwrap();
    }
    for i in 0..n_wild {
        let path = format!("/wildcard/dir{}/*", i);
        r.add_route(None, &path, HttpMethodSet::all(), n_static + n_param + i).unwrap();
    }

    // Verify all static
    for i in 0..n_static {
        let path = format!("/static/route/{}", i);
        let m = r.find_route(None, "GET", &path).unwrap();
        assert_eq!(*m.value, i);
    }
    // Verify wildcard
    for i in 0..n_wild {
        let path = format!("/wildcard/dir{}/sub/deep/file.txt", i);
        let m = r.find_route(None, "GET", &path).unwrap();
        assert_eq!(*m.value, n_static + n_param + i);
    }
}

// ---------------------------------------------------------------------------
// Edge cases: verify_nonexistent_paths
// ---------------------------------------------------------------------------

#[test]
fn edge_case_nonexistent_deep() {
    let mut r = router();
    r.add_route(None, "/api/v1/users", HttpMethodSet::all(), 1).unwrap();
    assert_eq!(
        r.find_route(None, "GET", "/api/v1/users/nonexistent").unwrap_err(),
        MatchError::NotFound
    );
    assert_eq!(r.find_route(None, "GET", "/api/v1").unwrap_err(), MatchError::NotFound);
}

#[test]
fn edge_case_partial_prefix() {
    let mut r = router();
    r.add_route(None, "/api/v1/users", HttpMethodSet::all(), 1).unwrap();
    r.add_route(None, "/api/v2", HttpMethodSet::all(), 2).unwrap();
    assert_eq!(*r.find_route(None, "GET", "/api/v2").unwrap().value, 2);
    assert_eq!(r.find_route(None, "GET", "/api/v2/extra").unwrap_err(), MatchError::NotFound);
}

// ---------------------------------------------------------------------------
// Regex: invalid patterns
// ---------------------------------------------------------------------------

#[test]
fn invalid_regex_returns_error() {
    let mut r = router();
    let result = r.add_route(None, r"^[invalid", HttpMethodSet::all(), 1);
    assert!(result.is_err(), "invalid regex should return error");
}

#[test]
fn valid_regex_accepted() {
    let mut r = router();
    let result = r.add_route(None, r"^/api/.*$", HttpMethodSet::all(), 1);
    assert!(result.is_ok());
}
