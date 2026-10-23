use ophan_net::http::{HttpMethod, HttpMethodSet};

use crate::Router;

use super::error::{InsertError, MatchError};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn router() -> Router<u32> {
    Router::new()
}

fn router_with_vhosts() -> Router<u32> {
    let mut r = Router::new();
    r.add_route(
        "/",
        HttpMethodSet::new(HttpMethod::GET | HttpMethod::POST | HttpMethod::PUT),
        vec!["api.example.com"],
        0,
    )
    .unwrap();
    r.add_route(
        "/",
        HttpMethodSet::new(HttpMethod::GET | HttpMethod::POST | HttpMethod::DELETE),
        vec!["admin.example.com"],
        1,
    )
    .unwrap();
    r.add_route("/", HttpMethodSet::new(HttpMethod::GET), vec!["*.example.com"], 2).unwrap();
    r
}

// ---------------------------------------------------------------------------
// README: Exact
// ---------------------------------------------------------------------------

#[test]
fn exact_match() {
    let mut r = router();
    r.add_route("/api/users", HttpMethodSet::all(), vec![], 42).unwrap();
    assert_eq!(*r.match_route(None, &http::Method::GET, "/api/users").unwrap().value, 42);
}

#[test]
fn exact_no_match_wrong_path() {
    let mut r = router();
    r.add_route("/api/users", HttpMethodSet::all(), vec![], 42).unwrap();
    assert_eq!(
        r.match_route(None, &http::Method::GET, "/api/users/123").unwrap_err(),
        MatchError::NotFound
    );
}

// ---------------------------------------------------------------------------
// README: Param simple
// ---------------------------------------------------------------------------

#[test]
fn param_simple() {
    let mut r = router();
    r.add_route("/api/users/:id", HttpMethodSet::all(), vec![], 20).unwrap();
    let m = r.match_route(None, &http::Method::GET, "/api/users/1").unwrap();
    assert_eq!(*m.value, 20);
    assert_eq!(m.params.get("id"), Some("1"));
}

#[test]
fn param_no_match_extra_segment() {
    let mut r = router();
    r.add_route("/api/users/:id", HttpMethodSet::all(), vec![], 20).unwrap();
    assert_eq!(
        r.match_route(None, &http::Method::GET, "/api/users/1/x").unwrap_err(),
        MatchError::NotFound
    );
}

#[test]
fn param_multi() {
    let mut r = router();
    r.add_route("/users/:uid/posts/:pid", HttpMethodSet::all(), vec![], 30).unwrap();
    let m = r.match_route(None, &http::Method::GET, "/users/7/posts/99").unwrap();
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
    r.add_route("/api/files/*", HttpMethodSet::all(), vec![], 50).unwrap();
    let m = r.match_route(None, &http::Method::GET, "/api/files/a/b/c").unwrap();
    assert_eq!(*m.value, 50);
    assert_eq!(m.params.get("_"), Some("a/b/c"));
}

#[test]
fn multi_segment_wildcard_single() {
    let mut r = router();
    r.add_route("/api/files/*", HttpMethodSet::all(), vec![], 50).unwrap();
    let m = r.match_route(None, &http::Method::GET, "/api/files/main.js").unwrap();
    assert_eq!(*m.value, 50);
    assert_eq!(m.params.get("_"), Some("main.js"));
}

#[test]
fn multi_segment_wildcard_matches_its_base() {
    let mut r = router();
    r.add_route("/api/files/*", HttpMethodSet::all(), vec![], 50).unwrap();

    assert_eq!(*r.match_route(None, &http::Method::GET, "/api/files").unwrap().value, 50);
    assert_eq!(*r.match_route(None, &http::Method::GET, "/api/files/").unwrap().value, 50);
    assert_eq!(
        r.match_route(None, &http::Method::GET, "/api/filesystem").unwrap_err(),
        MatchError::NotFound
    );
}

#[test]
fn explicit_base_route_wins_over_wildcard() {
    let mut r = router();
    r.add_route("/api/*", HttpMethodSet::all(), vec![], 1).unwrap();
    r.add_route("/api", HttpMethodSet::all(), vec![], 2).unwrap();

    assert_eq!(*r.match_route(None, &http::Method::GET, "/api").unwrap().value, 2);
    assert_eq!(*r.match_route(None, &http::Method::GET, "/api/x").unwrap().value, 1);
}

#[test]
fn root_after_catch_all_does_not_conflict() {
    let mut r = router();
    r.add_route("/*", HttpMethodSet::all(), vec![], 1).unwrap();
    r.add_route("/", HttpMethodSet::all(), vec![], 2).unwrap();

    assert_eq!(*r.match_route(None, &http::Method::GET, "/").unwrap().value, 2);
}

#[test]
fn route_is_registered_on_every_host() {
    let mut r = router();
    r.add_route("/x", HttpMethodSet::all(), vec!["a.com", "b.com"], 7).unwrap();

    assert_eq!(*r.match_route(Some("a.com"), &http::Method::GET, "/x").unwrap().value, 7);
    assert_eq!(*r.match_route(Some("b.com:8080"), &http::Method::GET, "/x").unwrap().value, 7);
}

#[test]
fn route_without_methods_accepts_all_on_shared_host() {
    let mut r = router();
    r.add_route("/get-only", HttpMethodSet::new(HttpMethod::GET), vec!["a.com"], 1).unwrap();
    r.add_route("/any", HttpMethodSet::new(HttpMethod::from_bits(0)), vec!["a.com"], 2).unwrap();

    assert_eq!(*r.match_route(Some("a.com"), &http::Method::POST, "/any").unwrap().value, 2);
}

#[test]
fn unknown_path_is_not_found_before_method_check() {
    let mut r = router();
    r.add_route("/x", HttpMethodSet::new(HttpMethod::GET), vec!["a.com"], 1).unwrap();

    assert_eq!(
        r.match_route(Some("a.com"), &http::Method::POST, "/missing").unwrap_err(),
        MatchError::NotFound
    );
}

#[test]
fn trailing_slash_pattern_matches() {
    let mut r = router();
    r.add_route("/users/", HttpMethodSet::all(), vec![], 1).unwrap();

    assert_eq!(*r.match_route(None, &http::Method::GET, "/users").unwrap().value, 1);
    assert_eq!(*r.match_route(None, &http::Method::GET, "/users/").unwrap().value, 1);
}

#[test]
fn ipv6_host_with_port() {
    let mut r = router();
    r.add_route("/", HttpMethodSet::all(), vec!["::1"], 9).unwrap();

    assert_eq!(*r.match_route(Some("[::1]:8080"), &http::Method::GET, "/").unwrap().value, 9);
}

// ---------------------------------------------------------------------------
// Mid-path wildcard (* in middle, single-segment)
// ---------------------------------------------------------------------------

#[test]
fn mid_path_wildcard() {
    let mut r = router();
    r.add_route("/api/*/action", HttpMethodSet::all(), vec![], 60).unwrap();
    let m = r.match_route(None, &http::Method::GET, "/api/v1/action").unwrap();
    assert_eq!(*m.value, 60);
}

#[test]
fn mid_path_wildcard_no_match_multi_segment() {
    let mut r = router();
    r.add_route("/api/*/action", HttpMethodSet::all(), vec![], 60).unwrap();
    // Mid-path * is single-segment only
    assert_eq!(
        r.match_route(None, &http::Method::GET, "/api/v1/sub/action").unwrap_err(),
        MatchError::NotFound
    );
}

// ---------------------------------------------------------------------------
// README: Param + wildcard mix
// ---------------------------------------------------------------------------

#[test]
fn param_and_wildcard_mix() {
    let mut r = router();
    r.add_route("/users/:id/posts/*", HttpMethodSet::all(), vec![], 70).unwrap();
    let m = r.match_route(None, &http::Method::GET, "/users/1/posts/a/b").unwrap();
    assert_eq!(*m.value, 70);
    assert_eq!(m.params.get("id"), Some("1"));
    assert_eq!(m.params.get("_"), Some("a/b"));
}

#[test]
fn param_and_wildcard_mix_single() {
    let mut r = router();
    r.add_route("/users/:id/posts/*", HttpMethodSet::all(), vec![], 70).unwrap();
    let m = r.match_route(None, &http::Method::GET, "/users/42/posts/latest").unwrap();
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
    r.add_route("/*", HttpMethodSet::all(), vec![], 99).unwrap();
    assert_eq!(*r.match_route(None, &http::Method::GET, "/anything").unwrap().value, 99);
    assert_eq!(*r.match_route(None, &http::Method::GET, "/a/b/c").unwrap().value, 99);
    assert_eq!(*r.match_route(None, &http::Method::GET, "/").unwrap().value, 99);
}

#[test]
fn catch_all_with_explicit_root() {
    let mut r = router();
    r.add_route("/", HttpMethodSet::all(), vec![], 1).unwrap();
    r.add_route("/*", HttpMethodSet::all(), vec![], 99).unwrap();
    // Explicit / takes priority
    assert_eq!(*r.match_route(None, &http::Method::GET, "/").unwrap().value, 1);
    // Catch-all handles everything else
    assert_eq!(*r.match_route(None, &http::Method::GET, "/foo").unwrap().value, 99);
}

// ---------------------------------------------------------------------------
// Trailing slash normalization
// ---------------------------------------------------------------------------

#[test]
fn exact_with_trailing_slash() {
    let mut r = router();
    r.add_route("/api/users", HttpMethodSet::all(), vec![], 42).unwrap();
    assert_eq!(*r.match_route(None, &http::Method::GET, "/api/users/").unwrap().value, 42);
}

#[test]
fn param_with_trailing_slash() {
    let mut r = router();
    r.add_route("/users/:uid/posts/:pid", HttpMethodSet::all(), vec![], 30).unwrap();
    let m = r.match_route(None, &http::Method::GET, "/users/7/posts/99/").unwrap();
    assert_eq!(*m.value, 30);
    assert_eq!(m.params.get("uid"), Some("7"));
    assert_eq!(m.params.get("pid"), Some("99"));
}

#[test]
fn root_slash_preserved() {
    let mut r = router();
    r.add_route("/", HttpMethodSet::all(), vec![], 1).unwrap();
    assert_eq!(*r.match_route(None, &http::Method::GET, "/").unwrap().value, 1);
}

#[test]
fn double_trailing_slash() {
    let mut r = router();
    r.add_route("/api/users", HttpMethodSet::all(), vec![], 42).unwrap();
    assert_eq!(*r.match_route(None, &http::Method::GET, "/api/users//").unwrap().value, 42);
}

// ---------------------------------------------------------------------------
// Edge cases: host resolution
// ---------------------------------------------------------------------------

#[test]
fn no_host_fallback() {
    let mut r = router();
    r.add_route("/api", HttpMethodSet::all(), vec![], 42).unwrap();
    assert_eq!(*r.match_route(None, &http::Method::GET, "/api").unwrap().value, 42);
}

#[test]
fn exact_host_match() {
    let r = router_with_vhosts();
    assert_eq!(
        *r.match_route(Some("api.example.com"), &http::Method::GET, "/").unwrap().value,
        0
    );
}

#[test]
fn wildcard_host_match() {
    let r = router_with_vhosts();
    assert_eq!(
        *r.match_route(Some("foo.example.com"), &http::Method::GET, "/").unwrap().value,
        2
    );
}

#[test]
fn wildcard_host_nested_subdomain() {
    let r = router_with_vhosts();
    assert_eq!(
        *r.match_route(Some("bar.foo.example.com"), &http::Method::GET, "/").unwrap().value,
        2
    );
}

#[test]
fn wildcard_host_no_apex() {
    let r = router_with_vhosts();
    assert_eq!(
        r.match_route(Some("example.com"), &http::Method::GET, "/").unwrap_err(),
        MatchError::NotFound
    );
}

#[test]
fn unknown_host_fallback() {
    let mut r = router();
    r.add_route("/data", HttpMethodSet::all(), vec![], 99).unwrap();
    assert_eq!(
        *r.match_route(Some("unknown.com"), &http::Method::GET, "/data").unwrap().value,
        99
    );
}

#[test]
fn host_port_stripped() {
    let r = router_with_vhosts();
    assert_eq!(
        *r.match_route(Some("api.example.com:443"), &http::Method::GET, "/").unwrap().value,
        0
    );
}

#[test]
fn empty_host_string() {
    let mut r = router();
    r.add_route("/data", HttpMethodSet::all(), vec![], 1).unwrap();
    assert_eq!(*r.match_route(Some(""), &http::Method::GET, "/data").unwrap().value, 1);
}

// ---------------------------------------------------------------------------
// Edge cases: method filtering
// ---------------------------------------------------------------------------

#[test]
fn all_methods_default() {
    let mut r = router();
    r.add_route("/any", HttpMethodSet::all(), vec![], 42).unwrap();
    for m in &[
        http::Method::GET,
        http::Method::POST,
        http::Method::PUT,
        http::Method::DELETE,
        http::Method::PATCH,
        http::Method::HEAD,
        http::Method::OPTIONS,
        http::Method::TRACE,
        http::Method::CONNECT,
    ] {
        assert!(r.match_route(None, m, "/any").is_ok(), "method {} should be allowed", m);
    }
}

#[test]
fn method_vhost_specific_allowed() {
    let r = router_with_vhosts();
    assert_eq!(
        *r.match_route(Some("api.example.com"), &http::Method::GET, "/").unwrap().value,
        0
    );
    assert_eq!(
        *r.match_route(Some("api.example.com"), &http::Method::POST, "/").unwrap().value,
        0
    );
}

#[test]
fn method_vhost_specific_rejected() {
    let r = router_with_vhosts();
    assert_eq!(
        r.match_route(Some("api.example.com"), &http::Method::DELETE, "/").unwrap_err(),
        MatchError::MethodNotAllowed
    );
}

// ---------------------------------------------------------------------------
// Edge cases: method merging
// ---------------------------------------------------------------------------

#[test]
fn methods_are_checked_per_route_on_same_host() {
    let mut r = Router::new();
    r.add_route("/a", HttpMethodSet::new(HttpMethod::GET), vec!["merge.test"], 1).unwrap();
    r.add_route("/b", HttpMethodSet::new(HttpMethod::POST), vec!["merge.test"], 2).unwrap();

    assert_eq!(*r.match_route(Some("merge.test"), &http::Method::GET, "/a").unwrap().value, 1);
    assert_eq!(
        *r.match_route(Some("merge.test"), &http::Method::POST, "/b").unwrap().value,
        2
    );
    assert_eq!(
        r.match_route(Some("merge.test"), &http::Method::POST, "/a").unwrap_err(),
        MatchError::MethodNotAllowed
    );
    assert_eq!(
        r.match_route(Some("merge.test"), &http::Method::GET, "/b").unwrap_err(),
        MatchError::MethodNotAllowed
    );
}

#[test]
fn merge_methods_on_default_host() {
    let mut r = Router::new();
    r.add_route("/a", HttpMethodSet::new(HttpMethod::GET), vec![], 1).unwrap();
    r.add_route("/b", HttpMethodSet::new(HttpMethod::POST), vec![], 2).unwrap();

    assert!(r.match_route(None, &http::Method::GET, "/a").is_ok());
    assert!(r.match_route(None, &http::Method::POST, "/b").is_ok());
}

// ---------------------------------------------------------------------------
// Edge cases: priority (static > param > catch-all)
// ---------------------------------------------------------------------------

#[test]
fn static_over_param() {
    let mut r = router();
    r.add_route("/users/:id", HttpMethodSet::all(), vec![], 1).unwrap();
    r.add_route("/users/me", HttpMethodSet::all(), vec![], 2).unwrap();
    assert_eq!(*r.match_route(None, &http::Method::GET, "/users/me").unwrap().value, 2);
    assert_eq!(*r.match_route(None, &http::Method::GET, "/users/42").unwrap().value, 1);
}

#[test]
fn static_over_catch_all() {
    let mut r = router();
    r.add_route("/*", HttpMethodSet::all(), vec![], 1).unwrap();
    r.add_route("/users/me", HttpMethodSet::all(), vec![], 2).unwrap();

    assert_eq!(*r.match_route(None, &http::Method::GET, "/users/me").unwrap().value, 2);
    assert_eq!(*r.match_route(None, &http::Method::GET, "/anything/else").unwrap().value, 1);
}

// ---------------------------------------------------------------------------
// Edge cases: virtual host isolation
// ---------------------------------------------------------------------------

#[test]
fn vhost_isolation() {
    let mut r = Router::new();
    r.add_route("/secret", HttpMethodSet::all(), vec!["a.com"], 1).unwrap();
    r.add_route("/public", HttpMethodSet::all(), vec!["b.com"], 2).unwrap();

    assert_eq!(*r.match_route(Some("a.com"), &http::Method::GET, "/secret").unwrap().value, 1);
    assert!(r.match_route(Some("a.com"), &http::Method::GET, "/public").is_err());
    assert_eq!(*r.match_route(Some("b.com"), &http::Method::GET, "/public").unwrap().value, 2);
    assert!(r.match_route(Some("b.com"), &http::Method::GET, "/secret").is_err());
}

// ---------------------------------------------------------------------------
// Edge cases: tree operations
// ---------------------------------------------------------------------------

#[test]
fn remove_route() {
    let mut r = router();
    r.add_route("/remove", HttpMethodSet::all(), vec![], 42).unwrap();
    assert!(r.match_route(None, &http::Method::GET, "/remove").is_ok());
    let removed = r.remove("/remove");
    assert_eq!(removed, Some(42));
    assert!(r.match_route(None, &http::Method::GET, "/remove").is_err());
}

#[test]
fn duplicate_insert_returns_err() {
    let mut r = router();
    r.add_route("/path", HttpMethodSet::all(), vec![], 1).unwrap();
    let result = r.add_route("/path", HttpMethodSet::all(), vec![], 2);
    assert!(result.is_err(), "duplicate insert should return error");
}

#[test]
fn empty_router() {
    let r = router();
    assert_eq!(
        r.match_route(None, &http::Method::GET, "/anything").unwrap_err(),
        MatchError::NotFound
    );
}

// ---------------------------------------------------------------------------
// Edge cases: unicode
// ---------------------------------------------------------------------------

#[test]
fn unicode_static() {
    let mut r = router();
    r.add_route("/café", HttpMethodSet::all(), vec![], 1).unwrap();
    assert_eq!(*r.match_route(None, &http::Method::GET, "/café").unwrap().value, 1);
}

#[test]
fn unicode_param() {
    let mut r = router();
    r.add_route("/users/:name", HttpMethodSet::all(), vec![], 1).unwrap();
    let m = r.match_route(None, &http::Method::GET, "/users/ユーザー").unwrap();
    assert_eq!(*m.value, 1);
    assert_eq!(m.params.get("name"), Some("ユーザー"));
}

// ---------------------------------------------------------------------------
// Edge cases: miscellaneous
// ---------------------------------------------------------------------------

#[test]
fn dot_in_path() {
    let mut r = router();
    r.add_route("/api/v1.0/resource", HttpMethodSet::all(), vec![], 1).unwrap();
    assert_eq!(
        *r.match_route(None, &http::Method::GET, "/api/v1.0/resource").unwrap().value,
        1
    );
}

#[test]
fn numeric_param_value() {
    let mut r = router();
    r.add_route("/items/:id", HttpMethodSet::all(), vec![], 1).unwrap();
    let m = r.match_route(None, &http::Method::GET, "/items/12345").unwrap();
    assert_eq!(*m.value, 1);
    assert_eq!(m.params.get("id"), Some("12345"));
}

#[test]
fn deeply_nested() {
    let mut r = router();
    r.add_route("/a/b/c/d/e/f/g/h/i/j/k/l/m/n/foo", HttpMethodSet::all(), vec![], 1).unwrap();
    assert_eq!(
        *r.match_route(None, &http::Method::GET, "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/foo").unwrap().value,
        1
    );
}

#[test]
fn many_params() {
    let mut r = router();
    r.add_route("/:a/:b/:c/:d/:e/:f/:g/:h", HttpMethodSet::all(), vec![], 1).unwrap();
    let m = r.match_route(None, &http::Method::GET, "/1/2/3/4/5/6/7/8").unwrap();
    assert_eq!(*m.value, 1);
    assert_eq!(m.params.get("a"), Some("1"));
    assert_eq!(m.params.get("h"), Some("8"));
}

#[test]
fn backtracking_scenario() {
    let mut r = router();
    r.add_route("/a/b/c", HttpMethodSet::all(), vec![], 1).unwrap();
    r.add_route("/a/:b/c", HttpMethodSet::all(), vec![], 2).unwrap();
    r.add_route("/a/:b/d", HttpMethodSet::all(), vec![], 3).unwrap();
    assert_eq!(*r.match_route(None, &http::Method::GET, "/a/b/c").unwrap().value, 1);
    assert_eq!(*r.match_route(None, &http::Method::GET, "/a/x/c").unwrap().value, 2);
    assert_eq!(*r.match_route(None, &http::Method::GET, "/a/x/d").unwrap().value, 3);
}

#[test]
fn root_path() {
    let mut r = router();
    r.add_route("/", HttpMethodSet::all(), vec![], 1).unwrap();
    assert_eq!(*r.match_route(None, &http::Method::GET, "/").unwrap().value, 1);
}

#[test]
fn find_route_mut() {
    let mut r = router();
    r.add_route("/counter", HttpMethodSet::all(), vec![], 0u32).unwrap();
    {
        let m = r.find_route_mut(None, &http::Method::GET, "/counter").unwrap();
        *m.value += 1;
    }
    assert_eq!(*r.match_route(None, &http::Method::GET, "/counter").unwrap().value, 1);
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
        r.add_route(path, HttpMethodSet::all(), vec![], i as u32).unwrap();
    }

    assert_eq!(*r.match_route(None, &http::Method::GET, "/api/v1/users").unwrap().value, 0);
    assert_eq!(*r.match_route(None, &http::Method::GET, "/api/v1/users/42").unwrap().value, 1);
    assert_eq!(
        *r.match_route(None, &http::Method::GET, "/api/v1/users/42/posts").unwrap().value,
        2
    );
    let m = r.match_route(None, &http::Method::GET, "/api/v1/users/42/posts/7").unwrap();
    assert_eq!(*m.value, 3);
    assert_eq!(m.params.get("pid"), Some("7"));
    assert_eq!(*r.match_route(None, &http::Method::GET, "/api/v1/posts").unwrap().value, 4);
    assert_eq!(*r.match_route(None, &http::Method::GET, "/api/v2/users").unwrap().value, 5);
    assert_eq!(*r.match_route(None, &http::Method::GET, "/api/health").unwrap().value, 6);
    assert_eq!(
        *r.match_route(None, &http::Method::GET, "/static/files/main.js").unwrap().value,
        7
    );
    assert_eq!(
        *r.match_route(None, &http::Method::GET, "/static/files/a/b/c").unwrap().value,
        7
    );

    // catch-all
    assert_eq!(*r.match_route(None, &http::Method::GET, "/unknown/path").unwrap().value, 8);
    assert_eq!(*r.match_route(None, &http::Method::GET, "/").unwrap().value, 8);
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
        r.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap();
    }
    for i in 0..n {
        let path = format!("/route/{}/detail", i);
        let m = r.match_route(None, &http::Method::GET, &path).unwrap();
        assert_eq!(*m.value, i);
    }
}

#[test]
fn stress_many_vhosts() {
    let mut r = Router::new();
    let n = 1_000;
    for i in 0..n {
        let host = format!("host{}.example.com", i);
        r.add_route("/data", HttpMethodSet::all(), vec![&host], i).unwrap();
    }
    for i in 0..n {
        let host = format!("host{}.example.com", i);
        let m = r.match_route(Some(&host), &http::Method::GET, "/data").unwrap();
        assert_eq!(*m.value, i);
    }
}

#[test]
fn stress_param_routes() {
    let mut r = router();
    let n = 1_000;
    for i in 0..n {
        let path = format!("/resource/{}/item", i);
        r.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap();
    }
    for i in 0..n {
        let path = format!("/resource/{}/item", i);
        let m = r.match_route(None, &http::Method::GET, &path).unwrap();
        assert_eq!(*m.value, i);
    }
}

#[test]
fn stress_mixed_routes() {
    let mut r = router();
    // Insert 5000 static + 500 param + 500 wildcard + catch-all
    let n_static = 5_000;
    let n_param = 500;
    let n_wild = 500;

    for i in 0..n_static {
        let path = format!("/static/route/{}", i);
        r.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap();
    }
    for i in 0..n_param {
        let path = format!("/param/{}/route", i);
        r.add_route(&path, HttpMethodSet::all(), vec![], n_static + i).unwrap();
    }
    for i in 0..n_wild {
        let path = format!("/wildcard/dir{}/*", i);
        r.add_route(&path, HttpMethodSet::all(), vec![], n_static + n_param + i).unwrap();
    }

    // Verify all static
    for i in 0..n_static {
        let path = format!("/static/route/{}", i);
        let m = r.match_route(None, &http::Method::GET, &path).unwrap();
        assert_eq!(*m.value, i);
    }
    // Verify wildcard
    for i in 0..n_wild {
        let path = format!("/wildcard/dir{}/sub/deep/file.txt", i);
        let m = r.match_route(None, &http::Method::GET, &path).unwrap();
        assert_eq!(*m.value, n_static + n_param + i);
    }
}

// ---------------------------------------------------------------------------
// Edge cases: verify_nonexistent_paths
// ---------------------------------------------------------------------------

#[test]
fn edge_case_nonexistent_deep() {
    let mut r = router();
    r.add_route("/api/v1/users", HttpMethodSet::all(), vec![], 1).unwrap();
    assert_eq!(
        r.match_route(None, &http::Method::GET, "/api/v1/users/nonexistent").unwrap_err(),
        MatchError::NotFound
    );
    assert_eq!(
        r.match_route(None, &http::Method::GET, "/api/v1").unwrap_err(),
        MatchError::NotFound
    );
}

#[test]
fn edge_case_partial_prefix() {
    let mut r = router();
    r.add_route("/api/v1/users", HttpMethodSet::all(), vec![], 1).unwrap();
    r.add_route("/api/v2", HttpMethodSet::all(), vec![], 2).unwrap();
    assert_eq!(*r.match_route(None, &http::Method::GET, "/api/v2").unwrap().value, 2);
    assert_eq!(
        r.match_route(None, &http::Method::GET, "/api/v2/extra").unwrap_err(),
        MatchError::NotFound
    );
}

// ---------------------------------------------------------------------------
// Several routes on one path, chosen by method
// ---------------------------------------------------------------------------

#[test]
fn same_path_routes_are_chosen_by_method() {
    let mut r = Router::new();
    r.add_route("/users", HttpMethodSet::new(HttpMethod::GET), vec!["api.test"], 1).unwrap();
    r.add_route(
        "/users",
        HttpMethodSet::new(HttpMethod::POST | HttpMethod::PUT),
        vec!["api.test"],
        2,
    )
    .unwrap();

    assert_eq!(
        *r.match_route(Some("api.test"), &http::Method::GET, "/users").unwrap().value,
        1
    );
    assert_eq!(
        *r.match_route(Some("api.test"), &http::Method::POST, "/users").unwrap().value,
        2
    );
    assert_eq!(
        *r.match_route(Some("api.test"), &http::Method::PUT, "/users").unwrap().value,
        2
    );
    assert_eq!(
        r.match_route(Some("api.test"), &http::Method::DELETE, "/users").unwrap_err(),
        MatchError::MethodNotAllowed
    );
}

#[test]
fn same_path_routes_sharing_a_method_conflict() {
    let mut r = Router::new();
    r.add_route(
        "/users",
        HttpMethodSet::new(HttpMethod::GET | HttpMethod::POST),
        vec!["api.test"],
        1,
    )
    .unwrap();

    let err = r.add_route("/users", HttpMethodSet::new(HttpMethod::POST), vec!["api.test"], 2).unwrap_err();
    assert!(matches!(err, InsertError::MethodConflict { .. }), "{err}");

    // A route without methods accepts all of them, so it overlaps any other route.
    let err = r.add_route("/users", HttpMethodSet::new(HttpMethod::NONE), vec!["api.test"], 3).unwrap_err();
    assert!(matches!(err, InsertError::MethodConflict { .. }), "{err}");

    // The failed insertions left the first route in place.
    assert_eq!(
        *r.match_route(Some("api.test"), &http::Method::POST, "/users").unwrap().value,
        1
    );
}

#[test]
fn same_path_on_other_hosts_does_not_conflict() {
    let mut r = Router::new();
    r.add_route("/users", HttpMethodSet::new(HttpMethod::GET), vec!["a.test"], 1).unwrap();
    r.add_route("/users", HttpMethodSet::new(HttpMethod::GET), vec!["b.test"], 2).unwrap();

    assert_eq!(*r.match_route(Some("a.test"), &http::Method::GET, "/users").unwrap().value, 1);
    assert_eq!(*r.match_route(Some("b.test"), &http::Method::GET, "/users").unwrap().value, 2);
}

#[test]
fn catch_all_routes_by_method_share_the_implicit_base() {
    let mut r = Router::new();
    r.add_route("/files/*", HttpMethodSet::new(HttpMethod::GET), vec!["api.test"], 1).unwrap();
    r.add_route("/files/*", HttpMethodSet::new(HttpMethod::POST), vec!["api.test"], 2).unwrap();

    assert_eq!(
        *r.match_route(Some("api.test"), &http::Method::GET, "/files/a.txt").unwrap().value,
        1
    );
    assert_eq!(
        *r.match_route(Some("api.test"), &http::Method::POST, "/files/a.txt").unwrap().value,
        2
    );
    assert_eq!(
        *r.match_route(Some("api.test"), &http::Method::GET, "/files").unwrap().value,
        1
    );
    assert_eq!(
        *r.match_route(Some("api.test"), &http::Method::POST, "/files").unwrap().value,
        2
    );
}

#[test]
fn explicit_base_route_only_replaces_its_methods_of_the_catch_all() {
    let mut r = Router::new();
    r.add_route("/users/*", HttpMethodSet::new(HttpMethod::GET), vec!["api.test"], 1).unwrap();
    r.add_route("/users", HttpMethodSet::new(HttpMethod::POST), vec!["api.test"], 2).unwrap();

    assert_eq!(
        *r.match_route(Some("api.test"), &http::Method::GET, "/users").unwrap().value,
        1
    );
    assert_eq!(
        *r.match_route(Some("api.test"), &http::Method::POST, "/users").unwrap().value,
        2
    );
}

#[test]
fn explicit_base_route_wins_over_the_catch_all_in_any_order() {
    let mut first_explicit = Router::new();
    first_explicit.add_route("/users", HttpMethodSet::new(HttpMethod::GET), vec![], 2).unwrap();
    first_explicit.add_route("/users/*", HttpMethodSet::new(HttpMethod::GET), vec![], 1).unwrap();

    let mut first_catch_all = Router::new();
    first_catch_all.add_route("/users/*", HttpMethodSet::new(HttpMethod::GET), vec![], 1).unwrap();
    first_catch_all.add_route("/users", HttpMethodSet::new(HttpMethod::GET), vec![], 2).unwrap();

    for r in [first_explicit, first_catch_all] {
        assert_eq!(*r.match_route(None, &http::Method::GET, "/users").unwrap().value, 2);
        assert_eq!(*r.match_route(None, &http::Method::GET, "/users/42").unwrap().value, 1);
    }
}

#[test]
fn catch_all_keeps_the_base_methods_an_explicit_route_does_not_take() {
    let mut r = Router::new();
    r.add_route(
        "/users/*",
        HttpMethodSet::new(HttpMethod::GET | HttpMethod::OPTIONS),
        vec![],
        1,
    )
    .unwrap();
    r.add_route(
        "/users",
        HttpMethodSet::new(HttpMethod::POST | HttpMethod::OPTIONS),
        vec![],
        2,
    )
    .unwrap();

    assert_eq!(*r.match_route(None, &http::Method::GET, "/users").unwrap().value, 1);
    assert_eq!(*r.match_route(None, &http::Method::POST, "/users").unwrap().value, 2);
    assert_eq!(*r.match_route(None, &http::Method::OPTIONS, "/users").unwrap().value, 2);
    assert_eq!(*r.match_route(None, &http::Method::OPTIONS, "/users/42").unwrap().value, 1);
}
