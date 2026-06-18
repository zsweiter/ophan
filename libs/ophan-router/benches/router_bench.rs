use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ophan_net::http::{HttpMethod, HttpMethodSet};
use ophan_router::Router;

fn bench_insert_exact(c: &mut Criterion) {
    c.bench_function("insert_10k_exact", |b| {
        b.iter(|| {
            let mut router = Router::<u32>::new();
            for i in 0..10_000 {
                let path = format!("/route/{i}");
                black_box(router.add_route(None, &path, HttpMethodSet::all(), i).unwrap());
            }
        });
    });
}

fn bench_match_exact(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    for i in 0..10_000 {
        let path = format!("/route/{i}");
        router.add_route(None, &path, HttpMethodSet::all(), i).unwrap();
    }
    c.bench_function("match_10k_exact_hit", |b| {
        b.iter(|| {
            for i in 0..10_000 {
                let path = format!("/route/{}", i);
                let m = router.find_route(None, "GET", &path).unwrap();
                black_box(*m.value);
            }
        });
    });
}

fn bench_match_exact_miss(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    for i in 0..1_000 {
        let path = format!("/route/{i}");
        router.add_route(None, &path, HttpMethodSet::all(), i).unwrap();
    }
    c.bench_function("match_1k_exact_miss", |b| {
        b.iter(|| {
            let _ = black_box(router.find_route(None, "GET", "/nonexistent"));
        });
    });
}

fn bench_match_param(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    for i in 0..1_000 {
        let path = format!("/users/{i}/posts/{i}");
        router.add_route(None, &path, HttpMethodSet::all(), i).unwrap();
    }
    // Also add a param route
    router.add_route(None, "/users/:uid/posts/:pid", HttpMethodSet::all(), 999).unwrap();

    c.bench_function("match_param", |b| {
        b.iter(|| {
            let m = router.find_route(None, "GET", "/users/42/posts/99").unwrap();
            black_box(*m.value);
            black_box(m.params.get("uid"));
            black_box(m.params.get("pid"));
        });
    });
}

fn bench_match_wildcard(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    router.add_route(None, "/static/files/*", HttpMethodSet::all(), 1).unwrap();

    c.bench_function("match_wildcard_multi", |b| {
        b.iter(|| {
            let m = router.find_route(None, "GET", "/static/files/a/b/c/d/e/f").unwrap();
            black_box(*m.value);
        });
    });
}

fn bench_match_catch_all(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    // Many specific routes + catch-all
    for i in 0..1_000 {
        let path = format!("/specific/route/{i}");
        router.add_route(None, &path, HttpMethodSet::all(), i).unwrap();
    }
    router.add_route(None, "/*", HttpMethodSet::all(), 999).unwrap();

    c.bench_function("match_catch_all_fallback", |b| {
        b.iter(|| {
            let m = router.find_route(None, "GET", "/unknown/path").unwrap();
            black_box(*m.value);
        });
    });
}

fn bench_match_regex(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    router.add_route(None, r"^/api/v[0-9]+/.*$", HttpMethodSet::all(), 1).unwrap();

    c.bench_function("match_regex", |b| {
        b.iter(|| {
            let m = router.find_route(None, "GET", "/api/v2/users/42/posts").unwrap();
            black_box(*m.value);
        });
    });
}

fn bench_match_regex_miss(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    router.add_route(None, r"^/api/v[0-9]+/.*$", HttpMethodSet::all(), 1).unwrap();

    c.bench_function("match_regex_miss", |b| {
        b.iter(|| {
            let _ = black_box(router.find_route(None, "GET", "/other/path"));
        });
    });
}

fn bench_host_resolution(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    for i in 0..5_000 {
        let host = format!("host{i}.example.com");
        router.add_route(Some(&host), "/", HttpMethodSet::all(), i).unwrap();
    }
    router.add_route(Some("*.wild.com"), "/", HttpMethodSet::all(), 999).unwrap();

    c.bench_function("host_resolve_exact", |b| {
        b.iter(|| {
            let m = router.find_route(Some("host4242.example.com"), "GET", "/").unwrap();
            black_box(*m.value);
        });
    });

    c.bench_function("host_resolve_wildcard", |b| {
        b.iter(|| {
            let m = router.find_route(Some("foo.wild.com"), "GET", "/").unwrap();
            black_box(*m.value);
        });
    });

    c.bench_function("host_resolve_fallback", |b| {
        b.iter(|| {
            let _ = black_box(router.find_route(Some("unknown.com"), "GET", "/"));
        });
    });
}

fn bench_mixed_workload(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    // 5000 static + 500 param + 500 wildcard + 50 regex + catch-all
    for i in 0..5_000 {
        let path = format!("/api/v{}/resource/{}", i % 10, i);
        router.add_route(None, &path, HttpMethodSet::all(), i).unwrap();
    }
    router.add_route(None, "/*", HttpMethodSet::all(), 9999).unwrap();

    let requests: Vec<&str> = vec![
        // hits
        "/api/v1/resource/42",
        "/api/v5/resource/100",
        // fallback to catch-all
        "/unknown/path",
    ];

    c.bench_function("mixed_workload_3_requests", |b| {
        b.iter(|| {
            for path in &requests {
                let m = router.find_route(None, "GET", path).unwrap();
                black_box(*m.value);
            }
        });
    });
}

fn bench_insert_and_match_many_vhosts(c: &mut Criterion) {
    c.bench_function("insert_100_vhosts_100_routes_each", |b| {
        b.iter(|| {
            let mut router = Router::<u32>::new();
            for v in 0..100 {
                let host = format!("vhost{v}.test.com");
                for r in 0..100 {
                    let path = format!("/route/{}", r);
                    router.add_route(Some(&host), &path, HttpMethodSet::new(HttpMethod::GET), v * 100 + r).unwrap();
                }
            }
            // Verify a few
            for v in 0..100 {
                let host = format!("vhost{v}.test.com");
                for r in (0..100).step_by(10) {
                    let path = format!("/route/{r}");
                    let m = router.find_route(Some(&host), "GET", &path).unwrap();
                    black_box(*m.value);
                }
            }
        });
    });
}

criterion_group!(
    benches,
    bench_insert_exact,
    bench_match_exact,
    bench_match_exact_miss,
    bench_match_param,
    bench_match_wildcard,
    bench_match_catch_all,
    bench_match_regex,
    bench_match_regex_miss,
    bench_host_resolution,
    bench_mixed_workload,
    bench_insert_and_match_many_vhosts,
);
criterion_main!(benches);
