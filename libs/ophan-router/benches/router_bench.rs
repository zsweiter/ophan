use std::time::Duration;

#[allow(unused_imports)]
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ophan_net::http::{HttpMethod, HttpMethodSet};
use ophan_router::Router;

fn bench_insert_exact(c: &mut Criterion) {
    c.bench_function("insert_10k_exact", |b| {
        b.iter(|| {
            let mut router = Router::<u32>::new();
            for i in 0..10_000 {
                let path = format!("/route/{i}");
                black_box(router.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap());
            }
        });
    });
}

fn bench_match_exact(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    for i in 0..10_000 {
        let path = format!("/route/{i}");
        router.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap();
    }
    c.bench_function("match_10k_exact_hit", |b| {
        b.iter(|| {
            for i in 0..10_000 {
                let path = format!("/route/{}", i);
                let m = router.match_route(None, &http::Method::GET, &path).unwrap();
                black_box(*m.value);
            }
        });
    });
}

fn bench_match_exact_miss(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    for i in 0..1_000 {
        let path = format!("/route/{i}");
        router.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap();
    }
    c.bench_function("match_1k_exact_miss", |b| {
        b.iter(|| {
            let _ = black_box(router.match_route(None, &http::Method::GET, "/nonexistent"));
        });
    });
}

fn bench_match_param(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    for i in 0..1_000 {
        let path = format!("/users/{i}/posts/{i}");
        router.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap();
    }
    // Also add a param route
    router.add_route("/users/:uid/posts/:pid", HttpMethodSet::all(), vec![], 999).unwrap();

    c.bench_function("match_param", |b| {
        b.iter(|| {
            let m = router.match_route(None, &http::Method::GET, "/users/42/posts/99").unwrap();
            black_box(*m.value);
            black_box(m.params.get("uid"));
            black_box(m.params.get("pid"));
        });
    });
}

fn bench_match_wildcard(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    router.add_route("/static/files/*", HttpMethodSet::all(), vec![], 1).unwrap();

    c.bench_function("match_wildcard_multi", |b| {
        b.iter(|| {
            let m = router.match_route(None, &http::Method::GET, "/static/files/a/b/c/d/e/f").unwrap();
            black_box(*m.value);
        });
    });
}

fn bench_match_catch_all(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    // Many specific routes + catch-all
    for i in 0..1_000 {
        let path = format!("/specific/route/{i}");
        router.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap();
    }
    router.add_route("/*", HttpMethodSet::all(), vec![], 999).unwrap();

    c.bench_function("match_catch_all_fallback", |b| {
        b.iter(|| {
            let m = router.match_route(None, &http::Method::GET, "/unknown/path").unwrap();
            black_box(*m.value);
        });
    });
}

fn bench_host_resolution(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    for i in 0..5_000 {
        let host = format!("host{i}.example.com");
        router.add_route("/", HttpMethodSet::all(), vec![&host], i).unwrap();
    }

    router.add_route("/", HttpMethodSet::all(), vec!["*.wild.com"], 999).unwrap();

    c.bench_function("host_resolve_exact", |b| {
        b.iter(|| {
            let m = router.match_route(Some("host4242.example.com"), &http::Method::GET, "/").unwrap();
            black_box(*m.value);
        });
    });

    c.bench_function("host_resolve_wildcard", |b| {
        b.iter(|| {
            let m = router.match_route(Some("foo.wild.com"), &http::Method::GET, "/").unwrap();
            black_box(*m.value);
        });
    });

    c.bench_function("host_resolve_fallback", |b| {
        b.iter(|| {
            let _ = black_box(router.match_route(Some("unknown.com"), &http::Method::GET, "/"));
        });
    });
}

fn bench_mixed_workload(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    // 5000 static + 500 param + 500 wildcard + catch-all
    for i in 0..5_000 {
        let path = format!("/api/v{}/resource/{}", i % 10, i);
        router.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap();
    }
    router.add_route("/*", HttpMethodSet::all(), vec![], 9999).unwrap();

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
                let m = router.match_route(None, &http::Method::GET, path).unwrap();
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
                    router.add_route(&path, HttpMethodSet::new(HttpMethod::GET), vec![&host], v * 100 + r).unwrap();
                }
            }
            // Verify a few
            for v in 0..100 {
                let host = format!("vhost{v}.test.com");
                for r in (0..100).step_by(10) {
                    let path = format!("/route/{r}");
                    let m = router.match_route(Some(&host), &http::Method::GET, &path).unwrap();
                    black_box(*m.value);
                }
            }
        });
    });
}

// ═══════════════════════════════════════════════════
//  EXTREME BENCHMARKS — scale
// ═══════════════════════════════════════════════════

fn bench_insert_100k_exact(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert_100K_exact");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(10));
    group.bench_function("insert_100K_exact", |b| {
        b.iter(|| {
            let mut router = Router::<u32>::new();
            for i in 0..100_000 {
                let path = format!("/r/{i}");
                black_box(router.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap());
            }
        });
    });
    group.finish();
}

fn bench_match_100k_exact_hit(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    for i in 0..100_000 {
        let path = format!("/r/{i}");
        router.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap();
    }
    let mut group = c.benchmark_group("match_100K_exact_hit");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(10));
    group.bench_function("match_100K_exact_hit", |b| {
        b.iter(|| {
            for i in 0..100_000 {
                let path = format!("/r/{i}");
                let m = router.match_route(None, &http::Method::GET, &path).unwrap();
                black_box(*m.value);
            }
        });
    });
    group.finish();
}

fn bench_insert_10k_deep_params(c: &mut Criterion) {
    c.bench_function("insert_10K_deep_params", |b| {
        b.iter(|| {
            let mut router = Router::<u32>::new();
            for i in 0..10_000 {
                let path = format!("/a/{i}/b/{i}/c/{i}/d/{i}/e/{i}");
                black_box(router.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap());
            }
        });
    });
}

// ═══════════════════════════════════════════════════
//  EXTREME BENCHMARKS — adversarial insertion
// ═══════════════════════════════════════════════════

fn bench_insert_reverse_order(c: &mut Criterion) {
    c.bench_function("insert_10K_reverse_sorted", |b| {
        b.iter(|| {
            let mut router = Router::<u32>::new();
            for i in (0..10_000).rev() {
                let path = format!("/route/{i}");
                black_box(router.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap());
            }
        });
    });
}

fn bench_insert_common_prefix(c: &mut Criterion) {
    c.bench_function("insert_10K_common_prefix", |b| {
        b.iter(|| {
            let mut router = Router::<u32>::new();
            for i in 0..10_000 {
                let path = format!("/api/v1/users/{i}/posts/{i}/comments/{i}");
                black_box(router.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap());
            }
        });
    });
}

fn bench_insert_interleaved(c: &mut Criterion) {
    c.bench_function("insert_10K_interleaved", |b| {
        b.iter(|| {
            let mut router = Router::<u32>::new();
            for i in 0..5_000 {
                let a = format!("/static/{i}");
                let b = format!("/api/{i}");
                black_box(router.add_route(&a, HttpMethodSet::all(), vec![], i).unwrap());
                black_box(router.add_route(&b, HttpMethodSet::all(), vec![], i + 5_000).unwrap());
            }
        });
    });
}

// ═══════════════════════════════════════════════════
//  EXTREME BENCHMARKS — adversarial matching
// ═══════════════════════════════════════════════════

fn bench_match_deep_miss(c: &mut Criterion) {
    // Build a tree with a deep param route, then match a path that
    // almost works but fails at the last segment, forcing backtracking
    // at each level.
    let mut router = Router::<u32>::new();
    for i in 0..1_000 {
        let path = format!("/a/{i}/b/{i}/c/{i}/d/{i}/e/{i}");
        router.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap();
    }
    // Deep param route at the same prefix
    router.add_route("/a/{p1}/b/{p2}/c/{p3}/d/{p4}/e/{p5}", HttpMethodSet::all(), vec![], 9999).unwrap();

    c.bench_function("match_deep_backtrack", |b| {
        b.iter(|| {
            // This hits the param route after passing through all levels
            let m = router.match_route(None, &http::Method::GET, "/a/x/b/y/c/z/d/w/e/v").unwrap();
            black_box(*m.value);
            black_box(m.params.get("p5"));
        });
    });
}

fn bench_match_many_params_extract(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    router.add_route("/{a}/{b}/{c}/{d}/{e}", HttpMethodSet::all(), vec![], 1).unwrap();

    c.bench_function("match_5_params_extract_all", |b| {
        b.iter(|| {
            let m = router.match_route(None, &http::Method::GET, "/p1/p2/p3/p4/p5").unwrap();
            black_box(*m.value);
            black_box(m.params.get("a"));
            black_box(m.params.get("b"));
            black_box(m.params.get("c"));
            black_box(m.params.get("d"));
            black_box(m.params.get("e"));
        });
    });
}

fn bench_match_adversarial_fallback(c: &mut Criterion) {
    // Insert many static routes at a deep level plus a catch-all at root
    let mut router = Router::<u32>::new();
    for i in 0..10_000 {
        let path = format!("/api/v1/resources/{i}/details");
        router.add_route(&path, HttpMethodSet::all(), vec![], i).unwrap();
    }
    router.add_route("/*", HttpMethodSet::all(), vec![], 9999).unwrap();

    c.bench_function("match_10K_static_plus_catchall_miss", |b| {
        b.iter(|| {
            // Falls through all static then hits catch-all
            let m = router.match_route(None, &http::Method::GET, "/api/v1/resources/99999/details").unwrap();
            black_box(*m.value);
        });
    });
}

// ═══════════════════════════════════════════════════
//  EXTREME BENCHMARKS — host resolution
// ═══════════════════════════════════════════════════

fn bench_host_resolution_extreme(c: &mut Criterion) {
    let mut router = Router::<u32>::new();
    for i in 0..10_000 {
        let host = format!("host{i}.example.com");
        router.add_route("/", HttpMethodSet::all(), vec![&host], i).unwrap();
    }
    router.add_route("/", HttpMethodSet::all(), vec!["*.deep.wildcard.com"], 9999).unwrap();

    c.bench_function("host_resolve_wildcard_deep", |b| {
        b.iter(|| {
            // Match against deep subdomain: tries wildcard matching with many labels
            let m = router.match_route(Some("a.b.c.deep.wildcard.com"), &http::Method::GET, "/").unwrap();
            black_box(*m.value);
        });
    });

    c.bench_function("host_resolve_miss_32_labels", |b| {
        b.iter(|| {
            // Build a 32-label hostname that fails at the sni table limit
            let host = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.a.b.c.d.e.f";
            let _ = black_box(router.match_route(Some(host), &http::Method::GET, "/"));
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
    bench_host_resolution,
    bench_mixed_workload,
    bench_insert_and_match_many_vhosts,
    bench_insert_100k_exact,
    bench_match_100k_exact_hit,
    bench_insert_10k_deep_params,
    bench_insert_reverse_order,
    bench_insert_common_prefix,
    bench_insert_interleaved,
    bench_match_deep_miss,
    bench_match_many_params_extract,
    bench_match_adversarial_fallback,
    bench_host_resolution_extreme,
);

criterion_main!(benches);
