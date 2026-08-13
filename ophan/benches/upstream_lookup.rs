use std::sync::Arc;

use ahash::AHashMap;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use flatkit::str::ImmerStr;

#[derive(Default)]
struct Backend;

struct Upstream {
    servers: Vec<Arc<Backend>>,
}

struct LoadBalancer {
    upstream_by_map: AHashMap<ImmerStr, Arc<Upstream>>,
    upstream_by_idx: Vec<Arc<Upstream>>,
}

struct RouteMap {
    upstream_name: ImmerStr,
}

struct RouteIdx {
    upstream_id: usize,
}

struct RouteArc {
    upstream: Arc<Upstream>,
}

impl LoadBalancer {
    #[inline(always)]
    fn get(&self, name: &ImmerStr) -> &Arc<Upstream> {
        self.upstream_by_map.get(name).unwrap()
    }

    #[inline(always)]
    fn get_by_id(&self, id: usize) -> &Arc<Upstream> {
        &self.upstream_by_idx.get(id).unwrap()
    }

    #[inline(always)]
    fn get_by_id_unchecked(&self, id: usize) -> &Arc<Upstream> {
        unsafe { self.upstream_by_idx.get_unchecked(id) }
    }
}

fn build() -> (LoadBalancer, RouteMap, RouteIdx, RouteArc) {
    const NUM_UPSTREAMS: usize = 128;
    const SERVERS_PER_UPSTREAM: usize = 16;
    const TARGET: usize = 37;

    let mut upstreams = Vec::with_capacity(NUM_UPSTREAMS);

    for _ in 0..NUM_UPSTREAMS {
        let servers = (0..SERVERS_PER_UPSTREAM).map(|_| Arc::new(Backend)).collect();

        upstreams.push(Arc::new(Upstream { servers }));
    }

    let mut upstream_by_map = AHashMap::new();

    for (i, upstream) in upstreams.iter().enumerate() {
        upstream_by_map.insert(ImmerStr::from(format!("upstream-{i}")), Arc::clone(upstream));
    }

    let upstream_by_idx = upstreams;

    let lb = LoadBalancer { upstream_by_map, upstream_by_idx };

    let route_map = RouteMap { upstream_name: ImmerStr::from(format!("upstream-{TARGET}")) };

    let route_idx = RouteIdx { upstream_id: TARGET };

    let route_arc = RouteArc { upstream: Arc::clone(&lb.upstream_by_idx[TARGET]) };

    (lb, route_map, route_idx, route_arc)
}

fn bench_lookup(c: &mut Criterion) {
    let (lb, route_map, route_idx, route_arc) = build();

    let mut group = c.benchmark_group("upstream_lookup");

    group.bench_function("hashmap", |b| {
        b.iter(|| {
            let upstream = lb.get(black_box(&route_map.upstream_name));
            black_box(upstream.servers.len());
        });
    });

    group.bench_function("index_checked", |b| {
        b.iter(|| {
            let upstream = lb.get_by_id(black_box(route_idx.upstream_id));
            black_box(upstream.servers.len());
        });
    });

    group.bench_function("index_unchecked", |b| {
        b.iter(|| {
            let upstream = lb.get_by_id_unchecked(black_box(route_idx.upstream_id));
            black_box(upstream.servers.len());
        });
    });

    group.bench_function("arc", |b| {
        b.iter(|| {
            black_box(route_arc.upstream.servers.len());
        });
    });

    group.finish();
}

criterion_group!(benches, bench_lookup);
criterion_main!(benches);
