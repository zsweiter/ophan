use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use flatkit::net::IpSet;
use std::net::IpAddr;

/// ~4k mixed v4/v6 CIDR set, mimicking a realistic geo/allowlist feed:
/// v4 dominates (~3k entries of scattered /24-/16s), v6 candidates fill in the
/// typical /32-/48 downstream prefixes.
fn build_hot_load() -> IpSet {
    let mut builder = IpSet::builder();

    // Hot allowlist range under test: never collides with the scattered
    // generated ranges below (their second octet stays under 25).
    builder.insert("10.100.50.0/24").unwrap();

    for i in 0..3000 {
        let octets = [10 + (i % 120) as u8, (i / 120) as u8, 0, 0];
        let prefix = match i % 4 {
            0 => "/24",
            1 => "/32",
            2 => "/16",
            _ => "/28",
        };
        let cidr = format!("{}.{}.{}.{}{prefix}", octets[0], octets[1], octets[2], octets[3]);
        builder.insert(&cidr).unwrap();
    }

    for i in 0..1000 {
        let cidr = format!("2001:{i:x}::/{}", 32 + (i % 17));
        builder.insert(&cidr).unwrap();
    }

    builder.build()
}

fn single(i: u8) -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(10, 100, 50, i))
}

// Single IPv6 inside the hottest registered block (2001:0::/32 area).
fn single_v6() -> IpAddr {
    IpAddr::V6("2001:0:db8::1".parse().unwrap())
}

// Guaranteed miss: falls between the merged v4 ranges above.
fn outside() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(220, 173, 90, 77))
}

fn bench_set(c: &mut Criterion) {
    let mut group = c.benchmark_group("Net IpSet");

    let candidates = vec![single(1), single(255), single_v6(), outside()];

    // =========================================================================
    // LEVEL 1: MILD LOAD (empty set)
    // =========================================================================
    let empty = IpSet::default();
    group.throughput(Throughput::Elements(1));

    group.bench_function("1_mild_empty_lookup", |b| {
        b.iter(|| black_box(empty.contains(black_box(single(7)))))
    });

    // =========================================================================
    // LEVEL 2: MEDIUM LOAD (realistic size ~4k CIDRs, single match step)
    // =========================================================================
    let set = build_hot_load();
    group.throughput(Throughput::Elements(1));

    group.bench_function("2_medium_hit_v4", |b| {
        b.iter(|| black_box(set.contains(black_box(single(1)))))
    });

    group.bench_function("3_medium_hit_v6", |b| {
        b.iter(|| black_box(set.contains(black_box(single_v6()))))
    });

    group.bench_function("4_medium_miss_v4", |b| {
        b.iter(|| black_box(set.contains(black_box(outside()))))
    });

    // =========================================================================
    // LEVEL 3: HEAVY LOAD (4x repeated full-stack contains per iteration)
    // =========================================================================
    group.throughput(Throughput::Elements(candidates.len() as u64));

    group.bench_function("5_heavy_mixed_candidates", |b| {
        b.iter(|| {
            for ip in &candidates {
                black_box(set.contains(black_box(*ip)));
            }
        })
    });
}

criterion_group!(benches, bench_set);
criterion_main!(benches);
