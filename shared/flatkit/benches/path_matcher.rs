use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use flatkit::matchers::path::PathMatcherSet;

fn bench_matcher(c: &mut Criterion) {
    let mut group = c.benchmark_group("Matcher PathMatcherSet");

    // =========================================================================
    // LEVEL 1: MILD LOAD (Typical Web & CLI Paths)
    // =========================================================================
    let mild_patterns = vec!["src/**/*.rs", "tests/**/*.rs", "Cargo.toml", "*.md", "scripts/{build,deploy}.sh"];

    // Pre-compilation outside the benchmark loop (measuring read/match speed only)
    let pathmatcher_mild = PathMatcherSet::compile(&mild_patterns).unwrap();

    let mild_paths = vec![
        "src/main.rs",
        "src/net/p2p/transport.rs",
        "tests/integration_test.rs",
        "Cargo.toml",
        "README.md",
        "scripts/build.sh",
        "src/core/unmatched.txt",
    ];

    group.throughput(Throughput::Elements(mild_paths.len() as u64));

    group.bench_function("1_mild_pathmatcher", |b| {
        b.iter(|| {
            for path in &mild_paths {
                black_box(pathmatcher_mild.is_match(path));
            }
        })
    });

    // =========================================================================
    // LEVEL 2: MEDIUM LOAD (Deep Directories & Wildcards)
    // =========================================================================
    let medium_patterns = vec!["**/internal/**/*.rs", "data/**/cache_*.bin", "pkg/{client,server,common}/**/*.go"];

    let pathmatcher_medium = PathMatcherSet::compile(&medium_patterns).unwrap();

    let medium_paths = vec![
        "services/auth/internal/crypto/keys.rs",
        "data/v1/us-east/cache_session_9921.bin",
        "pkg/server/transport/http/router.go",
        "services/auth/internal/db/pool.rs",
        "data/cache_invalid.bin",
        "pkg/other/transport/router.go",
    ];

    group.bench_function("2_medium_pathmatcher", |b| {
        b.iter(|| {
            for path in &medium_paths {
                black_box(pathmatcher_medium.is_match(path));
            }
        })
    });

    // =========================================================================
    // LEVEL 3: HEAVY / PATHOLOGICAL LOAD (Backtracking Stress)
    // =========================================================================
    let heavy_patterns = vec!["*a*b*c*d*e*f*", "**/x/**/y/**/z/**"];

    let pathmatcher_heavy = PathMatcherSet::compile(&heavy_patterns).unwrap();

    let heavy_paths = vec![
        "aaaaaaaaaa/bbbbbbbbbb/cccccccccc/dddddddddd/eeeeeeeeee/ffffffffff/target",
        "x/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z",
        "no_match_string_long_enough_to_force_exhaustive_evaluation_path_failure_case",
    ];

    group.bench_function("3_heavy_pathmatcher", |b| {
        b.iter(|| {
            for path in &heavy_paths {
                black_box(pathmatcher_heavy.is_match(path));
            }
        })
    });

    group.finish();
}

criterion_group!(benches, bench_matcher);
criterion_main!(benches);
