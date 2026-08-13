fn format_std(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < (1 << 20) {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < (1 << 30) {
        format!("{:.1} MB", bytes as f64 / (1 << 20) as f64)
    } else if bytes < (1 << 40) {
        format!("{:.1} GB", bytes as f64 / (1 << 30) as f64)
    } else {
        format!("{:.1} TB", bytes as f64 / (1u64 << 40) as f64)
    }
}

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use flatkit::format_size;

fn bench_custom(c: &mut Criterion) {
    let values = [0, 1, 999, 1023, 1024, 1536, 10_000, 100_000, 1_000_000, 50_000_000, 1_000_000_000, 10_000_000_000];

    c.bench_function("custom format_size", |b| {
        b.iter(|| {
            for &v in &values {
                black_box(format_size(black_box(v)));
            }
        });
    });
}

fn bench_format(c: &mut Criterion) {
    let values = [0, 1, 999, 1023, 1024, 1536, 10_000, 100_000, 1_000_000, 50_000_000, 1_000_000_000, 10_000_000_000];

    c.bench_function("format!", |b| {
        b.iter(|| {
            for &v in &values {
                black_box(format_std(black_box(v)));
            }
        });
    });
}

criterion_group!(benches, bench_custom, bench_format);
criterion_main!(benches);
