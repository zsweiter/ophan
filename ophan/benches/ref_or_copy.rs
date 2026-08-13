use criterion::{Criterion, black_box, criterion_group, criterion_main};

#[allow(dead_code)]
#[derive(Clone, Copy)]
enum ErrorKind {
    BadRequest,
    Unauthorized,
    Forbidden,
    TooManyRequests,
    InternalServerError,
}

#[inline(always)]
fn by_value(kind: ErrorKind) -> u16 {
    match kind {
        ErrorKind::BadRequest => 400,
        ErrorKind::Unauthorized => 401,
        ErrorKind::Forbidden => 403,
        ErrorKind::TooManyRequests => 429,
        ErrorKind::InternalServerError => 500,
    }
}

#[inline(always)]
fn by_ref(kind: &ErrorKind) -> u16 {
    match kind {
        ErrorKind::BadRequest => 400,
        ErrorKind::Unauthorized => 401,
        ErrorKind::Forbidden => 403,
        ErrorKind::TooManyRequests => 429,
        ErrorKind::InternalServerError => 500,
    }
}

fn bench_copy(c: &mut Criterion) {
    let kind = ErrorKind::Forbidden;

    c.bench_function("copy", |b| {
        b.iter(|| {
            let mut sum = 0u64;

            for _ in 0..1_000_000 {
                sum += black_box(by_value(black_box(kind))) as u64;
            }

            black_box(sum)
        })
    });
}

fn bench_ref(c: &mut Criterion) {
    let kind = ErrorKind::Forbidden;

    c.bench_function("ref", |b| {
        b.iter(|| {
            let mut sum = 0u64;

            for _ in 0..1_000_000 {
                sum += black_box(by_ref(black_box(&kind))) as u64;
            }

            black_box(sum)
        })
    });
}

criterion_group!(benches, bench_copy, bench_ref);
criterion_main!(benches);
