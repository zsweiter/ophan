use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub struct Backend {
    pub is_healthy: AtomicBool,
}

// --- APPROACH A: Dynamically filter everything on every single request ---
// This represents the sub-optimal path: heavy heap allocations and full cache thrashing.
fn approach_a_always_filter(backends: &[Arc<Backend>], counter: &AtomicUsize) -> Option<Arc<Backend>> {
    let healthy_backends: Vec<Arc<Backend>> = backends.iter().filter(|b| b.is_healthy.load(Ordering::Relaxed)).cloned().collect(); // <- Catastrophic: Triggers a heap allocation on the hot path

    if healthy_backends.is_empty() {
        return None;
    }

    let ticket = counter.fetch_add(1, Ordering::Relaxed);
    Some(Arc::clone(&healthy_backends[ticket % healthy_backends.len()]))
}

// --- APPROACH B: Your Optimized Theory (Select first, validate second) ---
// This represents the mechanical sympathy path: O(1) in the best case,
// zero allocations, and exactly one memory indirection when healthy.
fn approach_b_speculative_select(backends: &[Arc<Backend>], counter: &AtomicUsize) -> Option<Arc<Backend>> {
    let total_backends = backends.len();
    if total_backends == 0 {
        return None;
    }

    let ticket = counter.fetch_add(1, Ordering::Relaxed);
    let start_idx = ticket % total_backends;

    // Single memory indirection lookup (The Happy Path)
    let candidate = &backends[start_idx];
    if candidate.is_healthy.load(Ordering::Relaxed) {
        return Some(Arc::clone(candidate));
    }

    // Degraded Path: Iterative fallback scanning from the point of failure
    for i in 1..total_backends {
        let next_idx = (start_idx + i) % total_backends;
        let backend = &backends[next_idx];
        if backend.is_healthy.load(Ordering::Relaxed) {
            return Some(Arc::clone(backend));
        }
    }

    None
}

fn run_load_balancer_benchmarks(c: &mut Criterion) {
    // Setup: 10 Total backends (simulating 2 dead nodes at indices 3 and 7)
    let mut backends = Vec::new();
    for i in 0..10 {
        let is_healthy = i != 3 && i != 7;
        backends.push(Arc::new(Backend { is_healthy: AtomicBool::new(is_healthy) }));
    }

    let counter_a = AtomicUsize::new(0);
    let counter_b = AtomicUsize::new(0);

    // FIX: Notice the `mut group` here instead of just `let group`
    let mut group = c.benchmark_group("Load Balancer Optimization Dilemma");

    group.bench_function("Approach A (Always Filter & Allocate)", |b| {
        b.iter(|| approach_a_always_filter(black_box(&backends), black_box(&counter_a)))
    });

    group.bench_function("Approach B (Speculative Selection)", |b| {
        b.iter(|| approach_b_speculative_select(black_box(&backends), black_box(&counter_b)))
    });

    group.finish();
}

criterion_group!(benches, run_load_balancer_benchmarks);
criterion_main!(benches);
