use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use ophan::middlewares::rewrites;

fn create_dataset() -> Vec<(String, String)> {
    let mut rules = Vec::new();

    // 1. Reglas Exactas (500 reglas)
    for i in 0..500 {
        rules.push((format!("/static/page_{i}.html"), format!("/public/p_{i}.html")));
    }

    // 2. Reglas de Prefijo (200 reglas)
    for i in 0..200 {
        rules.push((format!("/api/v1/service_{i}/*"), format!("/internal/s_{i}/")));
    }

    // 3. Reglas de Sufijo (50 reglas)
    for i in 0..50 {
        rules.push((format!("*.ext_{i}"), format!(".target_{i}")));
    }

    // 4. Reglas Regex (20 reglas)
    for i in 0..20 {
        rules.push((format!(r"^/users/group_{i}/(\d+)$"), format!("/v2/g_{i}/$1")));
    }

    rules
}

fn bench_rewriters(c: &mut Criterion) {
    let rules = create_dataset();

    // Inicialización de los 3 motores
    let ultra = rewrites::RewriteEngine::new(rules.clone(), None, None, rewrites::TrailingSlashAction::Never).unwrap();

    let mut group = c.benchmark_group("URL_Rewrite_Engine_Comparison");

    let exact_path = "/static/page_450.html";
    group.bench_with_input(BenchmarkId::new("ExactMatch", "Ultra"), &exact_path, |b, path| {
        b.iter(|| ultra.apply(black_box(path)));
    });

    let prefix_path = "/api/v1/service_150/users/profile";

    group.bench_with_input(BenchmarkId::new("PrefixMatch", "Ultra"), &prefix_path, |b, path| {
        b.iter(|| ultra.apply(black_box(path)));
    });

    let regex_path = "/users/group_18/99421";

    group.bench_with_input(BenchmarkId::new("RegexMatch", "Ultra"), &regex_path, |b, path| {
        b.iter(|| ultra.apply(black_box(path)));
    });

    let nomatch_path = "/no/matching/route/exists/here";

    group.bench_with_input(BenchmarkId::new("NoMatch_WorstCase", "Ultra"), &nomatch_path, |b, path| {
        b.iter(|| ultra.apply(black_box(path)));
    });

    group.finish();
}

criterion_group!(benches, bench_rewriters);
criterion_main!(benches);
