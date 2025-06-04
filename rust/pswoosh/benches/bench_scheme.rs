use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ref0::*;
use ref0::sys_a::*;

fn bench_pswoosh_keygen_scheme(c: &mut Criterion) {
    c.bench_function("pswoosh_keygen", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            
            for _ in 0..iters {
                let _keys = pswoosh_keygen(&A, true);
            }
            
            start.elapsed()
        })
    });
}

fn bench_pswoosh_skey_deriv_scheme(c: &mut Criterion) {
    let (skp, pkp) = pswoosh_keygen(&A, true);
    
    let mut group = c.benchmark_group("pswoosh_skey_deriv_scheme");
    group.measurement_time(std::time::Duration::from_secs_f64(10.0));
    
    group.bench_function("pswoosh_skey_deriv", |b| {
        b.iter(|| black_box(pswoosh_skey_deriv(&pkp, &pkp, &skp, true)))
    });
    
    group.finish();
}

criterion_group!(
    scheme_benches,
    bench_pswoosh_keygen_scheme,
    bench_pswoosh_skey_deriv_scheme
);


criterion_main!(scheme_benches);