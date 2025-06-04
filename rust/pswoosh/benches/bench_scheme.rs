use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ref0::sys_a::*;
use ref0::*;

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("pswoosh_keygen", |b| {
        b.iter(|| {
            let (skp, pkp) = pswoosh_keygen(&A, black_box(true));
            black_box((skp, pkp))
        })
    });
}

fn bench_skey_deriv(c: &mut Criterion) {
    // Setup data for the benchmark
    let (skp, pkp) = pswoosh_keygen(&A, true);

    c.bench_function("pswoosh_skey_deriv", |b| {
        b.iter(|| {
            let ss = pswoosh_skey_deriv(
                black_box(&pkp),
                black_box(&pkp),
                black_box(&skp),
                black_box(true),
            );
            black_box(ss)
        })
    });
}

criterion_group!(benches, bench_keygen, bench_skey_deriv);
criterion_main!(benches);
