use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pswoosh::*;
use pswoosh::sys_a::*;
use pswoosh::{arithmetic::{poly::*, polyvec::*}};
use getrandom;

fn bench_getnoise_spec(c: &mut Criterion) {
    let mut seed: [u8; SYMBYTES] = [0; SYMBYTES];
    getrandom::getrandom(&mut seed).expect("getrandom failed");
    
    c.bench_function("getnoise_spec", |b| {
        b.iter(|| {
            let mut seed_copy = seed;
            black_box(getnoise_spec(&mut seed_copy, 0))
        })
    });
}

fn bench_getnoise(c: &mut Criterion) {
    let mut seed: [u8; SYMBYTES] = [0; SYMBYTES];
    getrandom::getrandom(&mut seed).expect("getrandom failed");
    
    c.bench_function("getnoise", |b| {
        b.iter(|| {
            let mut seed_copy = seed;
            black_box(getnoise(&mut seed_copy, 0))
        })
    });
}

fn bench_expand_seed(c: &mut Criterion) {
    let seed: [u8; SYMBYTES] = [0; SYMBYTES];
    
    c.bench_function("expand_seed", |b| {
        b.iter(|| {
            let mut buf: [u8; NOISE_BYTES] = [0; NOISE_BYTES];
            expand_seed(&seed, 0, &mut buf);
            black_box(buf)
        })
    });
}

fn bench_expand_seed_aes(c: &mut Criterion) {
    let seed: [u8; SYMBYTES] = [0; SYMBYTES];
    
    c.bench_function("expand_seed_aes", |b| {
        b.iter(|| {
            let mut buf: [u8; NOISE_BYTES] = [0; NOISE_BYTES];
            expand_seed_aes(&seed, 0, &mut buf);
            black_box(buf)
        })
    });
}

fn bench_genoffset(c: &mut Criterion) {
    let rin: [u8; POLYVEC_BYTES * 2] = [0; POLYVEC_BYTES * 2];
    
    let mut group = c.benchmark_group("genoffset");
    group.measurement_time(std::time::Duration::from_secs_f64(10.0));
    
    group.bench_function("genoffset", |b| {
        b.iter(|| black_box(genoffset(&rin)))
    });
    
    group.finish();
}

fn bench_poly_ntt(c: &mut Criterion) {
    c.bench_function("poly_ntt", |b| {
        b.iter(|| {
            let mut s: PolyVec = polyvec_init();
            poly_ntt(&mut s[0]);
            black_box(s)
        })
    });
}

fn bench_poly_invntt(c: &mut Criterion) {
    c.bench_function("poly_invntt", |b| {
        b.iter(|| {
            let mut s: PolyVec = polyvec_init();
            poly_invntt(&mut s[0]);
            black_box(s)
        })
    });
}

fn bench_polyvec_basemul_acc(c: &mut Criterion) {
    c.bench_function("polyvec_basemul_acc", |b| {
        b.iter(|| {
            black_box(polyvec_basemul_acc(A[0], A[1]))
        })
    });
}
//stack overflow
fn bench_pswoosh_keygen(c: &mut Criterion) {
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

fn bench_pswoosh_skey_deriv(c: &mut Criterion) {
    let (skp, pkp) = pswoosh_keygen(&A, true);
    
    let mut group = c.benchmark_group("pswoosh_skey_deriv");
    group.measurement_time(std::time::Duration::from_secs_f64(12.0));
    
    group.bench_function("pswoosh_skey_deriv", |b| {
        b.iter(|| black_box(pswoosh_skey_deriv(&pkp, &pkp, &skp, true)))
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_getnoise_spec,
    bench_getnoise,
    bench_expand_seed,
    bench_expand_seed_aes,
    bench_genoffset,
    bench_poly_ntt,
    bench_poly_invntt,
    bench_polyvec_basemul_acc,
    bench_pswoosh_keygen,
    bench_pswoosh_skey_deriv
);

criterion_main!(benches);