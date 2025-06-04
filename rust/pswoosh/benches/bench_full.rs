use criterion::{criterion_group, criterion_main, Criterion};
use getrandom;
use ref0::arithmetic::poly::*;
use ref0::arithmetic::polyvec::*;
use ref0::sysA::*;
use ref0::*;

fn bench_full(c: &mut Criterion) {
    let mut seed: [u8; SYMBYTES] = [0; SYMBYTES];
    let mut buf: [u8; NOISE_BYTES] = [0; NOISE_BYTES];
    let rin: [u8; POLYVEC_BYTES * 2] = [0; POLYVEC_BYTES * 2];
    let pkp: [u8; PUBLICKEY_BYTES];
    let skp: [u8; SECRETKEY_BYTES];
    let s: PolyVec = polyvec_init();

    getrandom::getrandom(&mut seed).expect("getrandom failed");

    c.bench_function("getnoise_spec", |b| b.iter(|| getnoise_spec(&mut seed, 0)));

    c.bench_function("getnoise", |b| b.iter(|| getnoise(&mut seed, 0)));

    c.bench_function("expand_seed", |b| {
        b.iter(|| expand_seed(&seed, 0, &mut buf))
    });

    c.bench_function("expand_seed_aes", |b| {
        b.iter(|| expand_seed_aes(&seed, 0, &mut buf))
    });

    c.bench_function("genoffset", |b| b.iter(|| genoffset(&rin)));

    c.bench_function("poly_ntt", |b| {
        let mut poly_copy = s[0].clone();
        b.iter(|| {
            poly_ntt(&mut poly_copy);
            poly_copy = s[0].clone(); // Reset for next iteration
        })
    });

    c.bench_function("poly_invntt", |b| {
        let mut poly_copy = s[0].clone();
        b.iter(|| {
            poly_invntt(&mut poly_copy);
            poly_copy = s[0].clone(); // Reset for next iteration
        })
    });

    c.bench_function("polyvec_basemul_acc", |b| {
        b.iter(|| polyvec_basemul_acc(A[0], A[1]))
    });

    c.bench_function("pswoosh_keygen", |b| b.iter(|| pswoosh_keygen(&A, true)));

    // For this one, you need to generate keys first
    (skp, pkp) = pswoosh_keygen(&A, true);
    c.bench_function("pswoosh_skey_deriv", |b| {
        b.iter(|| pswoosh_skey_deriv(&pkp, &pkp, &skp, true))
    });
}

criterion_group!(benches, bench_full);
criterion_main!(benches);
