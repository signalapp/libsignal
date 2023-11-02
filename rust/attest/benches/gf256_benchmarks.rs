//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

extern crate attest;
use attest::svr3::ppss::gf256v32::polynomial::Polynomial;
use attest::svr3::ppss::gf256v32::ring_ops::RingElt;

fn bench_gf256(c: &mut Criterion) {
    let mut rng = OsRng;
    let rhs = RingElt::random(&mut rng);
    c.bench_function("Add for RingElt", |b| {
        b.iter(|| std::hint::black_box(RingElt::ZERO + rhs))
    });

    let mut accumulator = RingElt::ZERO;
    c.bench_function("AddAssign for RingElt", |b| b.iter(|| accumulator += rhs));

    c.bench_function("Mul for RingElt", |b| {
        b.iter(|| std::hint::black_box(RingElt::ONE * rhs))
    });

    accumulator = RingElt::ONE;
    c.bench_function("MulAssign for RingElt", |b| b.iter(|| accumulator *= rhs));

    c.bench_function("RingElt::square", |b| {
        b.iter(|| std::hint::black_box(rhs.square()))
    });

    c.bench_function("RingElt::inv", |b| {
        b.iter(|| std::hint::black_box(rhs.inv()))
    });
}

fn bench_polynomial(c: &mut Criterion) {
    type P = Polynomial<10>;
    let rhs = {
        let mut coeffs = [RingElt::ZERO; 10];
        let mut n = RingElt::ONE;
        for coeff in &mut coeffs {
            *coeff = n;
            n.square_assign();
        }
        P::new(coeffs)
    };
    c.bench_function("Add for Polynomial", |b| {
        b.iter(|| std::hint::black_box(P::ZERO + rhs))
    });

    let mut accumulator = P::ZERO;
    c.bench_function("AddAssign for Polynomial", |b| {
        b.iter(|| accumulator += rhs)
    });

    c.bench_function("Mul for Polynomial", |b| {
        b.iter(|| std::hint::black_box(P::ONE * rhs))
    });

    accumulator = P::ONE;
    c.bench_function("MulAssign for Polynomial", |b| {
        b.iter(|| accumulator *= rhs)
    });
}

criterion_group!(benches, bench_gf256, bench_polynomial);
criterion_main!(benches);
