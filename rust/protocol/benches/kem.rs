//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use criterion::{criterion_group, criterion_main, Criterion};

use libsignal_protocol::kem::{KeyPair, KeyType};

use std::hint::black_box;

fn bench_kem(c: &mut Criterion) {
    for key_type in [KeyType::Kyber768, KeyType::Kyber1024] {
        c.bench_function(format!("{key_type:?}_generate").as_str(), |b| {
            b.iter(|| {
                black_box(KeyPair::generate(KeyType::Kyber768));
            });
        });
        let key_pairs: Vec<_> = std::iter::from_fn(|| Some(KeyPair::generate(key_type)))
            .take(10)
            .collect();
        c.bench_function(format!("{key_type:?}_encapsulate").as_str(), |b| {
            let mut public_keys = key_pairs.iter().map(|kp| &kp.public_key).cycle();
            b.iter(|| {
                black_box(public_keys.next().unwrap().encapsulate());
            });
        });
        c.bench_function(format!("{key_type:?}_decapsulate").as_str(), |b| {
            let mut ct_sk_pairs = key_pairs
                .iter()
                .map(|kp| {
                    let sk = &kp.secret_key;
                    let (_ss, ct) = kp.public_key.encapsulate();
                    (ct, sk)
                })
                .cycle();
            b.iter(|| {
                let (ct, sk) = ct_sk_pairs.next().unwrap();
                black_box(sk.decapsulate(&ct)).expect("decapsulation works");
            });
        });
    }
}

criterion_group!(benches, bench_kem);
criterion_main!(benches);
