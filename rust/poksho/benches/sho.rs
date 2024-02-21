//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use rand::rngs::OsRng;
use rand::RngCore;

#[inline]
fn bench_poksho_api<S: poksho::ShoApi, M: Measurement>(group: &mut BenchmarkGroup<M>) {
    group.bench_function("new", |b| b.iter(|| S::new(b"Signal_label_name_20240221")));

    let mut sho = S::new(b"Signal_label_name_20240221");

    let mut data = [0; 256];
    OsRng.fill_bytes(&mut data);

    group.bench_function("absorb_and_ratchet", |b| {
        b.iter(|| sho.absorb_and_ratchet(&data[..63]))
    });

    group.bench_function("absorb_and_ratchet then squeeze_and_ratchet", |b| {
        b.iter(|| {
            sho.absorb_and_ratchet(&[0u8; 129]);
            sho.squeeze_and_ratchet(63);
        })
    });

    group.bench_function("new, then several absorbs, ratchets, squeezes", |b| {
        b.iter(|| {
            let mut sho = S::new(b"Signal_label_name_20240221");

            sho.absorb_and_ratchet(b"abc");
            sho.absorb_and_ratchet(&data[..63]);
            sho.absorb_and_ratchet(&data[..64]);
            sho.absorb_and_ratchet(&data[..65]);
            sho.absorb_and_ratchet(&data[..127]);
            sho.absorb_and_ratchet(&data[..128]);
            sho.absorb_and_ratchet(&data[..129]);
            sho.squeeze_and_ratchet(63);
            sho.squeeze_and_ratchet(64);
            sho.squeeze_and_ratchet(65);
            sho.squeeze_and_ratchet(127);
            sho.squeeze_and_ratchet(128);
            sho.squeeze_and_ratchet(129);
            sho.absorb_and_ratchet(b"def");
            sho.squeeze_and_ratchet(63);
        })
    });
}

fn bench_poksho_api_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("ShoSha256");
    bench_poksho_api::<poksho::ShoSha256, _>(&mut group);
}

fn bench_poksho_api_mac_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("ShoHmacSha256");
    bench_poksho_api::<poksho::ShoHmacSha256, _>(&mut group);
}

criterion_group!(
    benches,
    bench_poksho_api_sha256,
    bench_poksho_api_mac_sha256
);
criterion_main!(benches);
