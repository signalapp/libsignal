//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

pub fn aes_gcm_siv(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-256-GCM-SIV");

    let key = vec![0xFF; 32];

    let cipher = signal_crypto::Aes256GcmSiv::new(&key).expect("valid key size");
    let aad = [0xADu8; 16];
    let nonce = [0x42u8; 12];
    let tag = [0x01; 16];

    for size in &[128, 1408] {
        let mut buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("encrypt", *size), |b| {
            b.iter(|| cipher.encrypt(&mut buf, &nonce, &aad))
        });
        group.bench_function(BenchmarkId::new("decrypt", *size), |b| {
            b.iter(|| cipher.decrypt(&mut buf, &nonce, &aad, &tag));
        });
    }
}

criterion_group!(benches, aes_gcm_siv);

criterion_main!(benches);
