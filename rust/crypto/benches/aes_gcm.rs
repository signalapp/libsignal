//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

pub fn aes_gcm(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-256-GCM");

    let key = vec![0xFF; 32];
    let aad = [0xADu8; 16];
    let nonce = [0x42u8; 12];
    let tag = [0x01; 16];

    for size in &[128, 1408] {
        let mut buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("encrypt", *size), |b| {
            b.iter(|| {
                let mut gcm_enc = signal_crypto::Aes256GcmEncryption::new(&key, &nonce, &aad)
                    .expect("valid key size");
                gcm_enc.encrypt(&mut buf).expect("OK");
                gcm_enc.compute_tag().expect("OK");
            })
        });
        group.bench_function(BenchmarkId::new("decrypt", *size), |b| {
            b.iter(|| {
                let mut gcm_dec = signal_crypto::Aes256GcmDecryption::new(&key, &nonce, &aad)
                    .expect("valid key size");
                gcm_dec.decrypt(&mut buf).expect("OK");
                gcm_dec.verify_tag(&tag).unwrap_err();
            })
        });
    }
}

criterion_group!(benches, aes_gcm);

criterion_main!(benches);
