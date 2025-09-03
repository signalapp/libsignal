//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use libsignal_core::curve::PrivateKey;
use signal_crypto::{SimpleHpkeReceiver as _, SimpleHpkeSender as _};

pub fn hpke(c: &mut Criterion) {
    let mut group = c.benchmark_group("HPKE");

    let private_key = PrivateKey::deserialize(&[0x77; 32]).expect("valid");
    let public_key = private_key.public_key().expect("can get public key");
    let info = b"info";
    let aad = b"extra";

    for size in &[128, 1408] {
        let buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        let sealed = public_key.seal(info, aad, &buf).expect("can seal");
        group.bench_function(BenchmarkId::new("seal", *size), |b| {
            b.iter(|| {
                _ = public_key.seal(info, aad, &buf).expect("can seal");
            })
        });
        group.bench_function(BenchmarkId::new("open", *size), |b| {
            b.iter(|| {
                _ = private_key.open(info, aad, &sealed).expect("can open");
            })
        });
    }
}

criterion_group!(benches, hpke);

criterion_main!(benches);
