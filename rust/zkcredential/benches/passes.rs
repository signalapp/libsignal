//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use curve25519_dalek::RistrettoPoint;
use poksho::ShoApi;
use zkcredential::pass::*;
use zkcredential::sho::ShoExt;
use zkcredential::RANDOMNESS_LEN;

fn pass_issuance(c: &mut Criterion) {
    let mut group = c.benchmark_group("pass_issuance");

    let mut input_sho = poksho::ShoSha256::new(b"test");
    let inputs: Vec<RistrettoPoint> = (0..1000u32).map(|_| input_sho.get_point()).collect();

    let root_key = ServerRootKeyPair::generate([42; RANDOMNESS_LEN]);

    let mut info_sho = poksho::ShoHmacSha256::new(b"ExamplePass");
    info_sho.absorb_and_ratchet(b"today's date");

    let todays_key = root_key.derive_key(info_sho.clone());
    let decrypt_key = ClientDecryptionKey::from_blinding_scalar(input_sho.get_scalar());
    let todays_public_key = root_key.public_key().derive_key(info_sho.clone());

    for count in [1, 5, 10, 100, 1000] {
        let points = inputs.iter().take(count).cloned();
        let issue_endorsements =
            || EndorsementResponse::issue(points.clone(), &todays_key, [43; RANDOMNESS_LEN]);

        group.bench_function(BenchmarkId::new("issue", count), |b| {
            b.iter(issue_endorsements)
        });

        let receive_endorsements = |issued: EndorsementResponse| {
            issued.receive(points.clone(), &todays_public_key).unwrap()
        };

        group.bench_function(BenchmarkId::new("receive", count), |b| {
            b.iter_batched(
                issue_endorsements,
                receive_endorsements,
                BatchSize::SmallInput,
            );
        });

        let prepare_passes = |endorsements: Vec<Endorsement>| {
            endorsements
                .into_iter()
                .map(|endorsement| endorsement.prepare_pass(&decrypt_key, info_sho.clone()))
                .collect::<Vec<_>>()
        };

        group.bench_function(BenchmarkId::new("prepare_pass", count), |b| {
            b.iter_batched(
                || receive_endorsements(issue_endorsements()),
                prepare_passes,
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, pass_issuance);
criterion_main!(benches);
