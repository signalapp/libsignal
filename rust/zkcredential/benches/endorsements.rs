//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use curve25519_dalek::RistrettoPoint;
use poksho::ShoApi;
use zkcredential::endorsements::*;
use zkcredential::sho::ShoExt;
use zkcredential::RANDOMNESS_LEN;

fn endorsement_flow(c: &mut Criterion) {
    let mut group = c.benchmark_group("endorsements");

    let mut input_sho = poksho::ShoSha256::new(b"test");
    let inputs: Vec<RistrettoPoint> = (0..1000u32).map(|_| input_sho.get_point()).collect();

    let root_key = ServerRootKeyPair::generate([42; RANDOMNESS_LEN]);

    let mut info_sho = poksho::ShoHmacSha256::new(b"ExampleEndorsements");
    info_sho.absorb_and_ratchet(b"today's date");

    let todays_key = root_key.derive_key(info_sho.clone());
    let blinding_key = input_sho.get_scalar();
    let decrypt_key = ClientDecryptionKey::from_blinding_scalar(blinding_key);
    let raw_decrypt_key = blinding_key.invert();
    let todays_public_key = root_key.public_key().derive_key(info_sho.clone());

    for count in [1, 5, 10, 100, 1000] {
        let points = inputs.iter().take(count).cloned();
        let issue_endorsements =
            || EndorsementResponse::issue(points.clone(), &todays_key, [43; RANDOMNESS_LEN]);

        group.bench_function(BenchmarkId::new("issue", count), |b| {
            b.iter(issue_endorsements)
        });

        let receive_endorsements = |issued: EndorsementResponse| {
            issued
                .receive(points.clone(), &todays_public_key)
                .unwrap()
                .decompressed
        };

        group.bench_function(BenchmarkId::new("receive", count), |b| {
            b.iter_batched(
                issue_endorsements,
                receive_endorsements,
                BatchSize::SmallInput,
            );
        });

        let to_tokens = |endorsements: Vec<Endorsement>| {
            endorsements
                .into_iter()
                .map(|endorsement| endorsement.to_token(&decrypt_key))
                .collect::<Vec<_>>()
        };

        group.bench_function(BenchmarkId::new("to_token", count), |b| {
            b.iter_batched(
                || receive_endorsements(issue_endorsements()),
                to_tokens,
                BatchSize::SmallInput,
            );
        });

        let tokens = to_tokens(receive_endorsements(issue_endorsements()));
        let decrypted_points = points.map(|p| p * raw_decrypt_key).collect::<Vec<_>>();

        group.bench_function(BenchmarkId::new("verify", count), |b| {
            b.iter(|| {
                for (token, point) in tokens.iter().zip(decrypted_points.iter()) {
                    todays_key.verify(point, token).unwrap();
                }
            });
        });
    }

    group.finish();
}

fn key_derivation(c: &mut Criterion) {
    let root_key = ServerRootKeyPair::generate([42; RANDOMNESS_LEN]);

    let mut info_sho = poksho::ShoHmacSha256::new(b"ExampleEndorsements");
    info_sho.absorb_and_ratchet(b"today's date");

    c.bench_function("ServerRootKeyPair::derive_key", |b| {
        b.iter(|| root_key.derive_key(info_sho.clone()))
    });

    c.bench_function("ServerRootPublicKey::derive_key", |b| {
        b.iter(|| root_key.public_key().derive_key(info_sho.clone()))
    });
}

criterion_group!(benches, endorsement_flow, key_derivation);
criterion_main!(benches);
