//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

extern crate usernames;
use usernames::{NicknameLimits, Username, UsernameError};

pub fn username_hash(username: &str) -> Result<[u8; 32], UsernameError> {
    Username::new(username).map(|un| un.hash())
}

pub fn username_proof(username: &str, randomness: &[u8]) -> Result<Vec<u8>, UsernameError> {
    Username::new(username)?.proof(randomness)
}

// Username validation is inseparable from the hash/proof calculations and therefore its costs are
// included in the benchmarks for both.
fn bench_usernames(c: &mut Criterion) {
    let mut rng = OsRng;
    let usernames =
        Username::candidates_from(&mut rng, "signal", NicknameLimits::default()).unwrap();

    let mut infinite_usernames = usernames.iter().cycle();
    c.bench_function("username_hash", |b| {
        b.iter(|| username_hash(infinite_usernames.next().unwrap()))
    });
    let randomness: Vec<u8> = (0..32).collect();
    c.bench_function("username_proof", |b| {
        b.iter(|| username_proof(infinite_usernames.next().unwrap(), &randomness))
    });

    let mut infinite_input = usernames
        .iter()
        .map(|name| {
            let username = Username::new(name).unwrap();
            let proof = username.proof(&randomness).unwrap();
            (username, proof)
        })
        .cycle();

    c.bench_function("username_verify_proof", |b| {
        b.iter(|| {
            let (username, proof) = infinite_input.next().unwrap();
            Username::verify_proof(&proof, username.hash()).unwrap()
        })
    });
}

criterion_group!(benches, bench_usernames);
criterion_main!(benches);
