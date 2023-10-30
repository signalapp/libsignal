//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::OnceLock;

use criterion::{criterion_group, criterion_main, Criterion};
use poksho::ShoApi;
use zkcredential::attributes::{derive_default_generator_points, Domain, KeyPair};

struct ExampleDomain;
impl Domain for ExampleDomain {
    type Attribute = [curve25519_dalek::RistrettoPoint; 2];
    const ID: &'static str = "ExampleDomain";

    fn G_a() -> [curve25519_dalek::RistrettoPoint; 2] {
        static STORAGE: OnceLock<[curve25519_dalek::RistrettoPoint; 2]> = OnceLock::new();
        *derive_default_generator_points::<Self>(&STORAGE)
    }
}

struct InverseDomain;
impl Domain for InverseDomain {
    type Attribute = [curve25519_dalek::RistrettoPoint; 2];
    const ID: &'static str = "InverseDomain";

    fn G_a() -> [curve25519_dalek::RistrettoPoint; 2] {
        static STORAGE: OnceLock<[curve25519_dalek::RistrettoPoint; 2]> = OnceLock::new();
        *derive_default_generator_points::<Self>(&STORAGE)
    }
}

fn attribute_key_inversion(c: &mut Criterion) {
    let mut sho = poksho::ShoSha256::new(b"test");
    let key_pair = KeyPair::<ExampleDomain>::derive_from(&mut sho);

    c.bench_function("KeyPair::inverse_of", |b| {
        b.iter(|| KeyPair::<InverseDomain>::inverse_of(&key_pair))
    });
}

criterion_group!(benches, attribute_key_inversion,);
criterion_main!(benches);
