//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_server_param_serialization(c: &mut Criterion) {
    let server_secret_params = zkgroup::ServerSecretParams::generate(zkgroup::TEST_ARRAY_32);

    let serialized_secret_params = zkgroup::serialize(&server_secret_params);

    c.bench_function("ServerSecretParams/serialize", |b| {
        b.iter(|| zkgroup::serialize(&server_secret_params));
    });

    let _ = zkgroup::deserialize::<zkgroup::ServerSecretParams>(&serialized_secret_params).unwrap();

    c.bench_function("ServerSecretParams/deserialize", |b| {
        b.iter(|| zkgroup::deserialize::<zkgroup::ServerSecretParams>(&serialized_secret_params));
    });

    let server_public_params = server_secret_params.get_public_params();

    let serialized_public_params = zkgroup::serialize(&server_public_params);

    c.bench_function("ServerPublicParams/serialize", |b| {
        b.iter(|| zkgroup::serialize(&server_public_params));
    });

    let _ = zkgroup::deserialize::<zkgroup::ServerPublicParams>(&serialized_public_params).unwrap();

    c.bench_function("ServerPublicParams/deserialize", |b| {
        b.iter(|| zkgroup::deserialize::<zkgroup::ServerPublicParams>(&serialized_public_params));
    });
}

criterion_group!(benches, bench_server_param_serialization,);
criterion_main!(benches);
