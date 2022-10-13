//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::{criterion_group, criterion_main, Criterion};

extern crate zkgroup;

fn benchmark_integration_auth(c: &mut Criterion) {
    let server_secret_params = zkgroup::ServerSecretParams::generate(zkgroup::TEST_ARRAY_32);
    let server_public_params = server_secret_params.get_public_params();

    let master_key = zkgroup::groups::GroupMasterKey::new(zkgroup::TEST_ARRAY_32_1);
    let group_secret_params =
        zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);
    let group_public_params = group_secret_params.get_public_params();

    // Random UID and issueTime
    let uid = zkgroup::TEST_ARRAY_16;
    let redemption_time = 123456u32;

    // SERVER
    // Issue credential
    let randomness = zkgroup::TEST_ARRAY_32_2;
    let auth_credential_response =
        server_secret_params.issue_auth_credential(randomness, uid, redemption_time);

    c.bench_function("issue_auth_credential", |b| {
        b.iter(|| server_secret_params.issue_auth_credential(randomness, uid, redemption_time))
    });

    // CLIENT
    let auth_credential = server_public_params
        .receive_auth_credential(uid, redemption_time, &auth_credential_response)
        .unwrap();

    c.bench_function("receive_auth_credential", |b| {
        b.iter(|| {
            server_public_params
                .receive_auth_credential(uid, redemption_time, &auth_credential_response)
                .unwrap()
        })
    });

    // Create and decrypt user entry
    let uuid_ciphertext = group_secret_params.encrypt_uuid(uid);
    let plaintext = group_secret_params.decrypt_uuid(uuid_ciphertext).unwrap();
    assert!(plaintext == uid);

    // Create and receive presentation
    let randomness = zkgroup::TEST_ARRAY_32_5;

    let presentation_v2 = server_public_params.create_auth_credential_presentation_v2(
        randomness,
        group_secret_params,
        auth_credential,
    );

    c.bench_function("create_auth_credential_presentation_v2", |b| {
        b.iter(|| {
            server_public_params.create_auth_credential_presentation_v2(
                randomness,
                group_secret_params,
                auth_credential,
            )
        })
    });

    let _presentation_bytes = &bincode::serialize(&presentation_v2).unwrap();

    //for b in presentation_bytes.iter() {
    //    print!("0x{:02x}, ", b);
    //}
    //assert!(AUTH_CREDENTIAL_PRESENTATION_RESULT[..] == presentation_bytes[..]);

    c.bench_function("verify_auth_credential_presentation_v2", |b| {
        b.iter(|| {
            server_secret_params
                .verify_auth_credential_presentation_v2(
                    group_public_params,
                    &presentation_v2,
                    redemption_time,
                )
                .unwrap();
        })
    });
}

// Copied and modified from tests/integration_tests.rs
pub fn benchmark_integration_profile(c: &mut Criterion) {
    // Random UID and issueTime
    let _uid = zkgroup::TEST_ARRAY_16;

    // SERVER
    let server_secret_params = zkgroup::ServerSecretParams::generate(zkgroup::TEST_ARRAY_32);
    let server_public_params = server_secret_params.get_public_params();

    // CLIENT
    let master_key = zkgroup::groups::GroupMasterKey::new(zkgroup::TEST_ARRAY_32_1);
    let group_secret_params =
        zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);
    let group_public_params = group_secret_params.get_public_params();

    let uid = zkgroup::TEST_ARRAY_16;
    let profile_key =
        zkgroup::profiles::ProfileKey::create(zkgroup::common::constants::TEST_ARRAY_32_1);
    let profile_key_commitment = profile_key.get_commitment(uid);

    // Create context and request
    let randomness = zkgroup::TEST_ARRAY_32_3;

    let context = server_public_params.create_profile_key_credential_request_context(
        randomness,
        uid,
        profile_key,
    );

    c.bench_function("create_profile_key_credential_request_context", |b| {
        b.iter(|| {
            server_public_params.create_profile_key_credential_request_context(
                randomness,
                uid,
                profile_key,
            )
        })
    });

    let request = context.get_request();

    // SERVER

    let randomness = zkgroup::TEST_ARRAY_32_4;
    let response = server_secret_params
        .issue_profile_key_credential(randomness, &request, uid, profile_key_commitment)
        .unwrap();

    c.bench_function("issue_profile_key_credential", |b| {
        b.iter(|| {
            server_secret_params
                .issue_profile_key_credential(randomness, &request, uid, profile_key_commitment)
                .unwrap()
        })
    });

    // CLIENT
    // Gets stored profile credential
    let profile_key_credential = server_public_params
        .receive_profile_key_credential(&context, &response)
        .unwrap();

    c.bench_function("receive_profile_key_credential", |b| {
        b.iter(|| {
            server_public_params
                .receive_profile_key_credential(&context, &response)
                .unwrap()
        })
    });

    // Create encrypted UID and profile key
    let uuid_ciphertext = group_secret_params.encrypt_uuid(uid);

    c.bench_function("encrypt_uuid", |b| {
        b.iter(|| group_secret_params.encrypt_uuid(uid))
    });

    let plaintext = group_secret_params.decrypt_uuid(uuid_ciphertext).unwrap();

    c.bench_function("decrypt_uuid", |b| {
        b.iter(|| group_secret_params.decrypt_uuid(uuid_ciphertext))
    });

    assert!(plaintext == uid);

    let profile_key_ciphertext = group_secret_params.encrypt_profile_key(profile_key, uid);

    c.bench_function("encrypt_profile_key", |b| {
        b.iter(|| group_secret_params.encrypt_profile_key(profile_key, uid))
    });

    let decrypted_profile_key = group_secret_params
        .decrypt_profile_key(profile_key_ciphertext, uid)
        .unwrap();

    c.bench_function("decrypt_profile_key", |b| {
        b.iter(|| group_secret_params.decrypt_profile_key(profile_key_ciphertext, uid))
    });

    assert!(decrypted_profile_key.get_bytes() == profile_key.get_bytes());

    // Create presentation
    let randomness = zkgroup::TEST_ARRAY_32_5;

    let presentation_v2 = server_public_params.create_profile_key_credential_presentation_v2(
        randomness,
        group_secret_params,
        profile_key_credential,
    );

    c.bench_function("create_profile_key_credential_presentation_v2", |b| {
        b.iter(|| {
            server_public_params.create_profile_key_credential_presentation_v2(
                randomness,
                group_secret_params,
                profile_key_credential,
            )
        })
    });

    // SERVER
    server_secret_params
        .verify_profile_key_credential_presentation_v2(group_public_params, &presentation_v2)
        .unwrap();

    c.bench_function("verify_profile_key_credential_presentation_v2", |b| {
        b.iter(|| {
            server_secret_params.verify_profile_key_credential_presentation_v2(
                group_public_params,
                &presentation_v2,
            )
        })
    });
}

criterion_group!(
    benches,
    benchmark_integration_profile,
    benchmark_integration_auth
);
criterion_main!(benches);
