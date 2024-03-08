//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

extern crate zkgroup;

fn benchmark_integration_auth(c: &mut Criterion) {
    let server_secret_params = zkgroup::ServerSecretParams::generate(zkgroup::TEST_ARRAY_32);
    let server_public_params = server_secret_params.get_public_params();

    let master_key = zkgroup::groups::GroupMasterKey::new(zkgroup::TEST_ARRAY_32_1);
    let group_secret_params =
        zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);
    let group_public_params = group_secret_params.get_public_params();

    // Random UID and issueTime
    let aci = libsignal_core::Aci::from_uuid_bytes(zkgroup::TEST_ARRAY_16);
    let redemption_time = 123456u32;

    // SERVER
    // Issue credential
    let randomness = zkgroup::TEST_ARRAY_32_2;
    let auth_credential_response =
        server_secret_params.issue_auth_credential(randomness, aci, redemption_time);

    c.bench_function("issue_auth_credential", |b| {
        b.iter(|| server_secret_params.issue_auth_credential(randomness, aci, redemption_time))
    });

    // CLIENT
    let auth_credential = server_public_params
        .receive_auth_credential(aci, redemption_time, &auth_credential_response)
        .unwrap();

    c.bench_function("receive_auth_credential", |b| {
        b.iter(|| {
            server_public_params
                .receive_auth_credential(aci, redemption_time, &auth_credential_response)
                .unwrap()
        })
    });

    // Create and decrypt user entry
    let uuid_ciphertext = group_secret_params.encrypt_service_id(aci.into());
    let plaintext = group_secret_params
        .decrypt_service_id(uuid_ciphertext)
        .unwrap();
    assert_eq!(plaintext, aci);

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
    // SERVER
    let server_secret_params = zkgroup::ServerSecretParams::generate(zkgroup::TEST_ARRAY_32);
    let server_public_params = server_secret_params.get_public_params();

    // CLIENT
    let master_key = zkgroup::groups::GroupMasterKey::new(zkgroup::TEST_ARRAY_32_1);
    let group_secret_params =
        zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);
    let group_public_params = group_secret_params.get_public_params();

    let aci = libsignal_core::Aci::from_uuid_bytes(zkgroup::TEST_ARRAY_16);
    let profile_key =
        zkgroup::profiles::ProfileKey::create(zkgroup::common::constants::TEST_ARRAY_32_1);
    let profile_key_commitment = profile_key.get_commitment(aci);

    // Create context and request
    let randomness = zkgroup::TEST_ARRAY_32_3;

    let context = server_public_params.create_profile_key_credential_request_context(
        randomness,
        aci,
        profile_key,
    );

    c.bench_function("create_profile_key_credential_request_context", |b| {
        b.iter(|| {
            server_public_params.create_profile_key_credential_request_context(
                randomness,
                aci,
                profile_key,
            )
        })
    });

    let request = context.get_request();

    // SERVER

    let randomness = zkgroup::TEST_ARRAY_32_4;
    let response = server_secret_params
        .issue_expiring_profile_key_credential(
            randomness,
            &request,
            aci,
            profile_key_commitment,
            zkgroup::SECONDS_PER_DAY,
        )
        .unwrap();

    c.bench_function("issue_profile_key_credential", |b| {
        b.iter(|| {
            server_secret_params
                .issue_expiring_profile_key_credential(
                    randomness,
                    &request,
                    aci,
                    profile_key_commitment,
                    zkgroup::SECONDS_PER_DAY,
                )
                .unwrap()
        })
    });

    // CLIENT
    // Gets stored profile credential
    let profile_key_credential = server_public_params
        .receive_expiring_profile_key_credential(&context, &response, 0)
        .unwrap();

    c.bench_function("receive_profile_key_credential", |b| {
        b.iter(|| {
            server_public_params
                .receive_expiring_profile_key_credential(&context, &response, 0)
                .unwrap()
        })
    });

    // Create encrypted UID and profile key
    let aci_service_id = aci.into();
    let uuid_ciphertext = group_secret_params.encrypt_service_id(aci_service_id);

    c.bench_function("encrypt_uuid", |b| {
        b.iter(|| group_secret_params.encrypt_service_id(aci_service_id))
    });

    let plaintext = group_secret_params
        .decrypt_service_id(uuid_ciphertext)
        .unwrap();

    c.bench_function("decrypt_uuid", |b| {
        b.iter(|| group_secret_params.decrypt_service_id(uuid_ciphertext))
    });

    assert_eq!(plaintext, aci_service_id);

    let profile_key_ciphertext = group_secret_params.encrypt_profile_key(profile_key, aci);

    c.bench_function("encrypt_profile_key", |b| {
        b.iter(|| group_secret_params.encrypt_profile_key(profile_key, aci))
    });

    let decrypted_profile_key = group_secret_params
        .decrypt_profile_key(profile_key_ciphertext, aci)
        .unwrap();

    c.bench_function("decrypt_profile_key", |b| {
        b.iter(|| group_secret_params.decrypt_profile_key(profile_key_ciphertext, aci))
    });

    assert!(decrypted_profile_key.get_bytes() == profile_key.get_bytes());

    // Create presentation
    let randomness = zkgroup::TEST_ARRAY_32_5;

    let presentation = server_public_params.create_expiring_profile_key_credential_presentation(
        randomness,
        group_secret_params,
        profile_key_credential,
    );

    c.bench_function("create_expiring_profile_key_credential_presentation", |b| {
        b.iter(|| {
            server_public_params.create_expiring_profile_key_credential_presentation(
                randomness,
                group_secret_params,
                profile_key_credential,
            )
        })
    });

    // SERVER
    server_secret_params
        .verify_expiring_profile_key_credential_presentation(group_public_params, &presentation, 0)
        .unwrap();

    c.bench_function(
        "verify_expiring_profile_key_credential_presentation_v2",
        |b| {
            b.iter(|| {
                server_secret_params.verify_expiring_profile_key_credential_presentation(
                    group_public_params,
                    &presentation,
                    0,
                )
            })
        },
    );
}

pub fn benchmark_group_send(c: &mut Criterion) {
    const DAY_ALIGNED_TIMESTAMP: zkgroup::Timestamp = 1681344000; // 2023-04-13 00:00:00 UTC

    // SERVER
    let server_secret_params = zkgroup::ServerSecretParams::generate(zkgroup::TEST_ARRAY_32);
    let server_public_params = server_secret_params.get_public_params();

    // CLIENT
    let master_key = zkgroup::groups::GroupMasterKey::new(zkgroup::TEST_ARRAY_32_1);
    let group_secret_params =
        zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);

    let aci = libsignal_core::Aci::from_uuid_bytes(zkgroup::TEST_ARRAY_16);

    let all_members: Vec<libsignal_core::ServiceId> = std::iter::once(aci)
        .chain((1u16..).map(|i| {
            libsignal_core::Aci::from(uuid::Uuid::new_v5(
                &uuid::Uuid::from_bytes(zkgroup::TEST_ARRAY_16_1),
                &i.to_be_bytes(),
            ))
        }))
        .map(libsignal_core::ServiceId::from)
        .take(1000)
        .collect();
    let all_member_ciphertexts: Vec<_> = all_members
        .iter()
        .map(|member| group_secret_params.encrypt_service_id(*member))
        .collect();

    let mut benchmark_group = c.benchmark_group("group_send_credential");
    for group_size in [2, 5, 10, 100, 1000] {
        let group = all_members.iter().take(group_size);
        let group_ciphertexts = all_member_ciphertexts.iter().take(group_size);

        let credential_response = zkgroup::groups::GroupSendCredentialResponse::issue_credential(
            group_ciphertexts.clone().copied(),
            &all_member_ciphertexts[0],
            DAY_ALIGNED_TIMESTAMP,
            &server_secret_params,
            zkgroup::TEST_ARRAY_32_2,
        )
        .expect("valid request");

        benchmark_group.bench_function(BenchmarkId::new("issue", group_size), |b| {
            b.iter(|| {
                zkgroup::groups::GroupSendCredentialResponse::issue_credential(
                    group_ciphertexts.clone().copied(),
                    &all_member_ciphertexts[0],
                    DAY_ALIGNED_TIMESTAMP,
                    &server_secret_params,
                    zkgroup::TEST_ARRAY_32_2,
                )
                .expect("valid request")
            })
        });

        let serialized_credential_response = zkgroup::serialize(&credential_response);

        let credential = credential_response
            .receive(
                &server_public_params,
                &group_secret_params,
                group.clone().copied(),
                all_members[0],
                DAY_ALIGNED_TIMESTAMP,
            )
            .expect("issued credential should be valid");

        benchmark_group.bench_function(
            BenchmarkId::new("deserialize_and_receive", group_size),
            |b| {
                b.iter(|| {
                    let credential_response: zkgroup::groups::GroupSendCredentialResponse =
                        zkgroup::deserialize(&serialized_credential_response).expect("valid");
                    credential_response
                        .receive(
                            &server_public_params,
                            &group_secret_params,
                            group.clone().copied(),
                            all_members[0],
                            DAY_ALIGNED_TIMESTAMP,
                        )
                        .expect("issued credential should be valid")
                })
            },
        );

        benchmark_group.bench_function(
            BenchmarkId::new("deserialize_and_receive_with_ciphertexts", group_size),
            |b| {
                b.iter(|| {
                    let credential_response: zkgroup::groups::GroupSendCredentialResponse =
                        zkgroup::deserialize(&serialized_credential_response).expect("valid");
                    credential_response
                        .receive_with_ciphertexts(
                            &server_public_params,
                            &group_secret_params,
                            group_ciphertexts.clone().copied(),
                            &all_member_ciphertexts[0],
                            DAY_ALIGNED_TIMESTAMP,
                        )
                        .expect("issued credential should be valid")
                })
            },
        );

        let presentation = credential.present(&server_public_params, zkgroup::TEST_ARRAY_32_3);

        benchmark_group.bench_function(BenchmarkId::new("present", group_size), |b| {
            b.iter(|| credential.present(&server_public_params, zkgroup::TEST_ARRAY_32_3))
        });

        presentation
            .verify(
                group.clone().skip(1).copied(),
                DAY_ALIGNED_TIMESTAMP,
                &server_secret_params,
            )
            .expect("credential should be valid for the timestamp given");

        benchmark_group.bench_function(BenchmarkId::new("verify", group_size), |b| {
            b.iter(|| {
                presentation
                    .verify(
                        group.clone().skip(1).copied(),
                        DAY_ALIGNED_TIMESTAMP,
                        &server_secret_params,
                    )
                    .expect("credential should be valid for the timestamp given")
            })
        });
    }
}

criterion_group!(
    benches,
    benchmark_integration_profile,
    benchmark_integration_auth,
    benchmark_group_send,
);
criterion_main!(benches);
