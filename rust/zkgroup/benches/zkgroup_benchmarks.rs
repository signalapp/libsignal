//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator as _};
use zkgroup::auth::AuthCredentialWithPniZkcResponse;
use zkgroup::SECONDS_PER_DAY;

fn benchmark_integration_auth(c: &mut Criterion) {
    let server_secret_params = zkgroup::ServerSecretParams::generate(zkgroup::TEST_ARRAY_32);
    let server_public_params = server_secret_params.get_public_params();

    let master_key = zkgroup::groups::GroupMasterKey::new(zkgroup::TEST_ARRAY_32_1);
    let group_secret_params =
        zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);
    let group_public_params = group_secret_params.get_public_params();

    // Random UID and issueTime
    let aci = libsignal_core::Aci::from_uuid_bytes(zkgroup::TEST_ARRAY_16);
    let pni = libsignal_core::Pni::from_uuid_bytes(zkgroup::TEST_ARRAY_16_1);
    let redemption_time = zkgroup::Timestamp::from_epoch_seconds(123456 * SECONDS_PER_DAY);

    // SERVER
    // Issue credential
    let randomness = zkgroup::TEST_ARRAY_32_2;
    let auth_credential_response = AuthCredentialWithPniZkcResponse::issue_credential(
        aci,
        pni,
        redemption_time,
        &server_secret_params,
        randomness,
    );

    c.bench_function("issue_auth_credential", |b| {
        b.iter(|| {
            AuthCredentialWithPniZkcResponse::issue_credential(
                aci,
                pni,
                redemption_time,
                &server_secret_params,
                randomness,
            )
        })
    });

    // CLIENT
    let auth_credential = auth_credential_response
        .clone()
        .receive(aci, pni, redemption_time, &server_public_params)
        .unwrap();

    c.bench_function("receive_auth_credential", |b| {
        b.iter(|| {
            auth_credential_response
                .clone()
                .receive(aci, pni, redemption_time, &server_public_params)
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

    let presentation =
        auth_credential.present(&server_public_params, &group_secret_params, randomness);

    c.bench_function("create_auth_credential_presentation_v2", |b| {
        b.iter(|| auth_credential.present(&server_public_params, &group_secret_params, randomness))
    });

    let _presentation_bytes = &bincode::serialize(&presentation).unwrap();

    //for b in presentation_bytes.iter() {
    //    print!("0x{:02x}, ", b);
    //}
    //assert!(AUTH_CREDENTIAL_PRESENTATION_RESULT[..] == presentation_bytes[..]);

    c.bench_function("verify_auth_credential_presentation_v2", |b| {
        b.iter(|| {
            presentation
                .verify(&server_secret_params, &group_public_params, redemption_time)
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
            zkgroup::Timestamp::from_epoch_seconds(zkgroup::SECONDS_PER_DAY),
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
                    zkgroup::Timestamp::from_epoch_seconds(zkgroup::SECONDS_PER_DAY),
                )
                .unwrap()
        })
    });

    // CLIENT
    // Gets stored profile credential
    let profile_key_credential = server_public_params
        .receive_expiring_profile_key_credential(
            &context,
            &response,
            zkgroup::Timestamp::from_epoch_seconds(0),
        )
        .unwrap();

    c.bench_function("receive_profile_key_credential", |b| {
        b.iter(|| {
            server_public_params
                .receive_expiring_profile_key_credential(
                    &context,
                    &response,
                    zkgroup::Timestamp::from_epoch_seconds(0),
                )
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
        .verify_expiring_profile_key_credential_presentation(
            group_public_params,
            &presentation,
            zkgroup::Timestamp::from_epoch_seconds(0),
        )
        .unwrap();

    c.bench_function(
        "verify_expiring_profile_key_credential_presentation_v2",
        |b| {
            b.iter(|| {
                server_secret_params.verify_expiring_profile_key_credential_presentation(
                    group_public_params,
                    &presentation,
                    zkgroup::Timestamp::from_epoch_seconds(0),
                )
            })
        },
    );
}

pub fn benchmark_group_send_endorsements(c: &mut Criterion) {
    const DAY_ALIGNED_TIMESTAMP: zkgroup::Timestamp =
        zkgroup::Timestamp::from_epoch_seconds(1681344000); // 2023-04-13 00:00:00 UTC
    let now = DAY_ALIGNED_TIMESTAMP;

    // SERVER
    let server_secret_params = zkgroup::ServerSecretParams::generate(zkgroup::TEST_ARRAY_32);
    let server_public_params = server_secret_params.get_public_params();
    let todays_key = zkgroup::groups::GroupSendDerivedKeyPair::for_expiration(
        now.add_seconds(SECONDS_PER_DAY),
        &server_secret_params,
    );

    // CLIENT
    let master_key = zkgroup::groups::GroupMasterKey::new(zkgroup::TEST_ARRAY_32_1);
    let group_secret_params =
        zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);

    let aci = libsignal_core::Aci::from_uuid_bytes(zkgroup::TEST_ARRAY_16);

    let all_members: Vec<libsignal_core::ServiceId> = std::iter::once(aci)
        .chain((1u16..).map(|i| {
            // Generate arbitrary v5 (hash-based) UUIDs for the rest of the group.
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

    let mut benchmark_group = c.benchmark_group("group_send_endorsements");
    for group_size in [2, 5, 10, 100, 1000] {
        let group = &all_members[..group_size];
        let group_ciphertexts = &all_member_ciphertexts[..group_size];

        let endorsement_response = zkgroup::groups::GroupSendEndorsementsResponse::issue(
            group_ciphertexts.iter().copied(),
            &todays_key,
            zkgroup::TEST_ARRAY_32_2,
        );

        benchmark_group.bench_function(BenchmarkId::new("issue", group_size), |b| {
            b.iter(|| {
                zkgroup::groups::GroupSendEndorsementsResponse::issue(
                    group_ciphertexts.iter().copied(),
                    &todays_key,
                    zkgroup::TEST_ARRAY_32_2,
                )
            })
        });

        let serialized_response = zkgroup::serialize(&endorsement_response);

        let endorsements: Vec<_> = endorsement_response
            .receive_with_service_ids_single_threaded(
                group.iter().copied(),
                now,
                &group_secret_params,
                &server_public_params,
            )
            .expect("issued endorsements should be valid")
            .into_iter()
            .map(|received| received.decompressed)
            .collect();

        benchmark_group.bench_function(
            BenchmarkId::new("deserialize_and_receive_with_service_ids", group_size),
            |b| {
                b.iter(|| {
                    let endorsement_response: zkgroup::groups::GroupSendEndorsementsResponse =
                        zkgroup::deserialize(&serialized_response).expect("valid");
                    endorsement_response
                        .receive_with_service_ids_single_threaded(
                            group.iter().copied(),
                            now,
                            &group_secret_params,
                            &server_public_params,
                        )
                        .expect("issued endorsements should be valid")
                })
            },
        );

        benchmark_group.bench_function(
            BenchmarkId::new(
                "deserialize_and_receive_with_service_ids_parallel",
                group_size,
            ),
            |b| {
                b.iter(|| {
                    let endorsement_response: zkgroup::groups::GroupSendEndorsementsResponse =
                        zkgroup::deserialize(&serialized_response).expect("valid");
                    endorsement_response
                        .receive_with_service_ids(
                            group.par_iter().copied(),
                            now,
                            &group_secret_params,
                            &server_public_params,
                        )
                        .expect("issued endorsements should be valid")
                })
            },
        );

        benchmark_group.bench_function(
            BenchmarkId::new("deserialize_and_receive_with_ciphertexts", group_size),
            |b| {
                b.iter(|| {
                    let endorsement_response: zkgroup::groups::GroupSendEndorsementsResponse =
                        zkgroup::deserialize(&serialized_response).expect("valid");
                    endorsement_response
                        .receive_with_ciphertexts(
                            group_ciphertexts.iter().copied(),
                            now,
                            &server_public_params,
                        )
                        .expect("issued credential should be valid")
                })
            },
        );

        benchmark_group.bench_function(BenchmarkId::new("combine", group_size), |b| {
            b.iter(|| zkgroup::groups::GroupSendEndorsement::combine(endorsements.iter().cloned()))
        });

        // We're not going to measure to_token or verify, since they aren't usually done in bulk.
        // zkcredential does have a benchmark for them and zkgroup wouldn't add much overhead.
    }
}

criterion_group!(
    benches,
    benchmark_integration_profile,
    benchmark_integration_auth,
    benchmark_group_send_endorsements,
);
criterion_main!(benches);
