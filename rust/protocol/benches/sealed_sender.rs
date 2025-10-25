//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::hint::black_box;
use std::time::SystemTime;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::{Rng, TryRngCore as _};
use uuid::Uuid;

#[path = "../tests/support/mod.rs"]
mod support;

pub fn v1(c: &mut Criterion) {
    let mut rng = OsRng.unwrap_err();

    let alice_address = ProtocolAddress::new(
        "9d0652a3-dcc3-4d11-975f-74d61598733f".to_owned(),
        DeviceId::new(1).unwrap(),
    );
    let bob_address = ProtocolAddress::new(
        "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_owned(),
        DeviceId::new(1).unwrap(),
    );

    let mut alice_store = support::test_in_memory_protocol_store().expect("brand new store");
    let mut bob_store = support::test_in_memory_protocol_store().expect("brand new store");

    let bob_pre_key_bundle = support::create_pre_key_bundle(&mut bob_store, &mut rng)
        .now_or_never()
        .expect("sync")
        .expect("valid");

    process_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_pre_key_bundle,
        SystemTime::now(),
        &mut rng,
    )
    .now_or_never()
    .expect("sync")
    .expect("valid");

    let trust_root = KeyPair::generate(&mut rng);
    let server_key = KeyPair::generate(&mut rng);

    let server_cert =
        ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)
            .expect("valid");

    let expires = Timestamp::from_epoch_millis(1605722925);

    let sender_cert = SenderCertificate::new(
        alice_address.name().to_string(),
        None,
        *alice_store
            .get_identity_key_pair()
            .now_or_never()
            .expect("sync")
            .expect("valid")
            .public_key(),
        alice_address.device_id(),
        expires,
        server_cert,
        &server_key.private_key,
        &mut rng,
    )
    .expect("valid");

    let message = b"hello";
    let usmc = UnidentifiedSenderMessageContent::new(
        CiphertextMessageType::Plaintext,
        sender_cert,
        message.to_vec(),
        ContentHint::Default,
        None,
    )
    .expect("valid");

    let mut encrypt_it = || {
        black_box(
            sealed_sender_encrypt_from_usmc(
                &bob_address,
                &usmc,
                &alice_store.identity_store,
                &mut rng,
            )
            .now_or_never()
            .expect("sync")
            .expect("valid"),
        )
    };
    let encrypted = encrypt_it();

    let mut decrypt_it = || {
        black_box(
            sealed_sender_decrypt_to_usmc(&encrypted, &bob_store.identity_store)
                .now_or_never()
                .expect("sync")
                .expect("valid"),
        )
    };
    assert_eq!(message, decrypt_it().contents().expect("valid"));

    c.bench_function("v1/encrypt", |b| b.iter(&mut encrypt_it));
    c.bench_function("v1/decrypt", |b| b.iter(&mut decrypt_it));
}

pub fn v2(c: &mut Criterion) {
    let mut rng = OsRng.unwrap_err();

    let alice_address = ProtocolAddress::new(
        "9d0652a3-dcc3-4d11-975f-74d61598733f".to_owned(),
        DeviceId::new(1).unwrap(),
    );
    let bob_address = ProtocolAddress::new(
        "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_owned(),
        DeviceId::new(1).unwrap(),
    );

    let mut alice_store = support::test_in_memory_protocol_store().expect("brand new store");
    let mut bob_store = support::test_in_memory_protocol_store().expect("brand new store");

    let bob_pre_key_bundle = support::create_pre_key_bundle(&mut bob_store, &mut rng)
        .now_or_never()
        .expect("sync")
        .expect("valid");

    process_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_pre_key_bundle,
        SystemTime::now(),
        &mut rng,
    )
    .now_or_never()
    .expect("sync")
    .expect("valid");

    let trust_root = KeyPair::generate(&mut rng);
    let server_key = KeyPair::generate(&mut rng);

    let server_cert =
        ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)
            .expect("valid");

    let expires = Timestamp::from_epoch_millis(1605722925);

    let sender_cert = SenderCertificate::new(
        alice_address.name().to_string(),
        None,
        *alice_store
            .get_identity_key_pair()
            .now_or_never()
            .expect("sync")
            .expect("valid")
            .public_key(),
        alice_address.device_id(),
        expires,
        server_cert,
        &server_key.private_key,
        &mut rng,
    )
    .expect("valid");

    let message = b"hello";
    let usmc = UnidentifiedSenderMessageContent::new(
        CiphertextMessageType::Plaintext,
        sender_cert,
        message.to_vec(),
        ContentHint::Default,
        None,
    )
    .expect("valid");

    let mut encrypt_it = || {
        black_box(
            sealed_sender_multi_recipient_encrypt(
                &[&bob_address],
                &alice_store
                    .session_store
                    .load_existing_sessions(&[&bob_address])
                    .expect("present"),
                [],
                &usmc,
                &alice_store.identity_store,
                &mut rng,
            )
            .now_or_never()
            .expect("sync")
            .expect("valid"),
        )
    };
    let outgoing = encrypt_it();

    let (incoming_recipient, incoming_message) =
        support::extract_single_ssv2_received_message(&outgoing);
    assert_eq!(&incoming_recipient.service_id_string(), bob_address.name());

    let mut decrypt_it = || {
        black_box(
            sealed_sender_decrypt_to_usmc(&incoming_message, &bob_store.identity_store)
                .now_or_never()
                .expect("sync")
                .expect("valid"),
        )
    };
    assert_eq!(message, decrypt_it().contents().expect("valid"));

    c.bench_function("v2/encrypt", |b| b.iter(&mut encrypt_it));
    c.bench_function("v2/decrypt", |b| b.iter(&mut decrypt_it));

    // Use cfg!(debug_assertions) as a proxy for "no optimizations".
    let recipient_counts: &[usize] = if cfg!(debug_assertions) {
        &[50]
    } else {
        &[2, 5, 10, 100, 1000]
    };

    // Fill out additional recipients.
    let mut recipients = vec![bob_address.clone()];
    while recipients.len() < *recipient_counts.last().unwrap() {
        let next_address = ProtocolAddress::new(
            Uuid::from_bytes(rng.random()).to_string(),
            DeviceId::new(1).unwrap(),
        );

        let mut next_store = support::test_in_memory_protocol_store().expect("brand new store");

        let next_pre_key_bundle = support::create_pre_key_bundle(&mut next_store, &mut rng)
            .now_or_never()
            .expect("sync")
            .expect("valid");

        process_prekey_bundle(
            &next_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &next_pre_key_bundle,
            SystemTime::now(),
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("valid");

        recipients.push(next_address);
    }

    let mut group = c.benchmark_group("v2/encrypt/multi-recipient");
    for &recipient_count in recipient_counts {
        group.bench_with_input(
            BenchmarkId::from_parameter(recipient_count),
            &recipient_count,
            |b, &recipient_count| {
                let recipients: Vec<_> = recipients.iter().take(recipient_count).collect();
                b.iter(|| {
                    sealed_sender_multi_recipient_encrypt(
                        &recipients,
                        &alice_store
                            .session_store
                            .load_existing_sessions(&recipients)
                            .expect("present"),
                        [],
                        &usmc,
                        &alice_store.identity_store,
                        &mut rng,
                    )
                    .now_or_never()
                    .expect("sync")
                    .expect("valid")
                });
            },
        );
    }
    group.finish();

    let mut group = c.benchmark_group("v2/encrypt/multi-device");
    for device_count in [2, 5, 10] {
        group.bench_with_input(
            BenchmarkId::from_parameter(device_count),
            &device_count,
            |b, &device_count| {
                let recipients: Vec<_> = vec![&bob_address; device_count];
                b.iter(|| {
                    sealed_sender_multi_recipient_encrypt(
                        &recipients,
                        &alice_store
                            .session_store
                            .load_existing_sessions(&recipients)
                            .expect("present"),
                        [],
                        &usmc,
                        &alice_store.identity_store,
                        &mut rng,
                    )
                    .now_or_never()
                    .expect("sync")
                    .expect("valid")
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, v1, v2);

criterion_main!(benches);
