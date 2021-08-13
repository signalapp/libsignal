//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![no_main]

use std::convert::TryFrom;

use futures_util::FutureExt;
use libfuzzer_sys::fuzz_target;
use libsignal_protocol::*;
use log::*;
use rand::prelude::*;

async fn process_pre_key(
    my_name: &str,
    my_store: &mut InMemSignalProtocolStore,
    their_store: &mut InMemSignalProtocolStore,
    their_address: &ProtocolAddress,
    use_one_time_pre_key: bool,
    rng: &mut (impl Rng + CryptoRng),
) {
    info!("{}:   processing a new pre-key bundle", my_name);
    let their_signed_pre_key_pair = KeyPair::generate(rng);
    let their_signed_pre_key_public = their_signed_pre_key_pair.public_key.serialize();
    let their_signed_pre_key_signature = their_store
        .get_identity_key_pair(None)
        .await
        .unwrap()
        .private_key()
        .calculate_signature(&their_signed_pre_key_public, rng)
        .unwrap();

    let signed_pre_key_id = rng.gen_range(0, 0xFF_FFFF);

    their_store
        .save_signed_pre_key(
            signed_pre_key_id,
            &SignedPreKeyRecord::new(
                signed_pre_key_id,
                /*timestamp*/ 42,
                &their_signed_pre_key_pair,
                &their_signed_pre_key_signature,
            ),
            None,
        )
        .await
        .unwrap();

    let pre_key_info = if use_one_time_pre_key {
        let pre_key_id = rng.gen_range(0, 0xFF_FFFF);
        let one_time_pre_key = KeyPair::generate(rng);

        their_store
            .save_pre_key(
                pre_key_id,
                &PreKeyRecord::new(pre_key_id, &one_time_pre_key),
                None,
            )
            .await
            .unwrap();
        Some((pre_key_id, one_time_pre_key.public_key))
    } else {
        None
    };

    let their_pre_key_bundle = PreKeyBundle::new(
        their_store.get_local_registration_id(None).await.unwrap(),
        1, // device id
        pre_key_info,
        signed_pre_key_id,
        their_signed_pre_key_pair.public_key,
        their_signed_pre_key_signature.into_vec(),
        *their_store
            .get_identity_key_pair(None)
            .await
            .unwrap()
            .identity_key(),
    )
    .unwrap();

    process_prekey_bundle(
        their_address,
        &mut my_store.session_store,
        &mut my_store.identity_store,
        &their_pre_key_bundle,
        rng,
        None,
    )
    .await
    .unwrap();
}

async fn send_message(
    my_name: &str,
    my_store: &mut InMemSignalProtocolStore,
    their_store: &mut InMemSignalProtocolStore,
    their_address: &ProtocolAddress,
    their_message_queue: &mut Vec<(CiphertextMessage, Box<[u8]>)>,
    rng: &mut (impl Rng + CryptoRng),
) {
    info!("{}: sending message", my_name);
    if my_store
        .load_session(their_address, None)
        .await
        .unwrap()
        .map(|session| !session.has_current_session_state())
        .unwrap_or(true)
    {
        process_pre_key(
            my_name,
            my_store,
            their_store,
            their_address,
            rng.gen_bool(0.75),
            rng,
        )
        .await;
    }

    let length = rng.gen_range(0, 140);
    let mut buffer = vec![0; length];
    rng.fill_bytes(&mut buffer);

    let outgoing_message = message_encrypt(
        &buffer,
        their_address,
        &mut my_store.session_store,
        &mut my_store.identity_store,
        None,
    )
    .await
    .unwrap();

    // Test serialization ahead of time.
    let incoming_message = match outgoing_message.message_type() {
        CiphertextMessageType::PreKey => CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(outgoing_message.serialize()).unwrap(),
        ),
        CiphertextMessageType::Whisper => CiphertextMessage::SignalMessage(
            SignalMessage::try_from(outgoing_message.serialize()).unwrap(),
        ),
        other_type => panic!("unexpected type {:?}", other_type),
    };

    their_message_queue.push((incoming_message, buffer.into()));
}

async fn receive_messages(
    my_name: &str,
    my_store: &mut InMemSignalProtocolStore,
    my_message_queue: &mut Vec<(CiphertextMessage, Box<[u8]>)>,
    their_address: &ProtocolAddress,
    rng: &mut (impl Rng + CryptoRng),
) {
    info!("{}: receiving messages", my_name);
    for (incoming_message, expected) in my_message_queue.drain(..) {
        let decrypted = message_decrypt(
            &incoming_message,
            their_address,
            &mut my_store.session_store,
            &mut my_store.identity_store,
            &mut my_store.pre_key_store,
            &mut my_store.signed_pre_key_store,
            rng,
            None,
        )
        .await
        .unwrap();

        assert_eq!(expected, decrypted.into());
    }
}

async fn archive_session(
    my_name: &str,
    my_store: &mut InMemSignalProtocolStore,
    their_address: &ProtocolAddress,
) {
    if let Some(mut session) = my_store.load_session(their_address, None).await.unwrap() {
        info!("{}: archiving session", my_name);
        session.archive_current_state().unwrap();
        my_store
            .store_session(their_address, &session, None)
            .await
            .unwrap()
    }
}

fuzz_target!(|data: (u64, &[u8])| {
    let _ = env_logger::try_init();

    let (seed, actions) = data;
    async {
        let mut csprng = StdRng::seed_from_u64(seed);

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1);
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1);

        let mut alice_store =
            InMemSignalProtocolStore::new(IdentityKeyPair::generate(&mut csprng), csprng.gen())
                .unwrap();
        let mut bob_store =
            InMemSignalProtocolStore::new(IdentityKeyPair::generate(&mut csprng), csprng.gen())
                .unwrap();

        let mut alice_queue = Vec::new();
        let mut bob_queue = Vec::new();

        for action in actions {
            let (my_name, my_store, my_queue, their_store, their_address, their_queue) =
                match action & 1 {
                    0 => (
                        "alice",
                        &mut alice_store,
                        &mut alice_queue,
                        &mut bob_store,
                        &bob_address,
                        &mut bob_queue,
                    ),
                    1 => (
                        "bob",
                        &mut bob_store,
                        &mut bob_queue,
                        &mut alice_store,
                        &alice_address,
                        &mut alice_queue,
                    ),
                    _ => unreachable!(),
                };
            match action >> 1 {
                0 => {
                    if my_queue.len() < 40 && their_queue.len() < 40 {
                        // Only archive if it can't result in old sessions getting expired.
                        // We're not testing that.
                        archive_session(my_name, my_store, their_address).await
                    }
                },
                1..=32 => {
                    receive_messages(my_name, my_store, my_queue, their_address, &mut csprng).await
                }
                33..=48 => {
                    info!("{}: drop an incoming message", my_name);
                    my_queue.pop();
                }
                49..=56 => {
                    info!("{}: shuffle incoming messages", my_name);
                    my_queue.shuffle(&mut csprng);
                }
                _ => {
                    if their_queue.len() < 1_500 {
                        // Only send if it can't result in a too-long chain.
                        // We're not testing that.
                        send_message(
                            my_name,
                            my_store,
                            their_store,
                            their_address,
                            their_queue,
                            &mut csprng,
                        )
                        .await
                    }
                }
            }
        }
    }
    .now_or_never()
    .expect("sync");
});
