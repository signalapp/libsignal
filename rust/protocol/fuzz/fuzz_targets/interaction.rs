//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![no_main]

use std::convert::TryFrom;

use futures_util::FutureExt;
use libfuzzer_sys::fuzz_target;
use libsignal_protocol::*;
use log::*;
use rand::prelude::*;

struct Participant {
    name: &'static str,
    address: ProtocolAddress,
    store: InMemSignalProtocolStore,
    message_queue: Vec<(CiphertextMessage, Box<[u8]>)>,
    archive_count: u8,
}

impl Participant {
    async fn process_pre_key(
        &mut self,
        them: &mut Self,
        use_one_time_pre_key: bool,
        rng: &mut (impl Rng + CryptoRng),
    ) {
        info!("{}:   processing a new pre-key bundle", self.name);
        let their_signed_pre_key_pair = KeyPair::generate(rng);
        let their_signed_pre_key_public = their_signed_pre_key_pair.public_key.serialize();
        let their_signed_pre_key_signature = them
            .store
            .get_identity_key_pair(None)
            .await
            .unwrap()
            .private_key()
            .calculate_signature(&their_signed_pre_key_public, rng)
            .unwrap();

        let signed_pre_key_id: SignedPreKeyId = rng.gen_range(0, 0xFF_FFFF).into();

        them.store
            .save_signed_pre_key(
                signed_pre_key_id.into(),
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
            let pre_key_id: PreKeyId = rng.gen_range(0, 0xFF_FFFF).into();
            let one_time_pre_key = KeyPair::generate(rng);

            them.store
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
            them.store.get_local_registration_id(None).await.unwrap(),
            1.into(), // device id
            pre_key_info.into(),
            signed_pre_key_id.into(),
            their_signed_pre_key_pair.public_key,
            their_signed_pre_key_signature.into_vec(),
            *them
                .store
                .get_identity_key_pair(None)
                .await
                .unwrap()
                .identity_key(),
        )
        .unwrap();

        process_prekey_bundle(
            &them.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &their_pre_key_bundle,
            rng,
            None,
        )
        .await
        .unwrap();
    }

    async fn send_message(&mut self, them: &mut Self, rng: &mut (impl Rng + CryptoRng)) {
        info!("{}: sending message", self.name);
        if self
            .store
            .load_session(&them.address, None)
            .await
            .unwrap()
            .map(|session| !session.has_current_session_state())
            .unwrap_or(true)
        {
            self.process_pre_key(them, rng.gen_bool(0.75), rng).await;
        }

        let length = rng.gen_range(0, 140);
        let mut buffer = vec![0; length];
        rng.fill_bytes(&mut buffer);

        let outgoing_message = message_encrypt(
            &buffer,
            &them.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
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

        them.message_queue.push((incoming_message, buffer.into()));
    }

    async fn receive_messages(
        &mut self,
        their_address: &ProtocolAddress,
        rng: &mut (impl Rng + CryptoRng),
    ) {
        info!("{}: receiving messages", self.name);
        for (incoming_message, expected) in self.message_queue.drain(..) {
            let decrypted = message_decrypt(
                &incoming_message,
                their_address,
                &mut self.store.session_store,
                &mut self.store.identity_store,
                &mut self.store.pre_key_store,
                &mut self.store.signed_pre_key_store,
                &mut self.store.kyber_pre_key_store,
                rng,
                None,
            )
            .await
            .unwrap();

            assert_eq!(expected, decrypted.into());
        }
    }

    async fn archive_session(&mut self, their_address: &ProtocolAddress) {
        if let Some(mut session) = self.store.load_session(their_address, None).await.unwrap() {
            info!("{}: archiving session", self.name);
            session.archive_current_state().unwrap();
            self.store
                .store_session(their_address, &session, None)
                .await
                .unwrap();
            self.archive_count += 1;
        }
    }
}

fuzz_target!(|data: (u64, &[u8])| {
    let _ = env_logger::try_init();

    let (seed, actions) = data;
    async {
        let mut csprng = StdRng::seed_from_u64(seed);

        let mut alice = Participant {
            name: "alice",
            address: ProtocolAddress::new("+14151111111".to_owned(), 1.into()),
            store: InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut csprng),
                csprng.gen(),
            )
            .unwrap(),
            message_queue: Vec::new(),
            archive_count: 0,
        };
        let mut bob = Participant {
            name: "bob",
            address: ProtocolAddress::new("+14151111112".to_owned(), 1.into()),
            store: InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut csprng),
                csprng.gen(),
            )
            .unwrap(),
            message_queue: Vec::new(),
            archive_count: 0,
        };

        for action in actions {
            let (me, them) = match action & 1 {
                0 => (&mut alice, &mut bob),
                1 => (&mut bob, &mut alice),
                _ => unreachable!(),
            };
            match action >> 1 {
                0 => {
                    if me.archive_count < 40 {
                        // Only archive if it can't result in old sessions getting expired.
                        // We're not testing that.
                        me.archive_session(&them.address).await
                    }
                }
                1..=32 => me.receive_messages(&them.address, &mut csprng).await,
                33..=48 => {
                    info!("{}: drop an incoming message", me.name);
                    me.message_queue.pop();
                }
                49..=56 => {
                    info!("{}: shuffle incoming messages", me.name);
                    me.message_queue.shuffle(&mut csprng);
                }
                _ => {
                    if them.message_queue.len() < 1_500 {
                        // Only send if it can't result in a too-long chain.
                        // We're not testing that.
                        me.send_message(them, &mut csprng).await
                    }
                }
            }
        }
    }
    .now_or_never()
    .expect("sync");
});
