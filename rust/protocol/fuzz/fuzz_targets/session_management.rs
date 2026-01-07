//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![no_main]

use std::time::SystemTime;

use futures_util::FutureExt;
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use libsignal_protocol::*;
use log::*;
use rand::prelude::*;

#[derive(Clone)]
struct LocalState {
    store: InMemSignalProtocolStore,
    pre_key_count: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MessageStatus {
    Sent,
    Dropped,
    Delivered,
}

struct Participant {
    name: &'static str,
    address: ProtocolAddress,
    message_queue: Vec<(CiphertextMessage, u64)>,
    state: LocalState,
    snapshots: Vec<LocalState>,
    // In an actual client, this would live inside LocalState, but we're just using it to make sure
    // there are no bugs in the ack/nack logic.
    message_send_log: Vec<MessageStatus>,
}

impl Participant {
    fn new(name: &'static str, address: ProtocolAddress, rng: &mut (impl Rng + CryptoRng)) -> Self {
        Self {
            name,
            address,
            message_queue: Vec::new(),
            state: LocalState {
                store: InMemSignalProtocolStore::new(IdentityKeyPair::generate(rng), rng.random())
                    .unwrap(),
                pre_key_count: 0,
            },
            snapshots: Vec::new(),
            message_send_log: Vec::new(),
        }
    }

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
            .state
            .store
            .get_identity_key_pair()
            .await
            .unwrap()
            .private_key()
            .calculate_signature(&their_signed_pre_key_public, rng)
            .unwrap();

        them.state.pre_key_count += 1;
        let signed_pre_key_id: SignedPreKeyId = them.state.pre_key_count.into();

        them.state
            .store
            .save_signed_pre_key(
                signed_pre_key_id,
                &SignedPreKeyRecord::new(
                    signed_pre_key_id,
                    libsignal_protocol::Timestamp::from_epoch_millis(42),
                    &their_signed_pre_key_pair,
                    &their_signed_pre_key_signature,
                ),
            )
            .await
            .unwrap();

        them.state.pre_key_count += 1;
        let pre_key_id: PreKeyId = them.state.pre_key_count.into();

        let pre_key_info = if use_one_time_pre_key {
            let one_time_pre_key = KeyPair::generate(rng);

            them.state
                .store
                .save_pre_key(
                    pre_key_id,
                    &PreKeyRecord::new(pre_key_id, &one_time_pre_key),
                )
                .await
                .unwrap();
            Some((pre_key_id, one_time_pre_key.public_key))
        } else {
            None
        };

        let their_kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
        let their_kyber_pre_key_public = their_kyber_pre_key_pair.public_key.serialize();
        let their_kyber_pre_key_signature = them
            .state
            .store
            .get_identity_key_pair()
            .await
            .unwrap()
            .private_key()
            .calculate_signature(&their_kyber_pre_key_public, rng)
            .unwrap();

        them.state.pre_key_count += 1;
        let kyber_pre_key_id: KyberPreKeyId = them.state.pre_key_count.into();

        them.state
            .store
            .save_kyber_pre_key(
                kyber_pre_key_id,
                &KyberPreKeyRecord::new(
                    kyber_pre_key_id,
                    libsignal_protocol::Timestamp::from_epoch_millis(42),
                    &their_kyber_pre_key_pair,
                    &their_kyber_pre_key_signature,
                ),
            )
            .await
            .unwrap();

        let their_pre_key_bundle = PreKeyBundle::new(
            them.state.store.get_local_registration_id().await.unwrap(),
            DeviceId::new(1).unwrap(),
            pre_key_info,
            signed_pre_key_id,
            their_signed_pre_key_pair.public_key,
            their_signed_pre_key_signature.into_vec(),
            kyber_pre_key_id,
            their_kyber_pre_key_pair.public_key,
            their_kyber_pre_key_signature.into_vec(),
            *them
                .state
                .store
                .get_identity_key_pair()
                .await
                .unwrap()
                .identity_key(),
        )
        .unwrap();

        process_prekey_bundle(
            &them.address,
            &mut self.state.store.session_store,
            &mut self.state.store.identity_store,
            &their_pre_key_bundle,
            SystemTime::UNIX_EPOCH,
            rng,
        )
        .await
        .unwrap();

        assert!(
            self.state
                .store
                .load_session(&them.address)
                .await
                .unwrap()
                .expect("just created")
                .has_usable_sender_chain(
                    SystemTime::UNIX_EPOCH,
                    SessionUsabilityRequirements::all()
                )
                .unwrap()
        );
    }

    async fn send_message(&mut self, them: &mut Self, rng: &mut (impl Rng + CryptoRng)) {
        self.send_message_with_id(them, self.message_send_log.len().try_into().unwrap(), rng)
            .await;
        self.message_send_log.push(MessageStatus::Sent);
    }

    async fn send_message_with_id(
        &mut self,
        them: &mut Self,
        id: u64,
        rng: &mut (impl Rng + CryptoRng),
    ) {
        info!("{}: sending message {id}", self.name);
        if !self
            .state
            .store
            .load_session(&them.address)
            .await
            .unwrap()
            .and_then(|session| {
                session
                    .has_usable_sender_chain(
                        SystemTime::UNIX_EPOCH,
                        SessionUsabilityRequirements::all(),
                    )
                    .ok()
            })
            .unwrap_or(false)
        {
            self.process_pre_key(them, rng.random_bool(0.75), rng).await;
        }

        let buffer = id.to_le_bytes();
        let outgoing_message = message_encrypt(
            &buffer,
            &them.address,
            &mut self.state.store.session_store,
            &mut self.state.store.identity_store,
            SystemTime::UNIX_EPOCH,
            rng,
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

        them.message_queue.push((incoming_message, id));
    }

    async fn receive_messages(&mut self, them: &mut Self, rng: &mut (impl Rng + CryptoRng)) {
        info!("{}: receiving messages", self.name);
        for (incoming_message, expected) in self.message_queue.split_off(0) {
            match incoming_message {
                CiphertextMessage::SignalMessage(_) | CiphertextMessage::PreKeySignalMessage(_) => {
                    match message_decrypt(
                        &incoming_message,
                        &them.address,
                        &mut self.state.store.session_store,
                        &mut self.state.store.identity_store,
                        &mut self.state.store.pre_key_store,
                        &self.state.store.signed_pre_key_store,
                        &mut self.state.store.kyber_pre_key_store,
                        rng,
                    )
                    .await
                    {
                        Ok(decrypted) => {
                            assert_eq!(expected.to_le_bytes(), &decrypted[..]);
                            // For this test we don't bother representing acks as messages; it
                            // wouldn't add anything.
                            them.ack(expected);
                        }
                        Err(e) => {
                            info!("{}: failed to receive {expected}: {e}", self.name);
                            let error_msg = DecryptionErrorMessage::for_original(
                                incoming_message.serialize(),
                                incoming_message.message_type(),
                                Timestamp::from_epoch_millis(expected),
                                1,
                            )
                            .expect("can encode DEM");
                            them.message_queue.push((
                                CiphertextMessage::PlaintextContent(error_msg.into()),
                                Default::default(),
                            ));
                        }
                    }
                }
                CiphertextMessage::SenderKeyMessage(_) => {
                    unreachable!("no sender key messages in this test")
                }
                CiphertextMessage::PlaintextContent(content) => {
                    self.handle_decryption_error(them, content, rng).await;
                }
            }
        }
    }

    async fn handle_decryption_error(
        &mut self,
        them: &mut Self,
        content: PlaintextContent,
        rng: &mut (impl Rng + CryptoRng),
    ) {
        info!("{}: received DEM", self.name);
        let their_address = &them.address;
        let dem = extract_decryption_error_message_from_serialized_content(content.body())
            .expect("all PlaintextContent is DecryptionErrorMessages in this test");
        assert_eq!(dem.device_id(), 1);

        let id = dem.timestamp().epoch_millis();
        let Some(status) = self.message_send_log.get(usize::try_from(id).unwrap()) else {
            panic!(
                "failed to decrypt an unsent message {id} ({} total sent)",
                self.message_send_log.len()
            )
        };
        match status {
            MessageStatus::Sent => {
                // Continue.
            }
            MessageStatus::Dropped => {
                panic!("got a decryption error for dropped message {id}");
            }
            MessageStatus::Delivered => {
                panic!("got a decryption error for successfully delivered message {id}");
            }
        }

        let ratchet_key = dem
            .ratchet_key()
            .expect("all DEMs for 1:1 messages have ratchet keys");
        if self
            .state
            .store
            .load_session(their_address)
            .await
            .unwrap()
            .is_some_and(|session| {
                session
                    .current_ratchet_key_matches(ratchet_key)
                    .expect("structurally valid session")
            })
        {
            self.archive_session(their_address).await;
        }

        self.send_message_with_id(them, id, rng).await;
    }

    async fn archive_session(&mut self, their_address: &ProtocolAddress) {
        if let Some(mut session) = self.state.store.load_session(their_address).await.unwrap() {
            info!("{}: archiving session", self.name);
            session.archive_current_state().unwrap();
            self.state
                .store
                .store_session(their_address, &session)
                .await
                .unwrap();
        }
    }

    fn snapshot_state(&mut self) {
        info!("{}: save snapshot", self.name);
        self.snapshots.push(self.state.clone());
    }

    fn restore_from_snapshot_if_exists(&mut self, i: u8) {
        let i = usize::from(i);
        if i >= self.snapshots.len() {
            return;
        }
        info!("{}: restoring snapshot", self.name);
        self.state = self.snapshots.remove(i);
    }

    fn ack(&mut self, id: u64) {
        self.update_status(id, MessageStatus::Delivered);
    }

    fn nack(&mut self, id: u64) {
        self.update_status(id, MessageStatus::Dropped);
    }

    fn update_status(&mut self, id: u64, updated_status: MessageStatus) {
        let Some(status) = self.message_send_log.get_mut(usize::try_from(id).unwrap()) else {
            panic!(
                "tried to ack an unsent message {id} ({} total sent)",
                self.message_send_log.len()
            )
        };
        match status {
            MessageStatus::Sent => {
                *status = updated_status;
            }
            MessageStatus::Dropped => {
                panic!("acked message {id} that was dropped");
            }
            MessageStatus::Delivered => {
                panic!("acked message {id} that was already delivered");
            }
        }
    }
}

#[derive(Arbitrary, Debug, PartialEq, Eq)]
enum Who {
    A,
    B,
}

#[derive(Arbitrary, Debug, PartialEq, Eq)]
enum Event {
    // Session events
    Archive,

    // Full state events
    Snapshot,
    Restore(u8),

    // Incoming message queue events
    Receive,
    Drop,
    Shuffle,

    // Outgoing message events
    Send(u8),
}

fuzz_target!(|actions: Vec<(Who, Event)>| {
    // Logs default to Off because we deliberately introduce session errors in this test.
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Off)
        .parse_default_env()
        .try_init();

    async {
        let mut csprng = StdRng::seed_from_u64(0);

        let mut alice = Participant::new(
            "alice",
            ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap()),
            &mut csprng,
        );
        let mut bob = Participant::new(
            "bob",
            ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap()),
            &mut csprng,
        );

        for (who, event) in actions {
            let (me, them) = match who {
                Who::A => (&mut alice, &mut bob),
                Who::B => (&mut bob, &mut alice),
            };
            match event {
                Event::Archive => {
                    // Unlike the interactions test, we allow archiving enough sessions that even
                    // old messages get lost.
                    me.archive_session(&them.address).await
                }
                Event::Snapshot => {
                    me.snapshot_state();
                }
                Event::Restore(i) => {
                    me.restore_from_snapshot_if_exists(i);
                }
                Event::Receive => me.receive_messages(them, &mut csprng).await,
                Event::Drop => {
                    if let Some((_, id)) = me.message_queue.pop() {
                        info!("{}: drop incoming message {id}", me.name);
                        them.nack(id);
                    }
                }
                Event::Shuffle => {
                    info!("{}: shuffle incoming messages", me.name);
                    me.message_queue.shuffle(&mut csprng);
                }
                Event::Send(i) => {
                    // Send several messages at once, to increase the likelihood of PQ ratchets.
                    let messages_to_send = i / 8;
                    for _ in 0..messages_to_send {
                        me.send_message(them, &mut csprng).await
                    }
                }
            }
        }

        // Allow time to quiesce: bring both sides up to speed, send one message in each direction
        // (synchronized), and service resend requests until both queues are empty.
        info!("Quiescing...");
        while !alice.message_queue.is_empty() || !bob.message_queue.is_empty() {
            alice.receive_messages(&mut bob, &mut csprng).await;
            bob.receive_messages(&mut alice, &mut csprng).await;
        }

        async fn exchange_messages_until_agreement(
            attempts: usize,
            alice: &mut Participant,
            bob: &mut Participant,
            rng: &mut (impl Rng + CryptoRng),
        ) {
            for _ in 0..attempts {
                // Go back to taking turns and see if things even out.
                alice.send_message(bob, rng).await;
                bob.receive_messages(alice, rng).await;
                bob.send_message(alice, rng).await;
                alice.receive_messages(bob, rng).await;

                let a_to_b_session = alice
                    .state
                    .store
                    .session_store
                    .load_session(&bob.address)
                    .await
                    .expect("can load")
                    .expect("Alice has a session with Bob");
                let b_to_a_session = bob
                    .state
                    .store
                    .session_store
                    .load_session(&alice.address)
                    .await
                    .expect("can load")
                    .expect("Bob has a session with Alice");
                if a_to_b_session
                    .alice_base_key()
                    .expect("A->B session established")
                    == b_to_a_session
                        .alice_base_key()
                        .expect("B->A session established")
                {
                    return;
                }
            }
            panic!(
                "even after {attempts} more messages in each direction, Alice and Bob are not on the same session"
            );
        }

        exchange_messages_until_agreement(10, &mut alice, &mut bob, &mut csprng).await;
    }
    .now_or_never()
    .expect("sync");
});
