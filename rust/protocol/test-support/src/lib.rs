//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Helpers used for fuzzing and proptests.

use std::time::SystemTime;

use arbitrary::Arbitrary;
use libsignal_protocol::*;
use rand::seq::SliceRandom as _;
use rand::{CryptoRng, Rng};

pub mod client_stores;

/// Returns whether there is a current, fully-usable active session for
/// `remote_address`.
pub async fn has_active_session(
    remote_address: &ProtocolAddress,
    session_store: &dyn SessionStore,
) -> Result<bool, SignalProtocolError> {
    match session_store.load_session(remote_address).await? {
        Some(record) => record
            .has_usable_sender_chain(SystemTime::UNIX_EPOCH, SessionUsabilityRequirements::all()),
        None => Ok(false),
    }
}

/// Archive the current active session for `remote_address`, if any.
///
/// Test helper. Production code archives sessions via the explicit
/// load / [`SessionRecord::archive_current_state`] / store sequence.
pub async fn archive_active_session(
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
) -> Result<(), SignalProtocolError> {
    let Some(mut session_record) = session_store.load_session(remote_address).await? else {
        return Ok(());
    };
    session_record.archive_current_state()?;
    session_store
        .store_session(remote_address, &session_record)
        .await?;
    Ok(())
}

/// Represents the part of [`Participant`] state that can be backed up by the OS.
///
/// (whether or not we want it to be)
#[derive(Clone)]
pub struct LocalState {
    store: InMemSignalProtocolStore,
    pre_key_count: u32,
}

/// States for a sent message, meant to verify test correctness as much as delivery guarantees.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageStatus {
    Sent,
    Dropped,
    Delivered,
}

/// Represents a (single-device) Signal protocol user.
///
/// Participants can send and receive messages, and have their message queues messed with.
pub struct Participant {
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
    pub fn new(
        name: &'static str,
        address: ProtocolAddress,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Self {
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

    pub fn address(&self) -> &ProtocolAddress {
        &self.address
    }

    pub fn has_pending_incoming_messages(&self) -> bool {
        !self.message_queue.is_empty()
    }

    pub fn current_store(&self) -> &InMemSignalProtocolStore {
        &self.state.store
    }

    async fn process_pre_key(
        &mut self,
        them: &mut Self,
        use_one_time_pre_key: bool,
        rng: &mut (impl Rng + CryptoRng),
    ) {
        log::info!("{}:   processing a new pre-key bundle", self.name);
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

        initiate_session(
            &them.address,
            &self.address,
            &mut self.state.store.session_store,
            &mut self.state.store.identity_store,
            &their_pre_key_bundle,
            SystemTime::UNIX_EPOCH,
            rng,
        )
        .await
        .unwrap();

        assert!(
            has_active_session(&them.address, &self.state.store.session_store)
                .await
                .unwrap()
        );
    }

    pub async fn send_message(&mut self, them: &mut Self, rng: &mut (impl Rng + CryptoRng)) {
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
        log::info!("{}: sending message {id}", self.name);
        if !has_active_session(&them.address, &self.state.store.session_store)
            .await
            .unwrap()
        {
            self.process_pre_key(them, rng.random_bool(0.75), rng).await;
        }

        let buffer = id.to_le_bytes();
        let outgoing_message = message_encrypt(
            &buffer,
            &them.address,
            &self.address,
            &mut self.state.store.session_store,
            &mut self.state.store.identity_store,
            SystemTime::UNIX_EPOCH,
            rng,
        )
        .await;

        let outgoing_message = outgoing_message.unwrap_or_else(|e| {
            panic!(
                "message_encrypt failed for {} sending to {}: {e}",
                self.name, them.name
            )
        });

        // Test serialization ahead of time.
        let incoming_message = deserialize_ciphertext(
            outgoing_message.serialize(),
            outgoing_message.message_type(),
        )
        .expect("serialized ciphertext should round-trip");

        them.message_queue.push((incoming_message, id));
    }

    pub async fn receive_messages(&mut self, them: &mut Self, rng: &mut (impl Rng + CryptoRng)) {
        log::info!("{}: receiving messages", self.name);
        for (incoming_message, expected) in self.message_queue.split_off(0) {
            match incoming_message {
                CiphertextMessage::SignalMessage(_) | CiphertextMessage::PreKeySignalMessage(_) => {
                    match message_decrypt(
                        &incoming_message,
                        &them.address,
                        &self.address,
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
                            log::info!("{}: failed to receive {expected}: {e}", self.name);
                            let error_msg = DecryptionErrorMessage::for_original(
                                incoming_message.serialize(),
                                incoming_message.message_type(),
                                Timestamp::from_epoch_millis(expected),
                                1,
                            )
                            .expect("can encode DEM");
                            them.message_queue.push((
                                CiphertextMessage::PlaintextContent(error_msg.into()),
                                u64::MAX,
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

    pub fn drop_message(&mut self, them: &mut Self) {
        match self.message_queue.pop() {
            None => {}
            Some((CiphertextMessage::PlaintextContent(_), _)) => {
                log::info!("{}: drop incoming decryption error message", self.name);
            }
            Some((_, id)) => {
                log::info!("{}: drop incoming message {id}", self.name);
                them.nack(id);
            }
        }
    }

    pub fn shuffle_messages(&mut self, rng: &mut impl Rng) {
        log::info!("{}: shuffle incoming messages", self.name);
        self.message_queue.shuffle(rng);
    }

    async fn handle_decryption_error(
        &mut self,
        them: &mut Self,
        content: PlaintextContent,
        rng: &mut (impl Rng + CryptoRng),
    ) {
        log::info!("{}: received DEM", self.name);
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

    pub async fn archive_session(&mut self, their_address: &ProtocolAddress) {
        if self
            .state
            .store
            .load_session(their_address)
            .await
            .unwrap()
            .is_some()
        {
            log::info!("{}: archiving session", self.name);
            archive_active_session(their_address, &mut self.state.store.session_store)
                .await
                .unwrap();
        }
    }

    pub fn snapshot_state(&mut self) {
        log::info!("{}: save snapshot", self.name);
        self.snapshots.push(self.state.clone());
    }

    pub fn restore_from_snapshot_if_exists(&mut self, i: u8) {
        let i = usize::from(i);
        if i >= self.snapshots.len() {
            return;
        }
        log::info!("{}: restoring snapshot", self.name);
        self.state = self.snapshots.remove(i);
    }

    pub fn ack(&mut self, id: u64) {
        self.update_status(id, MessageStatus::Delivered);
    }

    pub fn nack(&mut self, id: u64) {
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

pub fn deserialize_ciphertext(
    bytes: &[u8],
    message_type: CiphertextMessageType,
) -> Result<CiphertextMessage, SignalProtocolError> {
    match message_type {
        CiphertextMessageType::PreKey => Ok(CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(bytes)?,
        )),
        CiphertextMessageType::Whisper => Ok(CiphertextMessage::SignalMessage(
            SignalMessage::try_from(bytes)?,
        )),
        CiphertextMessageType::SenderKey => Ok(CiphertextMessage::SenderKeyMessage(
            SenderKeyMessage::try_from(bytes)?,
        )),
        CiphertextMessageType::Plaintext => Ok(CiphertextMessage::PlaintextContent(
            PlaintextContent::try_from(bytes)?,
        )),
    }
}

/// Represents the high-level actions that a [`Participant`] can take as data.
#[derive(Arbitrary, Debug, PartialEq, Eq, Clone)]
pub enum Event {
    // Session events
    Archive,

    // Full state events
    Snapshot,
    Restore {
        index: u8,
    },

    // Incoming message queue events
    Receive,
    Drop,
    Shuffle,

    // Outgoing message events
    Send {
        /// Lazy way to get a value 0..32.
        count_times_eight: u8,
    },
}

impl Event {
    pub async fn run(
        self,
        me: &mut Participant,
        them: &mut Participant,
        rng: &mut (impl Rng + CryptoRng),
    ) {
        match self {
            Event::Archive => {
                // Unlike the interactions test, we allow archiving enough sessions that even
                // old messages get lost.
                me.archive_session(them.address()).await
            }
            Event::Snapshot => me.snapshot_state(),
            Event::Restore { index } => me.restore_from_snapshot_if_exists(index),
            Event::Receive => me.receive_messages(them, rng).await,
            Event::Drop => me.drop_message(them),
            Event::Shuffle => me.shuffle_messages(rng),
            Event::Send { count_times_eight } => {
                // Send several messages at once, to increase the likelihood of PQ ratchets.
                let messages_to_send = count_times_eight / 8;
                for _ in 0..messages_to_send {
                    me.send_message(them, rng).await
                }
            }
        }
    }
}
