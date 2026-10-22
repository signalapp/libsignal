//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::new_without_default)]

pub use libsignal_protocol_current::{
    CiphertextMessageType, DecryptionErrorMessage, PlaintextContent, PreKeyBundle, Timestamp,
    UnidentifiedSenderMessageContent, extract_decryption_error_message_from_serialized_content,
};
use rand::Rng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom as _;

/// All randomness consumed by `LibSignalProtocolStore` impls flows through
/// `&mut StdRng` so a single seed can drive both the action schedule and the
/// internal randomness such as key material.
pub trait LibSignalProtocolStore {
    fn version(&self) -> &'static str;
    fn box_clone(&self) -> Box<dyn LibSignalProtocolStore>;
    fn to_current_for_remote(&self, remote: &str) -> Box<dyn LibSignalProtocolStore>;
    fn create_pre_key_bundle(&mut self, rng: &mut StdRng) -> PreKeyBundle;
    fn process_pre_key_bundle(
        &mut self,
        remote: &str,
        local: &str,
        pre_key_bundle: PreKeyBundle,
        rng: &mut StdRng,
    );
    fn has_active_session(&self, remote: &str) -> bool;
    fn archive_active_session(&mut self, remote: &str);
    fn active_session_id(&self, remote: &str) -> Option<Vec<u8>>;
    fn current_ratchet_key_matches(&self, remote: &str, ratchet_key: &[u8]) -> bool;
    fn encrypt(
        &mut self,
        remote: &str,
        local: &str,
        msg: &[u8],
        rng: &mut StdRng,
    ) -> (Vec<u8>, CiphertextMessageType) {
        self.try_encrypt(remote, local, msg, rng)
            .expect("can encrypt messages")
    }
    fn try_encrypt(
        &mut self,
        remote: &str,
        local: &str,
        msg: &[u8],
        rng: &mut StdRng,
    ) -> Result<(Vec<u8>, CiphertextMessageType), Box<dyn std::error::Error>>;
    fn decrypt(
        &mut self,
        remote: &str,
        local: &str,
        msg: &[u8],
        msg_type: CiphertextMessageType,
        rng: &mut StdRng,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

    fn encrypt_sealed_sender_v1(
        &self,
        remote: &str,
        msg: &UnidentifiedSenderMessageContent,
        rng: &mut StdRng,
    ) -> Vec<u8>;
    fn encrypt_sealed_sender_v2(
        &self,
        remote: &str,
        msg: &UnidentifiedSenderMessageContent,
        rng: &mut StdRng,
    ) -> Vec<u8>;
    fn decrypt_sealed_sender(&self, msg: &[u8]) -> UnidentifiedSenderMessageContent;
}

/// A successful last-resort prekey usage, retained independently of sessions.
/// Public keys use their complete serialized encoding, including the type byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KyberPreKeyUsage {
    pub kyber_pre_key_id: u32,
    pub signed_pre_key_id: u32,
    pub base_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SerializedConversationState {
    pub identity_key_pair: Vec<u8>,
    pub registration_id: u32,
    pub remote_identity_key: Option<Vec<u8>>,
    pub session_record: Option<Vec<u8>>,
    pub pre_keys: Vec<(u32, Vec<u8>)>,
    pub signed_pre_keys: Vec<(u32, Vec<u8>)>,
    pub kyber_pre_keys: Vec<(u32, Vec<u8>)>,
    /// All usage markers for the exported prekey store, including sessions
    /// already evicted from the archive and conversations with other peers.
    pub kyber_pre_key_usages: Vec<KyberPreKeyUsage>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageStatus {
    Sent,
    Dropped,
    Delivered,
}

/// A (single-device) Signal protocol user, based on `Participant` from
/// `libsignal-protocol-test-support` but abstracted over libsignal versions.
///
/// Where the test-support version holds concrete types, this one stays
/// version-agnostic so it can drive several pinned libsignal versions at once:
/// the store is a `dyn LibSignalProtocolStore` trait object, the address is a
/// `String`, and queued messages are raw bytes plus a `CiphertextMessageType`
/// tag rather than a concrete `CiphertextMessage`. The two structs will drift
/// apart as those concrete types evolve, and that's fine.
pub struct Participant {
    name: &'static str,
    address: String,
    message_queue: Vec<(Vec<u8>, CiphertextMessageType, u64)>,
    store: Box<dyn LibSignalProtocolStore>,
    snapshots: Vec<Box<dyn LibSignalProtocolStore>>,
    message_send_log: Vec<MessageStatus>,
}

impl Participant {
    pub fn new(name: &'static str, address: &str, store: Box<dyn LibSignalProtocolStore>) -> Self {
        Self {
            name,
            address: address.to_owned(),
            message_queue: Vec::new(),
            store,
            snapshots: Vec::new(),
            message_send_log: Vec::new(),
        }
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn version(&self) -> &'static str {
        self.store.version()
    }

    pub fn has_pending_incoming_messages(&self) -> bool {
        !self.message_queue.is_empty()
    }

    pub fn active_session_id(&self, remote: &str) -> Option<Vec<u8>> {
        self.store.active_session_id(remote)
    }

    pub fn all_messages_accounted_for(&self) -> bool {
        self.message_send_log
            .iter()
            .all(|status| !matches!(status, MessageStatus::Sent))
    }

    async fn process_pre_key(&mut self, them: &mut Self, rng: &mut StdRng) {
        log::info!("{}: processing a new pre-key bundle", self.name);
        let their_pre_key_bundle = them.store.create_pre_key_bundle(rng);
        let addr = self.address().to_string();
        self.store
            .process_pre_key_bundle(them.address(), &addr, their_pre_key_bundle, rng);
        assert!(self.store.has_active_session(them.address()));
    }

    pub async fn send_message(&mut self, them: &mut Self, rng: &mut StdRng) {
        self.send_message_with_id(them, self.message_send_log.len().try_into().unwrap(), rng)
            .await;
        self.message_send_log.push(MessageStatus::Sent);
    }

    async fn send_message_with_id(&mut self, them: &mut Self, id: u64, rng: &mut StdRng) {
        log::info!("{}({}): sending message {id}", self.name, self.version());
        let remote = them.address().to_owned();
        let local = self.address().to_owned();
        if !self.store.has_active_session(them.address()) {
            self.process_pre_key(them, rng).await;
        }

        let buffer = id.to_le_bytes();
        let mut outgoing_message = self.store.try_encrypt(&remote, &local, &buffer, rng);
        if outgoing_message.is_err() {
            self.process_pre_key(them, rng).await;
            outgoing_message = self.store.try_encrypt(&remote, &local, &buffer, rng);
        }

        let (outgoing_message, msg_type) = outgoing_message.unwrap_or_else(|e| {
            panic!(
                "message_encrypt failed for {}({}) sending to {}({}): {e}",
                self.name,
                self.version(),
                them.name,
                them.version()
            )
        });

        them.message_queue.push((outgoing_message, msg_type, id));
    }

    pub async fn receive_messages(&mut self, them: &mut Self, rng: &mut StdRng) {
        log::info!("{}({}): receiving messages", self.name, self.version());
        for (incoming_message, msg_type, expected) in self.message_queue.split_off(0) {
            let remote = them.address().to_owned();
            let local = self.address().to_owned();
            match msg_type {
                CiphertextMessageType::Plaintext => {
                    self.handle_decryption_error(them, &incoming_message, rng)
                        .await;
                }
                msg_type => {
                    match self
                        .store
                        .decrypt(&remote, &local, &incoming_message, msg_type, rng)
                    {
                        Ok(decrypted) => {
                            assert_eq!(expected.to_le_bytes(), &decrypted[..]);
                            them.ack(expected);
                        }
                        Err(e) => {
                            log::info!("{}: failed to receive {expected}: {e}", self.name);
                            let error_msg = DecryptionErrorMessage::for_original(
                                &incoming_message,
                                msg_type,
                                Timestamp::from_epoch_millis(expected),
                                1,
                            )
                            .expect("can encode DEM");
                            let plaintext = PlaintextContent::from(error_msg).serialized().to_vec();
                            them.message_queue.push((
                                plaintext,
                                CiphertextMessageType::Plaintext,
                                u64::MAX,
                            ));
                        }
                    }
                }
            }
        }
    }

    pub fn drop_message(&mut self, them: &mut Self) {
        match self.message_queue.pop() {
            None => {}
            Some((content, CiphertextMessageType::Plaintext, _)) => {
                log::info!("{}: drop incoming decryption error message", self.name);
                let dem = extract_decryption_error_message_from_serialized_content(
                    PlaintextContent::try_from(content.as_slice())
                        .expect("all plaintext content is DecryptionErrorMessage in this test")
                        .body(),
                )
                .expect("valid DEM");
                self.nack(dem.timestamp().epoch_millis());
            }
            Some((_, _, id)) => {
                log::info!("{}: drop incoming message {id}", self.name);
                them.nack(id);
            }
        }
    }

    pub fn shuffle_messages(&mut self, rng: &mut impl Rng) {
        log::info!("{}: shuffle incoming messages", self.name);
        self.message_queue.shuffle(rng);
    }

    pub fn corrupt_message(&mut self, _them: &mut Self) {
        let Some((message, msg_type, id)) = self.message_queue.pop() else {
            return;
        };
        match msg_type {
            // Skip the Plaintext (DecryptionErrorMessage) arm: we're not testing
            // corrupted DEMs, so re-queue it untouched.
            CiphertextMessageType::Plaintext => {
                self.message_queue.push((message, msg_type, id));
            }
            _ => {
                let mut message = message;
                if let Some(last) = message.last_mut() {
                    *last = last.wrapping_add(1);
                }
                log::info!("{}: corrupt incoming message {id}", self.name);
                self.message_queue.push((message, msg_type, id));
            }
        }
    }

    async fn handle_decryption_error(&mut self, them: &mut Self, content: &[u8], rng: &mut StdRng) {
        log::info!("{}({}): received DEM", self.name, self.version());
        let dem = extract_decryption_error_message_from_serialized_content(
            PlaintextContent::try_from(content)
                .expect("all plaintext content is DecryptionErrorMessage in this test")
                .body(),
        )
        .expect("valid DEM");
        assert_eq!(dem.device_id(), 1);

        let id = dem.timestamp().epoch_millis();
        let Some(status) = self.message_send_log.get(usize::try_from(id).unwrap()) else {
            panic!(
                "failed to decrypt an unsent message {id} ({} total sent)",
                self.message_send_log.len()
            )
        };
        match status {
            MessageStatus::Sent => {}
            MessageStatus::Dropped => {
                log::info!(
                    "{}: ignoring DEM for explicitly lost message {id}",
                    self.name
                );
                return;
            }
            MessageStatus::Delivered => {
                panic!("got a decryption error for successfully delivered message {id}")
            }
        }

        let ratchet_key = dem
            .ratchet_key()
            .expect("all DEMs for 1:1 messages have ratchet keys");
        if self
            .store
            .current_ratchet_key_matches(them.address(), &ratchet_key.serialize())
        {
            self.store.archive_active_session(them.address());
        }

        self.send_message_with_id(them, id, rng).await;
    }

    pub fn snapshot_state(&mut self) {
        log::info!("{}: save snapshot", self.name);
        self.snapshots.push(self.store.box_clone());
    }

    pub fn restore_from_snapshot_if_exists(&mut self, i: u8) {
        let i = usize::from(i);
        if i >= self.snapshots.len() {
            return;
        }
        log::info!("{}: restoring snapshot", self.name);
        self.store = self.snapshots.remove(i);
    }

    pub fn replace_store(&mut self, store: Box<dyn LibSignalProtocolStore>) {
        log::info!(
            "{}: replacing store implementation {} -> {}",
            self.name,
            self.store.version(),
            store.version()
        );
        self.store = store;
        self.snapshots.clear();
    }

    pub fn upgrade_store_to_current(&mut self, remote: &str) {
        self.replace_store(self.store.to_current_for_remote(remote));
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
            MessageStatus::Sent => *status = updated_status,
            MessageStatus::Dropped => panic!("acked message {id} that was dropped"),
            MessageStatus::Delivered => {
                panic!("acked message {id} that was already delivered")
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Event {
    Archive,
    Snapshot,
    Restore { index: u8 },
    Receive,
    Drop,
    Shuffle,
    Corrupt,
    Send { count_times_eight: u8 },
}

impl Event {
    pub async fn run(self, me: &mut Participant, them: &mut Participant, rng: &mut StdRng) {
        match self {
            Event::Archive => me.store.archive_active_session(them.address()),
            Event::Snapshot => me.snapshot_state(),
            Event::Restore { index } => me.restore_from_snapshot_if_exists(index),
            Event::Receive => me.receive_messages(them, rng).await,
            Event::Drop => me.drop_message(them),
            Event::Shuffle => me.shuffle_messages(rng),
            Event::Corrupt => me.corrupt_message(them),
            Event::Send { count_times_eight } => {
                let messages_to_send = count_times_eight / 8;
                for _ in 0..messages_to_send {
                    me.send_message(them, rng).await;
                }
            }
        }
    }
}

mod current;
pub use current::LibSignalProtocolCurrent;

mod pre_tahini;
pub use pre_tahini::LibSignalProtocolPreTahini;

mod v73;
pub use v73::LibSignalProtocolV73;
mod v74;
pub use v74::LibSignalProtocolV74;

// Use this function to debug tests
pub fn init_test_logger() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::max())
        .is_test(true)
        .try_init();
}

pub fn try_all_combinations(
    f: fn(&mut dyn LibSignalProtocolStore, &mut dyn LibSignalProtocolStore, &mut StdRng),
    make_previous: &[fn(&mut StdRng) -> Box<dyn LibSignalProtocolStore>],
    rng: &mut StdRng,
) {
    let run = |alice_store: &mut dyn LibSignalProtocolStore,
               bob_store: &mut dyn LibSignalProtocolStore,
               rng: &mut StdRng| {
        log::info!(
            "alice: {}, bob: {}",
            alice_store.version(),
            bob_store.version()
        );
        f(alice_store, bob_store, rng)
    };

    // Current<->Current, to test that the test is correct.
    run(
        &mut LibSignalProtocolCurrent::new(rng),
        &mut LibSignalProtocolCurrent::new(rng),
        rng,
    );

    // Current<->Previous
    for bob_store_maker in make_previous {
        let mut alice_store = LibSignalProtocolCurrent::new(rng);
        let mut bob_store = bob_store_maker(rng);
        run(&mut alice_store, &mut *bob_store, rng);
    }

    // Previous<->Current
    for alice_store_maker in make_previous {
        let mut alice_store = alice_store_maker(rng);
        let mut bob_store = LibSignalProtocolCurrent::new(rng);
        run(&mut *alice_store, &mut bob_store, rng);
    }
}
