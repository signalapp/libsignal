//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use async_trait::async_trait;
use futures_util::FutureExt;
use libsignal_protocol_current::*;
use rand::Rng;
use rand::rngs::StdRng;

use crate::{KyberPreKeyUsage, SerializedConversationState};

fn address(id: &str) -> ProtocolAddress {
    ProtocolAddress::new(id.into(), DeviceId::new(1).unwrap())
}

#[derive(Clone)]
pub struct LibSignalProtocolCurrent(InMemSignalProtocolStore, Vec<KyberPreKeyUsage>);

/// `InMemKyberPreKeyStore` does not expose its replay markers. Mirror
/// successful writes at the callback boundary so rollback export preserves
/// them, including writes followed by a failure later in the protocol
/// operation.
struct RecordingKyberPreKeyStore<'a> {
    inner: &'a mut InMemKyberPreKeyStore,
    usages: &'a mut Vec<KyberPreKeyUsage>,
}

#[async_trait(?Send)]
impl KyberPreKeyStore for RecordingKyberPreKeyStore<'_> {
    async fn get_kyber_pre_key(
        &self,
        kyber_pre_key_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        self.inner.get_kyber_pre_key(kyber_pre_key_id).await
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_pre_key_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.inner
            .save_kyber_pre_key(kyber_pre_key_id, record)
            .await
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_pre_key_id: KyberPreKeyId,
        signed_pre_key_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        self.inner
            .mark_kyber_pre_key_used(kyber_pre_key_id, signed_pre_key_id, base_key)
            .await?;
        self.usages.push(KyberPreKeyUsage {
            kyber_pre_key_id: kyber_pre_key_id.into(),
            signed_pre_key_id: signed_pre_key_id.into(),
            base_key: base_key.serialize().to_vec(),
        });
        Ok(())
    }
}

impl LibSignalProtocolCurrent {
    pub fn new(rng: &mut StdRng) -> Self {
        let identity_key = IdentityKeyPair::generate(rng);
        // Valid registration IDs fit in 14 bits.
        let registration_id: u8 = rng.random();

        Self(
            InMemSignalProtocolStore::new(identity_key, registration_id as u32)
                .expect("can initialize"),
            Vec::new(),
        )
    }

    pub fn from_serialized_conversation_state(
        snapshot: &SerializedConversationState,
        remote: &str,
    ) -> Self {
        let mut upgraded = Self(
            InMemSignalProtocolStore::new(
                IdentityKeyPair::try_from(&snapshot.identity_key_pair[..])
                    .expect("current can read serialized identity key pair"),
                snapshot.registration_id,
            )
            .expect("can initialize upgraded store"),
            snapshot.kyber_pre_key_usages.clone(),
        );

        if let Some(remote_identity) = &snapshot.remote_identity_key {
            upgraded
                .0
                .save_identity(
                    &address(remote),
                    &IdentityKey::decode(remote_identity)
                        .expect("current can read serialized remote identity"),
                )
                .now_or_never()
                .expect("synchronous")
                .expect("can restore known identity");
        }

        if let Some(session_record) = &snapshot.session_record {
            let session =
                SessionRecord::deserialize(session_record).expect("current can read old session");
            upgraded
                .0
                .store_session(&address(remote), &session)
                .now_or_never()
                .expect("synchronous")
                .expect("can restore session");
        }

        for (id, record) in &snapshot.pre_keys {
            let pre_key =
                PreKeyRecord::deserialize(record).expect("current can read serialized pre-key");
            upgraded
                .0
                .save_pre_key((*id).into(), &pre_key)
                .now_or_never()
                .expect("synchronous")
                .expect("can restore pre-key");
        }

        for (id, record) in &snapshot.signed_pre_keys {
            let signed_pre_key = SignedPreKeyRecord::deserialize(record)
                .expect("current can read serialized signed pre-key");
            upgraded
                .0
                .save_signed_pre_key((*id).into(), &signed_pre_key)
                .now_or_never()
                .expect("synchronous")
                .expect("can restore signed pre-key");
        }

        for (id, record) in &snapshot.kyber_pre_keys {
            let kyber_pre_key = KyberPreKeyRecord::deserialize(record)
                .expect("current can read serialized kyber pre-key");
            upgraded
                .0
                .save_kyber_pre_key((*id).into(), &kyber_pre_key)
                .now_or_never()
                .expect("synchronous")
                .expect("can restore kyber pre-key");
        }

        // Restoring the retained prekeys also requires their replay history.
        // This cannot be reconstructed from the bounded session archive.
        for usage in &snapshot.kyber_pre_key_usages {
            upgraded
                .0
                .mark_kyber_pre_key_used(
                    usage.kyber_pre_key_id.into(),
                    usage.signed_pre_key_id.into(),
                    &PublicKey::deserialize(&usage.base_key)
                        .expect("current can read serialized initiator base key"),
                )
                .now_or_never()
                .expect("synchronous")
                .expect("can restore kyber pre-key usage");
        }

        upgraded
    }

    pub fn serialize_conversation_state(&self, remote: &str) -> SerializedConversationState {
        let identity_key_pair = self
            .0
            .get_identity_key_pair()
            .now_or_never()
            .expect("synchronous")
            .expect("can fetch identity key pair")
            .serialize()
            .to_vec();
        let registration_id = self
            .0
            .get_local_registration_id()
            .now_or_never()
            .expect("synchronous")
            .expect("can fetch registration id");
        let remote_identity_key = self
            .0
            .get_identity(&address(remote))
            .now_or_never()
            .expect("synchronous")
            .expect("can fetch remote identity")
            .map(|key| key.serialize().to_vec());
        let session_record = self
            .0
            .load_session(&address(remote))
            .now_or_never()
            .expect("synchronous")
            .expect("can fetch session")
            .map(|session| session.serialize().expect("can serialize session"));
        let pre_keys = self
            .0
            .all_pre_key_ids()
            .copied()
            .map(|id| {
                let record = self
                    .0
                    .get_pre_key(id)
                    .now_or_never()
                    .expect("synchronous")
                    .expect("can fetch pre-key");
                (
                    u32::from(id),
                    record.serialize().expect("can serialize pre-key"),
                )
            })
            .collect();
        let signed_pre_keys = self
            .0
            .all_signed_pre_key_ids()
            .copied()
            .map(|id| {
                let record = self
                    .0
                    .get_signed_pre_key(id)
                    .now_or_never()
                    .expect("synchronous")
                    .expect("can fetch signed pre-key");
                (
                    u32::from(id),
                    record.serialize().expect("can serialize signed pre-key"),
                )
            })
            .collect();
        let kyber_pre_keys = self
            .0
            .all_kyber_pre_key_ids()
            .copied()
            .map(|id| {
                let record = self
                    .0
                    .get_kyber_pre_key(id)
                    .now_or_never()
                    .expect("synchronous")
                    .expect("can fetch kyber pre-key");
                (
                    u32::from(id),
                    record.serialize().expect("can serialize kyber pre-key"),
                )
            })
            .collect();

        SerializedConversationState {
            identity_key_pair,
            registration_id,
            remote_identity_key,
            session_record,
            pre_keys,
            signed_pre_keys,
            kyber_pre_keys,
            kyber_pre_key_usages: self.1.clone(),
        }
    }

    /// Models rolling a client back to the pinned pre-Tahini release: the
    /// stored state for `remote`, as this version wrote it, is loaded by
    /// pre-Tahini code.
    pub fn to_pre_tahini_for_remote(&self, remote: &str) -> crate::LibSignalProtocolPreTahini {
        crate::LibSignalProtocolPreTahini::from_serialized_conversation_state(
            &self.serialize_conversation_state(remote),
            remote,
        )
    }
}

impl super::LibSignalProtocolStore for LibSignalProtocolCurrent {
    fn version(&self) -> &'static str {
        "current"
    }

    fn box_clone(&self) -> Box<dyn super::LibSignalProtocolStore> {
        Box::new(self.clone())
    }

    fn to_current_for_remote(&self, _remote: &str) -> Box<dyn super::LibSignalProtocolStore> {
        Box::new(self.clone())
    }

    fn create_pre_key_bundle(&mut self, rng: &mut StdRng) -> PreKeyBundle {
        let pre_key_pair = KeyPair::generate(rng);
        let signed_pre_key_pair = KeyPair::generate(rng);
        let signed_pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);

        let identity_key = self
            .0
            .get_identity_key_pair()
            .now_or_never()
            .expect("synchronous")
            .expect("can fetch identity key");
        let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
        let signed_pre_key_signature = identity_key
            .private_key()
            .calculate_signature(&signed_pre_key_public, rng)
            .expect("can calculate signatures");

        let signed_pq_pre_key_public = signed_pq_pre_key_pair.public_key.serialize();
        let signed_pq_pre_key_signature = identity_key
            .private_key()
            .calculate_signature(&signed_pq_pre_key_public, rng)
            .expect("can sign");

        let device_id: DeviceId = rng.random();
        let pre_key_id: u32 = rng.random();
        let signed_pre_key_id: u32 = rng.random();
        let kyber_pre_key_id: u32 = rng.random();

        let pre_key_bundle = PreKeyBundle::new(
            self.0
                .get_local_registration_id()
                .now_or_never()
                .expect("synchronous")
                .expect("can fetch registration id"),
            device_id,
            Some((pre_key_id.into(), pre_key_pair.public_key)),
            signed_pre_key_id.into(),
            signed_pre_key_pair.public_key,
            signed_pre_key_signature.to_vec(),
            kyber_pre_key_id.into(),
            signed_pq_pre_key_pair.public_key.clone(),
            signed_pq_pre_key_signature.to_vec(),
            *self
                .0
                .get_identity_key_pair()
                .now_or_never()
                .expect("synchronous")
                .expect("can fetch identity key")
                .identity_key(),
        )
        .expect("can create pre-key bundles");

        self.0
            .save_pre_key(
                pre_key_id.into(),
                &PreKeyRecord::new(pre_key_id.into(), &pre_key_pair),
            )
            .now_or_never()
            .expect("synchronous")
            .expect("can save pre-keys");

        let timestamp = rng.random();

        self.0
            .save_signed_pre_key(
                signed_pre_key_id.into(),
                &SignedPreKeyRecord::new(
                    signed_pre_key_id.into(),
                    timestamp,
                    &signed_pre_key_pair,
                    &signed_pre_key_signature,
                ),
            )
            .now_or_never()
            .expect("synchronous")
            .expect("can save pre-keys");

        self.0
            .save_kyber_pre_key(
                kyber_pre_key_id.into(),
                &KyberPreKeyRecord::new(
                    kyber_pre_key_id.into(),
                    timestamp,
                    &signed_pq_pre_key_pair,
                    &signed_pq_pre_key_signature,
                ),
            )
            .now_or_never()
            .expect("synchronous")
            .expect("can save");

        pre_key_bundle
    }

    fn process_pre_key_bundle(
        &mut self,
        remote: &str,
        local: &str,
        pre_key_bundle: PreKeyBundle,
        rng: &mut StdRng,
    ) {
        process_prekey_bundle(
            &address(remote),
            &address(local),
            &mut self.0.session_store,
            &mut self.0.identity_store,
            &pre_key_bundle,
            SystemTime::now(),
            rng,
        )
        .now_or_never()
        .expect("synchronous")
        .expect("can process pre-key bundles")
    }

    fn has_active_session(&self, remote: &str) -> bool {
        self.0
            .load_session(&address(remote))
            .now_or_never()
            .expect("synchronous")
            .expect("can fetch sessions")
            .is_some_and(|session| session.alice_base_key().is_ok())
    }

    fn archive_active_session(&mut self, remote: &str) {
        let Some(mut session) = self
            .0
            .load_session(&address(remote))
            .now_or_never()
            .expect("synchronous")
            .expect("can fetch sessions")
        else {
            return;
        };
        session
            .archive_current_state()
            .expect("can archive session");
        self.0
            .session_store
            .store_session(&address(remote), &session)
            .now_or_never()
            .expect("synchronous")
            .expect("can store session");
    }

    fn active_session_id(&self, remote: &str) -> Option<Vec<u8>> {
        self.0
            .load_session(&address(remote))
            .now_or_never()
            .expect("synchronous")
            .expect("can fetch sessions")
            .and_then(|session| session.alice_base_key().ok().map(ToOwned::to_owned))
    }

    fn current_ratchet_key_matches(&self, remote: &str, ratchet_key: &[u8]) -> bool {
        let Ok(ratchet_key) = PublicKey::deserialize(ratchet_key) else {
            return false;
        };
        self.0
            .load_session(&address(remote))
            .now_or_never()
            .expect("synchronous")
            .expect("can fetch sessions")
            .is_some_and(|session| {
                session
                    .current_ratchet_key_matches(&ratchet_key)
                    .expect("structurally valid session")
            })
    }

    fn try_encrypt(
        &mut self,
        remote: &str,
        local: &str,
        msg: &[u8],
        rng: &mut StdRng,
    ) -> Result<(Vec<u8>, CiphertextMessageType), Box<dyn std::error::Error>> {
        let encrypted = message_encrypt(
            msg,
            &address(remote),
            &address(local),
            &mut self.0.session_store,
            &mut self.0.identity_store,
            SystemTime::now(),
            rng,
        )
        .now_or_never()
        .expect("synchronous")
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok((encrypted.serialize().to_vec(), encrypted.message_type()))
    }

    fn decrypt(
        &mut self,
        remote: &str,
        local: &str,
        msg: &[u8],
        msg_type: CiphertextMessageType,
        rng: &mut StdRng,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        match msg_type {
            CiphertextMessageType::Whisper => message_decrypt_signal(
                &SignalMessage::try_from(msg).expect("valid"),
                &address(remote),
                &address(local),
                &mut self.0.session_store,
                &mut self.0.identity_store,
                rng,
            )
            .now_or_never()
            .expect("synchronous")
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>),
            CiphertextMessageType::PreKey => message_decrypt_prekey(
                &PreKeySignalMessage::try_from(msg).expect("valid"),
                &address(remote),
                &address(local),
                &mut self.0.session_store,
                &mut self.0.identity_store,
                &mut self.0.pre_key_store,
                &self.0.signed_pre_key_store,
                &mut RecordingKyberPreKeyStore {
                    inner: &mut self.0.kyber_pre_key_store,
                    usages: &mut self.1,
                },
                rng,
            )
            .now_or_never()
            .expect("synchronous")
            .map(|r| r.plaintext)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>),
            _ => panic!("unexpected 1:1 message type"),
        }
    }

    fn encrypt_sealed_sender_v1(
        &self,
        remote: &str,
        msg: &UnidentifiedSenderMessageContent,
        rng: &mut StdRng,
    ) -> Vec<u8> {
        sealed_sender_encrypt_from_usmc(&address(remote), msg, &self.0, rng)
            .now_or_never()
            .expect("synchronous")
            .expect("can encrypt messages")
    }

    fn encrypt_sealed_sender_v2(
        &self,
        remote: &str,
        msg: &UnidentifiedSenderMessageContent,
        rng: &mut StdRng,
    ) -> Vec<u8> {
        let session = self
            .0
            .load_session(&address(remote))
            .now_or_never()
            .expect("synchronous")
            .expect("can fetch sessions")
            .expect("session established");
        sealed_sender_multi_recipient_encrypt(
            &[&address(remote)],
            &[&session],
            [],
            msg,
            &self.0,
            rng,
        )
        .now_or_never()
        .expect("synchronous")
        .expect("can encrypt messages")
    }

    fn decrypt_sealed_sender(&self, msg: &[u8]) -> UnidentifiedSenderMessageContent {
        sealed_sender_decrypt_to_usmc(msg, &self.0)
            .now_or_never()
            .expect("synchronous")
            .expect("can decrypt messages")
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng as _;

    use super::*;
    use crate::{LibSignalProtocolPreTahini, LibSignalProtocolStore};

    fn round_trip(
        alice: &mut dyn LibSignalProtocolStore,
        bob: &mut dyn LibSignalProtocolStore,
        rng: &mut StdRng,
    ) {
        let (message, kind) = alice.encrypt("bob", "alice", b"hello", rng);
        assert_eq!(
            bob.decrypt("alice", "bob", &message, kind, rng).unwrap(),
            b"hello"
        );
        let (reply, kind) = bob.encrypt("alice", "bob", b"reply", rng);
        assert_eq!(
            alice.decrypt("bob", "alice", &reply, kind, rng).unwrap(),
            b"reply"
        );
    }

    fn replace_sessions(
        alice: &mut dyn LibSignalProtocolStore,
        bob: &mut dyn LibSignalProtocolStore,
        count: usize,
        rng: &mut StdRng,
    ) {
        for _ in 0..count {
            let bundle = bob.create_pre_key_bundle(rng);
            alice.process_pre_key_bundle("bob", "alice", bundle, rng);
            round_trip(alice, bob, rng);
        }
    }

    fn check_replay_after_migration(evict_before_migration: bool) {
        let mut rng = StdRng::seed_from_u64(7);
        let mut alice = LibSignalProtocolPreTahini::new(&mut rng);
        let mut bob = LibSignalProtocolPreTahini::new(&mut rng);
        // InMemKyberPreKeyStore retains its keys, modeling last-resort use.
        // Omit the one-time EC key so replay rejection must use the marker.
        let bundle = bob
            .create_pre_key_bundle(&mut rng)
            .modify(|bundle| {
                bundle.pre_key_id = None;
                bundle.pre_key_public = None;
            })
            .unwrap();
        alice.process_pre_key_bundle("bob", "alice", bundle.clone(), &mut rng);
        let (replay, kind) = alice.encrypt("bob", "alice", b"original", &mut rng);
        assert_eq!(
            bob.decrypt("alice", "bob", &replay, kind, &mut rng)
                .unwrap(),
            b"original"
        );

        if evict_before_migration {
            // The pinned pre-Tahini version retains 40 archived sessions.
            replace_sessions(&mut alice, &mut bob, 41, &mut rng);
        }
        let mut bob = bob.reload_session_only("alice");
        let snapshot = bob.serialize_conversation_state("alice");
        let mut upgraded_alice = alice.clone();
        if !evict_before_migration {
            replace_sessions(&mut alice, &mut bob, 41, &mut rng);
        }

        let error = bob
            .decrypt("alice", "bob", &replay, kind, &mut rng)
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<libsignal_protocol_pre_tahini::SignalProtocolError>(),
            Some(libsignal_protocol_pre_tahini::SignalProtocolError::InvalidMessage(
                libsignal_protocol_pre_tahini::CiphertextMessageType::PreKey, reason
            )) if reason == "reused base key"
        ));

        let snapshot = if evict_before_migration {
            // A rejected replay must not append a duplicate usage that would
            // make subsequent restoration fail.
            bob.serialize_conversation_state("alice")
        } else {
            snapshot
        };
        let mut upgraded =
            LibSignalProtocolCurrent::from_serialized_conversation_state(&snapshot, "alice");
        if !evict_before_migration {
            // Tahini retains three archived sessions.
            replace_sessions(&mut upgraded_alice, &mut upgraded, 4, &mut rng);
        }

        let before_session = upgraded
            .0
            .load_session(&address("alice"))
            .now_or_never()
            .unwrap()
            .unwrap()
            .unwrap()
            .serialize()
            .unwrap();
        let before_identity = upgraded
            .0
            .get_identity(&address("alice"))
            .now_or_never()
            .unwrap()
            .unwrap();
        let error = upgraded
            .decrypt("alice", "bob", &replay, kind, &mut rng)
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<SignalProtocolError>(),
            Some(SignalProtocolError::InvalidMessage(CiphertextMessageType::PreKey, reason))
                if reason == "reused base key"
        ));
        assert_eq!(
            upgraded
                .0
                .load_session(&address("alice"))
                .now_or_never()
                .unwrap()
                .unwrap()
                .unwrap()
                .serialize()
                .unwrap(),
            before_session
        );
        assert_eq!(
            upgraded
                .0
                .get_identity(&address("alice"))
                .now_or_never()
                .unwrap()
                .unwrap(),
            before_identity
        );
        round_trip(&mut upgraded_alice, &mut upgraded, &mut rng);

        // Preserving a used tuple must not disable fresh initiations using the
        // same last-resort prekeys and a different initiator base key.
        upgraded_alice.process_pre_key_bundle("bob", "alice", bundle, &mut rng);
        round_trip(&mut upgraded_alice, &mut upgraded, &mut rng);
    }

    #[test]
    fn replay_rejected_after_eviction_before_migration() {
        check_replay_after_migration(true);
    }

    #[test]
    fn replay_rejected_after_eviction_after_migration() {
        check_replay_after_migration(false);
    }

    #[test]
    fn pending_prekey_messages_survive_migration_with_replay_history() {
        let mut rng = StdRng::seed_from_u64(8);
        let mut alice = LibSignalProtocolPreTahini::new(&mut rng);
        let mut bob = LibSignalProtocolPreTahini::new(&mut rng);
        let bundle = bob.create_pre_key_bundle(&mut rng);
        alice.process_pre_key_bundle("bob", "alice", bundle, &mut rng);
        // Alice has not received a reply, so every message carries the same
        // initiation header. Only the first receive writes a usage marker.
        for text in [b"first".as_slice(), b"second"] {
            let (message, kind) = alice.encrypt("bob", "alice", text, &mut rng);
            assert_eq!(kind, CiphertextMessageType::PreKey);
            assert_eq!(
                bob.decrypt("alice", "bob", &message, kind, &mut rng)
                    .unwrap(),
                text
            );
        }
        let (pending, kind) = alice.encrypt("bob", "alice", b"pending", &mut rng);
        assert_eq!(kind, CiphertextMessageType::PreKey);
        let snapshot = bob.serialize_conversation_state("alice");
        assert_eq!(snapshot.kyber_pre_key_usages.len(), 1);
        let mut upgraded =
            LibSignalProtocolCurrent::from_serialized_conversation_state(&snapshot, "alice");
        assert_eq!(
            upgraded
                .decrypt("alice", "bob", &pending, kind, &mut rng)
                .unwrap(),
            b"pending"
        );
        assert_eq!(
            upgraded.active_session_id("alice"),
            bob.active_session_id("alice")
        );
        round_trip(&mut alice, &mut upgraded, &mut rng);
    }

    #[test]
    fn migration_preserves_replay_history_across_peers_and_clones() {
        let mut rng = StdRng::seed_from_u64(9);
        let mut alice = LibSignalProtocolPreTahini::new(&mut rng);
        let mut charlie = LibSignalProtocolPreTahini::new(&mut rng);
        let mut bob = LibSignalProtocolPreTahini::new(&mut rng);
        let bundle = bob.create_pre_key_bundle(&mut rng);
        alice.process_pre_key_bundle("bob", "alice", bundle, &mut rng);
        round_trip(&mut alice, &mut bob, &mut rng);

        let bundle = bob
            .create_pre_key_bundle(&mut rng)
            .modify(|bundle| {
                bundle.pre_key_id = None;
                bundle.pre_key_public = None;
            })
            .unwrap();
        let earlier_bob = bob.clone();
        charlie.process_pre_key_bundle("bob", "charlie", bundle, &mut rng);
        let (message, kind) = charlie.encrypt("bob", "charlie", b"charlie", &mut rng);
        assert_eq!(
            bob.decrypt("charlie", "bob", &message, kind, &mut rng)
                .unwrap(),
            b"charlie"
        );

        // The exported prekeys are global even though only Alice's session is
        // exported. Charlie's usage must survive without his session record.
        let snapshot = bob.serialize_conversation_state("alice");
        assert_eq!(snapshot.kyber_pre_key_usages.len(), 2);
        let mut upgraded =
            LibSignalProtocolCurrent::from_serialized_conversation_state(&snapshot, "alice");
        let error = upgraded
            .decrypt("charlie", "bob", &message, kind, &mut rng)
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<SignalProtocolError>(),
            Some(SignalProtocolError::InvalidMessage(CiphertextMessageType::PreKey, reason))
                if reason == "reused base key"
        ));
        assert!(
            upgraded
                .0
                .load_session(&address("charlie"))
                .now_or_never()
                .unwrap()
                .unwrap()
                .is_none()
        );
        assert!(
            upgraded
                .0
                .get_identity(&address("charlie"))
                .now_or_never()
                .unwrap()
                .unwrap()
                .is_none()
        );
        round_trip(&mut alice, &mut upgraded, &mut rng);

        // A clone taken before Charlie's receive must still accept it for the
        // first time. Later writes cannot leak into a saved rollback state.
        let earlier_snapshot = earlier_bob.serialize_conversation_state("alice");
        assert_eq!(earlier_snapshot.kyber_pre_key_usages.len(), 1);
        let mut earlier_upgrade = LibSignalProtocolCurrent::from_serialized_conversation_state(
            &earlier_snapshot,
            "alice",
        );
        assert_eq!(
            earlier_upgrade
                .decrypt("charlie", "bob", &message, kind, &mut rng)
                .unwrap(),
            b"charlie"
        );
    }
}
