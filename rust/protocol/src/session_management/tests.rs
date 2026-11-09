//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures_util::FutureExt as _;
use rand::SeedableRng as _;
use rand::rngs::StdRng;
use test_case::test_case;

use super::*;
use crate::state::GenericSignedPreKey as _;
use crate::tahini::{LastAct, MAX_DIR_CHANGES};
use crate::{
    DeviceId, IdentityKeyPair, InMemSignalProtocolStore, KeyPair, KyberPreKeyRecord,
    SignedPreKeyRecord, Timestamp, kem,
};

struct Peer {
    address: ProtocolAddress,
    store: InMemSignalProtocolStore,
    bundle: PreKeyBundle,
}

impl Peer {
    async fn new(name: &str, rng: &mut StdRng) -> Self {
        let identity = IdentityKeyPair::generate(rng);
        let signed_key = KeyPair::generate(rng);
        let kyber_key = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
        let signed_signature = identity
            .private_key()
            .calculate_signature(&signed_key.public_key.serialize(), rng)
            .unwrap();
        let kyber_signature = identity
            .private_key()
            .calculate_signature(&kyber_key.public_key.serialize(), rng)
            .unwrap();
        let mut store = InMemSignalProtocolStore::new(identity, 1).unwrap();
        store
            .save_signed_pre_key(
                1.into(),
                &SignedPreKeyRecord::new(
                    1.into(),
                    Timestamp::from_epoch_millis(0),
                    &signed_key,
                    &signed_signature,
                ),
            )
            .await
            .unwrap();
        store
            .save_kyber_pre_key(
                1.into(),
                &KyberPreKeyRecord::new(
                    1.into(),
                    Timestamp::from_epoch_millis(0),
                    &kyber_key,
                    &kyber_signature,
                ),
            )
            .await
            .unwrap();
        // Retained last-resort keys, without a one-time EC key: a spent
        // initiation reaches the replay gate even after its session is gone.
        let bundle = PreKeyBundle::new(
            1,
            DeviceId::new(1).unwrap(),
            None,
            1.into(),
            signed_key.public_key,
            signed_signature.to_vec(),
            1.into(),
            kyber_key.public_key,
            kyber_signature.to_vec(),
            *identity.identity_key(),
        )
        .unwrap();
        Self {
            address: ProtocolAddress::new(name.into(), DeviceId::new(1).unwrap()),
            store,
            bundle,
        }
    }

    async fn initiate(&mut self, peer: &Self, rng: &mut StdRng) {
        initiate_session(
            &peer.address,
            &self.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &peer.bundle,
            SystemTime::UNIX_EPOCH,
            rng,
        )
        .await
        .unwrap();
    }

    async fn send(&mut self, peer: &Self, rng: &mut StdRng) -> CiphertextMessage {
        message_encrypt(
            b"hello",
            &peer.address,
            &self.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            SystemTime::UNIX_EPOCH,
            rng,
        )
        .await
        .unwrap()
    }

    async fn receive(
        &mut self,
        peer: &Self,
        message: &CiphertextMessage,
        rng: &mut StdRng,
    ) -> Result<Vec<u8>> {
        message_decrypt(
            message,
            &peer.address,
            &self.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
            rng,
        )
        .await
    }

    async fn record(&self, peer: &Self) -> SessionRecord {
        self.store
            .load_session(&peer.address)
            .await
            .unwrap()
            .unwrap()
    }

    async fn set_history(&mut self, peer: &Self, last_act: LastAct, counter: u32) {
        let mut record = self.record(peer).await;
        record.set_last_act(last_act);
        record.reset_direction_change_ctr();
        for _ in 0..counter {
            record.increment_direction_change_ctr();
        }
        self.store
            .store_session(&peer.address, &record)
            .await
            .unwrap();
    }
}

/// Both peers initiate and send before receiving. Return the higher-SID peer
/// as receiver, so the incoming message must lose the same-identity tiebreaker.
async fn crossed_initiations() -> (Peer, Peer, CiphertextMessage, StdRng) {
    let mut rng = StdRng::seed_from_u64(5);
    let mut alice = Peer::new("alice", &mut rng).await;
    let mut bob = Peer::new("bob", &mut rng).await;
    alice.initiate(&bob, &mut rng).await;
    bob.initiate(&alice, &mut rng).await;
    let alice_message = alice.send(&bob, &mut rng).await;
    let bob_message = bob.send(&alice, &mut rng).await;
    let alice_sid = alice.record(&bob).await.alice_base_key().unwrap().to_vec();
    let bob_sid = bob.record(&alice).await.alice_base_key().unwrap().to_vec();
    assert_ne!(alice_sid, bob_sid);
    if alice_sid > bob_sid {
        (alice, bob, bob_message, rng)
    } else {
        (bob, alice, alice_message, rng)
    }
}

#[test_case(LastAct::Send, 0, 1, false; "first direction change")]
#[test_case(LastAct::Send, MAX_DIR_CHANGES - 1, MAX_DIR_CHANGES, false; "reaches threshold")]
#[test_case(LastAct::Send, MAX_DIR_CHANGES, 0, true; "crosses threshold")]
#[test_case(LastAct::ReceiveInactive, MAX_DIR_CHANGES, MAX_DIR_CHANGES, false; "consecutive inactive receive")]
#[test_case(LastAct::ReceiveActive, 3, 3, false; "receive after active receive")]
#[test_case(LastAct::Unset, 0, 0, false; "no preceding send")]
fn fresh_losing_initiation_records_receive(
    last_act: LastAct,
    counter: u32,
    expected_counter: u32,
    breaks_deadlock: bool,
) {
    async {
        let (mut receiver, mut sender, message, mut rng) = crossed_initiations().await;
        receiver.set_history(&sender, last_act, counter).await;
        let active_sid = receiver
            .record(&sender)
            .await
            .alice_base_key()
            .unwrap()
            .to_vec();
        let incoming_sid = sender
            .record(&receiver)
            .await
            .alice_base_key()
            .unwrap()
            .to_vec();
        assert!(incoming_sid < active_sid);
        assert_eq!(
            receiver.receive(&sender, &message, &mut rng).await.unwrap(),
            b"hello"
        );

        let record = receiver.record(&sender).await;
        assert_eq!(record.last_act(), LastAct::ReceiveInactive);
        assert_eq!(record.direction_change_ctr(), expected_counter);
        assert_eq!(record.active_session().is_none(), breaks_deadlock);
        assert!(
            record
                .archived_sessions()
                .any(|state| state.unwrap().session_id() == incoming_sid)
        );
        if breaks_deadlock {
            assert_eq!(record.archived_session_count(), 2);
            assert!(
                record
                    .archived_sessions()
                    .any(|state| state.unwrap().session_id() == active_sid)
            );
            // Another message on the losing session decrypts without promotion.
            let next = sender.send(&receiver, &mut rng).await;
            assert_eq!(
                receiver.receive(&sender, &next, &mut rng).await.unwrap(),
                b"hello"
            );
            assert!(receiver.record(&sender).await.active_session().is_none());
        } else {
            assert_eq!(record.alice_base_key().unwrap(), active_sid);
        }

        if last_act == LastAct::Send && counter == 0 {
            // The following send counts the reverse direction change. Under
            // normal delivery both sides then converge on the larger SID.
            let reply = receiver.send(&sender, &mut rng).await;
            assert_eq!(receiver.record(&sender).await.direction_change_ctr(), 2);
            assert_eq!(
                sender.receive(&receiver, &reply, &mut rng).await.unwrap(),
                b"hello"
            );
            assert_eq!(
                sender.record(&receiver).await.alice_base_key().unwrap(),
                active_sid
            );
            let reply = sender.send(&receiver, &mut rng).await;
            assert_eq!(
                receiver.receive(&sender, &reply, &mut rng).await.unwrap(),
                b"hello"
            );
        }
    }
    .now_or_never()
    .unwrap();
}

#[test_case(false; "authentication failure")]
#[test_case(true; "replay rejection")]
fn rejected_losing_initiation_preserves_receive_history(replay: bool) {
    async {
        let (mut receiver, sender, message, mut rng) = crossed_initiations().await;
        receiver
            .set_history(&sender, LastAct::Send, MAX_DIR_CHANGES)
            .await;
        let before = receiver.record(&sender).await.serialize().unwrap();
        let identity_before = receiver.store.get_identity(&sender.address).await.unwrap();
        let rejected = if replay {
            let CiphertextMessage::PreKeySignalMessage(prekey) = &message else {
                panic!("prekey")
            };
            // Seed the persistent marker for an earlier acceptance whose
            // session is no longer held. The candidate can still authenticate.
            receiver
                .store
                .mark_kyber_pre_key_used(
                    prekey.kyber_pre_key_id().unwrap(),
                    prekey.signed_pre_key_id(),
                    prekey.base_key(),
                )
                .await
                .unwrap();
            message.clone()
        } else {
            let mut bytes = message.serialize().to_vec();
            *bytes.last_mut().unwrap() ^= 1;
            CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(bytes.as_slice()).unwrap(),
            )
        };
        let error = receiver
            .receive(&sender, &rejected, &mut rng)
            .await
            .unwrap_err();
        assert!(matches!(error,
            SignalProtocolError::InvalidMessage(CiphertextMessageType::PreKey, reason)
                if reason == if replay { "reused base key" } else { "decryption failed" }
        ));
        assert_eq!(receiver.record(&sender).await.serialize().unwrap(), before);
        assert_eq!(
            receiver.store.get_identity(&sender.address).await.unwrap(),
            identity_before
        );
        if !replay {
            // Authentication failure consumed neither keys nor a replay marker.
            assert_eq!(
                receiver.receive(&sender, &message, &mut rng).await.unwrap(),
                b"hello"
            );
            assert!(receiver.record(&sender).await.active_session().is_none());
        }
    }
    .now_or_never()
    .unwrap();
}
