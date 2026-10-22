//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use futures_util::FutureExt;
use libsignal_protocol_cross_version_testing::{
    LibSignalProtocolPreTahini, LibSignalProtocolStore, LibSignalProtocolV74,
    SerializedConversationState,
};
use libsignal_protocol_current::*;
use libsignal_protocol_test_support::client_stores::{
    ClientBehavior, ClientIdentityStore, ClientSessionStore,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

struct Receiver {
    sessions: ClientSessionStore,
    identities: ClientIdentityStore,
    keys: InMemSignalProtocolStore,
    local: ProtocolAddress,
    remote: ProtocolAddress,
}

impl Receiver {
    fn new(behavior: ClientBehavior, snapshot: SerializedConversationState) -> Self {
        let local = ProtocolAddress::new("bob".into(), DeviceId::new(1).unwrap());
        let remote = ProtocolAddress::new("alice".into(), DeviceId::new(1).unwrap());
        let key_pair = IdentityKeyPair::try_from(snapshot.identity_key_pair.as_slice()).unwrap();
        let mut keys = InMemSignalProtocolStore::new(key_pair, snapshot.registration_id).unwrap();
        // The snapshot supplies only freshly generated, unused bundle keys.
        // This test does not migrate established sessions or replay markers.
        assert!(snapshot.kyber_pre_key_usages.is_empty());
        for (id, bytes) in snapshot.pre_keys {
            keys.save_pre_key(id.into(), &PreKeyRecord::deserialize(&bytes).unwrap())
                .now_or_never()
                .unwrap()
                .unwrap();
        }
        for (id, bytes) in snapshot.signed_pre_keys {
            keys.save_signed_pre_key(id.into(), &SignedPreKeyRecord::deserialize(&bytes).unwrap())
                .now_or_never()
                .unwrap()
                .unwrap();
        }
        for (id, bytes) in snapshot.kyber_pre_keys {
            keys.save_kyber_pre_key(id.into(), &KyberPreKeyRecord::deserialize(&bytes).unwrap())
                .now_or_never()
                .unwrap()
                .unwrap();
        }
        let sessions = ClientSessionStore::default();
        let identities = ClientIdentityStore::new(
            behavior,
            local.clone(),
            key_pair,
            snapshot.registration_id,
            sessions.clone(),
        );
        Self {
            sessions,
            identities,
            keys,
            local,
            remote,
        }
    }

    fn sid(&self) -> Vec<u8> {
        self.sessions
            .load_session(&self.remote)
            .now_or_never()
            .unwrap()
            .unwrap()
            .unwrap()
            .alice_base_key()
            .unwrap()
            .to_vec()
    }

    fn send(&mut self, rng: &mut StdRng) -> CiphertextMessage {
        message_encrypt(
            b"bob",
            &self.remote,
            &self.local,
            &mut self.sessions,
            &mut self.identities,
            SystemTime::now(),
            rng,
        )
        .now_or_never()
        .unwrap()
        .unwrap()
    }

    fn receive(&mut self, bytes: &[u8], kind: CiphertextMessageType, rng: &mut StdRng) -> Vec<u8> {
        let ciphertext = match kind {
            CiphertextMessageType::PreKey => CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(bytes).unwrap(),
            ),
            CiphertextMessageType::Whisper => {
                CiphertextMessage::SignalMessage(SignalMessage::try_from(bytes).unwrap())
            }
            _ => panic!("expected a session message"),
        };
        message_decrypt(
            &ciphertext,
            &self.remote,
            &self.local,
            &mut self.sessions,
            &mut self.identities,
            &mut self.keys.pre_key_store,
            &self.keys.signed_pre_key_store,
            &mut self.keys.kyber_pre_key_store,
            rng,
        )
        .now_or_never()
        .unwrap()
        .unwrap()
    }
}

#[test]
fn old_senders_interoperate_with_client_identity_change_policies() {
    let versions: [fn(&mut StdRng) -> Box<dyn LibSignalProtocolStore>; 2] = [
        |rng| Box::new(LibSignalProtocolV74::new(rng)),
        |rng| Box::new(LibSignalProtocolPreTahini::new(rng)),
    ];
    for make_sender in versions {
        for behavior in [
            ClientBehavior::Android,
            ClientBehavior::Ios,
            ClientBehavior::Desktop,
        ] {
            let mut saw_lower_sid = false;
            let mut saw_higher_sid = false;
            for seed in 0..8 {
                let mut rng = StdRng::seed_from_u64(seed);
                let mut old_alice = make_sender(&mut rng);
                let mut key_source = LibSignalProtocolPreTahini::new(&mut rng);
                let bob_bundle = key_source.create_pre_key_bundle(&mut rng);
                let mut bob =
                    Receiver::new(behavior, key_source.serialize_conversation_state("alice"));
                let alice_bundle = old_alice.create_pre_key_bundle(&mut rng);
                process_prekey_bundle(
                    &bob.remote,
                    &bob.local,
                    &mut bob.sessions,
                    &mut bob.identities,
                    &alice_bundle,
                    SystemTime::now(),
                    &mut rng,
                )
                .now_or_never()
                .unwrap()
                .unwrap();
                let old_sid = bob.sid();
                let initial = bob.send(&mut rng);
                assert_eq!(
                    old_alice
                        .decrypt(
                            "bob",
                            "alice",
                            initial.serialize(),
                            initial.message_type(),
                            &mut rng
                        )
                        .unwrap(),
                    b"bob"
                );
                // Keep the reply in flight: Bob's K0 session remains unacknowledged.
                let (delayed, delayed_kind) =
                    old_alice.encrypt("bob", "alice", b"old identity", &mut rng);
                assert_eq!(delayed_kind, CiphertextMessageType::Whisper);

                let mut alice = make_sender(&mut rng);
                alice.process_pre_key_bundle("bob", "alice", bob_bundle, &mut rng);
                let (initiation, kind) = alice.encrypt("bob", "alice", b"new identity", &mut rng);
                assert_eq!(kind, CiphertextMessageType::PreKey);
                let parsed = PreKeySignalMessage::try_from(initiation.as_slice()).unwrap();
                let new_sid = parsed.base_key().serialize().to_vec();
                let identity = *parsed.identity_key();
                saw_lower_sid |= new_sid < old_sid;
                saw_higher_sid |= new_sid > old_sid;
                assert_eq!(bob.receive(&initiation, kind, &mut rng), b"new identity");
                assert_eq!(
                    bob.sid(),
                    new_sid,
                    "{:?}, {}, seed {seed}",
                    behavior,
                    alice.version()
                );
                bob.identities.approve_identity(&bob.remote);

                let save_calls = bob.identities.save_calls();
                assert_eq!(
                    bob.receive(&delayed, delayed_kind, &mut rng),
                    b"old identity"
                );
                assert_eq!(bob.identities.save_calls(), save_calls);
                assert_eq!(
                    bob.identities
                        .get_identity(&bob.remote)
                        .now_or_never()
                        .unwrap()
                        .unwrap(),
                    Some(identity)
                );
                assert_eq!(bob.sid(), new_sid);
                let reply = bob.send(&mut rng);
                assert_eq!(
                    alice
                        .decrypt(
                            "bob",
                            "alice",
                            reply.serialize(),
                            reply.message_type(),
                            &mut rng
                        )
                        .unwrap(),
                    b"bob"
                );
                assert_eq!(alice.active_session_id("bob").unwrap(), bob.sid());
            }
            assert!(
                saw_lower_sid && saw_higher_sid,
                "exercise both SID orders for {behavior:?}"
            );
        }
    }
}
