//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod support;

use std::time::SystemTime;

use futures_util::FutureExt;
use libsignal_protocol::*;
use libsignal_protocol_test_support::client_stores::{
    ClientBehavior, ClientIdentityStore, ClientSessionStore,
};
use rand::rngs::StdRng;
use rand::{CryptoRng, Rng, SeedableRng};
use test_case::{test_case, test_matrix};

struct Client {
    address: ProtocolAddress,
    sessions: ClientSessionStore,
    identities: ClientIdentityStore,
    // Supplies prekeys and the local identity for bundle generation. All
    // conversation operations use the client identity/session stores above.
    keys: InMemSignalProtocolStore,
}

impl Client {
    fn new(name: &str, behavior: ClientBehavior, rng: &mut (impl Rng + CryptoRng)) -> Self {
        let key_pair = IdentityKeyPair::generate(rng);
        Self::with_identity(name, DeviceId::new(1).unwrap(), key_pair, behavior)
    }

    fn with_identity(
        name: &str,
        device_id: DeviceId,
        key_pair: IdentityKeyPair,
        behavior: ClientBehavior,
    ) -> Self {
        let keys = InMemSignalProtocolStore::new(key_pair, 1).unwrap();
        let sessions = ClientSessionStore::default();
        let address = ProtocolAddress::new(name.into(), device_id);
        let identities =
            ClientIdentityStore::new(behavior, address.clone(), key_pair, 1, sessions.clone());
        Self {
            address,
            identities,
            sessions,
            keys,
        }
    }

    fn approve(&mut self, peer: &Self) {
        self.identities.approve_identity(&peer.address);
    }

    fn identity(&self) -> IdentityKey {
        *self
            .identities
            .get_identity_key_pair()
            .now_or_never()
            .unwrap()
            .unwrap()
            .identity_key()
    }

    fn stored_identity(&self, peer: &Self) -> IdentityKey {
        self.identities
            .get_identity(&peer.address)
            .now_or_never()
            .unwrap()
            .unwrap()
            .unwrap()
    }

    fn record(&self, peer: &Self) -> SessionRecord {
        self.sessions
            .load_session(&peer.address)
            .now_or_never()
            .unwrap()
            .unwrap()
            .unwrap()
    }

    /// The session's initiator base key, which identifies the session.
    fn sid(&self, peer: &Self) -> Vec<u8> {
        self.record(peer).alice_base_key().unwrap().to_vec()
    }

    fn bundle(&mut self, rng: &mut (impl Rng + CryptoRng)) -> PreKeyBundle {
        support::create_pre_key_bundle(&mut self.keys, rng)
            .now_or_never()
            .unwrap()
            .unwrap()
    }

    fn initiate(&mut self, peer: &mut Self, rng: &mut (impl Rng + CryptoRng)) {
        let bundle = peer.bundle(rng);
        self.initiate_with_bundle(peer, &bundle, rng);
    }

    fn initiate_with_bundle(
        &mut self,
        peer: &Self,
        bundle: &PreKeyBundle,
        rng: &mut (impl Rng + CryptoRng),
    ) {
        process_prekey_bundle(
            &peer.address,
            &self.address,
            &mut self.sessions,
            &mut self.identities,
            bundle,
            SystemTime::UNIX_EPOCH,
            rng,
        )
        .now_or_never()
        .unwrap()
        .unwrap();
    }

    fn send(
        &mut self,
        peer: &Self,
        text: &[u8],
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<CiphertextMessage, SignalProtocolError> {
        message_encrypt(
            text,
            &peer.address,
            &self.address,
            &mut self.sessions,
            &mut self.identities,
            SystemTime::UNIX_EPOCH,
            rng,
        )
        .now_or_never()
        .unwrap()
    }

    fn receive(
        &mut self,
        peer: &Self,
        message: &CiphertextMessage,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<Vec<u8>, SignalProtocolError> {
        message_decrypt(
            message,
            &peer.address,
            &self.address,
            &mut self.sessions,
            &mut self.identities,
            &mut self.keys.pre_key_store,
            &self.keys.signed_pre_key_store,
            &mut self.keys.kyber_pre_key_store,
            rng,
        )
        .now_or_never()
        .unwrap()
    }

    fn assert_exchange(&mut self, peer: &mut Self, rng: &mut (impl Rng + CryptoRng)) {
        let message = self.send(peer, b"hello", rng).unwrap();
        assert_eq!(peer.receive(self, &message, rng).unwrap(), b"hello");
        let reply = peer.send(self, b"reply", rng).unwrap();
        assert_eq!(self.receive(peer, &reply, rng).unwrap(), b"reply");
        assert_eq!(self.sid(peer), peer.sid(self));
    }
}

#[test_matrix([ClientBehavior::Android, ClientBehavior::Ios, ClientBehavior::Desktop])]
fn fresh_identity_change_supersedes_unacknowledged_session(behavior: ClientBehavior) {
    let mut saw_lower_sid = false;
    let mut saw_higher_sid = false;
    for seed in 0..8 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut old_alice = Client::new("alice", behavior, &mut rng);
        let mut bob = Client::new("bob", behavior, &mut rng);
        bob.initiate(&mut old_alice, &mut rng);
        let old_sid = bob.sid(&old_alice);
        assert_eq!(
            bob.send(&old_alice, b"unacknowledged", &mut rng)
                .unwrap()
                .message_type(),
            CiphertextMessageType::PreKey
        );

        let mut alice = Client::new("alice", behavior, &mut rng);
        alice.initiate(&mut bob, &mut rng);
        let new_sid = alice.sid(&bob);
        saw_lower_sid |= new_sid < old_sid;
        saw_higher_sid |= new_sid > old_sid;
        let message = alice.send(&bob, b"new identity", &mut rng).unwrap();
        assert_eq!(
            bob.receive(&alice, &message, &mut rng).unwrap(),
            b"new identity"
        );
        assert_eq!(
            bob.sid(&alice),
            new_sid,
            "identity change must win even with a lower SID (seed {seed})"
        );
        assert_eq!(bob.stored_identity(&alice), alice.identity());
        bob.approve(&alice);
        bob.assert_exchange(&mut alice, &mut rng);
    }
    assert!(
        saw_lower_sid && saw_higher_sid,
        "exercise both SID orderings"
    );
}

#[test_matrix([ClientBehavior::Android, ClientBehavior::Ios, ClientBehavior::Desktop])]
fn new_identity_still_requires_sending_approval(behavior: ClientBehavior) {
    let mut rng = StdRng::seed_from_u64(0);
    let mut old_alice = Client::new("alice", behavior, &mut rng);
    let mut bob = Client::new("bob", behavior, &mut rng);
    old_alice.initiate(&mut bob, &mut rng);
    old_alice.assert_exchange(&mut bob, &mut rng);
    let mut alice = Client::new("alice", behavior, &mut rng);
    alice.initiate(&mut bob, &mut rng);
    let message = alice.send(&bob, b"new identity", &mut rng).unwrap();
    bob.receive(&alice, &message, &mut rng).unwrap();
    assert_eq!(bob.sid(&alice), alice.sid(&bob));
    let before = bob.record(&alice).serialize().unwrap();
    assert!(matches!(
        bob.send(&alice, b"blocked", &mut rng),
        Err(SignalProtocolError::UntrustedIdentity(_))
    ));
    assert_eq!(bob.record(&alice).serialize().unwrap(), before);
    bob.approve(&alice);
    bob.assert_exchange(&mut alice, &mut rng);
}

#[test_matrix([ClientBehavior::Android, ClientBehavior::Ios, ClientBehavior::Desktop])]
fn unauthenticated_identity_change_does_not_mutate_stores(behavior: ClientBehavior) {
    let mut rng = StdRng::seed_from_u64(0);
    let mut old_alice = Client::new("alice", behavior, &mut rng);
    let mut bob = Client::new("bob", behavior, &mut rng);
    bob.initiate(&mut old_alice, &mut rng);
    let before = bob.record(&old_alice).serialize().unwrap();
    let save_calls = bob.identities.save_calls();
    let mut alice = Client::new("alice", behavior, &mut rng);
    alice.initiate(&mut bob, &mut rng);
    let message = alice.send(&bob, b"new identity", &mut rng).unwrap();
    let mut bytes = message.serialize().to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    let corrupt = CiphertextMessage::PreKeySignalMessage(
        PreKeySignalMessage::try_from(bytes.as_slice()).unwrap(),
    );
    assert!(bob.receive(&alice, &corrupt, &mut rng).is_err());
    assert_eq!(bob.record(&old_alice).serialize().unwrap(), before);
    assert_eq!(bob.stored_identity(&old_alice), old_alice.identity());
    assert_eq!(bob.identities.save_calls(), save_calls);
    // The failure did not consume the prekeys or the replay marker.
    assert_eq!(
        bob.receive(&alice, &message, &mut rng).unwrap(),
        b"new identity"
    );
}

#[test_case(false; "ordinary message")]
#[test_case(true; "prekey message")]
fn archived_receives_still_check_trust(prekey: bool) {
    let behavior = ClientBehavior::Android;
    let mut rng = StdRng::seed_from_u64(0);
    let mut alice = Client::new("alice", behavior, &mut rng);
    let mut bob = Client::new("bob", behavior, &mut rng);
    alice.initiate(&mut bob, &mut rng);
    let first = alice.send(&bob, b"first", &mut rng).unwrap();
    bob.receive(&alice, &first, &mut rng).unwrap();
    if !prekey {
        alice.assert_exchange(&mut bob, &mut rng);
    }
    let delayed = alice.send(&bob, b"delayed", &mut rng).unwrap();
    let mut record = bob.record(&alice);
    record.archive_current_state().unwrap();
    bob.sessions
        .store_session(&alice.address, &record)
        .now_or_never()
        .unwrap()
        .unwrap();
    let before = record.serialize().unwrap();
    // InMemIdentityKeyStore rejects a different key even on receiving.
    bob.keys
        .identity_store
        .save_identity(
            &alice.address,
            IdentityKeyPair::generate(&mut rng).identity_key(),
        )
        .now_or_never()
        .unwrap()
        .unwrap();
    let result = message_decrypt(
        &delayed,
        &alice.address,
        &bob.address,
        &mut bob.sessions,
        &mut bob.keys.identity_store,
        &mut bob.keys.pre_key_store,
        &bob.keys.signed_pre_key_store,
        &mut bob.keys.kyber_pre_key_store,
        &mut rng,
    )
    .now_or_never()
    .unwrap();
    assert!(matches!(
        result,
        Err(SignalProtocolError::UntrustedIdentity(_))
    ));
    assert_eq!(bob.record(&alice).serialize().unwrap(), before);
    assert_eq!(bob.receive(&alice, &delayed, &mut rng).unwrap(), b"delayed");
}

#[test_matrix([ClientBehavior::Android, ClientBehavior::Ios, ClientBehavior::Desktop])]
fn client_trust_policies_share_identity_and_approval_across_devices(behavior: ClientBehavior) {
    let mut rng = StdRng::seed_from_u64(0);
    let alice = Client::new("alice", behavior, &mut rng);
    let mut bob = Client::new("bob", behavior, &mut rng);
    let sibling = ProtocolAddress::new("alice".into(), DeviceId::new(2).unwrap());
    let key = alice.identity();
    bob.identities
        .save_identity(&alice.address, &key)
        .now_or_never()
        .unwrap()
        .unwrap();
    let changed_key = *IdentityKeyPair::generate(&mut rng).identity_key();
    assert!(
        bob.identities
            .is_trusted_identity(&sibling, &changed_key, Direction::Receiving)
            .now_or_never()
            .unwrap()
            .unwrap()
    );
    let sending = bob
        .identities
        .is_trusted_identity(&sibling, &changed_key, Direction::Sending)
        .now_or_never()
        .unwrap();
    match behavior {
        ClientBehavior::Ios => assert!(matches!(
            sending,
            Err(SignalProtocolError::ApplicationCallbackError(_, _))
        )),
        ClientBehavior::Android | ClientBehavior::Desktop => assert!(!sending.unwrap()),
    }
    bob.identities
        .save_identity(&sibling, &changed_key)
        .now_or_never()
        .unwrap()
        .unwrap();
    assert!(
        !bob.identities
            .is_trusted_identity(&alice.address, &changed_key, Direction::Sending)
            .now_or_never()
            .unwrap()
            .unwrap()
    );
    bob.identities.approve_identity(&sibling);
    assert!(
        bob.identities
            .is_trusted_identity(&alice.address, &changed_key, Direction::Sending)
            .now_or_never()
            .unwrap()
            .unwrap()
    );
}
