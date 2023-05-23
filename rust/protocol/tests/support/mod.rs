//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Different parts of this module are used in different tests/benchmarks, therefore some of the
// APIs will always be considered dead code.
#![allow(dead_code)]

use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};

use std::ops::RangeFrom;

// Deliberately not reusing the constants from `protocol`.
pub(crate) const PRE_KYBER_MESSAGE_VERSION: u32 = 3;
pub(crate) const KYBER_AWARE_MESSAGE_VERSION: u32 = 4;

pub fn test_in_memory_protocol_store() -> Result<InMemSignalProtocolStore, SignalProtocolError> {
    let mut csprng = OsRng;
    let identity_key = IdentityKeyPair::generate(&mut csprng);
    // Valid registration IDs fit in 14 bits.
    let registration_id: u8 = csprng.gen();

    InMemSignalProtocolStore::new(identity_key, registration_id as u32)
}

pub async fn encrypt(
    store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &str,
) -> Result<CiphertextMessage, SignalProtocolError> {
    message_encrypt(
        msg.as_bytes(),
        remote_address,
        &mut store.session_store,
        &mut store.identity_store,
        None,
    )
    .await
}

pub async fn decrypt(
    store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &CiphertextMessage,
) -> Result<Vec<u8>, SignalProtocolError> {
    let mut csprng = OsRng;
    message_decrypt(
        msg,
        remote_address,
        &mut store.session_store,
        &mut store.identity_store,
        &mut store.pre_key_store,
        &mut store.signed_pre_key_store,
        &mut store.kyber_pre_key_store,
        &mut csprng,
        None,
    )
    .await
}

pub async fn create_pre_key_bundle<R: Rng + CryptoRng>(
    store: &mut dyn ProtocolStore,
    mut csprng: &mut R,
) -> Result<PreKeyBundle, SignalProtocolError> {
    let pre_key_pair = KeyPair::generate(&mut csprng);
    let signed_pre_key_pair = KeyPair::generate(&mut csprng);

    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
    let signed_pre_key_signature = store
        .get_identity_key_pair(None)
        .await?
        .private_key()
        .calculate_signature(&signed_pre_key_public, &mut csprng)?;

    let device_id: u32 = csprng.gen();
    let pre_key_id: u32 = csprng.gen();
    let signed_pre_key_id: u32 = csprng.gen();

    let pre_key_bundle = PreKeyBundle::new(
        store.get_local_registration_id(None).await?,
        device_id.into(),
        Some((pre_key_id.into(), pre_key_pair.public_key)),
        signed_pre_key_id.into(),
        signed_pre_key_pair.public_key,
        signed_pre_key_signature.to_vec(),
        *store.get_identity_key_pair(None).await?.identity_key(),
    )?;

    store
        .save_pre_key(
            pre_key_id.into(),
            &PreKeyRecord::new(pre_key_id.into(), &pre_key_pair),
            None,
        )
        .await?;

    let timestamp = csprng.gen();

    store
        .save_signed_pre_key(
            signed_pre_key_id.into(),
            &SignedPreKeyRecord::new(
                signed_pre_key_id.into(),
                timestamp,
                &signed_pre_key_pair,
                &signed_pre_key_signature,
            ),
            None,
        )
        .await?;

    Ok(pre_key_bundle)
}

pub fn initialize_sessions_v3() -> Result<(SessionRecord, SessionRecord), SignalProtocolError> {
    let mut csprng = OsRng;
    let alice_identity = IdentityKeyPair::generate(&mut csprng);
    let bob_identity = IdentityKeyPair::generate(&mut csprng);

    let alice_base_key = KeyPair::generate(&mut csprng);

    let bob_base_key = KeyPair::generate(&mut csprng);
    let bob_ephemeral_key = bob_base_key;

    let alice_params = AliceSignalProtocolParameters::new(
        alice_identity,
        alice_base_key,
        *bob_identity.identity_key(),
        bob_base_key.public_key,
        bob_ephemeral_key.public_key,
    );

    let alice_session = initialize_alice_session_record(&alice_params, &mut csprng)?;

    let bob_params = BobSignalProtocolParameters::new(
        bob_identity,
        bob_base_key,
        None,
        bob_ephemeral_key,
        None,
        *alice_identity.identity_key(),
        alice_base_key.public_key,
        None,
    );

    let bob_session = initialize_bob_session_record(&bob_params)?;

    Ok((alice_session, bob_session))
}

pub fn initialize_sessions_v4() -> Result<(SessionRecord, SessionRecord), SignalProtocolError> {
    let mut csprng = OsRng;
    let alice_identity = IdentityKeyPair::generate(&mut csprng);
    let bob_identity = IdentityKeyPair::generate(&mut csprng);

    let alice_base_key = KeyPair::generate(&mut csprng);

    let bob_base_key = KeyPair::generate(&mut csprng);
    let bob_ephemeral_key = bob_base_key;

    let bob_kyber_key = kem::KeyPair::generate(kem::KeyType::Kyber1024);

    let alice_params = AliceSignalProtocolParameters::new(
        alice_identity,
        alice_base_key,
        *bob_identity.identity_key(),
        bob_base_key.public_key,
        bob_ephemeral_key.public_key,
    )
    .with_their_kyber_pre_key(&bob_kyber_key.public_key);

    let alice_session = initialize_alice_session_record(&alice_params, &mut csprng)?;
    let kyber_ciphertext = {
        let bytes = alice_session
            .get_kyber_ciphertext()?
            .expect("has kyber ciphertext")
            .clone();
        bytes.into_boxed_slice()
    };

    let bob_params = BobSignalProtocolParameters::new(
        bob_identity,
        bob_base_key,
        None,
        bob_ephemeral_key,
        Some(bob_kyber_key),
        *alice_identity.identity_key(),
        alice_base_key.public_key,
        Some(&kyber_ciphertext),
    );

    let bob_session = initialize_bob_session_record(&bob_params)?;

    Ok((alice_session, bob_session))
}

pub enum IdChoice {
    Exactly(u32),
    Next,
    Random,
}

impl From<u32> for IdChoice {
    fn from(id: u32) -> Self {
        IdChoice::Exactly(id)
    }
}

pub struct TestStoreBuilder {
    rng: OsRng,
    pub(crate) store: InMemSignalProtocolStore,
    id_range: RangeFrom<u32>,
}

impl TestStoreBuilder {
    pub fn new() -> Self {
        let mut rng = OsRng;
        let identity_key = IdentityKeyPair::generate(&mut rng);
        // Valid registration IDs fit in 14 bits.
        let registration_id: u8 = rng.gen();

        let store = InMemSignalProtocolStore::new(identity_key, registration_id as u32)
            .expect("can create store");
        Self {
            rng,
            store,
            id_range: 0..,
        }
    }

    pub fn from_store(store: &InMemSignalProtocolStore) -> Self {
        Self {
            rng: OsRng,
            store: store.clone(),
            id_range: 0..,
        }
    }

    pub fn with_pre_key(mut self, id_choice: IdChoice) -> Self {
        self.add_pre_key(id_choice);
        self
    }

    pub fn add_pre_key(&mut self, id_choice: IdChoice) {
        let id = self.gen_id(id_choice);
        // TODO: this requirement can be removed if store returns ids in the insertion order
        if let Some(latest_id) = self.store.all_pre_key_ids().last() {
            assert!(id > (*latest_id).into(), "Pre key ids should be increasing");
        }
        let pair = KeyPair::generate(&mut self.rng);
        self.store
            .save_pre_key(id.into(), &PreKeyRecord::new(id.into(), &pair), None)
            .now_or_never()
            .expect("sync")
            .expect("able to store pre key");
    }

    pub fn with_signed_pre_key(mut self, id_choice: IdChoice) -> Self {
        self.add_signed_pre_key(id_choice);
        self
    }

    pub fn add_signed_pre_key(&mut self, id_choice: IdChoice) {
        let id = self.gen_id(id_choice);
        if let Some(latest_id) = self.store.all_signed_pre_key_ids().last() {
            assert!(
                id > (*latest_id).into(),
                "Signed pre key ids should be increasing"
            );
        }
        let pair = KeyPair::generate(&mut self.rng);
        let public = pair.public_key.serialize();
        let signature = self.sign(&public);
        let record = SignedPreKeyRecord::new(id.into(), 42, &pair, &signature);
        self.store
            .save_signed_pre_key(id.into(), &record, None)
            .now_or_never()
            .expect("sync")
            .expect("able to store signed pre key");
    }

    pub fn with_kyber_pre_key(mut self, id_choice: IdChoice) -> Self {
        self.add_kyber_pre_key(id_choice);
        self
    }

    pub fn add_kyber_pre_key(&mut self, id_choice: IdChoice) {
        let id = self.gen_id(id_choice);
        if let Some(latest_id) = self.store.all_kyber_pre_key_ids().last() {
            assert!(
                id > (*latest_id).into(),
                "Signed pre key ids should be increasing"
            );
        }
        let pair = kem::KeyPair::generate(kem::KeyType::Kyber1024);
        let public = pair.public_key.serialize();
        let signature = self.sign(&public);
        let record = KyberPreKeyRecord::new(id.into(), 43, &pair, &signature);
        self.store
            .save_kyber_pre_key(id.into(), &record, None)
            .now_or_never()
            .expect("sync")
            .expect("able toe store kyber pre key");
    }

    pub fn make_bundle_with_latest_keys(&self, device_id: DeviceId) -> PreKeyBundle {
        let registration_id = self
            .store
            .get_local_registration_id(None)
            .now_or_never()
            .expect("sync")
            .expect("contains local registration id");
        let maybe_pre_key_record = self.store.all_pre_key_ids().max().map(|id| {
            self.store
                .pre_key_store
                .get_pre_key(*id, None)
                .now_or_never()
                .expect("syng")
                .expect("has pre key")
        });
        let identity_key_pair = self
            .store
            .get_identity_key_pair(None)
            .now_or_never()
            .expect("sync")
            .expect("has identity key pair");
        let identity_key = identity_key_pair.identity_key();
        let signed_pre_key_record = self
            .store
            .all_signed_pre_key_ids()
            .max()
            .map(|id| {
                self.store
                    .get_signed_pre_key(*id, None)
                    .now_or_never()
                    .expect("sync")
                    .expect("has signed pre key")
            })
            .expect("contains at least one signed pre key");
        let maybe_kyber_pre_key_record = self.store.all_kyber_pre_key_ids().max().map(|id| {
            self.store
                .get_kyber_pre_key(*id, None)
                .now_or_never()
                .expect("sync")
                .expect("has kyber pre key")
        });
        let mut bundle = PreKeyBundle::new(
            registration_id,
            device_id,
            maybe_pre_key_record.map(|rec| {
                (
                    rec.id().expect("has id"),
                    rec.public_key().expect("has public key"),
                )
            }),
            signed_pre_key_record.id().expect("has id"),
            signed_pre_key_record.public_key().expect("has public key"),
            signed_pre_key_record.signature().expect("has signature"),
            *identity_key,
        )
        .expect("can make pre key bundle from store");
        if let Some(rec) = maybe_kyber_pre_key_record {
            bundle = bundle.with_kyber_pre_key(
                rec.id().expect("has id"),
                rec.public_key().expect("has public key"),
                rec.signature().expect("has signature"),
            );
        }
        bundle
    }

    fn sign(&mut self, message: &[u8]) -> Box<[u8]> {
        let identity_key_pair = self
            .store
            .get_identity_key_pair(None)
            .now_or_never()
            .expect("sync")
            .expect("able to get identity");
        let signing_key = identity_key_pair.private_key();
        signing_key
            .calculate_signature(message, &mut self.rng)
            .expect("able to sign with identity key")
    }

    fn next_id(&mut self) -> u32 {
        self.id_range.next().expect("should have enough ids")
    }

    fn gen_id(&mut self, choice: IdChoice) -> u32 {
        match choice {
            IdChoice::Exactly(id) => id,
            // TODO: check the maximal existing id and continue from it
            IdChoice::Next => self.next_id(),
            IdChoice::Random => self.rng.gen(),
        }
    }
}

pub trait HasSessionVersion {
    fn session_version(&self, address: &ProtocolAddress) -> Result<u32, SignalProtocolError>;
}

impl HasSessionVersion for TestStoreBuilder {
    fn session_version(&self, address: &ProtocolAddress) -> Result<u32, SignalProtocolError> {
        self.store.session_version(address)
    }
}

impl HasSessionVersion for InMemSignalProtocolStore {
    fn session_version(&self, address: &ProtocolAddress) -> Result<u32, SignalProtocolError> {
        self.load_session(address, None)
            .now_or_never()
            .expect("sync")?
            .expect("session found")
            .session_version()
    }
}
