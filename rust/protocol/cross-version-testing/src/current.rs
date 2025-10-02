//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use futures_util::FutureExt;
use libsignal_protocol_current::*;
use rand::{Rng, rng};

fn address(id: &str) -> ProtocolAddress {
    ProtocolAddress::new(id.into(), DeviceId::new(1).unwrap())
}

pub struct LibSignalProtocolCurrent(InMemSignalProtocolStore);

impl LibSignalProtocolCurrent {
    pub fn new() -> Self {
        let mut csprng = rng();
        let identity_key = IdentityKeyPair::generate(&mut csprng);
        // Valid registration IDs fit in 14 bits.
        let registration_id: u8 = csprng.random();

        Self(
            InMemSignalProtocolStore::new(identity_key, registration_id as u32)
                .expect("can initialize"),
        )
    }
}

impl super::LibSignalProtocolStore for LibSignalProtocolCurrent {
    fn version(&self) -> &'static str {
        "current"
    }

    fn create_pre_key_bundle(&mut self) -> PreKeyBundle {
        let mut csprng = rng();
        let pre_key_pair = KeyPair::generate(&mut csprng);
        let signed_pre_key_pair = KeyPair::generate(&mut csprng);
        let signed_pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut csprng);

        let identity_key = self
            .0
            .get_identity_key_pair()
            .now_or_never()
            .expect("synchronous")
            .expect("can fetch identity key");
        let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
        let signed_pre_key_signature = identity_key
            .private_key()
            .calculate_signature(&signed_pre_key_public, &mut csprng)
            .expect("can calculate signatures");

        let signed_pq_pre_key_public = signed_pq_pre_key_pair.public_key.serialize();
        let signed_pq_pre_key_signature = identity_key
            .private_key()
            .calculate_signature(&signed_pq_pre_key_public, &mut csprng)
            .expect("can sign");

        let device_id: DeviceId = csprng.random();
        let pre_key_id: u32 = csprng.random();
        let signed_pre_key_id: u32 = csprng.random();
        let kyber_pre_key_id: u32 = csprng.random();

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

        let timestamp = csprng.random();

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

    fn process_pre_key_bundle(&mut self, remote: &str, pre_key_bundle: PreKeyBundle) {
        process_prekey_bundle(
            &address(remote),
            &mut self.0.session_store,
            &mut self.0.identity_store,
            &pre_key_bundle,
            SystemTime::now(),
            &mut rng(),
        )
        .now_or_never()
        .expect("synchronous")
        .expect("can process pre-key bundles")
    }

    fn encrypt(&mut self, remote: &str, msg: &[u8]) -> (Vec<u8>, CiphertextMessageType) {
        let encrypted = message_encrypt(
            msg,
            &address(remote),
            &mut self.0.session_store,
            &mut self.0.identity_store,
            SystemTime::now(),
            &mut rng(),
        )
        .now_or_never()
        .expect("synchronous")
        .expect("can encrypt messages");
        (encrypted.serialize().to_vec(), encrypted.message_type())
    }

    fn decrypt(&mut self, remote: &str, msg: &[u8], msg_type: CiphertextMessageType) -> Vec<u8> {
        match msg_type {
            CiphertextMessageType::Whisper => message_decrypt_signal(
                &SignalMessage::try_from(msg).expect("valid"),
                &address(remote),
                &mut self.0.session_store,
                &mut self.0.identity_store,
                &mut rng(),
            )
            .now_or_never()
            .expect("synchronous")
            .expect("can decrypt messages"),
            CiphertextMessageType::PreKey => message_decrypt_prekey(
                &PreKeySignalMessage::try_from(msg).expect("valid"),
                &address(remote),
                &mut self.0.session_store,
                &mut self.0.identity_store,
                &mut self.0.pre_key_store,
                &self.0.signed_pre_key_store,
                &mut self.0.kyber_pre_key_store,
                &mut rng(),
            )
            .now_or_never()
            .expect("synchronous")
            .expect("can decrypt messages"),
            _ => panic!("unexpected 1:1 message type"),
        }
    }

    fn encrypt_sealed_sender_v1(
        &self,
        remote: &str,
        msg: &UnidentifiedSenderMessageContent,
    ) -> Vec<u8> {
        sealed_sender_encrypt_from_usmc(&address(remote), msg, &self.0, &mut rng())
            .now_or_never()
            .expect("synchronous")
            .expect("can encrypt messages")
    }

    fn encrypt_sealed_sender_v2(
        &self,
        remote: &str,
        msg: &UnidentifiedSenderMessageContent,
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
            &mut rng(),
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
