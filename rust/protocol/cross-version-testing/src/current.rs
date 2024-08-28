//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use futures_util::FutureExt;
use libsignal_protocol_current::*;
use rand::{thread_rng, Rng};

fn address(id: &str) -> ProtocolAddress {
    ProtocolAddress::new(id.into(), 1.into())
}

pub struct LibSignalProtocolCurrent(InMemSignalProtocolStore);

impl LibSignalProtocolCurrent {
    pub fn new() -> Self {
        let mut csprng = thread_rng();
        let identity_key = IdentityKeyPair::generate(&mut csprng);
        // Valid registration IDs fit in 14 bits.
        let registration_id: u8 = csprng.gen();

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
        let mut csprng = thread_rng();
        let pre_key_pair = KeyPair::generate(&mut csprng);
        let signed_pre_key_pair = KeyPair::generate(&mut csprng);

        let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
        let signed_pre_key_signature = self
            .0
            .get_identity_key_pair()
            .now_or_never()
            .expect("synchronous")
            .expect("can fetch identity key")
            .private_key()
            .calculate_signature(&signed_pre_key_public, &mut csprng)
            .expect("can calculate signatures");

        let device_id: u32 = csprng.gen();
        let pre_key_id: u32 = csprng.gen();
        let signed_pre_key_id: u32 = csprng.gen();

        let pre_key_bundle = PreKeyBundle::new(
            self.0
                .get_local_registration_id()
                .now_or_never()
                .expect("synchronous")
                .expect("can fetch registration id"),
            device_id.into(),
            Some((pre_key_id.into(), pre_key_pair.public_key)),
            signed_pre_key_id.into(),
            signed_pre_key_pair.public_key,
            signed_pre_key_signature.to_vec(),
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

        let timestamp = csprng.gen();

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

        pre_key_bundle
    }

    fn process_pre_key_bundle(&mut self, remote: &str, pre_key_bundle: PreKeyBundle) {
        process_prekey_bundle(
            &address(remote),
            &mut self.0.session_store,
            &mut self.0.identity_store,
            &pre_key_bundle,
            SystemTime::now(),
            &mut thread_rng(),
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
                &mut thread_rng(),
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
                &mut self.0.signed_pre_key_store,
                &mut self.0.kyber_pre_key_store,
                &mut thread_rng(),
            )
            .now_or_never()
            .expect("synchronous")
            .expect("can decrypt messages"),
            _ => panic!("unexpected 1:1 message type"),
        }
    }
}
