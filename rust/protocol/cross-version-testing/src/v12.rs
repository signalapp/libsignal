//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures_util::FutureExt;
use libsignal_protocol_v12::*;
use rand_v7::{thread_rng, Rng};

fn address(id: &str) -> ProtocolAddress {
    ProtocolAddress::new(id.into(), 1)
}

pub struct LibSignalProtocolV12(InMemSignalProtocolStore);

impl LibSignalProtocolV12 {
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

impl super::LibSignalProtocolStore for LibSignalProtocolV12 {
    fn version(&self) -> &'static str {
        "v12"
    }

    fn create_pre_key_bundle(&mut self) -> super::PreKeyBundle {
        let mut csprng = thread_rng();
        let pre_key_pair = KeyPair::generate(&mut csprng);
        let signed_pre_key_pair = KeyPair::generate(&mut csprng);

        let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
        let signed_pre_key_signature = self
            .0
            .get_identity_key_pair(None)
            .now_or_never()
            .expect("synchronous")
            .expect("can fetch identity key")
            .private_key()
            .calculate_signature(&signed_pre_key_public, &mut csprng)
            .expect("can calculate signatures");

        let device_id: u32 = csprng.gen();
        let pre_key_id: u32 = csprng.gen();
        let signed_pre_key_id: u32 = csprng.gen();

        let pre_key_bundle = super::PreKeyBundle::new(
            self.0
                .get_local_registration_id(None)
                .now_or_never()
                .expect("synchronous")
                .expect("can fetch registration id"),
            device_id.into(),
            Some((
                pre_key_id.into(),
                pre_key_pair.public_key.serialize()[..]
                    .try_into()
                    .expect("compatible key serialization format"),
            )),
            signed_pre_key_id.into(),
            signed_pre_key_pair.public_key.serialize()[..]
                .try_into()
                .expect("compatible key serialization format"),
            signed_pre_key_signature.to_vec(),
            self.0
                .get_identity_key_pair(None)
                .now_or_never()
                .expect("synchronous")
                .expect("can fetch identity key")
                .identity_key()
                .serialize()[..]
                .try_into()
                .expect("compatible key serialization format"),
        )
        .expect("can create pre-key bundles");

        self.0
            .save_pre_key(
                pre_key_id,
                &PreKeyRecord::new(pre_key_id, &pre_key_pair),
                None,
            )
            .now_or_never()
            .expect("synchronous")
            .expect("can save pre-keys");

        let timestamp = csprng.gen();

        self.0
            .save_signed_pre_key(
                signed_pre_key_id,
                &SignedPreKeyRecord::new(
                    signed_pre_key_id,
                    timestamp,
                    &signed_pre_key_pair,
                    &signed_pre_key_signature,
                ),
                None,
            )
            .now_or_never()
            .expect("synchronous")
            .expect("can save pre-keys");

        pre_key_bundle
    }

    fn process_pre_key_bundle(&mut self, remote: &str, pre_key_bundle: super::PreKeyBundle) {
        let pre_key_bundle = PreKeyBundle::new(
            pre_key_bundle
                .registration_id()
                .expect("has registration ID"),
            DeviceId::from(pre_key_bundle.device_id().expect("has device ID")),
            pre_key_bundle
                .pre_key_id()
                .expect("can ask about one-time pre-keys")
                .map(|pre_key_id| {
                    (
                        u32::from(pre_key_id),
                        pre_key_bundle
                            .pre_key_public()
                            .expect("can ask about one-time pre-keys")
                            .expect("has one-time pre-key")
                            .serialize()[..]
                            .try_into()
                            .expect("compatible key serialization format"),
                    )
                }),
            u32::from(
                pre_key_bundle
                    .signed_pre_key_id()
                    .expect("has signed pre-key ID"),
            ),
            pre_key_bundle
                .signed_pre_key_public()
                .expect("has signed pre-key")
                .serialize()[..]
                .try_into()
                .expect("compatible key serialization format"),
            pre_key_bundle
                .signed_pre_key_signature()
                .expect("has signature")
                .to_vec(),
            pre_key_bundle
                .identity_key()
                .expect("has identity key")
                .serialize()[..]
                .try_into()
                .expect("compatible key serialization format"),
        )
        .expect("can create pre-key bundles");
        process_prekey_bundle(
            &address(remote),
            &mut self.0.session_store,
            &mut self.0.identity_store,
            &pre_key_bundle,
            &mut thread_rng(),
            None,
        )
        .now_or_never()
        .expect("synchronous")
        .expect("can process pre-key bundles")
    }

    fn encrypt(&mut self, remote: &str, msg: &[u8]) -> (Vec<u8>, super::CiphertextMessageType) {
        let encrypted = message_encrypt(
            msg,
            &address(remote),
            &mut self.0.session_store,
            &mut self.0.identity_store,
            None,
        )
        .now_or_never()
        .expect("synchronous")
        .expect("can encrypt messages");
        let message_type = match encrypted.message_type() {
            CiphertextMessageType::Whisper => super::CiphertextMessageType::Whisper,
            CiphertextMessageType::PreKey => super::CiphertextMessageType::PreKey,
            CiphertextMessageType::SenderKey => super::CiphertextMessageType::SenderKey,
            CiphertextMessageType::Plaintext => super::CiphertextMessageType::Plaintext,
        };
        (encrypted.serialize().to_vec(), message_type)
    }

    fn decrypt(
        &mut self,
        remote: &str,
        msg: &[u8],
        msg_type: super::CiphertextMessageType,
    ) -> Vec<u8> {
        match msg_type {
            super::CiphertextMessageType::Whisper => message_decrypt_signal(
                &SignalMessage::try_from(msg).expect("valid"),
                &address(remote),
                &mut self.0.session_store,
                &mut self.0.identity_store,
                &mut thread_rng(),
                None,
            )
            .now_or_never()
            .expect("synchronous")
            .expect("can decrypt messages"),
            super::CiphertextMessageType::PreKey => message_decrypt_prekey(
                &PreKeySignalMessage::try_from(msg).expect("valid"),
                &address(remote),
                &mut self.0.session_store,
                &mut self.0.identity_store,
                &mut self.0.pre_key_store,
                &mut self.0.signed_pre_key_store,
                &mut thread_rng(),
                None,
            )
            .now_or_never()
            .expect("synchronous")
            .expect("can decrypt messages"),
            _ => panic!("unexpected 1:1 message type"),
        }
    }
}
