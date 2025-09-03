//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use futures_util::FutureExt;
use libsignal_protocol_v70::*;
use rand_v8::{Rng, thread_rng};

fn address(id: &str) -> ProtocolAddress {
    ProtocolAddress::new(id.into(), 1.into())
}

pub struct LibSignalProtocolV70(InMemSignalProtocolStore);

impl LibSignalProtocolV70 {
    pub fn new() -> Self {
        let mut csprng = thread_rng();
        let identity_key = IdentityKeyPair::generate(&mut csprng);
        // Valid registration IDs fit in 14 bits.
        let registration_id: u8 = csprng.r#gen();

        Self(
            InMemSignalProtocolStore::new(identity_key, registration_id as u32)
                .expect("can initialize"),
        )
    }
}

impl super::LibSignalProtocolStore for LibSignalProtocolV70 {
    fn version(&self) -> &'static str {
        "v70"
    }

    fn create_pre_key_bundle(&mut self) -> super::PreKeyBundle {
        let mut csprng = thread_rng();
        let pre_key_pair = KeyPair::generate(&mut csprng);
        let signed_pre_key_pair = KeyPair::generate(&mut csprng);
        let signed_pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024);

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

        let device_id: u32 = csprng.gen_range(1..=127);
        let pre_key_id: u32 = csprng.r#gen();
        let signed_pre_key_id: u32 = csprng.r#gen();
        let kyber_pre_key_id: u32 = csprng.r#gen();

        let pre_key_bundle = super::PreKeyBundle::new(
            self.0
                .get_local_registration_id()
                .now_or_never()
                .expect("synchronous")
                .expect("can fetch registration id"),
            device_id.try_into().unwrap(),
            Some((pre_key_id.into(), pre_key_pair.public_key.into_current())),
            signed_pre_key_id.into(),
            signed_pre_key_pair.public_key.into_current(),
            signed_pre_key_signature.to_vec(),
            kyber_pre_key_id.into(),
            signed_pq_pre_key_pair.public_key.clone().into_current(),
            signed_pq_pre_key_signature.to_vec(),
            self.0
                .get_identity_key_pair()
                .now_or_never()
                .expect("synchronous")
                .expect("can fetch identity key")
                .identity_key()
                .into_current(),
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

        let timestamp = csprng.r#gen();

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

    fn process_pre_key_bundle(&mut self, remote: &str, pre_key_bundle: super::PreKeyBundle) {
        let pre_key_bundle = (|| {
            let bundle = PreKeyBundle::new(
                pre_key_bundle.registration_id()?,
                ConvertVersion::from_current(pre_key_bundle.device_id()?),
                pre_key_bundle
                    .pre_key_id()?
                    .map(ConvertVersion::from_current)
                    .zip(
                        pre_key_bundle
                            .pre_key_public()?
                            .map(ConvertVersion::from_current),
                    ),
                ConvertVersion::from_current(pre_key_bundle.signed_pre_key_id()?),
                ConvertVersion::from_current(pre_key_bundle.signed_pre_key_public()?),
                pre_key_bundle.signed_pre_key_signature()?.to_vec(),
                ConvertVersion::from_current(pre_key_bundle.identity_key()?.to_owned()),
            )
            .expect("can produce bundle")
            .with_kyber_pre_key(
                ConvertVersion::from_current(pre_key_bundle.kyber_pre_key_id()?),
                ConvertVersion::from_current(pre_key_bundle.kyber_pre_key_public()?.clone()),
                pre_key_bundle.kyber_pre_key_signature()?.to_vec(),
            );

            Ok::<_, libsignal_protocol_current::SignalProtocolError>(bundle)
        })()
        .expect("can retrieve values");
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

    fn encrypt(&mut self, remote: &str, msg: &[u8]) -> (Vec<u8>, super::CiphertextMessageType) {
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
        (
            encrypted.serialize().to_vec(),
            encrypted.message_type().into_current(),
        )
    }

    fn decrypt(
        &mut self,
        remote: &str,
        msg: &[u8],
        msg_type: super::CiphertextMessageType,
    ) -> Vec<u8> {
        match ConvertVersion::from_current(msg_type) {
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
                &self.0.signed_pre_key_store,
                &mut self.0.kyber_pre_key_store,
                &mut thread_rng(),
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
        msg: &libsignal_protocol_current::UnidentifiedSenderMessageContent,
    ) -> Vec<u8> {
        // We don't use ConvertVersion for this because we're passed a reference and USMC doesn't
        // implement Clone.
        let msg = UnidentifiedSenderMessageContent::deserialize(
            msg.serialized().expect("can re-serialize"),
        )
        .expect("compatible serialization");
        sealed_sender_encrypt_from_usmc(&address(remote), &msg, &self.0, &mut thread_rng())
            .now_or_never()
            .expect("synchronous")
            .expect("can encrypt messages")
    }

    fn encrypt_sealed_sender_v2(
        &self,
        remote: &str,
        msg: &libsignal_protocol_current::UnidentifiedSenderMessageContent,
    ) -> Vec<u8> {
        let msg = UnidentifiedSenderMessageContent::deserialize(
            msg.serialized().expect("can re-serialize"),
        )
        .expect("compatible serialization");
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
            &msg,
            &self.0,
            &mut thread_rng(),
        )
        .now_or_never()
        .expect("synchronous")
        .expect("can encrypt messages")
    }

    fn decrypt_sealed_sender(
        &self,
        msg: &[u8],
    ) -> libsignal_protocol_current::UnidentifiedSenderMessageContent {
        let decrypted = sealed_sender_decrypt_to_usmc(msg, &self.0)
            .now_or_never()
            .expect("synchronous")
            .expect("can decrypt messages");
        libsignal_protocol_current::UnidentifiedSenderMessageContent::deserialize(
            decrypted.serialized().expect("can re-serialize"),
        )
        .expect("compatible serialization")
    }
}

trait ConvertVersion {
    type Current;
    fn into_current(self) -> Self::Current;
    fn from_current(current: Self::Current) -> Self;
}

macro_rules! impl_convert_version {
    ($old:ty, $current:ty as serializable) => {
        impl ConvertVersion for $old {
            type Current = $current;
            fn from_current(current: Self::Current) -> Self {
                current
                    .serialize()
                    .as_ref()
                    .try_into()
                    .expect("compatible serialization")
            }
            fn into_current(self) -> Self::Current {
                self.serialize()
                    .as_ref()
                    .try_into()
                    .expect("compatible serialization")
            }
        }
    };
    ($old:ty, $current:ty as u32) => {
        impl ConvertVersion for $old {
            type Current = $current;
            fn from_current(current: Self::Current) -> Self {
                u32::from(current).into()
            }
            fn into_current(self) -> Self::Current {
                u32::from(self).try_into().expect("valid range")
            }
        }
    };
}

impl_convert_version!(
    PublicKey,
    libsignal_protocol_current::PublicKey as serializable
);
impl_convert_version!(
    IdentityKey,
    libsignal_protocol_current::IdentityKey as serializable
);
impl_convert_version!(
    kem::PublicKey,
    libsignal_protocol_current::kem::PublicKey as serializable
);
impl_convert_version!(
    kem::SecretKey,
    libsignal_protocol_current::kem::SecretKey as serializable
);
impl_convert_version!(DeviceId, libsignal_protocol_current::DeviceId as u32);
impl_convert_version!(PreKeyId, libsignal_protocol_current::PreKeyId as u32);
impl_convert_version!(
    SignedPreKeyId,
    libsignal_protocol_current::SignedPreKeyId as u32
);
impl_convert_version!(
    KyberPreKeyId,
    libsignal_protocol_current::KyberPreKeyId as u32
);

impl ConvertVersion for CiphertextMessageType {
    type Current = libsignal_protocol_current::CiphertextMessageType;

    fn into_current(self) -> Self::Current {
        match self {
            CiphertextMessageType::Whisper => Self::Current::Whisper,
            CiphertextMessageType::PreKey => Self::Current::PreKey,
            CiphertextMessageType::SenderKey => Self::Current::SenderKey,
            CiphertextMessageType::Plaintext => Self::Current::Plaintext,
        }
    }

    fn from_current(current: Self::Current) -> Self {
        match current {
            Self::Current::Whisper => Self::Whisper,
            Self::Current::PreKey => Self::PreKey,
            Self::Current::SenderKey => Self::SenderKey,
            Self::Current::Plaintext => Self::Plaintext,
        }
    }
}
