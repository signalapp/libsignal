//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use async_trait::async_trait;
use futures_util::FutureExt;
use libsignal_protocol_pre_tahini::*;
use rand::Rng;
use rand::rngs::StdRng;

use crate::{KyberPreKeyUsage, SerializedConversationState};

fn address(id: &str) -> ProtocolAddress {
    ProtocolAddress::new(id.into(), DeviceId::new(1).unwrap())
}

#[derive(Clone)]
pub struct LibSignalProtocolPreTahini(InMemSignalProtocolStore, Vec<KyberPreKeyUsage>);

/// The pinned store does not expose its replay markers. Mirror successful
/// writes at the callback boundary so migration and cloning preserve them,
/// including writes followed by a failure later in the protocol operation.
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

impl LibSignalProtocolPreTahini {
    pub fn new(rng: &mut StdRng) -> Self {
        let identity_key = IdentityKeyPair::generate(rng);
        let registration_id: u8 = rng.random();

        Self(
            InMemSignalProtocolStore::new(identity_key, registration_id as u32)
                .expect("can initialize"),
            Vec::new(),
        )
    }

    /// Loads state written by a newer version, as a client rolled back to this
    /// release would.
    pub fn from_serialized_conversation_state(
        snapshot: &SerializedConversationState,
        remote: &str,
    ) -> Self {
        let mut restored = Self(
            InMemSignalProtocolStore::new(
                IdentityKeyPair::try_from(&snapshot.identity_key_pair[..])
                    .expect("pre-tahini can read serialized identity key pair"),
                snapshot.registration_id,
            )
            .expect("can initialize restored store"),
            snapshot.kyber_pre_key_usages.clone(),
        );

        if let Some(remote_identity) = &snapshot.remote_identity_key {
            restored
                .0
                .save_identity(
                    &address(remote),
                    &IdentityKey::decode(remote_identity)
                        .expect("pre-tahini can read serialized remote identity"),
                )
                .now_or_never()
                .expect("synchronous")
                .expect("can restore known identity");
        }

        if let Some(session_record) = &snapshot.session_record {
            let session = SessionRecord::deserialize(session_record)
                .expect("pre-tahini can read newer session");
            restored
                .0
                .store_session(&address(remote), &session)
                .now_or_never()
                .expect("synchronous")
                .expect("can restore session");
        }

        for (id, record) in &snapshot.pre_keys {
            let pre_key =
                PreKeyRecord::deserialize(record).expect("pre-tahini can read serialized pre-key");
            restored
                .0
                .save_pre_key((*id).into(), &pre_key)
                .now_or_never()
                .expect("synchronous")
                .expect("can restore pre-key");
        }

        for (id, record) in &snapshot.signed_pre_keys {
            let signed_pre_key = SignedPreKeyRecord::deserialize(record)
                .expect("pre-tahini can read serialized signed pre-key");
            restored
                .0
                .save_signed_pre_key((*id).into(), &signed_pre_key)
                .now_or_never()
                .expect("synchronous")
                .expect("can restore signed pre-key");
        }

        for (id, record) in &snapshot.kyber_pre_keys {
            let kyber_pre_key = KyberPreKeyRecord::deserialize(record)
                .expect("pre-tahini can read serialized kyber pre-key");
            restored
                .0
                .save_kyber_pre_key((*id).into(), &kyber_pre_key)
                .now_or_never()
                .expect("synchronous")
                .expect("can restore kyber pre-key");
        }

        for usage in &snapshot.kyber_pre_key_usages {
            restored
                .0
                .mark_kyber_pre_key_used(
                    usage.kyber_pre_key_id.into(),
                    usage.signed_pre_key_id.into(),
                    &PublicKey::deserialize(&usage.base_key)
                        .expect("pre-tahini can read serialized initiator base key"),
                )
                .now_or_never()
                .expect("synchronous")
                .expect("can restore kyber pre-key usage");
        }

        restored
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

    pub fn reload_session_only(&self, remote: &str) -> Self {
        let mut restored = self.clone();
        if let Some(session) = self
            .0
            .load_session(&address(remote))
            .now_or_never()
            .expect("synchronous")
            .expect("can fetch session")
        {
            let serialized = session.serialize().expect("can serialize session");
            let reloaded = SessionRecord::deserialize(&serialized)
                .expect("pre-tahini can deserialize session");
            restored
                .0
                .store_session(&address(remote), &reloaded)
                .now_or_never()
                .expect("synchronous")
                .expect("can restore session");
        }
        restored
    }
}

impl super::LibSignalProtocolStore for LibSignalProtocolPreTahini {
    fn version(&self) -> &'static str {
        "pre-tahini"
    }

    fn box_clone(&self) -> Box<dyn super::LibSignalProtocolStore> {
        Box::new(self.clone())
    }

    fn to_current_for_remote(&self, remote: &str) -> Box<dyn super::LibSignalProtocolStore> {
        Box::new(
            crate::LibSignalProtocolCurrent::from_serialized_conversation_state(
                &self.serialize_conversation_state(remote),
                remote,
            ),
        )
    }

    fn create_pre_key_bundle(&mut self, rng: &mut StdRng) -> super::PreKeyBundle {
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

        let pre_key_bundle = super::PreKeyBundle::new(
            self.0
                .get_local_registration_id()
                .now_or_never()
                .expect("synchronous")
                .expect("can fetch registration id"),
            device_id.into_current(),
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
                .to_owned()
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
        pre_key_bundle: super::PreKeyBundle,
        rng: &mut StdRng,
    ) {
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
                ConvertVersion::from_current(pre_key_bundle.kyber_pre_key_id()?),
                ConvertVersion::from_current(pre_key_bundle.kyber_pre_key_public()?.clone()),
                pre_key_bundle.kyber_pre_key_signature()?.to_vec(),
                ConvertVersion::from_current(pre_key_bundle.identity_key()?.to_owned()),
            );

            Ok::<_, libsignal_protocol_current::SignalProtocolError>(
                bundle.expect("can produce bundle"),
            )
        })()
        .expect("can retrieve values");

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
        if let Some(mut session) = self
            .0
            .load_session(&address(remote))
            .now_or_never()
            .expect("synchronous")
            .expect("can fetch sessions")
        {
            session.archive_current_state().expect("can archive state");
            self.0
                .store_session(&address(remote), &session)
                .now_or_never()
                .expect("synchronous")
                .expect("can store session");
        }
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
    ) -> Result<(Vec<u8>, super::CiphertextMessageType), Box<dyn std::error::Error>> {
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
        Ok((
            encrypted.serialize().to_vec(),
            encrypted.message_type().into_current(),
        ))
    }

    fn decrypt(
        &mut self,
        remote: &str,
        local: &str,
        msg: &[u8],
        msg_type: super::CiphertextMessageType,
        rng: &mut StdRng,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        match msg_type {
            super::CiphertextMessageType::Whisper => message_decrypt_signal(
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
            super::CiphertextMessageType::PreKey => message_decrypt_prekey(
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
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>),
            _ => panic!("unexpected 1:1 message type"),
        }
    }

    fn encrypt_sealed_sender_v1(
        &self,
        remote: &str,
        msg: &libsignal_protocol_current::UnidentifiedSenderMessageContent,
        rng: &mut StdRng,
    ) -> Vec<u8> {
        let msg = UnidentifiedSenderMessageContent::deserialize(
            msg.serialized().expect("can re-serialize"),
        )
        .expect("compatible serialization");
        sealed_sender_encrypt_from_usmc(&address(remote), &msg, &self.0, rng)
            .now_or_never()
            .expect("synchronous")
            .expect("can encrypt messages")
    }

    fn encrypt_sealed_sender_v2(
        &self,
        remote: &str,
        msg: &libsignal_protocol_current::UnidentifiedSenderMessageContent,
        rng: &mut StdRng,
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
            rng,
        )
        .now_or_never()
        .expect("synchronous")
        .expect("can encrypt messages")
    }

    fn decrypt_sealed_sender(
        &self,
        msg: &[u8],
    ) -> libsignal_protocol_current::UnidentifiedSenderMessageContent {
        let usmc = sealed_sender_decrypt_to_usmc(msg, &self.0)
            .now_or_never()
            .expect("synchronous")
            .expect("can decrypt messages");
        libsignal_protocol_current::UnidentifiedSenderMessageContent::deserialize(
            usmc.serialized().expect("can re-serialize"),
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

impl ConvertVersion for DeviceId {
    type Current = libsignal_protocol_current::DeviceId;

    fn into_current(self) -> Self::Current {
        u32::from(self).try_into().expect("valid range")
    }

    fn from_current(current: Self::Current) -> Self {
        u32::from(current).try_into().expect("valid range")
    }
}
