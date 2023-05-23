//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implementations for stores defined in [super::traits].
//!
//! These implementations are purely in-memory, and therefore most likely useful for testing.

use crate::storage::{traits, Context};
use crate::{
    IdentityKey, IdentityKeyPair, KyberPreKeyId, KyberPreKeyRecord, PreKeyId, PreKeyRecord,
    ProtocolAddress, Result, SenderKeyRecord, SessionRecord, SignalProtocolError, SignedPreKeyId,
    SignedPreKeyRecord,
};

use async_trait::async_trait;
use std::borrow::Cow;
use std::collections::HashMap;
use uuid::Uuid;

/// Reference implementation of [traits::IdentityKeyStore].
#[derive(Clone)]
pub struct InMemIdentityKeyStore {
    key_pair: IdentityKeyPair,
    registration_id: u32,
    known_keys: HashMap<ProtocolAddress, IdentityKey>,
}

impl InMemIdentityKeyStore {
    /// Create a new instance.
    ///
    /// `key_pair` corresponds to [traits::IdentityKeyStore::get_identity_key_pair], and
    /// `registration_id` corresponds to [traits::IdentityKeyStore::get_local_registration_id].
    pub fn new(key_pair: IdentityKeyPair, registration_id: u32) -> Self {
        Self {
            key_pair,
            registration_id,
            known_keys: HashMap::new(),
        }
    }

    /// Clear the mapping of known keys.
    pub fn reset(&mut self) {
        self.known_keys.clear();
    }
}

#[async_trait(?Send)]
impl traits::IdentityKeyStore for InMemIdentityKeyStore {
    async fn get_identity_key_pair(&self, _ctx: Context) -> Result<IdentityKeyPair> {
        Ok(self.key_pair)
    }

    async fn get_local_registration_id(&self, _ctx: Context) -> Result<u32> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _ctx: Context,
    ) -> Result<bool> {
        match self.known_keys.get(address) {
            None => {
                self.known_keys.insert(address.clone(), *identity);
                Ok(false) // new key
            }
            Some(k) if k == identity => {
                Ok(false) // same key
            }
            Some(_k) => {
                self.known_keys.insert(address.clone(), *identity);
                Ok(true) // overwrite
            }
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: traits::Direction,
        _ctx: Context,
    ) -> Result<bool> {
        match self.known_keys.get(address) {
            None => {
                Ok(true) // first use
            }
            Some(k) => Ok(k == identity),
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<IdentityKey>> {
        match self.known_keys.get(address) {
            None => Ok(None),
            Some(k) => Ok(Some(k.to_owned())),
        }
    }
}

/// Reference implementation of [traits::PreKeyStore].
#[derive(Clone)]
pub struct InMemPreKeyStore {
    pre_keys: HashMap<PreKeyId, PreKeyRecord>,
}

impl InMemPreKeyStore {
    /// Create an empty pre-key store.
    pub fn new() -> Self {
        Self {
            pre_keys: HashMap::new(),
        }
    }

    /// Returns all registered pre-key ids
    pub fn all_pre_key_ids(&self) -> impl Iterator<Item = &PreKeyId> {
        self.pre_keys.keys()
    }
}

impl Default for InMemPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl traits::PreKeyStore for InMemPreKeyStore {
    async fn get_pre_key(&self, id: PreKeyId, _ctx: Context) -> Result<PreKeyRecord> {
        Ok(self
            .pre_keys
            .get(&id)
            .ok_or(SignalProtocolError::InvalidPreKeyId)?
            .clone())
    }

    async fn save_pre_key(
        &mut self,
        id: PreKeyId,
        record: &PreKeyRecord,
        _ctx: Context,
    ) -> Result<()> {
        // This overwrites old values, which matches Java behavior, but is it correct?
        self.pre_keys.insert(id, record.to_owned());
        Ok(())
    }

    async fn remove_pre_key(&mut self, id: PreKeyId, _ctx: Context) -> Result<()> {
        // If id does not exist this silently does nothing
        self.pre_keys.remove(&id);
        Ok(())
    }
}

/// Reference implementation of [traits::SignedPreKeyStore].
#[derive(Clone)]
pub struct InMemSignedPreKeyStore {
    signed_pre_keys: HashMap<SignedPreKeyId, SignedPreKeyRecord>,
}

impl InMemSignedPreKeyStore {
    /// Create an empty signed pre-key store.
    pub fn new() -> Self {
        Self {
            signed_pre_keys: HashMap::new(),
        }
    }

    /// Returns all registered signed pre-key ids
    pub fn all_signed_pre_key_ids(&self) -> impl Iterator<Item = &SignedPreKeyId> {
        self.signed_pre_keys.keys()
    }
}

impl Default for InMemSignedPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl traits::SignedPreKeyStore for InMemSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
        _ctx: Context,
    ) -> Result<SignedPreKeyRecord> {
        Ok(self
            .signed_pre_keys
            .get(&id)
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?
            .clone())
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
        _ctx: Context,
    ) -> Result<()> {
        // This overwrites old values, which matches Java behavior, but is it correct?
        self.signed_pre_keys.insert(id, record.to_owned());
        Ok(())
    }
}

/// Reference implementation of [traits::KyberPreKeyStore].
#[derive(Clone)]
pub struct InMemKyberPreKeyStore {
    kyber_pre_keys: HashMap<KyberPreKeyId, KyberPreKeyRecord>,
}

impl InMemKyberPreKeyStore {
    /// Create an empty kyber pre-key store.
    pub fn new() -> Self {
        Self {
            kyber_pre_keys: HashMap::new(),
        }
    }

    /// Returns all registered Kyber pre-key ids
    pub fn all_kyber_pre_key_ids(&self) -> impl Iterator<Item = &KyberPreKeyId> {
        self.kyber_pre_keys.keys()
    }
}

impl Default for InMemKyberPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl traits::KyberPreKeyStore for InMemKyberPreKeyStore {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
        _ctx: Context,
    ) -> Result<KyberPreKeyRecord> {
        Ok(self
            .kyber_pre_keys
            .get(&kyber_prekey_id)
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?
            .clone())
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
        _ctx: Context,
    ) -> Result<()> {
        self.kyber_pre_keys
            .insert(kyber_prekey_id, record.to_owned());
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        _kyber_prekey_id: KyberPreKeyId,
        _ctx: Context,
    ) -> Result<()> {
        Ok(())
    }
}

/// Reference implementation of [traits::SessionStore].
#[derive(Clone)]
pub struct InMemSessionStore {
    sessions: HashMap<ProtocolAddress, SessionRecord>,
}

impl InMemSessionStore {
    /// Create an empty session store.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Bulk version of [`SessionStore::load_session`].
    ///
    /// Useful for [crate::sealed_sender_multi_recipient_encrypt].
    ///
    /// [`SessionStore::load_session`]: crate::SessionStore::load_session
    pub fn load_existing_sessions(
        &self,
        addresses: &[&ProtocolAddress],
    ) -> Result<Vec<&SessionRecord>> {
        addresses
            .iter()
            .map(|&address| {
                self.sessions
                    .get(address)
                    .ok_or_else(|| SignalProtocolError::SessionNotFound(address.clone()))
            })
            .collect()
    }
}

impl Default for InMemSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl traits::SessionStore for InMemSessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<SessionRecord>> {
        match self.sessions.get(address) {
            None => Ok(None),
            Some(s) => Ok(Some(s.clone())),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        _ctx: Context,
    ) -> Result<()> {
        self.sessions.insert(address.clone(), record.clone());
        Ok(())
    }
}

/// Reference implementation of [traits::SenderKeyStore].
#[derive(Clone)]
pub struct InMemSenderKeyStore {
    // We use Cow keys in order to store owned values but compare to referenced ones.
    // See https://users.rust-lang.org/t/hashmap-with-tuple-keys/12711/6.
    keys: HashMap<(Cow<'static, ProtocolAddress>, Uuid), SenderKeyRecord>,
}

impl InMemSenderKeyStore {
    /// Create an empty sender key store.
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
}

impl Default for InMemSenderKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl traits::SenderKeyStore for InMemSenderKeyStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
        _ctx: Context,
    ) -> Result<()> {
        self.keys.insert(
            (Cow::Owned(sender.clone()), distribution_id),
            record.clone(),
        );
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        _ctx: Context,
    ) -> Result<Option<SenderKeyRecord>> {
        Ok(self
            .keys
            .get(&(Cow::Borrowed(sender), distribution_id))
            .cloned())
    }
}

/// Reference implementation of [traits::ProtocolStore].
#[allow(missing_docs)]
#[derive(Clone)]
pub struct InMemSignalProtocolStore {
    pub session_store: InMemSessionStore,
    pub pre_key_store: InMemPreKeyStore,
    pub signed_pre_key_store: InMemSignedPreKeyStore,
    pub kyber_pre_key_store: InMemKyberPreKeyStore,
    pub identity_store: InMemIdentityKeyStore,
    pub sender_key_store: InMemSenderKeyStore,
}

impl InMemSignalProtocolStore {
    /// Create an object with the minimal implementation of [traits::ProtocolStore], representing
    /// the given identity `key_pair` along with the separate randomly chosen `registration_id`.
    pub fn new(key_pair: IdentityKeyPair, registration_id: u32) -> Result<Self> {
        Ok(Self {
            session_store: InMemSessionStore::new(),
            pre_key_store: InMemPreKeyStore::new(),
            signed_pre_key_store: InMemSignedPreKeyStore::new(),
            kyber_pre_key_store: InMemKyberPreKeyStore::new(),
            identity_store: InMemIdentityKeyStore::new(key_pair, registration_id),
            sender_key_store: InMemSenderKeyStore::new(),
        })
    }

    /// Returns all registered pre-key ids
    pub fn all_pre_key_ids(&self) -> impl Iterator<Item = &PreKeyId> {
        self.pre_key_store.all_pre_key_ids()
    }

    /// Returns all registered signed pre-key ids
    pub fn all_signed_pre_key_ids(&self) -> impl Iterator<Item = &SignedPreKeyId> {
        self.signed_pre_key_store.all_signed_pre_key_ids()
    }

    /// Returns all registered Kyber pre-key ids
    pub fn all_kyber_pre_key_ids(&self) -> impl Iterator<Item = &KyberPreKeyId> {
        self.kyber_pre_key_store.all_kyber_pre_key_ids()
    }
}

#[async_trait(?Send)]
impl traits::IdentityKeyStore for InMemSignalProtocolStore {
    async fn get_identity_key_pair(&self, ctx: Context) -> Result<IdentityKeyPair> {
        self.identity_store.get_identity_key_pair(ctx).await
    }

    async fn get_local_registration_id(&self, ctx: Context) -> Result<u32> {
        self.identity_store.get_local_registration_id(ctx).await
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        ctx: Context,
    ) -> Result<bool> {
        self.identity_store
            .save_identity(address, identity, ctx)
            .await
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: traits::Direction,
        ctx: Context,
    ) -> Result<bool> {
        self.identity_store
            .is_trusted_identity(address, identity, direction, ctx)
            .await
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        ctx: Context,
    ) -> Result<Option<IdentityKey>> {
        self.identity_store.get_identity(address, ctx).await
    }
}

#[async_trait(?Send)]
impl traits::PreKeyStore for InMemSignalProtocolStore {
    async fn get_pre_key(&self, id: PreKeyId, ctx: Context) -> Result<PreKeyRecord> {
        self.pre_key_store.get_pre_key(id, ctx).await
    }

    async fn save_pre_key(
        &mut self,
        id: PreKeyId,
        record: &PreKeyRecord,
        ctx: Context,
    ) -> Result<()> {
        self.pre_key_store.save_pre_key(id, record, ctx).await
    }

    async fn remove_pre_key(&mut self, id: PreKeyId, ctx: Context) -> Result<()> {
        self.pre_key_store.remove_pre_key(id, ctx).await
    }
}

#[async_trait(?Send)]
impl traits::SignedPreKeyStore for InMemSignalProtocolStore {
    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
        ctx: Context,
    ) -> Result<SignedPreKeyRecord> {
        self.signed_pre_key_store.get_signed_pre_key(id, ctx).await
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
        ctx: Context,
    ) -> Result<()> {
        self.signed_pre_key_store
            .save_signed_pre_key(id, record, ctx)
            .await
    }
}

#[async_trait(?Send)]
impl traits::KyberPreKeyStore for InMemSignalProtocolStore {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
        ctx: Context,
    ) -> Result<KyberPreKeyRecord> {
        self.kyber_pre_key_store
            .get_kyber_pre_key(kyber_prekey_id, ctx)
            .await
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
        ctx: Context,
    ) -> Result<()> {
        self.kyber_pre_key_store
            .save_kyber_pre_key(kyber_prekey_id, record, ctx)
            .await
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ctx: Context,
    ) -> Result<()> {
        self.kyber_pre_key_store
            .mark_kyber_pre_key_used(kyber_prekey_id, ctx)
            .await
    }
}

#[async_trait(?Send)]
impl traits::SessionStore for InMemSignalProtocolStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        ctx: Context,
    ) -> Result<Option<SessionRecord>> {
        self.session_store.load_session(address, ctx).await
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        ctx: Context,
    ) -> Result<()> {
        self.session_store.store_session(address, record, ctx).await
    }
}

#[async_trait(?Send)]
impl traits::SenderKeyStore for InMemSignalProtocolStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
        ctx: Context,
    ) -> Result<()> {
        self.sender_key_store
            .store_sender_key(sender, distribution_id, record, ctx)
            .await
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        ctx: Context,
    ) -> Result<Option<SenderKeyRecord>> {
        self.sender_key_store
            .load_sender_key(sender, distribution_id, ctx)
            .await
    }
}

impl traits::ProtocolStore for InMemSignalProtocolStore {}
