use crate::error::{Result, SignalProtocolError};
use crate::state::{PreKeyId, PreKeyRecord, SessionRecord, SignedPreKeyId, SignedPreKeyRecord};
use crate::storage::traits;
use crate::{IdentityKey, IdentityKeyPair, ProtocolAddress, SenderKeyName, SenderKeyRecord};

use std::collections::HashMap;

#[derive(Clone)]
pub struct InMemIdentityKeyStore {
    key_pair: IdentityKeyPair,
    id: u32,
    known_keys: HashMap<ProtocolAddress, IdentityKey>,
}

impl InMemIdentityKeyStore {
    pub fn new(key_pair: IdentityKeyPair, id: u32) -> Self {
        Self {
            key_pair,
            id,
            known_keys: HashMap::new(),
        }
    }
}

impl traits::IdentityKeyStore for InMemIdentityKeyStore {
    fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        Ok(self.key_pair)
    }

    fn get_local_registration_id(&self) -> Result<u32> {
        Ok(self.id)
    }

    fn save_identity(&mut self, address: &ProtocolAddress, identity: &IdentityKey) -> Result<bool> {
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

    fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: traits::Direction,
    ) -> Result<bool> {
        match self.known_keys.get(address) {
            None => {
                Ok(true) // first use
            }
            Some(k) => Ok(k == identity),
        }
    }

    fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        match self.known_keys.get(address) {
            None => Ok(None),
            Some(k) => Ok(Some(k.to_owned())),
        }
    }
}

#[derive(Clone)]
pub struct InMemPreKeyStore {
    pre_keys: HashMap<PreKeyId, PreKeyRecord>,
}

impl InMemPreKeyStore {
    pub fn new() -> Self {
        Self {
            pre_keys: HashMap::new(),
        }
    }
}

impl Default for InMemPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl traits::PreKeyStore for InMemPreKeyStore {
    fn get_pre_key(&self, id: PreKeyId) -> Result<PreKeyRecord> {
        Ok(self
            .pre_keys
            .get(&id)
            .ok_or(SignalProtocolError::InvalidPreKeyId)?
            .clone())
    }

    fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> Result<()> {
        // This overwrites old values, which matches Java behavior, but is it correct?
        self.pre_keys.insert(id, record.to_owned());
        Ok(())
    }

    fn remove_pre_key(&mut self, id: PreKeyId) -> Result<()> {
        // If id does not exist this silently does nothing
        self.pre_keys.remove(&id);
        Ok(())
    }
}

#[derive(Clone)]
pub struct InMemSignedPreKeyStore {
    signed_pre_keys: HashMap<SignedPreKeyId, SignedPreKeyRecord>,
}

impl InMemSignedPreKeyStore {
    pub fn new() -> Self {
        Self {
            signed_pre_keys: HashMap::new(),
        }
    }
}

impl Default for InMemSignedPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl traits::SignedPreKeyStore for InMemSignedPreKeyStore {
    fn get_signed_pre_key(&self, id: SignedPreKeyId) -> Result<SignedPreKeyRecord> {
        Ok(self
            .signed_pre_keys
            .get(&id)
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?
            .clone())
    }

    fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        // This overwrites old values, which matches Java behavior, but is it correct?
        self.signed_pre_keys.insert(id, record.to_owned());
        Ok(())
    }
}

#[derive(Clone)]
pub struct InMemSessionStore {
    sessions: HashMap<ProtocolAddress, SessionRecord>,
}

impl InMemSessionStore {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }
}

impl Default for InMemSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl traits::SessionStore for InMemSessionStore {
    fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        match self.sessions.get(address) {
            None => Ok(None),
            Some(s) => Ok(Some(s.clone())),
        }
    }

    fn store_session(&mut self, address: &ProtocolAddress, record: &SessionRecord) -> Result<()> {
        self.sessions.insert(address.clone(), record.clone());
        Ok(())
    }
}

#[derive(Clone)]
pub struct InMemSenderKeyStore {
    keys: HashMap<SenderKeyName, SenderKeyRecord>,
}

impl InMemSenderKeyStore {
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

impl traits::SenderKeyStore for InMemSenderKeyStore {
    fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
    ) -> Result<()> {
        self.keys.insert(sender_key_name.clone(), record.clone());
        Ok(())
    }

    fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
    ) -> Result<Option<SenderKeyRecord>> {
        Ok(self.keys.get(&sender_key_name).cloned())
    }
}

#[derive(Clone)]
pub struct InMemSignalProtocolStore {
    pub session_store: InMemSessionStore,
    pub pre_key_store: InMemPreKeyStore,
    pub signed_pre_key_store: InMemSignedPreKeyStore,
    pub identity_store: InMemIdentityKeyStore,
    pub sender_key_store: InMemSenderKeyStore,
}

impl InMemSignalProtocolStore {
    pub fn new(key_pair: IdentityKeyPair, registration_id: u32) -> Result<Self> {
        Ok(Self {
            session_store: InMemSessionStore::new(),
            pre_key_store: InMemPreKeyStore::new(),
            signed_pre_key_store: InMemSignedPreKeyStore::new(),
            identity_store: InMemIdentityKeyStore::new(key_pair, registration_id),
            sender_key_store: InMemSenderKeyStore::new(),
        })
    }
}

impl traits::IdentityKeyStore for InMemSignalProtocolStore {
    fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        self.identity_store.get_identity_key_pair()
    }

    fn get_local_registration_id(&self) -> Result<u32> {
        self.identity_store.get_local_registration_id()
    }

    fn save_identity(&mut self, address: &ProtocolAddress, identity: &IdentityKey) -> Result<bool> {
        self.identity_store.save_identity(address, identity)
    }

    fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: traits::Direction,
    ) -> Result<bool> {
        self.identity_store
            .is_trusted_identity(address, identity, direction)
    }

    fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        self.identity_store.get_identity(address)
    }
}

impl traits::PreKeyStore for InMemSignalProtocolStore {
    fn get_pre_key(&self, id: PreKeyId) -> Result<PreKeyRecord> {
        self.pre_key_store.get_pre_key(id)
    }

    fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> Result<()> {
        self.pre_key_store.save_pre_key(id, record)
    }

    fn remove_pre_key(&mut self, id: PreKeyId) -> Result<()> {
        self.pre_key_store.remove_pre_key(id)
    }
}

impl traits::SignedPreKeyStore for InMemSignalProtocolStore {
    fn get_signed_pre_key(&self, id: SignedPreKeyId) -> Result<SignedPreKeyRecord> {
        self.signed_pre_key_store.get_signed_pre_key(id)
    }

    fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        self.signed_pre_key_store.save_signed_pre_key(id, record)
    }
}

impl traits::SessionStore for InMemSignalProtocolStore {
    fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        self.session_store.load_session(address)
    }

    fn store_session(&mut self, address: &ProtocolAddress, record: &SessionRecord) -> Result<()> {
        self.session_store.store_session(address, record)
    }
}

impl traits::SenderKeyStore for InMemSignalProtocolStore {
    fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
    ) -> Result<()> {
        self.sender_key_store
            .store_sender_key(sender_key_name, record)
    }

    fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
    ) -> Result<Option<SenderKeyRecord>> {
        self.sender_key_store.load_sender_key(sender_key_name)
    }
}

impl traits::ProtocolStore for InMemSignalProtocolStore {}
