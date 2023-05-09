//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto;
use std::result::Result;

use prost::Message;
use subtle::ConstantTimeEq;

use crate::ratchet::{ChainKey, MessageKeys, RootKey};
use crate::{kem, IdentityKey, KeyPair, PrivateKey, PublicKey, SignalProtocolError};

use crate::consts;
use crate::proto::storage::{session_structure, RecordStructure, SessionStructure};
use crate::state::{KyberPreKeyId, PreKeyId, SignedPreKeyId};

/// A distinct error type to keep from accidentally propagating deserialization errors.
#[derive(Debug)]
pub(crate) struct InvalidSessionError(&'static str);

impl std::fmt::Display for InvalidSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<InvalidSessionError> for SignalProtocolError {
    fn from(e: InvalidSessionError) -> Self {
        Self::InvalidSessionStructure(e.0)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct UnacknowledgedPreKeyMessageItems<'a> {
    pre_key_id: Option<PreKeyId>,
    signed_pre_key_id: SignedPreKeyId,
    base_key: PublicKey,
    kyber_pre_key_id: Option<KyberPreKeyId>,
    kyber_ciphertext: Option<&'a [u8]>,
}

impl<'a> UnacknowledgedPreKeyMessageItems<'a> {
    fn new(
        pre_key_id: Option<PreKeyId>,
        signed_pre_key_id: SignedPreKeyId,
        base_key: PublicKey,
        pending_kyber_pre_key: Option<&'a session_structure::PendingKyberPreKey>,
    ) -> Self {
        let (kyber_pre_key_id, kyber_ciphertext) = pending_kyber_pre_key
            .map(|pending| (pending.pre_key_id.into(), pending.ciphertext.as_slice()))
            .unzip();
        Self {
            pre_key_id,
            signed_pre_key_id,
            base_key,
            kyber_pre_key_id,
            kyber_ciphertext,
        }
    }

    pub(crate) fn pre_key_id(&self) -> Option<PreKeyId> {
        self.pre_key_id
    }

    pub(crate) fn signed_pre_key_id(&self) -> SignedPreKeyId {
        self.signed_pre_key_id
    }

    pub(crate) fn base_key(&self) -> &PublicKey {
        &self.base_key
    }

    pub(crate) fn kyber_pre_key_id(&self) -> Option<KyberPreKeyId> {
        self.kyber_pre_key_id
    }

    pub(crate) fn kyber_ciphertext(&self) -> Option<&'a [u8]> {
        self.kyber_ciphertext
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SessionState {
    session: SessionStructure,
}

impl SessionState {
    pub(crate) fn from_session_structure(session: SessionStructure) -> Self {
        Self { session }
    }

    pub(crate) fn new(
        version: u8,
        our_identity: &IdentityKey,
        their_identity: &IdentityKey,
        root_key: &RootKey,
    ) -> Self {
        Self {
            session: SessionStructure {
                session_version: version as u32,
                local_identity_public: our_identity.public_key().serialize().to_vec(),
                remote_identity_public: their_identity.serialize().to_vec(),
                root_key: root_key.key().to_vec(),
                previous_counter: 0,
                sender_chain: None,
                receiver_chains: vec![],
                pending_pre_key: None,
                pending_kyber_pre_key: None,
                remote_registration_id: 0,
                local_registration_id: 0,
                alice_base_key: vec![],
            },
        }
    }

    pub(crate) fn alice_base_key(&self) -> &[u8] {
        // Check the length before returning?
        &self.session.alice_base_key
    }

    pub(crate) fn set_alice_base_key(&mut self, key: &[u8]) {
        // Should we check the length?
        self.session.alice_base_key = key.to_vec();
    }

    pub(crate) fn session_version(&self) -> Result<u32, InvalidSessionError> {
        match self.session.session_version {
            0 => Ok(2),
            v => Ok(v),
        }
    }

    pub(crate) fn remote_identity_key(&self) -> Result<Option<IdentityKey>, InvalidSessionError> {
        match self.session.remote_identity_public.len() {
            0 => Ok(None),
            _ => Ok(Some(
                IdentityKey::decode(&self.session.remote_identity_public)
                    .map_err(|_| InvalidSessionError("invalid remote identity key"))?,
            )),
        }
    }

    pub(crate) fn remote_identity_key_bytes(&self) -> Result<Option<Vec<u8>>, InvalidSessionError> {
        Ok(self.remote_identity_key()?.map(|k| k.serialize().to_vec()))
    }

    pub(crate) fn local_identity_key(&self) -> Result<IdentityKey, InvalidSessionError> {
        IdentityKey::decode(&self.session.local_identity_public)
            .map_err(|_| InvalidSessionError("invalid local identity key"))
    }

    pub(crate) fn local_identity_key_bytes(&self) -> Result<Vec<u8>, InvalidSessionError> {
        Ok(self.local_identity_key()?.serialize().to_vec())
    }

    pub(crate) fn session_with_self(&self) -> Result<bool, InvalidSessionError> {
        if let Some(remote_id) = self.remote_identity_key_bytes()? {
            let local_id = self.local_identity_key_bytes()?;
            return Ok(remote_id == local_id);
        }

        // If remote ID is not set then we can't be sure but treat as non-self
        Ok(false)
    }

    pub(crate) fn previous_counter(&self) -> u32 {
        self.session.previous_counter
    }

    pub(crate) fn set_previous_counter(&mut self, ctr: u32) {
        self.session.previous_counter = ctr;
    }

    pub(crate) fn root_key(&self) -> Result<RootKey, InvalidSessionError> {
        let root_key_bytes = self.session.root_key[..]
            .try_into()
            .map_err(|_| InvalidSessionError("invalid root key"))?;
        Ok(RootKey::new(root_key_bytes))
    }

    pub(crate) fn set_root_key(&mut self, root_key: &RootKey) {
        self.session.root_key = root_key.key().to_vec();
    }

    pub(crate) fn sender_ratchet_key(&self) -> Result<PublicKey, InvalidSessionError> {
        match self.session.sender_chain {
            None => Err(InvalidSessionError("missing sender chain")),
            Some(ref c) => PublicKey::deserialize(&c.sender_ratchet_key)
                .map_err(|_| InvalidSessionError("invalid sender chain ratchet key")),
        }
    }

    pub(crate) fn sender_ratchet_key_for_logging(&self) -> Result<String, InvalidSessionError> {
        Ok(hex::encode(
            self.sender_ratchet_key()?
                .public_key_bytes()
                .expect("no invalid public keys"),
        ))
    }

    pub(crate) fn sender_ratchet_private_key(&self) -> Result<PrivateKey, InvalidSessionError> {
        match self.session.sender_chain {
            None => Err(InvalidSessionError("missing sender chain")),
            Some(ref c) => PrivateKey::deserialize(&c.sender_ratchet_key_private)
                .map_err(|_| InvalidSessionError("invalid sender chain private ratchet key")),
        }
    }

    pub fn has_sender_chain(&self) -> Result<bool, InvalidSessionError> {
        Ok(self.session.sender_chain.is_some())
    }

    pub(crate) fn all_receiver_chain_logging_info(&self) -> Vec<(Vec<u8>, Option<u32>)> {
        let mut results = vec![];
        for chain in self.session.receiver_chains.iter() {
            let sender_ratchet_public = chain.sender_ratchet_key.clone();

            let chain_key_idx = chain.chain_key.as_ref().map(|chain_key| chain_key.index);

            results.push((sender_ratchet_public, chain_key_idx))
        }
        results
    }

    pub(crate) fn get_receiver_chain(
        &self,
        sender: &PublicKey,
    ) -> Result<Option<(session_structure::Chain, usize)>, InvalidSessionError> {
        for (idx, chain) in self.session.receiver_chains.iter().enumerate() {
            // If we compared bytes directly it would be faster, but may miss non-canonical points.
            // It's unclear if supporting such points is desirable.
            let chain_ratchet_key = PublicKey::deserialize(&chain.sender_ratchet_key)
                .map_err(|_| InvalidSessionError("invalid receiver chain ratchet key"))?;

            if &chain_ratchet_key == sender {
                return Ok(Some((chain.clone(), idx)));
            }
        }

        Ok(None)
    }

    pub(crate) fn get_receiver_chain_key(
        &self,
        sender: &PublicKey,
    ) -> Result<Option<ChainKey>, InvalidSessionError> {
        match self.get_receiver_chain(sender)? {
            None => Ok(None),
            Some((chain, _)) => match chain.chain_key {
                None => Err(InvalidSessionError("missing receiver chain key")),
                Some(c) => {
                    let chain_key_bytes = c.key[..]
                        .try_into()
                        .map_err(|_| InvalidSessionError("invalid receiver chain key"))?;
                    Ok(Some(ChainKey::new(chain_key_bytes, c.index)))
                }
            },
        }
    }

    pub(crate) fn add_receiver_chain(&mut self, sender: &PublicKey, chain_key: &ChainKey) {
        let chain_key = session_structure::chain::ChainKey {
            index: chain_key.index(),
            key: chain_key.key().to_vec(),
        };

        let chain = session_structure::Chain {
            sender_ratchet_key: sender.serialize().to_vec(),
            sender_ratchet_key_private: vec![],
            chain_key: Some(chain_key),
            message_keys: vec![],
        };

        self.session.receiver_chains.push(chain);

        if self.session.receiver_chains.len() > consts::MAX_RECEIVER_CHAINS {
            log::info!(
                "Trimming excessive receiver_chain for session with base key {}, chain count: {}",
                self.sender_ratchet_key_for_logging()
                    .unwrap_or_else(|e| format!("<error: {}>", e.0)),
                self.session.receiver_chains.len()
            );
            self.session.receiver_chains.remove(0);
        }
    }

    pub(crate) fn with_receiver_chain(mut self, sender: &PublicKey, chain_key: &ChainKey) -> Self {
        self.add_receiver_chain(sender, chain_key);
        self
    }

    pub(crate) fn set_sender_chain(&mut self, sender: &KeyPair, next_chain_key: &ChainKey) {
        let chain_key = session_structure::chain::ChainKey {
            index: next_chain_key.index(),
            key: next_chain_key.key().to_vec(),
        };

        let new_chain = session_structure::Chain {
            sender_ratchet_key: sender.public_key.serialize().to_vec(),
            sender_ratchet_key_private: sender.private_key.serialize().to_vec(),
            chain_key: Some(chain_key),
            message_keys: vec![],
        };

        self.session.sender_chain = Some(new_chain);
    }

    pub(crate) fn with_sender_chain(mut self, sender: &KeyPair, next_chain_key: &ChainKey) -> Self {
        self.set_sender_chain(sender, next_chain_key);
        self
    }

    pub(crate) fn get_sender_chain_key(&self) -> Result<ChainKey, InvalidSessionError> {
        let sender_chain = self
            .session
            .sender_chain
            .as_ref()
            .ok_or(InvalidSessionError("missing sender chain"))?;

        let chain_key = sender_chain
            .chain_key
            .as_ref()
            .ok_or(InvalidSessionError("missing sender chain key"))?;

        let chain_key_bytes = chain_key.key[..]
            .try_into()
            .map_err(|_| InvalidSessionError("invalid sender chain key"))?;

        Ok(ChainKey::new(chain_key_bytes, chain_key.index))
    }

    pub(crate) fn get_sender_chain_key_bytes(&self) -> Result<Vec<u8>, InvalidSessionError> {
        Ok(self.get_sender_chain_key()?.key().to_vec())
    }

    pub(crate) fn set_sender_chain_key(&mut self, next_chain_key: &ChainKey) {
        let chain_key = session_structure::chain::ChainKey {
            index: next_chain_key.index(),
            key: next_chain_key.key().to_vec(),
        };

        // Is it actually valid to call this function with sender_chain == None?

        let new_chain = match self.session.sender_chain.take() {
            None => session_structure::Chain {
                sender_ratchet_key: vec![],
                sender_ratchet_key_private: vec![],
                chain_key: Some(chain_key),
                message_keys: vec![],
            },
            Some(mut c) => {
                c.chain_key = Some(chain_key);
                c
            }
        };

        self.session.sender_chain = Some(new_chain);
    }

    pub(crate) fn get_message_keys(
        &mut self,
        sender: &PublicKey,
        counter: u32,
    ) -> Result<Option<MessageKeys>, InvalidSessionError> {
        if let Some(mut chain_and_index) = self.get_receiver_chain(sender)? {
            let message_key_idx = chain_and_index
                .0
                .message_keys
                .iter()
                .position(|m| m.index == counter);

            if let Some(position) = message_key_idx {
                let message_key = chain_and_index.0.message_keys.remove(position);

                let cipher_key_bytes = message_key
                    .cipher_key
                    .try_into()
                    .map_err(|_| InvalidSessionError("invalid message cipher key"))?;
                let mac_key_bytes = message_key
                    .mac_key
                    .try_into()
                    .map_err(|_| InvalidSessionError("invalid message MAC key"))?;
                let iv_bytes = message_key
                    .iv
                    .try_into()
                    .map_err(|_| InvalidSessionError("invalid message IV"))?;

                let keys = MessageKeys::new(cipher_key_bytes, mac_key_bytes, iv_bytes, counter);

                // Update with message key removed
                self.session.receiver_chains[chain_and_index.1] = chain_and_index.0;
                return Ok(Some(keys));
            }
        }

        Ok(None)
    }

    pub(crate) fn set_message_keys(
        &mut self,
        sender: &PublicKey,
        message_keys: &MessageKeys,
    ) -> Result<(), InvalidSessionError> {
        let new_keys = session_structure::chain::MessageKey {
            cipher_key: message_keys.cipher_key().to_vec(),
            mac_key: message_keys.mac_key().to_vec(),
            iv: message_keys.iv().to_vec(),
            index: message_keys.counter(),
        };

        let chain_and_index = self
            .get_receiver_chain(sender)?
            .expect("called set_message_keys for a non-existent chain");
        let mut updated_chain = chain_and_index.0;
        updated_chain.message_keys.insert(0, new_keys);

        if updated_chain.message_keys.len() > consts::MAX_MESSAGE_KEYS {
            updated_chain.message_keys.pop();
        }

        self.session.receiver_chains[chain_and_index.1] = updated_chain;

        Ok(())
    }

    pub(crate) fn set_receiver_chain_key(
        &mut self,
        sender: &PublicKey,
        chain_key: &ChainKey,
    ) -> Result<(), InvalidSessionError> {
        let chain_and_index = self
            .get_receiver_chain(sender)?
            .expect("called set_receiver_chain_key for a non-existent chain");
        let mut updated_chain = chain_and_index.0;
        updated_chain.chain_key = Some(session_structure::chain::ChainKey {
            index: chain_key.index(),
            key: chain_key.key().to_vec(),
        });

        self.session.receiver_chains[chain_and_index.1] = updated_chain;

        Ok(())
    }

    pub(crate) fn set_unacknowledged_pre_key_message(
        &mut self,
        pre_key_id: Option<PreKeyId>,
        signed_ec_pre_key_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) {
        let signed_ec_pre_key_id: u32 = signed_ec_pre_key_id.into();
        let pending = session_structure::PendingPreKey {
            pre_key_id: pre_key_id.map(PreKeyId::into),
            signed_pre_key_id: signed_ec_pre_key_id as i32,
            base_key: base_key.serialize().to_vec(),
        };
        self.session.pending_pre_key = Some(pending);
    }

    #[allow(clippy::boxed_local)]
    pub(crate) fn set_kyber_ciphertext(&mut self, ciphertext: kem::SerializedCiphertext) {
        let pending = session_structure::PendingKyberPreKey {
            pre_key_id: u32::MAX, // has to be set to the actual value separately
            ciphertext: ciphertext.to_vec(),
        };
        self.session.pending_kyber_pre_key = Some(pending);
    }

    pub(crate) fn set_unacknowledged_kyber_pre_key_id(
        &mut self,
        signed_kyber_pre_key_id: KyberPreKeyId,
    ) {
        let mut pending = self
            .session
            .pending_kyber_pre_key
            .as_mut()
            .expect("must have been set if kyber pre key is present");
        pending.pre_key_id = signed_kyber_pre_key_id.into();
    }

    pub(crate) fn unacknowledged_pre_key_message_items(
        &self,
    ) -> Result<Option<UnacknowledgedPreKeyMessageItems>, InvalidSessionError> {
        if let Some(ref pending_pre_key) = self.session.pending_pre_key {
            Ok(Some(UnacknowledgedPreKeyMessageItems::new(
                pending_pre_key.pre_key_id.map(Into::into),
                (pending_pre_key.signed_pre_key_id as u32).into(),
                PublicKey::deserialize(&pending_pre_key.base_key)
                    .map_err(|_| InvalidSessionError("invalid pending PreKey message base key"))?,
                self.session.pending_kyber_pre_key.as_ref(),
            )))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn clear_unacknowledged_pre_key_message(&mut self) {
        self.session.pending_pre_key = None;
    }

    pub(crate) fn set_remote_registration_id(&mut self, registration_id: u32) {
        self.session.remote_registration_id = registration_id;
    }

    pub(crate) fn remote_registration_id(&self) -> u32 {
        self.session.remote_registration_id
    }

    pub(crate) fn set_local_registration_id(&mut self, registration_id: u32) {
        self.session.local_registration_id = registration_id;
    }

    pub(crate) fn local_registration_id(&self) -> u32 {
        self.session.local_registration_id
    }

    pub(crate) fn get_kyber_ciphertext(&self) -> Option<&Vec<u8>> {
        self.session
            .pending_kyber_pre_key
            .as_ref()
            .map(|pending| &pending.ciphertext)
    }
}

impl From<SessionStructure> for SessionState {
    fn from(value: SessionStructure) -> SessionState {
        SessionState::from_session_structure(value)
    }
}

impl From<SessionState> for SessionStructure {
    fn from(value: SessionState) -> SessionStructure {
        value.session
    }
}

impl From<&SessionState> for SessionStructure {
    fn from(value: &SessionState) -> SessionStructure {
        value.session.clone()
    }
}

#[derive(Clone)]
pub struct SessionRecord {
    current_session: Option<SessionState>,
    previous_sessions: Vec<Vec<u8>>,
}

impl SessionRecord {
    pub fn new_fresh() -> Self {
        Self {
            current_session: None,
            previous_sessions: Vec::new(),
        }
    }

    pub(crate) fn new(state: SessionState) -> Self {
        Self {
            current_session: Some(state),
            previous_sessions: Vec::new(),
        }
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, SignalProtocolError> {
        let record = RecordStructure::decode(bytes)
            .map_err(|_| InvalidSessionError("failed to decode session record protobuf"))?;

        Ok(Self {
            current_session: record.current_session.map(|s| s.into()),
            previous_sessions: record.previous_sessions,
        })
    }

    pub fn from_single_session_state(bytes: &[u8]) -> Result<Self, SignalProtocolError> {
        let session = SessionState::from_session_structure(
            SessionStructure::decode(bytes)
                .map_err(|_| InvalidSessionError("failed to decode session state protobuf"))?,
        );
        Ok(Self {
            current_session: Some(session),
            previous_sessions: Vec::new(),
        })
    }

    pub(crate) fn has_session_state(
        &self,
        version: u32,
        alice_base_key: &[u8],
    ) -> Result<bool, InvalidSessionError> {
        if let Some(current_session) = &self.current_session {
            if current_session.session_version()? == version
                && alice_base_key
                    .ct_eq(current_session.alice_base_key())
                    .into()
            {
                return Ok(true);
            }
        }

        for previous in self.previous_session_states() {
            let previous = previous?;
            if previous.session_version()? == version
                && alice_base_key.ct_eq(previous.alice_base_key()).into()
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn has_current_session_state(&self) -> bool {
        self.current_session.is_some()
    }

    pub(crate) fn session_state(&self) -> Option<&SessionState> {
        self.current_session.as_ref()
    }

    pub(crate) fn session_state_mut(&mut self) -> Option<&mut SessionState> {
        self.current_session.as_mut()
    }

    pub(crate) fn set_session_state(&mut self, session: SessionState) {
        self.current_session = Some(session);
    }

    pub(crate) fn previous_session_states(
        &self,
    ) -> impl ExactSizeIterator<Item = Result<SessionState, InvalidSessionError>> + '_ {
        self.previous_sessions.iter().map(|bytes| {
            Ok(SessionStructure::decode(&bytes[..])
                .map_err(|_| InvalidSessionError("failed to decode previous session protobuf"))?
                .into())
        })
    }

    pub(crate) fn promote_old_session(
        &mut self,
        old_session: usize,
        updated_session: SessionState,
    ) {
        self.previous_sessions.remove(old_session);
        self.promote_state(updated_session)
    }

    pub(crate) fn promote_state(&mut self, new_state: SessionState) {
        self.archive_current_state_inner();
        self.current_session = Some(new_state);
    }

    // A non-fallible version of archive_current_state.
    fn archive_current_state_inner(&mut self) {
        if let Some(current_session) = self.current_session.take() {
            if self.previous_sessions.len() >= consts::ARCHIVED_STATES_MAX_LENGTH {
                self.previous_sessions.pop();
            }
            self.previous_sessions
                .insert(0, current_session.session.encode_to_vec());
        } else {
            log::info!("Skipping archive, current session state is fresh",);
        }
    }

    pub fn archive_current_state(&mut self) -> Result<(), SignalProtocolError> {
        self.archive_current_state_inner();
        Ok(())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, SignalProtocolError> {
        let record = RecordStructure {
            current_session: self.current_session.as_ref().map(|s| s.into()),
            previous_sessions: self.previous_sessions.clone(),
        };
        Ok(record.encode_to_vec())
    }

    pub fn remote_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "remote_registration_id",
                    "No current session".into(),
                )
            })?
            .remote_registration_id())
    }

    pub fn local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "local_registration_id",
                    "No current session".into(),
                )
            })?
            .local_registration_id())
    }

    pub fn session_version(&self) -> Result<u32, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState("session_version", "No current session".into())
            })?
            .session_version()?)
    }

    pub fn local_identity_key_bytes(&self) -> Result<Vec<u8>, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "local_identity_key_bytes",
                    "No current session".into(),
                )
            })?
            .local_identity_key_bytes()?)
    }

    pub fn remote_identity_key_bytes(&self) -> Result<Option<Vec<u8>>, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "remote_identity_key_bytes",
                    "No current session".into(),
                )
            })?
            .remote_identity_key_bytes()?)
    }

    pub fn has_sender_chain(&self) -> Result<bool, SignalProtocolError> {
        match &self.current_session {
            Some(session) => Ok(session.has_sender_chain()?),
            None => Ok(false),
        }
    }

    pub fn alice_base_key(&self) -> Result<&[u8], SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState("alice_base_key", "No current session".into())
            })?
            .alice_base_key())
    }

    pub fn get_receiver_chain_key_bytes(
        &self,
        sender: &PublicKey,
    ) -> Result<Option<Box<[u8]>>, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "get_receiver_chain_key",
                    "No current session".into(),
                )
            })?
            .get_receiver_chain_key(sender)?
            .map(|chain| chain.key()[..].into()))
    }

    pub fn get_sender_chain_key_bytes(&self) -> Result<Vec<u8>, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "get_sender_chain_key_bytes",
                    "No current session".into(),
                )
            })?
            .get_sender_chain_key_bytes()?)
    }

    pub fn current_ratchet_key_matches(
        &self,
        key: &PublicKey,
    ) -> Result<bool, SignalProtocolError> {
        match &self.current_session {
            Some(session) => Ok(&session.sender_ratchet_key()? == key),
            None => Ok(false),
        }
    }

    pub fn get_kyber_ciphertext(&self) -> Result<Option<&Vec<u8>>, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "get_kyber_ciphertext",
                    "No current session".into(),
                )
            })?
            .get_kyber_ciphertext())
    }
}
