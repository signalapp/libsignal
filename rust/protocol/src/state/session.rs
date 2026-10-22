//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::result::Result;
use std::time::{Duration, SystemTime};

use bitflags::bitflags;
use prost::Message;
use subtle::ConstantTimeEq;

use crate::proto::storage::{
    RecordStructure, SessionStructure, TahiniSessionManagementState, record_structure,
    session_structure,
};
use crate::protocol::CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION;
use crate::ratchet::{ChainKey, RootKey};
use crate::state::{KyberPreKeyId, PreKeyId, SignedPreKeyId};
use crate::tahini::{LastAct, SessionOrigin};
use crate::{
    IdentityKey, KeyPair, PrivateKey, PublicKey, SessionNotFound, SignalProtocolError, consts, kem,
};

// ── Error types ─────────────────────────────────────────────────────────────

/// A distinct error type to keep from accidentally propagating deserialization errors.
#[derive(Debug)]
pub(crate) struct InvalidSessionError(pub(crate) &'static str);

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
    // Although we require PQXDH for all new sessions now,
    // we may in theory have an existing X3DH unacknowledged session,
    // so we leave these optional for now.
    kyber_pre_key_id: Option<KyberPreKeyId>,
    kyber_ciphertext: Option<&'a [u8]>,
    timestamp: SystemTime,
}

impl<'a> UnacknowledgedPreKeyMessageItems<'a> {
    fn new(
        pre_key_id: Option<PreKeyId>,
        signed_pre_key_id: SignedPreKeyId,
        base_key: PublicKey,
        pending_kyber_pre_key: Option<&'a session_structure::PendingKyberPreKey>,
        timestamp: SystemTime,
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
            timestamp,
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

    pub(crate) fn timestamp(&self) -> SystemTime {
        self.timestamp
    }
}

bitflags! {
    /// Specifies which criteria make a session "usable" beyond simply having a present sender
    /// chain.
    ///
    /// These requirements are conjunctive, i.e. specifying `NotStale | EstablishedWithPqxdh` means
    /// the session must be neither stale nor established with X3DH.
    ///
    /// This struct is generated using the `bitflags` crate; the [`Flags`](::bitflags::Flags) trait
    /// provides most of its API surface. It can also use "classic" C bitflag syntax, with `|` for
    /// union and `&` for intersection (as shown above).
    #[repr(transparent)]
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct SessionUsabilityRequirements : u32 {
        /// Requires that a session not be stale.
        ///
        /// A non-stale session is one of the following:
        /// - "incoming", i.e. started by the peer
        /// - "acknowledged", i.e. started locally but received a response
        /// - no more than a few weeks old (the exact time is chosen by libsignal)
        const NotStale = 1 << 0;
        /// Requires that a session was established using PQXDH (or newer) rather than X3DH/X4DH.
        ///
        /// This includes unacknowledged sessions that are using PQXDH, since if they get a
        /// response, the peer is confirmed to be using PQXDH as well.
        const EstablishedWithPqxdh = 1 << 1;
        /// Requires that a session is using SPQR.
        ///
        /// **Warning:** This allows unacknowledged sessions that include SPQR in their PreKey
        /// messages. If the peer downgrades the session (by discarding the SPQR information) and
        /// the local client allows it, a session that is previously considered "usable" can become
        /// "not usable" upon receiving a response. Therefore, this should not be used to determine
        /// whether a session is usable unless future downgrades will also be rejected.
        const Spqr = 1 << 2;
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
        alice_base_key: &PublicKey,
        pq_ratchet_state: spqr::SerializedState,
    ) -> Self {
        Self {
            session: SessionStructure {
                session_version: version as u32,
                local_identity_public: our_identity.public_key().serialize().into_vec(),
                remote_identity_public: their_identity.serialize().into_vec(),
                root_key: root_key.key().to_vec(),
                previous_counter: 0,
                sender_chain: None,
                receiver_chains: vec![],
                pending_pre_key: None,
                pending_kyber_pre_key: None,
                remote_registration_id: 0,
                local_registration_id: 0,
                alice_base_key: alice_base_key.serialize().into_vec(),
                pq_ratchet_state,
                origin: SessionOrigin::Legacy.into(),
            },
        }
    }

    pub(crate) fn alice_base_key(&self) -> &[u8] {
        // Check the length before returning?
        &self.session.alice_base_key
    }

    /// The session ID (Tahini SID). This is the alice_base_key, which
    /// uniquely identifies a session and is already on the wire.
    pub(crate) fn session_id(&self) -> &[u8] {
        self.alice_base_key()
    }

    pub(crate) fn origin(&self) -> SessionOrigin {
        // Unknown enum values fall back to Legacy (the proto default), which is
        // already treated as Remote for policy purposes.
        SessionOrigin::try_from(self.session.origin).unwrap_or(SessionOrigin::Legacy)
    }

    pub(crate) fn set_origin(&mut self, origin: SessionOrigin) {
        self.session.origin = origin.into();
    }

    /// Whether the remote peer is aware of this session.
    ///
    /// True once the peer has responded, which is exactly when the session's
    /// unacknowledged pre-key is cleared. This is equivalent to "origin is not
    /// `LocalNew`" for Tahini-created sessions, and is additionally correct for
    /// migrated pre-Tahini sessions whose stored origin reads as `Legacy` but
    /// which still carry a pending pre-key (locally initiated, no response yet).
    ///
    // This predicate doesn't really belong on `SessionState` — it's Tahini
    // policy, and Tahini policy lives in tahini.rs. It's here, and keyed on
    // `pending_pre_key` rather than on `origin()`, because migrated pre-Tahini
    // sessions store their origin as `Legacy` regardless of which side
    // initiated, so origin alone can't tell us whether the peer has
    // acknowledged. The pending pre-key can. The pure-Tahini form would be
    // `self.origin() != SessionOrigin::LocalNew` (which is why `LocalAcked` is
    // a distinct origin state — to make that form meaningful), living in
    // tahini.rs. If the migrated-Legacy case stops mattering — or if some
    // other approach makes it irrelevant here — feel free to move this.
    pub(crate) fn is_known_by_peer(&self) -> bool {
        self.session.pending_pre_key.is_none()
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

    #[deprecated]
    #[allow(unused)]
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

    pub(crate) fn sender_ratchet_key(&self) -> Result<PublicKey, InvalidSessionError> {
        match self.session.sender_chain {
            None => Err(InvalidSessionError("missing sender chain")),
            Some(ref c) => PublicKey::deserialize(&c.sender_ratchet_key)
                .map_err(|_| InvalidSessionError("invalid sender chain ratchet key")),
        }
    }

    pub(crate) fn sender_ratchet_key_for_logging(&self) -> Result<String, InvalidSessionError> {
        Ok(hex::encode(self.sender_ratchet_key()?.public_key_bytes()))
    }

    pub(crate) fn sender_ratchet_private_key(&self) -> Result<PrivateKey, InvalidSessionError> {
        match self.session.sender_chain {
            None => Err(InvalidSessionError("missing sender chain")),
            Some(ref c) => PrivateKey::deserialize(&c.sender_ratchet_key_private)
                .map_err(|_| InvalidSessionError("invalid sender chain private ratchet key")),
        }
    }

    pub fn has_usable_sender_chain(
        &self,
        now: SystemTime,
        requirements: SessionUsabilityRequirements,
    ) -> Result<bool, InvalidSessionError> {
        if self.session.sender_chain.is_none() {
            return Ok(false);
        }
        if requirements.contains(SessionUsabilityRequirements::NotStale) {
            if let Some(pending_pre_key) = &self.session.pending_pre_key {
                let creation_timestamp =
                    SystemTime::UNIX_EPOCH + Duration::from_secs(pending_pre_key.timestamp);
                if creation_timestamp + consts::MAX_UNACKNOWLEDGED_SESSION_AGE < now {
                    return Ok(false);
                }
            }
        }
        #[allow(clippy::collapsible_if)]
        if requirements.contains(SessionUsabilityRequirements::EstablishedWithPqxdh) {
            if self.session_version()? <= CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION.into() {
                return Ok(false);
            }
        }
        #[allow(clippy::collapsible_if)]
        if requirements.contains(SessionUsabilityRequirements::Spqr) {
            if self.pq_ratchet_state().is_empty() {
                return Ok(false);
            }
        }
        Ok(true)
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

    pub(crate) fn set_unacknowledged_pre_key_message(
        &mut self,
        pre_key_id: Option<PreKeyId>,
        signed_ec_pre_key_id: SignedPreKeyId,
        base_key: &PublicKey,
        now: SystemTime,
    ) {
        let signed_ec_pre_key_id: u32 = signed_ec_pre_key_id.into();
        let pending = session_structure::PendingPreKey {
            pre_key_id: pre_key_id.map(PreKeyId::into),
            signed_pre_key_id: signed_ec_pre_key_id as i32,
            base_key: base_key.serialize().to_vec(),
            timestamp: now
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        self.session.pending_pre_key = Some(pending);
    }

    pub(crate) fn set_kyber_ciphertext(&mut self, ciphertext: kem::SerializedCiphertext) {
        let pending = session_structure::PendingKyberPreKey {
            pre_key_id: u32::MAX, // has to be set to the actual value separately
            ciphertext: ciphertext.into_vec(),
        };
        self.session.pending_kyber_pre_key = Some(pending);
    }

    pub(crate) fn set_unacknowledged_kyber_pre_key_id(
        &mut self,
        signed_kyber_pre_key_id: KyberPreKeyId,
    ) {
        let pending = self
            .session
            .pending_kyber_pre_key
            .as_mut()
            .expect("must have been set if kyber pre key is present");
        pending.pre_key_id = signed_kyber_pre_key_id.into();
    }

    pub(crate) fn unacknowledged_pre_key_message_items(
        &self,
    ) -> Result<Option<UnacknowledgedPreKeyMessageItems<'_>>, InvalidSessionError> {
        if let Some(ref pending_pre_key) = self.session.pending_pre_key {
            Ok(Some(UnacknowledgedPreKeyMessageItems::new(
                pending_pre_key.pre_key_id.map(Into::into),
                (pending_pre_key.signed_pre_key_id as u32).into(),
                PublicKey::deserialize(&pending_pre_key.base_key)
                    .map_err(|_| InvalidSessionError("invalid pending PreKey message base key"))?,
                self.session.pending_kyber_pre_key.as_ref(),
                SystemTime::UNIX_EPOCH + Duration::from_secs(pending_pre_key.timestamp),
            )))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn clear_unacknowledged_pre_key_message(&mut self) {
        // Explicitly destructuring the SessionStructure in case there are new
        // pending fields that need to be cleared.
        let SessionStructure {
            session_version: _session_version,
            local_identity_public: _local_identity_public,
            remote_identity_public: _remote_identity_public,
            root_key: _root_key,
            previous_counter: _previous_counter,
            sender_chain: _sender_chain,
            receiver_chains: _receiver_chains,
            pending_pre_key: _pending_pre_key,
            pending_kyber_pre_key: _pending_kyber_pre_key,
            remote_registration_id: _remote_registration_id,
            local_registration_id: _local_registration_id,
            alice_base_key: _alice_base_key,
            pq_ratchet_state: _pq_ratchet_state,
            origin: _origin,
        } = &self.session;
        // ####### IMPORTANT #######
        // Don't forget to clean up new pending fields.
        // ####### IMPORTANT #######
        self.session.pending_pre_key = None;
        self.session.pending_kyber_pre_key = None;
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

    /// Extract the Double Ratchet state from this session.
    ///
    /// This **moves** the receiver chains out of the session protobuf,
    /// leaving them empty. The caller must either apply the ratchet state
    /// back via [`apply_ratchet_state`](Self::apply_ratchet_state) or
    /// discard this `SessionState` entirely. Reading receiver chains from
    /// a taken session is invalid and will produce incorrect results.
    ///
    /// The caller must supply `self_session` (whether this is a note-to-self
    /// session) since it requires identity key comparison, which is above the
    /// ratchet layer.
    pub(crate) fn take_ratchet_state(
        &mut self,
        self_session: bool,
    ) -> crate::error::Result<crate::double_ratchet::RatchetState> {
        let receiver_chains = std::mem::take(&mut self.session.receiver_chains);
        Ok(crate::double_ratchet::RatchetState::from_pb(
            &self.session,
            self_session,
            receiver_chains,
        )?)
    }

    /// Write modified Double Ratchet state back into this session.
    ///
    /// Only the ratchet-relevant fields are updated; all other session
    /// fields (identity keys, pending pre-key, SPQR state, etc.) are
    /// left unchanged.
    pub(crate) fn apply_ratchet_state(&mut self, ratchet: crate::double_ratchet::RatchetState) {
        ratchet.apply_to_pb(&mut self.session);
    }

    pub(crate) fn pq_ratchet_state(&self) -> &spqr::SerializedState {
        &self.session.pq_ratchet_state
    }

    /// Move the PQ ratchet state out, leaving an empty vec in its place.
    ///
    /// The caller must either write a new PQ ratchet state back via
    /// [`set_pq_ratchet_state`](Self::set_pq_ratchet_state) or discard
    /// this `SessionState` entirely.
    pub(crate) fn take_pq_ratchet_state(&mut self) -> spqr::SerializedState {
        std::mem::take(&mut self.session.pq_ratchet_state)
    }

    pub(crate) fn set_pq_ratchet_state(&mut self, state: spqr::SerializedState) {
        self.session.pq_ratchet_state = state;
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
    /// Per-device-record session management state.
    ///
    /// `None` is a pre-Tahini (Sesame/legacy) record on disk; any
    /// Tahini-side mutation (`set_last_act`, `increment_direction_change_ctr`,
    /// etc.) auto-promotes this to `Some(default)`.
    session_management_state: Option<TahiniSessionManagementState>,
}

impl SessionRecord {
    pub fn new_fresh() -> Self {
        Self {
            current_session: None,
            previous_sessions: Vec::new(),
            session_management_state: Some(TahiniSessionManagementState::default()),
        }
    }

    pub(crate) fn new(state: SessionState) -> Self {
        Self {
            current_session: Some(state),
            previous_sessions: Vec::new(),
            session_management_state: Some(TahiniSessionManagementState::default()),
        }
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, SignalProtocolError> {
        let record = RecordStructure::decode(bytes)
            .map_err(|_| InvalidSessionError("failed to decode session record protobuf"))?;

        let session_management_state = record.session_management_state.map(|sm| match sm {
            record_structure::SessionManagementState::Tahini(state) => state,
        });

        Ok(Self {
            current_session: record.current_session.map(|s| s.into()),
            previous_sessions: record.previous_sessions,
            session_management_state,
        })
    }

    pub(crate) fn active_session(&self) -> Option<&SessionState> {
        self.current_session.as_ref()
    }

    pub(crate) fn active_session_mut(&mut self) -> Option<&mut SessionState> {
        self.current_session.as_mut()
    }

    pub(crate) fn set_active_session(&mut self, session: SessionState) {
        self.current_session = Some(session);
    }

    pub(crate) fn archived_sessions(
        &self,
    ) -> impl ExactSizeIterator<Item = Result<SessionState, InvalidSessionError>> + '_ {
        self.previous_sessions.iter().map(|bytes| {
            Ok(SessionStructure::decode(&bytes[..])
                .map_err(|_| InvalidSessionError("failed to decode previous session protobuf"))?
                .into())
        })
    }

    /// The number of archived (previous) sessions retained in this record.
    pub fn archived_session_count(&self) -> usize {
        self.previous_sessions.len()
    }

    /// Archives the current active session (if any) and sets `new_state` as active.
    pub(crate) fn replace_active_session(&mut self, new_state: SessionState) {
        if let Some(s) = self.current_session.take() {
            self.archive_session(s);
        }
        self.current_session = Some(new_state);
    }

    pub fn archive_current_state(&mut self) -> Result<(), SignalProtocolError> {
        match self.current_session.take() {
            Some(s) => self.archive_session(s),
            None => log::info!("archive_current_state: no active session to archive"),
        }
        Ok(())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, SignalProtocolError> {
        let record = RecordStructure {
            current_session: self.current_session.as_ref().map(|s| s.into()),
            previous_sessions: self.previous_sessions.clone(),
            session_management_state: self
                .session_management_state
                .map(record_structure::SessionManagementState::Tahini),
        };
        Ok(record.encode_to_vec())
    }

    pub fn current_pq_state(&self) -> Option<&spqr::SerializedState> {
        self.current_session.as_ref().map(|s| s.pq_ratchet_state())
    }

    pub fn remote_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self
            .active_session()
            .ok_or_else(|| {
                SignalProtocolError::SessionNotFound(SessionNotFound::without_address(
                    "remote_registration_id",
                ))
            })?
            .remote_registration_id())
    }

    pub fn local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self
            .active_session()
            .ok_or_else(|| {
                SignalProtocolError::SessionNotFound(SessionNotFound::without_address(
                    "local_registration_id",
                ))
            })?
            .local_registration_id())
    }

    pub fn session_version(&self) -> Result<u32, SignalProtocolError> {
        Ok(self
            .active_session()
            .ok_or_else(|| {
                SignalProtocolError::SessionNotFound(SessionNotFound::without_address(
                    "session_version",
                ))
            })?
            .session_version()?)
    }

    pub fn local_identity_key_bytes(&self) -> Result<Vec<u8>, SignalProtocolError> {
        Ok(self
            .active_session()
            .ok_or_else(|| {
                SignalProtocolError::SessionNotFound(SessionNotFound::without_address(
                    "local_identity_key_bytes",
                ))
            })?
            .local_identity_key_bytes()?)
    }

    pub fn remote_identity_key_bytes(&self) -> Result<Option<Vec<u8>>, SignalProtocolError> {
        Ok(self
            .active_session()
            .ok_or_else(|| {
                SignalProtocolError::SessionNotFound(SessionNotFound::without_address(
                    "remote_identity_key_bytes",
                ))
            })?
            .remote_identity_key_bytes()?)
    }

    pub fn has_usable_sender_chain(
        &self,
        now: SystemTime,
        requirements: SessionUsabilityRequirements,
    ) -> Result<bool, SignalProtocolError> {
        match &self.current_session {
            Some(session) => Ok(session.has_usable_sender_chain(now, requirements)?),
            None => Ok(false),
        }
    }

    pub fn alice_base_key(&self) -> Result<&[u8], SignalProtocolError> {
        Ok(self
            .active_session()
            .ok_or_else(|| {
                SignalProtocolError::SessionNotFound(SessionNotFound::without_address(
                    "alice_base_key",
                ))
            })?
            .alice_base_key())
    }

    pub fn get_receiver_chain_key_bytes(
        &self,
        sender: &PublicKey,
    ) -> Result<Option<Box<[u8]>>, SignalProtocolError> {
        Ok(self
            .active_session()
            .ok_or_else(|| {
                SignalProtocolError::SessionNotFound(SessionNotFound::without_address(
                    "get_receiver_chain_key",
                ))
            })?
            .get_receiver_chain_key(sender)?
            .map(|chain| chain.key()[..].into()))
    }

    pub fn get_sender_chain_key_bytes(&self) -> Result<Vec<u8>, SignalProtocolError> {
        Ok(self
            .active_session()
            .ok_or_else(|| {
                SignalProtocolError::SessionNotFound(SessionNotFound::without_address(
                    "get_sender_chain_key_bytes",
                ))
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
            .active_session()
            .ok_or_else(|| {
                SignalProtocolError::SessionNotFound(SessionNotFound::without_address(
                    "get_kyber_ciphertext",
                ))
            })?
            .get_kyber_ciphertext())
    }

    // ── Tahini session management ───────────────────────────────────
    //
    // Reads on a legacy (None) record see Tahini defaults (last_act=Send,
    // ctr=0). The first write auto-promotes the record to Tahini.
    //
    // last_act defaults to Send (the proto enum-0 value) when a record carries no
    // Tahini state: a legacy record predates the counter, and Send is a safe
    // starting point -- it costs at most one direction change, against a threshold
    // of MAX_DIR_CHANGES, if that record's first Tahini action is a receive on an
    // inactive session.
    //
    // LastAct::Unset is a distinct value, never the default. It is written by
    // `on_initiate` for a freshly established session that has taken no action
    // yet, so its first send is not counted as a direction change (see tahini.rs).

    pub(crate) fn last_act(&self) -> LastAct {
        let raw = self
            .session_management_state
            .as_ref()
            .map(|s| s.last_act)
            .unwrap_or_default();
        LastAct::try_from(raw).unwrap_or(LastAct::Send)
    }

    pub(crate) fn set_last_act(&mut self, act: LastAct) {
        self.session_management_state
            .get_or_insert_with(TahiniSessionManagementState::default)
            .last_act = act.into();
    }

    pub(crate) fn direction_change_ctr(&self) -> u32 {
        self.session_management_state
            .as_ref()
            .map(|s| s.direction_change_ctr)
            .unwrap_or(0)
    }

    pub(crate) fn increment_direction_change_ctr(&mut self) {
        self.session_management_state
            .get_or_insert_with(TahiniSessionManagementState::default)
            .direction_change_ctr += 1;
    }

    pub(crate) fn reset_direction_change_ctr(&mut self) {
        if let Some(state) = self.session_management_state.as_mut() {
            state.direction_change_ctr = 0;
        }
    }

    /// Update an archived session in place (write back ratchet state
    /// after decryption without promoting).
    pub(crate) fn update_archived_session(
        &mut self,
        index: usize,
        updated: SessionState,
    ) -> Result<(), SignalProtocolError> {
        assert!(
            index < self.previous_sessions.len(),
            "update_archived_session: index {index} out of bounds (len {})",
            self.previous_sessions.len()
        );
        let prev =
            SessionStructure::decode(self.previous_sessions[index].as_slice()).map_err(|_| {
                SignalProtocolError::InvalidSessionStructure(
                    "update_archived_session: stored archived session failed to decode",
                )
            })?;
        assert!(
            prev.alice_base_key == updated.alice_base_key(),
            "update_archived_session: attempting to update session at index {index} but base key doesn't match."
        );
        let structure: SessionStructure = updated.into();
        self.previous_sessions[index] = structure.encode_to_vec();
        Ok(())
    }

    /// Where a session with the given `session_id` lives in this record.
    pub(crate) fn find_session_by_id(
        &self,
        session_id: &[u8],
    ) -> Result<Option<SessionLocation>, InvalidSessionError> {
        if let Some(current) = &self.current_session {
            if session_id.ct_eq(current.session_id()).into() {
                return Ok(Some(SessionLocation::Current));
            }
        }

        for (i, previous) in self.archived_sessions().enumerate() {
            if session_id.ct_eq(previous?.session_id()).into() {
                return Ok(Some(SessionLocation::Archived(i)));
            }
        }

        Ok(None)
    }

    pub(crate) fn get_session(
        &self,
        loc: SessionLocation,
    ) -> Result<Option<SessionState>, SignalProtocolError> {
        match loc {
            SessionLocation::Current => Ok(self.current_session.clone()),
            SessionLocation::Archived(idx) => {
                assert!(
                    idx < self.previous_sessions.len(),
                    "get_session: archived index {idx} out of bounds (len {})",
                    self.previous_sessions.len()
                );
                Ok(Some(SessionState {
                    session: SessionStructure::decode(self.previous_sessions[idx].as_ref())
                        .map_err(|_| {
                            InvalidSessionError("failed to decode previous session protobuf")
                        })?,
                }))
            }
        }
    }

    pub(crate) fn update_session_state(
        &mut self,
        loc: SessionLocation,
        state: SessionState,
    ) -> Result<(), SignalProtocolError> {
        match loc {
            SessionLocation::Current => {
                let current_session = self
                    .current_session
                    .as_ref()
                    .expect("accessing current session at validated location");
                assert!(current_session.alice_base_key() == state.alice_base_key());
                self.current_session = Some(state);
                Ok(())
            }
            SessionLocation::Archived(idx) => self.update_archived_session(idx, state),
        }
    }

    /// Put a session directly into the archive (e.g., tiebreaker loser).
    ///
    /// Enforces [`MAX_ARCHIVED_SESSIONS`](consts::MAX_ARCHIVED_SESSIONS);
    /// the oldest sessions are dropped until the archive has room.
    pub(crate) fn archive_session(&mut self, mut session: SessionState) {
        while self.previous_sessions.len() >= consts::MAX_ARCHIVED_SESSIONS {
            self.previous_sessions.pop();
        }
        crate::tahini::on_archive(&mut session);
        let structure: SessionStructure = session.into();
        self.previous_sessions.insert(0, structure.encode_to_vec());
    }
}

/// Result of [`SessionRecord::find_session_by_id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionLocation {
    Current,
    Archived(usize),
}
