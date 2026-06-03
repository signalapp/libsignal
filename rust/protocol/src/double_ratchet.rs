//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Double Ratchet implementation.
//!
//! The root key, sender chain, and counters are deserialized into typed
//! fields. Receiver chains are kept in protobuf form and deserialized
//! lazily on demand.
//!
//! References:
//! - [Double Ratchet spec](https://signal.org/docs/specifications/doubleratchet/)

use rand::{CryptoRng, Rng};

use crate::proto::storage::{SessionStructure, session_structure};
use crate::ratchet::{ChainKey, MessageKeyGenerator, RootKey};
use crate::state::InvalidSessionError;
use crate::{
    CiphertextMessageType, KeyPair, PrivateKey, PublicKey, Result, SignalProtocolError, consts,
};

// ── State ────────────────────────────────────────────────────────────

/// The state of a Double Ratchet session.
///
/// Contains the root key, sending and receiving chains, and cached
/// message keys for out-of-order messages. Receiver chains are stored
/// in protobuf form and deserialized lazily on demand.
#[derive(Clone)]
pub(crate) struct RatchetState {
    pub root_key: RootKey,
    pub sender_chain: Option<SenderChain>,
    pub receiver_chains: Vec<session_structure::Chain>,
    pub previous_counter: u32,
    /// Maximum number of messages we'll skip ahead in a single chain.
    /// Set to `consts::MAX_FORWARD_JUMPS` for normal sessions,
    /// `usize::MAX` for self-sessions (note-to-self), following the
    /// same pattern as SPQR's `max_jump` chain parameter.
    pub max_forward_jumps: usize,
}

/// The sending side of a ratchet: our current ephemeral key pair and
/// the chain key for encrypting outgoing messages.
#[derive(Clone)]
pub(crate) struct SenderChain {
    pub ratchet_key: KeyPair,
    pub chain_key: ChainKey,
}

// Receiver chains are stored as raw `session_structure::Chain` protobuf in
// `RatchetState::receiver_chains`. Only the ratchet key and chain key are
// deserialized on demand; skipped message keys stay in protobuf form and are
// only deserialized individually when a matching counter is found.

// ── Serialization bridge ──────────────────────────────────────────────

impl RatchetState {
    /// Deserialize the ratchet-relevant fields from a `SessionStructure`.
    ///
    /// Only reads root key, counters, and sender chain from `session`.
    /// Receiver chains are passed in separately (moved, not cloned) by
    /// the caller.
    ///
    /// Identity keys, registration IDs, pending pre-key state, and SPQR
    /// state are owned by higher layers and are not touched here.
    ///
    /// `self_session` must be computed by the caller (requires identity
    /// key comparison, which is not ratchet-layer knowledge).
    pub(crate) fn from_pb(
        session: &SessionStructure,
        self_session: bool,
        receiver_chains: Vec<session_structure::Chain>,
    ) -> std::result::Result<Self, InvalidSessionError> {
        let root_key_bytes: [u8; 32] = session
            .root_key
            .as_slice()
            .try_into()
            .map_err(|_| InvalidSessionError("invalid root key"))?;

        let sender_chain = session
            .sender_chain
            .as_ref()
            .map(SenderChain::from_pb)
            .transpose()?;

        Ok(Self {
            root_key: RootKey::new(root_key_bytes),
            sender_chain,
            receiver_chains,
            previous_counter: session.previous_counter,
            max_forward_jumps: if self_session {
                usize::MAX
            } else {
                consts::MAX_FORWARD_JUMPS
            },
        })
    }

    /// Write the ratchet state back into a `SessionStructure`.
    ///
    /// Only updates the ratchet-relevant fields; all other fields in
    /// `session` are left unchanged.
    pub(crate) fn apply_to_pb(self, session: &mut SessionStructure) {
        let Self {
            root_key,
            sender_chain,
            receiver_chains,
            previous_counter,
            max_forward_jumps: _, // not serialized; derived from session context
        } = self;
        session.root_key = root_key.key().to_vec();
        session.previous_counter = previous_counter;
        session.sender_chain = sender_chain.as_ref().map(SenderChain::to_pb);
        session.receiver_chains = receiver_chains;
    }
}

impl SenderChain {
    fn from_pb(chain: &session_structure::Chain) -> std::result::Result<Self, InvalidSessionError> {
        let public_key = PublicKey::deserialize(&chain.sender_ratchet_key)
            .map_err(|_| InvalidSessionError("invalid sender ratchet public key"))?;
        let private_key = PrivateKey::deserialize(&chain.sender_ratchet_key_private)
            .map_err(|_| InvalidSessionError("invalid sender ratchet private key"))?;
        let chain_key = ChainKey::from_pb(
            chain
                .chain_key
                .as_ref()
                .ok_or(InvalidSessionError("missing sender chain key"))?,
        )?;
        Ok(Self {
            ratchet_key: KeyPair {
                public_key,
                private_key,
            },
            chain_key,
        })
    }

    fn to_pb(&self) -> session_structure::Chain {
        session_structure::Chain {
            sender_ratchet_key: self.ratchet_key.public_key.serialize().to_vec(),
            sender_ratchet_key_private: self.ratchet_key.private_key.serialize().to_vec(),
            chain_key: Some(self.chain_key.to_pb()),
            message_keys: vec![],
        }
    }
}

impl ChainKey {
    fn from_pb(
        pb: &session_structure::chain::ChainKey,
    ) -> std::result::Result<Self, InvalidSessionError> {
        let key: [u8; 32] = pb
            .key
            .as_slice()
            .try_into()
            .map_err(|_| InvalidSessionError("invalid chain key"))?;
        Ok(Self::new(key, pb.index))
    }

    fn to_pb(&self) -> session_structure::chain::ChainKey {
        session_structure::chain::ChainKey {
            index: self.index(),
            key: self.key().to_vec(),
        }
    }
}

// ── Operations ───────────────────────────────────────────────────────

impl RatchetState {
    fn take_root_key(&mut self) -> RootKey {
        std::mem::replace(&mut self.root_key, RootKey::new([0; 32]))
    }

    /// Ensure a receiver chain exists for a remote ephemeral key, returning
    /// its chain key.
    ///
    /// If we already have a receiver chain for `their_ephemeral`, return
    /// its chain key. Otherwise, perform a DH ratchet step: derive a new
    /// receiver chain from the current root key and the remote ephemeral,
    /// then generate a fresh sender chain.
    pub fn ensure_receiver_chain<R: Rng + CryptoRng>(
        &mut self,
        their_ephemeral: &PublicKey,
        csprng: &mut R,
    ) -> Result<ChainKey> {
        if let Some(chain_key) = self.find_receiver_chain_key(their_ephemeral)? {
            return Ok(chain_key);
        }

        self.dh_ratchet_step(their_ephemeral, csprng)
    }

    /// Consume the message key for a specific counter value.
    ///
    /// If the counter is behind the current chain index, take a cached
    /// (skipped) key. If it's ahead, advance the chain — caching the
    /// intermediate keys for out-of-order delivery — up to `max_forward_jumps`.
    /// Either way, the key is consumed and cannot be retrieved again.
    pub fn consume_message_key(
        &mut self,
        their_ephemeral: &PublicKey,
        mut chain_key: ChainKey,
        counter: u32,
        // The original message type, for error reporting only.
        original_message_type: CiphertextMessageType,
        remote_address_for_logging: &str,
    ) -> Result<MessageKeyGenerator> {
        let chain_index = chain_key.index();

        if chain_index > counter {
            // Counter is in the past — look up a cached key.
            return self
                .take_skipped_key(their_ephemeral, counter)?
                .ok_or_else(|| {
                    log::info!(
                        "{remote_address_for_logging} Duplicate message for counter: {counter}"
                    );
                    SignalProtocolError::DuplicatedMessage(chain_index, counter)
                });
        }

        let jump = (counter - chain_index) as usize;
        if jump > self.max_forward_jumps {
            log::error!(
                "{remote_address_for_logging} Exceeded future message limit: {}, index: {chain_index}, counter: {counter}",
                self.max_forward_jumps,
            );
            return Err(SignalProtocolError::InvalidMessage(
                original_message_type,
                "message from too far into the future",
            ));
        } else if jump > consts::MAX_FORWARD_JUMPS {
            // This only happens if it is a session with self
            log::info!(
                "{remote_address_for_logging} Jumping ahead {jump} messages (index: {chain_index}, counter: {counter})"
            );
        }

        // Advance the chain to the target counter, caching skipped keys.
        while chain_key.index() < counter {
            self.store_skipped_key(their_ephemeral, chain_key.message_keys());
            chain_key = chain_key.next_chain_key();
        }

        // Update the receiver chain to the next key past the one we're returning.
        self.set_receiver_chain_key(their_ephemeral, chain_key.next_chain_key());

        Ok(chain_key.message_keys())
    }

    // ── Internals ────────────────────────────────────────────────────

    fn find_receiver_chain_key(
        &self,
        their_ephemeral: &PublicKey,
    ) -> std::result::Result<Option<ChainKey>, InvalidSessionError> {
        let Some(idx) = self.find_receiver_chain_index(their_ephemeral) else {
            return Ok(None);
        };
        let chain_key_pb = self.receiver_chains[idx]
            .chain_key
            .as_ref()
            .ok_or(InvalidSessionError("missing receiver chain key"))?;
        Ok(Some(ChainKey::from_pb(chain_key_pb)?))
    }

    fn dh_ratchet_step<R: Rng + CryptoRng>(
        &mut self,
        their_ephemeral: &PublicKey,
        csprng: &mut R,
    ) -> Result<ChainKey> {
        let sender_private_key = self
            .sender_chain
            .as_ref()
            .ok_or(InvalidSessionError("missing sender chain"))?
            .ratchet_key
            .private_key;

        // Receiving half-step: root_key + DH(our_sender, their_ephemeral)
        let current_root_key = self.take_root_key();
        let (new_root_key, receiver_chain_key) =
            current_root_key.create_chain(their_ephemeral, &sender_private_key)?;

        // Sending half-step: new_root_key + DH(new_ephemeral, their_ephemeral)
        let new_sender_key = KeyPair::generate(csprng);
        let (final_root_key, sender_chain_key) =
            new_root_key.create_chain(their_ephemeral, &new_sender_key.private_key)?;

        // Record the previous sender chain counter before we replace it.
        let current_index = self
            .sender_chain
            .as_ref()
            .expect("checked above")
            .chain_key
            .index();
        self.previous_counter = current_index.saturating_sub(1);

        self.root_key = final_root_key;

        self.receiver_chains.push(session_structure::Chain {
            sender_ratchet_key: their_ephemeral.serialize().to_vec(),
            sender_ratchet_key_private: vec![],
            chain_key: Some(receiver_chain_key.to_pb()),
            message_keys: vec![],
        });
        while self.receiver_chains.len() > consts::MAX_RECEIVER_CHAINS {
            self.receiver_chains.remove(0);
        }

        self.sender_chain = Some(SenderChain {
            ratchet_key: new_sender_key,
            chain_key: sender_chain_key,
        });

        Ok(receiver_chain_key)
    }

    fn take_skipped_key(
        &mut self,
        their_ephemeral: &PublicKey,
        counter: u32,
    ) -> std::result::Result<Option<MessageKeyGenerator>, InvalidSessionError> {
        let Some(chain_idx) = self.find_receiver_chain_index(their_ephemeral) else {
            return Ok(None);
        };
        let keys = &mut self.receiver_chains[chain_idx].message_keys;

        // Scan by protobuf index field — no deserialization needed for non-matches.
        let Some(pos) = keys.iter().position(|mk| mk.index == counter) else {
            return Ok(None);
        };

        // Remove before deserializing. If from_pb fails the key was corrupt
        // and unrecoverable — slightly different from main which preserves it,
        // but the outcome (error) is the same.
        let key_pb = keys.remove(pos);
        MessageKeyGenerator::from_pb(key_pb)
            .map(Some)
            .map_err(InvalidSessionError)
    }

    fn store_skipped_key(&mut self, their_ephemeral: &PublicKey, key: MessageKeyGenerator) {
        let chain_idx = self
            .find_receiver_chain_index(their_ephemeral)
            .expect("store_skipped_key called for non-existent chain");
        let keys = &mut self.receiver_chains[chain_idx].message_keys;

        // TODO: This insert(0) is O(n), making the skip-ahead loop O(n²).
        // We could switch to push() (appending newest at end) with rposition()
        // for search and remove(0) for trimming. That makes the common path
        // O(1) per key. Deferred because it changes serialized key order,
        // breaking bit-for-bit compatibility with the legacy implementation.
        keys.insert(0, key.into_pb());
        if keys.len() > consts::MAX_MESSAGE_KEYS {
            keys.pop();
        }
    }

    fn set_receiver_chain_key(&mut self, their_ephemeral: &PublicKey, chain_key: ChainKey) {
        let chain_idx = self
            .find_receiver_chain_index(their_ephemeral)
            .expect("set_receiver_chain_key called for non-existent chain");
        self.receiver_chains[chain_idx].chain_key = Some(chain_key.to_pb());
    }

    fn find_receiver_chain_index(&self, their_ephemeral: &PublicKey) -> Option<usize> {
        self.receiver_chains.iter().position(|chain| {
            match PublicKey::deserialize(&chain.sender_ratchet_key) {
                Ok(key) => &key == their_ephemeral,
                Err(_) => {
                    log::warn!("skipping corrupt receiver chain with invalid ratchet key");
                    false
                }
            }
        })
    }
}
