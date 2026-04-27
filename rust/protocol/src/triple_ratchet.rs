//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! The Triple Ratchet: Double Ratchet + SPQR combined into a single
//! encrypt/decrypt interface.
//!
//! Handles MAC computation/verification and AES-CBC encryption/decryption.
//!
//! The session management layer treats this as an opaque box: give it
//! plaintext, get ciphertext; give it ciphertext, get plaintext. Identity
//! checking, session selection, pre-key handling, and storage are NOT
//! this layer's concern.

use rand::{CryptoRng, Rng};

use crate::double_ratchet::RatchetState;
use crate::ratchet::ChainKey;
use crate::session_management::CurrentOrPrevious;
use crate::state::SessionState;
use crate::{
    CiphertextMessageType, IdentityKey, KeyPair, ProtocolAddress, Result, SignalMessage,
    SignalProtocolError,
};

/// Sender-side Triple Ratchet session.
///
/// This is intentionally narrower than [`TripleRatchet`]: encrypt only
/// depends on the current sender chain, SPQR state, identities, and metadata.
/// It does not deserialize receiver chains, so corrupt cold receiver-chain
/// state does not block sending.
///
/// # Ownership contract
///
/// [`from_session_state`](Self::from_session_state) **moves** the PQ ratchet
/// state out of the session (via [`SessionState::take_pq_ratchet_state`]),
/// leaving it temporarily invalid. The caller must either call
/// [`apply_to_session_state`](Self::apply_to_session_state) on success, or
/// discard the `SessionState` entirely.
pub(crate) struct OutgoingTripleRatchet {
    sender_ratchet_key: KeyPair,
    sender_chain_key: ChainKey,
    previous_counter: u32,
    pqr_state: spqr::SerializedState,
    session_version: u8,
    local_identity_key: IdentityKey,
    remote_identity_key: IdentityKey,
}

impl OutgoingTripleRatchet {
    pub(crate) fn from_session_state(state: &mut SessionState) -> Result<Self> {
        let sender_ratchet_key = KeyPair {
            public_key: state.sender_ratchet_key()?,
            private_key: state.sender_ratchet_private_key()?,
        };
        let sender_chain_key = state.get_sender_chain_key()?;
        let pqr_state = state.take_pq_ratchet_state();
        let session_version: u8 = state.session_version()?.try_into().map_err(|_| {
            SignalProtocolError::InvalidSessionStructure("version does not fit in u8")
        })?;
        let local_identity_key = state.local_identity_key()?;
        let remote_identity_key =
            state
                .remote_identity_key()?
                .ok_or(SignalProtocolError::InvalidSessionStructure(
                    "missing remote identity key",
                ))?;

        Ok(Self {
            sender_ratchet_key,
            sender_chain_key,
            previous_counter: state.previous_counter(),
            pqr_state,
            session_version,
            local_identity_key,
            remote_identity_key,
        })
    }

    pub(crate) fn apply_to_session_state(self, state: &mut SessionState) {
        state.set_sender_chain_key(&self.sender_chain_key);
        state.set_pq_ratchet_state(self.pqr_state);
    }

    pub(crate) fn encrypt<R: Rng + CryptoRng>(
        &mut self,
        plaintext: &[u8],
        local_address: Option<&ProtocolAddress>,
        remote_address: &ProtocolAddress,
        csprng: &mut R,
    ) -> Result<SignalMessage> {
        let spqr::Send {
            state: new_pqr_state,
            key: pqr_key,
            msg: pqr_msg,
        } = spqr::send(&self.pqr_state, csprng).map_err(|e| {
            SignalProtocolError::InvalidState(
                "encrypt",
                format!("post-quantum ratchet send error: {e}"),
            )
        })?;

        let message_keys = self.sender_chain_key.message_keys().generate_keys(pqr_key);

        let ctext = signal_crypto::aes_256_cbc_encrypt(
            plaintext,
            message_keys.cipher_key(),
            message_keys.iv(),
        )
        .map_err(|_| {
            log::error!("session state corrupt for {remote_address}");
            SignalProtocolError::InvalidSessionStructure("invalid sender chain message keys")
        })?;

        let addresses = local_address.map(|addr| (addr, remote_address));

        let message = SignalMessage::new(
            self.session_version,
            message_keys.mac_key(),
            addresses,
            self.sender_ratchet_key.public_key,
            self.sender_chain_key.index(),
            self.previous_counter,
            &ctext,
            &self.local_identity_key,
            &self.remote_identity_key,
            &pqr_msg,
        )?;

        self.sender_chain_key = self.sender_chain_key.next_chain_key();
        self.pqr_state = new_pqr_state;

        Ok(message)
    }

    pub(crate) fn session_version(&self) -> u8 {
        self.session_version
    }

    pub(crate) fn local_identity_key(&self) -> &IdentityKey {
        &self.local_identity_key
    }
}

/// A Triple Ratchet session combining Double Ratchet and SPQR.
///
/// Constructed from a [`SessionState`], this extracts the cryptographic
/// state needed for decrypt into typed fields. After a successful
/// operation, call [`apply_to_session_state`](Self::apply_to_session_state)
/// to write the updated state back.
///
/// # Ownership contract
///
/// [`from_session_state`](Self::from_session_state) **moves** the receiver
/// chains and PQ ratchet state out of the session, leaving it temporarily invalid.
/// The caller must either:
/// - Call [`apply_to_session_state`](Self::apply_to_session_state) on success, or
/// - Discard the `SessionState` (e.g., it was a clone for trial decrypt).
pub(crate) struct TripleRatchet {
    ratchet: RatchetState,
    pqr_state: spqr::SerializedState,
    local_identity_key: IdentityKey,
    remote_identity_key: IdentityKey,
}

impl TripleRatchet {
    /// Construct from a [`SessionState`] by extracting crypto state.
    ///
    /// This moves receiver chains and PQ ratchet state out of `state`.
    /// See the [ownership contract](Self#ownership-contract) for details.
    ///
    /// Fails if the session is missing required fields (root key, identity
    /// keys, etc.). The caller should map the error appropriately for the
    /// context (e.g., "no session available to decrypt").
    pub(crate) fn from_session_state(state: &mut SessionState, self_session: bool) -> Result<Self> {
        let ratchet = state.take_ratchet_state(self_session)?;
        let pqr_state = state.take_pq_ratchet_state();
        let local_identity_key = state.local_identity_key()?;
        let remote_identity_key =
            state
                .remote_identity_key()?
                .ok_or(SignalProtocolError::InvalidSessionStructure(
                    "missing remote identity key",
                ))?;

        Ok(Self {
            ratchet,
            pqr_state,
            local_identity_key,
            remote_identity_key,
        })
    }

    /// Write the updated crypto state back to a [`SessionState`].
    ///
    /// Only call this after a successful decrypt — this is how we ensure
    /// no state pollution on failure.
    pub(crate) fn apply_to_session_state(self, state: &mut SessionState) {
        state.apply_ratchet_state(self.ratchet);
        state.set_pq_ratchet_state(self.pqr_state);
    }

    // -- Decrypt -------------------------------------------------------

    /// Decrypt a [`SignalMessage`] to plaintext.
    ///
    /// Performs DR chain key derivation, SPQR key derivation, MAC
    /// verification, and AES-CBC decryption. Ratchet and SPQR state are
    /// only committed on success — a failed MAC or decryption leaves this
    /// session unchanged.
    ///
    /// `original_message_type` is used for error classification only
    /// (PreKey vs Whisper).
    pub(crate) fn decrypt<R: Rng + CryptoRng>(
        &mut self,
        sender_address: &ProtocolAddress,
        recipient_address: &ProtocolAddress,
        ciphertext: &SignalMessage,
        original_message_type: CiphertextMessageType,
        current_or_previous_for_logging: CurrentOrPrevious,
        csprng: &mut R,
    ) -> Result<Vec<u8>> {
        // DR: ensure we have a receiver chain, then consume the message key
        let their_ephemeral = ciphertext.sender_ratchet_key();
        let counter = ciphertext.counter();
        let chain_key = self
            .ratchet
            .ensure_receiver_chain(their_ephemeral, csprng)?;
        let message_key_gen = self.ratchet.consume_message_key(
            their_ephemeral,
            chain_key,
            counter,
            original_message_type,
            &sender_address.to_string(),
        )?;

        // SPQR recv — compute key but don't commit state yet
        let spqr::Recv {
            state: new_pqr_state,
            key: pqr_key,
        } = spqr::recv(&self.pqr_state, ciphertext.pq_ratchet()).map_err(|e| match e {
            spqr::Error::StateDecode => SignalProtocolError::InvalidState(
                "decrypt",
                format!("post-quantum ratchet error: {e}"),
            ),
            _ => {
                log::info!("post-quantum ratchet error in decrypt: {e}");
                SignalProtocolError::InvalidMessage(
                    original_message_type,
                    "post-quantum ratchet error",
                )
            }
        })?;

        // Derive final message keys by mixing DR chain key with SPQR key
        let message_keys = message_key_gen.generate_keys(pqr_key);

        // MAC verification
        let mac_valid = ciphertext.verify_mac_with_addresses(
            sender_address,
            recipient_address,
            &self.remote_identity_key,
            &self.local_identity_key,
            message_keys.mac_key(),
        )?;
        if !mac_valid {
            return Err(SignalProtocolError::InvalidMessage(
                original_message_type,
                "MAC verification failed",
            ));
        }

        // AES-CBC decrypt
        let ptext = match signal_crypto::aes_256_cbc_decrypt(
            ciphertext.body(),
            message_keys.cipher_key(),
            message_keys.iv(),
        ) {
            Ok(ptext) => ptext,
            Err(signal_crypto::DecryptionError::BadKeyOrIv) => {
                log::warn!(
                    "{current_or_previous_for_logging} session state corrupt for {sender_address}",
                );
                return Err(SignalProtocolError::InvalidSessionStructure(
                    "invalid receiver chain message keys",
                ));
            }
            Err(signal_crypto::DecryptionError::BadCiphertext(msg)) => {
                log::warn!("failed to decrypt 1:1 message: {msg}");
                return Err(SignalProtocolError::InvalidMessage(
                    original_message_type,
                    "failed to decrypt",
                ));
            }
        };

        // Commit SPQR state only after all verification passed
        self.pqr_state = new_pqr_state;

        Ok(ptext)
    }
}
