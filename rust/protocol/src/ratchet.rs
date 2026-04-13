//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod keys;

use rand::{CryptoRng, Rng};

pub(crate) use self::keys::{ChainKey, MessageKeyGenerator, RootKey};
use crate::handshake::Handshake;
use crate::pqxdh::{HandshakeKeys, Pqxdh};
// Re-export the parameter types for backward compatibility.
// Callers (session.rs, tests) use these via `ratchet::`.
pub use crate::pqxdh::{InitiatorParameters, RecipientParameters};
use crate::protocol::CIPHERTEXT_MESSAGE_CURRENT_VERSION;
use crate::state::SessionState;
use crate::{KeyPair, Result, SessionRecord, SignalProtocolError, consts};

// Backward-compatible aliases for the old names. These keep existing
// external callers (tests, bridge code) compiling during the transition.
#[doc(hidden)]
pub type AliceSignalProtocolParameters = InitiatorParameters;
#[doc(hidden)]
pub type BobSignalProtocolParameters<'a> = RecipientParameters<'a>;

fn spqr_chain_params(self_connection: bool) -> spqr::ChainParams {
    #[allow(clippy::needless_update)]
    spqr::ChainParams {
        max_jump: if self_connection {
            u32::MAX
        } else {
            consts::MAX_FORWARD_JUMPS.try_into().expect("should be <4B")
        },
        max_ooo_keys: consts::MAX_MESSAGE_KEYS.try_into().expect("should be <4B"),
        ..Default::default()
    }
}

/// Initialize a session from the initiator's side.
///
/// Performs the PQXDH key agreement and then sets up the Double Ratchet
/// and SPQR state.
pub(crate) fn initialize_alice_session<R: Rng + CryptoRng>(
    parameters: &InitiatorParameters,
    csprng: &mut R,
) -> Result<SessionState> {
    let (
        kyber_ciphertext,
        HandshakeKeys {
            root_key,
            chain_key,
            pqr_key,
        },
    ) = Pqxdh::initiate(parameters, csprng)?;

    initialize_initiator_session(
        parameters,
        root_key,
        chain_key,
        pqr_key,
        kyber_ciphertext,
        csprng,
    )
}

fn initialize_initiator_session<R: Rng + CryptoRng>(
    parameters: &InitiatorParameters,
    root_key: RootKey,
    chain_key: ChainKey,
    pqr_key: [u8; 32],
    kyber_ciphertext: crate::kem::SerializedCiphertext,
    csprng: &mut R,
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let sending_ratchet_key = KeyPair::generate(csprng);
    let (sending_chain_root_key, sending_chain_chain_key) = root_key.create_chain(
        parameters.their_ratchet_key(),
        &sending_ratchet_key.private_key,
    )?;

    let self_session = local_identity == parameters.their_identity_key();
    let pqr_state = spqr::initial_state(spqr::Params {
        auth_key: &pqr_key,
        version: spqr::Version::V1,
        direction: spqr::Direction::A2B,
        min_version: spqr::Version::V1, // Require that all clients speak SPQR
        chain_params: spqr_chain_params(self_session),
    })
    .map_err(|e| {
        // Since this is an error associated with the initial creation of the state,
        // it must be a problem with the arguments provided.
        SignalProtocolError::InvalidArgument(format!(
            "post-quantum ratchet: error creating initial A2B state: {e}"
        ))
    })?;

    let mut session = SessionState::new(
        CIPHERTEXT_MESSAGE_CURRENT_VERSION,
        local_identity,
        parameters.their_identity_key(),
        &sending_chain_root_key,
        &parameters.our_ephemeral_key_pair().public_key,
        pqr_state,
    )
    .with_receiver_chain(parameters.their_ratchet_key(), &chain_key)
    .with_sender_chain(&sending_ratchet_key, &sending_chain_chain_key);

    session.set_kyber_ciphertext(kyber_ciphertext);

    Ok(session)
}

/// Initialize a session from the recipient's side.
///
/// Performs the PQXDH key agreement and then sets up the Double Ratchet
/// and SPQR state.
pub(crate) fn initialize_bob_session(
    parameters: &RecipientParameters,
    our_ratchet_key_pair: &KeyPair,
) -> Result<SessionState> {
    let HandshakeKeys {
        root_key,
        chain_key,
        pqr_key,
    } = Pqxdh::accept(parameters)?;

    initialize_recipient_session(
        parameters,
        our_ratchet_key_pair,
        root_key,
        chain_key,
        pqr_key,
    )
}

fn initialize_recipient_session(
    parameters: &RecipientParameters,
    our_ratchet_key_pair: &KeyPair,
    root_key: RootKey,
    chain_key: ChainKey,
    pqr_key: [u8; 32],
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let self_session = local_identity == parameters.their_identity_key();
    let pqr_state = spqr::initial_state(spqr::Params {
        auth_key: &pqr_key,
        version: spqr::Version::V1,
        direction: spqr::Direction::B2A,
        min_version: spqr::Version::V1, // Require that all clients speak SPQR
        chain_params: spqr_chain_params(self_session),
    })
    .map_err(|e| {
        // Since this is an error associated with the initial creation of the state,
        // it must be a problem with the arguments provided.
        SignalProtocolError::InvalidArgument(format!(
            "post-quantum ratchet: error creating initial B2A state: {e}"
        ))
    })?;

    let session = SessionState::new(
        CIPHERTEXT_MESSAGE_CURRENT_VERSION,
        local_identity,
        parameters.their_identity_key(),
        &root_key,
        parameters.their_ephemeral_key(),
        pqr_state,
    )
    .with_sender_chain(our_ratchet_key_pair, &chain_key);

    Ok(session)
}

pub fn initialize_alice_session_record<R: Rng + CryptoRng>(
    parameters: &InitiatorParameters,
    csprng: &mut R,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_alice_session(
        parameters, csprng,
    )?))
}

pub fn initialize_bob_session_record(
    parameters: &RecipientParameters,
    our_ratchet_key_pair: &KeyPair,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_bob_session(
        parameters,
        our_ratchet_key_pair,
    )?))
}
