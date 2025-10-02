//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod keys;
mod params;

use rand::{CryptoRng, Rng};

pub(crate) use self::keys::{ChainKey, MessageKeyGenerator, RootKey};
pub use self::params::{AliceSignalProtocolParameters, BobSignalProtocolParameters};
use crate::protocol::CIPHERTEXT_MESSAGE_CURRENT_VERSION;
use crate::state::SessionState;
use crate::{KeyPair, Result, SessionRecord, SignalProtocolError, consts};

type InitialPQRKey = [u8; 32];

fn derive_keys(secret_input: &[u8]) -> (RootKey, ChainKey, InitialPQRKey) {
    derive_keys_with_label(
        b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024",
        secret_input,
    )
}

fn derive_keys_with_label(label: &[u8], secret_input: &[u8]) -> (RootKey, ChainKey, InitialPQRKey) {
    let mut secrets = [0; 96];
    hkdf::Hkdf::<sha2::Sha256>::new(None, secret_input)
        .expand(label, &mut secrets)
        .expect("valid length");
    let (root_key_bytes, chain_key_bytes, pqr_bytes) =
        (&secrets[0..32], &secrets[32..64], &secrets[64..96]);

    let root_key = RootKey::new(root_key_bytes.try_into().expect("correct length"));
    let chain_key = ChainKey::new(chain_key_bytes.try_into().expect("correct length"), 0);
    let pqr_key: InitialPQRKey = pqr_bytes.try_into().expect("correct length");

    (root_key, chain_key, pqr_key)
}

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

pub(crate) fn initialize_alice_session<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    mut csprng: &mut R,
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let mut secrets = Vec::with_capacity(32 * 6);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    let our_base_private_key = parameters.our_base_key_pair().private_key;

    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair()
            .private_key()
            .calculate_agreement(parameters.their_signed_pre_key())?,
    );

    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_identity_key().public_key())?,
    );

    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_signed_pre_key())?,
    );

    if let Some(their_one_time_prekey) = parameters.their_one_time_pre_key() {
        secrets
            .extend_from_slice(&our_base_private_key.calculate_agreement(their_one_time_prekey)?);
    }

    let kyber_ciphertext = {
        let (ss, ct) = parameters.their_kyber_pre_key().encapsulate(&mut csprng)?;
        secrets.extend_from_slice(ss.as_ref());
        ct
    };

    let (root_key, chain_key, pqr_key) = derive_keys(&secrets);

    let sending_ratchet_key = KeyPair::generate(&mut csprng);
    let (sending_chain_root_key, sending_chain_chain_key) = root_key.create_chain(
        parameters.their_ratchet_key(),
        &sending_ratchet_key.private_key,
    )?;

    let self_session = local_identity == parameters.their_identity_key();
    let pqr_state = spqr::initial_state(spqr::Params {
        auth_key: &pqr_key,
        version: spqr::Version::V1,
        direction: spqr::Direction::A2B,
        // Set min_version to V0 (allow fallback to no PQR at all) while
        // there are clients that don't speak PQR.  Once all clients speak
        // PQR, we can up this to V1 to require that all subsequent sessions
        // use at least V1.
        min_version: spqr::Version::V0,
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
        &parameters.our_base_key_pair().public_key,
        pqr_state,
    )
    .with_receiver_chain(parameters.their_ratchet_key(), &chain_key)
    .with_sender_chain(&sending_ratchet_key, &sending_chain_chain_key);

    session.set_kyber_ciphertext(kyber_ciphertext);

    Ok(session)
}

pub(crate) fn initialize_bob_session(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionState> {
    // validate their base key
    if !parameters.their_base_key().is_canonical() {
        return Err(SignalProtocolError::InvalidMessage(
            crate::CiphertextMessageType::PreKey,
            "incoming base key is invalid",
        ));
    }

    let local_identity = parameters.our_identity_key_pair().identity_key();

    let mut secrets = Vec::with_capacity(32 * 6);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair()
            .private_key
            .calculate_agreement(parameters.their_identity_key().public_key())?,
    );

    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair()
            .private_key()
            .calculate_agreement(parameters.their_base_key())?,
    );

    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair()
            .private_key
            .calculate_agreement(parameters.their_base_key())?,
    );

    if let Some(our_one_time_pre_key_pair) = parameters.our_one_time_pre_key_pair() {
        secrets.extend_from_slice(
            &our_one_time_pre_key_pair
                .private_key
                .calculate_agreement(parameters.their_base_key())?,
        );
    }

    secrets.extend_from_slice(
        &parameters
            .our_kyber_pre_key_pair()
            .secret_key
            .decapsulate(parameters.their_kyber_ciphertext())?,
    );

    let (root_key, chain_key, pqr_key) = derive_keys(&secrets);

    let self_session = local_identity == parameters.their_identity_key();
    let pqr_state = spqr::initial_state(spqr::Params {
        auth_key: &pqr_key,
        version: spqr::Version::V1,
        direction: spqr::Direction::B2A,
        // Set min_version to V0 (allow fallback to no PQR at all) while
        // there are clients that don't speak PQR.  Once all clients speak
        // PQR, we can up this to V1 to require that all subsequent sessions
        // use at least V1.
        min_version: spqr::Version::V0,
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
        parameters.their_base_key(),
        pqr_state,
    )
    .with_sender_chain(parameters.our_ratchet_key_pair(), &chain_key);

    Ok(session)
}

pub fn initialize_alice_session_record<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    csprng: &mut R,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_alice_session(
        parameters, csprng,
    )?))
}

pub fn initialize_bob_session_record(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_bob_session(parameters)?))
}
