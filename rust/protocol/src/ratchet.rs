//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod keys;
mod params;

use pswoosh::keys::SwooshKeyPair;
use rand::{CryptoRng, Rng};

pub(crate) use self::keys::{ChainKey, MessageKeyGenerator, RootKey};
pub use self::params::{AliceSignalProtocolParameters, BobSignalProtocolParameters, UsePQRatchet};
use crate::protocol::{CIPHERTEXT_MESSAGE_CURRENT_VERSION, CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION};
use crate::state::SessionState;
use crate::{consts, KeyPair, Result, SessionRecord, SignalProtocolError};

type InitialPQRKey = [u8; 32];

fn derive_keys(has_kyber: bool, secret_input: &[u8]) -> (RootKey, ChainKey, InitialPQRKey) {
    let label = if has_kyber {
        b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024".as_slice()
    } else {
        b"WhisperText".as_slice()
    };
    derive_keys_with_label(label, secret_input)
}

fn message_version(has_kyber: bool) -> u8 {
    if has_kyber {
        CIPHERTEXT_MESSAGE_CURRENT_VERSION
    } else {
        CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION
    }
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

    let sending_ratchet_key = KeyPair::generate(&mut csprng);

    let mut secrets = Vec::with_capacity(32 * 5);

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

    let kyber_ciphertext = parameters
        .their_kyber_pre_key()
        .map(|kyber_public| {
            let (ss, ct) = kyber_public.encapsulate(&mut csprng)?;
            secrets.extend_from_slice(ss.as_ref());
            Ok::<_, SignalProtocolError>(ct)
        })
        .transpose()?;
    let has_kyber = parameters.their_kyber_pre_key().is_some();

    let (root_key, chain_key, pqr_key) = derive_keys(has_kyber, &secrets);
        
    let (sending_chain_root_key, sending_chain_chain_key) = root_key.create_chain(
        parameters.their_ratchet_key(),
        &sending_ratchet_key.private_key,
    )?;

    let self_session = local_identity == parameters.their_identity_key();
    let pqr_state = match parameters.use_pq_ratchet() {
        UsePQRatchet::Yes => spqr::initial_state(spqr::Params {
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
        })?,
        UsePQRatchet::No => spqr::SerializedState::new(), // empty
    };

    let mut session = SessionState::new(
        message_version(has_kyber),
        local_identity,
        parameters.their_identity_key(),
        &sending_chain_root_key,
        &parameters.our_base_key_pair().public_key,
        pqr_state,
    )
    .with_receiver_chain(parameters.their_ratchet_key(), &chain_key)
    .with_sender_chain(&sending_ratchet_key, &sending_chain_chain_key);

    if let Some(kyber_ciphertext) = kyber_ciphertext {
        session.set_kyber_ciphertext(kyber_ciphertext);
    }

    Ok(session)
}

pub(crate) fn initialize_alice_session_pswoosh<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    mut csprng: &mut R,
) -> Result<SessionState> {

    let is_alice = true; // Always true for Alice's session initialization
    let local_identity = parameters.our_identity_key_pair().identity_key();

    // Use SwooshKeyPair for ratchet keys
    let sending_swoosh_ratchet_key = SwooshKeyPair::generate(is_alice);

    let mut secrets = Vec::with_capacity(32 * 6); // Extra capacity for PSWOOSH secret

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    let our_base_private_key = parameters.our_base_key_pair().private_key;

    // Standard X3DH key agreements (same as original)
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

    let kyber_ciphertext = parameters
        .their_kyber_pre_key()
        .map(|kyber_public| {
            let (ss, ct) = kyber_public.encapsulate(&mut csprng)?;
            secrets.extend_from_slice(ss.as_ref());
            Ok::<_, SignalProtocolError>(ct)
        })
        .transpose()?;
    let has_kyber = parameters.their_kyber_pre_key().is_some();

    let (root_key, chain_key, pqr_key) = derive_keys(has_kyber, &secrets);
    println!("🔑 Alice original root_key first 8 bytes: {:02x?}", &root_key.key()[..8]);
    println!("🔑 Alice original chain_key first 8 bytes: {:02x?}", &chain_key.key()[..8]);

    // Then use the updated root key to create Swoosh chain
    let (sending_swoosh_root_key, sending_swoosh_chain_key) = root_key.create_chain_swoosh(
        parameters.their_swoosh_ratchet_key().unwrap(),
        &sending_swoosh_ratchet_key.public_key,
        &sending_swoosh_ratchet_key.private_key,
        is_alice,
    )?;

    println!("🔑 Alice sending swoosh root key first 8 bytes: {:02x?}", &sending_swoosh_root_key.key()[..8]);
    println!("🔑 Alice sending swoosh chain key first 8 bytes: {:02x?}", &sending_swoosh_chain_key.key()[..8]);

    let self_session = local_identity == parameters.their_identity_key();
    let pqr_state = match parameters.use_pq_ratchet() {
        UsePQRatchet::Yes => spqr::initial_state(spqr::Params {
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
        })?,
        UsePQRatchet::No => spqr::SerializedState::new(), // empty
    };

    // Use hybrid session state to create chains with both regular and Swoosh keys
    let mut session = SessionState::new(
        message_version(has_kyber),
        local_identity,
        parameters.their_identity_key(),
        &sending_swoosh_root_key,
        &parameters.our_base_key_pair().public_key,
        pqr_state,
    )
    .with_receiver_swoosh_chain(parameters.their_swoosh_ratchet_key().unwrap(), &chain_key)
    .with_sender_swoosh_chain(&sending_swoosh_ratchet_key, &sending_swoosh_chain_key);

    if let Some(kyber_ciphertext) = kyber_ciphertext {
        session.set_kyber_ciphertext(kyber_ciphertext);
    }

    Ok(session)
}

pub(crate) fn initialize_bob_session_pswoosh(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionState> {

    let local_identity = parameters.our_identity_key_pair().identity_key();

    let mut secrets = Vec::with_capacity(32 * 5);

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

    match (
        parameters.our_kyber_pre_key_pair(),
        parameters.their_kyber_ciphertext(),
    ) {
        (Some(key_pair), Some(ciphertext)) => {
            let ss = key_pair.secret_key.decapsulate(ciphertext)?;
            secrets.extend_from_slice(ss.as_ref());
        }
        (None, None) => (), // Alice does not support kyber prekeys
        _ => {
            panic!("Either both or none of the kyber key pair and ciphertext can be provided")
        }
    }
    let has_kyber = parameters.our_kyber_pre_key_pair().is_some();

    let (root_key, chain_key, pqr_key) = derive_keys(has_kyber, &secrets);
    println!("🔑 Bob root_key first 8 bytes: {:02x?}", &root_key.key()[..8]);
    println!("🔑 Bob chain_key first 8 bytes: {:02x?}", &chain_key.key()[..8]);

    let self_session = local_identity == parameters.their_identity_key();
    let pqr_state = match parameters.use_pq_ratchet() {
        UsePQRatchet::Yes => spqr::initial_state(spqr::Params {
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
        })?,
        UsePQRatchet::No => spqr::SerializedState::new(), // empty
    };
    let session = SessionState::new(
        message_version(has_kyber),
        local_identity,
        parameters.their_identity_key(),
        &root_key,
        parameters.their_base_key(),
        pqr_state,
    )
    .with_sender_swoosh_chain(parameters.our_ratchet_swoosh_key_pair().unwrap(), &chain_key);

    Ok(session)
}

pub(crate) fn initialize_bob_session(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionState> {
    
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let mut secrets = Vec::with_capacity(32 * 5);

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

    match (
        parameters.our_kyber_pre_key_pair(),
        parameters.their_kyber_ciphertext(),
    ) {
        (Some(key_pair), Some(ciphertext)) => {
            let ss = key_pair.secret_key.decapsulate(ciphertext)?;
            secrets.extend_from_slice(ss.as_ref());
        }
        (None, None) => (), // Alice does not support kyber prekeys
        _ => {
            panic!("Either both or none of the kyber key pair and ciphertext can be provided")
        }
    }
    let has_kyber = parameters.our_kyber_pre_key_pair().is_some();

    let (root_key, chain_key, pqr_key) = derive_keys(has_kyber, &secrets);

    let self_session = local_identity == parameters.their_identity_key();
    let pqr_state = match parameters.use_pq_ratchet() {
        UsePQRatchet::Yes => spqr::initial_state(spqr::Params {
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
        })?,
        UsePQRatchet::No => spqr::SerializedState::new(), // empty
    };
    let session = SessionState::new(
        message_version(has_kyber),
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
