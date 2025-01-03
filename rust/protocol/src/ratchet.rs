//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod keys;
mod params;

use curve25519_dalek::{
    EdwardsPoint, MontgomeryPoint,
    constants::ED25519_BASEPOINT_TABLE,
    edwards::CompressedEdwardsY,
    scalar::Scalar,
};
use rand::{CryptoRng, Rng};
use sha2::{Sha512, Digest};

use crate::protocol::{CIPHERTEXT_MESSAGE_CURRENT_VERSION, CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION};
use crate::state::SessionState;
use crate::{KeyPair, Result, SessionRecord, PublicKey};

pub(crate) use self::keys::{ChainKey, MessageKeys, RootKey};
pub use self::params::{AliceSignalProtocolParameters, BobSignalProtocolParameters};

fn derive_keys(has_kyber: bool, secret_input: &[u8]) -> (RootKey, ChainKey) {
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

fn derive_keys_with_label(label: &[u8], secret_input: &[u8]) -> (RootKey, ChainKey) {
    let mut secrets = [0; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(None, secret_input)
        .expand(label, &mut secrets)
        .expect("valid length");
    let (root_key_bytes, chain_key_bytes) = secrets.split_at(32);

    let root_key = RootKey::new(root_key_bytes.try_into().expect("correct length"));
    let chain_key = ChainKey::new(chain_key_bytes.try_into().expect("correct length"), 0);

    (root_key, chain_key)
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

    let ephemeral_key = KeyPair::generate(&mut csprng);

    if let Some(their_one_time_prekey) = parameters.their_one_time_pre_key() {
        let ed_pub_key = CompressedEdwardsY::from_slice(their_one_time_prekey.public_key_bytes()?).unwrap().decompress().unwrap();

        let m_pub_key = PublicKey::from_djb_public_key_bytes(ed_pub_key.to_montgomery().to_bytes().as_slice())?;
        let shared_secret = ephemeral_key.private_key.calculate_agreement(&m_pub_key)?;

        let mut hasher = Sha512::new();
        hasher.update(&shared_secret);
        let hash_scalar = Scalar::from_hash(hasher);

        let opk_b_alice: EdwardsPoint = (&hash_scalar * ED25519_BASEPOINT_TABLE) + ed_pub_key;

        let our_base_scalar = Scalar::from_bytes_mod_order(our_base_private_key.serialize()[..32].try_into().unwrap());
        let shared_ed_secret: EdwardsPoint = our_base_scalar * opk_b_alice;

        let alice_agreement = shared_ed_secret.to_montgomery().to_bytes();
        secrets.extend_from_slice(&alice_agreement);
    }

    let kyber_ciphertext = parameters.their_kyber_pre_key().map(|kyber_public| {
        let (ss, ct) = kyber_public.encapsulate();
        secrets.extend_from_slice(ss.as_ref());
        ct
    });
    let has_kyber = parameters.their_kyber_pre_key().is_some();

    let (root_key, chain_key) = derive_keys(has_kyber, &secrets);

    let (sending_chain_root_key, sending_chain_chain_key) = root_key.create_chain(
        parameters.their_ratchet_key(),
        &sending_ratchet_key.private_key,
    )?;

    let mut session = SessionState::new(
        message_version(has_kyber),
        local_identity,
        parameters.their_identity_key(),
        &sending_chain_root_key,
        &parameters.our_base_key_pair().public_key,
    )
    .with_receiver_chain(parameters.their_ratchet_key(), &chain_key)
    .with_sender_chain(&sending_ratchet_key, &sending_chain_chain_key);

    session.set_ephemeral_derivation_key(&ephemeral_key.public_key);

    if let Some(kyber_ciphertext) = kyber_ciphertext {
        session.set_kyber_ciphertext(kyber_ciphertext);
    }

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
        if let Some(ephemeral_key) = parameters.ephemeral_derivation_key() {
            let shared_secret = our_one_time_pre_key_pair.private_key.calculate_agreement(&ephemeral_key)?;

            let mut hasher = Sha512::new();
            hasher.update(&shared_secret);
            let hash_scalar = Scalar::from_hash(hasher);

            let seed_scalar = Scalar::from_bytes_mod_order(our_one_time_pre_key_pair.private_key.serialize()[..32].try_into().unwrap());
            let scalar_opk_b = hash_scalar + seed_scalar;

            let ed_their_base_key =  MontgomeryPoint(parameters.their_base_key().public_key_bytes()?[..32].try_into().unwrap()).to_edwards(0).unwrap();
            let shared_ed_secret = &scalar_opk_b * ed_their_base_key;

            let agreement = shared_ed_secret.to_montgomery().to_bytes();

            secrets.extend_from_slice(&agreement);
        } else {
            let agreement = our_one_time_pre_key_pair
                .private_key
                .calculate_agreement(parameters.their_base_key())?;
            secrets.extend_from_slice(&agreement);
        }
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

    let (root_key, chain_key) = derive_keys(has_kyber, &secrets);

    let session = SessionState::new(
        message_version(has_kyber),
        local_identity,
        parameters.their_identity_key(),
        &root_key,
        parameters.their_base_key(),
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
