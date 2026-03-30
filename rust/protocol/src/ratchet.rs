//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Ratchet Definition/Explanation:
// 
// A cryptographic ratchet is a mechanism used in secure messaging protocols to continually 
// update encryption keys so that each message is protected with a fresh key. The key property 
// is that the process only moves forward — once a key is used, it cannot be derived again, and 
// past keys cannot be reconstructed from future ones.
//
// A double ratchet combines a cryptographic so-called "ratchet" based on the Diffie–Hellman key 
// exchange (DH) and a ratchet based on a key derivation function (KDF), such as a hash function, 
// and is therefore called a double ratchet.
//

mod keys;
mod params;

use libsignal_core::derive_arrays;
use rand::{CryptoRng, Rng};

pub(crate) use self::keys::{ChainKey, MessageKeyGenerator, RootKey};
pub use self::params::{AliceSignalProtocolParameters, BobSignalProtocolParameters};
use crate::protocol::CIPHERTEXT_MESSAGE_CURRENT_VERSION;
use crate::state::SessionState;
use crate::{KeyPair, Result, SessionRecord, SignalProtocolError, consts};

type InitialPQRKey = [u8; 32]; // Initial key for PQ Ratchet

fn derive_keys(secret_input: &[u8]) -> (RootKey, ChainKey, InitialPQRKey) {
    derive_keys_with_label(
        b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024",
        secret_input,
    )
}

// HKDF key derivation
fn derive_keys_with_label(label: &[u8], secret_input: &[u8]) -> (RootKey, ChainKey, InitialPQRKey) {
    let (root_key_bytes, chain_key_bytes, pqr_bytes) = derive_arrays(|bytes| {
        hkdf::Hkdf::<sha2::Sha256>::new(None, secret_input)
            .expand(label, bytes)
            .expect("valid length")
    });

    let root_key = RootKey::new(root_key_bytes);    // Master secret for ratchet (derive chain keys)
    let chain_key = ChainKey::new(chain_key_bytes, 0);  // Starting key for message encryption/decryption chains
    let pqr_key: InitialPQRKey = pqr_bytes;

    (root_key, chain_key, pqr_key)
}

// PQ ratchet parameters
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
// trait SampleSource {
//     fn sample(&self) -> &[u8];
// }

// impl SampleSource for &PublicKey {
//     fn sample(&self) -> &[u8] {
//         self.public_key_bytes()
//     }
// }

// impl SampleSource for &Vec<u8> {
//     fn sample(&self) -> &[u8] {
//         self.as_slice()
//     }
// }

// impl SampleSource for Vec<u8> {
//     fn sample(&self) -> &[u8] {
//         self.as_slice()
//     }
// }


// fn sample_from<T: SampleSource>(input: T) ->  {
//     input.sample()
// }

use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
    constants::RISTRETTO_BASEPOINT_POINT,
};
use sha2::{Sha256, Sha512, Digest};


fn encode(vk: &[u8], x: &[u8]) -> Vec<u8> {
    [vk.len().to_le_bytes().as_slice(), vk, x].concat()
}


pub fn generator_g() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

pub fn hash_generic_zp(input: &[u8]) -> Scalar {
    let hash = Sha512::digest(input);
    Scalar::from_bytes_mod_order_wide(&hash.into())
}

pub fn hash_fs(vk: &[u8], x: &[u8], h: &RistrettoPoint, h_prime: &RistrettoPoint, eta: &RistrettoPoint, eta_prime: &RistrettoPoint) -> Scalar {
    let mut bytes = Vec::new();
    bytes.extend(&(vk.len() as u64).to_le_bytes());
    bytes.extend(vk);
    bytes.extend(&(x.len() as u64).to_le_bytes());
    bytes.extend(x);
    bytes.extend(h.compress().as_bytes());
    bytes.extend(h_prime.compress().as_bytes());
    bytes.extend(eta.compress().as_bytes());
    bytes.extend(eta_prime.compress().as_bytes());

    let hash = Sha512::digest(&bytes);
    Scalar::from_bytes_mod_order_wide(&hash.into())
}

fn hash_to_G(domain_sep: &[u8], input: &[u8]) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(domain_sep);
    hasher.update(input);
    RistrettoPoint::from_hash(hasher)
}

pub fn hash_i(vk: &[u8], x: &[u8]) -> RistrettoPoint {
    hash_to_G(b"hash_i", &encode(vk, x))
}

pub fn hash_a(vk: &[u8], x: &[u8]) -> RistrettoPoint {
    hash_to_G(b"hash_a", &encode(vk, x))
}

pub fn hash_b(vk: &[u8], x: &[u8]) -> RistrettoPoint {
    hash_to_G(b"hash_b", &encode(vk, x))
}

pub fn hash_o(input: &[u8]) -> u64 {
    let hash = Sha256::digest(input);
    u64::from_le_bytes(hash[..8].try_into().unwrap())
}


// ***X3DH Key Agreement for Alice***
pub(crate) fn initialize_alice_session<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters, // Contains Alice's ik and eph keys, Bob's ik, signed prekey, otpk, PQ prekey
    mut csprng: &mut R,
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key(); // Alice's ipk

    let mut secrets = Vec::with_capacity(32 * 6);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    // Below are the DH operations for X3DH
    let our_base_private_key = parameters.our_base_key_pair().private_key;

    // Alice's private ik * Bob's signed prekey
    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair()
            .private_key()
            .calculate_agreement(parameters.their_signed_pre_key())?,
    );

    // Alice's eph key * Bob's ik
    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_identity_key().public_key())?,
    );

    // Alice's eph key * Bob's signed prekey
    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_signed_pre_key())?,
    );

    //step 0: parameters
    let vk; //otpk_bob,i 
    let g = generator_g();

    // Optional Alice's eph key * Bob's otpk
    if let Some(their_one_time_prekey) = parameters.their_one_time_pre_key() {
        secrets
            .extend_from_slice(&our_base_private_key.calculate_agreement(their_one_time_prekey)?);
        vk = their_one_time_prekey.public_key_bytes();
    } else {
        vk = parameters.their_signed_pre_key().public_key_bytes();
    }

    // Uses Bob's Kyber prekey to perform key encapsulation (KEM)
    // ss = shared secret from Kyber, ct = ciphertext sent to Bob
    let kyber_ciphertext = {
        let (ss, ct) = parameters.their_kyber_pre_key().encapsulate(&mut csprng)?;
        secrets.extend_from_slice(ss.as_ref());
        ct
    };


    //step 0.5, parameters
    //x = secrets 
    

    //sample alpha, beta from the set of real integers
    //step 1, page 11, preverify
    let alpha = hash_generic_zp(b"alpha");
    let beta = hash_generic_zp(b"beta");
    let h = alpha * g + beta * hash_i(vk, &secrets);    
    let hprime = alpha * hash_a(vk, &secrets) + beta * hash_b(vk, &secrets);

    //step 2
    let r1 = hash_generic_zp(b"r1");
    let r2 = hash_generic_zp(b"r2");
    let eta = (g * r1) + (hash_i(vk, &secrets) * r2);
    let etaprime = (hash_a(vk, &secrets) * r1) + (hash_b(vk, &secrets) * r2);
    let c = hash_fs(vk, &secrets, &h, &hprime, &eta, &etaprime);
    let s = (r1 - c * alpha, r2 - c * beta);
    let tau = (c,s);

    //step 3
    let vt = (h, hprime, tau);
    let vts = (vt, vk, &secrets, alpha, beta);
    //output vt, store vts



    let (root_key, chain_key, pqr_key) = derive_keys(&secrets);

    // Alice generates eph sending ratchet key
    // Perform DH with Bob's ratchet key
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

    // Create session object with receiver/sender chains
    let mut session = SessionState::new(
        CIPHERTEXT_MESSAGE_CURRENT_VERSION,
        local_identity,
        parameters.their_identity_key(),
        &sending_chain_root_key,
        &parameters.our_base_key_pair().public_key,
        pqr_state,
        32, //dummy sas
        Some(bincode::serialize(&vts).unwrap()),
        None,
    )
    .with_receiver_chain(parameters.their_ratchet_key(), &chain_key)
    .with_sender_chain(&sending_ratchet_key, &sending_chain_chain_key);

    session.set_kyber_ciphertext(kyber_ciphertext); // Ciphertext to send to Bob

    Ok(session) // Alice's session ready for messaging
}

pub(crate) fn initialize_bob_session(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionState> {
    // validate Alice's (ephemeral) base key
    if !parameters.their_base_key().is_canonical() {
        return Err(SignalProtocolError::InvalidMessage(
            crate::CiphertextMessageType::PreKey,
            "incoming base key is invalid",
        ));
    }

    let local_identity = parameters.our_identity_key_pair().identity_key(); // Bob's ipk

    let mut secrets = Vec::with_capacity(32 * 6);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    // DH agreement computations
    // Bob's spk * Alice's ik
    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair()
            .private_key
            .calculate_agreement(parameters.their_identity_key().public_key())?,
    );

    // Bob's ik * Alice's eph key
    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair()
            .private_key()
            .calculate_agreement(parameters.their_base_key())?,
    );

    // Bob's spk * Alice's eph key
    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair()
            .private_key
            .calculate_agreement(parameters.their_base_key())?,
    );
    
    // we need to be able to extract vt from the message to do it here
    // we SHOULD do it here, but we need to figure out how to decrypt the cipher
    // at this point (kyber could do it so it should be possible)
    //step 0: "retrieve" parameters k, vk
    // fresh genning them for speed right now
    let g = generator_g();
    let k = hash_generic_zp(b"placeholder fresh k for vk");
    let vk = g * k;
    let kptr;
    let x;
    //let vt;



    // Optional Bob's otpk * Alice's eph key
    if let Some(our_one_time_pre_key_pair) = parameters.our_one_time_pre_key_pair() {
        secrets.extend_from_slice(
            &our_one_time_pre_key_pair
                .private_key
                .calculate_agreement(parameters.their_base_key())?,
        );
        kptr = our_one_time_pre_key_pair;
    } else {
        kptr = parameters.our_signed_pre_key_pair();
    }

    // Bob's Kyber secret key recovers shared PQ secret from Alice's ciphertext
    secrets.extend_from_slice(
        &parameters
            .our_kyber_pre_key_pair()
            .secret_key
            .decapsulate(parameters.their_kyber_ciphertext())?,
    );

    x = &secrets;
    //let pvrf_ciphertext = parameters.their_pvrf();


    let (root_key, chain_key, pqr_key) = derive_keys(&secrets);

    // PQ ratchet from Bob to Alice
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

    // Bob's session object
    let session = SessionState::new(
        CIPHERTEXT_MESSAGE_CURRENT_VERSION,
        local_identity,
        parameters.their_identity_key(),
        &root_key,
        parameters.their_base_key(),
        pqr_state,
        32, //dummy sas
        None, //dummy vts
        None,
    )
    .with_sender_chain(parameters.our_ratchet_key_pair(), &chain_key);

    Ok(session)
}


// Wrappers
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
