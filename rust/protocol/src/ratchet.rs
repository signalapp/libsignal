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

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use libsignal_core::derive_arrays;
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
// Backward-compatible aliases for the old names. These keep existing
// external callers (tests, bridge code) compiling during the transition.
#[doc(hidden)]
pub type AliceSignalProtocolParameters = InitiatorParameters;
#[doc(hidden)]
pub type BobSignalProtocolParameters<'a> = RecipientParameters<'a>;

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

use curve25519_dalek::{
    ristretto::RistrettoPoint,
    MontgomeryPoint,
    EdwardsPoint,
    scalar::Scalar,
};
use sha2::{Sha256, Sha512, Digest};


fn encode(vk: &Vec<u8>, x: &[u8]) -> Vec<u8> {
    [vk.len().to_le_bytes().as_slice(), vk, x].concat()
}


pub fn generator_g() -> EdwardsPoint {
    ED25519_BASEPOINT_POINT
}

pub fn sample_random_zp<R: Rng + CryptoRng>(csprng: &mut R) -> Scalar {
    let mut bytes = [0u8; 64];
    csprng.fill(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

pub fn hash_fs(vk: &EdwardsPoint, x: &[u8], h: &EdwardsPoint, h_prime: &EdwardsPoint, eta: &EdwardsPoint, eta_prime: &EdwardsPoint) -> Scalar {
    let mut bytes = Vec::new();
    //bytes.extend(&(vk.len() as u64).to_le_bytes());
    bytes.extend(vk.compress().as_bytes());
    bytes.extend(&(x.len() as u64).to_le_bytes());
    bytes.extend(x);
    bytes.extend(h.compress().as_bytes());
    bytes.extend(h_prime.compress().as_bytes());
    bytes.extend(eta.compress().as_bytes());
    bytes.extend(eta_prime.compress().as_bytes());

    let hash = Sha512::digest(&bytes);
    Scalar::from_bytes_mod_order_wide(&hash.into())
}

fn hash_to_g_edwards(domain_sep: &[u8], input: &[u8]) -> EdwardsPoint {
    let mut hasher = Sha512::new();
    hasher.update(domain_sep);
    hasher.update(input);
    let ris = RistrettoPoint::from_hash(hasher);
    let xcoset = ris.xcoset4();
    let first = xcoset.first().unwrap();
    first.mul_by_cofactor()
}

pub fn hash_i(vk: &EdwardsPoint, x: &[u8]) -> EdwardsPoint {
    let compressed = vk.compress();
    let compressed_vecu8 = compressed.as_bytes().to_vec();
    hash_to_g_edwards(b"hash_i", &encode(&compressed_vecu8, x))
}

pub fn hash_a(vk: &EdwardsPoint, x: &[u8]) -> EdwardsPoint {
    let compressed = vk.compress();
    let compressed_vecu8 = compressed.as_bytes().to_vec();
    hash_to_g_edwards(b"hash_a", &encode(&compressed_vecu8, x))
}

pub fn hash_b(vk: &EdwardsPoint, x: &[u8]) -> EdwardsPoint {
    let compressed = vk.compress();
    let compressed_vecu8 = compressed.as_bytes().to_vec();
    hash_to_g_edwards(b"hash_b", &encode(&compressed_vecu8, x))
}

pub fn hash_o(point: &EdwardsPoint) -> Vec<u8> {
    let compressed = point.compress();
    let hash = Sha256::digest(compressed.as_bytes());
    hash[..3].to_vec()
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
    let local_identity = parameters.our_identity_key_pair().identity_key(); // Alice's ipk

    let mut x = Vec::with_capacity(32 * 6);
    x.extend_from_slice(parameters.our_identity_key_pair().public_key().public_key_bytes());
    x.extend_from_slice(parameters.their_identity_key().public_key().public_key_bytes());
    x.extend_from_slice(parameters.our_ephemeral_key_pair().public_key.public_key_bytes());
    

    
    //step 0: parameters
    let vk; //otpk_bob,i 
    let g = generator_g();

    // Optional Alice's eph key * Bob's otpk
    if let Some(their_one_time_prekey) = parameters.their_one_time_pre_key() {
        let bytes: [u8; 32] = their_one_time_prekey.public_key_bytes().try_into().unwrap();
        vk = MontgomeryPoint(bytes).to_edwards(0).unwrap();
        x.extend_from_slice(their_one_time_prekey.public_key_bytes());
    } else {
        let bytes: [u8; 32] = parameters.their_signed_pre_key().public_key_bytes().try_into().unwrap();
        vk = MontgomeryPoint(bytes).to_edwards(0).unwrap();
    }
    x.extend_from_slice(parameters.their_signed_pre_key().public_key_bytes());
    let mut alice_sas_contribution_salt = [0u8; 3];
    csprng.fill(&mut alice_sas_contribution_salt);
    let alice_sas_contribution_salt = alice_sas_contribution_salt.to_vec();


    

    //sample alpha, beta from the set of real integers
    //step 1, page 11, preverify
    let alpha = sample_random_zp(csprng);
    let beta = sample_random_zp(csprng);
    let h = (alpha * g) + (beta * hash_i(&vk, &x));
    let hprime = alpha * hash_a(&vk, &x) + beta * hash_b(&vk, &x);

    //step 2
    let r1 = sample_random_zp(csprng);
    let r2 = sample_random_zp(csprng);
    // scalar * point = point to the power of scaler in paper
    let eta = (g * r1) + (hash_i(&vk, &x) * r2);
    let etaprime = (hash_a(&vk, &x) * r1) + (hash_b(&vk, &x) * r2);
    let c = hash_fs(&vk, &x, &h, &hprime, &eta, &etaprime);
    //s values should be mod p
    let s = (r1 - c * alpha, r2 - c * beta);
    let tau = (c,s);

    //step 3
    let vt = (h, hprime, tau);
    let vts = (vt, vk, x.clone(), alpha, beta, alice_sas_contribution_salt.clone());
    let redacted_vts_for_bob = (vt, alice_sas_contribution_salt.clone());

    let pvrf_ciphertext =  bincode::serialize(&redacted_vts_for_bob).unwrap().into_boxed_slice();
    //output vt, store vts



    // Alice generates eph sending ratchet key
    // Perform DH with Bob's ratchet key
    let sending_ratchet_key = KeyPair::generate(csprng);
    let (sending_chain_root_key, sending_chain_chain_key) = root_key.create_chain(
        parameters.their_ratchet_key(),
        &sending_ratchet_key.private_key,
    )?;

    let pqr_state = spqr::initial_state(spqr::Params {
        auth_key: &pqr_key,
        version: spqr::Version::V1,
        direction: spqr::Direction::A2B,
        min_version: spqr::Version::V1, // Require that all clients speak SPQR
        chain_params: spqr_chain_params(parameters.self_session()),
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
        &parameters.our_ephemeral_key_pair().public_key,
        pqr_state,
        None,
        Some(bincode::serialize(&vts).unwrap()),
        None,
    )
    .with_receiver_chain(parameters.their_ratchet_key(), &chain_key)
    .with_sender_chain(&sending_ratchet_key, &sending_chain_chain_key);

    

    session.set_kyber_ciphertext(kyber_ciphertext); // Ciphertext to send to Bob

    session.set_pvrf_ciphertext(pvrf_ciphertext); // Ciphertext to send to Bob

    Ok(session) // Alice's session ready for messaging
}

/// Initialize a session from the recipient's side.
///
/// Performs the PQXDH key agreement and then sets up the Double Ratchet
/// and SPQR state.
pub(crate) fn initialize_bob_session(
    parameters: &RecipientParameters,
    our_ratchet_key_pair: &KeyPair,
) -> Result<SessionState> {
    // validate Alice's (ephemeral) base key
    if !parameters.their_ephemeral_key().is_canonical() {
        return Err(SignalProtocolError::InvalidMessage(
            crate::CiphertextMessageType::PreKey,
            "incoming base key is invalid",
        ));
    }


    //step 0: "retrieve" parameters k, vk
    let g = generator_g();
    let k ;
    let vk ;
    let mut x = Vec::with_capacity(32 * 6);
    let bob_response;
    let true_sas: Option<Vec<u8>>;
    //let vt;

    x.extend_from_slice(parameters.their_identity_key().public_key().public_key_bytes());
    x.extend_from_slice(parameters.our_identity_key_pair().public_key().public_key_bytes());
    x.extend_from_slice(parameters.their_ephemeral_key().public_key_bytes());



    // Optional Bob's otpk * Alice's eph key
    if let Some(our_one_time_pre_key_pair) = parameters.our_one_time_pre_key_pair() {
        let arr: [u8; 32] = our_one_time_pre_key_pair.private_key.serialize()
            .try_into()
            .expect("at least 32 bytes required");
        k = Scalar::from_bytes_mod_order(arr);
        let bytes: [u8; 32] = our_one_time_pre_key_pair.public_key.public_key_bytes().try_into().unwrap();
        vk = MontgomeryPoint(bytes).to_edwards(0).unwrap();
        
        x.extend_from_slice(our_one_time_pre_key_pair.public_key.public_key_bytes());
    } else {

        let arr: [u8; 32] = parameters.our_signed_pre_key_pair().private_key.serialize()[..32]
            .try_into()
            .expect("at least 32 bytes required");
        k = Scalar::from_bytes_mod_order(arr);
        let bytes: [u8; 32] = parameters.our_signed_pre_key_pair().public_key.public_key_bytes().try_into().unwrap();
        vk = MontgomeryPoint(bytes).to_edwards(0).unwrap();
    }

    x.extend_from_slice(parameters.our_signed_pre_key_pair().public_key.public_key_bytes());

    let their_pvrf_ciphertext = parameters.their_pvrf_ciphertext().as_ref().map(|b| b.to_vec());
    if let Some(bytes) = their_pvrf_ciphertext {
        let (
            (h, hprime, (c, (s1, s2))),
            their_contrib_salt
        ): (
            (EdwardsPoint, EdwardsPoint, (Scalar, (Scalar, Scalar))),
            Vec<u8>
        ) = match bincode::deserialize(&bytes) {
            Ok(v) => v,
            Err(e) => {
                return Err(SignalProtocolError::InvalidArgument(format!(
                    "pvrf sas-ma: error parsing initiator pvrf {e}"
                )))
            }
        };
        // Step 1, parse vars
        //let tau = (c, (s1, s2));
        //let vt = (h, hprime, tau);

        // Step 2
        let hi = hash_i(&vk, &x);
        let ha = hash_a(&vk, &x);
        let hb = hash_b(&vk, &x);

        // η = g^s1 * Hi(vk,x)^s2 * h^c
        // η' = Ha(vk,x)^s1 * Hb(vk,x)^s2 * h'^c
        let eta = (g * s1) + (hi * s2) + (h * c);
        let etaprime = (ha * s1) + (hb * s2) + (hprime * c);

        let computed_c = hash_fs(&vk, &x, &h, &hprime, &eta, &etaprime);

        // abort if mismatch
        if c != computed_c {
            log::info!("PVRF SAS-MA ERROR: Bob can't confirm Alice really generated this data");
            log::error!("should raise an error in the frontend");
        } 

        // Step 3
        let w = hi * k;
        let z = hash_o(&w); //the sas?
        let v = h * k;
        let pi = (w, v);

        // Step 4
        let response =  (z.clone(), pi, c, computed_c); //(vk, x, vt, z, pi);
        bob_response = Some(bincode::serialize(&response).unwrap());
        true_sas = Some(
            z.clone().iter()
            .zip(their_contrib_salt.iter())
            .map(|(x, y)| x ^ y)
            .collect()
        );
    } else {
        //log::info!("No PVRF ciphertext provided in PreKey message; skipping PVRF processing");
        bob_response = None;
        true_sas = None;
    }



    // PQ ratchet from Bob to Alice
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
        true_sas,
        bob_response
    )
}

fn initialize_recipient_session(
    parameters: &RecipientParameters,
    our_ratchet_key_pair: &KeyPair,
    root_key: RootKey,
    chain_key: ChainKey,
    pqr_key: [u8; 32],
    true_sas: Option<Vec<u8>>,
    bob_response: Option<Vec<u8>>,
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let pqr_state = spqr::initial_state(spqr::Params {
        auth_key: &pqr_key,
        version: spqr::Version::V1,
        direction: spqr::Direction::B2A,
        min_version: spqr::Version::V1, // Require that all clients speak SPQR
        chain_params: spqr_chain_params(parameters.self_session()),
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
        parameters.their_ephemeral_key(),
        pqr_state,
        true_sas,
        None, 
        bob_response,
    )
    .with_sender_chain(our_ratchet_key_pair, &chain_key);

    Ok(session)
}


// Wrappers
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

pub fn pvrf_verify_from_session_data(
    vk_bytes: &[u8],
    _x_bytes: &[u8],
    alpha_bytes: &[u8],  // 32-byte LE scalar
    beta_bytes: &[u8],   // 32-byte LE scalar
    w_bytes: &[u8],      // 32-byte edwards
    v_bytes: &[u8],      // 32-byte edwards
) -> Result<(bool, Vec<u8>)> {

    // Parse alpha and beta scalars
    let alpha_arr: [u8; 32] = alpha_bytes.try_into().map_err(|_|
        SignalProtocolError::InvalidArgument("alpha must be 32 bytes".to_string()))?;
    let beta_arr: [u8; 32] = beta_bytes.try_into().map_err(|_|
        SignalProtocolError::InvalidArgument("beta must be 32 bytes".to_string()))?;

    let alpha = Option::<Scalar>::from(Scalar::from_canonical_bytes(alpha_arr))
        .ok_or_else(|| SignalProtocolError::InvalidArgument("invalid alpha scalar".to_string()))?;
    let beta = Option::<Scalar>::from(Scalar::from_canonical_bytes(beta_arr))
        .ok_or_else(|| SignalProtocolError::InvalidArgument("invalid beta scalar".to_string()))?;

    // Parse w and v points
    let w = CompressedEdwardsY::from_slice(w_bytes)
        .map_err(|_| SignalProtocolError::InvalidArgument("invalid w slice".to_string()))?
        .decompress()
        .ok_or_else(|| SignalProtocolError::InvalidArgument("w decompression failed".to_string()))?;

    let v = CompressedEdwardsY::from_slice(v_bytes)
        .map_err(|_| SignalProtocolError::InvalidArgument("invalid v slice".to_string()))?
        .decompress()
        .ok_or_else(|| SignalProtocolError::InvalidArgument("v decompression failed".to_string()))?;

    // z = Ho(w)
    let z = hash_o(&w);

    // Reconstruct vk
    let vk_point = CompressedEdwardsY::from_slice(vk_bytes)
        .map_err(|_| SignalProtocolError::InvalidArgument("invalid vk slice".to_string()))?
        .decompress()
        .ok_or_else(|| SignalProtocolError::InvalidArgument("vk decompression failed".to_string()))?;


    // v = vk^alpha * w^beta
    let calculated_v = (vk_point * alpha) + (w * beta);
    let alt_calculated_v = (-vk_point * alpha) + (w * beta);

    let ok = v.compress().as_bytes() == calculated_v.compress().as_bytes() || v.compress().as_bytes() == alt_calculated_v.compress().as_bytes();
    if !ok {
        log::error!("PVRF VERIFY FAILED: v != calculated_v, RAISE ERROR IN FRONTEND");
    }

    Ok((ok, z))
}