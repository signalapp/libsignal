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


fn encode(vk: &Vec<u8>, x: &[u8]) -> Vec<u8> {
    [vk.len().to_le_bytes().as_slice(), vk, x].concat()
}


pub fn generator_g() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

pub fn hash_generic_zp(input: &[u8]) -> Scalar {
    let hash = Sha512::digest(input);
    Scalar::from_bytes_mod_order_wide(&hash.into())
}

pub fn hash_fs(vk: &Vec<u8>, x: &[u8], h: &RistrettoPoint, h_prime: &RistrettoPoint, eta: &RistrettoPoint, eta_prime: &RistrettoPoint) -> Scalar {
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

pub fn hash_i(vk: &Vec<u8>, x: &[u8]) -> RistrettoPoint {
    hash_to_G(b"hash_i", &encode(vk, x))
}

pub fn hash_a(vk: &Vec<u8>, x: &[u8]) -> RistrettoPoint {
    hash_to_G(b"hash_a", &encode(vk, x))
}

pub fn hash_b(vk: &Vec<u8>, x: &[u8]) -> RistrettoPoint {
    hash_to_G(b"hash_b", &encode(vk, x))
}

pub fn hash_o(point: &RistrettoPoint) -> Vec<u8> {
    // Compress the RistrettoPoint to a canonical 32-byte representation
    let compressed = point.compress();

    let hash = Sha256::digest(compressed.as_bytes());
    hash[..3].to_vec()
}

pub fn point_to_bytes(point: &RistrettoPoint) -> Vec<u8> {
    point.compress().as_bytes().to_vec()
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
        vk = their_one_time_prekey.public_key_bytes().to_vec();
    } else {
        vk = parameters.their_signed_pre_key().public_key_bytes().to_vec();
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
    let h = alpha * g + beta * hash_i(&vk, &secrets);    
    let hprime = alpha * hash_a(&vk, &secrets) + beta * hash_b(&vk, &secrets);

    //step 2
    let r1 = hash_generic_zp(b"r1");
    let r2 = hash_generic_zp(b"r2");
    // scalar * point = point to the power of scaler in paper
    let eta = (g * r1) + (hash_i(&vk, &secrets) * r2);
    let etaprime = (hash_a(&vk, &secrets) * r1) + (hash_b(&vk, &secrets) * r2);
    let c = hash_fs(&vk, &secrets, &h, &hprime, &eta, &etaprime);
    //s values should be mod p
    let s = (r1 - c * alpha, r2 - c * beta);
    let tau = (c,s);

    //step 3
    let vt = (h, hprime, tau);
    let vts = (vt, vk, secrets.clone(), alpha, beta);

    let pvrf_ciphertext =  bincode::serialize(&vts).unwrap().into_boxed_slice();
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

    session.set_pvrf_ciphertext(pvrf_ciphertext); // Ciphertext to send to Bob

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
    // fresh genning them for rapid dev right now
    let g = generator_g();
    let k ;//= hash_generic_zp(b"placeholder fresh k for vk");
    let vk ;//= point_to_bytes(&(g * k));
    let kptr;
    let x;
    let their_vts;
    let vts_response;
    let bob_response;
    //let vt;



    // Optional Bob's otpk * Alice's eph key
    if let Some(our_one_time_pre_key_pair) = parameters.our_one_time_pre_key_pair() {
        secrets.extend_from_slice(
            &our_one_time_pre_key_pair
                .private_key
                .calculate_agreement(parameters.their_base_key())?,
        );
        kptr = our_one_time_pre_key_pair;
        vk = our_one_time_pre_key_pair.public_key.public_key_bytes().to_vec();
        k = hash_generic_zp(our_one_time_pre_key_pair.private_key.serialize().as_ref());
    } else {
        kptr = parameters.our_signed_pre_key_pair();
        vk = parameters.our_signed_pre_key_pair().public_key.public_key_bytes().to_vec();
        k = hash_generic_zp(parameters.our_signed_pre_key_pair().private_key.serialize().as_ref());


    //      vk = their_one_time_prekey.public_key_bytes().to_vec();
    // } else {
    //     vk = parameters.their_signed_pre_key().public_key_bytes().to_vec();
    }

    // Bob's Kyber secret key recovers shared PQ secret from Alice's ciphertext
    secrets.extend_from_slice(
        &parameters
            .our_kyber_pre_key_pair()
            .secret_key
            .decapsulate(parameters.their_kyber_ciphertext())?,
    );

    x = &secrets;
    let their_pvrf_ciphertext = parameters.their_pvrf_ciphertext().as_ref().map(|b| b.to_vec());
    log::info!(
        "PVRF ciphertext in PreKey message as Bob: {}",
        their_pvrf_ciphertext
            .as_ref()
            .map(|_| "present")
            .unwrap_or("not present")
    );
    if let Some(bytes) = their_pvrf_ciphertext {
        log::info!("PVRF ciphertext bytes: {:?}", bytes);
        let (
            (h, hprime, (c, (s1, s2))),
            their_vk, //should be null or unset in real
            their_secrets, //should be null or unset in real
            their_alpha, //should be null or unset in real
            their_beta //should be null or unset in real
        ): (
            (RistrettoPoint, RistrettoPoint, (Scalar, (Scalar, Scalar))),
            Vec<u8>,
            Vec<u8>,
            Scalar,
            Scalar
        ) = bincode::deserialize(&bytes).unwrap();
        // Step 1, parse vars
        let tau = (c, (s1, s2));
        let vt = (h, hprime, tau);
        their_vts = (vt, their_vk, their_secrets, their_alpha, their_beta);
        vts_response = Some(bincode::serialize(&their_vts).unwrap());

        // Step 2
        let hi = hash_i(&vk, x);
        let ha = hash_a(&vk, x);
        let hb = hash_b(&vk, x);

        // η = g^s1 * Hi(vk,x)^s2 * h^c
        // η' = Ha(vk,x)^s1 * Hb(vk,x)^s2 * h'^c
        let eta = (g * (s1)) + (hi * (s2)) + h * (c);
        let etaprime = (ha * (s1)) + (hb * (s2)) + (hprime * (c));

        let computed_c = hash_fs(&vk, x, &h, &hprime, &eta, &etaprime);

        // abort if mismatch
        if c != computed_c {
            //panic!("abort");
            log::info!("THE C'S DIDNT MATCH FOR BOB, SHOULD HAVE ABORTED");
        } else {
            log::info!("THE C'S MATCHED FOR BOB'S SIDE");
        }

        // Step 3
        let w = hi*(k);
        let z = hash_o(&w); //the sas?
        let v = h * (k);
        let pi = (w, v);

        // Step 4
        let response =  (vk, x.clone(), vt, z, pi, c, computed_c); //(vk, x, vt, z, pi);
        bob_response = Some(bincode::serialize(&response).unwrap());
        log::info!("Bob's PVRF response: {:?}", bob_response);
        let example_decoded_bob_response: (Vec<u8>, Vec<u8>, (RistrettoPoint, RistrettoPoint, (Scalar, (Scalar, Scalar))), Vec<u8>, (RistrettoPoint, RistrettoPoint), Scalar, Scalar)
         =   bincode::deserialize(
            bob_response.as_ref().unwrap()
            )
        .unwrap();
        log::info!("Decoded Bob's PVRF response: {:?}", example_decoded_bob_response);
    } else {
        log::info!("No PVRF ciphertext provided in PreKey message; skipping PVRF processing");
        vts_response = None;
        bob_response = None;
    }


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
        vts_response, //should be None in real, using for logging now
        bob_response,
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

use curve25519_dalek::ristretto::CompressedRistretto;
fn read_u32_le(buf: &[u8], offset: &mut usize) -> Result<usize> {
    if *offset + 4 > buf.len() {
        return Err(SignalProtocolError::InvalidArgument(
            "buffer too short reading u32".to_string(),
        ));
    }
    let val = u32::from_le_bytes(buf[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    Ok(val)
}
 
fn read_bytes<'a>(buf: &'a [u8], offset: &mut usize, n: usize) -> Result<&'a [u8]> {
    if *offset + n > buf.len() {
        return Err(SignalProtocolError::InvalidArgument(
            "buffer too short reading bytes".to_string(),
        ));
    }
    let slice = &buf[*offset..*offset + n];
    *offset += n;
    Ok(slice)
}
fn read_point(buf: &[u8], offset: &mut usize) -> Result<RistrettoPoint> {
    let bytes = read_bytes(buf, offset, 32)?;
    // CompressedRistretto::from_slice returns a Result in newer dalek versions,
    // or a plain CompressedRistretto in older ones. Adjust the unwrap style to
    // match whichever dalek version your workspace uses.
    CompressedRistretto::from_slice(bytes)
        .map_err(|_| SignalProtocolError::InvalidArgument(
            "invalid compressed ristretto slice length".to_string(),
        ))?
        .decompress()
        .ok_or_else(|| SignalProtocolError::InvalidArgument(
            "ristretto point decompression failed".to_string(),
        ))
}
 
// Reconstruct a Scalar from 32 bytes — same as the snippet:
//   let temp_c_from_bytes = Scalar::from_canonical_bytes(temp_c).unwrap();
fn read_scalar(buf: &[u8], offset: &mut usize) -> Result<Scalar> {
    let bytes = read_bytes(buf, offset, 32)?;
    let arr: [u8; 32] = bytes.try_into().unwrap();
    // from_canonical_bytes returns CtOption; use unwrap_or_else for a proper error.
    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr))
        .ok_or_else(|| SignalProtocolError::InvalidArgument(
            "invalid canonical scalar bytes".to_string(),
        ))
}

pub fn pvrf_verify_from_session_data(
    vts_bytes: &[u8],
    bob_response_bytes: &[u8],
) -> Result<(bool, Vec<u8>)> {
 
    let mut vo = 0usize; // vts offset
 
    let h      = read_point(vts_bytes, &mut vo)?;
    let hprime = read_point(vts_bytes, &mut vo)?;
    let c      = read_scalar(vts_bytes, &mut vo)?; // tau.c  == s1 in bridge naming
    let s1     = read_scalar(vts_bytes, &mut vo)?; // tau.s.0
    let s2     = read_scalar(vts_bytes, &mut vo)?; // tau.s.1
 
    let vk_len = read_u32_le(vts_bytes, &mut vo)?;
    let vk     = read_bytes(vts_bytes, &mut vo, vk_len)?.to_vec();
 
    let x_len  = read_u32_le(vts_bytes, &mut vo)?;
    let x      = read_bytes(vts_bytes, &mut vo, x_len)?.to_vec();
 
    let alpha  = read_scalar(vts_bytes, &mut vo)?; // r1
    let beta   = read_scalar(vts_bytes, &mut vo)?; // r2
 
    // ── Parse Bob's response (from SessionRecord_GetBobResponse) ───────────
    //
    // Layout written by SessionRecord_GetBobResponse in bridge.rs:
    //    4  vk.len()
    //   ... vk
    //    4  x.len()
    //   ... x
    //   32  h      (compressed ristretto)
    //   32  hprime (compressed ristretto)
    //   32  s1     (scalar)   — bob's tau.c
    //   32  s2_1   (scalar)   — bob's tau.s.0
    //   32  s2_2   (scalar)   — bob's tau.s.1
    //    4  z.len()
    //   ... z      (bytes, the SAS = hash_o output, 3 bytes normally)
    //   32  w      (compressed ristretto)
    //   32  v      (compressed ristretto)
    //   32  c      (scalar)   — bob_c_sent
    //   32  computed_c (scalar)
 
    let mut bo = 0usize; // bob offset
 
    let bob_vk_len  = read_u32_le(bob_response_bytes, &mut bo)?;
    let bob_vk      = read_bytes(bob_response_bytes, &mut bo, bob_vk_len)?.to_vec();
 
    let bob_x_len   = read_u32_le(bob_response_bytes, &mut bo)?;
    let bob_x       = read_bytes(bob_response_bytes, &mut bo, bob_x_len)?.to_vec();
 
    let bob_h       = read_point(bob_response_bytes, &mut bo)?;
    let bob_hprime  = read_point(bob_response_bytes, &mut bo)?;
    let bob_s1      = read_scalar(bob_response_bytes, &mut bo)?;
    let bob_s2_1    = read_scalar(bob_response_bytes, &mut bo)?;
    let bob_s2_2    = read_scalar(bob_response_bytes, &mut bo)?;
 
    let z_len       = read_u32_le(bob_response_bytes, &mut bo)?;
    let z           = read_bytes(bob_response_bytes, &mut bo, z_len)?.to_vec();
 
    let w           = read_point(bob_response_bytes, &mut bo)?;
    let v           = read_point(bob_response_bytes, &mut bo)?;
    let bob_c_sent  = read_scalar(bob_response_bytes, &mut bo)?;
    let bob_comp_c  = read_scalar(bob_response_bytes, &mut bo)?;
 
    // ── Checks ───────────────────────────────────────────────────────────────
 
    // 1. vk and x must match between Alice's stored VTS and Bob's response
    if vk != bob_vk {
        log::error!("PVRF VERIFY FAILED: vk mismatch");
        return Ok((false, z));
    }
    if x != bob_x {
        log::error!("PVRF VERIFY FAILED: x mismatch");
        return Ok((false, z));
    }
 
    // 2. The vt tuple (h, hprime, tau) Alice stored must equal what Bob echoed back
    //    NOTE: the original code had a missing `}` here which made check 3 unreachable.
    if h != bob_h || hprime != bob_hprime || c != bob_s1 || s1 != bob_s2_1 || s2 != bob_s2_2 {
        log::error!("PVRF VERIFY FAILED: vt mismatch");
        return Ok((false, z));
    }  // <— this brace was missing in the original, fixed here
 
    // 3. Bob's own c check (ensures Bob didn't cheat in his step 2)
    if bob_c_sent != bob_comp_c {
        log::error!("PVRF VERIFY FAILED: Bob's c_sent != computed_c");
        return Ok((false, z));
    }
 
    // 4. z = Ho(w)  — Alice recomputes hash_o(w) and checks it matches Bob's z
    let expected_z = hash_o(&w);
    let ok_z = z == expected_z;
 
    // 5. v = vk^alpha * w^beta  — the SPHF verification (paper Fig 2, Verify step)
    //    vk is stored as 32 compressed bytes, reconstruct it as a RistrettoPoint
    let vk_point = CompressedRistretto::from_slice(&vk)
        .map_err(|_| SignalProtocolError::InvalidArgument(
            "vk slice length invalid".to_string(),
        ))?
        .decompress()
        .ok_or_else(|| SignalProtocolError::InvalidArgument(
            "vk decompression failed".to_string(),
        ))?;
 
    // v = vk^alpha * w^beta  (additive notation: alpha*vk_point + beta*w)
    let expected_v = (vk_point * alpha) + (w * beta);
    let ok_v = v == expected_v;
 
    let ok = ok_z && ok_v;
 
    if ok {
        log::info!("✅ PVRF VERIFY SUCCESS — SAS z: {:?}", z);
    } else {
        log::error!(
            "❌ PVRF VERIFY FAILED — ok_z={}, ok_v={}", ok_z, ok_v
        );
        log::error!("  expected_z={:?}  actual_z={:?}", expected_z, z);
    }
 
    Ok((ok, z))
}