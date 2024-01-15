//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implements the Password Protected secret Sharing (PPSS) scheme of
//! [JKKX16](https://eprint.iacr.org/2016/144.pdf) using XOR-based secret sharing.

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::Scalar;
use displaydoc::Display;
use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use subtle::ConstantTimeEq;

use crate::oprf;
use crate::oprf::errors::OPRFError;

#[derive(Display, Debug)]
pub enum PPSSError {
    /// Invalid commitment, cannot reconstruct secret.
    InvalidCommitment,
    /// OPRF server output must encode canonical Ristretto points.
    BadPointEncoding,
    /// {0}
    LengthMismatch(&'static str),
}

impl std::error::Error for PPSSError {}

type Key = [u8; 32];
type KeyShare = [u8; 32];
type Secret256 = [u8; 32];

fn arr_xor<const N: usize>(lhs: &[u8; N], rhs: &[u8], dest: &mut [u8; N]) {
    for i in 0..N {
        dest[i] = lhs[i] ^ rhs[i];
    }
}

fn arr_xor_assign<const N: usize>(src: &[u8; N], acc: &mut [u8; N]) {
    for i in 0..N {
        acc[i] ^= src[i];
    }
}

fn create_xor_keyshares<R: CryptoRngCore>(
    secret: &Secret256,
    n: usize,
    rng: &mut R,
) -> Vec<KeyShare> {
    let mut result = Vec::<KeyShare>::with_capacity(n);
    // An accumulator keyshare
    let mut acc = *secret;
    for _ in 0..(n - 1) {
        let mut data = [0u8; 32];
        rng.fill_bytes(&mut data);
        arr_xor_assign(&data, &mut acc);
        result.push(data);
    }
    result.push(acc);
    result
}

fn combine_xor_keyshares(keyshares: &[KeyShare]) -> Secret256 {
    let mut secret = [0u8; 32];
    for share in keyshares {
        arr_xor_assign(share, &mut secret)
    }
    secret
}

// OPRF evaluation
/// An `OPRFSession` holds public information that a client needs to send a request
/// to the OPRF server as well as private information that will be needed to process
/// the server's response.
pub struct OPRFSession {
    pub server_id: u64,
    pub blinded_elt_bytes: [u8; 32],
    blind: Scalar,
    oprf_input: Vec<u8>,
}

fn prepare_oprf_input(context: &'static str, server_id: u64, input: &str) -> Vec<u8> {
    let mut oprf_input_bytes = Vec::<u8>::new();
    oprf_input_bytes.extend_from_slice(context.as_bytes());
    oprf_input_bytes.extend_from_slice(&server_id.to_le_bytes());
    oprf_input_bytes.extend_from_slice(input.as_bytes());
    oprf_input_bytes
}

fn oprf_session_from_inputs<R: CryptoRngCore>(
    context: &'static str,
    server_id: u64,
    input: &str,
    rng: &mut R,
) -> Result<OPRFSession, OPRFError> {
    let oprf_input = prepare_oprf_input(context, server_id, input);
    let (blind, blinded_elt) = oprf::client::blind(&oprf_input, rng)?;
    Ok(OPRFSession {
        server_id,
        blind,
        blinded_elt_bytes: blinded_elt.compress().to_bytes(),
        oprf_input,
    })
}

/// Prepare OPRF requests for a given context and input to send to a list of servers.
///
/// # Errors
/// Returns `OPRFError::BlindError` if a computed blinded element turns out to be the identity.
/// This is would happen if the OPRF input were constructed so that it hashed to the identity.
pub fn begin_oprfs<R: CryptoRngCore>(
    context: &'static str,
    server_ids: &[u64],
    input: &str,
    rng: &mut R,
) -> Result<Vec<OPRFSession>, OPRFError> {
    server_ids
        .iter()
        .map(|sid| oprf_session_from_inputs(context, *sid, input, rng))
        .collect()
}

fn finalize_single_oprf(session: OPRFSession, bytes: &[u8; 32]) -> Result<[u8; 64], PPSSError> {
    // deserialize the Ristretto point
    let evaluated_elt = CompressedRistretto(*bytes)
        .decompress()
        .ok_or(PPSSError::BadPointEncoding)?;
    Ok(oprf::client::finalize(
        &session.oprf_input,
        &session.blind,
        &evaluated_elt,
    ))
}

/// Process OPRF server responses using the `OPRFSessions` created by `begin_oprfs`.
///
/// The order of `evaluated_elts` must correspond to the order of the
/// `OPRFSessions`s each session holds a public `server_id` and
/// `blinded_element` and the N-th element of `evaluated_elts` must be the
/// result of the server in the N-th session acting on the `blinded_elt_bytes`
/// of the N-th session.
///
/// # Errors
/// Returns `PPSSError::BadPointEncoding` if some member of `evaluated_elts`
/// is not a canonical encoding of Ristretto point.
pub fn finalize_oprfs(
    sessions: Vec<OPRFSession>,
    evaluated_elts: &[[u8; 32]],
) -> Result<Vec<[u8; 64]>, PPSSError> {
    std::iter::zip(sessions, evaluated_elts)
        .map(|(session, bytes)| finalize_single_oprf(session, bytes))
        .collect()
}

// Password Protected Secret Sharing (PPSS) functions
/// A `MaskedShareSet` contains the information needed to restore a secret using a password.
#[derive(Clone, Debug)]
pub struct MaskedShareSet {
    pub server_ids: Vec<u64>,
    pub masked_shares: Vec<KeyShare>,
    pub commitment: [u8; 32],
}

fn compute_commitment(
    context: &'static str,
    password: &[u8],
    shares: Vec<KeyShare>,
    masked_shares: &[KeyShare],
    r: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher = hasher
        .chain_update(context.as_bytes())
        .chain_update(b"commitment")
        .chain_update(password);

    //add the masked shares
    for ms in masked_shares {
        hasher.update(ms);
    }

    // add the secret shares
    for s in shares {
        hasher.update(s);
    }

    hasher.update(r);
    hasher.finalize().into()
}

fn derive_key_and_bits_from_secret(secret: &Secret256, context: &'static str) -> [u8; 64] {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut r_and_k = [0u8; 64];
    hk.expand_multi_info(&[context.as_bytes(), b"keygen"], &mut r_and_k)
        .expect("hkdf requested an invalid length.");
    r_and_k
}

// Initialize a PPSS session
/// After evaluating OPRFs on a list of servers to get `oprf_outputs`, call `backup_secret` to create a
/// password-protected backup of the secret.
pub fn backup_secret<R: CryptoRngCore>(
    context: &'static str,
    password: &[u8],
    server_ids: Vec<u64>,
    oprf_outputs: Vec<[u8; 64]>,
    secret: &Secret256,
    rng: &mut R,
) -> Result<MaskedShareSet, PPSSError> {
    if server_ids.len() != oprf_outputs.len() {
        return Err(PPSSError::LengthMismatch(
            "Number of OPRF outputs does not match that of server ids",
        ));
    }
    let shares = create_xor_keyshares(secret, oprf_outputs.len(), rng);
    let masked_shares: Vec<[u8; 32]> = shares
        .iter()
        .zip(oprf_outputs.iter())
        .map(|(share, mask)| {
            let mut masked = [0u8; 32];
            arr_xor(share, &mask[..32], &mut masked);
            masked
        })
        .collect();
    let r_and_k = derive_key_and_bits_from_secret(secret, context);
    let r = &r_and_k[..32];
    let commitment = compute_commitment(context, password, shares, &masked_shares, r);

    Ok(MaskedShareSet {
        server_ids,
        masked_shares,
        commitment,
    })
}

/// Recover a secret with a PPSS share set. The `oprf_outputs` should be the result
/// of a call to `finalize_oprfs` and the order of the `server_ids` used in the call to
/// `finalize_oprfs` should match the order of the `server_ids` in `masked_shareset`.
///
/// # Errors
/// Returns `PPSSError::InvalidCommitment` when the reconstructed secret does not pass
/// integrity validation.
///
pub fn restore_secret(
    context: &'static str,
    password: &[u8],
    oprf_outputs: Vec<[u8; 64]>,
    masked_shareset: MaskedShareSet,
) -> Result<(Secret256, Key), PPSSError> {
    if oprf_outputs.len() != masked_shareset.masked_shares.len() {
        return Err(PPSSError::LengthMismatch(
            "Number of OPRF outputs does not match that of masked shares",
        ));
    }
    let keyshares: Vec<[u8; 32]> = masked_shareset
        .masked_shares
        .iter()
        .zip(oprf_outputs.iter())
        .map(|(masked_share, mask)| {
            let mut share = [0u8; 32];
            arr_xor(masked_share, &mask[..32], &mut share);
            share
        })
        .collect();
    let secret = combine_xor_keyshares(keyshares.as_slice());
    let r_and_k = derive_key_and_bits_from_secret(&secret, context);
    let (r, k) = r_and_k.split_at(32);
    let commitment = compute_commitment(
        context,
        password,
        keyshares,
        &masked_shareset.masked_shares,
        r,
    );

    if commitment.ct_eq(&masked_shareset.commitment).into() {
        Ok((secret, k.try_into().unwrap()))
    } else {
        Err(PPSSError::InvalidCommitment)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::RistrettoPoint;

    struct OPRFServerSet {
        server_secrets: HashMap<u64, [u8; 32]>,
    }

    impl OPRFServerSet {
        fn new(server_ids: &[u64]) -> Self {
            let server_secrets: HashMap<u64, [u8; 32]> = server_ids
                .iter()
                .cloned()
                .map(|sid| (sid, bytemuck::cast::<[u64; 4], [u8; 32]>([sid; 4])))
                .collect();

            Self { server_secrets }
        }

        fn eval(&self, server_id: &u64, blinded_elt_bytes: &[u8; 32]) -> [u8; 32] {
            let secret = Scalar::from_bytes_mod_order(*self.server_secrets.get(server_id).unwrap());
            oprf_eval_bytes(&secret, blinded_elt_bytes)
        }
    }

    const CONTEXT: &str = "signal-svr3-ppss-test";

    fn oprf_eval(secret: &Scalar, blinded_elt: &RistrettoPoint) -> RistrettoPoint {
        secret * blinded_elt
    }

    fn oprf_eval_bytes(secret: &Scalar, blinded_elt_bytes: &[u8; 32]) -> [u8; 32] {
        let blinded_elt = CompressedRistretto::from_slice(blinded_elt_bytes)
            .expect("can create compressed ristretto")
            .decompress()
            .expect("can decompress");
        let eval_elt = oprf_eval(secret, &blinded_elt);
        eval_elt.compress().to_bytes()
    }

    #[test]
    fn store_reconstruct_xor_shares() {
        let mut rng = rand_core::OsRng;

        // set up constants - secret, oprf secrets
        let secret = [42u8; 32];
        let password = "supahsecretpassword";

        let server_ids = vec![4u64, 1, 6];
        let oprf_servers = OPRFServerSet::new(&server_ids);
        // get the blinds - they are in order of server_id
        let oprf_init_sessions = begin_oprfs(CONTEXT, &server_ids, password, &mut rng).unwrap();

        // eval the oprfs
        let eval_elt_bytes: Vec<[u8; 32]> = oprf_init_sessions
            .iter()
            .map(|session| oprf_servers.eval(&session.server_id, &session.blinded_elt_bytes))
            .collect();

        let oprf_outputs = finalize_oprfs(oprf_init_sessions, eval_elt_bytes.as_slice())
            .expect("oprf evaluated element encodings must be canonical");
        let masked_shareset = backup_secret(
            CONTEXT,
            password.as_bytes(),
            server_ids,
            oprf_outputs,
            &secret,
            &mut rng,
        )
        .unwrap();

        // Now reconstruct
        let oprf_restore_sessions =
            begin_oprfs(CONTEXT, &masked_shareset.server_ids, password, &mut rng).unwrap();

        // eval the oprfs
        let restore_eval_elt_bytes: Vec<[u8; 32]> = oprf_restore_sessions
            .iter()
            .map(|session| oprf_servers.eval(&session.server_id, &session.blinded_elt_bytes))
            .collect();
        let restore_oprf_outputs =
            finalize_oprfs(oprf_restore_sessions, restore_eval_elt_bytes.as_slice())
                .expect("oprf evaluated element encodings must be canonical");

        let (restored_secret, restored_key) = restore_secret(
            CONTEXT,
            password.as_bytes(),
            restore_oprf_outputs,
            masked_shareset,
        )
        .expect("valid commitment");
        assert_eq!(secret, restored_secret);

        let r_and_k = derive_key_and_bits_from_secret(&secret, CONTEXT);
        assert_eq!(&r_and_k[32..64], &restored_key);
    }

    #[test]
    fn backup_length_mismatch() {
        let mut rng = rand_core::OsRng;
        let secret = [0; 32];
        assert!(matches!(
            backup_secret(CONTEXT, b"password", vec![42], vec![], &secret, &mut rng),
            Err(PPSSError::LengthMismatch(_))
        ));
    }

    #[test]
    fn restore_length_mismatch() {
        let share_set = MaskedShareSet {
            server_ids: vec![42],
            masked_shares: vec![[0u8; 32]],
            commitment: [1u8; 32],
        };
        assert!(matches!(
            restore_secret(CONTEXT, b"password", vec![], share_set),
            Err(PPSSError::LengthMismatch(_))
        ));
    }
}
