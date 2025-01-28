//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[allow(unused_imports)]
use ::usernames::{
    create_for_username, decrypt_username, NicknameLimits, Username, UsernameError,
    UsernameLinkError,
};
use libsignal_bridge_macros::*;

#[allow(unused_imports)]
use crate::support::*;
use crate::*;

#[bridge_fn]
pub fn Username_Hash(username: String) -> Result<[u8; 32], UsernameError> {
    Username::new(&username).map(|un| un.hash())
}

#[bridge_fn]
pub fn Username_Proof(username: String, randomness: &[u8; 32]) -> Result<Vec<u8>, UsernameError> {
    Username::new(&username)?.proof(randomness)
}

#[bridge_fn]
pub fn Username_Verify(
    proof: &[u8],
    hash: &[u8],
) -> Result<(), ::usernames::ProofVerificationFailure> {
    if hash.len() != 32 {
        return Err(::usernames::ProofVerificationFailure);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(hash);
    Username::verify_proof(proof, arr)
}

#[bridge_fn]
pub fn Username_CandidatesFrom(
    nickname: String,
    min_len: u32,
    max_len: u32,
) -> Result<Box<[String]>, UsernameError> {
    let mut rng = rand::rngs::OsRng;
    let limits = NicknameLimits::new(min_len as usize, max_len as usize);
    Username::candidates_from(&mut rng, &nickname, limits).map(Vec::into_boxed_slice)
}

#[bridge_fn]
pub fn Username_HashFromParts(
    nickname: String,
    discriminator: String,
    min_len: u32,
    max_len: u32,
) -> Result<[u8; 32], UsernameError> {
    let limits = NicknameLimits::new(min_len as usize, max_len as usize);
    Username::from_parts(&nickname, &discriminator, limits).map(|un| un.hash())
}

#[bridge_fn(ffi = false)]
pub fn UsernameLink_Create(
    username: String,
    entropy: Option<&[u8]>,
) -> Result<Vec<u8>, UsernameLinkError> {
    let mut rng = rand::rngs::OsRng;
    let entropy = entropy
        .map(|buf| {
            buf.try_into()
                .map_err(|_| UsernameLinkError::InvalidEntropyDataLength)
        })
        .transpose()?;
    let (entropy, mut buffer) = create_for_username(&mut rng, username, entropy)?;
    buffer.splice(0..0, entropy);
    Ok(buffer)
}

#[bridge_fn(ffi = "username_link_create", jni = false, node = false)]
pub fn UsernameLink_CreateAllowingEmptyEntropy(
    username: String,
    entropy: &[u8],
) -> Result<Vec<u8>, UsernameLinkError> {
    let mut rng = rand::rngs::OsRng;
    let entropy = if entropy.is_empty() {
        None
    } else {
        Some(
            entropy
                .try_into()
                .map_err(|_| UsernameLinkError::InvalidEntropyDataLength)?,
        )
    };
    let (entropy, mut buffer) = create_for_username(&mut rng, username, entropy)?;
    buffer.splice(0..0, entropy);
    Ok(buffer)
}

#[bridge_fn]
pub fn UsernameLink_DecryptUsername(
    entropy: &[u8],
    encrypted_username: &[u8],
) -> Result<String, UsernameLinkError> {
    let entropy = entropy
        .try_into()
        .map_err(|_| UsernameLinkError::InvalidEntropyDataLength)?;
    decrypt_username(entropy, encrypted_username)
}
