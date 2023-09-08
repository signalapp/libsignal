//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;

#[allow(unused_imports)]
use crate::support::*;
use crate::*;

#[allow(unused_imports)]
use ::usernames::{
    create_for_username, decrypt_username, NicknameLimits, Username, UsernameError,
    UsernameLinkError,
};

#[bridge_fn]
pub fn Username_Hash(username: String) -> Result<[u8; 32], UsernameError> {
    Username::new(&username).map(|un| un.hash())
}

#[bridge_fn]
pub fn Username_Proof(username: String, randomness: &[u8]) -> Result<Vec<u8>, UsernameError> {
    Username::new(&username)?.proof(randomness)
}

#[bridge_fn_void]
pub fn Username_Verify(proof: &[u8], hash: &[u8]) -> Result<(), UsernameError> {
    if hash.len() != 32 {
        return Err(UsernameError::ProofVerificationFailure);
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
) -> Result<String, UsernameError> {
    let mut rng = rand::rngs::OsRng;
    let limits = NicknameLimits::new(min_len as usize, max_len as usize);
    Username::candidates_from(&mut rng, &nickname, limits).map(|names| names.join(","))
}

#[bridge_fn]
pub fn UsernameLink_Create(username: String) -> Result<Vec<u8>, UsernameLinkError> {
    let mut rng = rand::rngs::OsRng;
    create_for_username(&mut rng, username)
}

#[bridge_fn]
pub fn UsernameLink_DecryptUsername(
    entropy: &[u8],
    encrypted_username: &[u8],
) -> Result<String, UsernameLinkError> {
    decrypt_username(entropy, encrypted_username)
}
