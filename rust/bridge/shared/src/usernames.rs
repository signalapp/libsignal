//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;

use crate::support::*;
use crate::*;

use ::usernames::{NicknameLimits, Username, UsernameError};

#[bridge_fn_buffer]
pub fn Username_Hash(username: String) -> Result<[u8; 32], UsernameError> {
    Username::new(&username).map(|un| un.hash())
}

#[bridge_fn_buffer]
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
