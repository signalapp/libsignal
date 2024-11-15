//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
//! Implements the Prefix Tree.
use std::result::Result;

use sha2::{Digest as _, Sha256};

use crate::proto::PrefixProof as SearchResult;

const KEY_LENGTH: usize = 32;

/// Malformed proof
#[derive(Debug, displaydoc::Display)]
pub struct MalformedProof;

fn leaf_hash(key: &[u8; 32], ctr: u32, pos: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(key);
    hasher.update(ctr.to_be_bytes());
    hasher.update(pos.to_be_bytes());

    hasher.finalize().into()
}

fn parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);

    hasher.finalize().into()
}

fn evaluate_proof(
    key: &[u8; 32],
    value: &[u8; 32],
    proof: &[Vec<u8>],
) -> Result<[u8; 32], MalformedProof> {
    if proof.len() != 8 * KEY_LENGTH {
        return Err(MalformedProof);
    }

    let mut value = *value;
    for i in 0..proof.len() {
        let sibling: &[u8; 32] = proof[i].as_slice().try_into().map_err(|_| MalformedProof)?;

        let n = proof.len() - i - 1;
        let b = key[n / 8] >> (7 - (n % 8)) & 1; // Read n^th bit of key

        value = if b == 0 {
            parent_hash(&value, sibling)
        } else {
            parent_hash(sibling, &value)
        }
    }
    Ok(value)
}

// Takes a search result `res` as input, which was returned by searching for
// `key`, and returns the root that would make the proof valid. `pos` is the
// position of the first instance of `key` in the log.
pub fn evaluate(key: &[u8; 32], pos: u64, res: &SearchResult) -> Result<[u8; 32], MalformedProof> {
    evaluate_proof(key, &leaf_hash(key, res.counter, pos), &res.proof)
}
