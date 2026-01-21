//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use curve25519_dalek::scalar::Scalar;

use crate::simple_types::*;

// We use compact Schnorr signatures, sending the challenge instead of commitments
pub struct Proof {
    pub challenge: Scalar,
    pub response: G1,
}

impl Proof {
    /// Parses the given byte slice as a `Proof`.
    ///
    /// Returns `None` if the input is invalid. This does not run in constant
    /// time!
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let (chunks, chunks_remainder) = bytes.as_chunks::<32>();
        if !chunks_remainder.is_empty() {
            return None;
        }
        let mut array_chunks = chunks
            .iter()
            .map(|chunk| Option::from(Scalar::from_canonical_bytes(*chunk)));

        let challenge = array_chunks.next()??;
        if array_chunks.len() > 256 {
            return None;
        }

        let response = array_chunks.collect::<Option<Vec<Scalar>>>()?;
        if response.is_empty() {
            return None;
        }
        Some(Proof {
            challenge,
            response,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.challenge]
            .into_iter()
            .chain(&self.response)
            .flat_map(|scalar| *scalar.as_bytes())
            .collect()
    }
}
