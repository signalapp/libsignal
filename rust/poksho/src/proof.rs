//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::scalar::*;
use crate::simple_types::*;
use curve25519_dalek::scalar::Scalar;

// We use compact Schnorr signatures, sending the challenge instead of commitments
pub struct Proof {
    pub challenge: Scalar,
    pub response: G1,
}

impl Proof {
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let num_scalars = bytes.len() / 32;
        if !(2..=257).contains(&num_scalars) || num_scalars * 32 != bytes.len() {
            return None;
        }
        let challenge = scalar_from_slice_canonical(&bytes[0..32])?;
        let mut response = Vec::<Scalar>::with_capacity(num_scalars - 1);
        for i in 1..num_scalars {
            response.push(scalar_from_slice_canonical(&bytes[32 * i..(32 * i) + 32])?);
        }
        Some(Proof {
            challenge,
            response,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::with_capacity(self.response.len() * 32);
        bytes.extend_from_slice(self.challenge.as_bytes());
        for scalar in &self.response {
            bytes.extend_from_slice(scalar.as_bytes());
        }
        bytes
    }
}
