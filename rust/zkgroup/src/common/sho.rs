//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use poksho::ShoApi;

pub struct Sho {
    internal_sho: poksho::ShoHmacSha256,
}

impl Sho {
    pub fn new(label: &[u8], data: &[u8]) -> Self {
        let mut sho = poksho::ShoHmacSha256::new(label);
        sho.absorb_and_ratchet(data);
        Sho { internal_sho: sho }
    }

    pub fn absorb_and_ratchet(&mut self, data: &[u8]) {
        self.internal_sho.absorb_and_ratchet(data)
    }

    pub fn squeeze(&mut self, outlen: usize) -> Vec<u8> {
        self.internal_sho.squeeze_and_ratchet(outlen)
    }

    pub fn get_point(&mut self) -> RistrettoPoint {
        let mut point_bytes = [0u8; 64];
        point_bytes.copy_from_slice(&self.internal_sho.squeeze_and_ratchet(64)[..]);
        RistrettoPoint::from_uniform_bytes(&point_bytes)
    }

    pub fn get_point_single_elligator(&mut self) -> RistrettoPoint {
        let mut point_bytes = [0u8; 32];
        point_bytes.copy_from_slice(&self.internal_sho.squeeze_and_ratchet(32)[..]);
        RistrettoPoint::from_uniform_bytes_single_elligator(&point_bytes)
    }

    pub fn get_scalar(&mut self) -> Scalar {
        let mut scalar_bytes = [0u8; 64];
        scalar_bytes.copy_from_slice(&self.internal_sho.squeeze_and_ratchet(64)[..]);
        Scalar::from_bytes_mod_order_wide(&scalar_bytes)
    }
}
