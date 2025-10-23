//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use curve25519_dalek_signal::ristretto::RistrettoPoint;
use curve25519_dalek_signal::scalar::Scalar;
use poksho::ShoApi;
use poksho::shoapi::ShoApiExt as _;

#[derive(Clone)]
pub struct Sho {
    internal_sho: poksho::ShoHmacSha256,
}

impl Sho {
    /// Creates a Sho and immediately absorbs `data` and ratchets.
    ///
    /// This is exactly equivalent to calling [`Sho::new_seed`] followed by
    /// [`Sho::absorb_and_ratchet`]. Meant for when you're not doing any other absorbing.
    pub fn new(label: &[u8], data: &[u8]) -> Self {
        let mut sho = Self::new_seed(label);
        sho.absorb_and_ratchet(data);
        sho
    }

    pub fn new_seed(label: &[u8]) -> Self {
        let sho = poksho::ShoHmacSha256::new(label);
        Sho { internal_sho: sho }
    }

    pub fn absorb_and_ratchet(&mut self, data: &[u8]) {
        self.internal_sho.absorb_and_ratchet(data)
    }

    pub fn squeeze(&mut self, outlen: usize) -> Vec<u8> {
        self.internal_sho.squeeze_and_ratchet(outlen)
    }

    pub fn squeeze_as_array<const N: usize>(&mut self) -> [u8; N] {
        self.internal_sho.squeeze_and_ratchet_as_array()
    }

    pub fn get_point(&mut self) -> RistrettoPoint {
        RistrettoPoint::from_uniform_bytes(&self.internal_sho.squeeze_and_ratchet_as_array())
    }

    pub fn get_point_single_elligator(&mut self) -> RistrettoPoint {
        RistrettoPoint::from_uniform_bytes_single_elligator(
            &self.internal_sho.squeeze_and_ratchet_as_array(),
        )
    }

    pub fn get_scalar(&mut self) -> Scalar {
        Scalar::from_bytes_mod_order_wide(&self.internal_sho.squeeze_and_ratchet_as_array())
    }
}

impl AsMut<poksho::ShoHmacSha256> for Sho {
    fn as_mut(&mut self) -> &mut poksho::ShoHmacSha256 {
        &mut self.internal_sho
    }
}
