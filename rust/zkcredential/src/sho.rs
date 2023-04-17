//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Additional utilities for poksho's [`ShoApi`] types.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use poksho::ShoApi;

/// Extends [`ShoApi`] with convenience methods for generating Ristretto group elements.
pub trait ShoExt: ShoApi {
    /// Uses [`ShoApi::squeeze_and_ratchet`] to generate a pseudorandom point.
    fn get_point(&mut self) -> RistrettoPoint {
        let mut point_bytes = [0u8; 64];
        point_bytes.copy_from_slice(&self.squeeze_and_ratchet(64)[..]);
        RistrettoPoint::from_uniform_bytes(&point_bytes)
    }

    /// Uses [`ShoApi::squeeze_and_ratchet`] to generate a pseudorandom scalar.
    fn get_scalar(&mut self) -> Scalar {
        let mut scalar_bytes = [0u8; 64];
        scalar_bytes.copy_from_slice(&self.squeeze_and_ratchet(64)[..]);
        Scalar::from_bytes_mod_order_wide(&scalar_bytes)
    }
}

impl<T: ShoApi + ?Sized> ShoExt for T {}
