//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

pub type G1 = Vec<Scalar>; // Schnorr proves preimage of homomorphism from G1 -> G2
pub type G2 = Vec<RistrettoPoint>;
