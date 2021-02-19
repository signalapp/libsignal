//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use std::collections::HashMap;

// Simple 'newtype' wrappers around HashMap to make string literals more convenient

#[derive(Clone)]
pub struct ScalarArgs(pub HashMap<String, Scalar>);

#[derive(Clone)]
pub struct PointArgs(pub HashMap<String, RistrettoPoint>);

impl ScalarArgs {
    pub fn new() -> Self {
        Self(HashMap::<String, Scalar>::new())
    }

    pub fn add(&mut self, s: &str, val: Scalar) {
        self.0.insert(s.to_string(), val);
    }
}

impl Default for ScalarArgs {
    fn default() -> Self {
        Self::new()
    }
}

impl PointArgs {
    pub fn new() -> Self {
        Self(HashMap::<String, RistrettoPoint>::new())
    }

    pub fn add(&mut self, s: &str, val: RistrettoPoint) {
        self.0.insert(s.to_string(), val);
    }
}

impl Default for PointArgs {
    fn default() -> Self {
        Self::new()
    }
}
