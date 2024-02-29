//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::borrow::Cow;
use std::collections::HashMap;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

// Simple 'newtype' wrappers around HashMap to make string literals more convenient

#[derive(Clone)]
pub struct ScalarArgs(pub HashMap<Cow<'static, str>, Scalar>);

#[derive(Clone)]
pub struct PointArgs(pub HashMap<Cow<'static, str>, RistrettoPoint>);

impl ScalarArgs {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn add(&mut self, s: impl Into<Cow<'static, str>>, val: Scalar) {
        self.0.insert(s.into(), val);
    }
}

impl Default for ScalarArgs {
    fn default() -> Self {
        Self::new()
    }
}

impl PointArgs {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn add(&mut self, s: impl Into<Cow<'static, str>>, val: RistrettoPoint) {
        self.0.insert(s.into(), val);
    }
}

impl Default for PointArgs {
    fn default() -> Self {
        Self::new()
    }
}
