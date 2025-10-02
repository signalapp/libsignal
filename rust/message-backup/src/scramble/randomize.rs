//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use rand::Rng;
use rand::distr::{Alphanumeric, SampleString as _};

/// Replaces the contents with something random that is the same length.
///
/// More specific than "scramble" or "accept(scrambler)", so it's clearer that this is the right
/// choice for how to scramble a particular field.
pub trait Randomize {
    fn randomize(&mut self, rng: &mut impl Rng);
}

impl<T> Randomize for Option<T>
where
    T: Randomize,
{
    fn randomize(&mut self, rng: &mut impl Rng) {
        if let Some(x) = self.as_mut() {
            x.randomize(rng)
        }
    }
}

impl Randomize for String {
    fn randomize(&mut self, rng: &mut impl Rng) {
        *self = Alphanumeric.sample_string(rng, self.len());
    }
}

impl Randomize for [u8] {
    fn randomize(&mut self, rng: &mut impl Rng) {
        rng.fill_bytes(self);
    }
}

impl Randomize for Vec<u8> {
    fn randomize(&mut self, rng: &mut impl Rng) {
        self.as_mut_slice().randomize(rng);
    }
}

impl<T: Randomize> Randomize for Vec<T> {
    fn randomize(&mut self, rng: &mut impl Rng) {
        self.iter_mut().for_each(|x| x.randomize(rng));
    }
}

macro_rules! randomize_integer {
    ($name:ty) => {
        impl Randomize for $name {
            fn randomize(&mut self, rng: &mut impl Rng) {
                *self = rng.random();
            }
        }
    };
}

randomize_integer!(u32);
randomize_integer!(u64);

/// Generates a random but valid v4 UUID.
pub fn random_uuid(rng: &mut impl Rng) -> Vec<u8> {
    uuid::Builder::from_random_bytes(rng.random())
        .into_uuid()
        .into_bytes()
        .to_vec()
}
