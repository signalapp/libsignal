//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(not(feature = "extraction"))]
use serde::{Deserialize, Serialize};

/// Timestamp recorded as milliseconds since the Unix epoch.
#[cfg_attr(not(feature = "extraction"), derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Timestamp {
    millis: u64,
}

impl Timestamp {
    pub const fn from_epoch_millis(milliseconds: u64) -> Self {
        Self {
            millis: milliseconds,
        }
    }

    pub const fn epoch_millis(&self) -> u64 {
        self.millis
    }

    pub fn add_millis(&self, milliseconds: u64) -> Self {
        Self {
            millis: self.millis + milliseconds,
        }
    }

    pub fn sub_millis(&self, milliseconds: u64) -> Timestamp {
        Self {
            millis: self.millis - milliseconds,
        }
    }
}

impl From<Timestamp> for std::time::SystemTime {
    fn from(value: Timestamp) -> Self {
        Self::UNIX_EPOCH + std::time::Duration::from_millis(value.epoch_millis())
    }
}

#[cfg(not(feature = "extraction"))]
impl rand::distr::Distribution<Timestamp> for rand::distr::StandardUniform {
    fn sample<R: rand::prelude::Rng + ?Sized>(&self, rng: &mut R) -> Timestamp {
        Timestamp {
            millis: Self::sample(self, rng),
        }
    }
}
