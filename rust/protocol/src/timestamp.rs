//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use serde::{Deserialize, Serialize};

/// Timestamp recorded as milliseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const fn from_epoch_millis(milliseconds: u64) -> Self {
        Self(milliseconds)
    }

    pub const fn epoch_millis(&self) -> u64 {
        self.0
    }

    pub fn add_millis(&self, milliseconds: u64) -> Self {
        Self(self.0 + milliseconds)
    }

    pub fn sub_millis(&self, milliseconds: u64) -> Timestamp {
        Self(self.0 - milliseconds)
    }
}

impl From<Timestamp> for std::time::SystemTime {
    fn from(value: Timestamp) -> Self {
        Self::UNIX_EPOCH + std::time::Duration::from_millis(value.epoch_millis())
    }
}

#[derive(Debug, displaydoc::Display)]
pub enum UnrepresentableTimestamp {
    /// too far in the past
    TooFarInPast,
    /// too far in the future
    TooFarInFuture,
}

impl TryFrom<std::time::SystemTime> for Timestamp {
    type Error = UnrepresentableTimestamp;

    fn try_from(value: std::time::SystemTime) -> Result<Self, Self::Error> {
        match value.duration_since(std::time::SystemTime::UNIX_EPOCH) {
            Ok(duration) => match duration.as_millis().try_into() {
                Ok(millis) => Ok(Self::from_epoch_millis(millis)),
                Err(_) => Err(UnrepresentableTimestamp::TooFarInFuture),
            },
            Err(_) => Err(UnrepresentableTimestamp::TooFarInPast),
        }
    }
}

impl rand::distr::Distribution<Timestamp> for rand::distr::StandardUniform {
    fn sample<R: rand::prelude::Rng + ?Sized>(&self, rng: &mut R) -> Timestamp {
        Timestamp(Self::sample(self, rng))
    }
}
