//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use curve25519_dalek_signal::scalar::Scalar;
use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};
use zkcredential::attributes::PublicAttribute;

use crate::common::constants::*;

pub type AesKeyBytes = [u8; AES_KEY_LEN];
pub type GroupMasterKeyBytes = [u8; GROUP_MASTER_KEY_LEN];
pub type UidBytes = [u8; UUID_LEN];
pub type ProfileKeyBytes = [u8; PROFILE_KEY_LEN];
pub type RandomnessBytes = [u8; RANDOMNESS_LEN];
pub type SignatureBytes = [u8; SIGNATURE_LEN];
pub type NotarySignatureBytes = [u8; SIGNATURE_LEN];
pub type GroupIdentifierBytes = [u8; GROUP_IDENTIFIER_LEN];
pub type ProfileKeyVersionBytes = [u8; PROFILE_KEY_VERSION_LEN];
pub type ProfileKeyVersionEncodedBytes = [u8; PROFILE_KEY_VERSION_ENCODED_LEN];

// A random UUID that the receipt issuing server will blind authorize to redeem a given receipt
// level within a certain time frame.
pub type ReceiptSerialBytes = [u8; RECEIPT_SERIAL_LEN];

/// Timestamp measured in seconds past the epoch.
///
/// Clients should only accept round multiples of 86400 to avoid fingerprinting by the server.
/// For expirations, the timestamp should be within a couple of days into the future;
/// for redemption times, it should be within a day of the current date.
#[derive(
    Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, PartialDefault,
)]
#[serde(transparent)]
#[repr(transparent)]
pub struct Timestamp(u64);

impl Timestamp {
    #[inline]
    pub const fn from_epoch_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    #[inline]
    pub const fn epoch_seconds(&self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn add_seconds(&self, seconds: u64) -> Self {
        Self(self.0 + seconds)
    }

    #[inline]
    pub const fn sub_seconds(&self, seconds: u64) -> Self {
        Self(self.0 - seconds)
    }

    #[inline]
    pub fn checked_add_seconds(&self, seconds: u64) -> Option<Self> {
        self.0.checked_add(seconds).map(Self)
    }

    #[inline]
    pub fn checked_sub_seconds(&self, seconds: u64) -> Option<Self> {
        self.0.checked_sub(seconds).map(Self)
    }

    #[inline]
    pub const fn is_day_aligned(&self) -> bool {
        self.0 % SECONDS_PER_DAY == 0
    }

    #[inline]
    pub fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Number of seconds that `self` is after `before`.
    ///
    /// Returns `0` if `self` is equal to or earlier than `before`.
    pub(crate) fn saturating_seconds_since(&self, before: Timestamp) -> u64 {
        self.0.saturating_sub(before.0)
    }
}

impl From<Timestamp> for std::time::SystemTime {
    fn from(Timestamp(seconds): Timestamp) -> Self {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds)
    }
}

impl rand::distributions::Distribution<Timestamp> for rand::distributions::Standard {
    fn sample<R: rand::prelude::Rng + ?Sized>(&self, rng: &mut R) -> Timestamp {
        Timestamp(Self::sample(self, rng))
    }
}

impl PublicAttribute for Timestamp {
    fn hash_into(&self, sho: &mut dyn poksho::ShoApi) {
        self.0.hash_into(sho)
    }
}

// Used to tell the server handling receipt redemptions what to redeem the receipt for. Clients
// should validate this matches their expectations.
pub type ReceiptLevel = u64;

pub fn encode_redemption_time(redemption_time: u32) -> Scalar {
    let mut scalar_bytes: [u8; 32] = Default::default();
    scalar_bytes[0..4].copy_from_slice(&redemption_time.to_be_bytes());
    Scalar::from_bytes_mod_order(scalar_bytes)
}

pub fn encode_receipt_serial_bytes(receipt_serial_bytes: ReceiptSerialBytes) -> Scalar {
    let mut scalar_bytes: [u8; 32] = Default::default();
    scalar_bytes[0..16].copy_from_slice(&receipt_serial_bytes[..]);
    Scalar::from_bytes_mod_order(scalar_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_scalar() {
        let s_bytes = [0xFF; 32];
        match bincode::deserialize::<Scalar>(&s_bytes) {
            Err(_) => (),
            Ok(_) => unreachable!(),
        }
    }
}
