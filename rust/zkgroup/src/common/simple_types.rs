//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::constants::*;
use curve25519_dalek::scalar::Scalar;

pub type AesKeyBytes = [u8; AES_KEY_LEN];
pub type GroupMasterKeyBytes = [u8; GROUP_MASTER_KEY_LEN];
pub type UidBytes = [u8; UUID_LEN];
pub type ProfileKeyBytes = [u8; PROFILE_KEY_LEN];
pub type RandomnessBytes = [u8; RANDOMNESS_LEN];
pub type ReservedBytes = [u8; RESERVED_LEN];
pub type SignatureBytes = [u8; SIGNATURE_LEN];
pub type NotarySignatureBytes = [u8; SIGNATURE_LEN];
pub type GroupIdentifierBytes = [u8; GROUP_IDENTIFIER_LEN];
pub type ProfileKeyVersionBytes = [u8; PROFILE_KEY_VERSION_LEN];
pub type ProfileKeyVersionEncodedBytes = [u8; PROFILE_KEY_VERSION_ENCODED_LEN];

/// Measured in days past the epoch.
///
/// Clients should check that this is within a day of the current date.
pub type CoarseRedemptionTime = u32;

// A random UUID that the receipt issuing server will blind authorize to redeem a given receipt
// level within a certain time frame.
pub type ReceiptSerialBytes = [u8; RECEIPT_SERIAL_LEN];

/// Measured in seconds past the epoch.
///
/// Clients should only accept round multiples of 86400 to avoid fingerprinting by the server.
/// For expirations, the timestamp should be within a couple of days into the future;
/// for redemption times, it should be within a day of the current date.
pub type Timestamp = u64;

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
