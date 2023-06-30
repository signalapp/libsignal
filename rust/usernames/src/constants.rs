//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::ops::Range;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use lazy_static::lazy_static;

lazy_static! {
    pub(crate) static ref BASE_POINTS: [RistrettoPoint; 3] =
        COMPRESSED_BASE_POINTS_RAW.map(|bytes| {
            let compressed = CompressedRistretto::from_slice(&bytes);
            compressed.decompress().unwrap()
        });
}

const COMPRESSED_BASE_POINTS_RAW: [[u8; 32]; 3] = [
    [
        0x60, 0xb9, 0x93, 0x66, 0x3a, 0x3d, 0xae, 0xcc, 0x4c, 0x85, 0x2f, 0x53, 0x35, 0x47, 0xe3,
        0x5, 0x38, 0x8c, 0x2a, 0x50, 0xa5, 0x83, 0x93, 0xea, 0x27, 0x7d, 0xe4, 0xab, 0xf3, 0xde,
        0x54, 0x3a,
    ],
    [
        0xf2, 0xb6, 0xf1, 0xc8, 0x26, 0xfa, 0x36, 0x40, 0x20, 0x6f, 0x3b, 0x58, 0xb2, 0x28, 0x6b,
        0xde, 0xfd, 0xfd, 0xa6, 0xa5, 0x4f, 0xf9, 0x2, 0xf2, 0x4, 0xa7, 0x2d, 0xe7, 0x37, 0xd2,
        0x61, 0x57,
    ],
    [
        0x6, 0x6, 0xbd, 0x3a, 0xbf, 0xce, 0x4e, 0x96, 0x17, 0xd4, 0x48, 0xfb, 0x2c, 0xae, 0xb6,
        0xcc, 0x2, 0x8e, 0xc9, 0xa2, 0xb6, 0x2b, 0x10, 0xb3, 0xd9, 0xeb, 0x29, 0x48, 0xda, 0x6f,
        0x3f, 0x53,
    ],
];

// 37^48 will overflow the Scalar. See nickname_scalar implementation for details.
pub(crate) const MAX_NICKNAME_LENGTH: usize = 48;
pub(crate) const DISCRIMINATOR_RANGES: [Range<usize>; 8] = [
    1..100,
    100..1_000,
    1_000..10_000,
    10_000..100_000,
    100_000..1_000_000,
    1_000_000..10_000_000,
    10_000_000..100_000_000,
    100_000_000..1_000_000_000,
];

pub(crate) const CANDIDATES_PER_RANGE: [usize; 8] = [4, 3, 3, 2, 2, 2, 2, 2];

pub(crate) const USERNAME_LINK_LABEL_ENCRYPTION_KEY: &[u8] = b"Signal Username Link Encryption Key";
pub(crate) const USERNAME_LINK_LABEL_AUTHENTICATION_KEY: &[u8] =
    b"Signal Username Link Authentication Key";
pub(crate) const USERNAME_LINK_HMAC_ALGORITHM: &str = "HmacSha256";
pub(crate) const USERNAME_LINK_HMAC_LEN: usize = 32;
pub(crate) const USERNAME_LINK_ENTROPY_SIZE: usize = 32;
pub(crate) const USERNAME_LINK_KEY_SIZE: usize = 32;
pub(crate) const USERNAME_LINK_IV_SIZE: usize = 16;
pub(crate) const USERNAME_LINK_MAX_DATA_SIZE: usize = 128;
pub(crate) const USERNAME_LINK_MAX_PTEXT_SIZE: usize =
    USERNAME_LINK_MAX_DATA_SIZE - USERNAME_LINK_IV_SIZE - USERNAME_LINK_HMAC_LEN;

#[cfg(test)]
mod test {
    use zkgroup::common::sho::Sho;

    use super::*;

    #[test]
    fn generate_points() {
        let mut sho = Sho::new(b"Signal_Username_20230130_Constant_Points_Generate", b"");
        for p in BASE_POINTS.iter() {
            assert_eq!(&sho.get_point(), p);
        }
    }
}
