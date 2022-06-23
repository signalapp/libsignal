//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::constants::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::crypto::profile_key_struct;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use lazy_static::lazy_static;

lazy_static! {
    static ref SYSTEM_PARAMS: SystemParams =
        bincode::deserialize::<SystemParams>(&SystemParams::SYSTEM_HARDCODED).unwrap();
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemParams {
    pub(crate) G_j1: RistrettoPoint,
    pub(crate) G_j2: RistrettoPoint,
    pub(crate) G_j3: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentWithSecretNonce {
    pub(crate) J1: RistrettoPoint,
    pub(crate) J2: RistrettoPoint,
    pub(crate) J3: RistrettoPoint,
    pub(crate) j3: Scalar,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    pub(crate) J1: RistrettoPoint,
    pub(crate) J2: RistrettoPoint,
    pub(crate) J3: RistrettoPoint,
}

impl SystemParams {
    pub fn generate() -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Constant_ProfileKeyCommitment_SystemParams_Generate",
            b"",
        );
        let G_j1 = sho.get_point();
        let G_j2 = sho.get_point();
        let G_j3 = sho.get_point();
        SystemParams { G_j1, G_j2, G_j3 }
    }

    pub fn get_hardcoded() -> SystemParams {
        *SYSTEM_PARAMS
    }

    const SYSTEM_HARDCODED: [u8; 96] = [
        0xa8, 0xca, 0xb, 0xbd, 0x11, 0x48, 0xc4, 0x66, 0x72, 0x58, 0x60, 0x64, 0xa, 0xc5, 0x3d,
        0x27, 0x72, 0xb1, 0x4e, 0xea, 0xe0, 0x17, 0xa, 0x38, 0xc6, 0x2c, 0x7b, 0x3d, 0xd2, 0x9c,
        0x3e, 0x4a, 0x14, 0xb9, 0x46, 0x2d, 0x94, 0x8f, 0x5, 0x94, 0x50, 0x79, 0x9f, 0x4c, 0xc2,
        0xa0, 0x6e, 0x55, 0xde, 0xc8, 0x7, 0x73, 0x56, 0x70, 0xb9, 0x4a, 0x5c, 0xe8, 0xf, 0x59,
        0xf1, 0x95, 0x8, 0x61, 0xb0, 0xc0, 0xf7, 0xb9, 0x1f, 0x6e, 0xf9, 0xc7, 0x55, 0x60, 0x93,
        0xd8, 0x93, 0xa, 0x86, 0xbd, 0x36, 0x18, 0x8c, 0xec, 0x74, 0x5, 0x54, 0x65, 0x7d, 0x92,
        0xdc, 0xd8, 0x6a, 0xad, 0x25, 0x1c,
    ];
}

impl CommitmentWithSecretNonce {
    pub fn new(
        profile_key: profile_key_struct::ProfileKeyStruct,
        uid_bytes: UidBytes,
    ) -> CommitmentWithSecretNonce {
        let commitment_system = SystemParams::get_hardcoded();

        let profile_key_struct::ProfileKeyStruct { M3, M4, .. } = profile_key;
        let j3 = Self::calc_j3(profile_key.bytes, uid_bytes);
        let J1 = (j3 * commitment_system.G_j1) + M3;
        let J2 = (j3 * commitment_system.G_j2) + M4;
        let J3 = j3 * commitment_system.G_j3;
        CommitmentWithSecretNonce { J1, J2, J3, j3 }
    }

    pub fn get_profile_key_commitment(&self) -> Commitment {
        Commitment {
            J1: self.J1,
            J2: self.J2,
            J3: self.J3,
        }
    }

    pub fn calc_j3(profile_key_bytes: ProfileKeyBytes, uid_bytes: UidBytes) -> Scalar {
        let mut combined_array = [0u8; PROFILE_KEY_LEN + UUID_LEN];
        combined_array[..PROFILE_KEY_LEN].copy_from_slice(&profile_key_bytes);
        combined_array[PROFILE_KEY_LEN..].copy_from_slice(&uid_bytes);
        Sho::new(
            b"Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKeyCommitment_Calcj3",
            &combined_array,
        )
        .get_scalar()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system() {
        let params = SystemParams::generate();
        println!("PARAMS = {:#x?}", bincode::serialize(&params));
        assert!(SystemParams::generate() == SystemParams::get_hardcoded());
    }

    #[test]
    fn test_commitment() {
        let profile_key = profile_key_struct::ProfileKeyStruct::new(TEST_ARRAY_32, TEST_ARRAY_16);
        let c1 = CommitmentWithSecretNonce::new(profile_key, TEST_ARRAY_16);
        let c2 = CommitmentWithSecretNonce::new(profile_key, TEST_ARRAY_16);
        assert!(c1 == c2);
    }
}
