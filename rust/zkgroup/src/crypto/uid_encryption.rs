//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::errors::*;
use crate::common::sho::*;
use crate::crypto::uid_struct;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
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
    pub(crate) G_a1: RistrettoPoint,
    pub(crate) G_a2: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPair {
    pub(crate) a1: Scalar,
    pub(crate) a2: Scalar,
    pub(crate) A: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub(crate) A: RistrettoPoint,
}

#[derive(Copy, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub(crate) E_A1: RistrettoPoint,
    pub(crate) E_A2: RistrettoPoint,
}

impl SystemParams {
    pub fn generate() -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Constant_UidEncryption_SystemParams_Generate",
            b"",
        );
        let G_a1 = sho.get_point();
        let G_a2 = sho.get_point();
        SystemParams { G_a1, G_a2 }
    }

    pub fn get_hardcoded() -> SystemParams {
        *SYSTEM_PARAMS
    }

    const SYSTEM_HARDCODED: [u8; 64] = [
        0xa6, 0x32, 0x4c, 0x36, 0x8d, 0xf7, 0x34, 0x69, 0x11, 0x47, 0x98, 0x13, 0x48, 0xb6, 0xe7,
        0xeb, 0x42, 0xc3, 0x30, 0x7e, 0x71, 0x1b, 0x6c, 0x7e, 0xcc, 0xd3, 0x3, 0x2d, 0x45, 0x69,
        0x3f, 0x5a, 0x4, 0x80, 0x13, 0x52, 0x5b, 0x76, 0x12, 0x4b, 0xf2, 0x64, 0xc, 0x5e, 0x93,
        0x69, 0xc7, 0x6e, 0xfb, 0xe8, 0xa, 0xba, 0x2a, 0x24, 0xaa, 0x5d, 0x8e, 0x18, 0xa9, 0x8e,
        0xba, 0x14, 0xf8, 0x37,
    ];
}

impl KeyPair {
    pub fn derive_from(sho: &mut Sho) -> Self {
        let system = SystemParams::get_hardcoded();

        let a1 = sho.get_scalar();
        let a2 = sho.get_scalar();

        let A = a1 * system.G_a1 + a2 * system.G_a2;
        KeyPair { a1, a2, A }
    }

    pub fn encrypt(&self, uid: uid_struct::UidStruct) -> Ciphertext {
        let E_A1 = self.calc_E_A1(uid);
        let E_A2 = (self.a2 * E_A1) + uid.M2;
        Ciphertext { E_A1, E_A2 }
    }

    // Might return VerificationFailure
    pub fn decrypt(
        &self,
        ciphertext: Ciphertext,
    ) -> Result<uid_struct::UidStruct, ZkGroupVerificationFailure> {
        if ciphertext.E_A1 == RISTRETTO_BASEPOINT_POINT {
            return Err(ZkGroupVerificationFailure);
        }
        match uid_struct::UidStruct::from_M2(ciphertext.E_A2 - (self.a2 * ciphertext.E_A1)) {
            Err(_) => Err(ZkGroupVerificationFailure),
            Ok(decrypted_uid) => {
                if ciphertext.E_A1 == self.calc_E_A1(decrypted_uid) {
                    Ok(decrypted_uid)
                } else {
                    Err(ZkGroupVerificationFailure)
                }
            }
        }
    }

    fn calc_E_A1(&self, uid: uid_struct::UidStruct) -> RistrettoPoint {
        self.a1 * uid.M1
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey { A: self.A }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::*;

    #[test]
    fn test_uid_encryption() {
        let master_key = TEST_ARRAY_32;
        let mut sho = Sho::new(b"Test_Uid_Encryption", &master_key);

        //let system = SystemParams::generate();
        //println!("PARAMS = {:#x?}", bincode::serialize(&system));
        assert!(SystemParams::generate() == SystemParams::get_hardcoded());

        let key_pair = KeyPair::derive_from(&mut sho);

        // Test serialize of key_pair
        let key_pair_bytes = bincode::serialize(&key_pair).unwrap();
        match bincode::deserialize::<KeyPair>(&key_pair_bytes[0..key_pair_bytes.len() - 1]) {
            Err(_) => (),
            _ => unreachable!(),
        };
        let key_pair2: KeyPair = bincode::deserialize(&key_pair_bytes).unwrap();
        assert!(key_pair == key_pair2);

        let uid = uid_struct::UidStruct::new(TEST_ARRAY_16);
        let ciphertext = key_pair.encrypt(uid);

        // Test serialize / deserialize of Ciphertext
        let ciphertext_bytes = bincode::serialize(&ciphertext).unwrap();
        assert!(ciphertext_bytes.len() == 64);
        let ciphertext2: Ciphertext = bincode::deserialize(&ciphertext_bytes).unwrap();
        assert!(ciphertext == ciphertext2);
        //println!("ciphertext_bytes = {:#x?}", ciphertext_bytes);
        assert!(
            ciphertext_bytes
                == vec![
                    0xf8, 0x9e, 0xe7, 0x70, 0x5a, 0x66, 0x3, 0x6b, 0x90, 0x8d, 0xb8, 0x84, 0x21,
                    0x1b, 0x77, 0x3a, 0xc5, 0x43, 0xee, 0x35, 0xc4, 0xa3, 0x8, 0x62, 0x20, 0xfc,
                    0x3e, 0x1e, 0x35, 0xb4, 0x23, 0x4c, 0xfa, 0x1d, 0x2e, 0xea, 0x2c, 0xc2, 0xf4,
                    0xb4, 0xc4, 0x2c, 0xff, 0x39, 0xa9, 0xdc, 0xeb, 0x57, 0x29, 0x3b, 0x5f, 0x87,
                    0x70, 0xca, 0x60, 0xf9, 0xe9, 0xb7, 0x44, 0x47, 0xbf, 0xd3, 0xbd, 0x3d,
                ]
        );

        let plaintext = key_pair.decrypt(ciphertext2).unwrap();

        assert!(plaintext == uid);
    }
}
