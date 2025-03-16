//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

use std::sync::LazyLock;

use curve25519_dalek_signal::ristretto::RistrettoPoint;
use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zkcredential::attributes::Attribute;

use crate::common::errors::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::crypto::profile_key_struct;

static SYSTEM_PARAMS: LazyLock<SystemParams> =
    LazyLock::new(|| crate::deserialize::<SystemParams>(&SystemParams::SYSTEM_HARDCODED).unwrap());

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialDefault)]
pub struct SystemParams {
    pub(crate) G_b1: RistrettoPoint,
    pub(crate) G_b2: RistrettoPoint,
}

pub type KeyPair = zkcredential::attributes::KeyPair<ProfileKeyEncryptionDomain>;
pub type PublicKey = zkcredential::attributes::PublicKey<ProfileKeyEncryptionDomain>;
pub type Ciphertext = zkcredential::attributes::Ciphertext<ProfileKeyEncryptionDomain>;

impl SystemParams {
    pub fn generate() -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Constant_ProfileKeyEncryption_SystemParams_Generate",
            b"",
        );
        let G_b1 = sho.get_point();
        let G_b2 = sho.get_point();
        SystemParams { G_b1, G_b2 }
    }

    pub fn get_hardcoded() -> SystemParams {
        *SYSTEM_PARAMS
    }

    const SYSTEM_HARDCODED: [u8; 64] = [
        0xf6, 0xba, 0xa3, 0x17, 0xce, 0x18, 0x39, 0xc9, 0x3d, 0x61, 0x7e, 0xc, 0xd8, 0x37, 0xd1,
        0x9d, 0xa9, 0xc8, 0xa4, 0xc5, 0x20, 0xbf, 0x7c, 0x51, 0xb1, 0xe6, 0xc2, 0xcb, 0x2a, 0x4,
        0x9c, 0x61, 0x2e, 0x1, 0x75, 0x89, 0x4c, 0x87, 0x30, 0xb2, 0x3, 0xab, 0x3b, 0xd9, 0x8e,
        0xcb, 0x2d, 0x81, 0xab, 0xac, 0xb6, 0x5f, 0x8a, 0x61, 0x24, 0xf4, 0x97, 0x71, 0xd1, 0x4a,
        0x98, 0x52, 0x12, 0xc,
    ];
}

pub struct ProfileKeyEncryptionDomain;
impl zkcredential::attributes::Domain for ProfileKeyEncryptionDomain {
    type Attribute = profile_key_struct::ProfileKeyStruct;

    const ID: &'static str = "Signal_ZKGroup_20231011_ProfileKeyEncryption";

    fn G_a() -> [RistrettoPoint; 2] {
        let system = SystemParams::get_hardcoded();
        [system.G_b1, system.G_b2]
    }
}

impl ProfileKeyEncryptionDomain {
    pub(crate) fn decrypt(
        key_pair: &KeyPair,
        ciphertext: &Ciphertext,
        uid_bytes: UidBytes,
    ) -> Result<profile_key_struct::ProfileKeyStruct, ZkGroupVerificationFailure> {
        let M4 = key_pair
            .decrypt_to_second_point(ciphertext)
            .map_err(|_| ZkGroupVerificationFailure)?;
        let (mask, candidates) = M4.decode_253_bits();

        let target_M3 = key_pair.a1.invert() * ciphertext.as_points()[0];

        let mut retval: profile_key_struct::ProfileKeyStruct = PartialDefault::partial_default();
        let mut n_found = 0;
        #[allow(clippy::needless_range_loop)]
        for i in 0..8 {
            let is_valid_fe = Choice::from((mask >> i) & 1);
            let profile_key_bytes: ProfileKeyBytes = candidates[i];
            for j in 0..8 {
                let mut pk = profile_key_bytes;
                if ((j >> 2) & 1) == 1 {
                    pk[0] |= 0x01;
                }
                if ((j >> 1) & 1) == 1 {
                    pk[31] |= 0x80;
                }
                if (j & 1) == 1 {
                    pk[31] |= 0x40;
                }
                let M3 = profile_key_struct::ProfileKeyStruct::calc_M3(pk, uid_bytes);
                let candidate_retval = profile_key_struct::ProfileKeyStruct { bytes: pk, M3, M4 };
                let found = M3.ct_eq(&target_M3) & is_valid_fe;
                retval.conditional_assign(&candidate_retval, found);
                n_found += found.unwrap_u8();
            }
        }
        if n_found == 1 {
            Ok(retval)
        } else {
            Err(ZkGroupVerificationFailure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::*;

    #[test]
    fn test_profile_key_encryption() {
        let master_key = TEST_ARRAY_32_1;
        let mut sho = Sho::new(b"Test_Profile_Key_Encryption", &master_key);

        //let system = SystemParams::generate();
        //println!("PARAMS = {:#x?}", bincode::serialize(&system));
        assert!(SystemParams::generate() == SystemParams::get_hardcoded());

        let key_pair = KeyPair::derive_from(sho.as_mut());

        // Test serialize of key_pair
        let key_pair_bytes = bincode::serialize(&key_pair).unwrap();
        match bincode::deserialize::<KeyPair>(&key_pair_bytes[0..key_pair_bytes.len() - 1]) {
            Err(_) => (),
            _ => unreachable!(),
        };
        let key_pair2: KeyPair = bincode::deserialize(&key_pair_bytes).unwrap();
        assert!(key_pair == key_pair2);

        let profile_key_bytes = TEST_ARRAY_32_1;
        let uid_bytes = TEST_ARRAY_16_1;
        let profile_key = profile_key_struct::ProfileKeyStruct::new(profile_key_bytes, uid_bytes);
        let ciphertext = key_pair.encrypt(&profile_key);

        // Test serialize / deserialize of Ciphertext
        let ciphertext_bytes = bincode::serialize(&ciphertext).unwrap();
        assert!(ciphertext_bytes.len() == 64);
        let ciphertext2: Ciphertext = bincode::deserialize(&ciphertext_bytes).unwrap();
        assert!(ciphertext == ciphertext2);
        println!("ciphertext_bytes = {:#x?}", ciphertext_bytes);
        assert!(
            ciphertext_bytes
                == vec![
                    0x56, 0x18, 0xcb, 0x4c, 0x7d, 0x72, 0x1e, 0x1, 0x2b, 0x22, 0xf0, 0x77, 0xef,
                    0x12, 0x64, 0xf6, 0xb1, 0x43, 0xbb, 0x59, 0x7a, 0x1d, 0x66, 0x5a, 0x70, 0xaa,
                    0x84, 0x24, 0x5f, 0x24, 0x6d, 0x20, 0xba, 0xdb, 0x97, 0x47, 0x4a, 0x56, 0xf4,
                    0xb5, 0x36, 0x1a, 0xec, 0xa9, 0xd1, 0x18, 0xb7, 0x0, 0x4e, 0x14, 0x9, 0x71,
                    0x99, 0xa, 0xab, 0x2a, 0xf2, 0x43, 0x2d, 0x3f, 0x8f, 0x7d, 0x21, 0x3a,
                ]
        );

        let plaintext =
            ProfileKeyEncryptionDomain::decrypt(&key_pair, &ciphertext2, uid_bytes).unwrap();
        assert!(plaintext == profile_key);

        let mut sho = Sho::new(b"Test_Repeated_ProfileKeyEnc/Dec", b"seed");
        for _ in 0..100 {
            let uid_bytes: UidBytes = sho.squeeze_as_array();
            let profile_key_bytes: ProfileKeyBytes = sho.squeeze_as_array();

            let profile_key =
                profile_key_struct::ProfileKeyStruct::new(profile_key_bytes, uid_bytes);
            let ciphertext = key_pair.encrypt(&profile_key);
            assert!(
                ProfileKeyEncryptionDomain::decrypt(&key_pair, &ciphertext, uid_bytes).unwrap()
                    == profile_key
            );
        }

        let uid_bytes = TEST_ARRAY_16;
        let profile_key = profile_key_struct::ProfileKeyStruct::new(TEST_ARRAY_32, TEST_ARRAY_16);
        let ciphertext = key_pair.encrypt(&profile_key);
        assert!(
            ProfileKeyEncryptionDomain::decrypt(&key_pair, &ciphertext, uid_bytes).unwrap()
                == profile_key
        );

        let uid_bytes = TEST_ARRAY_16;
        let profile_key = profile_key_struct::ProfileKeyStruct::new(TEST_ARRAY_32_2, TEST_ARRAY_16);
        let ciphertext = key_pair.encrypt(&profile_key);
        assert!(
            ProfileKeyEncryptionDomain::decrypt(&key_pair, &ciphertext, uid_bytes).unwrap()
                == profile_key
        );

        let uid_bytes = TEST_ARRAY_16;
        let profile_key = profile_key_struct::ProfileKeyStruct::new(TEST_ARRAY_32_3, TEST_ARRAY_16);
        let ciphertext = key_pair.encrypt(&profile_key);
        assert!(
            ProfileKeyEncryptionDomain::decrypt(&key_pair, &ciphertext, uid_bytes).unwrap()
                == profile_key
        );

        let uid_bytes = TEST_ARRAY_16;
        let profile_key = profile_key_struct::ProfileKeyStruct::new(TEST_ARRAY_32_4, TEST_ARRAY_16);
        let ciphertext = key_pair.encrypt(&profile_key);
        assert!(
            ProfileKeyEncryptionDomain::decrypt(&key_pair, &ciphertext, uid_bytes).unwrap()
                == profile_key
        );
    }
}
