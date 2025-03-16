//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

use std::sync::LazyLock;

use curve25519_dalek_signal::ristretto::RistrettoPoint;
use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zkcredential::attributes::Attribute;

use crate::common::errors::*;
use crate::common::sho::*;
use crate::crypto::uid_struct;

static SYSTEM_PARAMS: LazyLock<SystemParams> =
    LazyLock::new(|| crate::deserialize::<SystemParams>(&SystemParams::SYSTEM_HARDCODED).unwrap());

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialDefault)]
pub struct SystemParams {
    pub(crate) G_a1: RistrettoPoint,
    pub(crate) G_a2: RistrettoPoint,
}

pub type KeyPair = zkcredential::attributes::KeyPair<UidEncryptionDomain>;
pub type PublicKey = zkcredential::attributes::PublicKey<UidEncryptionDomain>;
pub type Ciphertext = zkcredential::attributes::Ciphertext<UidEncryptionDomain>;

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

pub struct UidEncryptionDomain;
impl zkcredential::attributes::Domain for UidEncryptionDomain {
    type Attribute = uid_struct::UidStruct;

    const ID: &'static str = "Signal_ZKGroup_20230419_UidEncryption";

    fn G_a() -> [RistrettoPoint; 2] {
        let system = SystemParams::get_hardcoded();
        [system.G_a1, system.G_a2]
    }
}

impl UidEncryptionDomain {
    pub(crate) fn decrypt(
        key_pair: &KeyPair,
        ciphertext: &Ciphertext,
    ) -> Result<libsignal_core::ServiceId, ZkGroupVerificationFailure> {
        let M2 = key_pair
            .decrypt_to_second_point(ciphertext)
            .map_err(|_| ZkGroupVerificationFailure)?;
        match M2.lizard_decode::<sha2::Sha256>() {
            None => Err(ZkGroupVerificationFailure),
            Some(bytes) => {
                // We want to do a constant-time choice between the ACI and the PNI possibilities.
                // Only at the end do we do a normal branch to see if decryption succeeded,
                // and even then we don't want to expose whether we picked the ACI or the PNI.
                // So we store them both in an array, and index into it at the very end.
                // This isn't fully "data-oblivious"; only one service ID gets loaded from memory at
                // the end, and which one is data-dependent. But it is constant-time.
                let decoded_uuid = uuid::Uuid::from_bytes(bytes);
                let decoded_service_ids = [
                    libsignal_core::Aci::from(decoded_uuid).into(),
                    libsignal_core::Pni::from(decoded_uuid).into(),
                ];
                let decoded_aci = &decoded_service_ids[0];
                let decoded_pni = &decoded_service_ids[1];
                let aci_M1 = uid_struct::UidStruct::calc_M1(*decoded_aci);
                let pni_M1 = uid_struct::UidStruct::calc_M1(*decoded_pni);
                debug_assert!(aci_M1 != pni_M1);
                let decrypted_M1 = key_pair.a1.invert() * ciphertext.as_points()[0];
                let mut index = u8::MAX;
                index.conditional_assign(&0, decrypted_M1.ct_eq(&aci_M1));
                index.conditional_assign(&1, decrypted_M1.ct_eq(&pni_M1));
                decoded_service_ids
                    .get(index as usize)
                    .copied()
                    .ok_or(ZkGroupVerificationFailure)
            }
        }
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

        let key_pair = KeyPair::derive_from(sho.as_mut());

        // Test serialize of key_pair
        let key_pair_bytes = bincode::serialize(&key_pair).unwrap();
        match bincode::deserialize::<KeyPair>(&key_pair_bytes[0..key_pair_bytes.len() - 1]) {
            Err(_) => (),
            _ => unreachable!(),
        };
        let key_pair2: KeyPair = bincode::deserialize(&key_pair_bytes).unwrap();
        assert!(key_pair == key_pair2);

        let aci = libsignal_core::Aci::from_uuid_bytes(TEST_ARRAY_16);
        let uid = uid_struct::UidStruct::from_service_id(aci.into());
        let ciphertext = key_pair.encrypt(&uid);

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

        let plaintext = UidEncryptionDomain::decrypt(&key_pair, &ciphertext2).unwrap();
        assert!(matches!(plaintext, libsignal_core::ServiceId::Aci(_)));
        assert!(uid_struct::UidStruct::from_service_id(plaintext) == uid);
    }

    #[test]
    fn test_pni_encryption() {
        let mut sho = Sho::new(b"Test_Pni_Encryption", &[]);
        let key_pair = KeyPair::derive_from(sho.as_mut());

        let pni = libsignal_core::Pni::from_uuid_bytes(TEST_ARRAY_16);
        let uid = uid_struct::UidStruct::from_service_id(pni.into());
        let ciphertext = key_pair.encrypt(&uid);

        // Test serialize / deserialize of Ciphertext
        let ciphertext_bytes = bincode::serialize(&ciphertext).unwrap();
        assert!(ciphertext_bytes.len() == 64);
        let ciphertext2: Ciphertext = bincode::deserialize(&ciphertext_bytes).unwrap();
        assert!(ciphertext == ciphertext2);

        let plaintext = UidEncryptionDomain::decrypt(&key_pair, &ciphertext2).unwrap();
        assert!(matches!(plaintext, libsignal_core::ServiceId::Pni(_)));
        assert!(uid_struct::UidStruct::from_service_id(plaintext) == uid);
    }
}
