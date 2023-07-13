//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::constants::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::{api, crypto};
use serde::{Deserialize, Serialize};
use signal_crypto::Aes256GcmEncryption;

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ProfileKey {
    pub bytes: ProfileKeyBytes,
}

impl ProfileKey {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ProfileKey_Generate",
            &randomness,
        );
        let mut bytes = [0u8; PROFILE_KEY_LEN];
        bytes.copy_from_slice(&sho.squeeze(PROFILE_KEY_LEN)[..]);
        Self { bytes }
    }

    pub fn create(bytes: ProfileKeyBytes) -> Self {
        Self { bytes }
    }

    pub fn get_bytes(&self) -> ProfileKeyBytes {
        self.bytes
    }

    pub fn get_commitment(
        &self,
        user_id: libsignal_protocol::Aci,
    ) -> api::profiles::ProfileKeyCommitment {
        let uid_bytes = uuid::Uuid::from(user_id).into_bytes();
        let profile_key = crypto::profile_key_struct::ProfileKeyStruct::new(self.bytes, uid_bytes);
        let commitment =
            crypto::profile_key_commitment::CommitmentWithSecretNonce::new(profile_key, uid_bytes);
        api::profiles::ProfileKeyCommitment {
            reserved: Default::default(),
            commitment: commitment.get_profile_key_commitment(),
        }
    }

    pub fn get_profile_key_version(
        &self,
        user_id: libsignal_protocol::Aci,
    ) -> api::profiles::ProfileKeyVersion {
        let uid_bytes = uuid::Uuid::from(user_id).into_bytes();
        let mut combined_array = [0u8; PROFILE_KEY_LEN + UUID_LEN];
        combined_array[..PROFILE_KEY_LEN].copy_from_slice(&self.bytes);
        combined_array[PROFILE_KEY_LEN..].copy_from_slice(&uid_bytes);
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKey_GetProfileKeyVersion",
            &combined_array,
        );

        let pkv_hex_string = hex::encode(&sho.squeeze(PROFILE_KEY_VERSION_LEN)[..]);
        let mut pkv_hex_array: [u8; PROFILE_KEY_VERSION_ENCODED_LEN] =
            [0u8; PROFILE_KEY_VERSION_ENCODED_LEN];
        pkv_hex_array.copy_from_slice(pkv_hex_string.as_bytes());
        api::profiles::ProfileKeyVersion {
            bytes: pkv_hex_array,
        }
    }

    pub fn derive_access_key(&self) -> [u8; ACCESS_KEY_LEN] {
        let nonce = &[0u8; AESGCM_NONCE_LEN];
        let mut cipher = Aes256GcmEncryption::new(&self.bytes, nonce, &[]).unwrap();
        let mut buf = [0u8; ACCESS_KEY_LEN];
        cipher.encrypt(&mut buf[..]).unwrap();
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_key_kat() {
        // Pairs of profile keys and derived access keys
        let kat = [
            (
                [
                    0xb9, 0x50, 0x42, 0xa2, 0xc2, 0xd9, 0xe5, 0xb3, 0xbb, 0x9, 0x30, 0xe, 0xe4,
                    0x8, 0xa1, 0x72, 0xfa, 0xcd, 0x96, 0xe9, 0x1b, 0x50, 0x4e, 0x4, 0x3a, 0x5a,
                    0x2, 0x3d, 0xc4, 0xcf, 0xf3, 0x59,
                ],
                [
                    0x24, 0xfb, 0x96, 0xd4, 0xa5, 0xe3, 0x33, 0xe9, 0xd4, 0x45, 0x12, 0x5, 0xb9,
                    0xe2, 0xfa, 0xed,
                ],
            ),
            (
                [
                    0x26, 0x19, 0x7b, 0x17, 0xe5, 0xa2, 0xc3, 0x6d, 0x8c, 0x95, 0x18, 0xc3, 0x53,
                    0x58, 0xf1, 0x23, 0xc4, 0x76, 0x0, 0xd, 0xb6, 0xda, 0x75, 0x65, 0xc0, 0xd4,
                    0x1f, 0x66, 0x74, 0x46, 0x2c, 0x4d,
                ],
                [
                    0xe8, 0x95, 0xc3, 0xc, 0xf7, 0x80, 0x75, 0x7d, 0x22, 0xf7, 0xa1, 0x79, 0x70,
                    0x8b, 0x14, 0xa1,
                ],
            ),
        ];

        for (pk, ak) in kat {
            let profile_key = ProfileKey::create(pk);
            let access_key = profile_key.derive_access_key();
            assert_eq!(ak, access_key);
        }
    }
}
