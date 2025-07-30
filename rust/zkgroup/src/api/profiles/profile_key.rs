//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use aes::cipher::{BlockEncrypt as _, KeyInit as _};
use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::common::constants::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::{api, crypto};

#[derive(Copy, Clone, Serialize, Deserialize, PartialDefault)]
pub struct ProfileKey {
    pub bytes: ProfileKeyBytes,
}

impl std::fmt::Debug for ProfileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileKey")
            .field("bytes", &zkcredential::PrintAsHex(self.bytes.as_slice()))
            .finish()
    }
}

impl PartialEq for ProfileKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.as_slice().ct_eq(other.bytes.as_slice()).into()
    }
}

impl ProfileKey {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ProfileKey_Generate",
            &randomness,
        );
        let bytes = sho.squeeze_as_array();
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
        user_id: libsignal_core::Aci,
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

    pub fn derive_access_key(&self) -> [u8; ACCESS_KEY_LEN] {
        // Uses AES to implement a seeded PRNG, taking the first block of output as the result.
        // Originally defined as AES-GCM(&mut [0; ACCESS_KEY_LEN], [0; NONCE_LEN], init_ctr=1).
        // AES-GCM uses the first block to initialize its tag hash, which we discard in this case,
        // so we can simplify to AES-CTR(&mut [0; ACCESS_KEY_LEN], [0; NONCE_LEN], init_ctr=2)
        // and then since our "plaintext" is zeros, this becomes simply raw AES([0, 0, ..., 2]).
        static_assertions::const_assert_eq!(ACCESS_KEY_LEN, {
            type BlockSize = <::aes::Aes256Enc as ::aes::cipher::BlockSizeUser>::BlockSize;
            <BlockSize as ::aes::cipher::Unsigned>::USIZE
        });
        let aes = ::aes::Aes256Enc::new((&self.bytes).into());
        let mut buf = [0u8; ACCESS_KEY_LEN];
        buf[ACCESS_KEY_LEN - 1] = 2;
        aes.encrypt_block((&mut buf).into());
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
