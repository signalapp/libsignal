//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::constants::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::{api, crypto};
use serde::{Deserialize, Serialize};

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

    pub fn get_commitment(&self, uid_bytes: UidBytes) -> api::profiles::ProfileKeyCommitment {
        let profile_key = crypto::profile_key_struct::ProfileKeyStruct::new(self.bytes, uid_bytes);
        let commitment =
            crypto::profile_key_commitment::CommitmentWithSecretNonce::new(profile_key, uid_bytes);
        api::profiles::ProfileKeyCommitment {
            reserved: Default::default(),
            commitment: commitment.get_profile_key_commitment(),
        }
    }

    pub fn get_profile_key_version(&self, uid_bytes: UidBytes) -> api::profiles::ProfileKeyVersion {
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
}
