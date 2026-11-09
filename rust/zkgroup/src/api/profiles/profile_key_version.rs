//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use serde::ser::SerializeTuple;
use serde::{Serialize, Serializer};

use super::ProfileKey;
use crate::common::sho::Sho;
use crate::common::simple_types::*;
use crate::{
    PROFILE_KEY_LEN, PROFILE_KEY_VERSION_ENCODED_LEN, PROFILE_KEY_VERSION_LEN, UUID_LEN, api,
};

/// An identifier for a particular (profile key, ACI) combination.
///
/// Note that it is not a "*profile* version"; a Signal user can change their profile without
/// rotating their profile key, and the profile key version will not change either.
///
/// It is serialized as a hexadecimal string.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ProfileKeyVersion {
    pub bytes: ProfileKeyVersionBytes,
}

impl AsRef<ProfileKeyVersionBytes> for ProfileKeyVersion {
    fn as_ref(&self) -> &ProfileKeyVersionBytes {
        &self.bytes
    }
}

impl Serialize for ProfileKeyVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ascii: [u8; PROFILE_KEY_VERSION_ENCODED_LEN] =
            [0u8; PROFILE_KEY_VERSION_ENCODED_LEN];
        hex::encode_to_slice(self.bytes, &mut ascii).expect("lengths match");
        let mut seq = serializer.serialize_tuple(ascii.len())?;
        for b in ascii.iter() {
            seq.serialize_element(b)?;
        }
        seq.end()
    }
}

impl ProfileKey {
    // Defined here so it can construct a ProfileKeyVersion directly without making the `ascii`
    // field public.
    pub fn get_profile_key_version(
        &self,
        user_id: libsignal_core::Aci,
    ) -> api::profiles::ProfileKeyVersion {
        let uid_bytes = uuid::Uuid::from(user_id).into_bytes();
        let mut combined_array = [0u8; PROFILE_KEY_LEN + UUID_LEN];
        combined_array[..PROFILE_KEY_LEN].copy_from_slice(&self.bytes);
        combined_array[PROFILE_KEY_LEN..].copy_from_slice(&uid_bytes);
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKey_GetProfileKeyVersion",
            &combined_array,
        );

        api::profiles::ProfileKeyVersion {
            bytes: sho.squeeze_as_array::<PROFILE_KEY_VERSION_LEN>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use libsignal_core::Aci;
    use test_case::test_case;

    use super::*;

    #[test_case(
        Aci::from_uuid_bytes([0xa; 16]), &[1; 32],
        b"540169ba2813a4d92326faec4a07de372db4319ab3bb812827019fc8a771a38f"
    )]
    #[test_case(
        Aci::from_uuid_bytes([0xb; 16]), &[2; 32],
        b"4a471108a53e1b278f43be5a8d18c6b5f26cd038ebec80c2cf3058059f3e8950"
    )]
    fn test_vectors(aci: Aci, profile_key: &[u8; PROFILE_KEY_LEN], serialized: &[u8]) {
        let profile_key = ProfileKey {
            bytes: *profile_key,
        };
        assert_eq!(
            crate::serialize(&profile_key.get_profile_key_version(aci)).as_slice(),
            serialized
        );
    }
}
