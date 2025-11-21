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
/// A profile key version, properly encoded, is a hexadecimal ASCII string, meant to be put directly
/// into, e.g. HTTP requests.
///
/// Note that it is not a "*profile* version"; a Signal user can change their profile without
/// rotating their profile key, and the profile key version will not change either.
#[derive(Copy, Clone)]
pub struct ProfileKeyVersion {
    ascii: ProfileKeyVersionEncodedBytes,
}

impl AsRef<str> for ProfileKeyVersion {
    fn as_ref(&self) -> &str {
        // An "encoded" profile key version is hexadecimal ASCII.
        std::str::from_utf8(&self.ascii).expect("ASCII")
    }
}

impl Serialize for ProfileKeyVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(self.ascii.len())?;
        for b in self.ascii.iter() {
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

        let mut pkv_hex_array: [u8; PROFILE_KEY_VERSION_ENCODED_LEN] =
            [0u8; PROFILE_KEY_VERSION_ENCODED_LEN];
        hex::encode_to_slice(
            sho.squeeze_as_array::<PROFILE_KEY_VERSION_LEN>(),
            &mut pkv_hex_array,
        )
        .expect("lengths match");
        api::profiles::ProfileKeyVersion {
            ascii: pkv_hex_array,
        }
    }
}
