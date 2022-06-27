//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::constants::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};

use curve25519_dalek::subtle::{Choice, ConditionallySelectable};

#[derive(Copy, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileKeyStruct {
    pub(crate) bytes: ProfileKeyBytes,
    pub(crate) M3: RistrettoPoint,
    pub(crate) M4: RistrettoPoint,
}

impl ProfileKeyStruct {
    pub fn new(profile_key_bytes: ProfileKeyBytes, uid_bytes: UidBytes) -> Self {
        let mut encoded_profile_key = profile_key_bytes;
        encoded_profile_key[0] &= 254;
        encoded_profile_key[31] &= 63;
        let M3 = Self::calc_M3(profile_key_bytes, uid_bytes);
        let M4 = RistrettoPoint::from_uniform_bytes_single_elligator(&encoded_profile_key);

        ProfileKeyStruct {
            bytes: profile_key_bytes,
            M3,
            M4,
        }
    }

    pub fn calc_M3(profile_key_bytes: ProfileKeyBytes, uid_bytes: UidBytes) -> RistrettoPoint {
        let mut combined_array = [0u8; PROFILE_KEY_LEN + UUID_LEN];
        combined_array[..PROFILE_KEY_LEN].copy_from_slice(&profile_key_bytes);
        combined_array[PROFILE_KEY_LEN..].copy_from_slice(&uid_bytes);
        Sho::new(
            b"Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKey_CalcM3",
            &combined_array,
        )
        .get_point_single_elligator()
    }

    pub fn to_bytes(&self) -> ProfileKeyBytes {
        self.bytes
    }
}

impl ConditionallySelectable for ProfileKeyStruct {
    #[allow(clippy::needless_range_loop)]
    fn conditional_select(
        a: &ProfileKeyStruct,
        b: &ProfileKeyStruct,
        choice: Choice,
    ) -> ProfileKeyStruct {
        let mut bytes: ProfileKeyBytes = [0u8; PROFILE_KEY_LEN];
        for i in 0..PROFILE_KEY_LEN {
            bytes[i] = u8::conditional_select(&a.bytes[i], &b.bytes[i], choice);
        }

        ProfileKeyStruct {
            bytes,
            M3: RistrettoPoint::conditional_select(&a.M3, &b.M3, choice),
            M4: RistrettoPoint::conditional_select(&a.M4, &b.M4, choice),
        }
    }
}
