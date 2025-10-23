//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

use curve25519_dalek_signal::ristretto::RistrettoPoint;
use libsignal_core::ServiceId;
use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::common::sho::*;
use crate::common::simple_types::*;

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialDefault)]
pub struct UidStruct {
    // Currently unused. It would be possible to convert this back to the correct kind of ServiceId
    // using the same technique as decryption: comparing possible M1 points and seeing which one
    // matches. But we don't have a need for that, and therefore it's better if that operation
    // remains part of decryption, so that you're guaranteed to get a valid result or an error in
    // one step.
    //
    // At the same time, we can't just remove the field: it's serialized as part of AuthCredential
    // and AuthCredentialWithPni, which clients store locally.
    #[serde(rename = "bytes")]
    raw_uuid_bytes: UidBytes,
    pub(crate) M1: RistrettoPoint,
    pub(crate) M2: RistrettoPoint,
}

impl UidStruct {
    pub fn from_service_id(service_id: ServiceId) -> Self {
        let M1 = Self::calc_M1(Self::seed_M1(), service_id);
        let raw_uuid_bytes = service_id.raw_uuid().into_bytes();
        let M2 = RistrettoPoint::lizard_encode::<Sha256>(&raw_uuid_bytes);
        UidStruct {
            raw_uuid_bytes,
            M1,
            M2,
        }
    }

    pub(crate) fn seed_M1() -> Sho {
        Sho::new_seed(b"Signal_ZKGroup_20200424_UID_CalcM1")
    }

    pub(crate) fn calc_M1(mut seed: Sho, service_id: ServiceId) -> RistrettoPoint {
        seed.absorb_and_ratchet(&service_id.service_id_binary());
        seed.get_point()
    }
}

impl zkcredential::attributes::Attribute for UidStruct {
    fn as_points(&self) -> [RistrettoPoint; 2] {
        [self.M1, self.M2]
    }
}
