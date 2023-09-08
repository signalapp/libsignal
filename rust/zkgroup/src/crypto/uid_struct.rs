//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::sho::*;
use crate::common::simple_types::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use libsignal_protocol::ServiceId;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        let M1 = Self::calc_M1(service_id);
        let raw_uuid_bytes = service_id.raw_uuid().into_bytes();
        let M2 = RistrettoPoint::lizard_encode::<Sha256>(&raw_uuid_bytes);
        UidStruct {
            raw_uuid_bytes,
            M1,
            M2,
        }
    }

    pub fn calc_M1(service_id: ServiceId) -> RistrettoPoint {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_UID_CalcM1",
            &service_id.service_id_binary(),
        );
        sho.get_point()
    }
}

impl zkcredential::attributes::Attribute for UidStruct {
    fn as_points(&self) -> [RistrettoPoint; 2] {
        [self.M1, self.M2]
    }
}
